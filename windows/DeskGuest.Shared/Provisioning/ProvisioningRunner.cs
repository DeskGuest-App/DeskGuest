using System.Text;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.Jobs;
using DeskGuest.Shared.Security;

namespace DeskGuest.Shared.Provisioning;

// =====================================================================
// RMM-29 — the provisioning RUNNER: an RMM-15 journal job with named
// stages validate → capture-profile → apply-image → restore-profile
// → enroll → verify, authorised by an RMM-03 `provisioning` signed
// envelope whose payload binds run | image | content hash | device
// | profile manifest hash | mode.
//
// Hard rules, enforced HERE (endpoint side, independently of the
// hub service that minted the envelope):
//  * apply-image NEVER runs on an unverified profile capture. In
//    reimage mode the capture stage must produce a package that
//    verifies end-to-end before the apply stage may begin.
//  * the image definition is RE-FETCHED and its content hash
//    re-compared at apply time — a definition swapped or revoked
//    between authorization and apply refuses the apply.
//  * the executor's reported applied base-image hash must equal the
//    definition's pinned hash before the run believes it.
//  * bare-metal runs redeem a one-time provisioning token; the
//    token's mint-time binding must equal the authorized image.
//  * the target device must hold an endpoint-local acceptance of
//    provisioning — a device that never accepted is never imaged.
//  * every failure lands in a NAMED state (ProvisioningStates),
//    never an unnamed half-state; the destructive apply step is
//    NonIdempotent in the journal, so an interrupted apply parks
//    for a human decision instead of guessing.
//  * RESUME re-validates: a failed run resumed later re-runs the
//    validate + capture-verification stages in the resume pass
//    itself before apply may begin — it never resumes INTO the
//    destructive stage on yesterday's checks.
//
// D38 rmm29 FIX LANE (packet 5f9036d2, 12 findings) — the rules
// above are now actually enforced where the review found they
// were only claimed:
//  * F1: apply is attempted AT MOST ONCE per run unless a human
//    records a decision. A pass whose apply step COMPLETED skips
//    the executor on resume (post-apply failures resume AFTER
//    apply, never re-image). A pass whose apply was invoked but
//    did not verifiably complete leaves the run UNCERTAIN: any
//    later pass re-validates, then PARKS at the apply stage
//    (ProvisioningStates.Parked) until ResolveParkedApply records
//    RetryApply or FailRun.
//  * F2: a run id executes via Run() exactly once — Run() on an
//    id that already holds a non-refused record refuses; the
//    per-run token-redemption skip applies ONLY to a resume of
//    that same run, never to a fresh Run().
//  * F3: ResumeRun compares the resumed request against the
//    binding recorded by the first pass (image id/version/hash,
//    device, mode, capture-manifest hash, target user, decision
//    id) — a resume continues the SAME run or refuses.
//  * F4: the signed payload also binds the restore target user
//    and the cross-user decision id (see ProvisioningBinding).
//  * F5/F8: bare-metal redemption checks the token's mint scope
//    against the device's scope, and a device known to hold user
//    profiles refuses bare-metal outright (reimage is the only
//    path that captures first).
//  * F6/F7: a cross-user decision must come from the audited
//    register — a runner with NO register wired refuses any
//    presented decision — and a registered decision is checked
//    for freshness (24 h) and for its recorded run/device/package
//    binding when it carries one.
//  * F10: all runner state is mutated under one lock; a runner
//    executes one pass at a time.
//  * F11: apply verifies the executor-reported hash of every
//    pinned payload component (base image, driver pack, unattend
//    when pinned), not just the base image.
// =====================================================================

public static class ProvisioningModes
{
    public const string Reimage = "reimage";       // existing device; profile capture required
    public const string BareMetal = "bare_metal";  // no source profile; one-time token required
    public static readonly IReadOnlySet<string> All = new HashSet<string> { Reimage, BareMetal };
}

public static class ProvisioningStates
{
    public const string Completed = "completed";
    public const string Refused = "refused";
    public const string FailedValidation = "failed_validation";
    public const string FailedCaptureUnverified = "failed_capture_unverified";
    public const string FailedApply = "failed_apply";
    public const string FailedRestore = "failed_restore";
    public const string FailedEnroll = "failed_enroll";
    public const string FailedVerify = "failed_verify";
    /// <summary>F1: the apply step was invoked in an earlier pass
    /// and its outcome is uncertain (NonIdempotent) — the run is
    /// parked for a human decision (ResolveParkedApply), never
    /// silently re-applied and never silently continued.</summary>
    public const string Parked = "parked_human_decision";
}

/// <summary>The human decision for a run parked on an uncertain
/// apply (F1). RetryApply authorizes exactly one further apply
/// attempt on the next resume pass; FailRun ends the run as
/// refused (the device is treated as NOT provisioned and needs a
/// fresh run id).</summary>
public enum ProvisioningParkDecision { RetryApply, FailRun }

public static class ProvisioningSteps
{
    public const string Validate = "validate";
    public const string CaptureProfile = "capture_profile";
    public const string ApplyImage = "apply_image";
    public const string RestoreProfile = "restore_profile";
    public const string Enroll = "enroll";
    public const string Verify = "verify";

    public static IReadOnlyList<JobStepDefinition> All => new[]
    {
        new JobStepDefinition(Validate, "Validate image definition + authorization", StepIdempotency.Idempotent),
        new JobStepDefinition(CaptureProfile, "Capture + verify source profile (pre-image safety)", StepIdempotency.Idempotent),
        new JobStepDefinition(ApplyImage, "Apply image (DESTRUCTIVE — host imaging machinery)", StepIdempotency.NonIdempotent),
        new JobStepDefinition(RestoreProfile, "Restore profile (manifest-hash verified)", StepIdempotency.Idempotent),
        new JobStepDefinition(Enroll, "Enroll device", StepIdempotency.Idempotent),
        new JobStepDefinition(Verify, "Verify applied image + restored profile", StepIdempotency.Idempotent),
    };
}

/// <summary>The signed payload binding for one provisioning run.
/// The `provisioning` envelope's payload must equal this exactly.</summary>
public static class ProvisioningBinding
{
    // F4 (D38 rmm29): the payload binds EVERYTHING that steers the
    // run — including the restore target user and the cross-user
    // decision id, which previously travelled unsigned and could
    // be redirected between hub and endpoint under a valid
    // envelope. ("source-user" = restore to the captured profile's
    // own user; "none" = no cross-user decision presented.)
    public static string Payload(string runId, OsImageDefinition image, string deviceId,
        string? captureManifestHash, string mode,
        string? targetUserId = null, string? crossUserDecisionId = null) =>
        $"provisioning|{runId}|{image.Id}|{image.Version}|{image.ContentHash}|{deviceId}|{captureManifestHash ?? "none"}|{mode}|{targetUserId ?? "source-user"}|{crossUserDecisionId ?? "none"}";

    /// <summary>A stable hash of the DECLARED capture manifest —
    /// what the authorization binds before capture runs.</summary>
    public static string CaptureManifestHash(ProfileCaptureManifest manifest) =>
        ProvisioningHashing.Sha256Hex(System.Text.Json.JsonSerializer.Serialize(new
        {
            sourceDeviceId = manifest.SourceDeviceId,
            sourceUserId = manifest.SourceUserId,
            entries = manifest.Entries.OrderBy(e => e.Path, StringComparer.Ordinal)
                .Select(e => new { path = e.Path, category = e.Category }).ToArray(),
        }));
}

public sealed record ProvisioningRunRequest(
    string RunId,
    OsImageDefinition Image,
    string DeviceId,
    string Mode,
    ProfileCaptureManifest? CaptureManifest,
    string? TargetUserId,
    CrossUserRestoreDecision? CrossUserDecision,
    string? ProvisioningTokenCode);

public sealed record ProvisioningRunResult(
    string RunId, string DeviceId, string ImageId, string ImageVersion, string ImageContentHash,
    string Mode, string State, string Reason, string? JobId,
    string? ProfilePackageId, string? ProfileManifestHash, DateTimeOffset AtUtc);

/// <summary>The enrollment seam: enrolling a provisioned device is
/// hub/agent wiring; the runner records through this sink. Tests
/// drive the fake.</summary>
public interface IProvisioningEnrollmentSink
{
    void Enroll(string deviceId, string imageId, string imageVersion);
}

public sealed class FakeEnrollmentSink : IProvisioningEnrollmentSink
{
    public List<(string DeviceId, string ImageId, string ImageVersion)> Calls { get; } = new();
    private Exception? _throw;
    public FakeEnrollmentSink ThenThrow(Exception ex) { _throw = ex; return this; }
    public void Enroll(string deviceId, string imageId, string imageVersion)
    {
        if (_throw is not null) throw _throw;
        Calls.Add((deviceId, imageId, imageVersion));
    }
}

public sealed class ProvisioningRunner
{
    private readonly SignedCommandGate? _gate;
    private readonly ChainedAuditLog _audit;
    private readonly ProfileMigrationEngine _profiles;
    private readonly IProfileCaptureSource _captureSource;
    private readonly IImagingExecutor _imaging;
    private readonly IProvisioningEnrollmentSink _enrollment;
    private readonly ProvisioningTokenService _tokens;
    private readonly Func<string, string, OsImageDefinition?> _imageLookup;
    private readonly Func<string, string, bool> _imageRevoked;
    private readonly Func<string, bool> _deviceAccepted;
    private readonly Func<string, CrossUserRestoreDecision?>? _decisionLookup;
    private readonly Func<string, string?>? _deviceScope;
    private readonly Func<string, bool>? _deviceHasUserProfiles;
    // bd-shared-plat-2/F6: the restore WRITE target. When wired,
    // the restore stage writes every entry and verifies read-back
    // hashes; when not wired the stage is verify-only and the
    // completion reason says so — it never claims data landed.
    private readonly IProfileRestoreTarget? _restoreTarget;
    // F10: every piece of mutable runner state below is guarded by
    // _sync; a runner executes one pass at a time, so two
    // concurrent calls for one run id can never both reach apply.
    private readonly object _sync = new();
    private readonly Dictionary<string, ProvisioningRunResult> _runs = new(StringComparer.Ordinal);
    private readonly Dictionary<string, ProfilePackage> _captured = new(StringComparer.Ordinal);
    private readonly HashSet<string> _tokenRedeemedRuns = new(StringComparer.Ordinal);
    // F1: per-run apply discipline — completed (never re-run the
    // executor), uncertain (parked until a human decides), and the
    // one-shot retry authorization a RetryApply decision grants.
    private readonly HashSet<string> _applyCompletedRuns = new(StringComparer.Ordinal);
    private readonly HashSet<string> _applyUncertainRuns = new(StringComparer.Ordinal);
    private readonly HashSet<string> _applyRetryAuthorized = new(StringComparer.Ordinal);
    // F3: the binding recorded by a run's first pass; a resume
    // must match it exactly.
    private readonly Dictionary<string, RunBinding> _runBindings = new(StringComparer.Ordinal);

    private sealed record RunBinding(string ImageId, string ImageVersion, string ImageContentHash,
        string DeviceId, string Mode, string? CaptureManifestHash, string? TargetUserId,
        string? CrossUserDecisionId);

    private static RunBinding BindingOf(ProvisioningRunRequest request) => new(
        request.Image.Id, request.Image.Version, request.Image.ContentHash, request.DeviceId,
        request.Mode,
        request.CaptureManifest is null ? null : ProvisioningBinding.CaptureManifestHash(request.CaptureManifest),
        request.TargetUserId, request.CrossUserDecision?.Id);

    public ProvisioningRunner(SignedCommandGate? gate, ChainedAuditLog audit,
        ProfileMigrationEngine profiles, IProfileCaptureSource captureSource,
        IImagingExecutor imaging, IProvisioningEnrollmentSink enrollment,
        ProvisioningTokenService tokens,
        Func<string, string, OsImageDefinition?> imageLookup,
        Func<string, string, bool> imageRevoked,
        Func<string, bool> deviceAccepted,
        Func<string, CrossUserRestoreDecision?>? decisionLookup = null,
        Func<string, string?>? deviceScope = null,
        Func<string, bool>? deviceHasUserProfiles = null,
        IProfileRestoreTarget? restoreTarget = null)
    {
        _restoreTarget = restoreTarget;
        _gate = gate;
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _profiles = profiles ?? throw new ArgumentNullException(nameof(profiles));
        _captureSource = captureSource ?? throw new ArgumentNullException(nameof(captureSource));
        _imaging = imaging ?? throw new ArgumentNullException(nameof(imaging));
        _enrollment = enrollment ?? throw new ArgumentNullException(nameof(enrollment));
        _tokens = tokens ?? throw new ArgumentNullException(nameof(tokens));
        _imageLookup = imageLookup ?? throw new ArgumentNullException(nameof(imageLookup));
        _imageRevoked = imageRevoked ?? throw new ArgumentNullException(nameof(imageRevoked));
        _deviceAccepted = deviceAccepted ?? throw new ArgumentNullException(nameof(deviceAccepted));
        _decisionLookup = decisionLookup;
        _deviceScope = deviceScope;
        _deviceHasUserProfiles = deviceHasUserProfiles;
    }

    public ProvisioningRunResult? GetRun(string runId)
    {
        lock (_sync) return _runs.TryGetValue(runId ?? "", out var r) ? r : null;
    }

    // ---- bd-shared-plat-2/F5: the run ledger persists ----
    // The apply-once guarantees (F1/F2) previously lived only in
    // memory: a restart after an uncertain apply let a fresh Run()
    // with the same RunId re-run the destructive executor. The
    // ledger (runs, bindings, apply-completed/uncertain/retry
    // sets, token-redeemed runs, captured packages) now round-
    // trips through the HubPersistence envelope. Journal rebuild
    // remains an alternative host strategy; this is the runner's
    // own durable form.
    private sealed record LedgerDto(
        ProvisioningRunResult[] Runs, RunBindingDto[] Bindings,
        string[] ApplyCompleted, string[] ApplyUncertain, string[] ApplyRetryAuthorized,
        string[] TokenRedeemedRuns, ProfilePackage[] Captured);
    private sealed record RunBindingDto(string RunId, string ImageId, string ImageVersion,
        string ImageContentHash, string DeviceId, string Mode, string? CaptureManifestHash,
        string? TargetUserId, string? CrossUserDecisionId);

    public string ExportJson()
    {
        lock (_sync)
        {
            var dto = new LedgerDto(
                _runs.Values.ToArray(),
                _runBindings.Select(kv => new RunBindingDto(kv.Key, kv.Value.ImageId, kv.Value.ImageVersion,
                    kv.Value.ImageContentHash, kv.Value.DeviceId, kv.Value.Mode, kv.Value.CaptureManifestHash,
                    kv.Value.TargetUserId, kv.Value.CrossUserDecisionId)).ToArray(),
                _applyCompletedRuns.ToArray(), _applyUncertainRuns.ToArray(),
                _applyRetryAuthorized.ToArray(), _tokenRedeemedRuns.ToArray(),
                _captured.Values.ToArray());
            return DeskGuest.Shared.Hub.HubPersistence.Wrap("deskguest-provisioning-runner-v1",
                System.Text.Json.JsonSerializer.Serialize(dto));
        }
    }

    public int ImportJson(string json)
    {
        var payload = DeskGuest.Shared.Hub.HubPersistence.Unwrap(json, "deskguest-provisioning-runner-v1");
        if (payload is null) return 0;
        LedgerDto? dto;
        try { dto = System.Text.Json.JsonSerializer.Deserialize<LedgerDto>(payload); }
        catch { return 0; }
        if (dto is null) return 0;
        var n = 0;
        lock (_sync)
        {
            foreach (var r in dto.Runs ?? Array.Empty<ProvisioningRunResult>())
                if (r is not null && !_runs.ContainsKey(r.RunId)) { _runs[r.RunId] = r; n++; }
            foreach (var b in dto.Bindings ?? Array.Empty<RunBindingDto>())
                if (b is not null && !_runBindings.ContainsKey(b.RunId))
                    _runBindings[b.RunId] = new RunBinding(b.ImageId, b.ImageVersion, b.ImageContentHash,
                        b.DeviceId, b.Mode, b.CaptureManifestHash, b.TargetUserId, b.CrossUserDecisionId);
            foreach (var s in dto.ApplyCompleted ?? Array.Empty<string>()) _applyCompletedRuns.Add(s);
            foreach (var s in dto.ApplyUncertain ?? Array.Empty<string>()) _applyUncertainRuns.Add(s);
            foreach (var s in dto.ApplyRetryAuthorized ?? Array.Empty<string>()) _applyRetryAuthorized.Add(s);
            foreach (var s in dto.TokenRedeemedRuns ?? Array.Empty<string>()) _tokenRedeemedRuns.Add(s);
            // Captured packages are re-keyed by matching run ids:
            // a package belongs to the run whose result names it.
            foreach (var p in dto.Captured ?? Array.Empty<ProfilePackage>())
            {
                if (p is null) continue;
                var run = _runs.Values.FirstOrDefault(r => r.ProfilePackageId == p.Id);
                if (run is not null && !_captured.ContainsKey(run.RunId)) _captured[run.RunId] = p;
            }
        }
        return n;
    }

    public ProfilePackage? GetCapturedProfile(string runId)
    {
        lock (_sync) return _captured.TryGetValue(runId ?? "", out var p) ? p : null;
    }

    public ProvisioningRunResult Run(ProvisioningRunRequest request, SignedCommandEnvelope? envelope,
        JobJournal? journal, Func<bool> policyStillEnabled, DateTimeOffset now)
    {
        lock (_sync)
        {
            // F2: a run id executes via Run() exactly once. An id
            // that already holds a live record (failed, parked or
            // completed) is continued with ResumeRun or not at all —
            // in particular a bare-metal id whose token this runner
            // already redeemed can never be re-run past redemption.
            // (A REFUSED record never executed a stage, so a fresh
            // Run() after the refusal cause is fixed stays legal.)
            if (_runs.TryGetValue(request.RunId ?? "", out var prior) &&
                prior.State != ProvisioningStates.Refused)
            {
                var refusal = new ProvisioningRunResult(request.RunId, request.DeviceId,
                    request.Image.Id, request.Image.Version, request.Image.ContentHash, request.Mode,
                    ProvisioningStates.Refused,
                    $"run id '{request.RunId}' already holds a run in state '{prior.State}' — a run id executes once; continue it with ResumeRun, never a fresh Run() (refused)",
                    null, prior.ProfilePackageId, prior.ProfileManifestHash, now);
                _audit.Append("provisioning_not_completed", "provisioning-runner",
                    $"run={request.RunId} device={request.DeviceId} state=refused reason={refusal.Reason}", now);
                return refusal;
            }
            return Execute(request, envelope, journal, policyStillEnabled, now, resumed: false);
        }
    }

    /// <summary>Resume a previously failed run. The resume pass
    /// RE-RUNS validate + capture verification itself (a fresh
    /// journal job whose early stages are the re-validations) —
    /// apply may only begin on checks performed in THIS pass.</summary>
    public ProvisioningRunResult ResumeRun(ProvisioningRunRequest request, SignedCommandEnvelope? envelope,
        JobJournal? journal, Func<bool> policyStillEnabled, DateTimeOffset now)
    {
        lock (_sync)
        {
            if (!_runs.TryGetValue(request.RunId ?? "", out var prior) ||
                prior.State is ProvisioningStates.Completed or ProvisioningStates.Refused)
                return Record(request, ProvisioningStates.Refused, null,
                    "resume refused: no failed run with this id exists to resume (a completed or refused run is not resumable)", now);
            // F3: the resumed request must BE the failed run —
            // same image (id, version, content hash), same device,
            // same mode, same declared capture manifest, same
            // restore target user, same cross-user decision. A
            // resume that rebinds any of these is a new run wearing
            // a failed run's id (and its captured profile / redeemed
            // token), and refuses WITHOUT disturbing the record.
            if (_runBindings.TryGetValue(request.RunId ?? "", out var binding))
            {
                var candidate = BindingOf(request);
                if (!string.Equals(binding.ImageId, candidate.ImageId, StringComparison.OrdinalIgnoreCase) ||
                    !string.Equals(binding.ImageVersion, candidate.ImageVersion, StringComparison.Ordinal) ||
                    !string.Equals(binding.ImageContentHash, candidate.ImageContentHash, StringComparison.Ordinal) ||
                    !string.Equals(binding.DeviceId, candidate.DeviceId, StringComparison.OrdinalIgnoreCase) ||
                    !string.Equals(binding.Mode, candidate.Mode, StringComparison.Ordinal) ||
                    !string.Equals(binding.CaptureManifestHash, candidate.CaptureManifestHash, StringComparison.Ordinal) ||
                    !string.Equals(binding.TargetUserId, candidate.TargetUserId, StringComparison.OrdinalIgnoreCase) ||
                    !string.Equals(binding.CrossUserDecisionId, candidate.CrossUserDecisionId, StringComparison.Ordinal))
                {
                    var refusal = new ProvisioningRunResult(request.RunId, request.DeviceId,
                        request.Image.Id, request.Image.Version, request.Image.ContentHash, request.Mode,
                        ProvisioningStates.Refused,
                        "resume refused: the resumed request does not match the failed run's recorded binding (image, device, mode, capture manifest, target user or decision differ) — a resume continues the SAME run; it never rebinds it",
                        null, prior.ProfilePackageId, prior.ProfileManifestHash, now);
                    _audit.Append("provisioning_not_completed", "provisioning-runner",
                        $"run={request.RunId} device={request.DeviceId} state=refused reason={refusal.Reason}", now);
                    return refusal;
                }
            }
            return Execute(request, envelope, journal, policyStillEnabled, now, resumed: true);
        }
    }

    /// <summary>F1: the human decision for a run parked on an
    /// uncertain apply. RetryApply authorizes exactly one further
    /// apply attempt on the next resume pass. FailRun ends the run
    /// as refused — the device is treated as NOT provisioned.
    /// Returns false when the run is not parked on an uncertain
    /// apply (nothing to decide).</summary>
    public bool ResolveParkedApply(string runId, ProvisioningParkDecision decision,
        string decidedBy, DateTimeOffset now)
    {
        lock (_sync)
        {
            if (runId is null || !_applyUncertainRuns.Contains(runId) ||
                !_runs.TryGetValue(runId, out var prior))
                return false;
            if (decision == ProvisioningParkDecision.RetryApply)
            {
                _applyRetryAuthorized.Add(runId);
                _audit.Append("provisioning_park_decision", decidedBy ?? "human",
                    $"run={runId} decision=retry_apply (one further apply attempt authorized on resume)", now);
                return true;
            }
            _applyUncertainRuns.Remove(runId);
            _applyRetryAuthorized.Remove(runId);
            _runs[runId] = prior with
            {
                State = ProvisioningStates.Refused,
                Reason = $"human decision by '{decidedBy}': fail the run — the earlier apply outcome is uncertain, so the device is treated as NOT provisioned; provision it under a fresh run id",
                AtUtc = now,
            };
            _audit.Append("provisioning_park_decision", decidedBy ?? "human",
                $"run={runId} decision=fail_run (device treated as not provisioned)", now);
            return true;
        }
    }

    private ProvisioningRunResult Record(ProvisioningRunRequest request, string state, string? jobId,
        string reason, DateTimeOffset now, ProfilePackage? captured = null)
    {
        var result = new ProvisioningRunResult(request.RunId, request.DeviceId,
            request.Image.Id, request.Image.Version, request.Image.ContentHash, request.Mode,
            state, reason, jobId, captured?.Id, captured?.ManifestHash, now);
        _runs[request.RunId] = result;
        if (captured is not null) _captured[request.RunId] = captured;
        _audit.Append(state == ProvisioningStates.Completed ? "provisioning_completed" : "provisioning_not_completed",
            "provisioning-runner",
            $"run={request.RunId} device={request.DeviceId} image={request.Image.Id} v{request.Image.Version} mode={request.Mode} state={state} reason={reason}", now);
        return result;
    }

    private ProvisioningRunResult Execute(ProvisioningRunRequest request, SignedCommandEnvelope? envelope,
        JobJournal? journal, Func<bool> policyStillEnabled, DateTimeOffset now, bool resumed)
    {
        ProvisioningRunResult Fail(string state, string? jobId, string reason, ProfilePackage? cap = null) =>
            Record(request, state, jobId, reason, now, cap);
        ProvisioningRunResult Refuse(string reason) =>
            Record(request, ProvisioningStates.Refused, null, reason, now);

        if (!ProvisioningModes.All.Contains(request.Mode ?? ""))
            return Refuse($"unknown provisioning mode '{request.Mode}' — refused");
        if (string.IsNullOrWhiteSpace(request.RunId) || string.IsNullOrWhiteSpace(request.DeviceId))
            return Refuse("a provisioning run needs a run id and a target device — refused");

        // Endpoint-local acceptance: a device that never accepted
        // provisioning is never provisioned, whatever the hub signed.
        if (!_deviceAccepted(request.DeviceId))
            return Refuse($"device '{request.DeviceId}' holds no endpoint-local acceptance of provisioning — refused (provisioning is endpoint-consented, never hub-imposed)");

        // Policy gate (TOTAL POLICY CONTROL): the destructive toggle
        // must STILL be on at run time.
        if (!policyStillEnabled())
            return Refuse("policy 'rmm.provisioning.enabled' is not in force for this run — refused (provisioning is destructive and defaults OFF)");

        // F8: bare-metal skips capture BY DESIGN — so a device
        // known to hold user profiles must never be submitted as
        // bare-metal. When the profile-presence lookup is wired
        // and it reports profiles, reimage (capture-first) is the
        // only legal path.
        if (request.Mode == ProvisioningModes.BareMetal && _deviceHasUserProfiles is not null &&
            _deviceHasUserProfiles(request.DeviceId))
            return Refuse($"device '{request.DeviceId}' holds existing user profiles — bare-metal provisioning would destroy them with no capture; refused (use reimage mode, which captures and verifies first)");

        // ---- RMM-03 gate: NOTHING provisions unverified. ----
        if (_gate is null)
            return Refuse("no signed-command gate wired on the agent — provisioning refuses (RMM-03: unsigned commands never execute)");
        var verdict = _gate.Authorize(envelope, now, SignedCommandClasses.Provisioning);
        if (!verdict.Allowed) return Refuse(verdict.Reason);
        var expected = ProvisioningBinding.Payload(request.RunId, request.Image, request.DeviceId,
            request.CaptureManifest is null ? null : ProvisioningBinding.CaptureManifestHash(request.CaptureManifest),
            request.Mode, request.TargetUserId, request.CrossUserDecision?.Id);
        var actual = Encoding.UTF8.GetString(verdict.Payload!);
        if (actual != expected)
            return Refuse("the signed envelope does not bind THIS run, image, content hash, device, capture manifest, mode, target user and decision (payload binding mismatch) — refused");

        // F3: record this run's binding on its first pass; resume
        // passes are compared against it in ResumeRun.
        _runBindings.TryAdd(request.RunId, BindingOf(request));

        // ---- RMM-15 provisioning job. ----
        ResumableJob? job = null;
        if (journal is not null)
        {
            job = journal.CreateJob(JobKinds.Provisioning, request.DeviceId,
                ProvisioningSteps.All, envelope, now);
            if (job is null)
                return Refuse("the job journal refused the provisioning job (envelope class/expiry or step shape) — provisioning refuses rather than run uncheckpointed");
            journal.StartJob(job.Id, now);
        }
        string? JobId = job?.Id;
        bool Step(string stepId, Func<string?> body, out string? error)
        {
            error = null;
            if (job is not null && !journal!.BeginStep(job.Id, stepId, now)) { error = $"journal refused to begin step '{stepId}'"; return false; }
            error = body();
            if (error is not null)
            {
                if (job is not null) journal!.FailStep(job.Id, stepId, error, now);
                return false;
            }
            if (job is not null) journal!.CompleteStep(job.Id, stepId, now);
            return true;
        }
        void Skip(string stepId)
        {
            if (job is null) return;
            if (journal!.BeginStep(job.Id, stepId, now)) journal.CompleteStep(job.Id, stepId, now);
        }

        // ---- Stage 1: validate (re-run in EVERY pass, incl. resume).
        OsImageDefinition? current = null;
        if (!Step(ProvisioningSteps.Validate, () =>
        {
            if (request.Image.Validate() is { } v) return v;
            if (!request.Image.Enabled) return $"image '{request.Image.Id}' v{request.Image.Version} is disabled — refused";
            current = _imageLookup(request.Image.Id, request.Image.Version);
            if (current is null) return $"image '{request.Image.Id}' v{request.Image.Version} is not in the repository at run time — refused";
            if (current.ContentHash != request.Image.ContentHash)
                return $"image definition changed since authorization (authorized {request.Image.ContentHash}, current {current.ContentHash}) — refused; re-authorize the new definition";
            if (_imageRevoked(request.Image.Id, request.Image.Version))
                return $"image '{request.Image.Id}' v{request.Image.Version} is revoked — refused";
            // Bare-metal: the one-time token is redeemed HERE, in
            // the validate stage — BEFORE the destructive apply.
            // (Recovery lane #2 fix: the inherited runner redeemed
            // at enroll, after the image was already written, so a
            // replayed/expired/mis-bound token was only discovered
            // post-apply.) Redemption consumes the token; a run
            // that fails later does not get it back — fail-closed.
            // F2: the redemption skip applies ONLY to a resume of
            // this same run (resumed == true) — a fresh Run() can
            // never reach here for an id that already redeemed,
            // because Run() refuses an id holding a live record.
            if (request.Mode == ProvisioningModes.BareMetal &&
                !(resumed && _tokenRedeemedRuns.Contains(request.RunId)))
            {
                // F5: redemption is scope-checked against the
                // DEVICE's scope. Without a scope lookup the mint
                // scope cannot be verified, and bare-metal refuses
                // rather than redeeming unchecked.
                if (_deviceScope is null)
                    return "no device-scope lookup is wired on this runner — a bare-metal token's mint scope cannot be verified against the device; refused BEFORE apply";
                var view = _tokens.Redeem(request.ProvisioningTokenCode, request.Image.Id,
                    request.Image.Version, request.Image.ContentHash, now,
                    _deviceScope(request.DeviceId));
                if (view is null)
                    return "the provisioning token is unknown, expired, already consumed, bound to a different image, or minted for a different scope than the device's — refused BEFORE apply (tokens are single-use, mint-bound and scope-bound)";
                // The redemption belongs to THIS run: a resume pass
                // of the same run does not redeem again (the token
                // is consumed), and no other run can reuse it.
                _tokenRedeemedRuns.Add(request.RunId);
            }
            return null;
        }, out var verr))
            return Fail(ProvisioningStates.FailedValidation, JobId, verr!);

        // ---- Stage 2: capture-profile (the pre-image safety gate).
        ProfilePackage? captured = null;
        if (request.Mode == ProvisioningModes.Reimage)
        {
            if (!Step(ProvisioningSteps.CaptureProfile, () =>
            {
                if (request.CaptureManifest is null)
                    return "reimage mode names no capture manifest — a reimage without a declared profile capture is refused";
                if (!string.Equals(request.CaptureManifest.SourceDeviceId, request.DeviceId, StringComparison.OrdinalIgnoreCase))
                    return "the capture manifest's source device is not the run's target device — refused";
                // On resume, a previously captured package may be
                // re-presented — but it is RE-VERIFIED here, in
                // this pass, before it counts.
                if (resumed && _captured.TryGetValue(request.RunId, out var priorPkg))
                {
                    // F3 (defense in depth — ResumeRun already
                    // compares the recorded binding): the reused
                    // package must belong to THIS run's device.
                    if (!string.Equals(priorPkg.SourceDeviceId, request.DeviceId, StringComparison.OrdinalIgnoreCase))
                        return "the previously captured profile belongs to a different device than this run's target — the resume must re-capture; apply is blocked";
                    var (okPrior, whyPrior) = _profiles.Verify(priorPkg);
                    if (!okPrior) return $"the previously captured profile no longer verifies ({whyPrior}) — the resume must re-capture; apply is blocked";
                    captured = priorPkg;
                    return null;
                }
                var (pkg, reason) = _profiles.CaptureAndSeal(request.CaptureManifest, _captureSource, now);
                if (pkg is null) return reason;
                var (ok, why) = _profiles.Verify(pkg);
                if (!ok) return $"captured profile failed verification: {why}";
                captured = pkg;
                return null;
            }, out var cerr))
                return Fail(ProvisioningStates.FailedCaptureUnverified, JobId,
                    $"apply-image is blocked: no VERIFIED pre-image profile capture exists ({cerr})", captured);
        }
        else Skip(ProvisioningSteps.CaptureProfile);

        // ---- Stage 3: apply-image (DESTRUCTIVE). Re-fetch + re-pin
        // at the moment of apply; the executor's reported hashes
        // must equal the pinned hashes for EVERY pinned component.
        // F1: this stage runs the executor at most once per run
        // unless a human authorizes a retry — see the header.
        if (_applyCompletedRuns.Contains(request.RunId))
        {
            // A previous pass of THIS run applied and verified the
            // image; this pass resumes AFTER apply (restore /
            // enroll / verify), it never re-images the device.
            Skip(ProvisioningSteps.ApplyImage);
        }
        else
        {
            var applyUncertain = false;
            var parkedNow = false;
            if (!Step(ProvisioningSteps.ApplyImage, () =>
            {
                var atApply = _imageLookup(request.Image.Id, request.Image.Version);
                if (atApply is null) return "image definition vanished before apply — refused";
                if (atApply.ContentHash != request.Image.ContentHash)
                    return $"image definition was substituted between authorization and apply (authorized {request.Image.ContentHash}, at-apply {atApply.ContentHash}) — apply refused";
                if (_imageRevoked(request.Image.Id, request.Image.Version))
                    return "image was revoked between authorization and apply — apply refused";
                // F1: a previous pass invoked apply and its outcome
                // is uncertain. Without a recorded human RetryApply
                // decision this pass PARKS here — after validate +
                // capture verification above have re-run — and the
                // executor is never invoked again on a guess.
                if (_applyUncertainRuns.Contains(request.RunId) &&
                    !_applyRetryAuthorized.Contains(request.RunId))
                {
                    parkedNow = true;
                    return "the apply step was already invoked in an earlier pass and its outcome is uncertain (apply is NonIdempotent) — the run is parked for a human decision (ResolveParkedApply: RetryApply or FailRun); apply was NOT re-attempted";
                }
                _applyRetryAuthorized.Remove(request.RunId); // one decision = one attempt
                ImagingApplyResult result;
                try { result = _imaging.ApplyImage(new ImagingApplyRequest(atApply, request.DeviceId, request.RunId)); }
                catch (Exception ex) { applyUncertain = true; return $"imaging executor threw: {ex.Message}"; }
                if (!result.Ok) { applyUncertain = true; return result.Reason; }
                if (!string.Equals(result.AppliedBaseImageHash, atApply.BaseImageHash, StringComparison.OrdinalIgnoreCase))
                { applyUncertain = true; return $"the executor reports it applied base image hash '{result.AppliedBaseImageHash}', not the pinned '{atApply.BaseImageHash}' — the applied image is NOT the authorized image; run failed by name"; }
                // F11: the driver pack is pinned by the definition —
                // the executor must REPORT applying that exact pack.
                if (result.AppliedDriverPackHash is null)
                { applyUncertain = true; return "the executor did not report the driver-pack hash it applied — the pinned driver pack is unverified; run failed by name"; }
                if (!string.Equals(result.AppliedDriverPackHash, atApply.DriverPackHash, StringComparison.OrdinalIgnoreCase))
                { applyUncertain = true; return $"the executor reports it applied driver pack hash '{result.AppliedDriverPackHash}', not the pinned '{atApply.DriverPackHash}' — a substituted driver pack is not the authorized image; run failed by name"; }
                if (atApply.UnattendHash is not null)
                {
                    if (result.AppliedUnattendHash is null)
                    { applyUncertain = true; return "the executor did not report the unattend-file hash it applied, though the definition pins one — unverified; run failed by name"; }
                    if (!string.Equals(result.AppliedUnattendHash, atApply.UnattendHash, StringComparison.OrdinalIgnoreCase))
                    { applyUncertain = true; return $"the executor reports it applied unattend hash '{result.AppliedUnattendHash}', not the pinned '{atApply.UnattendHash}' — run failed by name"; }
                }
                _applyCompletedRuns.Add(request.RunId);
                _applyUncertainRuns.Remove(request.RunId);
                return null;
            }, out var aerr))
            {
                if (parkedNow)
                    return Fail(ProvisioningStates.Parked, JobId, aerr!, captured);
                if (applyUncertain)
                {
                    // The pass that invoked apply reports the named
                    // failure; the run is flagged UNCERTAIN so any
                    // later pass parks at this stage (above) until a
                    // human decides — it never re-applies on a guess.
                    _applyUncertainRuns.Add(request.RunId);
                    return Fail(ProvisioningStates.FailedApply, JobId,
                        $"{aerr} — the apply outcome is UNCERTAIN (apply is NonIdempotent): this run is parked for a human decision (ResolveParkedApply: RetryApply or FailRun) before any resume may re-attempt apply",
                        captured);
                }
                return Fail(ProvisioningStates.FailedApply, JobId, aerr!, captured);
            }
        }

        // ---- Stage 4: restore-profile (manifest-hash verified).
        if (request.Mode == ProvisioningModes.Reimage)
        {
            if (!Step(ProvisioningSteps.RestoreProfile, () =>
            {
                // A presented cross-user decision must BE the
                // audited record in the register — a fabricated
                // decision object refuses. (Recovery lane #2
                // hardening, completed by the D38 fix lane:)
                // F7 — the lookup is no longer optional in effect:
                // a runner with NO register wired refuses any
                // presented decision outright (the runner-only
                // fabrication path is closed, not defaulted open).
                // F6 — the registered decision must also be FRESH
                // (24 h, and not future-dated beyond clock skew)
                // and must honour any run/device/package binding
                // recorded with it.
                if (request.CrossUserDecision is not null)
                {
                    if (_decisionLookup is null)
                        return "no audited cross-user decision register is wired on this runner — a presented decision cannot be verified against the register; restore refused";
                    var registered = _decisionLookup(request.CrossUserDecision.Id);
                    if (registered is null ||
                        !string.Equals(registered.SourceUserId, request.CrossUserDecision.SourceUserId, StringComparison.OrdinalIgnoreCase) ||
                        !string.Equals(registered.TargetUserId, request.CrossUserDecision.TargetUserId, StringComparison.OrdinalIgnoreCase) ||
                        !string.Equals(registered.ApprovedBy, request.CrossUserDecision.ApprovedBy, StringComparison.OrdinalIgnoreCase) ||
                        !string.Equals(registered.RequestedBy, request.CrossUserDecision.RequestedBy, StringComparison.OrdinalIgnoreCase))
                        return "the cross-user decision presented is not the audited decision recorded under that id — restore refused";
                    if (registered.DecidedUtc > now.AddMinutes(5))
                        return "the cross-user decision is dated in the future — restore refused (a decision cannot predate its own recording)";
                    if (now > registered.DecidedUtc.AddHours(24))
                        return "the cross-user decision has expired (decisions are valid for 24 hours) — a fresh audited decision is required; restore refused";
                    if (registered.RunId is not null &&
                        !string.Equals(registered.RunId, request.RunId, StringComparison.Ordinal))
                        return "the cross-user decision is bound to a different run — restore refused";
                    if (registered.DeviceId is not null &&
                        !string.Equals(registered.DeviceId, request.DeviceId, StringComparison.OrdinalIgnoreCase))
                        return "the cross-user decision is bound to a different device — restore refused";
                    if (registered.ProfilePackageId is not null &&
                        !string.Equals(registered.ProfilePackageId, captured?.Id, StringComparison.Ordinal))
                        return "the cross-user decision is bound to a different profile package — restore refused";
                }
                var targetUser = request.TargetUserId ?? request.CaptureManifest!.SourceUserId;
                // bd-shared-plat-2/F6: with a target wired, the
                // restore WRITES and reads back; without one it is
                // verify-only (and the completion reason names it).
                var (ok, reason, _, verifiedHash) = _restoreTarget is not null
                    ? _profiles.RestoreToTarget(captured, request.DeviceId, targetUser, request.CrossUserDecision, _restoreTarget)
                    : _profiles.Restore(captured, request.DeviceId, targetUser, request.CrossUserDecision);
                if (!ok) return reason;
                if (!string.Equals(verifiedHash, captured!.ManifestHash, StringComparison.Ordinal))
                    return "restore verified against a different manifest hash than the capture sealed — refused";
                return null;
            }, out var rerr))
                return Fail(ProvisioningStates.FailedRestore, JobId, rerr!, captured);
        }
        else Skip(ProvisioningSteps.RestoreProfile);

        // ---- Stage 5: enroll. (Bare-metal token redemption
        // happened in the validate stage, before apply — see there.)
        if (!Step(ProvisioningSteps.Enroll, () =>
        {
            try { _enrollment.Enroll(request.DeviceId, request.Image.Id, request.Image.Version); }
            catch (Exception ex) { return $"enrollment failed: {ex.Message}"; }
            return null;
        }, out var eerr))
            return Fail(ProvisioningStates.FailedEnroll, JobId, eerr!, captured);

        // ---- Stage 6: verify.
        if (!Step(ProvisioningSteps.Verify, () =>
        {
            var final = _imageLookup(request.Image.Id, request.Image.Version);
            if (final is null || final.ContentHash != request.Image.ContentHash)
                return "post-run verification: the image definition no longer matches the authorized content hash";
            if (captured is not null)
            {
                var (ok, why) = _profiles.Verify(captured);
                if (!ok) return $"post-run verification: the restored profile no longer verifies ({why})";
            }
            return null;
        }, out var verr2))
            return Fail(ProvisioningStates.FailedVerify, JobId, verr2!, captured);

        // bd-shared-plat-2/F6: the completion reason is honest
        // about the restore leg — "restored" only when a target
        // actually wrote the entries.
        var restoreClaim = request.Mode != ProvisioningModes.Reimage
            ? "no profile to restore (bare-metal)"
            : _restoreTarget is not null
                ? "profile restored (written + read-back verified)"
                : "profile VERIFIED ONLY — no restore target wired, nothing was written to the target profile";
        return Record(request, ProvisioningStates.Completed, JobId,
            (resumed ? "provisioning run completed (resumed pass re-validated validate + capture before apply)"
                    : "provisioning run completed: image applied and verified, device enrolled") + $"; restore: {restoreClaim}",
            now, captured);
    }
}
