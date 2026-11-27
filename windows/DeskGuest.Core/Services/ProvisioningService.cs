using System.Text;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.Jobs;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.Provisioning;
using DeskGuest.Shared.Security;

namespace DeskGuest.Core.Services;

// =====================================================================
// RMM-29 — ProvisioningService (hub/Core side).
//
// Owns the image repository, the profile-migration engine, the
// one-time provisioning-token service and the cross-user decision
// register; mints RMM-03 `provisioning` authorizations; and runs
// ProvisioningRunner executions against injected seams.
//
// POLICY (TOTAL POLICY CONTROL): the constructor REGISTERS
// `rmm.provisioning.enabled` into the RMM-07 registry with default
// OFF — provisioning is destructive, so only an explicit policy
// document setting it "true" for a device enables a run. The older
// seeded `rmm.imaging.enabled` (default ON) names the reporting
// surface, NOT this gate (see ProvisioningModel.cs header).
//
// COMPOSITION, no parallel mechanisms: image definitions reference
// RMM-16 package ids (applied by the package repository after
// imaging), RMM-07 policy document ids, and an RMM-20 runbook id;
// the run is an RMM-15 journal job; the pre-image safety story is
// the verified profile capture itself plus RMM-06 backup discipline
// (a reimage run's sealed profile package id is recorded on the run
// result as the recoverable pre-image artefact).
//
// HOST MACHINERY HONESTY: the imaging executor defaults to
// UnavailableImagingExecutor — WinPE/deployment-share wiring does
// not exist in this build, so a default-constructed service REFUSES
// at apply by name rather than claiming an image was written.
// NOTHING here images a real machine.
// =====================================================================

public sealed record ProvisioningVerdict(bool Allowed, string Reason);

/// <summary>BD-WIN-CORE-3/F7: the production default enrollment
/// sink. The old default was FakeEnrollmentSink — a TEST double —
/// so a default-constructed ProvisioningService recorded enrollments
/// into a fake and reported success for an enrollment that never
/// happened. This sink refuses by name (throws, which the runner
/// surfaces as a failed enrollment step) until the host wires a
/// real enrollment sink.</summary>
public sealed class UnavailableProvisioningEnrollmentSink : IProvisioningEnrollmentSink
{
    public void Enroll(string deviceId, string imageId, string imageVersion) =>
        throw new InvalidOperationException(
            $"enrollment sink is host wiring, NOT wired in this build — device '{deviceId}' was NOT enrolled for image '{imageId}' v{imageVersion} (named remainder; a Fake* default must never report a provisioning enrollment that did not happen)");
}

public sealed class ProvisioningService
{
    private static readonly TimeSpan EnvelopeTtl = TimeSpan.FromMinutes(30);

    private readonly ChainedAuditLog _audit;
    private readonly ManagementPolicyEngine _policy;
    private readonly Func<string, IDeviceFacts?> _facts;
    private readonly SignedCommandSigner? _signer;
    private readonly SignedCommandGate? _gate;
    private readonly ISecretProtector _protector;
    private readonly IProfileCaptureSource _captureSource;
    private readonly IImagingExecutor _imaging;
    private readonly IProvisioningEnrollmentSink _enrollment;
    private readonly Func<JobJournal?> _journalFactory;
    private readonly Func<DateTimeOffset> _clock;
    private readonly HashSet<string> _acceptedDevices = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, CrossUserRestoreDecision> _crossUserDecisions = new(StringComparer.Ordinal);
    // F12: declared with the other fields (was at the bottom of
    // the class). F10/F12: one runner per live run id; a completed
    // run's runner is pruned and its id recorded terminal, an
    // in-flight set refuses concurrent execution of one run id.
    private readonly Dictionary<string, ProvisioningRunner> _runnersByRun = new(StringComparer.Ordinal);
    private readonly HashSet<string> _inFlightRuns = new(StringComparer.Ordinal);
    private readonly HashSet<string> _terminalRunIds = new(StringComparer.Ordinal);
    private readonly object _gateLock = new();

    public ImageRepository Images { get; } = new();
    public ProfileMigrationEngine Profiles { get; }
    public ProvisioningTokenService Tokens { get; } = new();

    public ProvisioningService(ChainedAuditLog audit, ManagementPolicyEngine policy,
        Func<string, IDeviceFacts?> facts, SignedCommandSigner? signer, SignedCommandGate? gate,
        ISecretProtector protector, IProfileCaptureSource captureSource,
        IImagingExecutor? imaging = null, IProvisioningEnrollmentSink? enrollment = null,
        Func<JobJournal?>? journalFactory = null, Func<DateTimeOffset>? clock = null)
    {
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _policy = policy ?? throw new ArgumentNullException(nameof(policy));
        _facts = facts ?? throw new ArgumentNullException(nameof(facts));
        _signer = signer;
        _gate = gate;
        _protector = protector ?? throw new ArgumentNullException(nameof(protector));
        _captureSource = captureSource ?? throw new ArgumentNullException(nameof(captureSource));
        _imaging = imaging ?? new UnavailableImagingExecutor();
        // BD-WIN-CORE-3/F7: never a Fake* in production composition.
        _enrollment = enrollment ?? new UnavailableProvisioningEnrollmentSink();
        _journalFactory = journalFactory ?? (() => new JobJournal());
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
        Profiles = new ProfileMigrationEngine(_protector);
        // TOTAL POLICY CONTROL: register the destructive-run toggle
        // seeded OFF. An explicit policy "true" is the only enable.
        _policy.Registry.Register(new FeatureToggle(
            ProvisioningPolicyKeys.ProvisioningEnabled, "RMM-29", false,
            "OS imaging / provisioning runs (DESTRUCTIVE — explicit enable required; default OFF)"));
    }

    /// <summary>Whether the vault machinery sealing profiles is real
    /// protection (DPAPI) or the dev pass-through — surfaced, never
    /// hidden.</summary>
    public bool ProfileProtectionIsReal => Profiles.IsRealProtection;

    private bool PolicyEnabledFor(string deviceId)
    {
        var facts = _facts(deviceId);
        return facts is not null && _policy.IsEnabled(facts, ProvisioningPolicyKeys.ProvisioningEnabled);
    }

    // ---- endpoint-local acceptance --------------------------------

    /// <summary>Record that the endpoint itself accepted
    /// provisioning (the endpoint-local consent artefact). Without
    /// this record the runner refuses every run for the device.</summary>
    public void RecordDeviceAcceptance(string deviceId, string acceptedBy)
    {
        lock (_gateLock) _acceptedDevices.Add(deviceId ?? "");
        _audit.Append("provisioning_device_accepted", acceptedBy ?? "endpoint",
            $"device={deviceId} acceptance recorded endpoint-locally", _clock());
    }

    public bool DeviceAccepted(string deviceId)
    {
        lock (_gateLock) return _acceptedDevices.Contains(deviceId ?? "");
    }

    // ---- image definitions ------------------------------------------

    public ProvisioningVerdict AdmitImage(OsImageDefinition image, string actor)
    {
        var refusal = Images.Admit(image);
        if (refusal is not null) return new ProvisioningVerdict(false, refusal);
        _audit.Append("provisioning_image_admitted", actor,
            $"image={image.Id} v{image.Version} hash={image.ContentHash} apps={string.Join(",", image.ApplicationPackages)} policies={string.Join(",", image.PolicyDocumentIds)} runbook={image.PostProvisionRunbookId ?? "none"}", _clock());
        return new ProvisioningVerdict(true, $"image '{image.Id}' v{image.Version} admitted (content hash {image.ContentHash})");
    }

    public ProvisioningVerdict RevokeImage(string id, string version, string actor)
    {
        if (!Images.Revoke(id, version))
            return new ProvisioningVerdict(false, $"image '{id}' v{version} is not admitted — nothing to revoke");
        _audit.Append("provisioning_image_revoked", actor, $"image={id} v{version}", _clock());
        return new ProvisioningVerdict(true, $"image '{id}' v{version} revoked — new authorizations and in-flight applies refuse");
    }

    // ---- cross-user restore decisions -------------------------------

    public ProvisioningVerdict RecordCrossUserDecision(CrossUserRestoreDecision decision, string actor)
    {
        if (decision is null || string.IsNullOrWhiteSpace(decision.Id))
            return new ProvisioningVerdict(false, "a cross-user decision needs an id — refused");
        if (string.IsNullOrWhiteSpace(decision.ApprovedBy) ||
            string.Equals(decision.ApprovedBy, decision.RequestedBy, StringComparison.OrdinalIgnoreCase))
            return new ProvisioningVerdict(false, "a cross-user decision needs an approver distinct from its requester — refused (self-approval is a silent restore)");
        // F6: the register is audited, so the CALLER must be the
        // approver — a requester (or anyone else) cannot write
        // "approved_by=someone-else" into the register on the
        // approver's behalf.
        if (!string.Equals(actor, decision.ApprovedBy, StringComparison.OrdinalIgnoreCase))
            return new ProvisioningVerdict(false, "only the decision's approver may record it — the recording actor is not the approver named in the decision; refused");
        lock (_gateLock)
        {
            // F6: entries are never silently overwritten — an id
            // already recorded with DIFFERENT content refuses; an
            // identical re-record is an idempotent no-op.
            if (_crossUserDecisions.TryGetValue(decision.Id, out var existing) &&
                !existing.Equals(decision))
                return new ProvisioningVerdict(false, $"a cross-user decision with id '{decision.Id}' is already recorded with different content — decisions are never silently overwritten; refused (record a new decision under a new id)");
            _crossUserDecisions[decision.Id] = decision;
        }
        _audit.Append("provisioning_cross_user_decision", actor,
            $"decision={decision.Id} from_user={decision.SourceUserId} to_user={decision.TargetUserId} requested_by={decision.RequestedBy} approved_by={decision.ApprovedBy} reason={decision.Reason}", _clock());
        return new ProvisioningVerdict(true, $"cross-user decision '{decision.Id}' recorded ({decision.SourceUserId} → {decision.TargetUserId}, approved by {decision.ApprovedBy})");
    }

    // ---- bare-metal tokens ------------------------------------------

    /// <summary>Mint a one-time provisioning token bound to an
    /// admitted, non-revoked image. Returns the code ONCE.</summary>
    public (string? Code, ProvisioningVerdict Verdict) MintProvisioningToken(
        string imageId, string imageVersion, string scopeId, string mintedBy)
    {
        var image = Images.Get(imageId, imageVersion);
        if (image is null) return (null, new ProvisioningVerdict(false, $"image '{imageId}' v{imageVersion} is not admitted — no token minted"));
        if (Images.IsRevoked(imageId, imageVersion)) return (null, new ProvisioningVerdict(false, $"image '{imageId}' v{imageVersion} is revoked — no token minted"));
        var code = Tokens.Mint(imageId, imageVersion, image.ContentHash, scopeId, mintedBy, _clock());
        _audit.Append("provisioning_token_minted", mintedBy,
            $"image={imageId} v{imageVersion} hash={image.ContentHash} scope={scopeId} (code shown once; only its hash is retained)", _clock());
        return (code, new ProvisioningVerdict(true, "provisioning token minted (single-use, expiring, image-bound)"));
    }

    // ---- authorization + run -----------------------------------------

    private ProvisioningRunner NewRunner() => new(_gate, _audit, Profiles, _captureSource,
        _imaging, _enrollment, Tokens, Images.Get, Images.IsRevoked, DeviceAccepted,
        id => { lock (_gateLock) return _crossUserDecisions.TryGetValue(id ?? "", out var d) ? d : null; },
        // F5: the device's scope (from its inventory facts) — the
        // runner checks the token's mint scope against it.
        id => _facts(id)?.ScopeId,
        // F8: the device is known to hold user profiles when its
        // inventory facts carry the RMM-04 attribute
        // "profile_present=true" — such a device refuses
        // bare-metal (capture-first reimage is the only path).
        id => _facts(id)?.Attributes is { } attrs &&
              attrs.TryGetValue("profile_present", out var v) &&
              string.Equals(v, "true", StringComparison.OrdinalIgnoreCase));

    /// <summary>Authorize + execute one provisioning run. The
    /// service checks policy BEFORE minting; the runner re-checks
    /// everything endpoint-side. Returns the run result (its State
    /// is always a NAMED ProvisioningStates value).</summary>
    public ProvisioningRunResult RunProvisioning(ProvisioningRunRequest request, string requestedBy,
        bool resume = false)
    {
        var now = _clock();
        if (_facts(request.DeviceId) is null)
        {
            _audit.Append("provisioning_refused", requestedBy,
                $"run={request.RunId} device={request.DeviceId} reason=unknown device (no inventory facts) — refused", now);
            return new ProvisioningRunResult(request.RunId, request.DeviceId, request.Image.Id,
                request.Image.Version, request.Image.ContentHash, request.Mode,
                ProvisioningStates.Refused, "unknown device (no inventory facts) — refused", null, null, null, now);
        }
        if (!PolicyEnabledFor(request.DeviceId))
        {
            _audit.Append("provisioning_refused", requestedBy,
                $"run={request.RunId} device={request.DeviceId} reason=policy 'rmm.provisioning.enabled' is not explicitly enabled for this device (seeded OFF) — refused", now);
            return new ProvisioningRunResult(request.RunId, request.DeviceId, request.Image.Id,
                request.Image.Version, request.Image.ContentHash, request.Mode,
                ProvisioningStates.Refused,
                "policy 'rmm.provisioning.enabled' is not explicitly enabled for this device (seeded OFF) — refused",
                null, null, null, now);
        }
        if (_signer is null)
        {
            _audit.Append("provisioning_refused", requestedBy,
                $"run={request.RunId} device={request.DeviceId} reason=no command signer wired — provisioning refuses rather than run unsigned", now);
            return new ProvisioningRunResult(request.RunId, request.DeviceId, request.Image.Id,
                request.Image.Version, request.Image.ContentHash, request.Mode,
                ProvisioningStates.Refused, "no command signer wired — refused", null, null, null, now);
        }
        // F2/F12: a completed run id is terminal at the service
        // too — it never executes again under either verb.
        lock (_gateLock)
        {
            if (_terminalRunIds.Contains(request.RunId))
            {
                _audit.Append("provisioning_refused", requestedBy,
                    $"run={request.RunId} device={request.DeviceId} reason=run id already completed — a run id is single-execution; use a fresh run id", now);
                return new ProvisioningRunResult(request.RunId, request.DeviceId, request.Image.Id,
                    request.Image.Version, request.Image.ContentHash, request.Mode,
                    ProvisioningStates.Refused,
                    $"run id '{request.RunId}' already completed — a run id is single-execution; provision under a fresh run id (refused)",
                    null, null, null, now);
            }
            // F10: one execution per run id at a time — a second
            // concurrent call refuses instead of racing the runner.
            if (!_inFlightRuns.Add(request.RunId))
            {
                _audit.Append("provisioning_refused", requestedBy,
                    $"run={request.RunId} device={request.DeviceId} reason=run already in flight", now);
                return new ProvisioningRunResult(request.RunId, request.DeviceId, request.Image.Id,
                    request.Image.Version, request.Image.ContentHash, request.Mode,
                    ProvisioningStates.Refused,
                    $"run id '{request.RunId}' is already in flight — concurrent execution of one run id is refused",
                    null, null, null, now);
            }
        }
        try
        {
            var payload = ProvisioningBinding.Payload(request.RunId, request.Image, request.DeviceId,
                request.CaptureManifest is null ? null : ProvisioningBinding.CaptureManifestHash(request.CaptureManifest),
                request.Mode, request.TargetUserId, request.CrossUserDecision?.Id);
            var envelope = _signer.Sign(SignedCommandClasses.Provisioning,
                Encoding.UTF8.GetBytes(payload), now, EnvelopeTtl);
            _audit.Append(resume ? "provisioning_resume_authorized" : "provisioning_authorized", requestedBy,
                $"run={request.RunId} device={request.DeviceId} image={request.Image.Id} v{request.Image.Version} hash={request.Image.ContentHash} mode={request.Mode}", now);
            // One runner per run id, kept on the service: a resume must
            // continue the SAME run record (and its captured profile).
            ProvisioningRunner runner;
            lock (_gateLock)
            {
                if (!_runnersByRun.TryGetValue(request.RunId, out runner!))
                {
                    runner = NewRunner();
                    _runnersByRun[request.RunId] = runner;
                }
            }
            var journal = _journalFactory();
            var result = resume
                ? runner.ResumeRun(request, envelope, journal, () => PolicyEnabledFor(request.DeviceId), now)
                : runner.Run(request, envelope, journal, () => PolicyEnabledFor(request.DeviceId), now);
            // F12: a completed run's runner (and its captured
            // profile blobs) is pruned; the id stays terminal.
            // Failed / parked / refused runs keep their runner —
            // the record is exactly what a resume (or a park
            // decision) needs, and a refusal ABOUT a call must
            // never destroy the run it refused to touch.
            lock (_gateLock)
            {
                if (result.State == ProvisioningStates.Completed)
                {
                    _runnersByRun.Remove(request.RunId);
                    _terminalRunIds.Add(request.RunId);
                }
            }
            return result;
        }
        finally
        {
            lock (_gateLock) _inFlightRuns.Remove(request.RunId);
        }
    }

    /// <summary>F1: record the human decision for a run parked on
    /// an uncertain apply (see ProvisioningRunner.ResolveParkedApply).
    /// FailRun also prunes the runner and marks the id terminal.</summary>
    public ProvisioningVerdict ResolveParkedApply(string runId, ProvisioningParkDecision decision, string decidedBy)
    {
        ProvisioningRunner? runner;
        lock (_gateLock) _runnersByRun.TryGetValue(runId ?? "", out runner);
        if (runner is null)
            return new ProvisioningVerdict(false, $"no live run with id '{runId}' — nothing is parked under that id");
        if (!runner.ResolveParkedApply(runId, decision, decidedBy, _clock()))
            return new ProvisioningVerdict(false, $"run '{runId}' is not parked on an uncertain apply — no decision recorded");
        if (decision == ProvisioningParkDecision.FailRun)
        {
            lock (_gateLock)
            {
                _runnersByRun.Remove(runId);
                _terminalRunIds.Add(runId);
            }
            return new ProvisioningVerdict(true, $"run '{runId}' failed by human decision — the device is treated as not provisioned");
        }
        return new ProvisioningVerdict(true, $"run '{runId}': retry of the apply step authorized — resume the run to make the attempt");
    }
}
