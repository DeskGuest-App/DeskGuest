using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DeskGuest.Shared.Distribution;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.Inventory;
using DeskGuest.Shared.Jobs;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.Patching;
using DeskGuest.Shared.Security;

namespace DeskGuest.Core.Services;

// =====================================================================
// RMM-02 — PatchService: the Core wiring for patch management.
//
// Owns, per endpoint, in the Core data-dir shape:
//   * the curated PatchCatalogue (hub-admin content; admitted via
//     signed delivery or the audited local path — never fetched);
//   * the PatchApprovalStore (every decision chained-audited);
//   * the RolloutPlanStore (rings; thresholds; halted states);
//   * the endpoint-SIGNED JobJournal (RMM-15) persisted at
//     <dataDir>/patch-jobs/journal.json — constructed with the
//     endpoint DeviceIdentity and the enterprise chained-audit
//     sink, per the RMM-15 lane's consumption contract;
//   * the RMM-14 PeerContentStore + ContentFetcher fetch path.
//
// Durability (D38 fix lane, packet 11e17009):
//   * the journal is WAL-attached from construction, so EVERY
//     journal append — including step_started for the
//     non-idempotent apply step — is fsynced to disk BEFORE the
//     mutating call returns, and Deploy additionally checkpoints
//     the full journal and refuses to enter apply when the
//     checkpoint or the WAL reports a persistence failure (F1);
//   * catalogue, approval decisions, rollout plans (states,
//     outcomes, halts, resume baselines), retirement tombstones,
//     reboot deferral counts and per-content applied anchors are
//     persisted to <dataDir>/patch-state.json (fsync + rename) on
//     every mutation and restored at construction (F3/F12). A
//     state file that does not load cleanly puts the service in a
//     named BROKEN state that refuses deployment and decisions —
//     a restart must never silently resurrect a rejected patch or
//     un-halt a ring by forgetting them.
//
// On start/reconnect: journal LoadFromFile → ResumeAll with the
// resume toggle read from ManagementPolicyService (RMM-07) and the
// customer key ring supplied so envelope authority is signature-
// rechecked. Parked jobs are reported, NEVER auto-resolved.
//
// Deployment is fail-closed at every gate, in order: policy toggle
// (rmm.patch.enabled) → persisted-state health → catalogue entry
// exists → payload pin → approval currency (checked, NEVER
// re-derived at deploy time — D38 F6: auto-evaluation is an
// explicit, audited act that happens before a deploy is attempted,
// so a catalogue edit cannot launder itself into an approval as a
// side effect of deploying) → ring gate (including halts recorded
// against EARLIER content revisions of the same entry — D38 F4)
// → RMM-03 signed envelope bound to THIS entry + device +
// content hash → PatchRun job (fetch via RMM-14 → verify →
// applier plan over the VERIFIED bytes materialised from the
// content store — D38 F2 → verify plan → reboot gate).
// Ring SUCCESS is recorded only by ConfirmInstall, on install
// evidence presented by host wiring — never by plan construction
// (D38 F5). Live patch execution is host wiring: the applier
// builds command plans here; the plans execute via the
// signed-command gate on the endpoint. Live patching proof is
// PENDING.
// =====================================================================
public sealed class PatchService
{
    private readonly ChainedAuditLog _audit;
    private readonly ManagementPolicyService _policies;
    private readonly SignedCommandGate? _gate;
    private readonly CustomerCommandKeyRing? _ring;
    private readonly Func<DateTimeOffset> _now;
    private readonly string _dataDir;
    private readonly string _journalPath;
    private readonly string _statePath;
    private readonly Dictionary<string, int> _deferrals = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DateTimeOffset> _appliedUtc = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _deferralGate = new();
    private readonly object _stateGate = new();
    private string? _stateBroken;

    public PatchCatalogue Catalogue { get; private set; } = new();
    public PatchApprovalStore Approvals { get; private set; } = new();
    public RolloutPlanStore Rollouts { get; private set; } = new();
    public JobJournal Journal { get; }
    public PeerContentStore ContentStore { get; private set; } = new();
    public ContentFetcher Fetcher { get; } = new();

    // BD-WIN-CORE-3/F12(b): the approval + reboot policies are no
    // longer silent public setters. Setting one is AUDITED and
    // PERSISTED with the rest of the patch state, and LoadState
    // restores them — a restart no longer quietly resets deferral
    // limits or auto-approve rules to defaults.
    private ApprovalPolicy _approvalPolicy = ApprovalPolicy.ManualOnly;
    private RebootPolicy _rebootPolicy = RebootPolicy.Default;
    public ApprovalPolicy ApprovalPolicy
    {
        get => _approvalPolicy;
        set
        {
            _approvalPolicy = value ?? ApprovalPolicy.ManualOnly;
            _audit.Append("patch_approval_policy_changed", "patch-service",
                $"rules={_approvalPolicy.Rules?.Count ?? 0}", _now());
            SaveState();
        }
    }
    public RebootPolicy RebootPolicy
    {
        get => _rebootPolicy;
        set
        {
            _rebootPolicy = value ?? RebootPolicy.Default;
            _audit.Append("patch_reboot_policy_changed", "patch-service",
                $"maxDeferrals={_rebootPolicy.MaxDeferrals} enforceCritical={_rebootPolicy.EnforceCritical} deadlineHours={_rebootPolicy.EnforcementDeadlineHours}", _now());
            SaveState();
        }
    }

    public PatchService(string dataDir, ChainedAuditLog audit, ManagementPolicyService policies,
        SignedCommandGate? gate, DeviceIdentity endpointIdentity, CustomerCommandKeyRing? ring = null,
        Func<DateTimeOffset>? now = null)
    {
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _policies = policies ?? throw new ArgumentNullException(nameof(policies));
        _gate = gate;
        _ring = ring;
        _now = now ?? (() => DateTimeOffset.UtcNow);
        _dataDir = dataDir ?? throw new ArgumentNullException(nameof(dataDir));
        // bd-shared-plat-2/F9 (W9 wiring): the P2P content store is
        // disk-backed under the patch data dir — verified payloads
        // (and the revocation set) survive a Core restart instead
        // of living only in this process's memory.
        ContentStore = new PeerContentStore(
            revocationFilePath: Path.Combine(dataDir, "p2p-revocations.json"),
            contentDirectory: Path.Combine(dataDir, "p2p-content"));
        _journalPath = Path.Combine(dataDir, "patch-jobs", "journal.json");
        _statePath = Path.Combine(dataDir, "patch-state.json");
        Journal = new JobJournal(endpointIdentity,
            (kind, actor, detail) => _audit.Append(kind, actor ?? "patch-service", detail ?? "", _now()));
        // F1: write-ahead persistence from the FIRST append, not
        // from the first Start — a Deploy that runs before any
        // Start (or after a Start that already happened) journals
        // every step transition to disk before the step runs.
        Journal.AttachPersistence(_journalPath);
        LoadState();
    }

    public string JournalPath => _journalPath;
    public string StatePath => _statePath;

    /// <summary>Named health of the persisted patch state:
    /// "fresh…", "loaded: …", or "BROKEN: …" (deployments and
    /// decisions refuse while BROKEN — fail closed).</summary>
    public string StateStoreState { get; private set; } = "not loaded yet";

    public bool IsPatchEnabled(IDeviceFacts facts) => _policies.IsEnabled(facts, "rmm.patch.enabled");
    public bool IsResumeEnabled(IDeviceFacts facts) => _policies.IsEnabled(facts, "rmm.job_resume.enabled");

    // ---- persisted state (D38 F3/F12) -------------------------------

    private sealed record PatchStateFile(
        List<PatchCatalogueEntry> Catalogue,
        List<ApprovalDecisionRecord> Approvals,
        List<RolloutPlan.Dto> Plans,
        Dictionary<string, long> RetiredFloors,
        Dictionary<string, int> Deferrals,
        Dictionary<string, DateTimeOffset> AppliedUtc,
        // BD-WIN-CORE-3/F12(b): persisted policies (null in state
        // files written before this fix — defaults then apply).
        ApprovalPolicy? ApprovalPolicy = null,
        RebootPolicy? RebootPolicy = null);

    private void LoadState()
    {
        if (!File.Exists(_statePath))
        {
            StateStoreState = "fresh: no patch state file yet (first boot)";
            return;
        }
        try
        {
            var file = JsonSerializer.Deserialize<PatchStateFile>(File.ReadAllText(_statePath))
                ?? throw new InvalidOperationException("patch state parsed to null");
            // Build into fresh stores and commit only on a fully
            // clean load: a half-restored state (approvals without
            // their catalogue, plans without their halts) is worse
            // than a named refusal.
            var catalogue = new PatchCatalogue();
            foreach (var (id, floor) in file.RetiredFloors ?? new Dictionary<string, long>())
                catalogue.RestoreRetiredFloor(id, floor);
            foreach (var entry in file.Catalogue ?? new List<PatchCatalogueEntry>())
            {
                var (accepted, reason) = catalogue.AddOrReplace(entry);
                if (!accepted)
                    throw new InvalidOperationException($"persisted catalogue entry '{entry?.Id}' refused on restore: {reason}");
            }
            var approvals = new PatchApprovalStore();
            approvals.Restore(file.Approvals ?? new List<ApprovalDecisionRecord>());
            var rollouts = new RolloutPlanStore();
            foreach (var dto in file.Plans ?? new List<RolloutPlan.Dto>())
            {
                var plan = RolloutPlan.Restore(dto);
                var (added, reason) = rollouts.Add(plan);
                if (!added)
                    throw new InvalidOperationException($"persisted rollout plan '{dto.Id}' refused on restore: {reason}");
            }
            Catalogue = catalogue;
            Approvals = approvals;
            Rollouts = rollouts;
            // BD-WIN-CORE-3/F12(b): restore persisted policies
            // directly to the backing fields (no audit/save cycle
            // during load — the load itself is the record).
            if (file.ApprovalPolicy is not null) _approvalPolicy = file.ApprovalPolicy;
            if (file.RebootPolicy is not null) _rebootPolicy = file.RebootPolicy;
            _deferrals.Clear();
            foreach (var (k, v) in file.Deferrals ?? new Dictionary<string, int>()) _deferrals[k] = v;
            _appliedUtc.Clear();
            foreach (var (k, v) in file.AppliedUtc ?? new Dictionary<string, DateTimeOffset>()) _appliedUtc[k] = v;
            StateStoreState = $"loaded: {Catalogue.All.Count} catalogue entr(ies), {Approvals.Records.Count} decision(s), {Rollouts.All.Count} rollout plan(s), {_deferrals.Count} deferral record(s) restored from disk";
        }
        catch (Exception ex)
        {
            _stateBroken = $"patch state at '{_statePath}' did not load ({ex.GetType().Name}: {ex.Message}) — deployments and decisions refuse until the state is repaired (fail closed: a restart must never resurrect a rejected patch or un-halt a ring by forgetting them)";
            StateStoreState = "BROKEN: " + _stateBroken;
        }
    }

    /// <summary>Persist every mutation (fsync + rename). A failed
    /// save marks the state BROKEN: memory and disk have diverged,
    /// and the honest posture from there is refusal, not hope.</summary>
    private bool SaveState()
    {
        lock (_stateGate)
        {
            if (_stateBroken is not null) return false;
            try
            {
                var file = new PatchStateFile(
                    Catalogue.All.ToList(),
                    Approvals.Records.ToList(),
                    Rollouts.All.Select(p => p.Export()).ToList(),
                    new Dictionary<string, long>(Catalogue.RetiredFloors, StringComparer.OrdinalIgnoreCase),
                    new Dictionary<string, int>(_deferrals, StringComparer.OrdinalIgnoreCase),
                    new Dictionary<string, DateTimeOffset>(_appliedUtc, StringComparer.OrdinalIgnoreCase));
                Directory.CreateDirectory(_dataDir);
                var tmp = _statePath + ".tmp";
                var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(file));
                using (var fs = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    fs.Write(bytes, 0, bytes.Length);
                    fs.Flush(true);
                }
                File.Move(tmp, _statePath, overwrite: true);
                return true;
            }
            catch (Exception ex)
            {
                _stateBroken = $"patch state could not be persisted ({ex.GetType().Name}: {ex.Message}) — the in-memory change is NOT durable, so deployments and decisions refuse from here (fail closed)";
                StateStoreState = "BROKEN: " + _stateBroken;
                return false;
            }
        }
    }

    private string? StateBrokenRefusal() => _stateBroken is null ? null :
        $"persisted patch state is BROKEN — {_stateBroken}";

    /// <summary>Persist the current state NOW. Service operations
    /// persist their own mutations; host wiring that manipulates a
    /// plan object directly (StartRing, RecordOutcome outside
    /// Deploy/ConfirmInstall) calls this to make that change
    /// durable before it is relied on.</summary>
    public bool CheckpointState() => SaveState();

    // ---- lifecycle -------------------------------------------------

    /// <summary>Start/reconnect pass (the RMM-15 consumption
    /// contract): load the persisted journal, then ResumeAll with
    /// policy-supplied resume enablement and the customer ring for
    /// authority recheck. The report is chained-audited; parked
    /// jobs surface in it and are left for a human.</summary>
    private bool _journalLoaded;
    private readonly object _startGate = new();

    public ResumeReport Start(IDeviceFacts facts)
    {
        var now = _now();
        // Closing integration fix (RMM-14/15 recovery lane remainder):
        // Start is idempotent-safe. The FIRST Start loads the persisted
        // journal (D38 F5/F6 semantics preserved: LoadFromFile names a
        // missing-file-with-surviving-anchor as journal_lost). Later
        // Starts do NOT re-import: LoadFromFile resets the journal's
        // live-execution flag and reloads on-disk state, so a
        // mid-execution Start would clobber live jobs. Subsequent
        // passes resume from the in-memory journal only.
        lock (_startGate)
        {
            if (!_journalLoaded)
            {
                Journal.LoadFromFile(_journalPath);
                _journalLoaded = true;
            }
        }
        var report = Journal.ResumeAll(now, () => IsResumeEnabled(facts), _ring);
        _audit.Append("patch_journal_resumed", "patch-service",
            $"chainOk={report.ChainOk} authorityRechecked={report.AuthorityRechecked} resumed={report.ResumedCount} outcomes={report.Outcomes.Count}", now);
        SaveJournal();
        return report;
    }

    public JobStateReport BuildStateReport(IDeviceFacts facts) =>
        Journal.BuildStateReport(facts.DeviceId, () => IsResumeEnabled(facts), _now());

    private bool SaveJournal()
    {
        try { Journal.SaveToFile(_journalPath); return true; }
        catch { return false; /* persistence failure surfaces on next Start's chain check — and Deploy checks this return before the non-idempotent step (F1) */ }
    }

    // ---- catalogue -------------------------------------------------

    /// <summary>Admit catalogue entries over the audited local path
    /// (admin-curated content placed on the hub). Every admission
    /// and refusal is a chained audit event.</summary>
    public (bool Ok, string Reason) AdmitEntries(IEnumerable<PatchCatalogueEntry> entries, string via)
    {
        if (StateBrokenRefusal() is { } broken) return (false, broken);
        var now = _now();
        var results = new List<string>();
        var allOk = true;
        var anyAccepted = false;
        foreach (var entry in entries)
        {
            var (ok, reason) = Catalogue.AddOrReplace(entry);
            allOk &= ok;
            anyAccepted |= ok;
            results.Add(reason);
            _audit.Append(ok ? "patch_catalogue_admitted" : "patch_catalogue_refused", "patch-service",
                $"entry={entry?.Id} via={via} reason={reason}", now);
        }
        if (anyAccepted && !SaveState())
            return (false, $"catalogue admission could not be persisted — {StateStoreState}");
        return (allOk, string.Join("; ", results));
    }

    /// <summary>Retire a catalogue entry (audited): it leaves
    /// service, and its revision floor is tombstoned + persisted,
    /// so the entry's old revisions — and the approvals bound to
    /// them — can never be re-admitted back into service (F10).</summary>
    public (bool Ok, string Reason) RetireEntry(string entryId, string via)
    {
        if (StateBrokenRefusal() is { } broken) return (false, broken);
        var now = _now();
        if (!Catalogue.Retire(entryId))
            return (false, $"unknown catalogue entry '{entryId}' — nothing to retire");
        _audit.Append("patch_catalogue_retired", "patch-service", $"entry={entryId} via={via}", now);
        if (!SaveState())
            return (false, $"retirement of '{entryId}' could not be persisted — {StateStoreState}");
        return (true, $"catalogue entry '{entryId}' retired; its revision floor is tombstoned");
    }

    /// <summary>Admit a WinGet-shaped manifest the admin provided
    /// as local content. Parse is atomic (a bad manifest imports
    /// nothing); admission then applies per entry.</summary>
    public (bool Ok, string Reason) ImportWinGetManifest(string json, long revision, string via)
    {
        var parsed = WinGetManifestImport.Parse(json, revision);
        if (!parsed.Ok)
        {
            _audit.Append("patch_catalogue_refused", "patch-service", $"manifest via={via} reason={parsed.Reason}", _now());
            return (false, parsed.Reason);
        }
        return AdmitEntries(parsed.Entries, via);
    }

    /// <summary>Signed catalogue delivery: the catalogue JSON rides
    /// a patch_deploy envelope; the RMM-03 gate verifies BEFORE the
    /// payload is parsed (a compromised hub cannot deliver
    /// catalogue content either).</summary>
    public (bool Ok, string Reason) ImportCatalogueSigned(SignedCommandEnvelope? envelope)
    {
        var now = _now();
        if (_gate is null)
            return (false, "no customer command key is configured on this endpoint — signed catalogue delivery refuses (RMM-03)");
        var verdict = _gate.Authorize(envelope, now, SignedCommandClasses.PatchDeploy);
        if (!verdict.Allowed) return (false, verdict.Reason);
        List<PatchCatalogueEntry>? entries;
        try { entries = JsonSerializer.Deserialize<List<PatchCatalogueEntry>>(Encoding.UTF8.GetString(verdict.Payload!)); }
        catch { entries = null; }
        if (entries is null)
        {
            const string reason = "signed catalogue payload did not parse as catalogue entries — refused";
            _audit.Append("patch_catalogue_refused", "patch-service", reason, now);
            return (false, reason);
        }
        return AdmitEntries(entries, "signed delivery");
    }

    // ---- scan --------------------------------------------------------

    public (bool Ok, string Reason, IReadOnlyList<MissingPatch> Missing) Scan(IDeviceFacts facts, DeviceInventoryRecord record)
    {
        if (!IsPatchEnabled(facts))
            return (false, "patch management is disabled by policy for this device (rmm.patch.enabled) — scan refuses", Array.Empty<MissingPatch>());
        var missing = PatchScanner.DetermineMissing(record, Catalogue);
        _audit.Append("patch_scan", "patch-service",
            $"device={record.DeviceId} missing={missing.Count} entries={string.Join(",", missing.Select(m => m.EntryId))}", _now());
        return (true, $"scan complete: {missing.Count} missing patch(es) for '{record.DeviceId}'", missing);
    }

    // ---- approvals ---------------------------------------------------

    /// <summary>Record a human approval/rejection. Who/when is the
    /// audit contract: the decision record and the chained audit
    /// entry both carry the decider. <paramref name="supersede"/>
    /// is the explicit revocation path (D38 F7): it appends a new
    /// decision that overrides a standing contradicting one at the
    /// same scope — the only way an approval (or a reject) for the
    /// SAME content is ever taken back.</summary>
    public (bool Ok, string Reason) Decide(IDeviceFacts facts, string entryId, string deviceScope, bool approve, string decidedBy, bool supersede = false)
    {
        if (StateBrokenRefusal() is { } broken) return (false, broken);
        var now = _now();
        var entry = Catalogue.Get(entryId);
        if (entry is null) return (false, $"unknown catalogue entry '{entryId}' — no decision can be recorded against content that does not exist");
        var record = new ApprovalDecisionRecord(entry.Id, entry.ContentHash, deviceScope,
            approve ? ApprovalDecisions.Approved : ApprovalDecisions.Rejected,
            decidedBy, now, approve ? "manual approval" : "manual rejection");
        var (ok, reason) = Approvals.Record(record, supersede);
        _audit.Append(ok ? (approve ? "patch_approved" : "patch_rejected") : "patch_decision_refused", decidedBy,
            $"entry={entry.Id} scope={deviceScope} content={entry.ContentHash[..12]}… supersede={supersede} reason={reason}", now);
        if (ok && !SaveState())
            return (false, $"decision recorded in memory but could NOT be persisted — treated as not durable: {StateStoreState}");
        return (ok, reason);
    }

    /// <summary>Run the approval rules for one entry+device. An
    /// auto-approve or rule-reject is RECORDED (the rule is the
    /// actor); RequireManual records nothing and reports pending.
    /// This is an explicit, audited act — Deploy NEVER calls it
    /// (D38 F6): evaluation happens when an operator/policy pass
    /// asks for it, against the content that stands at that
    /// moment, and the recorded decision binds that content hash.</summary>
    public (ApprovalMode Mode, string Reason) AutoEvaluate(IDeviceFacts facts, string entryId, string deviceId)
    {
        if (StateBrokenRefusal() is { } broken) return (ApprovalMode.RequireManual, broken);
        var now = _now();
        var entry = Catalogue.Get(entryId);
        if (entry is null) return (ApprovalMode.RequireManual, $"unknown catalogue entry '{entryId}'");
        var (mode, ruleName) = ApprovalPolicy.Evaluate(entry);
        if (mode == ApprovalMode.RequireManual)
            return (mode, $"approval policy requires a manual decision (rule: {ruleName})");
        var before = Approvals.Records.Count;
        var record = new ApprovalDecisionRecord(entry.Id, entry.ContentHash, deviceId,
            mode == ApprovalMode.AutoApprove ? ApprovalDecisions.Approved : ApprovalDecisions.Rejected,
            $"policy:{ruleName}", now, $"auto rule '{ruleName}'");
        var (ok, reason) = Approvals.Record(record);
        _audit.Append(mode == ApprovalMode.AutoApprove ? "patch_approved" : "patch_rejected", $"policy:{ruleName}",
            $"entry={entry.Id} scope={deviceId} content={entry.ContentHash[..12]}… recorded={ok} reason={reason}", now);
        if (ok && Approvals.Records.Count > before && !SaveState())
            return (mode, $"auto decision recorded in memory but could NOT be persisted — treated as not durable: {StateStoreState}");
        return (mode, ok ? $"rule '{ruleName}' decided: {record.Decision}" : reason);
    }

    // ---- deployment --------------------------------------------------

    public sealed record DeployResult(bool Ok, string Reason, string? JobId, RebootDecision? Reboot);

    /// <summary>The expected signed-payload binding for a deploy
    /// envelope: patch_deploy | entry | device | content hash. An
    /// envelope minted for any other patch, device, or content
    /// refuses here even when its signature is genuine.</summary>
    public static string DeployPayload(string entryId, string deviceId, string contentHash) =>
        $"patch_deploy|{entryId}|{deviceId}|{contentHash}";

    /// <summary>Materialise the VERIFIED payload bytes (D38 F2):
    /// the applier's plan is built over the file written from the
    /// content store bytes that just verified against the pin —
    /// never over a caller-supplied path whose contents nothing
    /// checked. The file is content-addressed by the pin itself
    /// and re-verified on reuse.</summary>
    private string MaterializePayload(string payloadHash, byte[] bytes)
    {
        var dir = Path.Combine(_dataDir, "patch-payloads");
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, payloadHash + ".bin");
        if (File.Exists(path))
        {
            var existing = File.ReadAllBytes(path);
            if (Convert.ToHexString(SHA256.HashData(existing)).Equals(payloadHash, StringComparison.OrdinalIgnoreCase))
                return path;
        }
        var tmp = path + ".tmp";
        using (var fs = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            fs.Write(bytes, 0, bytes.Length);
            fs.Flush(true);
        }
        File.Move(tmp, path, overwrite: true);
        return path;
    }

    public DeployResult Deploy(IDeviceFacts facts, string entryId, SignedCommandEnvelope? envelope,
        ContentManifest? manifest, IReadOnlyList<IContentSource> sources, IPatchApplier applier, string payloadPath)
    {
        var now = _now();
        var deviceId = facts.DeviceId;
        DeployResult Refuse(string reason)
        {
            _audit.Append("patch_deploy_refused", "patch-service", $"entry={entryId} device={deviceId} reason={reason}", now);
            return new DeployResult(false, reason, null, null);
        }

        if (!IsPatchEnabled(facts))
            return Refuse("patch management is disabled by policy for this device (rmm.patch.enabled) — deployment refuses (fail closed)");
        if (StateBrokenRefusal() is { } brokenState)
            return Refuse(brokenState);
        var entry = Catalogue.Get(entryId);
        if (entry is null) return Refuse($"unknown catalogue entry '{entryId}' — deployment refuses");
        var payloadCheck = PatchPayloadGate.Check(entry, manifest, null);
        if (!payloadCheck.Ok) return Refuse(payloadCheck.Reason);

        // Approval currency is CHECKED, never manufactured (F6):
        // no standing decision for THIS content ⇒ refusal naming
        // the exact blocker (a standing reject, stale-content
        // approval, or no approval). Auto-evaluation is the
        // separate, audited AutoEvaluate act.
        var approval = Approvals.CheckCurrent(entry, deviceId);
        if (!approval.Approved) return Refuse(approval.Reason);

        var plans = Rollouts.PlansFor(entry.Id, entry.ContentHash, deviceId);
        foreach (var plan in plans)
        {
            var ringName = plan.RingOf(deviceId)!;
            var status = plan.StatusOf(ringName);
            if (status.State != RingStates.InProgress)
                return Refuse($"rollout plan '{plan.Id}' ring '{ringName}' is {status.State} — deployment to this device is gated by its ring (a halted ring deploys nothing; resuming it is a new signed decision)");
        }
        // F4: a halt recorded against an EARLIER revision of this
        // entry gates this device for EVERY revision until the
        // halted plan is resumed by its own signed decision.
        foreach (var halted in Rollouts.HaltedForEntry(entry.Id, deviceId))
            return Refuse($"rollout plan '{halted.Id}' has a HALTED ring covering device '{deviceId}' for entry '{entry.Id}' under an earlier content revision — a catalogue edit does not lift a halt; resume the halted plan with a fresh signed decision before this device deploys any revision of this entry");

        if (_gate is null)
            return Refuse("no customer command key is configured on this endpoint — patch deployment refuses (RMM-03: unsigned commands never execute)");
        var verdict = _gate.Authorize(envelope, now, SignedCommandClasses.PatchDeploy);
        if (!verdict.Allowed) return Refuse(verdict.Reason);
        var payloadText = Encoding.UTF8.GetString(verdict.Payload!);
        if (payloadText != DeployPayload(entry.Id, deviceId, entry.ContentHash))
            return Refuse("the signed envelope does not bind THIS patch, device and content (payload binding mismatch) — refused (an envelope minted for another patch or device never deploys this one)");

        var job = Journal.CreateJob(JobKinds.PatchRun, deviceId, PatchRunSteps.For(entry), envelope, now);
        if (job is null) return Refuse("the job journal refused the patch run (envelope class/expiry or step shape) — deployment refuses");
        Journal.StartJob(job.Id, now);

        string Fail(string step, string reason)
        {
            Journal.FailStep(job.Id, step, reason, now);
            foreach (var plan in plans)
            {
                var ringName = plan.RingOf(deviceId)!;
                var (recorded, recordReason) = plan.RecordOutcome(ringName, deviceId, false, now);
                if (!recorded)
                    _audit.Append("patch_ring_outcome_unrecorded", "patch-service",
                        $"entry={entry.Id} device={deviceId} plan={plan.Id} ring={ringName} outcome=failure reason={recordReason}", now);
            }
            _audit.Append("patch_deploy_failed", "patch-service", $"entry={entry.Id} device={deviceId} job={job.Id} step={step} reason={reason}", now);
            SaveJournal();
            SaveState();
            return reason;
        }

        // fetch (idempotent, content-addressed)
        Journal.BeginStep(job.Id, PatchRunSteps.Fetch, now);
        if (manifest is not null)
        {
            var fetch = Fetcher.Fetch(manifest, sources, ContentStore, h => ContentStore.IsRevoked(h));
            if (!fetch.Ok) return new DeployResult(false, Fail(PatchRunSteps.Fetch, fetch.Reason), job.Id, null);
        }
        Journal.CompleteStep(job.Id, PatchRunSteps.Fetch, now);

        // verify payload (idempotent, pure check against the pin)
        Journal.BeginStep(job.Id, PatchRunSteps.VerifyPayload, now);
        byte[]? verifiedBytes = null;
        if (entry.PayloadHash is not null)
        {
            verifiedBytes = ContentStore.GetWhole(entry.PayloadHash);
            if (verifiedBytes is null || manifest is null || !manifest.VerifyWhole(verifiedBytes))
                return new DeployResult(false, Fail(PatchRunSteps.VerifyPayload, "fetched payload does not verify against the catalogue pin — deployment stops before apply"), job.Id, null);
        }
        Journal.CompleteStep(job.Id, PatchRunSteps.VerifyPayload, now);

        // F2: the apply plan is built over the VERIFIED bytes,
        // materialised from the content store under their pin.
        // For a pinned entry the caller's payloadPath is ignored
        // entirely. For an OS-channel entry (no pin, no DeskGuest
        // payload) payloadPath names the OS channel's own media —
        // there are no DeskGuest bytes to substitute.
        var effectivePayloadPath = verifiedBytes is not null
            ? MaterializePayload(entry.PayloadHash!, verifiedBytes)
            : payloadPath;

        // apply (NON-idempotent: the journal parks this run if the
        // process dies mid-step — see PatchRunSteps). F1: the
        // step_started entry must be DURABLE before the applier is
        // touched — the journal is WAL-attached (every append
        // fsyncs), and this full checkpoint must also succeed; a
        // persistence failure here stops the deploy BEFORE apply,
        // never after it.
        Journal.BeginStep(job.Id, PatchRunSteps.Apply, now);
        if (Journal.PersistenceError is { } persistenceError)
            return new DeployResult(false, Fail(PatchRunSteps.Apply,
                $"journal write-ahead persistence failed ({persistenceError}) — deployment stops BEFORE the non-idempotent apply step (fail closed: an unjournalled apply can never be allowed to happen)"), job.Id, null);
        if (!SaveJournal())
            return new DeployResult(false, Fail(PatchRunSteps.Apply,
                "the job journal could not be checkpointed to disk before the non-idempotent apply step — deployment stops BEFORE apply (fail closed: a crash mid-apply must leave a journal that parks the run for a human)"), job.Id, null);
        var built = applier.BuildApply(new PatchApplyRequest(entry, effectivePayloadPath, deviceId));
        if (!built.Ok)
            return new DeployResult(false, Fail(PatchRunSteps.Apply, built.Detail), job.Id, null);
        Journal.CompleteStep(job.Id, PatchRunSteps.Apply, now);

        // verify install (idempotent): the applier's verify plan is
        // the host-wiring check; installed-state truth arrives with
        // the next RMM-04 inventory scan.
        Journal.BeginStep(job.Id, PatchRunSteps.VerifyInstall, now);
        if (built.VerifyPlan is null)
            return new DeployResult(false, Fail(PatchRunSteps.VerifyInstall, "the applier produced no verify plan — install cannot be confirmed, run fails honestly"), job.Id, null);
        Journal.CompleteStep(job.Id, PatchRunSteps.VerifyInstall, now);

        // reboot gate (idempotent, pure policy evaluation). F12:
        // the enforcement anchor is the FIRST deploy instant for
        // this (entry, content, device) — persisted, so the
        // critical deadline runs from when the patch actually
        // landed and later evaluations (EvaluateReboot) can reach
        // the enforced state; it is never quietly reset to "now"
        // on every look.
        Journal.BeginStep(job.Id, PatchRunSteps.RebootGateStep, now);
        var anchorKey = AnchorKey(entry, deviceId);
        if (!_appliedUtc.TryGetValue(anchorKey, out var appliedUtc))
        {
            appliedUtc = now;
            _appliedUtc[anchorKey] = now;
        }
        var deferrals = DeferralCount(entry.Id, deviceId);
        var reboot = RebootGate.Evaluate(entry, RebootPolicy, appliedUtc, deferrals, now);
        Journal.CompleteStep(job.Id, PatchRunSteps.RebootGateStep, now);

        // F5: NO ring outcome is recorded here. Building an apply
        // plan is not an installation; the ring records success
        // only via ConfirmInstall on install evidence.
        _audit.Append("patch_deployed", "patch-service",
            $"entry={entry.Id} device={deviceId} job={job.Id} approval=({approval.Reason}) reboot={reboot.State} apply=({built.Detail}) ringOutcome=pending-install-confirmation", now);
        SaveJournal();
        SaveState();
        return new DeployResult(true,
            $"patch '{entry.Id}' deploy run completed for '{deviceId}' (job {job.Id}); apply plan: {built.InstallPlan?.Executable} — live execution is host wiring via the signed-command gate, proof PENDING; ring outcome is NOT recorded until install is confirmed (ConfirmInstall); reboot state: {reboot.State}",
            job.Id, reboot);
    }

    /// <summary>Record a ring outcome from INSTALL EVIDENCE
    /// (D38 F5): host wiring calls this after the executed install
    /// is verified — the verify plan's result, or the next RMM-04
    /// inventory scan showing the fixed version. This is the ONLY
    /// path that records a ring success. Failures land here too
    /// (a failed install is a ring failure, once-only as always).</summary>
    public (bool Ok, string Reason) ConfirmInstall(string entryId, string deviceId, bool verified, string evidence)
    {
        if (StateBrokenRefusal() is { } broken) return (false, broken);
        var now = _now();
        var entry = Catalogue.Get(entryId);
        if (entry is null) return (false, $"unknown catalogue entry '{entryId}' — no install outcome can be recorded against content that does not exist");
        var plans = Rollouts.PlansFor(entry.Id, entry.ContentHash, deviceId);
        if (plans.Count == 0)
            return (true, $"no rollout plan covers device '{deviceId}' for entry '{entry.Id}' — no ring outcome to record (install evidence noted: {evidence})");
        var results = new List<string>();
        var allOk = true;
        foreach (var plan in plans)
        {
            var ringName = plan.RingOf(deviceId)!;
            var (ok, reason) = plan.RecordOutcome(ringName, deviceId, verified, now);
            allOk &= ok;
            results.Add($"plan '{plan.Id}' ring '{ringName}': {reason}");
        }
        _audit.Append(verified ? "patch_install_confirmed" : "patch_install_failed", "patch-service",
            $"entry={entry.Id} device={deviceId} evidence={evidence} outcomes={string.Join("; ", results)}", now);
        SaveState();
        return (allOk, string.Join("; ", results));
    }

    // ---- rings -------------------------------------------------------

    /// <summary>Register a rollout plan and persist it (F3). Plans
    /// registered directly on Rollouts work in memory; this is the
    /// durable path host wiring uses.</summary>
    public (bool Ok, string Reason) RegisterPlan(RolloutPlan plan)
    {
        if (StateBrokenRefusal() is { } broken) return (false, broken);
        var (ok, reason) = Rollouts.Add(plan);
        if (ok && !SaveState())
            return (false, $"rollout plan registered in memory but could NOT be persisted — {StateStoreState}");
        return (ok, reason);
    }

    /// <summary>Resume a halted ring: requires a FRESH signed
    /// envelope binding (plan, ring, halt-evidence hash), verified
    /// through the RMM-03 gate, and records the decision before the
    /// ring moves. There is no unsigned or automatic path.</summary>
    public (bool Ok, string Reason) ResumeRing(string planId, string ringName, SignedCommandEnvelope? envelope, string decidedBy)
    {
        if (StateBrokenRefusal() is { } broken) return (false, broken);
        var now = _now();
        var plan = Rollouts.Get(planId);
        if (plan is null) return (false, $"unknown rollout plan '{planId}' — refused");
        RingStatus status;
        try { status = plan.StatusOf(ringName); }
        catch (ArgumentException) { return (false, $"unknown ring '{ringName}' in plan '{planId}' — refused"); }
        if (status.State != RingStates.Halted || status.HaltEvidence is null)
            return (false, $"ring '{ringName}' in plan '{planId}' is {status.State} — only a halted ring can be resumed");
        if (_gate is null)
            return (false, "no customer command key is configured on this endpoint — ring resume refuses (a resume is a signed decision, RMM-03)");
        var verdict = _gate.Authorize(envelope, now, SignedCommandClasses.PatchDeploy);
        if (!verdict.Allowed) return (false, verdict.Reason);
        var expectedPayload = $"ring_resume|{planId}|{ringName}|{status.HaltEvidence.EvidenceHash}";
        if (Encoding.UTF8.GetString(verdict.Payload!) != expectedPayload)
            return (false, "the signed resume envelope does not bind THIS plan, ring and halt evidence — refused");
        var decision = new ApprovalDecisionRecord(plan.EntryId, plan.EntryContentHash,
            $"ring:{planId}:{ringName}", ApprovalDecisions.Approved, decidedBy, now,
            $"ring_resume:{planId}:{ringName}:{status.HaltEvidence.EvidenceHash}");
        var (recorded, recordReason) = Approvals.Record(decision);
        if (!recorded) return (false, recordReason);
        var (ok, reason) = plan.ResumeHalted(ringName, decision);
        _audit.Append(ok ? "patch_ring_resumed" : "patch_ring_resume_refused", decidedBy,
            $"plan={planId} ring={ringName} evidence={status.HaltEvidence.EvidenceHash[..12]}… reason={reason}", now);
        if (ok) SaveState();
        return (ok, reason);
    }

    // ---- reboot deferrals + anchors -----------------------------------

    private static string DeferralKey(PatchCatalogueEntry entry, string deviceId) =>
        // F12: deferrals bind CONTENT, not just the entry id — a
        // new revision starts a new deferral budget, and a restart
        // no longer resets either (the map is persisted, F3).
        entry.Id + "|" + entry.ContentHash + "|" + deviceId;

    private static string AnchorKey(PatchCatalogueEntry entry, string deviceId) =>
        entry.Id + "|" + entry.ContentHash + "|" + deviceId;

    public int DeferralCount(string entryId, string deviceId)
    {
        var entry = Catalogue.Get(entryId);
        if (entry is null) return 0;
        lock (_deferralGate) return _deferrals.GetValueOrDefault(DeferralKey(entry, deviceId));
    }

    /// <summary>Record one user deferral. The policy limit is hard:
    /// at the limit this refuses and the count does not move.</summary>
    public (bool Ok, string Reason) RecordDeferral(string entryId, string deviceId)
    {
        if (StateBrokenRefusal() is { } broken) return (false, broken);
        var entry = Catalogue.Get(entryId);
        if (entry is null) return (false, $"unknown catalogue entry '{entryId}' — refused");
        lock (_deferralGate)
        {
            var key = DeferralKey(entry, deviceId);
            var used = _deferrals.GetValueOrDefault(key);
            var (allowed, reason) = RebootGate.CanDefer(RebootPolicy, used);
            if (!allowed)
            {
                _audit.Append("patch_reboot_deferral_refused", "patch-service", $"entry={entryId} device={deviceId} reason={reason}", _now());
                return (false, reason);
            }
            _deferrals[key] = used + 1;
            _audit.Append("patch_reboot_deferred", "patch-service", $"entry={entryId} device={deviceId} deferrals={used + 1}/{RebootPolicy.MaxDeferrals}", _now());
            if (!SaveState())
                return (false, $"deferral recorded in memory but could NOT be persisted — {StateStoreState}");
            return (true, reason);
        }
    }

    /// <summary>Re-evaluate the reboot gate for an already-deployed
    /// patch at a LATER instant (D38 F12): the enforcement anchor
    /// is the persisted first-deploy time for this content, so the
    /// critical deadline genuinely approaches and the enforced
    /// state is reachable — Deploy's own evaluation, anchored at
    /// its deploy instant, could never reach it.</summary>
    public (bool Ok, string Reason, RebootDecision? Decision) EvaluateReboot(string entryId, string deviceId)
    {
        var entry = Catalogue.Get(entryId);
        if (entry is null) return (false, $"unknown catalogue entry '{entryId}' — refused", null);
        if (!_appliedUtc.TryGetValue(AnchorKey(entry, deviceId), out var appliedUtc))
            return (false, $"no deployment of entry '{entryId}' to device '{deviceId}' is recorded — there is no reboot to evaluate", null);
        var decision = RebootGate.Evaluate(entry, RebootPolicy, appliedUtc, DeferralCount(entryId, deviceId), _now());
        return (true, decision.Reason, decision);
    }
}
