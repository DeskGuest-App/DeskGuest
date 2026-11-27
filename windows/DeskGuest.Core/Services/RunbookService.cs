using System.Text;
using System.Text.Json;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.Jobs;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.Monitoring;
using DeskGuest.Shared.Remediation;
using DeskGuest.Shared.Runbooks;
using DeskGuest.Shared.Security;

namespace DeskGuest.Core.Services;

// =====================================================================
// RMM-20 — RunbookService: approval-gated SOP execution chains.
//
// Composition, not reinvention:
//   * automated steps execute through RMM-08's RemediationRunner
//     (same signed-envelope gate, same step primitives, same output
//     capture) — there is NO second executor;
//   * human confirmations ride the same attributed-decision
//     discipline as RMM-08's approval flow (park → attributed
//     decision → execution record), extended with attester rules;
//   * a run is an RMM-15 JobJournal job (script_chain): steps
//     checkpoint in authored order, and a run paused at a human
//     step resumes AT that step — resume never skips it;
//   * runbook definitions are RMM-03 signed library content
//     (policy_delivery), admitted whole with revision discipline
//     exactly like the automation library;
//   * availability is RMM-07 policy content: the seeded toggle
//     `rmm.runbooks.enabled` plus per-runbook
//     `rmm.runbooks.<id>.enabled` settings, re-checked before
//     EVERY step (the kill-switch race).
//
// PINNING: a run executes the definition version it started with.
// StartRun snapshots the definition (defensive copy) and pins its
// content hash into the execution record; a library revision
// mid-run changes nothing under the running execution.
//
// SEPARATION OF DUTIES (the destruction pass's home ground):
//   * an attestation for a step with a required attester is
//     accepted ONLY from that attester; a step marked
//     RequireDistinctAttester refuses the run's initiator;
//   * an approval is NEVER accepted from the run's initiator
//     (no self-approval), and a required approver binds by id;
//   * a skip is a RECORDED decision by an actor other than the
//     executing tech (and, where the step names its attester /
//     approver, only that named actor) — never a silent path.
// `initiatedBy` / `attestedBy` / `approvedBy` / `skippedBy` are the
// AUTHENTICATED actors of the calling session (the JobStateReport
// seam discipline): identity comes from the caller, never from
// runbook content.
// =====================================================================

public sealed class RunbookService
{
    private static readonly TimeSpan EnvelopeTtl = TimeSpan.FromMinutes(5);
    // CONV-F1: there is deliberately NO separate long-lived job-envelope
    // TTL. The checkpoint job envelope is a SignedCommand envelope, so
    // D38 F7's gated bound (SignedCommandSigner.MaxEnvelopeLifetime = 4h)
    // applies to it; the former 24h constant made every signed StartRun
    // throw at the signer. The sibling services mint their RMM-15
    // script_chain journal envelopes with their ordinary EnvelopeTtl
    // (RemediationService, SoftwareDeploymentService — the RMM-16 in-lane
    // precedent), and RunbookService does the same. Lifetime beyond the
    // envelope is not lost silently: step checkpointing never re-checks
    // envelope expiry, and RMM-15's ResumeAll adjudicates an envelope
    // that expired mid-outage as authority_expired (fail closed) — the
    // same treatment every other journal job gets.
    private const int MaxTotalStepAttempts = 200;
    private const int MaxSkipReasonLength = 512; // D38 F11 (predecessor fragment referenced it; defined here)

    private readonly ChainedAuditLog _audit;
    private readonly ManagementPolicyEngine _policy;
    private readonly Func<string, IDeviceFacts?> _factsByDevice;
    private readonly SignedCommandSigner? _signer;
    private readonly SignedCommandGate? _gate;
    private readonly RemediationRunner _runner;
    private readonly IRunbookCheckEvaluator _checks;
    private readonly Func<AutomationLibrary> _automationLibrary;
    private readonly JobJournal _journal;
    private readonly Func<DateTimeOffset> _now;
    private readonly object _lock = new();

    private RunbookLibrary _library = RunbookLibrary.Default();
    private readonly Dictionary<string, RunState> _runs = new(StringComparer.Ordinal);

    // D38 F6: library-id discipline survives id switches — a
    // replaced id is retired forever (case-insensitive, matching
    // definition lookup), and once a SIGNED library is in force
    // the unsigned local admission path closes entirely (the
    // RMM-01/RMM-08 D38 pattern, mirrored).
    private readonly HashSet<string> _retiredLibraryIds = new(StringComparer.OrdinalIgnoreCase);
    private bool _signedLibraryInForce;

    // D38 F4: actors authorised to record a skip of a step that
    // names no attester/approver of its own. Caller-supplied
    // principal registry (the authenticated session's authority
    // source is host wiring); EMPTY means no such skip is
    // authorised — fail closed, never "any second string".
    private readonly HashSet<string> _authorisedSkippers;

    // BD-WIN-CORE-4/F6: approving/attesting a step that names NO
    // approver/attester of its own was "any second string" — a
    // weaker authority than skipping, which D38 F4 already bound
    // to a registry. Approval/attestation now follow the same
    // law: unnamed steps accept ONLY registry actors (host-wired
    // from the roster's approver principals); an empty registry
    // fails closed.
    private readonly HashSet<string> _authorisedApprovers;
    private readonly HashSet<string> _authorisedAttesters;

    // D38 F12: the latest audit anchor per run, indexed at append
    // time — verification is O(1) in audit history, not a substring
    // scan of every entry ever written.
    private readonly Dictionary<string, string> _anchorByRun = new(StringComparer.Ordinal);
    private int _auditVerifiedCount = -1;
    private bool _auditVerifiedOk;

    /// <summary>D38 F12: terminal runs retained for verification;
    /// beyond this the OLDEST terminal runs are evicted (named in
    /// the audit). Parked/running runs are never evicted.</summary>
    public const int MaxRetainedTerminalRuns = 100;

    private sealed class RunState
    {
        public required RunbookDefinition Def;       // pinned snapshot
        public required RunbookExecution Exec;
        public required IDeviceFacts Facts;
        public required string PinnedDefinitionHash; // D38 F8: held apart from Exec so the pin guard compares two independent values
        public int CurrentIndex;
        public int JournalNext;
        public bool AnyFailureContinued;
        public bool LoopActive;                      // D38 F7: RunLoop re-entry guard
    }

    public RunbookService(
        ChainedAuditLog audit,
        ManagementPolicyEngine policy,
        Func<string, IDeviceFacts?> factsByDevice,
        SignedCommandSigner? signer,
        SignedCommandGate? gate,
        IRemediationStepExecutor remediationExecutor,
        IRunbookCheckEvaluator checkEvaluator,
        Func<AutomationLibrary> automationLibrary,
        JobJournal? journal = null,
        Func<DateTimeOffset>? now = null,
        IEnumerable<string>? authorisedSkipperIds = null,
        IEnumerable<string>? authorisedApproverIds = null,
        IEnumerable<string>? authorisedAttesterIds = null)
    {
        _authorisedSkippers = new HashSet<string>(
            authorisedSkipperIds ?? Enumerable.Empty<string>(), StringComparer.Ordinal);
        _authorisedApprovers = new HashSet<string>(
            authorisedApproverIds ?? Enumerable.Empty<string>(), StringComparer.Ordinal);
        _authorisedAttesters = new HashSet<string>(
            authorisedAttesterIds ?? Enumerable.Empty<string>(), StringComparer.Ordinal);
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _policy = policy ?? throw new ArgumentNullException(nameof(policy));
        _factsByDevice = factsByDevice ?? throw new ArgumentNullException(nameof(factsByDevice));
        _signer = signer;
        _gate = gate;
        _now = now ?? (() => DateTimeOffset.UtcNow);
        _journal = journal ?? new JobJournal(null,
            (kind, actor, detail) => _audit.Append(kind, actor ?? "runbook-service", detail ?? "", _now()));
        _runner = new RemediationRunner(
            remediationExecutor ?? throw new ArgumentNullException(nameof(remediationExecutor)), gate, audit);
        _checks = checkEvaluator ?? throw new ArgumentNullException(nameof(checkEvaluator));
        _automationLibrary = automationLibrary ?? throw new ArgumentNullException(nameof(automationLibrary));
    }

    public RunbookLibrary Library { get { lock (_lock) return _library; } }
    public JobJournal Journal => _journal;

    public RunbookExecution? GetRun(string? runId)
    {
        lock (_lock) return runId is not null && _runs.TryGetValue(runId, out var s) ? s.Exec : null;
    }

    public IReadOnlyList<RunbookExecution> Runs
    {
        get { lock (_lock) return _runs.Values.Select(s => s.Exec).OrderBy(e => e.StartedUtc).ToList(); }
    }

    public IReadOnlyList<RunbookExecution> RunsForWorkItem(string workItemId) =>
        Runs.Where(e => e.WorkItemId == workItemId).ToList();

    // ---- run persistence (BD-WIN-CORE-4/F8, bounded slice) --------
    // Parked runs (paused for approval/attestation) were purely
    // in-memory: a hub restart lost them while their RMM-15 journal
    // job stayed behind. Runs now round-trip through the same
    // HubPersistence integrity envelope as the other hub stores.
    // The pinned definition snapshot travels WITH the execution
    // record and its hash is re-verified on import — a tampered
    // snapshot imports nothing. (Reporting stores + deployment
    // write-through wiring remain the named residuals of F8.)

    public string ExportRunsJson()
    {
        lock (_lock)
        {
            var payload = System.Text.Json.JsonSerializer.Serialize(new
            {
                Runs = _runs.Values.Select(s => new { s.Exec, s.Def }).ToList(),
            });
            return DeskGuest.Shared.Hub.HubPersistence.Wrap("deskguest-runbook-runs-v1", payload);
        }
    }

    /// <summary>Restore runs exported by ExportRunsJson. Returns
    /// the number restored; 0 on any integrity/parse failure, in
    /// which case nothing is imported (parse-then-apply).</summary>
    public int ImportRunsJson(string json)
    {
        var payload = DeskGuest.Shared.Hub.HubPersistence.Unwrap(json, "deskguest-runbook-runs-v1");
        if (payload is null) return 0;
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(payload);
            var parsed = new List<(RunbookExecution Exec, RunbookDefinition Def)>();
            foreach (var r in doc.RootElement.GetProperty("Runs").EnumerateArray())
            {
                var exec = r.GetProperty("Exec").Deserialize<RunbookExecution>()
                    ?? throw new InvalidOperationException("run record did not parse");
                var def = r.GetProperty("Def").Deserialize<RunbookDefinition>()
                    ?? throw new InvalidOperationException("definition did not parse");
                if (RunbookLibrary.DefinitionHash(def) != exec.DefinitionHash)
                    throw new InvalidOperationException("pinned definition hash mismatch");
                if (!exec.VerifyStepChain())
                    throw new InvalidOperationException("step chain does not verify");
                parsed.Add((exec, def));
            }
            var restored = 0;
            lock (_lock)
            {
                foreach (var (exec, def) in parsed)
                {
                    var facts = _factsByDevice(exec.DeviceId);
                    if (facts is null) continue;
                    var idx = exec.CurrentStepId is not null
                        ? def.Steps.ToList().FindIndex(s => s.Id == exec.CurrentStepId)
                        : -1;
                    if (idx < 0)
                    {
                        idx = exec.Steps.ToList().FindIndex(s =>
                            s.State is not (RunbookStepStates.Done or RunbookStepStates.Skipped));
                        if (idx < 0) idx = def.Steps.Count;
                    }
                    _runs[exec.RunId] = new RunState
                    {
                        Def = def,
                        Exec = exec,
                        Facts = facts,
                        PinnedDefinitionHash = exec.DefinitionHash,
                        CurrentIndex = idx,
                        AnyFailureContinued = exec.Steps.Any(s =>
                            s.State is RunbookStepStates.Failed or RunbookStepStates.CheckFailed),
                    };
                    restored++;
                }
            }
            return restored;
        }
        catch { return 0; }
    }

    // ---- library admission (RMM-03 signed content) -------------------

    public PolicyVerdict ApplySignedLibrary(SignedCommandEnvelope? envelope)
    {
        var now = _now();
        if (_gate is null)
        {
            const string reason = "no customer command key is configured — signed runbook-library delivery refuses (RMM-03)";
            _audit.Append("runbook_library_refused", "runbook-service", reason, now);
            return new PolicyVerdict(false, reason);
        }
        var verdict = _gate.Authorize(envelope, now, SignedCommandClasses.PolicyDelivery);
        if (!verdict.Allowed) return new PolicyVerdict(false, verdict.Reason);
        RunbookLibrary? library;
        try { library = RunbookLibrary.FromCanonicalJson(Encoding.UTF8.GetString(verdict.Payload!)); }
        catch { library = null; }
        if (library is null)
        {
            const string reason = "signed payload did not parse as a runbook library — refused";
            _audit.Append("runbook_library_refused", "runbook-service", reason, now);
            return new PolicyVerdict(false, reason);
        }
        return AdmitLibrary(library, "signed delivery", viaSigned: true);
    }

    /// <summary>D38 F6: the local path carries an actor seam now —
    /// a non-empty `via` naming the admitting path is required, and
    /// once a signed library is in force this path is CLOSED: local
    /// admission can never bypass signed delivery.</summary>
    public PolicyVerdict AdmitLocalLibrary(RunbookLibrary library, string via)
    {
        if (string.IsNullOrWhiteSpace(via))
            return new PolicyVerdict(false, "local runbook-library admission needs a named admitting path (via) — refused (anonymous local admission is not an authority)");
        lock (_lock)
        {
            if (_signedLibraryInForce)
            {
                const string locked = "a signed runbook library is in force — the unsigned local admission path is closed (runbook content changes only through signed delivery)";
                _audit.Append("runbook_library_refused", "runbook-service",
                    $"library={library.Id} via={via} reason={locked}", _now());
                return new PolicyVerdict(false, locked);
            }
        }
        return AdmitLibrary(library, via, viaSigned: false);
    }

    private PolicyVerdict AdmitLibrary(RunbookLibrary library, string via, bool viaSigned)
    {
        var now = _now();
        var invalid = library.Validate();
        if (invalid is not null)
        {
            _audit.Append("runbook_library_refused", "runbook-service",
                $"library={library.Id} via={via} reason={invalid}", now);
            return new PolicyVerdict(false, invalid);
        }
        lock (_lock)
        {
            // D38 F6: a retired id never returns at ANY revision —
            // admit A r5, switch to B, replay A r1 (or r99) refuses.
            if (_retiredLibraryIds.Contains(library.Id))
            {
                var retired = $"runbook library id '{library.Id}' was replaced and is retired — refused (switching ids back cannot resurrect older content or erase revision history)";
                _audit.Append("runbook_library_refused", "runbook-service", $"library={library.Id} via={via} reason={retired}", now);
                return new PolicyVerdict(false, retired);
            }
            if (string.Equals(library.Id, _library.Id, StringComparison.OrdinalIgnoreCase))
            {
                if (library.Revision < _library.Revision)
                {
                    var stale = $"runbook library '{library.Id}' revision {library.Revision} is stale (current {_library.Revision}) — refused";
                    _audit.Append("runbook_library_refused", "runbook-service", $"library={library.Id} via={via} reason={stale}", now);
                    return new PolicyVerdict(false, stale);
                }
                if (library.Revision == _library.Revision && library.ContentHash != _library.ContentHash)
                {
                    var conflict = $"runbook library '{library.Id}' revision {library.Revision} conflicts with the admitted library of the same id+revision — refused (definition tampering after signing changes nothing)";
                    _audit.Append("runbook_library_refused", "runbook-service", $"library={library.Id} via={via} reason={conflict}", now);
                    return new PolicyVerdict(false, conflict);
                }
                if (library.Revision == _library.Revision)
                    return new PolicyVerdict(true, $"runbook library '{library.Id}' r{library.Revision} already admitted (idempotent)");
            }
            // Defensive copy: the admitted library is frozen at
            // admission (the RMM-07/RMM-08 lesson).
            var replacedId = _library.Id;
            _library = library with
            {
                Runbooks = library.Runbooks.Select(r => r with { Steps = r.Steps.ToList() }).ToList(),
            };
            if (!string.Equals(replacedId, _library.Id, StringComparison.OrdinalIgnoreCase))
                _retiredLibraryIds.Add(replacedId);
            if (viaSigned) _signedLibraryInForce = true;
            _audit.Append("runbook_library_applied", "runbook-service",
                $"library={library.Id} revision={library.Revision} runbooks={library.Runbooks.Count} hash={library.ContentHash} via={via}", now);
            return new PolicyVerdict(true, $"runbook library '{library.Id}' r{library.Revision} admitted via {via}");
        }
    }

    // ---- policy --------------------------------------------------------

    private bool PolicyOk(IDeviceFacts facts, string runbookId)
    {
        if (!_policy.IsEnabled(facts, RunbookPolicyKeys.RunbooksEnabled)) return false;
        var setting = _policy.ComputeEffective(facts).Get(RunbookPolicyKeys.RunbookEnabled(runbookId));
        if (setting is null) return true;
        return bool.TryParse(setting.Value, out var v) && v; // unparsable ⇒ disabled (fail closed)
    }

    /// <summary>D38 F10: policy is checked BEFORE a human decision
    /// is recorded — never record-then-discover. A decision attempted
    /// while the kill switch is off refuses, the run aborts for
    /// policy, and NO attestation/approval/skip lands in the record
    /// or the journal. Call under _lock, on a non-terminal run.</summary>
    private string? PolicyGateForDecision(RunState state, DateTimeOffset now)
    {
        if (PolicyOk(state.Facts, state.Exec.RunbookId)) return null;
        AbortForPolicy(state, now);
        return "runbooks are disabled by policy — the decision was NOT recorded and the run aborted (policy is checked before any decision lands)";
    }

    // ---- run lifecycle ---------------------------------------------------

    /// <summary>Start a run. Gates, in order: named initiator →
    /// device facts → TOTAL POLICY CONTROL → library lookup/enabled
    /// → per-runbook policy. The definition is SNAPSHOTTED and its
    /// hash pinned before the first step; the run then advances
    /// until it completes, fails, or pauses at a human gate.</summary>
    public (RunbookExecution? Run, string Reason) StartRun(
        string runbookId, string deviceId, string initiatedBy, string? workItemId, DateTimeOffset now)
    {
        (RunbookExecution?, string) Refuse(string reason)
        {
            _audit.Append("runbook_start_refused", initiatedBy ?? "runbook-service",
                $"runbook={runbookId} device={deviceId} reason={reason}", now);
            return (null, reason);
        }
        if (string.IsNullOrWhiteSpace(initiatedBy))
            return Refuse("a run needs a named initiator — refused (an unattributed run is not a procedure record)");
        var facts = _factsByDevice(deviceId);
        if (facts is null)
            return Refuse($"no device facts for '{deviceId}' — policy cannot be evaluated — refused (fail closed)");

        RunbookDefinition? found;
        RunbookLibrary library;
        lock (_lock) { library = _library; found = library.Get(runbookId); }
        if (found is null)
            return Refuse($"unknown runbook '{runbookId}' — no such runbook in library '{library.Id}' r{library.Revision} — refused");
        if (!found.Enabled)
            return Refuse($"runbook '{found.Id}' is disabled in library '{library.Id}' — refused");
        if (!PolicyOk(facts, found.Id))
            return Refuse($"runbooks are disabled by policy for this device ({RunbookPolicyKeys.RunbooksEnabled} / {RunbookPolicyKeys.RunbookEnabled(found.Id)}) — refused; policy is the kill switch");

        // PIN: snapshot the definition exactly as admitted.
        var def = found with { Steps = found.Steps.ToList() };
        var defHash = RunbookLibrary.DefinitionHash(def);
        var runId = Guid.NewGuid().ToString("N");

        // RMM-15 checkpoint job (script_chain).
        string? jobId = null;
        if (_signer is not null)
        {
            var jobEnvelope = _signer.Sign(SignedCommandClasses.ScriptExec,
                Encoding.UTF8.GetBytes($"runbook|{def.Id}|{defHash}"), now, EnvelopeTtl);
            var stepDefs = def.Steps.Select(s => new JobStepDefinition(s.Id, s.Title,
                s.Idempotent ? StepIdempotency.Idempotent : StepIdempotency.NonIdempotent)).ToList();
            var job = _journal.CreateJob(JobKinds.ScriptChain, deviceId, stepDefs, jobEnvelope, now);
            if (job is null)
            {
                return Refuse("the job journal refused the runbook's script_chain job (envelope class/expiry or step shape) — the run refuses rather than run uncheckpointed");
            }
            _journal.StartJob(job.Id, now);
            jobId = job.Id;
        }
        else
        {
            _audit.Append("runbook_journal_unavailable", "runbook-service",
                $"run={runId} runbook={def.Id} reason=no customer signer configured — the run proceeds with its audited execution record but no RMM-15 journal job (named, never silent)", now);
        }

        var records = new List<RunbookStepRecord>();
        var prev = RunbookExecution.GenesisHash;
        foreach (var s in def.Steps)
        {
            var rec = RunbookStepRecord.Pending(s, prev);
            records.Add(rec);
            prev = rec.RecordHash;
        }
        var exec = new RunbookExecution(runId, def.Id, library.Id, library.Revision, defHash,
            deviceId, initiatedBy, workItemId, now, null, RunbookRunStatuses.Running, null,
            records, jobId, 0);
        var state = new RunState { Def = def, Exec = exec, Facts = facts, PinnedDefinitionHash = defHash };
        lock (_lock) _runs[runId] = state;
        _audit.Append("runbook_started", initiatedBy,
            $"run={runId} runbook={def.Id} library={library.Id} r{library.Revision} definitionHash={defHash} device={deviceId} steps={def.Steps.Count} job={jobId ?? "(none)"} workItem={workItemId ?? "(none)"}", now);
        RunLoop(state, now);
        lock (_lock) return (state.Exec, $"run {runId} started; status={state.Exec.Status}");
    }

    /// <summary>Resume a paused/halted run. A run paused at a human
    /// step resumes AT that step: resume returns it still paused —
    /// the human step is never skipped by resuming. A halted check
    /// is re-evaluated. The pinned definition hash is re-verified
    /// before anything moves.</summary>
    public (bool Ok, string Reason) ResumeRun(string runId, DateTimeOffset now)
    {
        RunState? state;
        lock (_lock) _runs.TryGetValue(runId ?? "", out state);
        if (state is null) return (false, $"no run '{runId}' — refused");
        lock (_lock)
        {
            var exec = state.Exec;
            if (exec.IsTerminal)
                return (false, $"run '{runId}' is terminal ({exec.Status}) — there is nothing to resume");
            // D38 F8: the pin guard compares the snapshot AND the
            // record against the hash held APART from both at
            // StartRun — previously both sides of the comparison
            // derived from the same snapshot, so it could never fire.
            if (RunbookLibrary.DefinitionHash(state.Def) != state.PinnedDefinitionHash ||
                exec.DefinitionHash != state.PinnedDefinitionHash)
            {
                state.Exec = exec with { Status = RunbookRunStatuses.Failed, FinishedUtc = now };
                _audit.Append("runbook_pin_mismatch", "runbook-service",
                    $"run={runId} reason=the pinned definition hash no longer matches the run's snapshot — run failed rather than continue on unverifiable content", now);
                return (false, "the run's pinned definition no longer verifies — run failed (definition pin mismatch)");
            }
            if (!PolicyOk(state.Facts, exec.RunbookId))
            {
                AbortForPolicy(state, now);
                return (false, "runbooks are disabled by policy at resume time — the run aborted (policy governs parked runs too)");
            }
            state.Exec = exec with { ResumeCount = exec.ResumeCount + 1 };
            _audit.Append("runbook_resume_requested", "runbook-service",
                $"run={runId} status={exec.Status} currentStep={exec.CurrentStepId ?? "(none)"} resumeCount={state.Exec.ResumeCount}", now);
            if (exec.Status is RunbookRunStatuses.PausedAwaitingAttestation or RunbookRunStatuses.PausedAwaitingApproval)
            {
                AnchorRecord(state, exec.InitiatedBy, now);
                return (true, $"run '{runId}' resumed at its human step '{exec.CurrentStepId}' — still paused there; a human step is never skipped by resuming");
            }
            if (exec.Status == RunbookRunStatuses.HaltedCheckFailed)
            {
                // Re-evaluate the halted check from its own step.
                var idx = state.CurrentIndex;
                UpdateStep(state, state.Def.Steps[idx].Id,
                    r => r with { State = RunbookStepStates.Pending });
                state.Exec = state.Exec with { Status = RunbookRunStatuses.Running };
            }
        }
        RunLoop(state, now);
        lock (_lock) return (true, $"run '{runId}' resumed; status={state.Exec.Status}");
    }

    /// <summary>Record a human attestation for the step the run is
    /// paused on, then continue the run. Attester rules are enforced
    /// against the AUTHENTICATED caller identity.</summary>
    public (bool Ok, string Reason) Attest(string runId, string stepId, string attestedBy, DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(attestedBy))
            return (false, "an attestation needs an attester — refused (the attestation is attributed or it does not happen)");
        RunState? state;
        lock (_lock) _runs.TryGetValue(runId ?? "", out state);
        if (state is null) return (false, $"no run '{runId}' — refused");
        lock (_lock)
        {
            var exec = state.Exec;
            if (exec.Status != RunbookRunStatuses.PausedAwaitingAttestation || exec.CurrentStepId != stepId)
                return (false, $"run '{runId}' is not paused awaiting attestation on step '{stepId}' — refused");
            var step = state.Def.Steps[state.CurrentIndex];
            if (step.Kind != RunbookStepKinds.HumanConfirmation)
                return (false, $"step '{stepId}' is not a human-confirmation step — refused");
            if (step.RequiredAttesterId is not null &&
                !string.Equals(attestedBy, step.RequiredAttesterId, StringComparison.Ordinal))
                return (false, $"step '{stepId}' is reserved for attester '{step.RequiredAttesterId}' — attestation by '{attestedBy}' refused (the executing tech cannot attest a step reserved for another attester)");
            if (step.RequireDistinctAttester &&
                string.Equals(attestedBy, exec.InitiatedBy, StringComparison.Ordinal))
                return (false, $"step '{stepId}' requires an attester different from the executing tech ('{exec.InitiatedBy}') — self-attestation refused");
            // BD-WIN-CORE-4/F6: an unnamed attester is a registry
            // authority, not any second string (the SkipStep law).
            if (step.RequiredAttesterId is null && !_authorisedAttesters.Contains(attestedBy))
                return (false, $"step '{stepId}' names no attester, and '{attestedBy}' is not in the authorised-attester registry — refused (an attestation needs an authorised actor, not merely a second string)");
            if (PolicyGateForDecision(state, now) is { } policyRefusal)
                return (false, policyRefusal);
            UpdateStep(state, stepId, r => r with
            {
                State = RunbookStepStates.Done,
                AttestedBy = attestedBy, AttestedUtc = now, Attempts = r.Attempts + 1,
            });
            _audit.Append("runbook_step_attested", attestedBy,
                $"run={runId} runbook={exec.RunbookId} step={stepId} prompt={step.AttestationPrompt}", now);
            JournalAccount(state, stepId);
            state.CurrentIndex++;
            state.Exec = state.Exec with { Status = RunbookRunStatuses.Running, CurrentStepId = null };
        }
        RunLoop(state, now);
        lock (_lock) return (true, $"step '{stepId}' attested by {attestedBy}; run status={state.Exec.Status}");
    }

    /// <summary>Record an approval for the gated step the run is
    /// paused on, then continue. Self-approval is refused by
    /// construction: the approver may never be the initiator.</summary>
    public (bool Ok, string Reason) ApproveStep(string runId, string stepId, string approvedBy, DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(approvedBy))
            return (false, "an approval needs an approver — refused");
        RunState? state;
        lock (_lock) _runs.TryGetValue(runId ?? "", out state);
        if (state is null) return (false, $"no run '{runId}' — refused");
        lock (_lock)
        {
            var exec = state.Exec;
            if (exec.Status != RunbookRunStatuses.PausedAwaitingApproval || exec.CurrentStepId != stepId)
                return (false, $"run '{runId}' is not paused awaiting approval on step '{stepId}' — refused");
            if (string.Equals(approvedBy, exec.InitiatedBy, StringComparison.Ordinal))
                return (false, $"step '{stepId}' cannot be approved by the run's initiator ('{approvedBy}') — self-approval refused; a gated step needs a second human");
            var step = state.Def.Steps[state.CurrentIndex];
            if (step.RequiredApproverId is not null &&
                !string.Equals(approvedBy, step.RequiredApproverId, StringComparison.Ordinal))
                return (false, $"step '{stepId}' requires approver '{step.RequiredApproverId}' — approval by '{approvedBy}' refused");
            // BD-WIN-CORE-4/F6: same registry law for approvals.
            if (step.RequiredApproverId is null && !_authorisedApprovers.Contains(approvedBy))
                return (false, $"step '{stepId}' names no approver, and '{approvedBy}' is not in the authorised-approver registry — refused (an approval needs an authorised actor, not merely a second string)");
            if (PolicyGateForDecision(state, now) is { } policyRefusal)
                return (false, policyRefusal);
            UpdateStep(state, stepId, r => r with
            {
                State = RunbookStepStates.Pending,
                ApprovedBy = approvedBy, ApprovedUtc = now,
            });
            _audit.Append("runbook_step_approved", approvedBy,
                $"run={runId} runbook={exec.RunbookId} step={stepId}", now);
            state.Exec = state.Exec with { Status = RunbookRunStatuses.Running, CurrentStepId = null };
        }
        RunLoop(state, now);
        lock (_lock) return (true, $"step '{stepId}' approved by {approvedBy}; run status={state.Exec.Status}");
    }

    /// <summary>Record a skip decision for the step the run is
    /// paused/halted on, then continue. A skip is a DECISION: named
    /// actor, named reason, audited, and visible in the record
    /// forever. The executing tech can never skip their own gates.</summary>
    public (bool Ok, string Reason) SkipStep(string runId, string stepId, string skippedBy, string reason, DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(skippedBy))
            return (false, "a skip needs a deciding actor — refused");
        if (string.IsNullOrWhiteSpace(reason))
            return (false, "a skip needs a recorded reason — refused (a skip without a reason is a silent path)");
        // D38 F11: the reason is caller free text stored in evidence
        // — bound it and redact it like every other captured text.
        if (reason.Length > MaxSkipReasonLength)
            return (false, $"a skip reason is bounded at {MaxSkipReasonLength} chars — refused (the reason is evidence, not a document)");
        reason = RunbookCapture.Capture(reason);
        RunState? state;
        lock (_lock) _runs.TryGetValue(runId ?? "", out state);
        if (state is null) return (false, $"no run '{runId}' — refused");
        lock (_lock)
        {
            var exec = state.Exec;
            if (!RunbookRunStatuses.IsPaused(exec.Status) || exec.CurrentStepId != stepId)
                return (false, $"run '{runId}' is not paused/halted on step '{stepId}' — there is nothing to skip");
            if (string.Equals(skippedBy, exec.InitiatedBy, StringComparison.Ordinal))
                return (false, $"step '{stepId}' cannot be skipped by the executing tech ('{skippedBy}') — a skip is a recorded decision by an authorised actor other than the person executing the run");
            var step = state.Def.Steps[state.CurrentIndex];
            var named = step.Kind == RunbookStepKinds.HumanConfirmation ? step.RequiredAttesterId
                : step.RequiresApproval ? step.RequiredApproverId : null;
            if (named is not null && !string.Equals(skippedBy, named, StringComparison.Ordinal))
                return (false, $"step '{stepId}' names '{named}' as its attester/approver — a skip by '{skippedBy}' refused");
            // D38 F4: a step naming NO attester/approver of its own
            // (a halted check, an unnamed human step) may be skipped
            // ONLY by an actor in the authorised-skipper registry —
            // "any string that is not the initiator" is not an
            // authority. Empty registry ⇒ nobody (fail closed).
            if (named is null && !_authorisedSkippers.Contains(skippedBy))
                return (false, $"step '{stepId}' names no attester/approver, and '{skippedBy}' is not in the authorised-skipper registry — refused (a skip needs an authorised actor, not merely a second string)");
            // D38 F10: policy BEFORE the decision lands (SkipStep
            // was the one decision path the predecessor fragment
            // missed — Attest/ApproveStep already gate).
            if (PolicyGateForDecision(state, now) is { } policyRefusal)
                return (false, policyRefusal);
            var wasFailed = GetRecord(state, stepId).State is RunbookStepStates.CheckFailed or RunbookStepStates.Failed;
            UpdateStep(state, stepId, r => r with
            {
                State = RunbookStepStates.Skipped,
                SkippedBy = skippedBy, SkipReason = reason, SkippedUtc = now,
            });
            // D38 F3: skipping a step whose whole point was a gate —
            // an approval-gated step or a human attestation — means
            // the gated action never ran / the sign-off never
            // happened. The run may complete, but its outcome is
            // partial_failure, never succeeded. (Skipping an
            // already-failed step keeps the existing rule.)
            if (wasFailed || step.Kind == RunbookStepKinds.HumanConfirmation || step.RequiresApproval)
                state.AnyFailureContinued = true;
            _audit.Append("runbook_step_skipped", skippedBy,
                $"run={runId} runbook={exec.RunbookId} step={stepId} reason={reason} — a recorded skip decision, never a silent path", now);
            JournalAccount(state, stepId);
            state.CurrentIndex++;
            state.Exec = state.Exec with { Status = RunbookRunStatuses.Running, CurrentStepId = null };
        }
        RunLoop(state, now);
        lock (_lock) return (true, $"step '{stepId}' skipped by recorded decision of {skippedBy}; run status={state.Exec.Status}");
    }

    /// <summary>Verify a run's execution record against (1) its own
    /// step chain and (2) the head hash anchored in the chained
    /// audit log at the last pause/decision/completion. A rewritten
    /// record disagrees with one of them and this says so.</summary>
    public (bool Ok, string Reason) VerifyExecutionRecord(string runId)
    {
        RunbookExecution? exec;
        string? anchor;
        lock (_lock)
        {
            exec = runId is not null && _runs.TryGetValue(runId, out var s) ? s.Exec : null;
            _anchorByRun.TryGetValue(runId ?? "", out anchor);
        }
        if (exec is null) return (false, $"no run '{runId}'");
        if (!exec.VerifyStepChain())
            return (false, $"run '{runId}': the step-record chain does not recompute — a step record was rewritten after sealing");
        // D38 F2 + F12: the anchor is indexed per run at append time
        // (no substring scan of the whole audit history), and it
        // covers the run-level HEADER hash — Status, InitiatedBy,
        // DefinitionHash, FinishedUtc, WorkItemId, CurrentStepId —
        // not just the step-chain head. Rewriting a final
        // partial_failure to succeeded, or swapping the initiator,
        // changes the header hash and fails here.
        if (anchor is not null)
        {
            var anchoredHead = anchor.Split("head=")[^1].Split(' ')[0].Trim();
            var anchoredHeader = anchor.Contains("header=")
                ? anchor.Split("header=")[^1].Split(' ')[0].Trim() : anchoredHead;
            var anchoredStatus = anchor.Contains("status=")
                ? anchor.Split("status=")[^1].Split(' ')[0].Trim() : "";
            if (exec.Status == RunbookRunStatuses.Running)
            {
                // 'running' is NOT a tamper shield (F2): a record
                // claiming to be running while carrying a finish
                // time, or with every step already concluded,
                // contradicts itself — that shape is exactly the
                // rewrite-with-recomputed-chain attack.
                if (exec.FinishedUtc is not null ||
                    (exec.Steps.Count > 0 && exec.Steps.All(s => s.State is
                        RunbookStepStates.Done or RunbookStepStates.Skipped or
                        RunbookStepStates.Failed or RunbookStepStates.CheckFailed)))
                    return (false, $"run '{runId}': the record claims status 'running' but is finished/concluded — the execution record was rewritten after it was anchored");
            }
            else if (anchoredHead != exec.RecordHeadHash ||
                     anchoredHeader != exec.HeaderHash ||
                     anchoredStatus != exec.Status)
            {
                return (false, $"run '{runId}': record head/header/status ({exec.RecordHeadHash}/{exec.HeaderHash}/{exec.Status}) disagree with the audit-anchored values ({anchoredHead}/{anchoredHeader}/{anchoredStatus}) — the execution record was rewritten after it was anchored");
            }
        }
        // D38 F12: the audit-chain verification is cached on the
        // entry count — it re-runs only when the log has grown,
        // not on every verification call.
        bool auditOk; string auditSummary = "";
        lock (_lock)
        {
            if (_auditVerifiedCount == _audit.Entries.Count)
            {
                auditOk = _auditVerifiedOk;
            }
            else
            {
                var v = _audit.Verify();
                _auditVerifiedCount = _audit.Entries.Count;
                _auditVerifiedOk = v.Ok;
                auditOk = v.Ok;
                auditSummary = v.Summary;
            }
        }
        if (!auditOk)
            return (false, $"run '{runId}': the chained audit log itself does not verify ({auditSummary})");
        return (true, $"run '{runId}': step chain recomputes and matches the audit-anchored head + run header");
    }

    // ---- the loop ---------------------------------------------------------

    /// <summary>D38 F7: the loop does NOT hold the service-wide
    /// _lock while a check evaluator or an automated step executes
    /// (host probes / agent round-trips can be slow; holding the
    /// lock starved every other run and every read). The loop runs
    /// in phases: decide under _lock → execute OUTSIDE _lock →
    /// record under _lock. LoopActive (set under _lock) makes a
    /// re-entrant RunLoop call a no-op — the active loop re-reads
    /// state each phase, so a decision recorded meanwhile (attest /
    /// approve / skip already advanced CurrentIndex themselves) is
    /// picked up, never double-executed.</summary>
    private void RunLoop(RunState state, DateTimeOffset now)
    {
        lock (_lock)
        {
            if (state.LoopActive) return;
            state.LoopActive = true;
        }
        try { RunLoopCore(state, now); }
        finally { lock (_lock) state.LoopActive = false; }
    }

    private void RunLoopCore(RunState state, DateTimeOffset now)
    {
        var def = state.Def;
        while (true)
        {
            RunbookStep step;
            int attempts;
            string runId, deviceId;
            lock (_lock)
            {
                // Advance past concluded steps.
                while (state.CurrentIndex < def.Steps.Count)
                {
                    var head = def.Steps[state.CurrentIndex];
                    if (GetRecord(state, head.Id).State is
                        RunbookStepStates.Done or RunbookStepStates.Skipped)
                    {
                        state.CurrentIndex++;
                        continue;
                    }
                    break;
                }
                if (state.CurrentIndex >= def.Steps.Count)
                {
                    // Every step accounted for: honest final outcome.
                    var anyFailed = state.Exec.Steps.Any(s =>
                        s.State is RunbookStepStates.Failed or RunbookStepStates.CheckFailed) || state.AnyFailureContinued;
                    FinishRun(state, anyFailed ? RunbookRunStatuses.PartialFailure : RunbookRunStatuses.Succeeded, now);
                    return;
                }
                step = def.Steps[state.CurrentIndex];
                var rec = GetRecord(state, step.Id);
                attempts = rec.Attempts;
                runId = state.Exec.RunId;
                deviceId = state.Exec.DeviceId;
                if (state.Exec.Steps.Sum(s => s.Attempts) > MaxTotalStepAttempts)
                {
                    UpdateStep(state, step.Id, r => r with
                    {
                        State = RunbookStepStates.Failed,
                        Error = $"step-attempt bound reached ({MaxTotalStepAttempts} across the run) — run stopped at its bound, not left looping",
                    });
                    FinishRun(state, RunbookRunStatuses.Failed, now);
                    return;
                }
                // Kill-switch race: policy re-checked before EVERY step.
                if (!PolicyOk(state.Facts, def.Id))
                {
                    AbortForPolicy(state, now);
                    return;
                }
                // Approval gate: the step does not run unapproved.
                if (step.RequiresApproval && rec.ApprovedBy is null)
                {
                    UpdateStep(state, step.Id, r => r with { State = RunbookStepStates.AwaitingApproval });
                    state.Exec = state.Exec with
                    {
                        Status = RunbookRunStatuses.PausedAwaitingApproval, CurrentStepId = step.Id,
                    };
                    _audit.Append("runbook_paused_approval", state.Exec.InitiatedBy,
                        $"run={state.Exec.RunId} runbook={def.Id} step={step.Id} requiredApprover={step.RequiredApproverId ?? "(authorised-approver registry)"}", now);
                    AnchorRecord(state, state.Exec.InitiatedBy, now);
                    return;
                }
                switch (step.Kind)
                {
                    case RunbookStepKinds.HumanConfirmation:
                        UpdateStep(state, step.Id, r => r with { State = RunbookStepStates.AwaitingAttestation });
                        state.Exec = state.Exec with
                        {
                            Status = RunbookRunStatuses.PausedAwaitingAttestation, CurrentStepId = step.Id,
                        };
                        _audit.Append("runbook_paused_attestation", state.Exec.InitiatedBy,
                            $"run={state.Exec.RunId} runbook={def.Id} step={step.Id} requiredAttester={step.RequiredAttesterId ?? "(named human; distinct from executor: " + step.RequireDistinctAttester + ")"}", now);
                        AnchorRecord(state, state.Exec.InitiatedBy, now);
                        return;
                    case RunbookStepKinds.Check:
                    case RunbookStepKinds.Automated:
                        break; // execute OUTSIDE the lock, below
                    default:
                        // Admission refuses unknown kinds; defence in depth.
                        UpdateStep(state, step.Id, r => r with
                        {
                            State = RunbookStepStates.Failed,
                            Error = $"unknown step kind '{step.Kind}' — refused at execution",
                        });
                        FinishRun(state, RunbookRunStatuses.Failed, now);
                        return;
                }
            }

            if (step.Kind == RunbookStepKinds.Check)
            {
                CheckRunResult result;
                try { result = _checks.Evaluate(step, runId, deviceId); }
                catch (Exception ex) { result = CheckRunResult.Fail($"check evaluator threw {ex.GetType().Name}: {ex.Message}"); }
                var observed = RunbookCapture.Capture(result.Observed);
                lock (_lock)
                {
                    _audit.Append(result.Passed ? "runbook_check_passed" : "runbook_check_failed",
                        "runbook-service",
                        $"run={runId} runbook={def.Id} step={step.Id} check={step.CheckKind} target={step.CheckTarget} observed={observed}", now);
                    if (result.Passed)
                    {
                        UpdateStep(state, step.Id, r => r with
                        {
                            State = RunbookStepStates.Done, Attempts = r.Attempts + 1,
                            CheckPassed = true, CheckObserved = observed, Error = null,
                        });
                        JournalAccount(state, step.Id);
                        state.CurrentIndex++;
                    }
                    else
                    {
                        UpdateStep(state, step.Id, r => r with
                        {
                            State = RunbookStepStates.CheckFailed, Attempts = r.Attempts + 1,
                            CheckPassed = false, CheckObserved = observed,
                            Error = $"check '{step.CheckKind}' on '{step.CheckTarget}' did not pass",
                        });
                        if (!ApplyFailurePolicy(state, step, now)) return;
                    }
                }
                continue;
            }

            // Automated: execute through the RMM-08 runner, no lock held.
            var (ok, output, error, innerId) = ExecuteAutomated(state, step, attempts, now);
            lock (_lock)
            {
                if (ok)
                {
                    UpdateStep(state, step.Id, r => r with
                    {
                        State = RunbookStepStates.Done, Attempts = r.Attempts + 1,
                        Output = output, Error = null, InnerExecutionId = innerId,
                    });
                    JournalAccount(state, step.Id);
                    state.CurrentIndex++;
                }
                else
                {
                    UpdateStep(state, step.Id, r => r with
                    {
                        State = RunbookStepStates.Failed, Attempts = r.Attempts + 1,
                        Output = output, Error = error, InnerExecutionId = innerId,
                    });
                    if (!ApplyFailurePolicy(state, step, now)) return;
                }
            }
        }
    }

    /// <summary>Apply a step's declared failure policy after a
    /// failure has been recorded. Returns false when the run stops
    /// here (halt): automated halt = run failed (terminal); check
    /// halt = run HALTED at the check (resumable — re-run or a
    /// recorded skip), never advanced past silently.</summary>
    private bool ApplyFailurePolicy(RunState state, RunbookStep step, DateTimeOffset now)
    {
        switch (step.OnFailure)
        {
            case RunbookFailurePolicies.Continue:
                state.AnyFailureContinued = true;
                JournalAccount(state, step.Id);
                state.CurrentIndex++;
                return true;
            case RunbookFailurePolicies.Route:
                state.AnyFailureContinued = true;
                JournalAccount(state, step.Id);
                var target = state.Def.Steps.ToList().FindIndex(s => s.Id == step.RouteStepId);
                state.CurrentIndex = target >= 0 ? target : state.Def.Steps.Count;
                return true;
            default: // Halt
                if (step.Kind == RunbookStepKinds.Check)
                {
                    state.Exec = state.Exec with
                    {
                        Status = RunbookRunStatuses.HaltedCheckFailed, CurrentStepId = step.Id,
                    };
                    _audit.Append("runbook_halted_check", "runbook-service",
                        $"run={state.Exec.RunId} runbook={state.Def.Id} step={step.Id} — a failed check halts the run here; it advances only by re-check or a recorded skip decision", now);
                    AnchorRecord(state, state.Exec.InitiatedBy, now);
                }
                else
                {
                    FinishRun(state, RunbookRunStatuses.Failed, now);
                }
                return false;
        }
    }

    /// <summary>Execute ONE automated step through the RMM-08
    /// engine: resolve the definition from the CURRENT automation
    /// library, mint the binding envelopes, and let
    /// RemediationRunner verify + run it. The inner execution's own
    /// record (id + per-step summary) is captured into the runbook
    /// step record.</summary>
    private (bool Ok, string Output, string? Error, string? InnerExecutionId) ExecuteAutomated(
        RunState state, RunbookStep step, int attempts, DateTimeOffset now)
    {
        var exec = state.Exec;
        var library = _automationLibrary();
        var def = library.Get(step.AutomationId!);
        if (def is null)
            return (false, "", $"unknown automation '{step.AutomationId}' — no such definition in automation library '{library.Id}' r{library.Revision} — the step cannot run (automated steps compose the RMM-08 library; there is no fallback executor)", null);
        if (!def.Enabled)
            return (false, "", $"automation '{def.Id}' is disabled in library '{library.Id}' — the step cannot run", null);
        if (_signer is null)
            return (false, "", "no customer command signer is configured on the hub — the RMM-08 automation envelope cannot be minted — the step cannot run (RMM-03)", null);
        var alertId = $"{exec.RunId}:{step.Id}:{attempts + 1}";
        var alert = new HealthAlertEvent(alertId, exec.DeviceId, exec.RunbookId,
            "runbook", "info", HealthAlertStates.Raised, now, now, 1,
            $"runbook '{exec.RunbookId}' step '{step.Id}'", null, null, null, null, "hub");
        var envelope = _signer.Sign(SignedCommandClasses.Automation,
            // The v2 RMM-08 binding includes the alert condition;
            // the runner recomputes the payload WITH
            // alert.ConditionId and refuses on mismatch, so the
            // mint must name the condition this step's synthetic
            // alert carries (exec.RunbookId) — RemediationService
            // and SoftwareDeploymentService do the same with their
            // alerts' conditions. Omitting it refused EVERY
            // automated runbook step (CONV-F5).
            Encoding.UTF8.GetBytes(RemediationBinding.Payload(def, library, exec.DeviceId, alertId, alert.ConditionId)),
            now, EnvelopeTtl);
        var inner = _runner.Run(def, library, alert, envelope, journal: null, journalEnvelope: null,
            policyStillEnabled: () =>
                _policy.IsEnabled(state.Facts, RemediationPolicyKeys.RemediationEnabled) &&
                PolicyOk(state.Facts, exec.RunbookId),
            now);
        var summary = RunbookCapture.Capture(
            $"automation={def.Id} outcome={inner.Outcome} steps=[{string.Join(", ", inner.Steps.Select(s => $"{s.StepId}:{s.State}"))}]");
        return inner.Outcome == RemediationOutcomes.Succeeded
            ? (true, summary, null, inner.ExecutionId)
            : (false, summary, $"automation '{def.Id}' execution outcome={inner.Outcome}", inner.ExecutionId);
    }

    // ---- record plumbing ---------------------------------------------------

    private static RunbookStepRecord GetRecord(RunState state, string stepId) =>
        state.Exec.Steps.First(s => s.StepId == stepId);

    /// <summary>Mutate one step record and re-seal the chain from
    /// that record onward (a record's hash covers its predecessor,
    /// so a legitimate in-flight update cascades; the audit anchor
    /// is what makes a POST-anchor rewrite detectable).</summary>
    private static void UpdateStep(RunState state, string stepId,
        Func<RunbookStepRecord, RunbookStepRecord> mutate)
    {
        var steps = state.Exec.Steps.ToList();
        var idx = steps.FindIndex(s => s.StepId == stepId);
        if (idx < 0) return;
        steps[idx] = mutate(steps[idx]);
        var prev = idx == 0 ? RunbookExecution.GenesisHash : steps[idx - 1].RecordHash;
        for (var i = idx; i < steps.Count; i++)
        {
            steps[i] = RunbookStepRecord.Seal(steps[i], prev);
            prev = steps[i].RecordHash;
        }
        state.Exec = state.Exec with { Steps = steps };
    }

    /// <summary>Anchor the record in the chained audit log. D38 F2:
    /// the anchor carries the run-level HEADER hash alongside the
    /// step-chain head, so run-level fields are tamper-evident too.
    /// D38 F12: the latest anchor per run is indexed as it is
    /// appended. Call under _lock.</summary>
    private void AnchorRecord(RunState state, string actor, DateTimeOffset now)
    {
        var detail = $"run={state.Exec.RunId} head={state.Exec.RecordHeadHash} header={state.Exec.HeaderHash} status={state.Exec.Status}";
        _audit.Append("runbook_record_anchor", actor, detail, now);
        _anchorByRun[state.Exec.RunId] = detail;
    }

    /// <summary>Journal checkpointing at authored order (the RMM-08
    /// discipline): a step checkpoints when it concludes AND every
    /// earlier step has checkpointed; out-of-order conclusions
    /// checkpoint when the order catches up.</summary>
    private void JournalAccount(RunState state, string stepId)
    {
        var jobId = state.Exec.JobId;
        if (jobId is null) return;
        var now = _now();
        // Authored-order prefix accounting: account every concluded
        // step from JournalNext forward, in order (out-of-order
        // conclusions from routing account when the order catches
        // up). D38 F1: a step that concluded FAILED / CHECK-FAILED
        // is accounted as FAILED — FailStep fails the journal job
        // with the reason — and is NEVER CompleteStep'd. Previously
        // the head step was completed unconditionally, so a run
        // whose record said partial_failure could leave a Done
        // journal job behind it. The journal's vocabulary has no
        // "failed but continuing" state (its types are gated), so
        // the job fails at the first failed step while the runbook
        // record — the per-step truth — carries the continuation.
        while (state.JournalNext < state.Def.Steps.Count)
        {
            var nextId = state.Def.Steps[state.JournalNext].Id;
            var rec = GetRecord(state, nextId);
            if (rec.State is RunbookStepStates.Done or RunbookStepStates.Skipped)
            {
                if (_journal.BeginStep(jobId, nextId, now))
                    _journal.CompleteStep(jobId, nextId, now);
                state.JournalNext++;
                continue;
            }
            if (rec.State is RunbookStepStates.Failed or RunbookStepStates.CheckFailed)
            {
                _journal.FailStep(jobId, nextId,
                    $"step '{nextId}' concluded {rec.State}: {rec.Error ?? "failed"} (runbook execution record is the per-step truth)", now);
                state.JournalNext++;
            }
            break;
        }
    }

    private void JournalFailCurrent(RunState state, string reason, DateTimeOffset now)
    {
        var jobId = state.Exec.JobId;
        if (jobId is null) return;
        var job = _journal.GetJob(jobId);
        if (job is null || job.IsTerminal) return;
        var at = state.JournalNext < state.Def.Steps.Count
            ? state.Def.Steps[state.JournalNext].Id : state.Def.Steps[^1].Id;
        if (_journal.BeginStep(jobId, at, now))
            _journal.FailStep(jobId, at, reason, now);
        else
            _journal.FailStep(jobId, state.Exec.CurrentStepId ?? at, reason, now);
    }

    private void AbortForPolicy(RunState state, DateTimeOffset now)
    {
        state.Exec = state.Exec with
        {
            Status = RunbookRunStatuses.AbortedPolicyDisabled, FinishedUtc = now,
        };
        _audit.Append("runbook_aborted", "runbook-service",
            $"run={state.Exec.RunId} runbook={state.Def.Id} device={state.Exec.DeviceId} atStep={state.Def.Steps[Math.Min(state.CurrentIndex, state.Def.Steps.Count - 1)].Id} reason=runbooks disabled by policy mid-run ({RunbookPolicyKeys.RunbooksEnabled}) — remaining steps did not run", now);
        JournalFailCurrent(state, "aborted: runbooks disabled by policy mid-run", now);
        AnchorRecord(state, state.Exec.InitiatedBy, now);
    }

    private void FinishRun(RunState state, string outcome, DateTimeOffset now)
    {
        state.Exec = state.Exec with { Status = outcome, FinishedUtc = now, CurrentStepId = null };
        _audit.Append("runbook_completed", state.Exec.InitiatedBy,
            $"run={state.Exec.RunId} runbook={state.Def.Id} device={state.Exec.DeviceId} outcome={outcome} steps=[{string.Join(", ", state.Exec.Steps.Select(s => $"{s.StepId}:{s.State}"))}] job={state.Exec.JobId ?? "(none)"} workItem={state.Exec.WorkItemId ?? "(none)"}", now);
        if (state.Exec.JobId is not null)
        {
            var job = _journal.GetJob(state.Exec.JobId);
            if (job is not null && !job.IsTerminal)
            {
                if (outcome == RunbookRunStatuses.Succeeded)
                {
                    // Account any remaining concluded steps so the
                    // job can reach done; if steps remain
                    // unaccounted the job fails honestly below.
                    foreach (var s in state.Def.Steps.Skip(state.JournalNext).ToList())
                        JournalAccount(state, s.Id);
                    var after = _journal.GetJob(state.Exec.JobId);
                    if (after is not null && !after.IsTerminal)
                        JournalFailCurrent(state, "runbook finished succeeded but journal steps remain unaccounted", now);
                }
                else
                {
                    JournalFailCurrent(state, $"runbook outcome={outcome}", now);
                }
            }
        }
        AnchorRecord(state, state.Exec.InitiatedBy, now);
        // D38 F12: _runs is bounded — beyond MaxRetainedTerminalRuns
        // the OLDEST terminal runs are evicted (named in the audit;
        // their audit trail and anchors' history remain in the
        // chained log). Parked/running runs are never evicted, and
        // the just-finished run is never the victim.
        var terminal = _runs.Values
            .Where(s => s.Exec.IsTerminal && s.Exec.RunId != state.Exec.RunId)
            .OrderBy(s => s.Exec.StartedUtc).ToList();
        while (terminal.Count + 1 > MaxRetainedTerminalRuns && terminal.Count > 0)
        {
            var victim = terminal[0];
            terminal.RemoveAt(0);
            _runs.Remove(victim.Exec.RunId);
            _anchorByRun.Remove(victim.Exec.RunId);
            _audit.Append("runbook_run_evicted", "runbook-service",
                $"run={victim.Exec.RunId} reason=terminal-run retention bound ({MaxRetainedTerminalRuns}) reached — oldest terminal run evicted from the in-process store; its chained audit trail remains", now);
        }
    }
}
