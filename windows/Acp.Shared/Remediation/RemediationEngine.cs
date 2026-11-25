using System.Text.Json;
using Acp.Shared.Audit;
using Acp.Shared.Enterprise;
using Acp.Shared.Hub;
using Acp.Shared.Jobs;
using Acp.Shared.Monitoring;
using Acp.Shared.Security;

namespace Acp.Shared.Remediation;

// =====================================================================
// RMM-08 — the execution half: the agent-side step executor contract,
// the bounded step interpreter (RemediationRunner), and the loop
// guard. The hub-side dispatch service (RemediationService, Core)
// owns policy, tiers, approvals and the library; THIS file owns what
// happens once a signed execution is authorised:
//
//   * NOTHING runs before the RMM-03 gate verifies the execution's
//     `automation` envelope, and the envelope's payload must bind
//     THIS definition (library id + revision + content hash), THIS
//     device and THIS alert. A genuine envelope minted for another
//     action, device or alert executes nothing here.
//   * Steps run through IRemediationStepExecutor — the agent's
//     primitives (service control, process control, shell). Tests
//     drive fakes; no test executes a real remediation action.
//   * rerun_patch steps delegate to IPatchRerunTarget (an interface
//     the RMM-02 wiring implements against PatchService) — this
//     engine never reaches into patch internals.
//   * Every step's output is captured REDACTED (Acp.Shared.Audit
//     .Redactor) and BOUNDED into the structured execution record.
//     Output is data: it is never written into the audit chain as
//     free text beyond a bounded, redacted summary, and it is never
//     parsed back — a script whose output mimics audit lines forges
//     nothing.
//   * Policy is re-checked before EVERY step (the kill-switch race:
//     `rmm.remediation.enabled` flipping OFF mid-flight aborts the
//     run before the next step — the steps already done are recorded
//     honestly as done; the run's outcome is aborted, not success).
//   * Multi-step executions are checkpointed in an RMM-15
//     JobJournal (script_chain) when one is wired: steps complete
//     in the journal at definition granularity, a step failure fails
//     the job with its reason, and a policy abort fails it too —
//     never half-applied silently.
// =====================================================================

/// <summary>What the runner hands a step executor: the execution's
/// identity, so a primitive can attribute its own effects.</summary>
public sealed record RemediationExecutionContext(
    string ExecutionId, string RemediationId, string DeviceId,
    string AlertId, string ConditionId);

/// <summary>One primitive's result. Output is raw here; the runner
/// redacts + bounds it before it is recorded anywhere.</summary>
public sealed record StepRunResult(bool Ok, string Output, string? Error)
{
    public static StepRunResult Success(string output = "") => new(true, output, null);
    public static StepRunResult Failure(string error, string output = "") => new(false, output, error);
}

/// <summary>The agent-side primitive contract: execute ONE typed
/// step. Implementations are the host wiring (service controller,
/// process control, the shell gate for run_script bodies); the
/// recording fake below is what tests drive.</summary>
public interface IRemediationStepExecutor
{
    StepRunResult Execute(RemediationStep step, RemediationExecutionContext context);
}

/// <summary>The re-run-a-failed-patch seam (RMM-02). A step executor
/// that also implements this serves rerun_patch steps; one that does
/// not fails them by name — the engine targets the interface, never
/// PatchService internals.</summary>
public interface IPatchRerunTarget
{
    StepRunResult RerunPatch(string patchEntryId, RemediationExecutionContext context);
}

/// <summary>Recording + scripted test double for the step executor
/// (house pattern: fakes live beside the model). Results are keyed
/// by step id; an unscripted step succeeds with empty output. A
/// per-step hook lets a test act DURING a step (the kill-switch race
/// flips policy inside step 1). Also serves rerun_patch via
/// <see cref="PatchResults"/>.</summary>
public sealed class RecordingRemediationStepExecutor : IRemediationStepExecutor, IPatchRerunTarget
{
    public List<(string StepId, string Kind)> Calls { get; } = new();
    public Dictionary<string, StepRunResult> Results { get; } = new(StringComparer.Ordinal);
    public Dictionary<string, Action> Hooks { get; } = new(StringComparer.Ordinal);
    public Dictionary<string, StepRunResult> PatchResults { get; } = new(StringComparer.OrdinalIgnoreCase);
    public List<string> PatchCalls { get; } = new();

    public StepRunResult Execute(RemediationStep step, RemediationExecutionContext context)
    {
        Calls.Add((step.Id, step.Kind));
        if (Hooks.TryGetValue(step.Id, out var hook)) hook();
        if (step.Kind == RemediationStepKinds.RerunPatch)
            return RerunPatch(step.Target ?? "", context);
        if (Results.TryGetValue(step.Id, out var r)) return r;
        // D38-F9: wait steps reach the executor like every other
        // kind — the double stands in for the host's pacing
        // primitive and reports the wait it was asked to pace
        // (without sleeping on wall-clock in tests).
        if (step.Kind == RemediationStepKinds.Wait)
            return int.TryParse(step.Argument, out var secs)
                ? StepRunResult.Success($"wait {secs}s (paced by executor)")
                : StepRunResult.Failure("wait step argument is not a seconds count");
        return StepRunResult.Success($"ok:{step.Id}");
    }

    public StepRunResult RerunPatch(string patchEntryId, RemediationExecutionContext context)
    {
        PatchCalls.Add(patchEntryId);
        return PatchResults.TryGetValue(patchEntryId, out var r)
            ? r : StepRunResult.Success($"patch re-run queued:{patchEntryId}");
    }
}

// ---- execution records -------------------------------------------------

public static class RemediationOutcomes
{
    public const string Succeeded = "succeeded";
    public const string Failed = "failed";
    public const string PartialFailure = "partial_failure";
    public const string AbortedPolicyDisabled = "aborted_policy_disabled";
    public const string LoopBoundReached = "loop_bound_reached";
    public const string Refused = "refused";
}

public static class StepExecutionStates
{
    public const string Done = "done";
    public const string Failed = "failed";
    public const string Skipped = "skipped";
}

/// <summary>One step's recorded execution: iteration counts loop
/// re-entries; Output is the redacted, bounded capture.</summary>
public sealed record StepExecution(
    string StepId, string Kind, int Iteration, string State, string Output, string? Error);

/// <summary>The full record of one remediation execution, kept
/// against its triggering alert. ConditionCleared starts null
/// (unknown): a remediation that RAN is not a condition that
/// CLEARED — the field moves only when the caller reports the
/// condition's observed state back (RemediationService
/// .RecordConditionFeedback).</summary>
public sealed record RemediationExecution(
    string ExecutionId,
    string RemediationId,
    string LibraryId,
    long LibraryRevision,
    string DeviceId,
    string AlertId,
    string ConditionId,
    DateTimeOffset StartedUtc,
    DateTimeOffset? FinishedUtc,
    string Outcome,
    IReadOnlyList<StepExecution> Steps,
    string? JobId,
    bool? ConditionCleared);

// ---- loop guard ----------------------------------------------------------

/// <summary>Loop safety for the engine: per (action, device)
/// cooldown + max-runs-per-window from the definition, plus a global
/// per-hour cap across all actions and devices (the trigger-storm
/// bound). State is dispatch history only; a refused check records
/// nothing, so being refused never extends a cooldown.</summary>
public sealed class RemediationLoopGuard
{
    public const int GlobalMaxRunsPerHour = 200;

    /// <summary>W3 host wiring: raised after every committed
    /// history mutation so CoreRuntime can write the guard
    /// through to disk (export/import were built by W2-B; this
    /// event is the change signal the host subscribes to).</summary>
    public event Action? Changed;

    private readonly Dictionary<string, List<DateTimeOffset>> _runs = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<DateTimeOffset> _globalRuns = new();
    private readonly object _gate = new();

    private static string Key(string remediationId, string deviceId) => $"{remediationId}|{deviceId}";

    /// <summary>Null when a run may proceed; otherwise the named
    /// refusal (cooldown active / window exhausted / global cap).
    /// D38-F3: only entries at or before `now` count — a future-dated
    /// entry (clock skew, a bad monitor clock) can neither extend a
    /// cooldown nor consume window/global budget before its time.</summary>
    public string? Check(AutomationDefinition def, string deviceId, DateTimeOffset now)
    {
        lock (_gate) return CheckLocked(def, deviceId, now);
    }

    private string? CheckLocked(AutomationDefinition def, string deviceId, DateTimeOffset now)
    {
        var runs = _runs.TryGetValue(Key(def.Id, deviceId), out var list) ? list : new List<DateTimeOffset>();
        var past = runs.Where(t => t <= now).ToList();
        var last = past.Count > 0 ? past.Max() : (DateTimeOffset?)null;
        if (last is { } l && now - l < def.Cooldown)
            return $"cooldown active for '{def.Id}' on '{deviceId}' (last run {l:O}, cooldown {def.Cooldown}) — refused";
        var inWindow = past.Count(t => now - t < def.Window);
        if (inWindow >= def.MaxRunsPerWindow)
            return $"run limit for '{def.Id}' on '{deviceId}' reached ({def.MaxRunsPerWindow} per {def.Window}) — refused (a remediation that retriggers itself is a runaway, not a retry)";
        var globalInHour = _globalRuns.Count(t => t <= now && now - t < TimeSpan.FromHours(1));
        if (globalInHour >= GlobalMaxRunsPerHour)
            return $"global remediation cap reached ({GlobalMaxRunsPerHour}/hour across the fleet) — refused (trigger storm bound)";
        return null;
    }

    public void Record(AutomationDefinition def, string deviceId, DateTimeOffset now)
    {
        lock (_gate) RecordLocked(def, deviceId, now);
        Changed?.Invoke();
    }

    private void RecordLocked(AutomationDefinition def, string deviceId, DateTimeOffset now)
    {
        var key = Key(def.Id, deviceId);
        if (!_runs.TryGetValue(key, out var list)) _runs[key] = list = new List<DateTimeOffset>();
        list.Add(now);
        // Prune what no window can still see (the widest window
        // admission allows), so history stays bounded.
        list.RemoveAll(t => now - t > AutomationLimits.MaxWindow);
        _globalRuns.Add(now);
        _globalRuns.RemoveAll(t => now - t > TimeSpan.FromHours(1));
    }

    // ---- durability (BD-SHARED-RMM-3/F12) --------------------------
    // The loop guard's history IS a safety limit: in memory only, a
    // restart — including one a crash-looping remediation triggers —
    // reset every cooldown, window and the global cap. The history
    // now round-trips through the HubPersistence envelope, following
    // WorkItemStore's pattern. Host wiring persists on change and
    // restores at start; a host that restores NOTHING should call
    // SeedRestoredEmpty so the guard treats the missing history as
    // "just ran" rather than as a clean slate.

    private sealed record LoopGuardDto(
        Dictionary<string, List<DateTimeOffset>> Runs, List<DateTimeOffset> GlobalRuns);

    public string ExportJson()
    {
        lock (_gate)
        {
            var dto = new LoopGuardDto(
                _runs.ToDictionary(kv => kv.Key, kv => kv.Value.ToList(), StringComparer.OrdinalIgnoreCase),
                _globalRuns.ToList());
            return HubPersistence.Wrap("acp-remediation-loop-guard-v1", JsonSerializer.Serialize(dto));
        }
    }

    /// <summary>Restore exported run history. Returns false (and
    /// changes nothing) on an envelope/parse failure.</summary>
    public bool ImportJson(string json)
    {
        var payload = HubPersistence.Unwrap(json, "acp-remediation-loop-guard-v1");
        if (payload is null) return false;
        LoopGuardDto? dto;
        try { dto = JsonSerializer.Deserialize<LoopGuardDto>(payload); } catch { return false; }
        if (dto is null) return false;
        lock (_gate)
        {
            _runs.Clear();
            foreach (var (k, v) in dto.Runs ?? new Dictionary<string, List<DateTimeOffset>>())
                _runs[k] = v.ToList();
            _globalRuns.Clear();
            _globalRuns.AddRange(dto.GlobalRuns ?? new List<DateTimeOffset>());
        }
        Changed?.Invoke();
        return true;
    }

    /// <summary>Fail-closed restore for a MISSING history (fresh
    /// install or a lost store): every (definition, device) pair is
    /// unknown, so the guard cannot seed per-pair runs — instead the
    /// GLOBAL window is seeded as just-run, which holds the
    /// fleet-wide cap shut for one hour while per-pair cooldowns
    /// re-learn. Named and deliberate, never a silent clean slate.</summary>
    public void SeedRestoredEmpty(DateTimeOffset now)
    {
        lock (_gate)
        {
            _globalRuns.Clear();
            for (var i = 0; i < GlobalMaxRunsPerHour; i++) _globalRuns.Add(now);
        }
    }

    /// <summary>D38-F2: check-and-record as ONE atomic step under
    /// the lock. The old Check-then-Record pair let concurrent
    /// dispatches both pass the check and exceed the window/global
    /// caps. Null = recorded, proceed; non-null = refusal, nothing
    /// recorded.</summary>
    public string? TryRecord(AutomationDefinition def, string deviceId, DateTimeOffset now)
    {
        lock (_gate)
        {
            var refusal = CheckLocked(def, deviceId, now);
            if (refusal is not null) return refusal;
            RecordLocked(def, deviceId, now);
            Changed?.Invoke();
            return null;
        }
    }

    /// <summary>D38-F6: release one reservation made by TryRecord —
    /// a run the runner REFUSED (gate/envelope/journal) never
    /// executed, so it must not consume cooldown/window/global
    /// budget. Removes the newest matching entry.</summary>
    public void Release(AutomationDefinition def, string deviceId, DateTimeOffset now)
    {
        lock (_gate)
        {
            if (_runs.TryGetValue(Key(def.Id, deviceId), out var list))
            {
                var idx = list.LastIndexOf(now);
                if (idx >= 0) list.RemoveAt(idx);
            }
            var g = _globalRuns.LastIndexOf(now);
            if (g >= 0) _globalRuns.RemoveAt(g);
        }
    }

    public int RunsInWindow(AutomationDefinition def, string deviceId, DateTimeOffset now)
    {
        lock (_gate)
            return _runs.TryGetValue(Key(def.Id, deviceId), out var list)
                ? list.Count(t => now - t < def.Window) : 0;
    }
}

// ---- the runner ------------------------------------------------------------

/// <summary>The signed payload binding for one execution. The
/// automation envelope's payload must equal this string exactly:
/// the envelope therefore authorises THIS definition content, on
/// THIS device, for THIS alert — nothing else.</summary>
public static class RemediationBinding
{
    // D38-F12: every field is LENGTH-PREFIXED, so no field value
    // (separator characters included) can shift a boundary and make
    // two different bindings collide. Null encodes as "-1:".
    private static string LP(string? s) => s is null ? "-1:" : $"{s.Length}:{s}";

    /// <summary>D38-F1 + F12: the payload binds the definition's
    /// CONTENT (its full step plan, via PlanHash), the library
    /// identity, the device, the alert AND the condition — a genuine
    /// envelope minted for the same definition id with substituted
    /// steps does NOT match this payload.</summary>
    public static string Payload(AutomationDefinition def, AutomationLibrary library,
        string deviceId, string alertId, string? conditionId = null) =>
        "automation|v2|" + string.Join("|",
            LP(def.Id), LP(PlanHash(def)), LP(library.Id), LP(library.Revision.ToString()),
            LP(library.ContentHash), LP(deviceId), LP(alertId), LP(conditionId));

    /// <summary>The step-plan hash the journal's script_chain
    /// envelope binds (the journal requires its own authorising
    /// class, script_exec — see JobKinds). D38-F12: EVERY step field
    /// that changes behaviour is hashed, length-prefixed — two
    /// different plans cannot share a hash by construction of the
    /// encoding (collision resistance then rests on SHA-256 alone).</summary>
    public static string PlanHash(AutomationDefinition def) =>
        SignedCommandEnvelope.HashPayload(System.Text.Encoding.UTF8.GetBytes(
            string.Join("|", def.Steps.Select(s => string.Join("|",
                LP(s.Id), LP(s.Kind), LP(s.Target), LP(s.Argument), LP(s.ScriptBody),
                LP(s.When), LP(s.GuardArgument), LP(s.OnFailure), LP(s.NextOnSuccess),
                LP(s.NextOnFailure), LP(s.MaxExecutions.ToString()), LP(s.Idempotent.ToString()))))));

    /// <summary>D38-F1: structural equality of two definitions —
    /// every field, steps in order (record equality alone compares
    /// the Steps list by reference, so it cannot be used here).</summary>
    public static bool DefinitionEquals(AutomationDefinition a, AutomationDefinition b) =>
        a.Id == b.Id && a.Name == b.Name && a.Description == b.Description &&
        a.ApprovalTier == b.ApprovalTier && a.Cooldown == b.Cooldown &&
        a.MaxRunsPerWindow == b.MaxRunsPerWindow && a.Window == b.Window &&
        a.Enabled == b.Enabled && a.Steps.SequenceEqual(b.Steps);
}

/// <summary>The bounded step interpreter. One Run = one execution:
/// gate verification first, then steps in authored order with
/// guards, chaining and bounded loops, policy re-checked before
/// every step, output captured redacted + bounded, journal
/// checkpointed at definition granularity when wired.</summary>
public sealed class RemediationRunner
{
    private readonly IRemediationStepExecutor _executor;
    private readonly SignedCommandGate? _gate;
    private readonly ChainedAuditLog _audit;

    public RemediationRunner(IRemediationStepExecutor executor, SignedCommandGate? gate, ChainedAuditLog audit)
    {
        _executor = executor ?? throw new ArgumentNullException(nameof(executor));
        _gate = gate;
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
    }

    public RemediationExecution Run(
        AutomationDefinition def, AutomationLibrary library, HealthAlertEvent alert,
        SignedCommandEnvelope? envelope, JobJournal? journal, SignedCommandEnvelope? journalEnvelope,
        Func<bool> policyStillEnabled, DateTimeOffset now)
    {
        var executionId = Guid.NewGuid().ToString("N");
        var steps = new List<StepExecution>();
        RemediationExecution Finish(string outcome, string? jobId, DateTimeOffset finished) =>
            new(executionId, def.Id, library.Id, library.Revision, alert.DeviceId, alert.AlertId,
                alert.ConditionId, now, finished, outcome, steps.ToList(), jobId, null);

        // ---- RMM-03 gate: NOTHING runs unverified. ----
        if (_gate is null)
        {
            const string reason = "no signed-command gate wired on the agent — remediation refuses (RMM-03: unsigned commands never execute)";
            _audit.Append("remediation_refused", "remediation-runner",
                $"execution={executionId} remediation={def.Id} device={alert.DeviceId} alert={alert.AlertId} reason={reason}", now);
            return Finish(RemediationOutcomes.Refused, null, now);
        }
        var verdict = _gate.Authorize(envelope, now, SignedCommandClasses.Automation);
        if (!verdict.Allowed)
        {
            _audit.Append("remediation_refused", "remediation-runner",
                $"execution={executionId} remediation={def.Id} device={alert.DeviceId} alert={alert.AlertId} reason={verdict.Reason}", now);
            return Finish(RemediationOutcomes.Refused, null, now);
        }
        var expected = RemediationBinding.Payload(def, library, alert.DeviceId, alert.AlertId, alert.ConditionId);
        var actual = System.Text.Encoding.UTF8.GetString(verdict.Payload!);
        if (actual != expected)
        {
            const string reason = "the signed envelope does not bind THIS automation content, library content, device, alert and condition (payload binding mismatch) — refused (an envelope minted for another action, step plan or device never executes this one)";
            _audit.Append("remediation_refused", "remediation-runner",
                $"execution={executionId} remediation={def.Id} device={alert.DeviceId} alert={alert.AlertId} reason={reason}", now);
            return Finish(RemediationOutcomes.Refused, null, now);
        }
        // D38-F1: the definition handed to the runner must BE the
        // definition in the library handed to the runner — a caller
        // swapping in same-id steps of its own is refused even with
        // a genuine envelope (the payload's plan hash already binds
        // the library's steps; this is the direct check).
        var libraryDef = library.Get(def.Id);
        if (libraryDef is null || !RemediationBinding.DefinitionEquals(libraryDef, def))
        {
            const string reason = "the definition supplied is not the definition in the supplied library (same-id step substitution) — refused";
            _audit.Append("remediation_refused", "remediation-runner",
                $"execution={executionId} remediation={def.Id} device={alert.DeviceId} alert={alert.AlertId} reason={reason}", now);
            return Finish(RemediationOutcomes.Refused, null, now);
        }

        // ---- RMM-15 checkpoint job (script_chain). ----
        ResumableJob? job = null;
        if (journal is not null)
        {
            try
            {
                var defs = def.Steps.Select(s => new JobStepDefinition(s.Id, s.Id,
                    s.Idempotent ? StepIdempotency.Idempotent : StepIdempotency.NonIdempotent)).ToList();
                job = journal.CreateJob(JobKinds.ScriptChain, alert.DeviceId, defs, journalEnvelope, now);
                if (job is null)
                {
                    const string reason = "the job journal refused the script_chain job (envelope class/expiry or step shape) — execution refuses rather than run uncheckpointed";
                    _audit.Append("remediation_refused", "remediation-runner",
                        $"execution={executionId} remediation={def.Id} device={alert.DeviceId} alert={alert.AlertId} reason={reason}", now);
                    return Finish(RemediationOutcomes.Refused, null, now);
                }
                journal.StartJob(job.Id, now);
            }
            catch (Exception ex)
            {
                // D38-F10: a throwing journal must refuse the run
                // cleanly, never escape Run with no record.
                var reason = $"the job journal threw {ex.GetType().Name} creating the script_chain job — execution refuses rather than run uncheckpointed";
                _audit.Append("remediation_refused", "remediation-runner",
                    $"execution={executionId} remediation={def.Id} device={alert.DeviceId} alert={alert.AlertId} reason={reason}", now);
                return Finish(RemediationOutcomes.Refused, null, now);
            }
        }

        var ctx = new RemediationExecutionContext(executionId, def.Id, alert.DeviceId, alert.AlertId, alert.ConditionId);
        _audit.Append("remediation_started", "remediation-runner",
            $"execution={executionId} remediation={def.Id} library={library.Id} r{library.Revision} device={alert.DeviceId} alert={alert.AlertId} condition={alert.ConditionId} steps={def.Steps.Count} job={job?.Id ?? "(none)"}", now);

        var byId = def.Steps.ToDictionary(s => s.Id, StringComparer.Ordinal);
        var executionCounts = new Dictionary<string, int>(StringComparer.Ordinal);
        var anyFailureContinued = false;
        var outcome = RemediationOutcomes.Succeeded;
        string? currentId = def.Steps[0].Id;
        StepRunResult? previous = null;
        var totalExecutions = 0;

        // Journal checkpointing is at definition granularity and in
        // AUTHORED order (the journal's own monotonic discipline):
        // a step checkpoints when its execution concludes AND every
        // earlier step has checkpointed. Out-of-order chains
        // checkpoint when the order catches up; the execution record
        // above is the per-iteration truth regardless.
        var journalNext = 0;
        var journalConcluded = new HashSet<string>(StringComparer.Ordinal);
        // D38-F5/F10: journal calls are wrapped — a throwing journal
        // degrades checkpointing (audited), it never escapes Run and
        // orphans the execution record.
        void JournalCall(Action call, string what)
        {
            if (job is null) return;
            try { call(); }
            catch (Exception ex)
            {
                try
                {
                    _audit.Append("remediation_journal_error", "remediation-runner",
                        $"execution={executionId} remediation={def.Id} what={what} error={ex.GetType().Name}: {CaptureOutput(ex.Message)}", now);
                }
                catch { /* the audit chain itself failed; the run's record still stands */ }
            }
        }
        // Drain concluded steps into the journal in authored order.
        // D38-F5: while the run is still in flight the LAST
        // uncompleted step is held back — completing it would mark
        // the job Done mid-run, after which a re-entered step's
        // stop-mode failure could never fail the job (FailStep
        // refuses terminal jobs). The held step completes only when
        // the run's outcome is known.
        void JournalDrain(bool final)
        {
            if (job is null) return;
            while (journalNext < def.Steps.Count &&
                   journalConcluded.Contains(def.Steps[journalNext].Id))
            {
                if (!final && journalNext == def.Steps.Count - 1) return; // holdback
                var sid = def.Steps[journalNext].Id;
                JournalCall(() =>
                {
                    if (journal!.BeginStep(job.Id, sid, now))
                        journal.CompleteStep(job.Id, sid, now);
                }, $"complete step {sid}");
                journalNext++;
            }
        }
        void JournalComplete(string stepId)
        {
            if (job is null) return;
            journalConcluded.Add(stepId);
            JournalDrain(final: false);
        }
        void JournalFail(string stepId, string reason)
        {
            if (job is null || job.IsTerminal) return;
            // Fail the job at the journal's next step (with the
            // holdback discipline at least one step is never Done,
            // so this lands); fall back to the failing step itself.
            var at = journalNext < def.Steps.Count ? def.Steps[journalNext].Id : stepId;
            JournalCall(() =>
            {
                if (journal!.BeginStep(job.Id, at, now))
                    journal.FailStep(job.Id, at, reason, now);
                else
                    journal.FailStep(job.Id, stepId, reason, now);
            }, $"fail step {stepId}");
        }

        while (currentId is not null)
        {
            var step = byId[currentId];

            // Kill-switch race: policy is re-checked before EVERY
            // step. OFF mid-flight aborts before the next primitive.
            // D38-F10: a THROWING policy callback is a failed check —
            // it aborts the run like OFF, it never escapes Run.
            bool policyOn;
            try { policyOn = policyStillEnabled(); }
            catch (Exception ex)
            {
                _audit.Append("remediation_aborted", "remediation-runner",
                    $"execution={executionId} remediation={def.Id} device={alert.DeviceId} atStep={step.Id} reason=policy check threw {ex.GetType().Name}: {CaptureOutput(ex.Message)} — treated as disabled (fail closed)", now);
                outcome = RemediationOutcomes.AbortedPolicyDisabled;
                if (job is not null && !job.IsTerminal)
                    JournalFail(step.Id, "aborted: policy check threw");
                break;
            }
            if (!policyOn)
            {
                outcome = RemediationOutcomes.AbortedPolicyDisabled;
                _audit.Append("remediation_aborted", "remediation-runner",
                    $"execution={executionId} remediation={def.Id} device={alert.DeviceId} atStep={step.Id} reason=policy disabled mid-flight ({RemediationPolicyKeys.RemediationEnabled}) — remaining steps did not run", now);
                if (job is not null && !job.IsTerminal)
                    JournalFail(step.Id, "aborted: policy disabled mid-flight");
                break;
            }

            // Loop bounds: per-step re-entry + the global cap.
            var iteration = executionCounts.GetValueOrDefault(step.Id) + 1;
            if (iteration > step.MaxExecutions || totalExecutions >= AutomationLimits.MaxTotalStepExecutions)
            {
                outcome = RemediationOutcomes.LoopBoundReached;
                _audit.Append("remediation_loop_bound", "remediation-runner",
                    $"execution={executionId} remediation={def.Id} step={step.Id} iteration={iteration} maxExecutions={step.MaxExecutions} totalExecutions={totalExecutions} cap={AutomationLimits.MaxTotalStepExecutions} — run stopped at its bound, not left looping", now);
                break;
            }

            // Guard (conditional vocabulary) against the previous
            // EXECUTED step. A skipped step does not replace
            // `previous` — conditions chain over real results.
            if (!GuardPasses(step, previous))
            {
                steps.Add(new StepExecution(step.Id, step.Kind, iteration, StepExecutionStates.Skipped,
                    "", "guard not satisfied"));
                JournalComplete(step.Id); // a guard-skip is a completed decision, checkpointed as done/skipped progress
                currentId = NextInOrder(def, step.Id);
                continue;
            }

            executionCounts[step.Id] = iteration;
            totalExecutions++;
            StepRunResult result;
            try
            {
                // D38-F9: EVERY step kind — wait included — goes to
                // the executor. Pacing is the executor's (host-side)
                // primitive, exactly as the header claims; the
                // engine itself never sleeps and never special-cases
                // a step out of the executor's sight.
                result = _executor.Execute(step, ctx);
            }
            catch (Exception ex)
            {
                result = StepRunResult.Failure($"executor threw {ex.GetType().Name}: {ex.Message}");
            }
            var captured = CaptureOutput(result.Output);
            // D38-F4: the Error channel gets the SAME treatment as
            // Output — redacted + capped before it touches the
            // execution record, the audit chain or the journal.
            var capturedError = result.Error is null ? null : CaptureOutput(result.Error);
            steps.Add(new StepExecution(step.Id, step.Kind, iteration,
                result.Ok ? StepExecutionStates.Done : StepExecutionStates.Failed,
                captured, capturedError));
            _audit.Append(result.Ok ? "remediation_step_completed" : "remediation_step_failed",
                "remediation-runner",
                $"execution={executionId} remediation={def.Id} step={step.Id} kind={step.Kind} iteration={iteration} outputChars={captured.Length}{(result.Ok ? "" : $" error={capturedError}")}", now);
            previous = result;

            if (result.Ok)
            {
                JournalComplete(step.Id);
                currentId = step.NextOnSuccess ?? NextInOrder(def, step.Id);
            }
            else if (step.NextOnFailure is not null)
            {
                // A routed failure does NOT checkpoint the step as
                // done in the journal and does NOT fail the job yet:
                // the run is still in flight. If the run ends
                // partial, the journal job is failed at the end with
                // that reason (see below) — never left running.
                currentId = step.NextOnFailure;
                anyFailureContinued = true; // a failure was routed, not hidden: the run cannot end "succeeded"
            }
            else if (step.OnFailure == StepFailureModes.Continue)
            {
                anyFailureContinued = true;
                currentId = NextInOrder(def, step.Id);
            }
            else
            {
                JournalFail(step.Id, capturedError ?? "step failed");
                outcome = RemediationOutcomes.Failed;
                // Remaining steps are recorded SKIPPED — a chained
                // partial failure is visible in full, never silently
                // dropped and never reported as success.
                foreach (var rest in def.Steps.Skip(def.Steps.ToList().FindIndex(s => s.Id == step.Id) + 1))
                    if (!steps.Any(x => x.StepId == rest.Id))
                        steps.Add(new StepExecution(rest.Id, rest.Kind, 0, StepExecutionStates.Skipped, "", "not reached: an earlier step failed with onFailure=stop"));
                break;
            }
        }

        if (outcome == RemediationOutcomes.Succeeded)
        {
            // Partial-failure honesty, with retry recovery: a step
            // whose LAST execution failed (its failure was continued
            // past or routed to a handler) makes the run partial —
            // never "succeeded". A step that failed and later
            // SUCCEEDED on a retry chain recovered; its last state
            // is done, and the run is honestly succeeded (the failed
            // attempts remain in the step record).
            var lastByStep = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var se in steps)
                if (se.State is StepExecutionStates.Done or StepExecutionStates.Failed)
                    lastByStep[se.StepId] = se.State;
            if (lastByStep.Values.Any(v => v == StepExecutionStates.Failed))
                outcome = RemediationOutcomes.PartialFailure;
        }
        if (outcome == RemediationOutcomes.Succeeded && job is not null && !job.IsTerminal)
        {
            // D38-F5(a): a succeeded run finalises its journal job —
            // steps bypassed by chaining are accounted as concluded
            // (the record-completeness pass below records them
            // skipped), the held-back last step completes, and the
            // job reads Done, never left running.
            foreach (var s in def.Steps) journalConcluded.Add(s.Id);
            JournalDrain(final: true);
        }
        if (outcome == RemediationOutcomes.LoopBoundReached && job is not null && !job.IsTerminal)
            JournalFail(currentId ?? def.Steps[^1].Id, "loop bound reached");
        if (outcome == RemediationOutcomes.PartialFailure && job is not null && !job.IsTerminal)
            JournalFail(def.Steps[0].Id, "partial_failure: a step failed and the run continued or routed the failure");

        // Record completeness: every step in the definition is
        // accounted for in the execution record. A step chaining
        // bypassed (a success/failure jump over it) or never reached
        // after an abort/bound stop is recorded SKIPPED with the
        // reason — the record never silently omits a step.
        foreach (var s in def.Steps)
            if (!steps.Any(x => x.StepId == s.Id))
                steps.Add(new StepExecution(s.Id, s.Kind, 0, StepExecutionStates.Skipped,
                    "", "not reached: bypassed by chaining or the run stopped before it"));

        var done = Finish(outcome, job?.Id, now);
        _audit.Append("remediation_completed", "remediation-runner",
            $"execution={executionId} remediation={def.Id} device={alert.DeviceId} alert={alert.AlertId} outcome={outcome} stepsExecuted={totalExecutions} job={job?.Id ?? "(none)"} conditionCleared=unknown (a run is not a clearance)", now);
        return done;
    }

    private static bool GuardPasses(RemediationStep step, StepRunResult? previous) => step.When switch
    {
        StepGuards.Always => true,
        StepGuards.IfPreviousSucceeded => previous is null || previous.Ok,
        StepGuards.IfPreviousFailed => previous is not null && !previous.Ok,
        StepGuards.IfOutputContains => previous is not null &&
            (previous.Output ?? "").Contains(step.GuardArgument ?? "", StringComparison.OrdinalIgnoreCase),
        _ => false, // unknown guard: never passes (admission refuses these; defence in depth)
    };

    private static string? NextInOrder(AutomationDefinition def, string stepId)
    {
        var idx = def.Steps.ToList().FindIndex(s => s.Id == stepId);
        return idx >= 0 && idx + 1 < def.Steps.Count ? def.Steps[idx + 1].Id : null;
    }

    /// <summary>Capture one step's output into evidence form:
    /// redacted (secrets never enter the record), bounded (with the
    /// truncation named), single-purpose data — never re-parsed.</summary>
    public static string CaptureOutput(string? raw)
    {
        var redacted = Redactor.RedactText(raw ?? "");
        return redacted.Length <= AutomationLimits.MaxOutputChars
            ? redacted
            : redacted[..AutomationLimits.MaxOutputChars] +
              $"…[truncated {redacted.Length - AutomationLimits.MaxOutputChars} chars]";
    }
}
