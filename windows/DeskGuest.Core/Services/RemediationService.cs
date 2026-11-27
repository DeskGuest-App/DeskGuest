using System.Text;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.Jobs;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.Monitoring;
using DeskGuest.Shared.Remediation;
using DeskGuest.Shared.Security;

namespace DeskGuest.Core.Services;

// =====================================================================
// RMM-08 — RemediationService: the hub-side auto-remediation engine,
// implementing RMM-01's IRemediationSink contract.
//
// Dispatch path, in order, every refusal a chained audit event:
//   1. Device facts resolve (policy cannot be evaluated without
//      them — fail closed).
//   2. TOTAL POLICY CONTROL: `rmm.remediation.enabled` for the
//      device via the RMM-07 engine. OFF stops ALL dispatch — this
//      is the global engine kill, by policy alone, audited. The
//      runner additionally re-checks it before every step, so OFF
//      mid-flight aborts a run already in progress.
//   3. The automation exists in the admitted library and is enabled
//      there and not disabled per-action by policy.
//   4. Approval tier: the effective tier is the MORE restrictive of
//      the library's tier and policy's per-action tier setting —
//      policy can raise an action to requires_approval, it can
//      NEVER lower one. A requires-approval action parks a pending
//      approval against the alert and does not run; only a recorded
//      human Approve() executes it, and approval re-runs EVERY gate
//      (policy may have changed, the library may have changed, the
//      loop guard applies at execution time).
//   5. Loop guard: per-action cooldown + max-runs-per-window +
//      the global storm cap (RemediationLoopGuard).
//   6. Execution: the service mints the RMM-03 `automation`
//      envelope binding this definition's library content, device
//      and alert, plus the script_exec envelope the RMM-15 journal
//      binds; the agent-side RemediationRunner verifies the
//      automation envelope through the signed-command gate BEFORE
//      any step executes, then runs the bounded step model through
//      IRemediationStepExecutor primitives.
//
// The library arrives ONLY as signed content (policy_delivery) or
// the audited local path; admission is whole-library (validation +
// revision discipline), and the admitted library is frozen by
// defensive copy — post-admission mutation of the caller's lists
// changes nothing live.
//
// Feedback honesty: an execution record's ConditionCleared stays
// null until RecordConditionFeedback reports the condition's
// OBSERVED state back. A successful run never acks or resets the
// alert by itself; a condition clearing supersedes any still-pending
// approval for that alert (the fix is moot), and a condition
// persisting after a "successful" run is recorded as persisting.
// =====================================================================

/// <summary>A parked requires-approval remediation, held against
/// its triggering alert. Approval is a recorded human decision;
/// denial and supersession are terminal and audited.</summary>
public sealed record RemediationApprovalRequest(
    string ApprovalId,
    string RemediationId,
    string AlertId,
    string DeviceId,
    string ConditionId,
    string LibraryId,
    string LibraryContentHash,
    DateTimeOffset RequestedUtc,
    string Status,
    string? DecidedBy,
    DateTimeOffset? DecidedUtc,
    string? ExecutionId,
    string AlertState = "")
{
    public bool IsPending => Status == RemediationApprovalStatuses.Pending;
}

public static class RemediationApprovalStatuses
{
    public const string Pending = "pending";
    public const string Executed = "executed";
    public const string Denied = "denied";
    public const string Expired = "expired";
    public const string SupersededConditionCleared = "superseded_condition_cleared";
    public const string SupersededLibraryChanged = "superseded_library_changed";
}

public sealed class RemediationService : IRemediationSink
{
    /// <summary>How long a parked approval stays decidable. Past
    /// it, approval refuses as expired — the alert it was parked
    /// against is a day old and deserves a fresh trigger, not a
    /// stale human click.</summary>
    public static readonly TimeSpan ApprovalTtl = TimeSpan.FromHours(24);

    private static readonly TimeSpan EnvelopeTtl = TimeSpan.FromMinutes(5);

    private readonly ChainedAuditLog _audit;
    private readonly ManagementPolicyEngine _policy;
    private readonly Func<string, IDeviceFacts?> _factsByDevice;
    private readonly SignedCommandSigner? _signer;
    private readonly SignedCommandGate? _gate;
    private readonly RemediationRunner _runner;
    private readonly JobJournal _journal;
    private readonly Func<DateTimeOffset> _now;
    private readonly object _lock = new();

    private AutomationLibrary _library = AutomationLibrary.Default();
    private readonly RemediationLoopGuard _loopGuard = new();
    private readonly List<RemediationExecution> _executions = new();
    private readonly Dictionary<string, RemediationApprovalRequest> _approvals = new(StringComparer.Ordinal);

    // D38-F8: once a library id has been replaced by a different
    // id, the old id is RETIRED — re-admitting it at any revision
    // refuses, so switching ids cannot resurrect older/weaker
    // content and erase the revision history (the RMM-01 pattern).
    private readonly HashSet<string> _retiredLibraryIds = new(StringComparer.OrdinalIgnoreCase);
    // D38-F2: approvals currently claimed by an in-flight Approve
    // call — the claim is taken atomically under _lock, so
    // single-use is a fact, not a check-then-act hope.
    private readonly HashSet<string> _approvalsInFlight = new(StringComparer.Ordinal);
    // D38-F6: bounded retention — parked/executed state cannot
    // grow without limit under a trigger storm.
    public const int MaxPendingApprovals = 100;
    public const int MaxRetainedExecutions = 1_000;
    public const int MaxRetainedApprovals = 1_000;

    /// <summary>D38-F3: the service's injected clock is the ONLY
    /// trusted time. A caller-supplied `now` is honoured only
    /// within a small skew of it; outside the skew the service
    /// clock governs every time-based gate (approval TTL, cooldown,
    /// windows, envelope expiry) — a backdated now cannot bypass a
    /// TTL and a future-dated now cannot poison the loop guard.</summary>
    public static readonly TimeSpan MaxClockSkew = TimeSpan.FromMinutes(5);

    private DateTimeOffset EffectiveNow(DateTimeOffset callerNow)
    {
        var clock = _now();
        return callerNow <= clock + MaxClockSkew && callerNow >= clock - MaxClockSkew
            ? callerNow : clock;
    }

    /// <param name="gate">The RMM-03 gate: verifies signed library
    /// delivery (policy_delivery) and, in the runner, each
    /// execution's automation envelope. When null, signed delivery
    /// refuses and the runner refuses every execution — named,
    /// never silent.</param>
    /// <param name="signer">The hub-side customer signer that mints
    /// execution envelopes. When null, dispatch refuses: an engine
    /// that cannot sign cannot command (RMM-03).</param>
    /// <param name="journal">The RMM-15 job journal executions are
    /// checkpointed into. When null the service constructs an
    /// in-process journal so checkpointing semantics always apply;
    /// persistence (SaveToFile/LoadFromFile in the Core data dir)
    /// is the wiring's step, exactly as PatchService does for
    /// patch runs.</param>
    public RemediationService(
        ChainedAuditLog audit,
        ManagementPolicyEngine policy,
        Func<string, IDeviceFacts?> factsByDevice,
        SignedCommandSigner? signer,
        SignedCommandGate? gate,
        IRemediationStepExecutor executor,
        JobJournal? journal = null,
        Func<DateTimeOffset>? now = null)
    {
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _policy = policy ?? throw new ArgumentNullException(nameof(policy));
        _factsByDevice = factsByDevice ?? throw new ArgumentNullException(nameof(factsByDevice));
        _signer = signer;
        _gate = gate;
        _now = now ?? (() => DateTimeOffset.UtcNow);
        _journal = journal ?? new JobJournal(null,
            (kind, actor, detail) => _audit.Append(kind, actor ?? "remediation-service", detail ?? "", _now()));
        _runner = new RemediationRunner(
            executor ?? throw new ArgumentNullException(nameof(executor)), gate, audit);
    }

    public AutomationLibrary Library { get { lock (_lock) return _library; } }
    public JobJournal Journal => _journal;
    public RemediationLoopGuard LoopGuard => _loopGuard;

    public IReadOnlyList<RemediationExecution> Executions
    {
        get { lock (_lock) return _executions.ToList(); }
    }

    public IReadOnlyList<RemediationExecution> ExecutionsForAlert(string alertId)
    {
        lock (_lock) return _executions.Where(e => e.AlertId == alertId).ToList();
    }

    public IReadOnlyList<RemediationApprovalRequest> PendingApprovals
    {
        get { lock (_lock) return _approvals.Values.Where(a => a.IsPending)
            .OrderBy(a => a.RequestedUtc).ToList(); }
    }

    public RemediationApprovalRequest? GetApproval(string approvalId)
    {
        lock (_lock) return approvalId is not null && _approvals.TryGetValue(approvalId, out var a) ? a : null;
    }

    /// <summary>THE policy gate other surfaces can ask: is the
    /// remediation engine enabled for this device at all?</summary>
    public bool IsEngineEnabled(IDeviceFacts facts) =>
        _policy.IsEnabled(facts, RemediationPolicyKeys.RemediationEnabled);

    // ---- library admission ------------------------------------------

    /// <summary>Apply an automation library delivered as a signed
    /// command envelope (class policy_delivery). Verification
    /// precedes parsing; validation + revision discipline follow;
    /// every outcome is a chained audit event.</summary>
    public PolicyVerdict ApplySignedLibrary(SignedCommandEnvelope? envelope)
    {
        var now = _now();
        if (_gate is null)
        {
            const string reason = "no customer command key is configured — signed automation-library delivery refuses (RMM-03)";
            _audit.Append("remediation_library_refused", "remediation-service", reason, now);
            return new PolicyVerdict(false, reason);
        }
        var verdict = _gate.Authorize(envelope, now, SignedCommandClasses.PolicyDelivery);
        if (!verdict.Allowed) return new PolicyVerdict(false, verdict.Reason);
        AutomationLibrary? library;
        try { library = AutomationLibrary.FromCanonicalJson(Encoding.UTF8.GetString(verdict.Payload!)); }
        catch { library = null; }
        if (library is null)
        {
            const string reason = "signed payload did not parse as an automation library — refused";
            _audit.Append("remediation_library_refused", "remediation-service", reason, now);
            return new PolicyVerdict(false, reason);
        }
        return AdmitLibrary(library, "signed delivery");
    }

    /// <summary>Admit a library from an already-trusted local path
    /// (tests, first-boot seeding beyond the built-in default). The
    /// same validation + revision discipline applies.</summary>
    public PolicyVerdict AdmitLocalLibrary(AutomationLibrary library, string via) => AdmitLibrary(library, via);

    private PolicyVerdict AdmitLibrary(AutomationLibrary library, string via)
    {
        var now = _now();
        var invalid = library.Validate();
        if (invalid is not null)
        {
            _audit.Append("remediation_library_refused", "remediation-service",
                $"library={library.Id} via={via} reason={invalid}", now);
            return new PolicyVerdict(false, invalid);
        }
        lock (_lock)
        {
            // D38-F8: a retired id never comes back, and the
            // same-id comparison is case-insensitive — definition
            // lookups are case-insensitive, so revision discipline
            // must be too ('Site-Lib' r1 is 'site-lib' r1).
            if (_retiredLibraryIds.Contains(library.Id))
            {
                var retired = $"automation library id '{library.Id}' was replaced and is retired — refused (switching ids back cannot resurrect older content or erase revision history)";
                _audit.Append("remediation_library_refused", "remediation-service", $"library={library.Id} via={via} reason={retired}", now);
                return new PolicyVerdict(false, retired);
            }
            if (string.Equals(library.Id, _library.Id, StringComparison.OrdinalIgnoreCase))
            {
                if (library.Revision < _library.Revision)
                {
                    var stale = $"automation library '{library.Id}' revision {library.Revision} is stale (current {_library.Revision}) — refused";
                    _audit.Append("remediation_library_refused", "remediation-service", $"library={library.Id} via={via} reason={stale}", now);
                    return new PolicyVerdict(false, stale);
                }
                if (library.Revision == _library.Revision && library.ContentHash != _library.ContentHash)
                {
                    var conflict = $"automation library '{library.Id}' revision {library.Revision} conflicts with the admitted library of the same id+revision — refused";
                    _audit.Append("remediation_library_refused", "remediation-service", $"library={library.Id} via={via} reason={conflict}", now);
                    return new PolicyVerdict(false, conflict);
                }
                if (library.Revision == _library.Revision)
                    return new PolicyVerdict(true, $"automation library '{library.Id}' r{library.Revision} already admitted (idempotent)");
            }
            // Defensive copy (the RMM-07 lesson): the admitted
            // library is frozen at admission — a caller holding the
            // original lists must not mutate live automation content
            // with no revision, no signature and no audit.
            var replacedId = _library.Id;
            _library = library with
            {
                Definitions = library.Definitions.Select(d => d with { Steps = d.Steps.ToList() }).ToList(),
            };
            if (!string.Equals(replacedId, _library.Id, StringComparison.OrdinalIgnoreCase))
                _retiredLibraryIds.Add(replacedId);
            _audit.Append("remediation_library_applied", "remediation-service",
                $"library={library.Id} revision={library.Revision} definitions={library.Definitions.Count} hash={library.ContentHash} via={via}", now);
            return new PolicyVerdict(true, $"automation library '{library.Id}' r{library.Revision} admitted via {via}");
        }
    }

    // ---- policy helpers ------------------------------------------------

    /// <summary>The effective approval tier for an action on a
    /// device: the MORE restrictive of the library tier and the
    /// policy tier setting. Policy can raise, never lower; an
    /// unparsable policy tier value raises to requires_approval
    /// (fail closed).</summary>
    public string EffectiveTier(AutomationDefinition def, IDeviceFacts facts)
    {
        var setting = _policy.ComputeEffective(facts).Get(RemediationPolicyKeys.ActionTier(def.Id));
        string? policyTier = null;
        if (setting is not null)
            policyTier = RemediationTiers.All.Contains(setting.Value ?? "")
                ? setting.Value : RemediationTiers.RequiresApproval;
        return RemediationTiers.Combine(def.ApprovalTier, policyTier);
    }

    private string? ActionDisabledReason(AutomationDefinition def, IDeviceFacts facts)
    {
        var setting = _policy.ComputeEffective(facts).Get(RemediationPolicyKeys.ActionEnabled(def.Id));
        if (setting is null) return null;
        if (bool.TryParse(setting.Value, out var enabled))
            return enabled ? null : $"automation '{def.Id}' is disabled for this device by policy ({RemediationPolicyKeys.ActionEnabled(def.Id)}=false)";
        return $"automation '{def.Id}' carries an unparsable policy enable value '{setting.Value}' — refused (fail closed)";
    }

    // ---- the IRemediationSink contract ---------------------------------

    /// <summary>RMM-01's dispatch contract: a condition fired and
    /// named this remediation. Outcomes are values, all audited:
    /// executed / parked pending approval / refused (named).</summary>
    public RemediationDispatchResult Dispatch(string remediationId, HealthAlertEvent alert, DateTimeOffset callerNow)
    {
        var now = EffectiveNow(callerNow); // D38-F3: service clock governs
        RemediationDispatchResult Refuse(string reason)
        {
            _audit.Append("remediation_dispatch_refused", "remediation-service",
                $"remediation={remediationId} device={alert.DeviceId} alert={alert.AlertId} reason={reason}", now);
            return new RemediationDispatchResult(false, reason);
        }

        var facts = _factsByDevice(alert.DeviceId);
        if (facts is null)
            return Refuse($"no device facts for '{alert.DeviceId}' — policy cannot be evaluated — refused (fail closed)");
        if (!IsEngineEnabled(facts))
            return Refuse($"auto-remediation is disabled by policy for this device ({RemediationPolicyKeys.RemediationEnabled}) — dispatch refuses; the policy toggle is the engine kill switch");

        AutomationDefinition? def;
        AutomationLibrary library;
        lock (_lock) { library = _library; def = library.Get(remediationId); }
        if (def is null)
            return Refuse($"unknown remediation '{remediationId}' — no such automation in library '{library.Id}' r{library.Revision} — refused");
        if (!def.Enabled)
            return Refuse($"automation '{def.Id}' is disabled in library '{library.Id}' — refused");
        if (ActionDisabledReason(def, facts) is { } disabled)
            return Refuse(disabled);

        if (EffectiveTier(def, facts) == RemediationTiers.RequiresApproval)
        {
            lock (_lock)
            {
                // D38-F6: parking is deduped per (action, alert) —
                // a storm on one alert parks ONE request, not one
                // per trigger — and the pending set is capped.
                var existing = _approvals.Values.FirstOrDefault(a =>
                    a.IsPending && a.AlertId == alert.AlertId && a.RemediationId == def.Id);
                if (existing is not null)
                    return new RemediationDispatchResult(false,
                        $"pending_approval:{existing.ApprovalId} (automation '{def.Id}' requires approval; already parked against alert {alert.AlertId})");
                if (_approvals.Values.Count(a => a.IsPending) >= MaxPendingApprovals)
                    return Refuse($"pending-approval cap reached ({MaxPendingApprovals}) — dispatch refuses rather than park unbounded approval state");
                var approval = new RemediationApprovalRequest(
                    Guid.NewGuid().ToString("N"), def.Id, alert.AlertId, alert.DeviceId, alert.ConditionId,
                    library.Id, library.ContentHash, now, RemediationApprovalStatuses.Pending, null, null, null,
                    AlertState: alert.State);
                _approvals[approval.ApprovalId] = approval;
                PruneApprovalsLocked();
                _audit.Append("remediation_approval_parked", "remediation-service",
                    $"approval={approval.ApprovalId} remediation={def.Id} device={alert.DeviceId} alert={alert.AlertId} condition={alert.ConditionId} tier=requires_approval — a trigger alone never runs a human-gated action", now);
                return new RemediationDispatchResult(false,
                    $"pending_approval:{approval.ApprovalId} (automation '{def.Id}' requires approval; parked against alert {alert.AlertId})");
            }
        }

        return Execute(def, library, alert, facts, now);
    }

    /// <summary>Execute one admitted definition against one alert,
    /// with the loop guard applied at execution time. Shared by the
    /// auto dispatch path and the approval path.</summary>
    private RemediationDispatchResult Execute(
        AutomationDefinition def, AutomationLibrary library, HealthAlertEvent alert,
        IDeviceFacts facts, DateTimeOffset now)
    {
        if (_signer is null)
        {
            const string reason = "no customer command signer is configured on the hub — remediation cannot mint its RMM-03 automation envelope — refused";
            _audit.Append("remediation_dispatch_refused", "remediation-service",
                $"remediation={def.Id} device={alert.DeviceId} alert={alert.AlertId} reason={reason}", now);
            return new RemediationDispatchResult(false, reason);
        }
        // D38-F2: the loop guard's check-and-record is ONE atomic
        // step — concurrent dispatches cannot both pass the check
        // and exceed the window/global caps.
        if (_loopGuard.TryRecord(def, alert.DeviceId, now) is { } guardRefusal)
        {
            _audit.Append("remediation_dispatch_refused", "remediation-service",
                $"remediation={def.Id} device={alert.DeviceId} alert={alert.AlertId} reason={guardRefusal}", now);
            return new RemediationDispatchResult(false, guardRefusal);
        }

        var envelope = _signer.Sign(SignedCommandClasses.Automation,
            Encoding.UTF8.GetBytes(RemediationBinding.Payload(def, library, alert.DeviceId, alert.AlertId, alert.ConditionId)),
            now, EnvelopeTtl);
        var journalEnvelope = _signer.Sign(SignedCommandClasses.ScriptExec,
            Encoding.UTF8.GetBytes($"script_chain|{def.Id}|{RemediationBinding.PlanHash(def)}"),
            now, EnvelopeTtl);

        RemediationExecution execution;
        try
        {
            execution = _runner.Run(def, library, alert, envelope, _journal, journalEnvelope,
                // D38-F10: policy is re-evaluated against FRESH
                // device facts at every step — a group/scope move
                // mid-run that turns remediation off is seen, not
                // frozen at dispatch time.
                policyStillEnabled: () =>
                {
                    var fresh = _factsByDevice(alert.DeviceId);
                    return fresh is not null && IsEngineEnabled(fresh) && ActionDisabledReason(def, fresh) is null;
                },
                now);
        }
        catch (Exception ex)
        {
            // D38-F10: a runner exception never escapes Dispatch
            // with the guard consumed and no record — the
            // reservation is released and a refused execution is
            // recorded + audited.
            _loopGuard.Release(def, alert.DeviceId, now);
            execution = new RemediationExecution(
                Guid.NewGuid().ToString("N"), def.Id, library.Id, library.Revision,
                alert.DeviceId, alert.AlertId, alert.ConditionId, now, now,
                RemediationOutcomes.Refused, Array.Empty<StepExecution>(), null, null);
            _audit.Append("remediation_dispatch_refused", "remediation-service",
                $"remediation={def.Id} device={alert.DeviceId} alert={alert.AlertId} reason=runner threw {ex.GetType().Name}: {RemediationRunner.CaptureOutput(ex.Message)} — recorded as refused, loop-guard reservation released", now);
            lock (_lock) { _executions.Add(execution); PruneExecutionsLocked(); }
            return new RemediationDispatchResult(false, $"execution refused (runner threw {ex.GetType().Name}): execution={execution.ExecutionId}");
        }
        // D38-F6: a run the runner REFUSED (gate/envelope/journal)
        // never executed — its guard reservation is released, so
        // refusals cannot burn the fleet's budget.
        if (execution.Outcome == RemediationOutcomes.Refused)
            _loopGuard.Release(def, alert.DeviceId, now);
        lock (_lock) { _executions.Add(execution); PruneExecutionsLocked(); }
        return execution.Outcome == RemediationOutcomes.Refused
            ? new RemediationDispatchResult(false, $"execution refused (see audit): execution={execution.ExecutionId}")
            : new RemediationDispatchResult(true,
                $"executed execution={execution.ExecutionId} outcome={execution.Outcome} job={execution.JobId ?? "(none)"}");
    }

    // D38-F6: bounded retention. Executions are evidence, pruned
    // oldest-first past the cap; approvals prune only TERMINAL
    // entries (a pending approval is never silently dropped).
    private void PruneExecutionsLocked()
    {
        while (_executions.Count > MaxRetainedExecutions)
            _executions.RemoveAt(0);
    }

    private void PruneApprovalsLocked()
    {
        while (_approvals.Count > MaxRetainedApprovals)
        {
            var oldestTerminal = _approvals.Values.Where(a => !a.IsPending)
                .OrderBy(a => a.RequestedUtc).FirstOrDefault();
            if (oldestTerminal is null) return;
            _approvals.Remove(oldestTerminal.ApprovalId);
        }
    }

    // ---- approvals -------------------------------------------------------

    /// <summary>Record a human approval and execute. EVERY gate
    /// re-runs at decision time: expiry, policy (the kill switch
    /// may have flipped while the approval sat parked), library
    /// content (a library revision since parking supersedes the
    /// parked request — the human approved THAT content, not
    /// whatever replaced it), and the loop guard.</summary>
    public (bool Ok, string Reason) Approve(string approvalId, string decidedBy, DateTimeOffset callerNow)
    {
        if (string.IsNullOrWhiteSpace(decidedBy)) return (false, "an approval needs a decider — refused (the decision is attributed or it does not happen)");
        var now = EffectiveNow(callerNow); // D38-F3: a backdated now cannot bypass the TTL
        RemediationApprovalRequest req;
        lock (_lock)
        {
            if (approvalId is null || !_approvals.TryGetValue(approvalId, out var found) || !found.IsPending)
                return (false, $"no pending approval '{approvalId}' — refused");
            // D38-F2: CLAIM the approval atomically, in the same
            // lock as the pending check. A concurrent Approve (or a
            // double-click) sees the claim and refuses — the action
            // executes exactly once. The claim is released in the
            // finally below on every path.
            if (!_approvalsInFlight.Add(approvalId))
                return (false, $"approval '{approvalId}' is already being executed by a concurrent decision — refused (single-use)");
            req = found;
        }
        try
        {
            return ApproveClaimed(req, decidedBy, now);
        }
        finally
        {
            lock (_lock) _approvalsInFlight.Remove(approvalId);
        }
    }

    private (bool Ok, string Reason) ApproveClaimed(RemediationApprovalRequest req, string decidedBy, DateTimeOffset now)
    {
        var approvalId = req.ApprovalId;
        if (now > req.RequestedUtc + ApprovalTtl)
        {
            SetApproval(req with { Status = RemediationApprovalStatuses.Expired, DecidedBy = decidedBy, DecidedUtc = now });
            _audit.Append("remediation_approval_expired", decidedBy,
                $"approval={req.ApprovalId} remediation={req.RemediationId} alert={req.AlertId} requested={req.RequestedUtc:O} ttl={ApprovalTtl} — approval refused as expired", now);
            return (false, $"approval '{approvalId}' expired (parked {req.RequestedUtc:O}, ttl {ApprovalTtl}) — refused; a fresh trigger must re-park it");
        }
        var facts = _factsByDevice(req.DeviceId);
        if (facts is null)
            return (false, $"no device facts for '{req.DeviceId}' — policy cannot be evaluated — approval refused (fail closed)");
        if (!IsEngineEnabled(facts))
        {
            _audit.Append("remediation_approval_refused", decidedBy,
                $"approval={req.ApprovalId} remediation={req.RemediationId} alert={req.AlertId} reason=engine disabled by policy ({RemediationPolicyKeys.RemediationEnabled}) at decision time — the kill switch governs parked approvals too", now);
            return (false, "auto-remediation is disabled by policy at decision time — approval cannot execute (the request stays pending)");
        }
        AutomationDefinition? def;
        AutomationLibrary library;
        lock (_lock) { library = _library; def = library.Get(req.RemediationId); }
        if (def is null || library.ContentHash != req.LibraryContentHash)
        {
            SetApproval(req with { Status = RemediationApprovalStatuses.SupersededLibraryChanged, DecidedBy = decidedBy, DecidedUtc = now });
            _audit.Append("remediation_approval_superseded", decidedBy,
                $"approval={req.ApprovalId} remediation={req.RemediationId} alert={req.AlertId} reason=the automation library changed since this approval was parked — the human approved content that is no longer in force", now);
            return (false, "the automation library changed since this approval was parked — superseded; a fresh trigger must re-park it");
        }
        if (ActionDisabledReason(def, facts) is { } disabled)
            return (false, disabled + " — approval cannot execute (the request stays pending)");

        // The parked alert snapshot is reconstructed from the
        // request — including the alert state CAPTURED AT PARK
        // TIME (D38-F7: the state is carried, never fabricated as
        // Raised). The centre's live alert is never mutated by an
        // approval; a condition that cleared while parked
        // supersedes the request through RecordConditionFeedback.
        var alert = new HealthAlertEvent(req.AlertId, req.DeviceId, req.ConditionId,
            "", "", string.IsNullOrEmpty(req.AlertState) ? HealthAlertStates.Raised : req.AlertState,
            req.RequestedUtc, req.RequestedUtc, 1,
            "parked remediation approval", null, null, null, null, "endpoint");
        var result = Execute(def, library, alert, facts, now);
        if (!result.Dispatched)
        {
            _audit.Append("remediation_approval_refused", decidedBy,
                $"approval={req.ApprovalId} remediation={req.RemediationId} alert={req.AlertId} reason={result.Outcome}", now);
            return (false, result.Outcome);
        }
        string? executionId;
        lock (_lock) executionId = _executions.LastOrDefault(e => e.AlertId == req.AlertId)?.ExecutionId;
        // D38-F2: the Executed mark is CONDITIONAL — if feedback
        // superseded this request while it executed, the
        // supersession stands and is never overwritten back.
        bool markedExecuted;
        lock (_lock)
        {
            markedExecuted = _approvals.TryGetValue(req.ApprovalId, out var current) && current.IsPending;
            if (markedExecuted)
                _approvals[req.ApprovalId] = req with
                {
                    Status = RemediationApprovalStatuses.Executed,
                    DecidedBy = decidedBy, DecidedUtc = now, ExecutionId = executionId,
                };
        }
        if (!markedExecuted)
            _audit.Append("remediation_approval_superseded", decidedBy,
                $"approval={req.ApprovalId} remediation={req.RemediationId} alert={req.AlertId} reason=the condition cleared while the approved execution ran — the run completed, and the request's status stands as superseded, not executed", now);
        _audit.Append("remediation_approval_executed", decidedBy,
            $"approval={req.ApprovalId} remediation={req.RemediationId} alert={req.AlertId} execution={executionId} outcome={result.Outcome}", now);
        return (true, result.Outcome);
    }

    /// <summary>Record a human denial. Terminal: the action never
    /// runs for this alert, and the denial is attributed + audited.
    /// The alert itself is untouched — denying a fix is not
    /// acknowledging the fault away.</summary>
    public (bool Ok, string Reason) Deny(string approvalId, string decidedBy, DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(decidedBy)) return (false, "a denial needs a decider — refused");
        lock (_lock)
        {
            if (approvalId is null || !_approvals.TryGetValue(approvalId, out var req) || !req.IsPending)
                return (false, $"no pending approval '{approvalId}' — refused");
            _approvals[approvalId] = req with
            {
                Status = RemediationApprovalStatuses.Denied, DecidedBy = decidedBy, DecidedUtc = now,
            };
            _audit.Append("remediation_approval_denied", decidedBy,
                $"approval={approvalId} remediation={req.RemediationId} alert={req.AlertId} device={req.DeviceId} — the action will not run for this alert", now);
            return (true, $"approval '{approvalId}' denied by {decidedBy}; automation '{req.RemediationId}' will not run for alert {req.AlertId}");
        }
    }

    private void SetApproval(RemediationApprovalRequest req)
    {
        lock (_lock) _approvals[req.ApprovalId] = req;
    }

    // ---- feedback: closing the loop into RMM-01 --------------------------

    /// <summary>Report the triggering condition's OBSERVED state
    /// back after an execution (the monitor's next cycles are the
    /// observer). This is the ONLY path that moves an execution's
    /// ConditionCleared: true = the condition was observed clear,
    /// false = it is still firing. A still-pending approval for the
    /// alert is superseded when the condition clears (the fix is
    /// moot). This method deliberately does NOT ack or reset the
    /// alert — the alert centre's own lifecycle (the monitor's
    /// auto-reset on a clear sample) owns that; what remediation
    /// contributes is the honest record of whether its action
    /// worked. Returns the executions updated.</summary>
    public int RecordConditionFeedback(string alertId, bool conditionCleared, DateTimeOffset callerNow)
    {
        var now = EffectiveNow(callerNow); // D38-F3
        var updated = 0;
        lock (_lock)
        {
            for (var i = 0; i < _executions.Count; i++)
            {
                if (_executions[i].AlertId != alertId) continue;
                // D38-F7: a REFUSED run never ran — feedback about
                // the condition says nothing about it, and a
                // refused run must never read 'cleared'.
                if (_executions[i].Outcome == RemediationOutcomes.Refused) continue;
                _executions[i] = _executions[i] with { ConditionCleared = conditionCleared };
                updated++;
            }
            if (conditionCleared)
            {
                foreach (var req in _approvals.Values.Where(a => a.AlertId == alertId && a.IsPending).ToList())
                {
                    _approvals[req.ApprovalId] = req with { Status = RemediationApprovalStatuses.SupersededConditionCleared };
                    _audit.Append("remediation_approval_superseded", "remediation-service",
                        $"approval={req.ApprovalId} remediation={req.RemediationId} alert={alertId} reason=the condition cleared before the approval was decided — the fix is moot", now);
                }
            }
        }
        _audit.Append(conditionCleared ? "remediation_condition_cleared" : "remediation_condition_persisted",
            "remediation-service",
            $"alert={alertId} executionsUpdated={updated} conditionCleared={conditionCleared} — recorded against the execution(s); the alert's own lifecycle is unchanged by this record", now);
        return updated;
    }
}

/// <summary>The honest host-wiring executor for this build: every
/// primitive reports that agent host wiring (service controller,
/// process control, the shell gate for run_script bodies, the
/// RMM-02 patch re-run target) is not wired here, and NO action is
/// taken. It exists so a wired-but-unproven host fails by name
/// instead of pretending a fix happened — live execution proof is
/// PENDING, in the PatchService shape.</summary>
public sealed class HostWiringRemediationStepExecutor : IRemediationStepExecutor, IPatchRerunTarget
{
    public StepRunResult Execute(RemediationStep step, RemediationExecutionContext context) =>
        StepRunResult.Failure(
            $"host wiring pending: step kind '{step.Kind}' executes on the agent host (service/process control, path cleanup, shell gate) — not wired in this build; no action was taken");

    public StepRunResult RerunPatch(string patchEntryId, RemediationExecutionContext context) =>
        StepRunResult.Failure(
            $"host wiring pending: patch re-run for '{patchEntryId}' targets the RMM-02 patch service through IPatchRerunTarget — not wired in this build; no action was taken");
}
