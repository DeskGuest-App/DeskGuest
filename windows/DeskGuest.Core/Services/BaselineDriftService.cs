using System.Text;
using DeskGuest.Shared.Baselines;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.Monitoring;
using DeskGuest.Shared.Security;

namespace DeskGuest.Core.Services;

// =====================================================================
// RMM-19 — BaselineDriftService: the Core wiring for desired-state
// baselines + drift detection.
//
//   * Delivery: baselines arrive ONLY as RMM-03 signed commands
//     (class policy_delivery) — the endpoint verifies the customer's
//     signature before a baseline is even parsed, so a compromised
//     hub cannot rewrite desired state either. Admission (validation,
//     revision discipline, forward-only effective dates, defensive
//     copy) is the BaselineStore's; every outcome is a chained audit
//     event, and an admission that absorbs existing drift raises a
//     dedicated baseline_absorption_noted event per notice — the
//     absorption is never buried in a generic "applied" line.
//   * Comparison: agent-local, on the policy cadence, through the
//     IObservedStateProvider seam. A cycle that cannot observe
//     reports UNKNOWN — it raises nothing and clears nothing.
//   * Reporting: each deviation raises ONE alert in RMM-01's
//     HealthAlertCentre (kind baseline_drift, condition id per
//     item, detail = expected vs observed) under the centre's own
//     dedup / cooldown / flood discipline. When a deviation clears,
//     THIS service resets exactly the alerts it raised (tracked by
//     id) — it never touches RMM-01's own alerts sharing the centre.
//   * Remediation: a NEW drift alert whose item links an RMM-08 id
//     is offered to the DriftRemediationGate; only a gate pass
//     reaches the IRemediationSink, and the sink's own service
//     re-runs every RMM-08 gate (tiers, loop guard, signed
//     execution) before anything executes. Gate refusals are
//     audited with their reason.
//   * Everything is gated by TOTAL POLICY CONTROL:
//     rmm.baselines.enabled for the device (registry-seeded ON).
//     Disabled means no delivery effect beyond refusal records, no
//     comparison, no alerts — and the refusal is audited, never
//     silent.
// =====================================================================

/// <summary>One drift cycle's outcome — the endpoint-side record a
/// caller (the Core's duty loop, tests) reads.</summary>
public sealed record DriftCycleResult(
    bool BaselinesEnabled,
    bool Ran,
    string? NotRunReason,
    DriftEvaluation? Evaluation,
    IReadOnlyList<HealthAlertEvent> NewAlerts,
    IReadOnlyList<HealthAlertEvent> ResetAlerts,
    IReadOnlyList<string> RemediationOutcomes)
{
    public IReadOnlyList<HealthAlertEvent> NewAlerts { get; init; } = NewAlerts ?? Array.Empty<HealthAlertEvent>();
    public IReadOnlyList<HealthAlertEvent> ResetAlerts { get; init; } = ResetAlerts ?? Array.Empty<HealthAlertEvent>();
    public IReadOnlyList<string> RemediationOutcomes { get; init; } = RemediationOutcomes ?? Array.Empty<string>();
}

/// <summary>The hub-facing drift report for one device: facts (the
/// baseline judged against, the outcome, the per-item deviations,
/// the active alert ids) — the payload that rides the existing
/// heartbeat/state channel shape, like RMM-01's DeviceHealthReport.</summary>
public sealed record DeviceDriftReport(
    string DeviceId,
    long Seq,
    DateTimeOffset GeneratedUtc,
    string BaselineHash,
    IReadOnlyList<string> BaselineDocuments,
    string Outcome,
    IReadOnlyList<DriftDeviation> Deviations,
    IReadOnlyList<DriftIndeterminate> Indeterminate,
    IReadOnlyList<string> ActiveDriftAlertIds,
    // D38 fix (F4): the report now carries WHEN the state it
    // reports was observed and judged, and whether that judgment
    // is STALE. A report built long after the last evaluation
    // flips its outcome to unknown (see BuildReport) — silence
    // after a compliant cycle must never read as health forever.
    DateTimeOffset? ObservedUtc = null,
    DateTimeOffset? EvaluatedUtc = null,
    bool IsStale = false)
{
    public IReadOnlyList<DriftDeviation> Deviations { get; init; } = Deviations ?? Array.Empty<DriftDeviation>();
    public IReadOnlyList<DriftIndeterminate> Indeterminate { get; init; } = Indeterminate ?? Array.Empty<DriftIndeterminate>();
    public IReadOnlyList<string> ActiveDriftAlertIds { get; init; } = ActiveDriftAlertIds ?? Array.Empty<string>();
}

public sealed class BaselineDriftService
{
    private readonly ChainedAuditLog _audit;
    private readonly ManagementPolicyService _policies;
    private readonly HealthAlertCentre _centre;
    private readonly SignedCommandGate? _gate;
    private readonly IObservedStateProvider _provider;
    private readonly Func<string, IDeviceFacts?> _factsFor;
    private readonly IRemediationSink? _remediation;
    private readonly Func<DateTimeOffset> _now;
    private readonly object _lock = new();

    private readonly Dictionary<string, DriftEvaluation> _lastEvaluation = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, ObservedEndpointState> _lastObserved = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DateTimeOffset> _lastRunUtc = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, List<string>> _raisedAlertIdsByDevice = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, long> _reportSeq = new(StringComparer.OrdinalIgnoreCase);
    // D38 fix (F2): the absorption context is kept SEPARATELY from
    // the last evaluation. A collector-gap cycle overwrites the
    // last evaluation with an indeterminate one (correct for
    // reporting), but the deviations that cycle could not judge do
    // not stop being on record — the evaluation + observed state
    // that PRODUCED them stays here, pruned only when a later
    // cycle actually judges an item again, so a laundering
    // revision admitted after a gap still has to name them.
    private readonly Dictionary<string, DriftEvaluation> _absorptionEval = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, ObservedEndpointState> _absorptionObs = new(StringComparer.OrdinalIgnoreCase);
    // D38 fix (F9): the service's private admission capability.
    // The store is locked to it at construction, so the public
    // Store surface can no longer be used to admit a baseline
    // around the signed-delivery gate and the chained audit.
    private readonly BaselineAdmissionToken _admissionToken = new();

    /// <summary>D38 fix (F3): observation freshness bounds, judged
    /// against the service clock — the stale guard used to compare
    /// only against the previous accepted observation, so a
    /// future-dated snapshot could poison the watermark and an
    /// arbitrarily old snapshot was accepted as a device's first.
    /// A snapshot more than this far in the future, or older than
    /// this at acceptance, judges nothing.</summary>
    public static readonly TimeSpan MaxObservationFutureSkew = TimeSpan.FromMinutes(5);
    public static readonly TimeSpan MaxObservationAge = TimeSpan.FromHours(24);

    public BaselineStore Store { get; }

    public BaselineDriftService(
        ChainedAuditLog audit,
        ManagementPolicyService policies,
        HealthAlertCentre centre,
        SignedCommandGate? gate,
        IObservedStateProvider provider,
        Func<string, IDeviceFacts?> factsFor,
        BaselineStore? store = null,
        IRemediationSink? remediation = null,
        Func<DateTimeOffset>? now = null)
    {
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _policies = policies ?? throw new ArgumentNullException(nameof(policies));
        _centre = centre ?? throw new ArgumentNullException(nameof(centre));
        _gate = gate;
        _provider = provider ?? throw new ArgumentNullException(nameof(provider));
        _factsFor = factsFor ?? throw new ArgumentNullException(nameof(factsFor));
        Store = store ?? new BaselineStore();
        // D38 fix (F9): lock the store to this service. Direct
        // Store.Admit calls from any other holder of the reference
        // now refuse; admission flows through ApplySignedBaseline
        // (RMM-03 verified) or AdmitLocalBaseline (audited), only.
        Store.LockAdmission(_admissionToken);
        _remediation = remediation;
        _now = now ?? (() => DateTimeOffset.UtcNow);
    }

    private IDeviceFacts? Facts(string deviceId) => _factsFor(deviceId);

    public bool BaselinesEnabled(IDeviceFacts facts) =>
        _policies.IsEnabled(facts, BaselinePolicyKeys.Enabled);

    public DriftEvaluation? LastEvaluation(string deviceId)
    {
        lock (_lock) return deviceId is not null && _lastEvaluation.TryGetValue(deviceId, out var e) ? e : null;
    }

    // ---- baseline delivery -------------------------------------------------

    /// <summary>Apply a baseline delivered as a signed command
    /// envelope. Verification (RMM-03, class policy_delivery)
    /// precedes parsing; the store's admission discipline follows;
    /// absorptions are audited per notice.</summary>
    public PolicyVerdict ApplySignedBaseline(SignedCommandEnvelope? envelope, string deviceIdForAbsorption)
    {
        var now = _now();
        if (_gate is null)
        {
            const string reason = "no customer command key is configured on this endpoint — signed baseline delivery refuses (RMM-03)";
            _audit.Append("baseline_refusal", "baseline-drift", reason, now);
            return new PolicyVerdict(false, reason);
        }
        var verdict = _gate.Authorize(envelope, now, SignedCommandClasses.PolicyDelivery);
        if (!verdict.Allowed) return new PolicyVerdict(false, verdict.Reason);
        BaselineDocument? doc;
        try { doc = BaselineDocument.FromCanonicalJson(Encoding.UTF8.GetString(verdict.Payload!)); }
        catch { doc = null; }
        if (doc is null)
        {
            const string reason = "signed payload did not parse as a baseline document — refused";
            _audit.Append("baseline_refusal", "baseline-drift", reason, now);
            return new PolicyVerdict(false, reason);
        }
        return Admit(doc, "signed delivery", deviceIdForAbsorption);
    }

    /// <summary>Admit a baseline from an already-trusted local path
    /// (tests, hub-side authoring before signing). The same store
    /// discipline applies; the admission is audited as a baseline
    /// change, absorptions per notice. This is the ONLY unsigned
    /// entry point, and it is audited — the store itself is locked
    /// to this service (D38 F9), so Store.Admit cannot be used to
    /// route around it.</summary>
    public PolicyVerdict AdmitLocalBaseline(BaselineDocument doc, string via, string deviceIdForAbsorption) =>
        Admit(doc, via, deviceIdForAbsorption);

    /// <summary>The absorption context held for one device: the
    /// drift-record evaluation + observed state when drift is on
    /// record (D38 F2 — a later gap cycle must not erase it),
    /// otherwise the last evaluation + observed state.</summary>
    private (DriftEvaluation? Eval, ObservedEndpointState? Obs) AbsorptionContext(string deviceId)
    {
        lock (_lock)
        {
            if (_absorptionEval.TryGetValue(deviceId, out var ae) &&
                _absorptionObs.TryGetValue(deviceId, out var ao))
                return (ae, ao);
            if (_lastEvaluation.TryGetValue(deviceId, out var e) &&
                _lastObserved.TryGetValue(deviceId, out var o))
                return (e, o);
            return (null, null);
        }
    }

    private PolicyVerdict Admit(BaselineDocument doc, string via, string deviceIdForAbsorption)
    {
        var now = _now();
        // Absorption context: the device whose drift is on record,
        // when we hold both an evaluation and its observed state.
        IDeviceFacts? facts = null;
        DriftEvaluation? lastEval = null;
        ObservedEndpointState? lastObs = null;
        IReadOnlyList<string> groups = Array.Empty<string>();
        ResolvedBaselinePolicy? policy = null;
        if (deviceIdForAbsorption is not null)
            (lastEval, lastObs) = AbsorptionContext(deviceIdForAbsorption);
        if (lastEval is not null)
        {
            facts = Facts(deviceIdForAbsorption);
            if (facts is not null)
            {
                groups = _policies.Engine.MemberGroupIds(facts);
                policy = BaselinePolicyResolver.Resolve(_policies.Engine, facts);
            }
            else { lastEval = null; lastObs = null; }
        }

        var result = Store.Admit(doc, now, facts, groups, lastEval, lastObs, policy?.ScopeKinds,
            _admissionToken);
        if (!result.Accepted)
        {
            _audit.Append("baseline_refusal", "baseline-drift",
                $"baseline={doc.Id} via={via} reason={result.Reason}", now);
            return new PolicyVerdict(false, result.Reason);
        }
        _audit.Append("baseline_applied", "baseline-drift",
            $"baseline={doc.Id} revision={doc.Revision} level={doc.Level} target={doc.TargetId} items={doc.Items.Count} effective={doc.EffectiveUtc:O} authoredBy={doc.AuthoredBy} hash={doc.ContentHash} via={via}", now);
        foreach (var abs in result.Absorptions)
            _audit.Append("baseline_absorption_noted", "baseline-drift",
                $"baseline={doc.Id} revision={doc.Revision} device={deviceIdForAbsorption} item={abs.ItemId} kind={abs.Kind} target={abs.Target} mechanism={abs.Mechanism} oldExpected={abs.OldExpected} observed={abs.Observed} newExpected={abs.NewExpected} — existing drift absorbed by this baseline change; the drift history is NOT erased", now);

        // D38 fix (F1): the caller-supplied device is NOT the only
        // device whose drift this revision can absorb — an org or
        // group revision reaches every device in its scope, and a
        // wrong/null caller id must not launder the rest. For
        // EVERY other device with drift on record, preview the
        // absorption against the now-admitted store and name each
        // one in the audit chain and in the returned verdict.
        var otherNotices = new List<string>();
        List<string> contextDevices;
        lock (_lock)
            contextDevices = _absorptionEval.Keys
                .Union(_lastEvaluation.Keys, StringComparer.OrdinalIgnoreCase)
                .Where(d => !string.Equals(d, deviceIdForAbsorption, StringComparison.OrdinalIgnoreCase))
                .ToList();
        foreach (var other in contextDevices)
        {
            var (oEval, oObs) = AbsorptionContext(other);
            if (oEval is null || oObs is null || oEval.Deviations.Count == 0) continue;
            var oFacts = Facts(other);
            if (oFacts is null) continue;
            var oGroups = _policies.Engine.MemberGroupIds(oFacts);
            var oPolicy = BaselinePolicyResolver.Resolve(_policies.Engine, oFacts);
            foreach (var abs in Store.PreviewAbsorptions(doc, oFacts, oGroups, oEval, oObs, oPolicy.ScopeKinds))
            {
                _audit.Append("baseline_absorption_noted", "baseline-drift",
                    $"baseline={doc.Id} revision={doc.Revision} device={other} item={abs.ItemId} kind={abs.Kind} target={abs.Target} mechanism={abs.Mechanism} oldExpected={abs.OldExpected} observed={abs.Observed} newExpected={abs.NewExpected} — existing drift on device '{other}' absorbed by this baseline change (the admission named device '{deviceIdForAbsorption}'; absorption is checked for every device with drift on record); the drift history is NOT erased", now);
                otherNotices.Add($"{other}:{abs.ItemId} ({abs.Mechanism})");
            }
        }
        var reason = result.Reason;
        if (otherNotices.Count > 0)
            reason += $"; ALSO ABSORBS existing deviation(s) on other devices: {string.Join("; ", otherNotices)} — named per device in the audit chain";
        return new PolicyVerdict(true, reason);
    }

    // ---- the comparison cycle -------------------------------------------------

    /// <summary>Run one comparison cycle for one device. Cadence is
    /// policy: a non-forced cycle inside the cadence window does
    /// not observe and does not judge (NotRunReason names it).
    /// A forced cycle always runs — the cadence governs the duty
    /// loop, never an operator's explicit check.</summary>
    public DriftCycleResult RunCycle(string deviceId, bool force = false)
    {
        var now = _now();
        var facts = Facts(deviceId);
        if (facts is null)
        {
            var reason = $"unknown device '{deviceId}' — drift cycle refuses (no facts, no comparison)";
            _audit.Append("baseline_refusal", "baseline-drift", $"device={deviceId} reason={reason}", now);
            return new DriftCycleResult(false, false, reason, null, null, null, null);
        }
        if (!BaselinesEnabled(facts))
        {
            var reason = $"baselines are disabled by policy for device '{deviceId}' ({BaselinePolicyKeys.Enabled}) — no comparison performed";
            _audit.Append("baseline_disabled", "baseline-drift", $"device={deviceId} reason={reason}", now);
            return new DriftCycleResult(false, false, reason, null, null, null, null);
        }
        var policy = BaselinePolicyResolver.Resolve(_policies.Engine, facts);
        lock (_lock)
        {
            if (!force && _lastRunUtc.TryGetValue(deviceId, out var last) && now - last < policy.Cadence)
                return new DriftCycleResult(true, false,
                    $"inside the comparison cadence ({policy.CadenceSeconds}s; last cycle {last:O}) — not due",
                    _lastEvaluation.GetValueOrDefault(deviceId), null, null, null);
        }

        ObservedEndpointState? observed;
        try { observed = _provider.Observe(deviceId, now); }
        catch (Exception ex)
        {
            _audit.Append("drift_observation_failed", "baseline-drift",
                $"device={deviceId} provider threw {ex.GetType().Name}: {ex.Message} — cycle is UNKNOWN, nothing raised, nothing cleared", now);
            observed = null;
        }
        lock (_lock) _lastRunUtc[deviceId] = now;
        if (observed is null)
        {
            _audit.Append("drift_cycle_unknown", "baseline-drift",
                $"device={deviceId} reason=no observed state available (provider returned nothing) — compliance is UNKNOWN, never assumed", now);
            return new DriftCycleResult(true, true, "no observed state — outcome unknown",
                _lastEvaluation.GetValueOrDefault(deviceId), null, null, null);
        }
        if (!string.Equals(observed.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase))
        {
            _audit.Append("drift_cycle_unknown", "baseline-drift",
                $"device={deviceId} reason=provider returned observed state for '{observed.DeviceId}' — a mismatched observation judges nothing", now);
            return new DriftCycleResult(true, true, "observed state device mismatch — outcome unknown",
                _lastEvaluation.GetValueOrDefault(deviceId), null, null, null);
        }
        // Stale-replay guard (recovery-lane fix, RMM-19; extended
        // by the D38 fix, F3): an observation OLDER than the last
        // one this service accepted for the device judges nothing
        // and clears nothing — a replayed pre-drift snapshot must
        // not launder live drift (the RMM-18 stale-replay
        // discipline, applied here). The recovery guard compared
        // ONLY against the previous accepted observation, which a
        // hostile or broken collector could bypass or weaponise:
        //   (a) a snapshot dated in the FUTURE was accepted, and
        //       then made every genuine later observation "stale"
        //       — the device froze at whatever the future snapshot
        //       said. Now: beyond MaxObservationFutureSkew of the
        //       service clock refuses.
        //   (b) an arbitrarily OLD snapshot was accepted as a
        //       device's first observation (or the first after a
        //       restart, the watermark being in memory). Now:
        //       older than MaxObservationAge at acceptance refuses
        //       even with no watermark.
        //   (c) an EQUAL timestamp with DIFFERENT content was
        //       accepted (the check was <, not <=), so two
        //       different states claimed the same instant and the
        //       later one judged and cleared. Now: equal timestamp
        //       + different content refuses as a timestamp
        //       conflict; equal timestamp + identical content is
        //       the same snapshot re-presented and may judge (a
        //       baseline change in between is judged against it).
        string? staleReason = null;
        if (observed.ObservedUtc > now + MaxObservationFutureSkew)
            staleReason = $"future-dated observation: observed {observed.ObservedUtc:O} is more than {MaxObservationFutureSkew} ahead of the service clock {now:O} — a future snapshot judges nothing and must not poison the freshness watermark";
        else if (now - observed.ObservedUtc > MaxObservationAge)
            staleReason = $"expired observation: observed {observed.ObservedUtc:O} is more than {MaxObservationAge} old at acceptance ({now:O}) — a snapshot that old judges nothing, watermark or no watermark";
        lock (_lock)
        {
            if (staleReason is null && _lastObserved.TryGetValue(deviceId, out var prev))
            {
                if (observed.ObservedUtc < prev.ObservedUtc)
                    staleReason = $"stale observation replayed: observed {observed.ObservedUtc:O} is older than the last accepted observation {prev.ObservedUtc:O} — a stale snapshot judges nothing and clears nothing";
                else if (observed.ObservedUtc == prev.ObservedUtc &&
                         !string.Equals(ObservedFingerprint(observed), ObservedFingerprint(prev), StringComparison.Ordinal))
                    staleReason = $"timestamp conflict: observed {observed.ObservedUtc:O} equals the last accepted observation's timestamp but its content differs — two different states cannot share one instant; the conflicting snapshot judges nothing and clears nothing";
            }
            if (staleReason is not null)
            {
                _audit.Append("drift_cycle_unknown", "baseline-drift",
                    $"device={deviceId} reason={staleReason}", now);
                return new DriftCycleResult(true, true,
                    "stale observation refused — outcome unknown",
                    _lastEvaluation.GetValueOrDefault(deviceId), null, null, null);
            }
        }

        var groups = _policies.Engine.MemberGroupIds(facts);
        var effective = Store.ComputeEffective(facts, groups, now);
        var evaluation = BaselineEvaluator.Evaluate(effective, observed, policy.ScopeKinds, now);
        // The deviations on record BEFORE this cycle (D38 F1/F2):
        // the reset pass below reads the clearing of each of them
        // against the expectation that was in force when it was
        // recorded, and the absorption context is pruned/advanced
        // by what this cycle actually judged.
        Dictionary<string, DriftDeviation> prevDrift;
        lock (_lock)
        {
            prevDrift = _absorptionEval.TryGetValue(deviceId, out var ae)
                ? ae.Deviations.ToDictionary(d => d.ItemId, StringComparer.OrdinalIgnoreCase)
                : new Dictionary<string, DriftDeviation>(StringComparer.OrdinalIgnoreCase);
            _lastEvaluation[deviceId] = evaluation;
            _lastObserved[deviceId] = observed;
            UpdateAbsorptionContextLocked(deviceId, evaluation, observed);
        }
        _audit.Append("drift_evaluated", "baseline-drift",
            $"device={deviceId} outcome={evaluation.Outcome} baselineHash={evaluation.BaselineHash} documents={string.Join(",", evaluation.BaselineDocuments)} judged={evaluation.ItemsJudged} deviations={evaluation.Deviations.Count} indeterminate={evaluation.Indeterminate.Count} outOfScope={evaluation.ItemsSkippedOutOfScope} disabledItems={evaluation.ItemsSkippedDisabled}", now);
        foreach (var gap in evaluation.Indeterminate)
            _audit.Append("drift_indeterminate", "baseline-drift",
                $"device={deviceId} item={gap.ItemId} kind={gap.Kind} target={gap.Target} reason={gap.Reason}", now);

        // Bridge deviations into RMM-01's alert centre.
        var newAlerts = new List<HealthAlertEvent>();
        var remediationOutcomes = new List<string>();
        var stillDeviating = evaluation.Deviations.Select(d => d.ConditionId).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var dev in evaluation.Deviations)
        {
            var outcome = _centre.Raise(deviceId, dev.ConditionId, DriftAlerting.Kind,
                dev.Severity, dev.Detail + $" [baseline {dev.SourceDocumentId}@r{dev.SourceRevision}]",
                DriftAlerting.Source, policy.DriftCooldown, now);
            if (outcome.Outcome == RaiseOutcome.New && outcome.Alert is not null)
            {
                newAlerts.Add(outcome.Alert);
                lock (_lock)
                {
                    if (!_raisedAlertIdsByDevice.TryGetValue(deviceId, out var ids))
                        _raisedAlertIdsByDevice[deviceId] = ids = new List<string>();
                    ids.Add(outcome.Alert.AlertId);
                }
                MaybeRemediate(dev, outcome.Alert, policy, facts, now, remediationOutcomes);
            }
        }

        // Reset exactly the drift alerts THIS service raised whose
        // items no longer deviate. An indeterminate item is NOT a
        // clearance — its alert stays (a collector gap never clears
        // real drift).
        var resetAlerts = new List<HealthAlertEvent>();
        var indeterminateConditions = evaluation.Indeterminate
            .Select(g => DriftAlerting.ConditionIdFor(g.ItemId)).ToHashSet(StringComparer.OrdinalIgnoreCase);
        List<string> tracked;
        lock (_lock)
            tracked = _raisedAlertIdsByDevice.TryGetValue(deviceId, out var t) ? t.ToList() : new List<string>();
        var pruneIds = new List<string>();
        foreach (var alertId in tracked)
        {
            var alert = _centre.Get(alertId);
            // D38 fix (F10): an alert that is gone or no longer
            // active — reset by an operator, expired by the centre
            // — leaves the tracked list NOW. Previously such ids
            // were skipped forever and every cycle and every report
            // re-fetched them, and rotating item ids grew the list
            // without bound.
            if (alert is null || !alert.IsActive) { pruneIds.Add(alertId); continue; }
            if (stillDeviating.Contains(alert.ConditionId)) continue;
            if (indeterminateConditions.Contains(alert.ConditionId)) continue;
            // Clearing-by-change naming (recovery-lane fix, RMM-19):
            // an alert can also stop firing because the item left
            // the comparison — removed from the effective baseline,
            // disabled, or its kind taken out of policy scope. That
            // is NOT the endpoint returning to the desired state,
            // and the clearing is named as such in the audit chain
            // (policy scope edits bypass baseline admission, so
            // without this record a scope narrowing would launder
            // drift silently at reset time).
            var itemId = alert.ConditionId.StartsWith("drift:", StringComparison.OrdinalIgnoreCase)
                ? alert.ConditionId["drift:".Length..] : alert.ConditionId;
            var entry = effective.Get(itemId);
            string? clearedByChange =
                entry is null ? "item_removed"
                : !entry.Item.Enabled ? "item_disabled"
                : !policy.ScopeKinds.Contains(entry.Item.Kind) ? "out_of_scope"
                : null;
            // D38 fix (F1): the fourth clearing-by-change — the
            // item is still judged, but the baseline's expectation
            // for it MOVED since the deviation was recorded (onto
            // the drifted value, or anywhere else). The recovery
            // fix named removal/disable/scope only, so a moved
            // expectation reset as "item now matches the baseline"
            // — an honest-looking recovery for what was actually a
            // baseline change. The deviation on record carries the
            // expectation it was judged against; if the effective
            // item's kind, target or expectation differs from it,
            // the clearing is named expectation_moved. (A kind or
            // target swap under the same id is named here too: the
            // judged item is not the item now in force.)
            if (clearedByChange is null && prevDrift.TryGetValue(itemId, out var recorded))
            {
                var item = entry!.Item;
                bool expectationDiffers;
                if (item.Kind == BaselineItemKinds.SoftwareForbidden)
                    // Presence is the whole expectation; it cannot
                    // "move" — only a kind/target swap (checked
                    // below) changes what this item judges.
                    expectationDiffers = false;
                else if (item.Kind == BaselineItemKinds.SoftwareRequired &&
                         recorded.Expected.StartsWith("version >= ", StringComparison.Ordinal))
                    expectationDiffers = !string.Equals(item.ExpectedVersion ?? "",
                        recorded.Expected["version >= ".Length..], StringComparison.OrdinalIgnoreCase);
                else if (item.Kind == BaselineItemKinds.SoftwareRequired)
                    expectationDiffers = false; // recorded expectation was presence ("installed")
                else
                    expectationDiffers = !string.Equals(item.Expected ?? "", recorded.Expected,
                        StringComparison.OrdinalIgnoreCase);
                if (!string.Equals(item.Kind, recorded.Kind, StringComparison.OrdinalIgnoreCase) ||
                    !string.Equals(item.Target, recorded.Target, StringComparison.OrdinalIgnoreCase) ||
                    expectationDiffers)
                    clearedByChange = "expectation_moved";
            }
            if (clearedByChange is not null)
                _audit.Append("drift_alert_cleared_by_change", "baseline-drift",
                    $"device={deviceId} item={itemId} mechanism={clearedByChange} alert={alertId} — drift alert cleared because the baseline/policy stopped judging this item, NOT because the endpoint returned to the desired state", now);
            var reset = _centre.Reset(alertId, "baseline-drift",
                clearedByChange is not null
                    ? $"auto-reset: item no longer judged ({clearedByChange}) — cleared by baseline/policy change, named in the audit chain"
                    : "auto-reset: drift cleared (item now matches the baseline)", now);
            if (reset is not null) resetAlerts.Add(reset);
        }
        if (resetAlerts.Count > 0 || pruneIds.Count > 0)
        {
            lock (_lock)
            {
                var gone = resetAlerts.Select(a => a.AlertId).ToHashSet(StringComparer.Ordinal);
                gone.UnionWith(pruneIds);
                if (_raisedAlertIdsByDevice.TryGetValue(deviceId, out var ids))
                    ids.RemoveAll(gone.Contains);
            }
        }

        return new DriftCycleResult(true, true, null, evaluation, newAlerts, resetAlerts, remediationOutcomes);
    }

    /// <summary>Advance/prune the absorption context (D38 F2)
    /// after a judged cycle. Deviations this cycle found REPLACE
    /// the record (with this cycle's snapshot as their evidence);
    /// deviations a previous cycle found SURVIVE while this cycle
    /// leaves their item indeterminate (a collector gap is not a
    /// clearance, and the laundering revision that arrives after
    /// the gap must still name them); an item this cycle JUDGED
    /// compliant leaves the record. Caller holds _lock.</summary>
    private void UpdateAbsorptionContextLocked(string deviceId, DriftEvaluation evaluation, ObservedEndpointState observed)
    {
        var kept = new List<DriftDeviation>();
        if (_absorptionEval.TryGetValue(deviceId, out var prev))
        {
            var nowDeviating = evaluation.Deviations.Select(d => d.ItemId)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            var nowIndeterminate = evaluation.Indeterminate.Select(g => g.ItemId)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach (var dev in prev.Deviations)
            {
                if (nowDeviating.Contains(dev.ItemId)) continue;      // replaced below
                if (nowIndeterminate.Contains(dev.ItemId)) kept.Add(dev); // gap: still on record
                // otherwise judged compliant this cycle: off the record
            }
        }
        var merged = evaluation.Deviations.Concat(kept).ToList();
        if (merged.Count == 0)
        {
            _absorptionEval.Remove(deviceId);
            _absorptionObs.Remove(deviceId);
        }
        else if (evaluation.Deviations.Count > 0)
        {
            _absorptionEval[deviceId] = evaluation with { Deviations = merged };
            _absorptionObs[deviceId] = observed;
        }
        else if (kept.Count > 0 && _absorptionEval.TryGetValue(deviceId, out var existing))
        {
            // Gap cycle only: keep the original evidence snapshot,
            // narrow the record to the kept deviations.
            _absorptionEval[deviceId] = existing with { Deviations = kept };
        }
    }

    /// <summary>A content fingerprint of one observed snapshot,
    /// for the equal-timestamp conflict check (D38 F3c): two
    /// snapshots at the same ObservedUtc are "the same snapshot"
    /// only when every collected section and reading matches.</summary>
    private static string ObservedFingerprint(ObservedEndpointState o)
    {
        var sb = new StringBuilder();
        sb.Append(o.DeviceId).Append('|');
        sb.Append(string.Join(",", o.CollectedSections.OrderBy(s => s, StringComparer.Ordinal))).Append('|');
        foreach (var s in o.Services.OrderBy(s => s.Name, StringComparer.OrdinalIgnoreCase))
            sb.Append("svc:").Append(s.Name).Append('=').Append(s.State).Append(';');
        sb.Append('|');
        if (o.Settings is not null)
            foreach (var kv in o.Settings.OrderBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase))
                sb.Append("set:").Append(kv.Key).Append('=').Append(kv.Value).Append(';');
        sb.Append('|');
        foreach (var s in o.Software.OrderBy(s => s.Name, StringComparer.OrdinalIgnoreCase))
            sb.Append("sw:").Append(s.Name).Append('=').Append(s.Version).Append(';');
        sb.Append('|');
        if (o.Security is not null)
            sb.Append("sec:").Append(o.Security.AvEnabled).Append(',')
              .Append(o.Security.FirewallEnabled).Append(',').Append(o.Security.EncryptionEnabled);
        return sb.ToString();
    }

    private void MaybeRemediate(DriftDeviation dev, HealthAlertEvent alert, ResolvedBaselinePolicy policy,
        IDeviceFacts facts, DateTimeOffset now, List<string> outcomes)
    {
        if (string.IsNullOrWhiteSpace(dev.RemediationId)) return; // report-only item: nothing to gate
        var engineEnabled = _policies.IsEnabled(facts, MonitoringPolicyKeys.RemediationEnabled);
        var (allowed, reason) = DriftRemediationGate.Evaluate(dev, policy, baselinesEnabled: true, engineEnabled);
        if (!allowed)
        {
            _audit.Append("drift_remediation_refused", "baseline-drift",
                $"device={alert.DeviceId} item={dev.ItemId} remediation={dev.RemediationId} reason={reason}", now);
            outcomes.Add($"refused:{dev.RemediationId}:{reason}");
            return;
        }
        if (_remediation is null)
        {
            _audit.Append("drift_remediation_refused", "baseline-drift",
                $"device={alert.DeviceId} item={dev.ItemId} remediation={dev.RemediationId} reason=policy allows it but no remediation sink is wired (RMM-08 not present) — nothing executed", now);
            outcomes.Add($"refused:{dev.RemediationId}:no remediation sink wired");
            return;
        }
        var result = _remediation.Dispatch(dev.RemediationId!, alert, now);
        _audit.Append(result.Dispatched ? "drift_remediation_dispatched" : "drift_remediation_failed",
            "baseline-drift",
            $"device={alert.DeviceId} item={dev.ItemId} remediation={dev.RemediationId} alert={alert.AlertId} outcome={result.Outcome}", now);
        outcomes.Add($"{(result.Dispatched ? "dispatched" : "failed")}:{dev.RemediationId}:{result.Outcome}");
    }

    // ---- reporting -------------------------------------------------

    /// <summary>Build the drift report for the hub from the last
    /// evaluation + the centre's live alert state for the drift
    /// alerts this service raised. No evaluation yet → the outcome
    /// is stated as unknown with the reason in an indeterminate
    /// entry — never a fabricated compliant.</summary>
    public DeviceDriftReport BuildReport(string deviceId)
    {
        var now = _now();
        DriftEvaluation? eval;
        List<string> tracked;
        long seq;
        lock (_lock)
        {
            eval = _lastEvaluation.GetValueOrDefault(deviceId);
            tracked = _raisedAlertIdsByDevice.TryGetValue(deviceId, out var t) ? t.ToList() : new List<string>();
            seq = _reportSeq[deviceId] = _reportSeq.GetValueOrDefault(deviceId) + 1;
        }
        var activeIds = new List<string>();
        var deadIds = new List<string>();
        foreach (var id in tracked)
        {
            var a = _centre.Get(id);
            if (a is not null && a.IsActive) activeIds.Add(id);
            else deadIds.Add(id);
        }
        // D38 fix (F10): reports prune dead tracked ids too, not
        // just cycles — a device that is only ever reported on must
        // not accumulate them either.
        if (deadIds.Count > 0)
            lock (_lock)
            {
                if (_raisedAlertIdsByDevice.TryGetValue(deviceId, out var ids))
                    ids.RemoveAll(new HashSet<string>(deadIds, StringComparer.Ordinal).Contains);
            }
        if (eval is null)
            return new DeviceDriftReport(deviceId, seq, now, "(none)",
                Array.Empty<string>(), DriftOutcomes.Unknown,
                Array.Empty<DriftDeviation>(),
                new[] { new DriftIndeterminate("(none)", "(none)", "(none)", "no drift cycle has run for this device yet — state is unknown, not compliant") },
                activeIds);
        // D38 fix (F4): a report is only as fresh as its last
        // evaluation. Past the staleness bound (twice the policy
        // cadence, at least an hour) the last outcome is NOT
        // carried as current: the report flips to unknown, names
        // the silence in an indeterminate entry, and carries the
        // observed/evaluated timestamps so the hub can see exactly
        // how old the "health" it was being shown was. The last
        // deviations stay on the report as history, and live drift
        // ALERTS are untouched — an alert is a standing fact until
        // a judged cycle clears it; a stale report is about the
        // report's freshness, not a clearance.
        var staleAfter = TimeSpan.FromHours(1);
        var facts = Facts(deviceId);
        if (facts is not null)
        {
            var cadence = BaselinePolicyResolver.Resolve(_policies.Engine, facts).Cadence;
            if (cadence * 2 > staleAfter) staleAfter = cadence * 2;
        }
        var age = now - eval.EvaluatedUtc;
        if (age > staleAfter)
        {
            var gaps = eval.Indeterminate.Concat(new[]
            {
                new DriftIndeterminate("(report)", "(freshness)", "(evaluation)",
                    $"no drift cycle has judged this device for {age} (last evaluation {eval.EvaluatedUtc:O}, report generated {now:O}) — the last outcome ({eval.Outcome}) is stale and is NOT reported as current; silence is not health"),
            }).ToList();
            return new DeviceDriftReport(deviceId, seq, now, eval.BaselineHash, eval.BaselineDocuments,
                DriftOutcomes.Unknown, eval.Deviations, gaps, activeIds,
                eval.ObservedUtc, eval.EvaluatedUtc, IsStale: true);
        }
        return new DeviceDriftReport(deviceId, seq, now, eval.BaselineHash, eval.BaselineDocuments,
            eval.Outcome, eval.Deviations, eval.Indeterminate, activeIds,
            eval.ObservedUtc, eval.EvaluatedUtc, IsStale: false);
    }

    /// <summary>D38 fix (F10): evict ALL per-device state this
    /// service holds (last evaluation/observed, absorption context,
    /// cadence watermark, tracked alert ids, report sequence) —
    /// the host calls this when a device is decommissioned or
    /// re-imaged, so the per-device dictionaries do not grow for
    /// the life of the process. Standing alerts in the centre are
    /// NOT touched: they are the centre's record, not this
    /// service's cache.</summary>
    public void PurgeDevice(string deviceId)
    {
        if (deviceId is null) return;
        lock (_lock)
        {
            _lastEvaluation.Remove(deviceId);
            _lastObserved.Remove(deviceId);
            _lastRunUtc.Remove(deviceId);
            _raisedAlertIdsByDevice.Remove(deviceId);
            _reportSeq.Remove(deviceId);
            _absorptionEval.Remove(deviceId);
            _absorptionObs.Remove(deviceId);
        }
    }

    /// <summary>The effective baseline for a device right now (the
    /// queryable view other surfaces and the hub cross-check use).</summary>
    public EffectiveBaseline EffectiveFor(string deviceId)
    {
        var facts = Facts(deviceId);
        if (facts is null) return new EffectiveBaseline(deviceId, _now(), Array.Empty<EffectiveBaselineItem>(), Array.Empty<string>());
        return Store.ComputeEffective(facts, _policies.Engine.MemberGroupIds(facts), _now());
    }
}
