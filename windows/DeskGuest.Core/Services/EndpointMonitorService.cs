using System.Diagnostics;
using System.Text;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.Inventory;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.Monitoring;
using DeskGuest.Shared.Security;

namespace DeskGuest.Core.Services;

// =====================================================================
// RMM-01 — the endpoint monitor: a module beside the session host in
// the same agent, with a separate duty. It samples the endpoint
// through IHealthCollector, evaluates the admitted condition library
// ON THE ENDPOINT, drives the alert lifecycle, fires per-condition
// actions through the RMM-12 / RMM-08 sinks (policy-gated), consumes
// RMM-04 warranty alerts, and emits the DeviceHealthReport the hub
// ingests over the existing heartbeat/state channel shape.
//
// Policy: the whole module is gated on rmm.monitoring.enabled via
// the RMM-07 engine's IsEnabled contract (TOTAL POLICY CONTROL) —
// the check is injected as the engine + this device's facts, never
// hardcoded. The condition library is signed management-policy
// content: it arrives ONLY as an RMM-03 signed envelope (class
// policy_delivery). Maintenance windows are NOT signed content
// (D38-F8 correction — this header previously claimed they were):
// they are admitted through the alert centre's attributed, audited
// API (creator + reason required, duration-bounded, cancellable),
// and authorizing the caller is the admitting host's
// responsibility, recorded in the chain.
//
// The monitor watches itself: consecutive collector failures degrade
// its reported status, and past the failure threshold it raises a
// monitor_failure alert through a path maintenance windows cannot
// suppress. A dead monitor therefore reports failure — never health.
// =====================================================================

/// <summary>One monitor cycle's outcome — the endpoint-side record a
/// caller (the Core's duty loop, tests) reads. Firing lists the
/// condition ids whose debounce completed this cycle; Indeterminate
/// names the conditions whose readings were absent (collector gaps),
/// so "we could not see" is never confused with "all clear".</summary>
public sealed record MonitorCycleResult(
    bool MonitorEnabled,
    string MonitorStatus,
    EndpointSample? Sample,
    IReadOnlyList<string> FiringConditionIds,
    IReadOnlyList<string> IndeterminateConditionIds,
    IReadOnlyList<HealthAlertEvent> NewAlerts,
    IReadOnlyList<HealthAlertEvent> AutoResetAlerts,
    int SuppressedCount,
    string? RefusalReason);

/// <summary>The endpoint monitor service for ONE device.</summary>
public sealed class EndpointMonitorService
{
    /// <summary>Consecutive failed/empty collection cycles after
    /// which the monitor declares itself failing and raises the
    /// monitor_failure alert.</summary>
    public const int MonitorFailureThreshold = 3;

    private readonly string _deviceId;
    private readonly IDeviceFacts _facts;
    private readonly ManagementPolicyEngine _policy;
    private readonly IHealthCollector _collector;
    private readonly HealthAlertCentre _centre;
    private readonly ChainedAuditLog _audit;
    private readonly SignedCommandGate? _gate;
    private readonly IWorkItemSink? _workItems;
    private readonly IRemediationSink? _remediation;
    private readonly Func<DateTimeOffset> _now;
    private readonly Func<DateTimeOffset, IReadOnlyList<WarrantyAlertEvent>>? _warrantySource;
    private readonly Func<DateTimeOffset, IReadOnlyList<SerialConflictAlertEvent>>? _serialConflictSource;
    private readonly object _lock = new();

    private ConditionLibrary _library = ValidatedDefault();
    private readonly Dictionary<string, int> _consecutive = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DateTimeOffset> _remediationLastFired = new(StringComparer.OrdinalIgnoreCase);
    private int _consecutiveCollectorFailures;
    private long _reportSeq;
    private bool _disabledAudited;

    // D38-F3: once a library has been admitted, its id is the only
    // live one; a replaced library's id is RETIRED — re-admitting it
    // later (at any revision, on any path) refuses, so an attacker
    // cannot switch ids back to an older library, and the built-in
    // Default cannot be restored once a signed library has replaced
    // it. And once a library has arrived through the SIGNED path,
    // the unsigned local path closes entirely.
    private readonly HashSet<string> _retiredLibraryIds = new(StringComparer.OrdinalIgnoreCase);
    private bool _signedLibraryInForce;

    // D38-F2: the last completed cycle's evaluation facts. The
    // monitor's reported status and the hub report are built from
    // these, so a section that could not be read (indeterminate
    // conditions) degrades the reported status instead of vanishing.
    private IReadOnlyList<string> _lastIndeterminate = Array.Empty<string>();
    private IReadOnlyList<string> _lastFiringEvaluated = Array.Empty<string>();
    private IReadOnlyList<string> _lastCollectorNotes = Array.Empty<string>();

    // D38-F8a: when each condition's current breach began (first
    // consecutive Firing evaluation). A maintenance window created
    // after this instant does not suppress the raise.
    private readonly Dictionary<string, DateTimeOffset> _firingSince = new(StringComparer.OrdinalIgnoreCase);

    // D38-F10: alerts for which a work item was ACTUALLY opened.
    // Only those are ever closed, and only while the work-items
    // feature is policy-enabled at close time.
    private readonly HashSet<string> _workItemOpened = new(StringComparer.Ordinal);
    private readonly object _workItemGate = new();

    public EndpointMonitorService(
        string deviceId,
        IDeviceFacts facts,
        ManagementPolicyEngine policy,
        IHealthCollector collector,
        HealthAlertCentre centre,
        ChainedAuditLog audit,
        SignedCommandGate? gate = null,
        IWorkItemSink? workItems = null,
        IRemediationSink? remediation = null,
        Func<DateTimeOffset>? now = null,
        Func<DateTimeOffset, IReadOnlyList<WarrantyAlertEvent>>? warrantySource = null,
        Func<DateTimeOffset, IReadOnlyList<SerialConflictAlertEvent>>? serialConflictSource = null)
    {
        _deviceId = deviceId ?? throw new ArgumentNullException(nameof(deviceId));
        _facts = facts ?? throw new ArgumentNullException(nameof(facts));
        _policy = policy ?? throw new ArgumentNullException(nameof(policy));
        _collector = collector ?? throw new ArgumentNullException(nameof(collector));
        _centre = centre ?? throw new ArgumentNullException(nameof(centre));
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _gate = gate;
        _workItems = workItems;
        _remediation = remediation;
        _now = now ?? (() => DateTimeOffset.UtcNow);
        _warrantySource = warrantySource;
        _serialConflictSource = serialConflictSource;
        // D38-F10: work items close on ANY reset of an alert that
        // opened one (auto-reset, manual reset, library-removal
        // reset), through the centre's single reset path.
        _centre.AlertReset += OnAlertReset;
    }

    /// <summary>The built-in default, VALIDATED at construction
    /// (D38-F3): the constructor previously assigned Default()
    /// unchecked and only a test ever called Validate() on it. A
    /// default that failed its own admission rules would be a build
    /// defect — it now fails loudly at startup instead of silently
    /// monitoring with inadmissible content.</summary>
    private static ConditionLibrary ValidatedDefault()
    {
        var lib = ConditionLibrary.Default();
        if (lib.Validate() is { } invalid)
            throw new InvalidOperationException($"built-in default condition library is inadmissible: {invalid}");
        return lib;
    }

    public string DeviceId => _deviceId;
    public HealthAlertCentre Centre => _centre;

    /// <summary>The library currently in force (built-in default
    /// until a signed library is admitted).</summary>
    public ConditionLibrary Library { get { lock (_lock) return _library; } }

    /// <summary>THE policy gate: rmm.monitoring.enabled for this
    /// device, via the registry/engine contract.</summary>
    public bool MonitoringEnabled => _policy.IsEnabled(_facts, MonitoringPolicyKeys.MonitoringEnabled);

    public string MonitorStatus
    {
        get
        {
            lock (_lock)
                // D38-F2: collector failures are not the only
                // impairment. A cycle that left conditions
                // INDETERMINATE (their sections were never read)
                // means the monitor is partially blind: the status
                // is Degraded, never Ok, until a cycle reads
                // everything the library asks about.
                return _consecutiveCollectorFailures >= MonitorFailureThreshold ? MonitorStatuses.Failing
                    : _consecutiveCollectorFailures > 0 || _lastIndeterminate.Count > 0 ? MonitorStatuses.Degraded
                    : MonitorStatuses.Ok;
        }
    }

    // ---- signed condition-library delivery ---------------------------

    /// <summary>Apply a condition library delivered as a signed
    /// command envelope. Verification (RMM-03, class policy_delivery)
    /// precedes parsing; admission validation and revision discipline
    /// follow; every outcome is a chained audit event. An unsigned,
    /// altered, stale or invalid library refuses and the library in
    /// force does not change.</summary>
    public PolicyVerdict ApplySignedLibrary(SignedCommandEnvelope? envelope)
    {
        var now = _now();
        if (_gate is null)
        {
            const string reason = "no customer command key is configured on this endpoint — signed condition-library delivery refuses (RMM-03)";
            _audit.Append("policy_refusal", "endpoint-monitor", reason, now);
            return new PolicyVerdict(false, reason);
        }
        var verdict = _gate.Authorize(envelope, now, SignedCommandClasses.PolicyDelivery);
        if (!verdict.Allowed) return new PolicyVerdict(false, verdict.Reason);
        ConditionLibrary? library;
        try { library = ConditionLibrary.FromCanonicalJson(Encoding.UTF8.GetString(verdict.Payload!)); }
        catch { library = null; }
        if (library is null)
        {
            const string reason = "signed payload did not parse as a condition library — refused";
            _audit.Append("policy_refusal", "endpoint-monitor", reason, now);
            return new PolicyVerdict(false, reason);
        }
        return AdmitLibrary(library, "signed delivery", viaSigned: true);
    }

    /// <summary>Admit a library from an already-trusted local path
    /// (tests, first-boot seeding beyond the built-in default). The
    /// same validation + revision discipline applies. D38-F3: this
    /// path takes UNSIGNED content, so it closes the moment a signed
    /// library is in force — from then on, monitoring content
    /// changes only through the verified signed path.</summary>
    public PolicyVerdict AdmitLocalLibrary(ConditionLibrary library, string via)
    {
        var now = _now();
        lock (_lock)
        {
            if (_signedLibraryInForce)
            {
                const string locked = "a signed condition library is in force — the unsigned local admission path is closed (monitoring content changes only through signed delivery)";
                _audit.Append("policy_refusal", "endpoint-monitor",
                    $"library={library.Id} via={via} reason={locked}", now);
                return new PolicyVerdict(false, locked);
            }
        }
        return AdmitLibrary(library, via, viaSigned: false);
    }

    private PolicyVerdict AdmitLibrary(ConditionLibrary library, string via, bool viaSigned)
    {
        var now = _now();
        var invalid = library.Validate();
        if (invalid is not null)
        {
            _audit.Append("policy_refusal", "endpoint-monitor",
                $"library={library.Id} via={via} reason={invalid}", now);
            return new PolicyVerdict(false, invalid);
        }
        List<HealthAlertEvent> orphaned = new();
        lock (_lock)
        {
            // D38-F3: a retired id never comes back — not at a higher
            // revision, not on the signed path. Switching ids is a
            // one-way door per id, so "restore the old library" is
            // not an available move once it has been replaced.
            if (_retiredLibraryIds.Contains(library.Id))
            {
                var retired = $"condition library id '{library.Id}' was replaced and is retired — refused (a replaced library cannot be restored by switching ids back)";
                _audit.Append("policy_refusal", "endpoint-monitor", $"library={library.Id} via={via} reason={retired}", now);
                return new PolicyVerdict(false, retired);
            }
            if (library.Id == _library.Id)
            {
                if (library.Revision < _library.Revision)
                {
                    var stale = $"condition library '{library.Id}' revision {library.Revision} is stale (current {_library.Revision}) — refused";
                    _audit.Append("policy_refusal", "endpoint-monitor", $"library={library.Id} via={via} reason={stale}", now);
                    return new PolicyVerdict(false, stale);
                }
                if (library.Revision == _library.Revision && library.ContentHash != _library.ContentHash)
                {
                    var conflict = $"condition library '{library.Id}' revision {library.Revision} conflicts with the admitted library of the same id+revision — refused";
                    _audit.Append("policy_refusal", "endpoint-monitor", $"library={library.Id} via={via} reason={conflict}", now);
                    return new PolicyVerdict(false, conflict);
                }
                if (library.Revision == _library.Revision)
                    return new PolicyVerdict(true, $"condition library '{library.Id}' r{library.Revision} already admitted (idempotent)");
            }
            var old = _library;
            // Defensive copy (the RMM-07 destruction lesson): the
            // admitted library is frozen at admission — a caller
            // holding the original conditions list must not be able
            // to mutate live monitoring content after the fact, with
            // no revision, no signature and no audit.
            _library = library with { Conditions = library.Conditions.ToList() };
            if (!string.Equals(old.Id, _library.Id, StringComparison.OrdinalIgnoreCase))
                _retiredLibraryIds.Add(old.Id);
            if (viaSigned) _signedLibraryInForce = true;
            // D38-F7: debounce streaks and breach-start times survive
            // admission for conditions that are UNCHANGED (same id,
            // record-equal content). Previously every admission
            // cleared all streaks, which reset live debounced alerts
            // on the next cycle under a false "condition cleared"
            // reason and then cooldown-blocked their re-raise.
            var newById = _library.Conditions.ToDictionary(c => c.Id, StringComparer.OrdinalIgnoreCase);
            bool Unchanged(string id) =>
                newById.TryGetValue(id, out var nc) &&
                old.Conditions.FirstOrDefault(c => string.Equals(c.Id, id, StringComparison.OrdinalIgnoreCase)) is { } oc &&
                oc.Equals(nc);
            foreach (var id in _consecutive.Keys.Where(id => !Unchanged(id)).ToList())
                _consecutive.Remove(id);
            foreach (var id in _firingSince.Keys.Where(id => !Unchanged(id)).ToList())
                _firingSince.Remove(id);
            // Alerts whose conditions the new library removed or
            // disabled are reset below (outside this lock) with the
            // TRUE reason — never swept up by the sample-driven
            // auto-reset as "condition cleared" (D38-F7).
            var liveIds = new HashSet<string>(
                _library.Conditions.Where(c => c.Enabled).Select(c => c.Id), StringComparer.OrdinalIgnoreCase);
            orphaned = _centre.ActiveAlerts
                .Where(a => a.Source == "endpoint" &&
                            string.Equals(a.DeviceId, _deviceId, StringComparison.OrdinalIgnoreCase) &&
                            !liveIds.Contains(a.ConditionId))
                .ToList();
            _audit.Append("policy_applied", "endpoint-monitor",
                $"library={library.Id} revision={library.Revision} conditions={library.Conditions.Count} hash={library.ContentHash} via={via}", now);
        }
        foreach (var alert in orphaned)
            _centre.Reset(alert.AlertId, "endpoint-monitor",
                "auto-reset: condition removed or disabled by library admission", now);
        return new PolicyVerdict(true, $"condition library '{library.Id}' r{library.Revision} admitted via {via}");
    }

    // ---- the cycle ------------------------------------------------------

    /// <summary>Run one monitoring cycle at the injected clock:
    /// policy gate → collect → evaluate (debounced) → suppress →
    /// raise/refresh → actions → auto-reset → warranty consume.
    /// Every step's outcome is in the result; refusals and failures
    /// are named, never silent.</summary>
    public MonitorCycleResult RunCycle()
    {
        var now = _now();
        if (!MonitoringEnabled)
        {
            lock (_lock)
            {
                if (!_disabledAudited)
                {
                    _disabledAudited = true;
                    _audit.Append("monitoring_disabled", "endpoint-monitor",
                        $"device={_deviceId} policy key {MonitoringPolicyKeys.MonitoringEnabled} is off — no sampling performed", now);
                }
            }
            return new MonitorCycleResult(false, MonitorStatus, null,
                Array.Empty<string>(), Array.Empty<string>(),
                Array.Empty<HealthAlertEvent>(), Array.Empty<HealthAlertEvent>(), 0,
                "monitoring disabled by policy (rmm.monitoring.enabled)");
        }
        lock (_lock) _disabledAudited = false;

        EndpointSample sample;
        try
        {
            sample = _collector.Collect(_deviceId, now);
            if (sample.IsEmpty)
                RegisterCollectorFailure(now, "collector produced an empty sample (no readings)");
            else
            {
                bool wasFailing;
                lock (_lock)
                {
                    wasFailing = _consecutiveCollectorFailures >= MonitorFailureThreshold;
                    _consecutiveCollectorFailures = 0;
                }
                if (wasFailing)
                {
                    // The monitor recovered: its own failure alert
                    // auto-resets (it is Source="monitor", so the
                    // sample-driven auto-reset never touches it).
                    // D38-F9: recovery matches on kind + source too,
                    // not the condition id alone — an alert that
                    // merely SHARES the reserved id (raised before the
                    // id was reserved, or by another path) must not be
                    // closed by the collector-recovery path.
                    var own = _centre.ActiveAlerts.FirstOrDefault(a =>
                        a.DeviceId == _deviceId &&
                        a.ConditionId == SystemAlertConditionIds.MonitorFailure &&
                        a.Kind == ConditionKinds.MonitorFailure &&
                        a.Source == "monitor");
                    if (own is not null)
                        _centre.Reset(own.AlertId, "endpoint-monitor",
                            "auto-reset: collector recovered", now);
                }
            }
        }
        catch (Exception ex)
        {
            RegisterCollectorFailure(now, $"collector threw {ex.GetType().Name}: {ex.Message}");
            sample = EndpointSample.Empty(_deviceId, now, $"collector_failed:{ex.GetType().Name}");
        }

        ConditionLibrary library;
        lock (_lock) library = _library;

        var firing = new List<string>();
        var firingEvaluated = new List<string>();
        var indeterminate = new List<string>();
        var newAlerts = new List<HealthAlertEvent>();
        var suppressed = 0;

        foreach (var condition in library.Conditions.Where(c => c.Enabled))
        {
            if (!ConditionKinds.IsSampleEvaluated(condition.Kind)) continue;
            var eval = ConditionEvaluator.Evaluate(condition, sample);
            switch (eval.Outcome)
            {
                case ConditionOutcome.Indeterminate:
                    indeterminate.Add(condition.Id);
                    break;
                case ConditionOutcome.Clear:
                    lock (_lock)
                    {
                        _consecutive[condition.Id] = 0;
                        _firingSince.Remove(condition.Id);
                    }
                    break;
                case ConditionOutcome.Firing:
                {
                    int streak;
                    lock (_lock)
                    {
                        streak = _consecutive.GetValueOrDefault(condition.Id) + 1;
                        _consecutive[condition.Id] = streak;
                        if (!_firingSince.ContainsKey(condition.Id))
                            _firingSince[condition.Id] = now;
                    }
                    // D38-F7: a condition that is FIRING but still
                    // debouncing is still firing — it belongs to the
                    // still-firing set below, or its active alert
                    // would be auto-reset as "condition cleared"
                    // while the breach is in progress.
                    firingEvaluated.Add(condition.Id);
                    if (streak < condition.ConsecutiveSamples) break; // still debouncing
                    firing.Add(condition.Id);
                    DateTimeOffset since;
                    lock (_lock) since = _firingSince.GetValueOrDefault(condition.Id, now);
                    var outcome = _centre.Raise(_deviceId, condition.Id, condition.Kind,
                        condition.Severity, eval.Detail, "endpoint", condition.Cooldown, now,
                        firingSinceUtc: since);
                    if (outcome.Outcome == RaiseOutcome.Suppressed) suppressed++;
                    else if (outcome.Outcome == RaiseOutcome.New && outcome.Alert is not null)
                    {
                        newAlerts.Add(outcome.Alert);
                        FireActions(condition, outcome.Alert, now);
                    }
                    break;
                }
            }
        }

        // D38-F2: publish this cycle's evaluation facts for the
        // status property and the hub report.
        lock (_lock)
        {
            _lastIndeterminate = indeterminate.ToList();
            _lastFiringEvaluated = firingEvaluated.ToList();
            _lastCollectorNotes = sample.CollectorNotes.ToList();
        }

        // Auto-reset: active endpoint alerts whose conditions are no
        // longer firing. An INDETERMINATE condition (its reading was
        // absent this cycle) neither fires nor clears, so it is part
        // of the still-firing set — a collector gap must never reset
        // a real alert. A DEBOUNCE-PENDING firing condition is part
        // of it too (firingEvaluated, D38-F7). The centre only
        // touches Source="endpoint" alerts, so warranty/monitor/hub
        // alerts are never reset here. Work-item closure rides the
        // centre's AlertReset event (OnAlertReset, D38-F10) so
        // manual resets close work items exactly like auto-resets.
        var stillFiringOrUnknown = new HashSet<string>(firingEvaluated, StringComparer.OrdinalIgnoreCase);
        foreach (var id in indeterminate) stillFiringOrUnknown.Add(id);
        var autoReset = _centre.AutoResetCleared(_deviceId, stillFiringOrUnknown, now);

        // Warranty consumption (RMM-04): events over stored data only.
        if (_warrantySource is not null)
        {
            var warrantyAlerts = _centre.IngestWarrantyAlerts(_warrantySource(now), now);
            newAlerts.AddRange(warrantyAlerts);
        }

        // Serial-conflict consumption (RMM-04, D38-F5(d)): fleet
        // integrity events over stored data only, into the same
        // centre. Hub wiring passes InventoryStore
        // .CollectSerialConflictAlerts as this source.
        if (_serialConflictSource is not null)
        {
            var conflictAlerts = _centre.IngestSerialConflictAlerts(_serialConflictSource(now), now);
            newAlerts.AddRange(conflictAlerts);
        }

        return new MonitorCycleResult(true, MonitorStatus, sample,
            firing, indeterminate, newAlerts, autoReset, suppressed, null);
    }

    /// <summary>Per-condition actions on a NEW alert. Notify is the
    /// centre raise itself (already mirrored to DIR-57). Work items
    /// and remediation are each gated on their own feature toggle —
    /// a disabled RMM-12/RMM-08 means the sink is never touched, and
    /// the gating is audited so the absence is explained, not silent.
    /// Remediation additionally honours the condition cooldown as its
    /// re-fire discipline: one dispatch per alert episode.</summary>
    private void FireActions(MonitorCondition condition, HealthAlertEvent alert, DateTimeOffset now)
    {
        if (condition.Actions.OpenWorkItem)
        {
            if (_workItems is null)
            {
                _audit.Append("health_action_skipped", "endpoint-monitor",
                    $"alert={alert.AlertId} action=work_item reason=no work-item sink wired (RMM-12 not present)", now);
            }
            else if (!_policy.IsEnabled(_facts, MonitoringPolicyKeys.WorkItemsEnabled))
            {
                _audit.Append("health_action_skipped", "endpoint-monitor",
                    $"alert={alert.AlertId} action=work_item reason=disabled by policy ({MonitoringPolicyKeys.WorkItemsEnabled})", now);
            }
            else
            {
                _workItems.OpenWorkItem(alert, now);
                lock (_workItemGate) _workItemOpened.Add(alert.AlertId);
                _audit.Append("health_action_fired", "endpoint-monitor",
                    $"alert={alert.AlertId} action=work_item condition={condition.Id}", now);
            }
        }

        if (condition.Actions.WantsRemediation)
        {
            var remediationId = condition.Actions.RemediationId!;
            if (_remediation is null)
            {
                _audit.Append("health_action_skipped", "endpoint-monitor",
                    $"alert={alert.AlertId} action=remediation:{remediationId} reason=no remediation sink wired (RMM-08 not present)", now);
            }
            else if (!_policy.IsEnabled(_facts, MonitoringPolicyKeys.RemediationEnabled))
            {
                _audit.Append("health_action_skipped", "endpoint-monitor",
                    $"alert={alert.AlertId} action=remediation:{remediationId} reason=disabled by policy ({MonitoringPolicyKeys.RemediationEnabled})", now);
            }
            else
            {
                lock (_lock)
                {
                    if (_remediationLastFired.TryGetValue(condition.Id, out var last) &&
                        now - last < condition.Cooldown)
                    {
                        _audit.Append("health_action_skipped", "endpoint-monitor",
                            $"alert={alert.AlertId} action=remediation:{remediationId} reason=condition cooldown (last dispatch {last:O})", now);
                        return;
                    }
                    _remediationLastFired[condition.Id] = now;
                }
                var result = _remediation.Dispatch(remediationId, alert, now);
                _audit.Append(result.Dispatched ? "health_action_fired" : "health_action_failed",
                    "endpoint-monitor",
                    $"alert={alert.AlertId} action=remediation:{remediationId} condition={condition.Id} outcome={result.Outcome}", now);
            }
        }
    }

    /// <summary>D38-F10: close the work item for a reset alert —
    /// but ONLY if this monitor actually opened one for it, and
    /// ONLY while rmm.work_items.enabled is on at close time. The
    /// previous code closed on every auto-reset with no policy
    /// check (touching a policy-disabled sink, unaudited) and never
    /// closed on manual resets at all. A policy-disabled close is
    /// an audited skip; the sink is not touched.</summary>
    private void OnAlertReset(HealthAlertEvent alert)
    {
        bool opened;
        lock (_workItemGate) opened = _workItemOpened.Remove(alert.AlertId);
        if (!opened || _workItems is null) return;
        var now = _now();
        if (!_policy.IsEnabled(_facts, MonitoringPolicyKeys.WorkItemsEnabled))
        {
            _audit.Append("health_action_skipped", "endpoint-monitor",
                $"alert={alert.AlertId} action=work_item_close reason=disabled by policy ({MonitoringPolicyKeys.WorkItemsEnabled}) — sink not touched; the work item stays open in RMM-12", now);
            return;
        }
        _workItems.CloseWorkItem(alert, alert.ResetReason ?? "alert reset", now);
        _audit.Append("health_action_fired", "endpoint-monitor",
            $"alert={alert.AlertId} action=work_item_close reason={alert.ResetReason}", now);
    }

    /// <summary>Watchdog bookkeeping: a failed/empty cycle degrades
    /// the monitor; at the threshold the monitor raises its own
    /// failure alert (kind monitor_failure — never suppressible, and
    /// raised through the centre so it is chained + mirrored like
    /// every other alert).</summary>
    private void RegisterCollectorFailure(DateTimeOffset now, string detail)
    {
        int failures;
        lock (_lock) failures = ++_consecutiveCollectorFailures;
        _audit.Append("monitor_collector_failure", "endpoint-monitor",
            $"device={_deviceId} consecutiveFailures={failures} detail={detail}", now);
        if (failures >= MonitorFailureThreshold)
        {
            _centre.Raise(_deviceId, SystemAlertConditionIds.MonitorFailure, ConditionKinds.MonitorFailure,
                AlertSeverities.Critical,
                $"endpoint monitor collector failing ({failures} consecutive failures): {detail}",
                "monitor", TimeSpan.FromMinutes(5), now);
        }
    }

    /// <summary>Build the health report for the hub: monotonic seq,
    /// the library in force (id + content hash), the monitor's own
    /// status, the firing set and the active alerts. This is the
    /// payload that rides the existing heartbeat/state channel.</summary>
    public DeviceHealthReport BuildReport()
    {
        var now = _now();
        ConditionLibrary library;
        long seq;
        List<string> indeterminate;
        List<string> firingEvaluated;
        List<string> collectorNotes;
        lock (_lock)
        {
            library = _library;
            // D38-F5: the sequence is anchored to the wall clock, not
            // to process lifetime. A purely in-memory counter
            // restarted at 0 on every agent restart, so the hub
            // refused every post-restart report as replay/stale until
            // the new counter passed the old one — the device was
            // reporting and the hub read it Down. Ticks anchor makes
            // a restarted agent's first report newer than any
            // pre-restart report; the max() keeps it strictly
            // monotonic within the process too. (Residual: a wall
            // clock rolled back across a restart below the previous
            // anchor can still collide — named in the lane log.)
            seq = _reportSeq = Math.Max(_reportSeq + 1, now.UtcTicks);
            indeterminate = _lastIndeterminate.ToList();
            firingEvaluated = _lastFiringEvaluated.ToList();
            collectorNotes = _lastCollectorNotes.ToList();
        }
        var active = _centre.ActiveAlerts
            .Where(a => string.Equals(a.DeviceId, _deviceId, StringComparison.OrdinalIgnoreCase))
            .ToList();
        // D38-F2: the firing set is what the last cycle EVALUATED as
        // firing (including window-suppressed and debounce-pending
        // conditions), unioned with the conditions behind active
        // endpoint alerts — not merely the active-alert list, which
        // silently dropped suppressed and debouncing breaches.
        var firing = new HashSet<string>(firingEvaluated, StringComparer.OrdinalIgnoreCase);
        foreach (var a in active.Where(a => a.Source == "endpoint")) firing.Add(a.ConditionId);
        var notes = new List<string>();
        lock (_lock)
        {
            if (_consecutiveCollectorFailures > 0)
                notes.Add($"collector_failures:{_consecutiveCollectorFailures}");
        }
        // The indeterminate conditions and the collector's own
        // not-read notes travel in the report, so the hub can see
        // the monitor is impaired instead of reading silence as
        // health (D38-F2).
        foreach (var id in indeterminate) notes.Add($"indeterminate:{id}");
        notes.AddRange(collectorNotes);
        return new DeviceHealthReport(
            _deviceId, seq, now, library.Id, library.ContentHash,
            MonitorStatus, notes, firing.ToList(), active);
    }
}

/// <summary>The Core's honest runtime collector: reads only what the
/// runtime + existing DeskGuest machinery can state truthfully on any host
/// — ready-drive space (DriveInfo), uptime (Environment.TickCount64),
/// process names + working sets (System.Diagnostics). CPU/RAM
/// percentages, SMART, services, the Event Log and security state
/// are NOT honestly readable here: those sections stay absent (the
/// composite names them not_read) until the Windows-host WMI/CIM +
/// EventLog + Security Center wiring lands. Named remainder, never
/// fabricated readings.</summary>
public static class RuntimeHealthCollector
{
    public static CompositeHealthCollector Create()
    {
        return new CompositeHealthCollector
        {
            Disks = _ => DriveInfo.GetDrives().Where(d => d.IsReady)
                .Select(d => new DiskSample(
                    d.Name, d.AvailableFreeSpace, d.TotalSize,
                    SmartStatus: null,           // WMI MSStorageDriver_FailurePredictStatus — host wiring
                    PredictiveFailure: null))    // host wiring
                .ToList(),
            Processes = _ => Process.GetProcesses()
                .Select(p =>
                {
                    try { return new ProcessSample(p.ProcessName, p.WorkingSet64, null); }
                    catch { return new ProcessSample(p.ProcessName, 0, null); }
                })
                .GroupBy(p => p.Name, StringComparer.OrdinalIgnoreCase)
                .Select(g => g.OrderByDescending(p => p.WorkingSetBytes).First())
                .ToList(),
            Uptime = _ => TimeSpan.FromMilliseconds(Environment.TickCount64),
            // Resources (CPU/RAM %), Services, Applications, EventLog,
            // Security, Guests: deliberately unset → the composite
            // records not_read:<section> for each. Windows-host wiring:
            // WMI Win32_Processor/Win32_OperatingSystem, ServiceController,
            // registry uninstall keys, EventLogReader, Security Center
            // WMI, Hyper-V — all behind these same delegates.
        };
    }
}
