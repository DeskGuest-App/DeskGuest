using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.Inventory;

namespace DeskGuest.Shared.Monitoring;

// =====================================================================
// RMM-01 — alert lifecycle, maintenance windows, action sinks, and
// the hub-side ingest / device-down model.
//
// The alert centre here EXTENDS DIR-57's model (DeskGuest.Shared.Enterprise
// .AlertCenter): every raise is mirrored into the DIR-57 centre under
// the endpoint_health / warranty classes, and every lifecycle
// transition joins the SAME hash-chained ledger (ChainedAuditLog) the
// rest of DeskGuest audits into. There is deliberately no second audit
// chain and no second notification surface — this type adds the
// health-specific lifecycle (raised / acknowledged / reset,
// auto-reset on clear, dedup + flood discipline) on top of them.
//
// Maintenance windows suppress ALERTING during planned work — never
// the audit, and never the NeverSuppressible kinds (security state,
// device-down, monitor failure, warranty). Suppression is itself
// audited: a suppressed firing leaves a chained record naming the
// window, so a window can never be used to quietly hide a fault.
// =====================================================================

/// <summary>Alert lifecycle states. Reset is terminal for an alert
/// instance; a condition that fires again afterwards raises a NEW
/// alert (subject to the condition's cooldown).</summary>
public static class HealthAlertStates
{
    public const string Raised = "raised";
    public const string Acknowledged = "acknowledged";
    public const string Reset = "reset";
}

/// <summary>One endpoint-health alert event — the unit that travels
/// over DeskGuest's transports to the hub and the alert centre. Immutable
/// facts are set at raise; lifecycle fields move only through
/// HealthAlertCentre transitions.</summary>
public sealed record HealthAlertEvent(
    string AlertId,
    string DeviceId,
    string ConditionId,
    string Kind,
    string Severity,
    string State,
    DateTimeOffset RaisedUtc,
    DateTimeOffset LastSeenUtc,
    int OccurrenceCount,
    string Detail,
    string? AcknowledgedBy,
    DateTimeOffset? AcknowledgedUtc,
    DateTimeOffset? ResetUtc,
    string? ResetReason,
    string Source) // "endpoint" | "hub" | "warranty" | "monitor"
{
    public bool IsActive => State is HealthAlertStates.Raised or HealthAlertStates.Acknowledged;

    /// <summary>The dedup identity: at most one ACTIVE alert exists
    /// per (device, condition). Warranty alerts never collapse into
    /// each other because their CONDITION ID already carries the
    /// warranty kind (`warranty:expiring` vs `warranty:expired` —
    /// see IngestWarrantyAlerts), so the single key form below is
    /// the whole rule. (D38-F12: this property previously had two
    /// identical branches whose comment claimed a distinction the
    /// code did not make.)</summary>
    public string DedupKey => $"{DeviceId}|{ConditionId}";
}

// ---- action sinks (RMM-12 / RMM-08 consume these) ----------------------

/// <summary>The work-item sink: RMM-12's surface. RMM-01 calls it
/// when a condition whose actions say so raises (open) and when that
/// alert auto-resets because the condition cleared (close). The
/// recording double below is the contract RMM-12 implements against.</summary>
public interface IWorkItemSink
{
    void OpenWorkItem(HealthAlertEvent alert, DateTimeOffset now);
    void CloseWorkItem(HealthAlertEvent alert, string reason, DateTimeOffset now);
}

/// <summary>Recording test double for IWorkItemSink (house pattern:
/// fakes live beside the model, like FakeWarrantyLookup).</summary>
public sealed class RecordingWorkItemSink : IWorkItemSink
{
    public List<HealthAlertEvent> Opened { get; } = new();
    public List<(HealthAlertEvent Alert, string Reason)> Closed { get; } = new();
    public void OpenWorkItem(HealthAlertEvent alert, DateTimeOffset now) => Opened.Add(alert);
    public void CloseWorkItem(HealthAlertEvent alert, string reason, DateTimeOffset now) => Closed.Add((alert, reason));
}

/// <summary>Outcome of a remediation dispatch attempt. Refusals are
/// values: policy-disabled, unknown remediation, and sink-reported
/// failure are distinct named outcomes, all audited by the caller.</summary>
public sealed record RemediationDispatchResult(bool Dispatched, string Outcome);

/// <summary>The remediation sink: RMM-08's engine surface. RMM-01
/// dispatches a condition's named remediation when its alert first
/// raises — policy-gated by the caller (rmm.remediation.enabled)
/// before the sink is ever touched.</summary>
public interface IRemediationSink
{
    RemediationDispatchResult Dispatch(string remediationId, HealthAlertEvent alert, DateTimeOffset now);
}

/// <summary>Recording test double for IRemediationSink.</summary>
public sealed class RecordingRemediationSink : IRemediationSink
{
    public List<(string RemediationId, string AlertId)> Dispatches { get; } = new();
    public RemediationDispatchResult Result { get; set; } = new(true, "dispatched (recording double)");
    public RemediationDispatchResult Dispatch(string remediationId, HealthAlertEvent alert, DateTimeOffset now)
    {
        Dispatches.Add((remediationId, alert.AlertId));
        return Result;
    }
}

// ---- maintenance windows -------------------------------------------------

/// <summary>Named bounds for maintenance windows. A window is planned
/// work: bounded, attributed, and never retroactive beyond a small
/// grace (a window created AFTER a fault to cover it is exactly the
/// abuse these bounds exist to refuse).</summary>
public static class MaintenanceWindowLimits
{
    public static readonly TimeSpan MaxDuration = TimeSpan.FromHours(48);
    public static readonly TimeSpan MaxRetroactiveGrace = TimeSpan.FromMinutes(5);
    public const int MaxReasonLength = 512;
}

public sealed record MaintenanceWindow(
    string Id,
    string DeviceId,          // a concrete device, or "*" for the fleet — fleet windows are refused for NeverSuppressible kinds anyway
    DateTimeOffset StartsUtc,
    DateTimeOffset EndsUtc,
    string Reason,
    string CreatedBy,
    DateTimeOffset CreatedUtc)
{
    public bool Covers(string deviceId, DateTimeOffset now) =>
        now >= StartsUtc && now < EndsUtc &&
        (DeviceId == "*" || string.Equals(DeviceId, deviceId, StringComparison.OrdinalIgnoreCase));

    /// <summary>Admission validation at creation time (`now` = the
    /// creation instant). Null when admissible.</summary>
    public string? Validate(DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(Id)) return "maintenance window needs an id — refused";
        if (string.IsNullOrWhiteSpace(DeviceId)) return "maintenance window needs a device (or '*') — refused";
        if (string.IsNullOrWhiteSpace(CreatedBy)) return "maintenance window needs a creator — refused (suppression is attributed or it does not happen)";
        if (string.IsNullOrWhiteSpace(Reason) || Reason.Length > MaintenanceWindowLimits.MaxReasonLength)
            return "maintenance window needs a reason within bounds — refused";
        if (EndsUtc <= StartsUtc) return "maintenance window ends before it starts — refused";
        if (EndsUtc - StartsUtc > MaintenanceWindowLimits.MaxDuration)
            return $"maintenance window exceeds the {MaintenanceWindowLimits.MaxDuration.TotalHours:0}h maximum — refused (an unbounded window is a silencer, not planned work)";
        if (StartsUtc < now - MaintenanceWindowLimits.MaxRetroactiveGrace)
            return "maintenance window starts in the past — refused (retroactive suppression is how faults get hidden)";
        if (EndsUtc <= now) return "maintenance window already over — refused";
        return null;
    }
}

// ---- the alert centre -----------------------------------------------------

/// <summary>Raised-alert outcome: either a genuinely new alert, a
/// refresh of the active one (dedup), a suppression, or a flood-cap
/// refusal — each named, each audited by the centre.</summary>
public sealed record RaiseOutcome(string Outcome, HealthAlertEvent? Alert)
{
    public const string New = "new";
    public const string Refreshed = "refreshed";
    public const string Suppressed = "suppressed";
    public const string FloodCapped = "flood_capped";
    public const string Cooldown = "cooldown";
}

/// <summary>The endpoint-health alert centre: lifecycle + dedup +
/// flood discipline over health alerts, mirrored into DIR-57's
/// AlertCenter and the shared ChainedAuditLog. Thread-safe; all
/// state moves under one gate.</summary>
public sealed class HealthAlertCentre
{
    /// <summary>Flood discipline: at most this many NEW alerts per
    /// device per rolling hour. Beyond the cap, occurrences are
    /// counted on the flood record and audited — a malfunctioning
    /// condition (or a hostile sample source) cannot drown the
    /// centre, the audit chain, or the sinks.</summary>
    public const int MaxNewAlertsPerDevicePerHour = 60;

    private readonly ChainedAuditLog _audit;
    private readonly AlertCenter _dir57;
    private readonly Dictionary<string, HealthAlertEvent> _byId = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> _activeByDedup = new(StringComparer.Ordinal); // dedupKey -> alertId
    private readonly Dictionary<string, DateTimeOffset> _lastResetByDedup = new(StringComparer.Ordinal);
    private readonly Dictionary<string, List<DateTimeOffset>> _newAlertTimes = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, int> _floodedOccurrences = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<MaintenanceWindow> _windows = new();
    // D38-F11: suppression / cooldown audit entries are throttled per
    // (outcome, device, condition): at most one chained entry per
    // hour, with the throttled count folded into the next entry. A
    // 48h window over a large library at a 1-minute cycle must not
    // be able to write ~1.5M audit entries — but the count is never
    // lost, only aggregated.
    private readonly Dictionary<string, (DateTimeOffset Last, int Pending)> _auditThrottle = new(StringComparer.Ordinal);
    private readonly object _gate = new();

    /// <summary>Fired AFTER an alert transitions to Reset (manual,
    /// auto-reset, supersede, hub mirror reset — every path goes
    /// through the one ResetInternal). Subscribers (the endpoint
    /// monitor) use it to close per-alert side effects such as work
    /// items on ANY reset, not only the auto-reset path (D38-F10).
    /// Invoked outside the centre's gate.</summary>
    public event Action<HealthAlertEvent>? AlertReset;

    public HealthAlertCentre(ChainedAuditLog audit, AlertCenter dir57Alerts)
    {
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _dir57 = dir57Alerts ?? throw new ArgumentNullException(nameof(dir57Alerts));
    }

    public IReadOnlyList<HealthAlertEvent> Alerts
    {
        get { lock (_gate) return _byId.Values.OrderBy(a => a.RaisedUtc).ThenBy(a => a.AlertId, StringComparer.Ordinal).ToList(); }
    }

    public IReadOnlyList<HealthAlertEvent> ActiveAlerts
    {
        get { lock (_gate) return _byId.Values.Where(a => a.IsActive).OrderBy(a => a.RaisedUtc).ToList(); }
    }

    public HealthAlertEvent? Get(string alertId)
    {
        lock (_gate) return alertId is not null && _byId.TryGetValue(alertId, out var a) ? a : null;
    }

    /// <summary>Suppressed-occurrence counts swallowed by the flood
    /// cap, per device — visible, never silent.</summary>
    public IReadOnlyDictionary<string, int> FloodedOccurrences
    {
        get { lock (_gate) return new Dictionary<string, int>(_floodedOccurrences); }
    }

    // -- maintenance windows --

    public IReadOnlyList<MaintenanceWindow> Windows
    {
        get { lock (_gate) return _windows.ToList(); }
    }

    /// <summary>Create a maintenance window. Validation refusals are
    /// audited too — an attempted abusive window is a fact the record
    /// keeps. A window NEVER suppresses the audit: its own creation
    /// is the first entry it cannot hide.</summary>
    public (bool Accepted, string Reason) AddWindow(MaintenanceWindow window, DateTimeOffset now)
    {
        var refusal = window.Validate(now);
        lock (_gate)
        {
            if (refusal is not null)
            {
                _audit.Append("maintenance_window_refused", window.CreatedBy ?? "unknown",
                    $"window={window.Id} device={window.DeviceId} reason={refusal}", now);
                return (false, refusal);
            }
            if (_windows.Any(w => w.Id == window.Id))
            {
                const string dup = "a maintenance window with this id already exists — refused";
                _audit.Append("maintenance_window_refused", window.CreatedBy, $"window={window.Id} reason={dup}", now);
                return (false, dup);
            }
            // D38-F8: expired windows are pruned at admission time —
            // the window list must not grow without bound. Pruning is
            // audited, like everything else a window touches.
            var pruned = _windows.RemoveAll(w => w.EndsUtc <= now);
            if (pruned > 0)
                _audit.Append("maintenance_windows_pruned", window.CreatedBy,
                    $"pruned={pruned} expired maintenance windows at admission of window={window.Id}", now);
            _windows.Add(window);
            _audit.Append("maintenance_window_created", window.CreatedBy,
                $"window={window.Id} device={window.DeviceId} from={window.StartsUtc:O} to={window.EndsUtc:O} reason={window.Reason}", now);
            return (true, "maintenance window created");
        }
    }

    /// <summary>Cancel a maintenance window before it ends (D38-F8:
    /// windows previously could never be cancelled). Attributed and
    /// audited; an unknown id or an unattributed cancellation
    /// refuses. A cancelled window stops suppressing immediately.</summary>
    public (bool Removed, string Reason) RemoveWindow(string windowId, string removedBy, DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(removedBy))
            return (false, "maintenance window cancellation needs an actor — refused (suppression changes are attributed or they do not happen)");
        lock (_gate)
        {
            var window = _windows.FirstOrDefault(w => w.Id == windowId);
            if (window is null) return (false, $"no maintenance window '{windowId}' — nothing to cancel");
            _windows.Remove(window);
            _audit.Append("maintenance_window_removed", removedBy,
                $"window={window.Id} device={window.DeviceId} removed before its end {window.EndsUtc:O}", now);
            return (true, "maintenance window cancelled");
        }
    }

    /// <summary>The window suppressing this device+kind at `now`, if
    /// any. NeverSuppressible kinds return null BY CONSTRUCTION —
    /// there is no window shape that reaches them.</summary>
    public MaintenanceWindow? SuppressingWindow(string deviceId, string kind, DateTimeOffset now)
    {
        if (ConditionKinds.NeverSuppressible.Contains(kind)) return null;
        lock (_gate) return _windows.FirstOrDefault(w => w.Covers(deviceId, now));
    }

    // -- raising --

    /// <summary>Raise or refresh the alert for (device, condition).
    /// Dedup: an active alert for the same key refreshes (occurrence
    /// count + last-seen) instead of duplicating — and refresh is
    /// checked BEFORE suppression (D38-F8b: a window must not freeze
    /// an already-active alert's occurrence count / last-seen; the
    /// window suppresses NEW notifications, not the record of a
    /// known fault). Cooldown: a key whose previous alert reset less
    /// than `cooldown` ago does not re-raise yet. Suppression and
    /// flood-capping are audited outcomes, not silent drops.
    /// `firingSinceUtc` (D38-F8a): when the caller knows when the
    /// condition FIRST breached, a window created after that instant
    /// does not suppress this raise — the retroactive grace exists
    /// for administrative lag, not to hide a fault that was already
    /// firing when the window was created.</summary>
    public RaiseOutcome Raise(
        string deviceId, string conditionId, string kind, string severity,
        string detail, string source, TimeSpan cooldown, DateTimeOffset now,
        DateTimeOffset? firingSinceUtc = null)
    {
        var dedup = $"{deviceId}|{conditionId}";
        detail = BoundDetail(detail, MaxStoredDetailLength);
        lock (_gate)
        {
            if (_activeByDedup.TryGetValue(dedup, out var activeId) &&
                _byId.TryGetValue(activeId, out var active))
            {
                var refreshed = active with
                {
                    LastSeenUtc = now,
                    OccurrenceCount = active.OccurrenceCount + 1,
                    Detail = detail,
                };
                _byId[activeId] = refreshed;
                return new RaiseOutcome(RaiseOutcome.Refreshed, refreshed);
            }
            var window = SuppressingWindowLocked(deviceId, kind, now);
            if (window is not null && firingSinceUtc is { } since && window.CreatedUtc > since)
            {
                // The window postdates the breach: it cannot hide a
                // fault that was already firing. Named in the audit
                // (throttled like other repeat outcomes).
                AuditThrottledLocked("health_alert_window_postdated", $"window-postdated|{dedup}",
                    $"device={deviceId} condition={conditionId} kind={kind} window={window.Id} windowCreated={window.CreatedUtc:O} firingSince={since:O} — window created after the breach began; not applied", now);
                window = null;
            }
            if (window is not null)
            {
                AuditThrottledLocked("health_alert_suppressed", $"suppressed|{dedup}",
                    $"device={deviceId} condition={conditionId} kind={kind} window={window.Id} detail={BoundDetail(detail, MaxAuditDetailLength)}", now);
                return new RaiseOutcome(RaiseOutcome.Suppressed, null);
            }
            // Prune reset markers that can no longer bind: no
            // admissible cooldown exceeds the library cap (24h), so a
            // marker older than 25h is dead state (D38-F11).
            PruneResetMarkersLocked(now);
            if (_lastResetByDedup.TryGetValue(dedup, out var resetAt) && now - resetAt < cooldown)
            {
                AuditThrottledLocked("health_alert_cooldown", $"cooldown|{dedup}",
                    $"device={deviceId} condition={conditionId} kind={kind} resetAt={resetAt:O} cooldown={cooldown}", now);
                return new RaiseOutcome(RaiseOutcome.Cooldown, null);
            }
            // Flood discipline (per device, rolling hour). D38-F4:
            // NeverSuppressible kinds are EXEMPT — otherwise a flood
            // of suppressible alerts (or one forged hub report) could
            // fill a device's cap and make its real device_down /
            // monitor_failure / security alert come back FloodCapped.
            if (!ConditionKinds.NeverSuppressible.Contains(kind))
            {
                var times = _newAlertTimes.TryGetValue(deviceId, out var list) ? list : new List<DateTimeOffset>();
                times.RemoveAll(t => now - t > TimeSpan.FromHours(1));
                _newAlertTimes[deviceId] = times;
                if (times.Count >= MaxNewAlertsPerDevicePerHour)
                {
                    _floodedOccurrences[deviceId] = _floodedOccurrences.GetValueOrDefault(deviceId) + 1;
                    if (times.Count == MaxNewAlertsPerDevicePerHour)
                        _audit.Append("health_alert_flood_capped", "endpoint-monitor",
                            $"device={deviceId} condition={conditionId} kind={kind} cap={MaxNewAlertsPerDevicePerHour}/hour reached — further new alerts this hour are counted, not raised", now);
                    return new RaiseOutcome(RaiseOutcome.FloodCapped, null);
                }
                times.Add(now);
            }
            var alert = new HealthAlertEvent(
                AlertId: Guid.NewGuid().ToString("N"),
                DeviceId: deviceId, ConditionId: conditionId, Kind: kind, Severity: severity,
                State: HealthAlertStates.Raised, RaisedUtc: now, LastSeenUtc: now,
                OccurrenceCount: 1, Detail: detail,
                AcknowledgedBy: null, AcknowledgedUtc: null, ResetUtc: null, ResetReason: null,
                Source: source);
            _byId[alert.AlertId] = alert;
            PruneResetHistoryLocked();
            _activeByDedup[dedup] = alert.AlertId;
            _audit.Append("health_alert_raised", "endpoint-monitor",
                $"alert={alert.AlertId} device={deviceId} condition={conditionId} kind={kind} severity={severity} source={source} detail={BoundDetail(detail, MaxAuditDetailLength)}", now);
            MirrorToDir57(alert, now);
            return new RaiseOutcome(RaiseOutcome.New, alert);
        }
    }

    /// <summary>Detail strings are caller-controlled (a hostile hub
    /// report, a chatty condition): they are bounded before they can
    /// reach storage or the audit chain (D38-F11).</summary>
    public const int MaxStoredDetailLength = 4096;
    public const int MaxAuditDetailLength = 512;

    private static string BoundDetail(string? detail, int max) =>
        detail is null ? "" : detail.Length <= max ? detail : detail[..max] + "…[bounded]";

    /// <summary>Append an audit entry for a repeat outcome (a
    /// suppression or cooldown hit) at most once per hour per key;
    /// occurrences in between are counted and folded into the next
    /// entry (D38-F11). Caller holds the gate.</summary>
    private void AuditThrottledLocked(string kind, string throttleKey, string detail, DateTimeOffset now)
    {
        if (_auditThrottle.TryGetValue(throttleKey, out var t) && now - t.Last < TimeSpan.FromHours(1))
        {
            _auditThrottle[throttleKey] = (t.Last, t.Pending + 1);
            return;
        }
        var extra = t.Pending > 0
            ? $" (+{t.Pending} further occurrences in the past hour were counted, not individually audited)"
            : "";
        _audit.Append(kind, "endpoint-monitor", detail + extra, now);
        _auditThrottle[throttleKey] = (now, 0);
    }

    /// <summary>BD-SHARED-RMM-2/F12: retained RESET alerts are
    /// history, not live state — beyond this bound the oldest reset
    /// alerts are pruned (active alerts are never pruned). The audit
    /// chain keeps the full raising/resetting record; this bounds
    /// the in-memory centre and its re-sorting Alerts view.</summary>
    public const int MaxRetainedResetAlerts = 2000;

    private void PruneResetHistoryLocked()
    {
        var excess = _byId.Values.Count(a => !a.IsActive) - MaxRetainedResetAlerts;
        if (excess <= 0) return;
        foreach (var old in _byId.Values.Where(a => !a.IsActive)
                     .OrderBy(a => a.RaisedUtc).ThenBy(a => a.AlertId, StringComparer.Ordinal)
                     .Take(excess).ToList())
            _byId.Remove(old.AlertId);
    }

    private void PruneResetMarkersLocked(DateTimeOffset now)
    {
        if (_lastResetByDedup.Count == 0) return;
        var dead = _lastResetByDedup
            .Where(kv => now - kv.Value > TimeSpan.FromHours(25)).Select(kv => kv.Key).ToList();
        foreach (var k in dead) _lastResetByDedup.Remove(k);
    }

    private MaintenanceWindow? SuppressingWindowLocked(string deviceId, string kind, DateTimeOffset now)
    {
        if (ConditionKinds.NeverSuppressible.Contains(kind)) return null;
        return _windows.FirstOrDefault(w => w.Covers(deviceId, now));
    }

    private void MirrorToDir57(HealthAlertEvent alert, DateTimeOffset now)
    {
        // DIR-57's centre takes named classes only; endpoint health
        // rides the two classes this directive adds to its set.
        var cls = alert.Kind == ConditionKinds.Warranty ? "warranty" : "endpoint_health";
        _dir57.Raise(cls,
            $"[{alert.Severity}] {alert.Kind} on {alert.DeviceId} ({alert.ConditionId}): {alert.Detail}", now);
    }

    // -- lifecycle transitions --

    /// <summary>Acknowledge an active alert. Unknown or already-reset
    /// alerts refuse (false) — an ack against nothing is not recorded
    /// as if it happened.</summary>
    public bool Acknowledge(string alertId, string acknowledgedBy, DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(acknowledgedBy)) return false;
        lock (_gate)
        {
            if (!_byId.TryGetValue(alertId ?? "", out var a) || !a.IsActive) return false;
            _byId[alertId] = a with
            {
                State = HealthAlertStates.Acknowledged,
                AcknowledgedBy = acknowledgedBy,
                AcknowledgedUtc = now,
            };
            _audit.Append("health_alert_acknowledged", acknowledgedBy,
                $"alert={alertId} device={a.DeviceId} condition={a.ConditionId}", now);
            return true;
        }
    }

    /// <summary>Manually reset an active alert (a human closed it).
    /// Returns the reset alert, or null when there was nothing
    /// active to reset.</summary>
    public HealthAlertEvent? Reset(string alertId, string resetBy, string reason, DateTimeOffset now) =>
        ResetInternal(alertId, resetBy, reason, now);

    /// <summary>Auto-reset every active alert for a device whose
    /// condition is NOT in `stillFiringConditionIds` — the condition
    /// cleared, so the alert closes itself. Warranty, device-down
    /// and monitor alerts are excluded by their condition ids never
    /// appearing in a sample-firing set; callers pass exactly the
    /// sample-evaluated firing set. Returns the alerts reset.</summary>
    public IReadOnlyList<HealthAlertEvent> AutoResetCleared(
        string deviceId, IReadOnlySet<string> stillFiringConditionIds, DateTimeOffset now)
    {
        List<HealthAlertEvent> candidates;
        lock (_gate)
            candidates = _byId.Values
                .Where(a => a.IsActive &&
                            string.Equals(a.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase) &&
                            a.Source == "endpoint" &&
                            !stillFiringConditionIds.Contains(a.ConditionId))
                .ToList();
        var reset = new List<HealthAlertEvent>();
        foreach (var a in candidates)
            if (ResetInternal(a.AlertId, "endpoint-monitor", "auto-reset: condition cleared", now) is { } r)
                reset.Add(r);
        return reset;
    }

    private HealthAlertEvent? ResetInternal(string alertId, string actor, string reason, DateTimeOffset now)
    {
        HealthAlertEvent? reset = null;
        lock (_gate)
        {
            if (!_byId.TryGetValue(alertId ?? "", out var a) || !a.IsActive) return null;
            var r = a with { State = HealthAlertStates.Reset, ResetUtc = now, ResetReason = reason };
            _byId[alertId] = r;
            _activeByDedup.Remove($"{a.DeviceId}|{a.ConditionId}");
            _lastResetByDedup[$"{a.DeviceId}|{a.ConditionId}"] = now;
            _audit.Append("health_alert_reset", actor,
                $"alert={alertId} device={a.DeviceId} condition={a.ConditionId} reason={reason}", now);
            reset = r;
        }
        // Outside the gate: subscribers close per-alert side effects
        // (work items) and may call back into the centre or the audit.
        if (reset is not null) AlertReset?.Invoke(reset);
        return reset;
    }

    /// <summary>Consume RMM-04 serial-conflict alerts (D38-F5(d))
    /// into this centre, alongside warranty. A conflict is a FLEET
    /// fact (one serial, several claiming device ids): one alert is
    /// raised PER CLAIMING DEVICE, its detail naming the serial and
    /// every claimant, so the conflict is visible on each affected
    /// device's alert path — not only when someone queries the
    /// store. Evaluation happened over stored hub data
    /// (InventoryStore.CollectSerialConflictAlerts); ingesting never
    /// triggers collection. Lifecycle: re-ingesting the same
    /// conflict refreshes (dedup); when a later ingest no longer
    /// lists a (device, serial) pair, that alert AUTO-RESETS — the
    /// store stopped reporting the conflict, so it resolved.
    /// Returns the genuinely NEW alerts created.</summary>
    public IReadOnlyList<HealthAlertEvent> IngestSerialConflictAlerts(
        IEnumerable<SerialConflictAlertEvent> events, DateTimeOffset now)
    {
        var created = new List<HealthAlertEvent>();
        var present = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var e in events)
        {
            if (e.Kind != SerialConflictAlertEvent.KindSerialConflict) continue; // unknown kind: not ours to raise
            var conditionId = $"serial-conflict:{e.SerialNumber}";
            var detail = $"duplicate serial {e.SerialNumber} claimed by devices: {string.Join(", ", e.DeviceIds)}";
            foreach (var deviceId in e.DeviceIds)
            {
                present.Add($"{deviceId}|{conditionId}");
                var outcome = Raise(deviceId, conditionId, ConditionKinds.SerialConflict,
                    AlertSeverities.Warning, detail, "inventory", TimeSpan.FromHours(1), now);
                if (outcome.Outcome == RaiseOutcome.New && outcome.Alert is not null)
                    created.Add(outcome.Alert);
            }
        }
        // Auto-reset conflicts the store no longer reports.
        List<HealthAlertEvent> stale;
        lock (_gate)
            stale = _byId.Values
                .Where(a => a.IsActive && a.Kind == ConditionKinds.SerialConflict &&
                            !present.Contains($"{a.DeviceId}|{a.ConditionId}"))
                .ToList();
        foreach (var a in stale)
            ResetInternal(a.AlertId, "endpoint-monitor",
                "auto-reset: serial conflict no longer reported by the inventory store", now);
        return created;
    }

    /// <summary>Consume RMM-04 warranty alerts into this centre.
    /// Evaluation happened over STORED hub data (InventoryStore
    /// .CollectWarrantyAlerts) — ingesting never triggers a lookup;
    /// this method only maps events the caller already holds. The
    /// condition id carries the warranty kind so expiring→expired is
    /// a transition (the expiring alert auto-resets when the expired
    /// one raises, via the caller's firing-set discipline — here:
    /// directly, since an expired warranty supersedes its warning).
    /// Returns the genuinely NEW alerts created.</summary>
    public IReadOnlyList<HealthAlertEvent> IngestWarrantyAlerts(
        IEnumerable<WarrantyAlertEvent> events, DateTimeOffset now)
    {
        var created = new List<HealthAlertEvent>();
        var present = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var e in events.OrderBy(e => e.ExpiresUtc))
        {
            var conditionId = $"warranty:{e.Kind}";
            present.Add($"{e.DeviceId}|{conditionId}");
            var severity = e.Severity == WarrantyAlertEvent.SeverityExpired
                ? AlertSeverities.Critical : AlertSeverities.Warning;
            var detail = $"warranty {e.Kind} vendor={e.Vendor} serial={e.SerialNumber} expires={e.ExpiresUtc:O} daysRemaining={e.DaysRemaining}";
            var outcome = Raise(e.DeviceId, conditionId, ConditionKinds.Warranty, severity,
                detail, "warranty", TimeSpan.FromDays(1), now);
            if (outcome.Outcome == RaiseOutcome.New && outcome.Alert is not null)
            {
                created.Add(outcome.Alert);
                // An expired warranty supersedes its own expiring warning.
                if (e.Kind == WarrantyAlertEvent.KindExpired)
                {
                    HealthAlertEvent? warning;
                    lock (_gate)
                        warning = _byId.Values.FirstOrDefault(a => a.IsActive &&
                            a.DeviceId == e.DeviceId && a.ConditionId == $"warranty:{WarrantyAlertEvent.KindExpiring}");
                    if (warning is not null)
                        ResetInternal(warning.AlertId, "endpoint-monitor",
                            "superseded: warranty expired", now);
                }
            }
        }
        // D38-F12: a warranty alert whose (device, kind) the source
        // no longer reports AUTO-RESETS — the same lifecycle serial
        // conflicts already had. Before this, a renewed warranty's
        // alert stayed active forever because nothing ever closed
        // it. The caller's event list is the authoritative current
        // snapshot (InventoryStore.CollectWarrantyAlerts), exactly
        // as with serial conflicts.
        List<HealthAlertEvent> stale;
        lock (_gate)
            stale = _byId.Values
                .Where(a => a.IsActive && a.Kind == ConditionKinds.Warranty &&
                            !present.Contains($"{a.DeviceId}|{a.ConditionId}"))
                .ToList();
        foreach (var a in stale)
            ResetInternal(a.AlertId, "endpoint-monitor",
                "auto-reset: warranty state no longer reported by the inventory store", now);
        return created;
    }
}

// ---- hub ingest + device-down ----------------------------------------------

/// <summary>The endpoint→hub health report: the alert-centre payload
/// that rides DeskGuest's existing heartbeat/state channel shape. It
/// carries FACTS (what fired, what the monitor itself is doing, the
/// library in force) — never raw sample dumps; evaluation already
/// happened on the endpoint.</summary>
public sealed record DeviceHealthReport(
    string DeviceId,
    long Seq,
    DateTimeOffset GeneratedUtc,
    string LibraryId,
    string LibraryHash,
    string MonitorStatus,          // "ok" | "degraded" | "failing"
    IReadOnlyList<string> MonitorNotes,
    IReadOnlyList<string> FiringConditionIds,
    IReadOnlyList<HealthAlertEvent> ActiveAlerts)
{
    public IReadOnlyList<string> MonitorNotes { get; init; } = MonitorNotes ?? Array.Empty<string>();
    public IReadOnlyList<string> FiringConditionIds { get; init; } = FiringConditionIds ?? Array.Empty<string>();
    public IReadOnlyList<HealthAlertEvent> ActiveAlerts { get; init; } = ActiveAlerts ?? Array.Empty<HealthAlertEvent>();
}

public static class MonitorStatuses
{
    public const string Ok = "ok";
    public const string Degraded = "degraded";
    public const string Failing = "failing";
    public static readonly IReadOnlySet<string> All = new HashSet<string> { Ok, Degraded, Failing };
}

/// <summary>What the hub believes about one device's health. The
/// "unknown" and "down" states are first-class: a device that has
/// never reported, or has gone silent, is NEVER reported healthy.</summary>
public static class DeviceHealthStates
{
    public const string Unknown = "unknown";   // never reported
    public const string Healthy = "healthy";   // reporting, nothing firing, monitor ok
    public const string Alerting = "alerting"; // reporting, conditions firing
    public const string Degraded = "degraded"; // reporting, but the monitor itself is impaired
    public const string Down = "down";         // silent past the down threshold
}

public sealed record DeviceHealthView(
    string DeviceId, string State, DateTimeOffset? LastReportUtc,
    long LastSeq, IReadOnlyList<string> FiringConditionIds, string? Detail);

/// <summary>Hub-side ingest for endpoint health reports. Tracks
/// last-seen per device, refuses replayed/stale/future reports,
/// mirrors new alerts into the hub's alert centre, and detects
/// device-down from SILENCE: a device whose reports stop is down,
/// and its return auto-resets the down alert. The down threshold is
/// explicit configuration, never a hidden constant.</summary>
public sealed class HubHealthIngest
{
    private readonly HealthAlertCentre _centre;
    private readonly TimeSpan _downAfter;
    private readonly Dictionary<string, DeviceHealthView> _views = new(StringComparer.OrdinalIgnoreCase);
    // D38-F6: mirrored alerts are tracked as endpoint alert id → hub
    // alert id, per device, and ONLY while the endpoint still
    // reports them active — when one disappears from a report, its
    // hub mirror is reset and the entry is dropped, so this map is
    // bounded by the device's currently-active alert set instead of
    // growing forever.
    private readonly Dictionary<string, Dictionary<string, string>> _mirroredAlertIds = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();

    public HubHealthIngest(HealthAlertCentre centre, TimeSpan downAfter)
    {
        _centre = centre ?? throw new ArgumentNullException(nameof(centre));
        if (downAfter <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(downAfter), "down threshold must be positive");
        _downAfter = downAfter;
    }

    public TimeSpan DownAfter => _downAfter;

    /// <summary>Ingest one report. Refusals are named values: empty
    /// device, non-monotonic seq (replay/stale), future-dated beyond
    /// a 5-minute skew allowance, unknown monitor status.</summary>
    public (bool Accepted, string Reason) Ingest(DeviceHealthReport report, DateTimeOffset now)
    {
        if (report is null || string.IsNullOrWhiteSpace(report.DeviceId))
            return (false, "health report carries no device id — refused");
        if (!MonitorStatuses.All.Contains(report.MonitorStatus ?? ""))
            return (false, $"health report names unknown monitor status '{report.MonitorStatus}' — refused");
        if (report.GeneratedUtc > now.AddMinutes(5))
            return (false, "health report is future-dated beyond the skew allowance — refused");
        lock (_gate)
        {
            if (_views.TryGetValue(report.DeviceId, out var prev) && report.Seq <= prev.LastSeq)
                return (false, $"health report seq {report.Seq} is not after the last accepted seq {prev.LastSeq} — refused (replay/stale)");
        }

        // Mirror genuinely-new active alerts into the hub centre.
        Dictionary<string, string> mirrored;
        lock (_gate)
        {
            if (!_mirroredAlertIds.TryGetValue(report.DeviceId, out mirrored))
                _mirroredAlertIds[report.DeviceId] = mirrored = new Dictionary<string, string>(StringComparer.Ordinal);
        }
        var refusedCrossDevice = 0;
        var reportedActive = new HashSet<string>(StringComparer.Ordinal);
        foreach (var alert in report.ActiveAlerts)
        {
            // D38-F4: an alert inside a report is evidence about the
            // REPORTING device only. One whose DeviceId names another
            // device is refused — otherwise one device (or one forged
            // report) could raise alerts on any other device and fill
            // a victim's flood cap ahead of its real alerts.
            if (!string.Equals(alert.DeviceId, report.DeviceId, StringComparison.OrdinalIgnoreCase))
            {
                refusedCrossDevice++;
                continue;
            }
            reportedActive.Add(alert.AlertId);
            bool isNew;
            lock (_gate) isNew = !mirrored.ContainsKey(alert.AlertId);
            if (!isNew) continue;
            var outcome = _centre.Raise(report.DeviceId, alert.ConditionId, alert.Kind, alert.Severity,
                alert.Detail, "hub", TimeSpan.Zero, now);
            if (outcome.Alert is not null)
                lock (_gate) mirrored[alert.AlertId] = outcome.Alert.AlertId;
        }
        // D38-F6: alerts the endpoint no longer reports active have
        // cleared on the endpoint — reset their hub mirrors, or hub
        // alerts would stay active forever and a later re-fire would
        // just refresh the stale copy.
        List<string> vanished;
        lock (_gate) vanished = mirrored.Keys.Where(id => !reportedActive.Contains(id)).ToList();
        foreach (var endpointAlertId in vanished)
        {
            string hubAlertId;
            lock (_gate)
            {
                hubAlertId = mirrored[endpointAlertId];
                mirrored.Remove(endpointAlertId);
            }
            _centre.Reset(hubAlertId, "hub-ingest",
                "auto-reset: endpoint no longer reports this alert active", now);
        }
        lock (_gate)
        {
            if (mirrored.Count == 0) _mirroredAlertIds.Remove(report.DeviceId);
        }

        // D38-F2: a report whose monitor could not read sections
        // (indeterminate conditions named in its notes) is a DEGRADED
        // monitor, never a healthy device — even when its status
        // string says ok and nothing is firing.
        var monitorImpaired = report.MonitorStatus != MonitorStatuses.Ok ||
            report.MonitorNotes.Any(n => n.StartsWith("indeterminate:", StringComparison.OrdinalIgnoreCase));
        var state = report.FiringConditionIds.Count > 0
            ? DeviceHealthStates.Alerting
            : monitorImpaired ? DeviceHealthStates.Degraded : DeviceHealthStates.Healthy;
        lock (_gate)
        {
            // "Was down" is judged by the computed view (stored state
            // OR silence past the threshold), so a device that returns
            // without an intervening sweep still clears its down alert.
            var wasDown = _views.ContainsKey(report.DeviceId) &&
                          View(report.DeviceId, now).State == DeviceHealthStates.Down;
            _views[report.DeviceId] = new DeviceHealthView(
                report.DeviceId, state, report.GeneratedUtc, report.Seq,
                report.FiringConditionIds, $"library={report.LibraryId} monitor={report.MonitorStatus}");
            if (wasDown)
            {
                // The device returned: its down alert auto-resets.
                var down = _centre.ActiveAlerts.FirstOrDefault(a =>
                    a.DeviceId == report.DeviceId && a.Kind == ConditionKinds.DeviceDown);
                if (down is not null)
                    _centre.Reset(down.AlertId, "hub-ingest", "auto-reset: device reporting again", now);
            }
        }
        return (true, $"health report accepted (state {state})" +
            (refusedCrossDevice > 0
                ? $"; {refusedCrossDevice} mirrored alert(s) naming a different device refused"
                : ""));
    }

    /// <summary>The hub's current view of one device at `now`. A
    /// device past its silence threshold reads DOWN here even
    /// between sweeps — the view computes it, it does not wait to be
    /// told.</summary>
    public DeviceHealthView View(string deviceId, DateTimeOffset now)
    {
        lock (_gate)
        {
            if (!_views.TryGetValue(deviceId ?? "", out var v))
                return new DeviceHealthView(deviceId ?? "", DeviceHealthStates.Unknown, null, 0,
                    Array.Empty<string>(), "no health report ever received — state is unknown, not healthy");
            if (v.LastReportUtc is { } last && now - last > _downAfter && v.State != DeviceHealthStates.Down)
                return v with
                {
                    State = DeviceHealthStates.Down,
                    Detail = $"silent for {now - last} (threshold {_downAfter}) — device is down or unreachable",
                };
            return v;
        }
    }

    /// <summary>One down-detection sweep: every tracked device silent
    /// past the threshold gets its device_down alert (deduped by the
    /// centre) and its view marked down. Returns the devices newly
    /// marked down on THIS sweep.</summary>
    public IReadOnlyList<string> SweepDeviceDown(DateTimeOffset now)
    {
        var newlyDown = new List<string>();
        List<DeviceHealthView> snapshot;
        lock (_gate) snapshot = _views.Values.ToList();
        foreach (var v in snapshot)
        {
            var view = View(v.DeviceId, now);
            if (view.State != DeviceHealthStates.Down) continue;
            bool wasDown;
            lock (_gate)
            {
                wasDown = _views[v.DeviceId].State == DeviceHealthStates.Down;
                _views[v.DeviceId] = view;
            }
            var outcome = _centre.Raise(v.DeviceId, SystemAlertConditionIds.DeviceDown, ConditionKinds.DeviceDown,
                AlertSeverities.Critical,
                $"no health report for {now - (v.LastReportUtc ?? now)} (threshold {_downAfter})",
                "hub", TimeSpan.Zero, now);
            if (!wasDown && outcome.Outcome == RaiseOutcome.New) newlyDown.Add(v.DeviceId);
        }
        return newlyDown;
    }

    public IReadOnlyList<DeviceHealthView> Views(DateTimeOffset now)
    {
        lock (_gate) return _views.Keys.Select(id => View(id, now)).ToList();
    }
}
