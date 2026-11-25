using Acp.Shared.Enterprise;
using Acp.Shared.HealthScoring;
using Acp.Shared.Inventory;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Monitoring;
using Acp.Shared.Backup;
using Acp.Shared.Vulnerability;

namespace Acp.Core.Services;

// =====================================================================
// RMM-28 — Endpoint health scoring: the Core data surface.
//
// Computes per-device health scores from the source systems' own
// shapes (RMM-01 hub ingest + alert centre, RMM-05 exposure store
// + feed provenance, RMM-06 backup health facts, RMM-17 posture,
// RMM-04 inventory store), under RMM-07 policy: the feature toggle
// `rmm.health_scoring.enabled` (seeded ON) gates computation, and
// the weights + staleness bounds are policy CONTENT — versioned,
// recorded on every score, never retro-applied to snapshots.
//
// Every computation, refusal and import is a chained-audit event.
// Scores are stored as point-in-time snapshots in HealthScoreStore;
// history and trend read snapshots back exactly as recorded.
// =====================================================================

// ---- adapters over the real source systems -------------------------------

/// <summary>RMM-01 adapter: the hub ingest's computed view plus the
/// alert centre's active alerts for the device.</summary>
public sealed class HubMonitoringFactsSource : IMonitoringFactsSource
{
    private readonly HubHealthIngest _ingest;
    private readonly HealthAlertCentre _centre;

    public HubMonitoringFactsSource(HubHealthIngest ingest, HealthAlertCentre centre)
    {
        _ingest = ingest ?? throw new ArgumentNullException(nameof(ingest));
        _centre = centre ?? throw new ArgumentNullException(nameof(centre));
    }

    public MonitoringHealthInput? Get(string deviceId, DateTimeOffset now) => new(
        _ingest.View(deviceId, now),
        _centre.ActiveAlerts
            .Where(a => string.Equals(a.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase))
            .ToList());
}

/// <summary>RMM-05 adapter: the exposure store's unclosed items for
/// the device, with the feed provenance supplied by the caller
/// (VulnerabilityService.ProvenanceFor under RMM-05's own policy).</summary>
public sealed class ExposureStoreFactsSource : IExposureFactsSource
{
    private readonly ExposureStore _store;
    private readonly Func<DateTimeOffset, FeedProvenance> _provenance;

    public ExposureStoreFactsSource(ExposureStore store, Func<DateTimeOffset, FeedProvenance> provenance)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _provenance = provenance ?? throw new ArgumentNullException(nameof(provenance));
    }

    public ExposureHealthInput? Get(string deviceId, DateTimeOffset now) => new(
        _store.Items
            .Where(i => !i.IsClosed && string.Equals(i.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase))
            .ToList(),
        _provenance(now));
}

/// <summary>RMM-04 adapter: the hub inventory store's record.</summary>
public sealed class InventoryStoreFactsSource : IInventoryFactsSource
{
    private readonly InventoryStore _store;
    public InventoryStoreFactsSource(InventoryStore store) =>
        _store = store ?? throw new ArgumentNullException(nameof(store));
    public DeviceInventoryRecord? Get(string deviceId, DateTimeOffset now) => _store.Get(deviceId);
}

/// <summary>RMM-17 adapter: posture is per-device service state in
/// the Core, so the seam is a delegate the host wires to its
/// EndpointSecurityService instances.</summary>
public sealed class DelegatePostureFactsSource : IPostureFactsSource
{
    private readonly Func<string, PostureHealthInput?> _get;
    public DelegatePostureFactsSource(Func<string, PostureHealthInput?> get) =>
        _get = get ?? throw new ArgumentNullException(nameof(get));
    public PostureHealthInput? Get(string deviceId, DateTimeOffset now) => _get(deviceId);
}

// ---- the service -------------------------------------------------------------

public sealed record HealthScoreOutcome(DeviceHealthScore? Score, string Reason)
{
    public bool Ok => Score is not null;
}

public sealed class HealthScoringService
{
    private readonly ChainedAuditLog _audit;
    private readonly ManagementPolicyEngine _policy;
    private readonly Func<string, IDeviceFacts?> _factsByDevice;
    private readonly IMonitoringFactsSource? _monitoring;
    private readonly IExposureFactsSource? _exposure;
    private readonly IBackupHealthFactsProvider? _backup;
    private readonly IPostureFactsSource? _posture;
    private readonly IInventoryFactsSource? _inventory;
    private readonly HealthScoreStore _store;
    private readonly Func<DateTimeOffset> _now;

    /// <summary>Any facts source may be null (not wired on this
    /// host): its component then scores UNKNOWN with the absence
    /// named — an unwired source never becomes a silent 100.</summary>
    public HealthScoringService(
        ChainedAuditLog audit, ManagementPolicyEngine policy,
        Func<string, IDeviceFacts?> factsByDevice,
        IMonitoringFactsSource? monitoring, IExposureFactsSource? exposure,
        IBackupHealthFactsProvider? backup, IPostureFactsSource? posture,
        IInventoryFactsSource? inventory,
        HealthScoreStore? store = null, Func<DateTimeOffset>? now = null,
        byte[]? signingKey = null, byte[]? previousSigningKey = null)
    {
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _policy = policy ?? throw new ArgumentNullException(nameof(policy));
        _factsByDevice = factsByDevice ?? throw new ArgumentNullException(nameof(factsByDevice));
        _monitoring = monitoring;
        _exposure = exposure;
        _backup = backup;
        _posture = posture;
        _inventory = inventory;
        // FL-28a (F1): a hub signing key keys the snapshot store
        // (signed exports, signature-required imports). Hosts that
        // provision no key keep the unkeyed store — named remainder.
        _store = store ?? new HealthScoreStore(signingKey, previousSigningKey);
        _now = now ?? (() => DateTimeOffset.UtcNow);
    }

    public HealthScoreStore Store => _store;

    public bool IsEnabled(string deviceId)
    {
        var facts = _factsByDevice(deviceId);
        return facts is not null && _policy.IsEnabled(facts, HealthScoringPolicyKeys.Enabled);
    }

    /// <summary>The weights + staleness bounds in force for a
    /// device, from its Effective Policy. Refusals are returned
    /// with the parse — malformed weights content is visible,
    /// never silently defaulted.</summary>
    public (HealthScoreWeights? Weights, HealthStalenessBounds Bounds, IReadOnlyList<string> Refusals)
        PolicyFor(string deviceId)
    {
        var facts = _factsByDevice(deviceId);
        if (facts is null)
            return (null, HealthStalenessBounds.Default,
                new[] { $"no device facts for '{deviceId}' — no health-scoring policy can be computed" });
        var effective = _policy.ComputeEffective(facts);
        var (weights, weightRefusals) = HealthScoreWeightsPolicy.Parse(effective);
        var (bounds, staleRefusals) = HealthStalenessPolicy.Parse(effective);
        return (weights, bounds, weightRefusals.Concat(staleRefusals).ToList());
    }

    /// <summary>Compute, snapshot and audit one device's health
    /// score. Refusals (policy OFF, unknown device, malformed
    /// weights policy) are named values and are audited too.</summary>
    public HealthScoreOutcome ComputeScore(string deviceId, string actor)
    {
        var now = _now();
        actor = string.IsNullOrWhiteSpace(actor) ? "health-scoring" : actor;
        HealthScoreOutcome Refuse(string reason)
        {
            _audit.Append("health_score_refused", actor, $"device={deviceId} reason={reason}", now);
            return new HealthScoreOutcome(null, reason);
        }

        var facts = _factsByDevice(deviceId);
        if (facts is null) return Refuse($"no device facts for '{deviceId}' — the device is not known to this hub");
        if (!_policy.IsEnabled(facts, HealthScoringPolicyKeys.Enabled))
            return Refuse("rmm.health_scoring.enabled is OFF by policy for this device");

        var (weights, bounds, refusals) = PolicyFor(deviceId);
        if (weights is null || refusals.Count > 0)
            return Refuse($"health-scoring policy content refused: {string.Join("; ", refusals)}");

        // FL-28b / F12: per-device error isolation. A throwing
        // facts source (or a scorer fault) for THIS device becomes
        // an audited refusal for this device — previously the
        // exception propagated and aborted ComputeFleet for every
        // remaining device in the run.
        HealthScoreInputs inputs;
        DeviceHealthScore score;
        try
        {
            inputs = new HealthScoreInputs(
                _monitoring?.Get(deviceId, now),
                _exposure?.Get(deviceId, now),
                _backup?.GetFacts(deviceId, now),
                _posture?.Get(deviceId, now),
                _inventory?.Get(deviceId, now));
            score = HealthScoreEngine.Compute(deviceId, facts.ScopeId, inputs, weights!, bounds, now);
        }
        catch (Exception ex)
        {
            return Refuse($"health scoring failed for this device: {ex.GetType().Name}: {ex.Message} — isolated to this device; the fleet run continues");
        }
        var (ok, reason) = _store.Add(score);
        if (!ok) return Refuse($"computed score failed snapshot admission: {reason}");
        _audit.Append("health_score_computed", actor,
            $"device={deviceId} aggregate={(score.Aggregate is { } a ? a.ToString("F1") : "unscored")} state={score.State} " +
            $"coverage={score.CoverageFraction:F2} weights={score.WeightsVersion} " +
            $"unknown=[{string.Join(",", score.UnknownComponents)}] cap={score.AggregateCapReason ?? "none"} hash={score.ContentHash}", now);
        return new HealthScoreOutcome(score, reason);
    }

    /// <summary>Compute fresh scores for the given devices and
    /// build the fleet report over the store's latest snapshots.
    /// Per-device refusals are returned alongside — a device that
    /// could not be scored is named, never silently absent.</summary>
    public (HealthFleetReport Report, IReadOnlyList<string> Refusals) ComputeFleet(
        IReadOnlyList<string> deviceIds, string scopeId, string actor)
    {
        // FL-28a (F5): the report covers EXACTLY the requested
        // devices in the requested scope. Previously it was built
        // from the store's unfiltered LatestAll(), so every device
        // ever scored leaked into every fleet report. A device
        // REFUSED in this run is excluded even if an older snapshot
        // exists — its stale number must not ride this run's report
        // unmarked; it is named in the refusals instead.
        var requested = new HashSet<string>(deviceIds ?? Array.Empty<string>(),
            StringComparer.OrdinalIgnoreCase);
        var refusedThisRun = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var refusals = new List<string>();
        foreach (var deviceId in deviceIds ?? Array.Empty<string>())
        {
            var outcome = ComputeScore(deviceId, actor);
            if (!outcome.Ok)
            {
                refusals.Add($"{deviceId}: {outcome.Reason}");
                refusedThisRun.Add(deviceId);
            }
        }
        var latest = _store.LatestAll(s =>
            string.Equals(s.ScopeId, scopeId, StringComparison.OrdinalIgnoreCase) &&
            requested.Contains(s.DeviceId) &&
            !refusedThisRun.Contains(s.DeviceId));
        var report = HealthFleetReportBuilder.Build(latest, scopeId, _now());
        return (report, refusals);
    }

    /// <summary>The fleet report over EXISTING snapshots — no
    /// recomputation; what was recorded is what is reported.
    /// Filtered to the requested scope (FL-28a F5).</summary>
    public HealthFleetReport FleetReport(string scopeId) =>
        HealthFleetReportBuilder.Build(
            _store.LatestAll(s =>
                string.Equals(s.ScopeId, scopeId, StringComparison.OrdinalIgnoreCase)),
            scopeId, _now());

    public DeviceHealthScore? Latest(string deviceId) => _store.Latest(deviceId);

    public IReadOnlyList<DeviceHealthScore> History(string deviceId,
        DateTimeOffset? fromUtc = null, DateTimeOffset? toUtc = null) =>
        _store.History(deviceId, fromUtc, toUtc);

    /// <summary>Trend over the device's recorded snapshots.</summary>
    public DeviceHealthTrend Trend(string deviceId) =>
        HealthTrendBuilder.Build(deviceId, _store.History(deviceId));

    /// <summary>Import a snapshot produced elsewhere (e.g. another
    /// hub's export). FL-28a (F6) gates, all refusing by name and
    /// chained: a named actor is required; the snapshot must
    /// verify (hash + signature when keyed + fact-level
    /// integrity); its ComputedUtc must not be future-dated; its
    /// scope must match <paramref name="expectedScopeId"/> when
    /// given; the device must be known to this hub and health
    /// scoring must be ON by policy for it. Admitted imports are
    /// segregated from computed snapshots in Latest.</summary>
    public (bool Ok, string Reason) ImportSnapshot(string? json, string actor,
        string? expectedScopeId = null)
    {
        var now = _now();
        (bool, string) Refuse(string reason)
        {
            _audit.Append("health_score_import_refused",
                string.IsNullOrWhiteSpace(actor) ? "health-scoring" : actor,
                $"reason={reason}", now);
            return (false, reason);
        }

        if (string.IsNullOrWhiteSpace(actor))
            return Refuse("snapshot import requires a named actor — refused (anonymous imports carry no provenance)");
        // BD-WIN-CORE-3/F9 (reconciled with the RMM-28 F6 contract):
        // an UNKEYED store verifies imports by content hash +
        // decomposition integrity (HealthScoreIntegrity) — internal
        // consistency, not provenance. That posture is RMM-28's
        // deliberate design (imports are segregated from computed
        // snapshots and never surface as this hub's own score), so
        // it is NOT refused here; it is named in the audit entry on
        // admission below, so an integrity-only admission is never
        // silent. When a hub signing key IS provisioned,
        // TryParseVerified requires the signature.
        var (vok, vreason, score) = _store.TryParseVerified(json);
        if (!vok) return Refuse(vreason);
        if (score!.ComputedUtc > now.AddMinutes(5))
            return Refuse($"snapshot ComputedUtc {score.ComputedUtc:O} is in the future (beyond the 5-minute skew allowance) — refused (a future-dated import would shadow real snapshots)");
        if (expectedScopeId is not null &&
            !string.Equals(expectedScopeId, score.ScopeId, StringComparison.OrdinalIgnoreCase))
            return Refuse($"snapshot scope '{score.ScopeId}' does not match the expected scope '{expectedScopeId}' — refused");
        var facts = _factsByDevice(score.DeviceId);
        if (facts is null)
            return Refuse($"no device facts for '{score.DeviceId}' — the device is not known to this hub; import refused");
        if (!_policy.IsEnabled(facts, HealthScoringPolicyKeys.Enabled))
            return Refuse("rmm.health_scoring.enabled is OFF by policy for this device — import refused");

        var (ok, reason, admitted) = _store.AddImported(score);
        if (!ok) return Refuse(reason);
        _audit.Append("health_score_snapshot_imported", actor,
            $"device={admitted!.DeviceId} computed={admitted.ComputedUtc:O} weights={admitted.WeightsVersion} hash={admitted.ContentHash} " +
            (_store.IsKeyed ? "verification=signature" : "verification=integrity-only (no hub signing key provisioned — BD-WIN-CORE-3/F9)"), now);
        return (true, reason);
    }
}
