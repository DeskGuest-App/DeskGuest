using DeskGuest.Shared.AnomalyBaselining;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.Monitoring;

namespace DeskGuest.Core.Services;

// =====================================================================
// RMM-27 — AnomalyDetectionService: the Core wiring for local
// anomaly baselining over RMM-01 history.
//
//   * FEED: the service consumes the SAME EndpointSample stream
//     RMM-01's monitor collects (MetricObservationExtractor) — it
//     keeps its own rolling admitted history in AnomalyProfileStore
//     because RMM-01 retains no sample history of its own. Nothing
//     is re-collected and nothing leaves the endpoint/hub.
//   * DETECTION: a value outside a MATURE profile's learned band,
//     sustained continuously for the policy sustain duration,
//     raises ONE alert into RMM-01's HealthAlertCentre (kind
//     metric_anomaly, condition id per metric+target) under the
//     centre's own dedup / cooldown / flood discipline. The alert
//     detail is the evaluation's numeric evidence — observed value,
//     band, median, sample count, maturity — never a bare
//     "anomaly detected". When the value returns inside the band,
//     THIS service resets exactly the alerts it raised.
//   * LEARNING runs beside detection with the store's poisoning
//     discipline: values under an active anomaly alert for the
//     metric are excluded, values outside the (provisional) band
//     are excluded, recomputation is rate-limited, and material
//     profile drift is audited as its own event
//     (anomaly_profile_drift) — the band teaching itself a new
//     normal is a visible fact, not a silent slide.
//   * POLICY: the whole feature is gated on the RMM-07 registry
//     toggle rmm.anomaly_baselining.enabled (seeded ON); sensitivity,
//     sustain, severity and cooldown are policy content resolved
//     per device through Effective Policy. Disabled means: no
//     learning, no detection, no alerts — and the cycle result
//     names the refusal.
//   * TIMESTAMP DISCIPLINE + RELEARN (FL-27a, D38 RMM-27 F2/F5):
//     cycle time is the service's `now` — future-dated observations
//     are quarantined, recomputation runs on service time, and a
//     service-raised alert is reset when its profile falls back to
//     learning. A genuine regime change is relearned through the
//     audited admin rebaseline (RebaselineProfile), never by the
//     observation path quietly absorbing it.
//   * LEARNED ≠ DECLARED: this service never reads or writes
//     RMM-19 baselines. The two models meet only in the shared
//     alert centre, as separate kinds (metric_anomaly vs
//     baseline_drift).
// =====================================================================

/// <summary>One anomaly cycle's outcome for one device sample.</summary>
public sealed record AnomalyCycleResult(
    bool AnomalyEnabled,
    bool Ran,
    string? NotRunReason,
    string DeviceId,
    IReadOnlyList<AnomalyEvaluation> Evaluations,
    IReadOnlyList<AdmissionResult> Admissions,
    IReadOnlyList<HealthAlertEvent> NewAlerts,
    IReadOnlyList<HealthAlertEvent> ResetAlerts,
    IReadOnlyList<ProfileDriftNotice> DriftNotices,
    IReadOnlyList<string> PolicyNotes)
{
    public IReadOnlyList<AnomalyEvaluation> Evaluations { get; init; } = Evaluations ?? Array.Empty<AnomalyEvaluation>();
    public IReadOnlyList<AdmissionResult> Admissions { get; init; } = Admissions ?? Array.Empty<AdmissionResult>();
    public IReadOnlyList<HealthAlertEvent> NewAlerts { get; init; } = NewAlerts ?? Array.Empty<HealthAlertEvent>();
    public IReadOnlyList<HealthAlertEvent> ResetAlerts { get; init; } = ResetAlerts ?? Array.Empty<HealthAlertEvent>();
    public IReadOnlyList<ProfileDriftNotice> DriftNotices { get; init; } = DriftNotices ?? Array.Empty<ProfileDriftNotice>();
    public IReadOnlyList<string> PolicyNotes { get; init; } = PolicyNotes ?? Array.Empty<string>();
}

/// <summary>The hub-facing anomaly report for one device: every
/// learned profile with its maturity report and exclusion counters —
/// facts only, riding the existing report shape discipline.</summary>
public sealed record DeviceAnomalyReport(
    string DeviceId,
    long Seq,
    DateTimeOffset GeneratedUtc,
    IReadOnlyList<LearnedProfile> Profiles,
    IReadOnlyList<string> Notes)
{
    public IReadOnlyList<LearnedProfile> Profiles { get; init; } = Profiles ?? Array.Empty<LearnedProfile>();
    public IReadOnlyList<string> Notes { get; init; } = Notes ?? Array.Empty<string>();
}

public sealed class AnomalyDetectionService
{
    private readonly ChainedAuditLog _audit;
    private readonly ManagementPolicyService _policies;
    private readonly HealthAlertCentre _centre;
    private readonly Func<string, IDeviceFacts?> _factsFor;
    private readonly Func<DateTimeOffset> _now;
    private readonly object _lock = new();

    private readonly Dictionary<AnomalyProfileKey, DateTimeOffset> _outsideSince = new();
    private readonly Dictionary<AnomalyProfileKey, string> _raisedAlertIdByKey = new();
    private readonly Dictionary<string, long> _reportSeq = new(StringComparer.OrdinalIgnoreCase);

    public AnomalyProfileStore Store { get; }

    public AnomalyDetectionService(
        ChainedAuditLog audit,
        ManagementPolicyService policies,
        HealthAlertCentre centre,
        Func<string, IDeviceFacts?> factsFor,
        AnomalyProfileStore? store = null,
        Func<DateTimeOffset>? now = null)
    {
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _policies = policies ?? throw new ArgumentNullException(nameof(policies));
        _centre = centre ?? throw new ArgumentNullException(nameof(centre));
        _factsFor = factsFor ?? throw new ArgumentNullException(nameof(factsFor));
        Store = store ?? new AnomalyProfileStore();
        _now = now ?? (() => DateTimeOffset.UtcNow);
    }

    /// <summary>THE policy gate: rmm.anomaly_baselining.enabled for
    /// this device, via the RMM-07 registry/engine contract.</summary>
    public bool AnomalyEnabledFor(string deviceId) =>
        _factsFor(deviceId) is { } facts && _policies.IsEnabled(facts, AnomalyPolicyKeys.Enabled);

    /// <summary>Observe one RMM-01 endpoint sample: extract its
    /// metric observations, evaluate each against its profile
    /// (detection BEFORE admission — a value is judged by the band
    /// as it stood, then the admission discipline decides whether
    /// it may teach), run the sustain discipline, and admit what
    /// may be learned.</summary>
    public AnomalyCycleResult Observe(EndpointSample sample)
    {
        if (sample is null) throw new ArgumentNullException(nameof(sample));
        return ObserveObservations(sample.DeviceId, MetricObservationExtractor.FromSample(sample), sample.AtUtc);
    }

    /// <summary>Observe a batch of metric observations for one
    /// device (the direct-history feed: backfill from stored RMM-01
    /// history runs through exactly this path).
    ///
    /// TIMESTAMP DISCIPLINE (FL-27a / F2): `now` is the service's
    /// clock for this cycle and it is USED — previously it was
    /// accepted and never referenced, so the window, the recompute
    /// rate limit, sustain and maturity all ran on caller-supplied
    /// observation timestamps and a feed could date its way past
    /// every defence. Now: an observation dated beyond
    /// AnomalyLimits.MaxObservationFutureSkew ahead of `now` is
    /// QUARANTINED (recorded as a refused_future_dated admission;
    /// never judged, never learned, never able to satisfy sustain);
    /// the batch is processed in chronological order; the store's
    /// rolling window runs on `now`; stale observations (older than
    /// the newest admitted sample) are refused by the store; and
    /// profile recomputation happens once per touched profile at
    /// the END of the cycle, stamped with `now`, so the rate limit
    /// and the drift history run on service time.</summary>
    public AnomalyCycleResult ObserveObservations(
        string deviceId, IReadOnlyList<MetricObservation> observations, DateTimeOffset now)
    {
        AnomalyCycleResult NotRun(string reason) => new(false, false, reason, deviceId,
            Array.Empty<AnomalyEvaluation>(), Array.Empty<AdmissionResult>(),
            Array.Empty<HealthAlertEvent>(), Array.Empty<HealthAlertEvent>(),
            Array.Empty<ProfileDriftNotice>(), Array.Empty<string>());

        var facts = _factsFor(deviceId);
        if (facts is null) return NotRun($"no device facts for '{deviceId}' — anomaly cycle did not run");
        if (!_policies.IsEnabled(facts, AnomalyPolicyKeys.Enabled))
            return NotRun($"anomaly baselining disabled by policy ({AnomalyPolicyKeys.Enabled}) — no learning, no detection");

        var policy = AnomalyPolicyResolver.Resolve(_policies.Engine, facts);
        var evaluations = new List<AnomalyEvaluation>();
        var admissions = new List<AdmissionResult>();
        var newAlerts = new List<HealthAlertEvent>();
        var resetAlerts = new List<HealthAlertEvent>();
        var driftNotices = new List<ProfileDriftNotice>();
        var touchedKeys = new List<AnomalyProfileKey>();

        foreach (var obs in observations
                     .Where(o => string.Equals(o.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase))
                     .OrderBy(o => o.AtUtc))
        {
            var key = obs.Key;

            // FL-27a / F2: future quarantine, on service time.
            if (obs.AtUtc > now.Add(AnomalyLimits.MaxObservationFutureSkew))
            {
                admissions.Add(new AdmissionResult(AdmissionOutcomes.RefusedFutureDated,
                    $"observation for {obs.Metric} at {obs.AtUtc:O} is ahead of service time {now:O} beyond the " +
                    $"{AnomalyLimits.MaxObservationFutureSkew.TotalMinutes:F0}-minute skew allowance — quarantined (not judged, not learned)"));
                continue;
            }
            if (!touchedKeys.Contains(key)) touchedKeys.Add(key);

            // Active-alert state BEFORE this observation is handled:
            // an alert already active for this metric excludes the
            // value from learning (poisoning defence 2).
            var activeAlert = _centre.ActiveAlerts.FirstOrDefault(a =>
                string.Equals(a.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase) &&
                a.Kind == AnomalyAlerting.Kind && a.ConditionId == key.ConditionId);
            var underAlert = activeAlert is not null;

            // 1) Detection against the profile as it stands.
            var profile = Store.GetProfile(key);
            var eval = AnomalyEvaluator.Evaluate(key, obs.Value, profile);
            evaluations.Add(eval);

            lock (_lock)
            {
                switch (eval.Verdict)
                {
                    case AnomalyVerdicts.OutsideBand:
                    {
                        if (!_outsideSince.TryGetValue(key, out var since))
                        {
                            since = obs.AtUtc;
                            _outsideSince[key] = since;
                        }
                        if (obs.AtUtc - since >= policy.Sustain)
                        {
                            var detail = eval.EvidenceDetail +
                                $" :: sustained outside band for {obs.AtUtc - since} (policy sustain {policy.Sustain})";
                            var outcome = _centre.Raise(deviceId, key.ConditionId, AnomalyAlerting.Kind,
                                policy.Severity, detail, AnomalyAlerting.Source, policy.Cooldown, obs.AtUtc);
                            if (outcome.Outcome == RaiseOutcome.New && outcome.Alert is not null)
                            {
                                newAlerts.Add(outcome.Alert);
                                _raisedAlertIdByKey[key] = outcome.Alert.AlertId;
                            }
                            else if (outcome.Alert is not null)
                            {
                                _raisedAlertIdByKey[key] = outcome.Alert.AlertId;
                            }
                        }
                        break;
                    }
                    case AnomalyVerdicts.InsideBand:
                    {
                        _outsideSince.Remove(key);
                        if (_raisedAlertIdByKey.TryGetValue(key, out var alertId))
                        {
                            _raisedAlertIdByKey.Remove(key);
                            var reset = _centre.Reset(alertId, "anomaly-detection",
                                "auto-reset: value returned inside the learned band", obs.AtUtc);
                            if (reset is not null) resetAlerts.Add(reset);
                        }
                        break;
                    }
                    default:
                        // Learning: no verdict, and no sustain state
                        // is carried — an immature profile neither
                        // accuses nor clears.
                        _outsideSince.Remove(key);
                        // FL-27a / F5: a service-raised alert must
                        // not outlive the profile that raised it.
                        // If the profile has fallen back to learning
                        // (window slide, import, rebaseline), the
                        // alert staying active deadlocked the
                        // profile: every new value was excluded as
                        // under-active-alert, so it could never
                        // relearn, so it stayed immature forever.
                        // Reset exactly our own alert here — the
                        // profile's immaturity clears it, and
                        // clearing it lifts the learning exclusion.
                        if (_raisedAlertIdByKey.TryGetValue(key, out var staleAlertId))
                        {
                            _raisedAlertIdByKey.Remove(key);
                            var reset = _centre.Reset(staleAlertId, "anomaly-detection",
                                "auto-reset: profile returned to learning (immature) — a service-raised alert cannot outlive its profile, and clearing it lifts the alert-period learning exclusion so the profile can relearn",
                                obs.AtUtc);
                            if (reset is not null) resetAlerts.Add(reset);
                        }
                        break;
                }
            }

            // 2) Admission (the store applies the poisoning
            // discipline; the rolling window runs on service time).
            admissions.Add(Store.Admit(obs, underAlert, policy.BandFactor, now));
        }

        // 3) Recomputation, once per touched profile, on SERVICE
        // time (FL-27a / F2): the rate limit, the profile's
        // ComputedUtc and the drift audit all carry `now`, never a
        // caller-supplied observation timestamp. Material drift is
        // surfaced + audited, as before.
        foreach (var key in touchedKeys)
        {
            var (_, drift, _) = Store.Recompute(key, now, policy.BandFactor);
            if (drift is not null)
            {
                driftNotices.Add(drift);
                _audit.Append("anomaly_profile_drift", "anomaly-detection",
                    $"device={deviceId} metric={key.Metric} target={key.Target} {drift.Detail}", now);
            }
        }

        // FL-27b / F9: eviction runs each cycle — profiles whose
        // admitted history has fully aged out (and empty profiles)
        // are removed, so renamed disks / vanished processes /
        // decommissioned targets cannot accumulate forever. The
        // per-device profile cap in the store bounds growth
        // between cycles.
        Store.EvictStale(now);

        return new AnomalyCycleResult(true, true, null, deviceId,
            evaluations, admissions, newAlerts, resetAlerts, driftNotices, policy.Notes);
    }

    /// <summary>FL-27a / F5 — the admin relearn path. A genuine
    /// regime change (new workload, new hardware) is UNLEARNABLE on
    /// the observation path by design: trimmed admission excludes
    /// the new regime's values and alert-period exclusion excludes
    /// the rest. Rebaseline is the named, audited door: it requires
    /// a named actor, is gated on the same policy toggle as every
    /// other anomaly act, resets exactly the service-raised alert
    /// for the profile (so the alert-period exclusion lifts with
    /// the history it was guarding), clears the sustain clock, and
    /// clears the learned state so the new regime is learned fresh
    /// under the ordinary maturity discipline — the profile is
    /// silent (learning) until it re-earns maturity, never instantly
    /// trusted.</summary>
    public (bool Done, string Detail) RebaselineProfile(
        string deviceId, string metric, string target, string actor, DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(actor))
            return (false, "rebaseline requires a named actor — refused (an anonymous rebaseline would be an unauditable poisoning door)");
        var facts = _factsFor(deviceId);
        if (facts is null) return (false, $"no device facts for '{deviceId}' — rebaseline did not run");
        if (!_policies.IsEnabled(facts, AnomalyPolicyKeys.Enabled))
            return (false, $"anomaly baselining disabled by policy ({AnomalyPolicyKeys.Enabled}) — rebaseline did not run");
        if (!AnomalyMetrics.All.Contains(metric ?? ""))
            return (false, $"metric '{metric}' is not a learned metric — rebaseline refused");

        var key = new AnomalyProfileKey(deviceId, metric, target ?? "*");
        lock (_lock)
        {
            _outsideSince.Remove(key);
            if (_raisedAlertIdByKey.TryGetValue(key, out var alertId))
            {
                _raisedAlertIdByKey.Remove(key);
                _centre.Reset(alertId, "anomaly-detection",
                    $"auto-reset: profile rebaselined by {actor} — the learned history the alert was raised against has been cleared", now);
            }
        }
        var (existed, cleared) = Store.Rebaseline(key);
        _audit.Append("anomaly_profile_rebaseline", actor,
            $"device={deviceId} metric={metric} target={key.Target} priorProfile={(existed ? "cleared" : "none")} samplesCleared={cleared}", now);
        return (true, existed
            ? $"profile for {key} rebaselined by {actor}: {cleared} admitted samples cleared — the metric relearns under the ordinary maturity discipline (silent until mature)"
            : $"no profile existed for {key} — rebaseline by {actor} recorded; learning starts from empty");
    }

    /// <summary>The current learned profile for one key, if any —
    /// with its maturity report; surfaces show "still learning"
    /// from this, never silence.</summary>
    public LearnedProfile? ProfileFor(AnomalyProfileKey key) => Store.GetProfile(key);

    /// <summary>Build the anomaly report for one device: all of its
    /// profiles (with maturity), plus the honesty notes.</summary>
    public DeviceAnomalyReport BuildReport(string deviceId)
    {
        long seq;
        lock (_lock)
        {
            _reportSeq.TryGetValue(deviceId, out seq);
            _reportSeq[deviceId] = ++seq;
        }
        var profiles = Store.Keys
            .Where(k => string.Equals(k.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase))
            .Select(k => Store.GetProfile(k)).Where(p => p is not null).Cast<LearnedProfile>()
            .OrderBy(p => p.Key.Metric, StringComparer.Ordinal).ThenBy(p => p.Key.Target, StringComparer.Ordinal)
            .ToList();
        var notes = new List<string>
        {
            AnomalyHonesty.Method,
            AnomalyHonesty.SeasonalityLimitation,
            AnomalyHonesty.LearnedVsDeclared,
        };
        foreach (var p in profiles)
        {
            var (underAlert, outsideBand, dropped, admitted) = Store.Counters(p.Key);
            notes.Add($"{p.Key.Metric}/{p.Key.Target}: {p.MaturityReport}; admitted={admitted} " +
                      $"excludedUnderAlert={underAlert} excludedOutsideBand={outsideBand} droppedForCap={dropped}");
        }
        return new DeviceAnomalyReport(deviceId, seq, _now(), profiles, notes);
    }
}
