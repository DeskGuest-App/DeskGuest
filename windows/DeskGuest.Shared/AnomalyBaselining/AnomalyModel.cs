using System.Text.Json;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.Monitoring;

namespace DeskGuest.Shared.AnomalyBaselining;

// =====================================================================
// RMM-27 — Local anomaly baselining over RMM-01 history (ADOPTED
// 2026-11-20). MODEL LAYER: per-device + per-metric LEARNED
// statistical profiles, robust band computation, poisoning-resistant
// admission, profile-drift history, and claim-checked export/import
// (claims are verified by recomputation from the embedded samples —
// an integrity check, NOT authentication: exports carry no MAC or
// signature, so a fully self-consistent forgery is indistinguishable
// from an honest export; who may import is an authorization question
// answered by the device binding on Import, not by the statistics).
//
// *** LEARNED NORM ≠ DECLARED BASELINE — READ THIS FIRST ***
// RMM-19 (DeskGuest.Shared.Baselines) is ADMIN-DECLARED expected state: a
// human signed a document saying what SHOULD be true. RMM-27 is a
// LEARNED statistical norm: the endpoint observed what HAS been
// true. They are different kinds of fact, kept in different models,
// and neither ever overrides the other: a learned band moving does
// not edit a declared baseline, and a declared baseline does not
// widen or narrow a learned band. Drift (RMM-19) answers "does the
// machine match what we declared?"; anomaly (RMM-27) answers "does
// the machine match its own history?". Both report into the SAME
// RMM-01 alert centre — there is no parallel alerting path.
//
// Doctrine carried from the lane assignment:
//   * ROBUST STATISTICS ONLY: medians and percentile bands. A mean
//     can be dragged by one spike; a median cannot. No ML model
//     files, no cloud calls, no data leaves the endpoint/hub — this
//     layer is arithmetic over locally stored RMM-01 samples, and
//     the model says so (AnomalyHonesty).
//   * IMMATURE PROFILES ARE SILENT: until a profile has seen
//     MinSamplesForMaturity samples spanning MinLearningSpan, it
//     produces NO anomaly verdict — it reports "still learning".
//     Silence is not safety and a verdict without data is
//     fabrication, so the learning state is a first-class verdict.
//   * POISONING RESISTANCE is the heart of the design (see
//     AnomalyProfileStore.Admit): values observed while an anomaly
//     alert is active for the metric are never learned; once a
//     provisional band exists, values outside it are never learned
//     (trimmed admission); profile recomputation is rate-limited,
//     so teaching the band a new normal takes a named, long time;
//     and every recomputation is kept in a drift history — a
//     material band shift is a surfaced fact, never a silent one.
//   * SEASONALITY, HONESTLY: profiles are AGGREGATE (no weekday /
//     weekend split). A Monday-morning load spike judged against a
//     band learned mostly on a quiet Sunday is the known residual;
//     the mitigations are the maturity floor (a band needs 24h+ of
//     span before it may speak at all) and the sustained-duration
//     rule (a brief spike never alerts). The residual is named in
//     AnomalyHonesty.SeasonalityLimitation, not smoothed over.
//   * CRASH CADENCE is named in the register but is NOT modelled:
//     RMM-01's EndpointSample carries no crash-count reading, and
//     this layer does not invent one. It arrives when a collector
//     honestly supplies it (named remainder).
// =====================================================================

/// <summary>The honesty block: what this feature is and is not,
/// carried in code so any surface can quote it verbatim.</summary>
public static class AnomalyHonesty
{
    public const string Method =
        "on-device robust statistics (median + percentile bands) over locally stored RMM-01 samples; " +
        "no ML model files, no cloud calls, no data leaves the endpoint/hub";
    public const string SeasonalityLimitation =
        "profiles are aggregate over the learning window — weekday/weekend patterns are NOT modelled separately; " +
        "the maturity floor (minimum samples + minimum span) and the sustained-duration rule are the mitigation, " +
        "and a recurring weekly pattern can still alert until the window holds enough of both regimes";
    public const string NotModelled =
        "crash cadence is not modelled: RMM-01 samples carry no crash-count reading and none is invented here";
    public const string LearnedVsDeclared =
        "a learned profile (RMM-27) is what the machine HAS done; a declared baseline (RMM-19) is what an admin " +
        "signed that it SHOULD do. Neither overrides the other; both report into the RMM-01 alert centre.";
}

/// <summary>TOTAL POLICY CONTROL keys for RMM-27. The feature toggle
/// is the RMM-07 registry-seeded key `rmm.anomaly_baselining.enabled`
/// (seeded ON, ManagementPolicy.cs FeatureToggleRegistry). The
/// content keys below are read through Effective Policy by
/// AnomalyPolicyResolver — sensitivity is policy content, per the
/// TOTAL POLICY CONTROL directive.</summary>
public static class AnomalyPolicyKeys
{
    public const string Enabled = "rmm.anomaly_baselining.enabled";
    /// <summary>low | medium | high. Maps to the band factor:
    /// low = wide band (few alerts), high = narrow band.</summary>
    public const string Sensitivity = "rmm.anomaly_detection.sensitivity";
    public const string DefaultSensitivity = "medium";
    /// <summary>Seconds a value must stay outside the band before an
    /// anomaly raises. Default 600; clamped 0..3600. FL-27b / F10
    /// honesty: a sustain of 0 is a legitimate admin choice but it
    /// DISABLES the sustained-duration mitigation the design leans
    /// on ("a brief spike never alerts" is only true while sustain
    /// &gt; 0) — the resolver names that consequence in its Notes
    /// whenever the resolved sustain is 0, instead of the doctrine
    /// quietly contradicting the configuration.</summary>
    public const string SustainSeconds = "rmm.anomaly_detection.sustain_seconds";
    public const int DefaultSustainSeconds = 600;
    public const int MinSustainSeconds = 0;
    public const int MaxSustainSeconds = 3600;
    /// <summary>Severity of anomaly alerts. Default warning;
    /// validated against AlertSeverities.</summary>
    public const string Severity = "rmm.anomaly_detection.severity";
    /// <summary>Per-metric anomaly-alert cooldown in seconds.
    /// Default 1800; clamped 60..86400.</summary>
    public const string CooldownSeconds = "rmm.anomaly_detection.cooldown_seconds";
    public const int DefaultCooldownSeconds = 1800;
    public const int MinCooldownSeconds = 60;
    public const int MaxCooldownSeconds = 86_400;

    public static double BandFactorFor(string? sensitivity) => sensitivity switch
    {
        "low" => 3.0,
        "high" => 1.25,
        _ => 2.0, // medium (and the named default for anything unknown)
    };
}

/// <summary>Named constants of the learning discipline. Every one is
/// a load-bearing honesty or anti-poisoning bound, not a tuning
/// accident — the destruction ledger attacks each of them.</summary>
public static class AnomalyLimits
{
    /// <summary>Samples a profile must hold before it may produce a
    /// verdict at all.</summary>
    public const int MinSamplesForMaturity = 30;
    /// <summary>Minimum time span the learned samples must cover
    /// before maturity — 30 samples in one minute teach nothing
    /// about a machine's normal day.</summary>
    public static readonly TimeSpan MinLearningSpan = TimeSpan.FromHours(24);
    /// <summary>Samples at which a PROVISIONAL band exists. A
    /// provisional band never produces verdicts. (BD-SHARED-RMM-1
    /// F4: trimmed admission no longer engages at this threshold —
    /// it engages at MATURITY; before that only gross outliers
    /// are excluded, so a still-learning profile cannot seal
    /// itself against a legitimate regime change.)</summary>
    public const int ProvisionalSamples = 10;
    /// <summary>Pre-maturity gross-outlier gate, in MAD-sigmas
    /// from the running median (BD-SHARED-RMM-1 F4). Wide enough
    /// that honest regime movement passes, narrow enough that a
    /// poisoning spike cannot teach a still-learning profile.</summary>
    public const double GrossOutlierSigma = 10.0;
    /// <summary>Rolling window admitted samples are kept for.</summary>
    public static readonly TimeSpan LearningWindow = TimeSpan.FromDays(14);
    /// <summary>Hard cap on retained admitted samples per profile —
    /// a refusal-by-drop-oldest bound, counted in the profile's
    /// DroppedForCap counter, never silent.</summary>
    public const int MaxSamplesPerProfile = 5000;
    /// <summary>Minimum interval between profile recomputations.
    /// This is the slow-drift defence's clock: even a perfect
    /// poisoning feed moves the band at most once per hour, and
    /// every move is in the drift history.</summary>
    public static readonly TimeSpan MinProfileUpdateInterval = TimeSpan.FromHours(1);
    /// <summary>Profile snapshots retained per profile (the drift
    /// history). Oldest fall off only past this generous cap.</summary>
    public const int MaxDriftHistoryPerProfile = 128;
    /// <summary>A recomputation whose median moves by more than the
    /// OLD band's full width is a MATERIAL drift: surfaced as a
    /// ProfileDriftNotice + audit event, never silent.</summary>
    public const double MaterialDriftBandWidths = 1.0;
    /// <summary>Per-recompute movement clamp: a recomputation may
    /// move the median and each band edge by at most this fraction
    /// of the OLD band's width. Destruction find (RMM-27 D3):
    /// boundary-inclusive admission let an attacker feeding exactly
    /// the band edge ratchet the percentiles upward geometrically.
    /// With the clamp + the hourly rate limit, teaching the band a
    /// new normal takes a named, long, fully-recorded time — and
    /// every clamped step is flagged on the snapshot.</summary>
    public const double MaxBandMoveFractionPerUpdate = 0.25;
    /// <summary>Minimum half-width of a learned band, as a floor
    /// against degenerate (constant) histories collapsing the band
    /// to a point: max(5% of |median|, 0.5 units).</summary>
    public const double MinHalfWidthFractionOfMedian = 0.05;
    public const double MinHalfWidthAbsolute = 0.5;
    /// <summary>How far ahead of service time an observation may be
    /// dated before it is quarantined (FL-27a / F2). Matches the
    /// house 5-minute future-skew allowance used by import and by
    /// RMM-01 report intake. A feed that dates its values in the
    /// future could otherwise satisfy the sustain rule instantly
    /// and pre-teach tomorrow's band today.</summary>
    public static readonly TimeSpan MaxObservationFutureSkew = TimeSpan.FromMinutes(5);
    /// <summary>FL-27b / F9: hard cap on learned profiles per
    /// device. A feed inventing unbounded distinct targets (one per
    /// process-instance name, say) could otherwise grow the store
    /// without limit — there was NO eviction or cap anywhere. A new
    /// profile beyond the cap is refused by name; existing profiles
    /// are never disturbed by the cap.</summary>
    public const int MaxProfilesPerDevice = 256;
    /// <summary>FL-27b / F9: a profile whose newest admitted sample
    /// is older than this (or which holds no samples) is evicted by
    /// AnomalyProfileStore.EvictStale — comfortably beyond the 14-day
    /// learning window, so eviction only removes profiles whose
    /// admitted history has already fully aged out of the window
    /// and which therefore carry no live learning.</summary>
    public static readonly TimeSpan ProfileIdleEvictionAge = TimeSpan.FromDays(30);
}

/// <summary>The closed set of metrics RMM-27 learns, all honestly
/// extractable from RMM-01's EndpointSample. A metric outside this
/// set is refused at admission — an unknown metric is a field that
/// changes meaning (house fail-closed rule).</summary>
public static class AnomalyMetrics
{
    public const string CpuPercent = "cpu_percent";                    // Target "*"
    public const string RamPercent = "ram_percent";                    // Target "*"
    public const string DiskFreePercent = "disk_free_percent";         // Target = volume name
    public const string ProcessWorkingSetBytes = "process_working_set_bytes"; // Target = process name

    public static readonly IReadOnlySet<string> All = new HashSet<string>
    { CpuPercent, RamPercent, DiskFreePercent, ProcessWorkingSetBytes };
}

/// <summary>Identity of one learned profile: exactly one device,
/// one metric, one target. Device is part of the key BY
/// CONSTRUCTION — device A's profile cannot judge device B because
/// there is no code path that looks one up under another device.</summary>
public sealed record AnomalyProfileKey(string DeviceId, string Metric, string Target)
{
    // FL-27b / F6+F7: identity is normalized ONCE, here at key
    // construction — device and target trimmed, blank target → "*".
    // Previously the record's equality used the RAW strings while
    // ConditionId trimmed/lowercased the target and the service
    // filtered/reported device ids case-insensitively: "C:" and
    // "c:" (or " dev-1 " and "dev-1") were the same condition but
    // DIFFERENT profiles, silently splitting one device's learning
    // in two. Every lookup path (store, service dictionaries,
    // alert-condition matching via ConditionId) now derives from
    // this one normalized identity. Case is PRESERVED (display and
    // ToString keep the caller's casing); cross-case unification
    // happens where the house already does it — the service's
    // OrdinalIgnoreCase device filter and ConditionId's lowercase.
    public string DeviceId { get; init; } = (DeviceId ?? "").Trim();
    public string Metric { get; init; } = (Metric ?? "").Trim();
    public string Target { get; init; } = string.IsNullOrWhiteSpace(Target) ? "*" : Target.Trim();

    public string ConditionId =>
        "anomaly:" + Metric + ":" + Target.ToLowerInvariant();
    public override string ToString() => $"{DeviceId}|{Metric}|{Target}";
}

/// <summary>One numeric observation of one metric on one device at
/// one instant — the unit RMM-01 history feeds this layer.</summary>
public sealed record MetricObservation(string DeviceId, string Metric, string Target, double Value, DateTimeOffset AtUtc)
{
    public AnomalyProfileKey Key => new(DeviceId, Metric, Target);
}

/// <summary>Extracts the honestly-available metric observations from
/// one RMM-01 endpoint sample. A reading the sample does not carry
/// produces NO observation — never a zero, never a guess.</summary>
public static class MetricObservationExtractor
{
    public static IReadOnlyList<MetricObservation> FromSample(EndpointSample s)
    {
        var obs = new List<MetricObservation>();
        if (s.CpuPercent is { } cpu) obs.Add(new MetricObservation(s.DeviceId, AnomalyMetrics.CpuPercent, "*", cpu, s.AtUtc));
        if (s.RamPercent is { } ram) obs.Add(new MetricObservation(s.DeviceId, AnomalyMetrics.RamPercent, "*", ram, s.AtUtc));
        foreach (var d in s.Disks)
            if (d.FreePercent is { } free) obs.Add(new MetricObservation(s.DeviceId, AnomalyMetrics.DiskFreePercent, d.Name, free, s.AtUtc));
        // FL-27b / F6: process observations are AGGREGATED per
        // process name (trimmed, case-insensitive) into ONE
        // observation carrying the summed working set. Previously
        // the extractor emitted one observation per ProcessSample,
        // so a process with several instances produced several
        // competing observations for the same profile key in the
        // same instant — the profile learned whichever arrived
        // last, not the process's actual footprint.
        foreach (var g in s.Processes.GroupBy(
                     p => (p.Name ?? "").Trim(), StringComparer.OrdinalIgnoreCase))
            obs.Add(new MetricObservation(s.DeviceId, AnomalyMetrics.ProcessWorkingSetBytes,
                g.Key, g.Sum(p => (double)p.WorkingSetBytes), s.AtUtc));
        return obs;
    }
}

// ---- robust statistics -------------------------------------------------

/// <summary>Robust statistics over a sample set: median and
/// percentiles by linear interpolation on the sorted values. No
/// means anywhere in this layer.</summary>
public static class RobustStats
{
    public static double Percentile(IReadOnlyList<double> sortedAscending, double p)
    {
        if (sortedAscending.Count == 0) return double.NaN;
        if (sortedAscending.Count == 1) return sortedAscending[0];
        var rank = p / 100.0 * (sortedAscending.Count - 1);
        var lo = (int)Math.Floor(rank);
        var hi = (int)Math.Ceiling(rank);
        if (lo == hi) return sortedAscending[lo];
        var frac = rank - lo;
        return sortedAscending[lo] + (sortedAscending[hi] - sortedAscending[lo]) * frac;
    }

    /// <summary>Median absolute deviation, scaled to a
    /// normal-equivalent sigma (×1.4826). Used by pre-maturity
    /// gross-outlier exclusion (BD-SHARED-RMM-1 F4).</summary>
    public static double MadSigma(IReadOnlyList<double> values)
    {
        if (values.Count == 0) return 0;
        var sorted = values.OrderBy(v => v).ToList();
        var median = Percentile(sorted, 50);
        var deviations = values.Select(v => Math.Abs(v - median)).OrderBy(v => v).ToList();
        return 1.4826 * Percentile(deviations, 50);
    }

    /// <summary>Compute the band for a value set at a band factor.
    /// Band = median ± factor × (percentile spread), with the
    /// MinHalfWidth floor so a constant history still yields a band
    /// of non-zero width (a point band would alert on ANY change,
    /// including honest noise).</summary>
    public static (double Median, double P05, double P95, double BandLow, double BandHigh) Band(
        IReadOnlyList<double> values, double bandFactor)
    {
        var sorted = values.OrderBy(v => v).ToList();
        var median = Percentile(sorted, 50);
        var p05 = Percentile(sorted, 5);
        var p95 = Percentile(sorted, 95);
        var floor = Math.Max(Math.Abs(median) * AnomalyLimits.MinHalfWidthFractionOfMedian,
                             AnomalyLimits.MinHalfWidthAbsolute);
        var halfLow = Math.Max(median - p05, floor) * bandFactor;
        var halfHigh = Math.Max(p95 - median, floor) * bandFactor;
        return (median, p05, p95, median - halfLow, median + halfHigh);
    }
}

// ---- profiles ------------------------------------------------------------

/// <summary>One computed learned profile: the robust statistics of
/// the admitted history, the band, and the maturity facts. Maturity
/// is COMPUTED from SampleCount + Span — it is never a stored flag
/// an importer or caller can simply assert (see the store's import
/// discipline).</summary>
public sealed record LearnedProfile(
    AnomalyProfileKey Key,
    int SampleCount,
    DateTimeOffset FirstSampleUtc,
    DateTimeOffset LastSampleUtc,
    double Median,
    double P05,
    double P95,
    double BandLow,
    double BandHigh,
    double BandFactor,
    DateTimeOffset ComputedUtc,
    long Revision)
{
    public TimeSpan Span => SampleCount > 0 ? LastSampleUtc - FirstSampleUtc : TimeSpan.Zero;

    public bool IsMature =>
        SampleCount >= AnomalyLimits.MinSamplesForMaturity && Span >= AnomalyLimits.MinLearningSpan;

    /// <summary>Why this profile is (not) mature, in numbers — the
    /// "still learning" report a surface shows instead of silence.</summary>
    public string MaturityReport => IsMature
        ? $"mature: {SampleCount} samples spanning {Span.TotalHours:F1}h"
        : $"still learning: {SampleCount}/{AnomalyLimits.MinSamplesForMaturity} samples, " +
          $"span {Span.TotalHours:F1}h/{AnomalyLimits.MinLearningSpan.TotalHours:F0}h — no anomaly verdicts until mature";
}

/// <summary>One entry in a profile's drift history: the band as
/// computed at one recomputation. The history is the slow-drift
/// attack's visibility — the band's own movement is a kept fact.</summary>
public sealed record ProfileSnapshot(
    DateTimeOffset ComputedUtc, long Revision, int SampleCount,
    double Median, double BandLow, double BandHigh, bool WasMaterialDrift,
    bool MoveClamped = false);

/// <summary>A material band shift, surfaced by a recomputation:
/// the old and new medians and bands, in numbers. Profile drift is
/// a reportable fact, not a silent slide.</summary>
public sealed record ProfileDriftNotice(
    AnomalyProfileKey Key, DateTimeOffset AtUtc,
    double OldMedian, double NewMedian, double OldBandLow, double OldBandHigh,
    double NewBandLow, double NewBandHigh, string Detail);

/// <summary>Why an observation was or was not learned.</summary>
public static class AdmissionOutcomes
{
    public const string Admitted = "admitted";
    public const string ExcludedUnderActiveAlert = "excluded_under_active_alert";
    public const string ExcludedOutsideBand = "excluded_outside_band";
    public const string RefusedUnknownMetric = "refused_unknown_metric";
    public const string RefusedBadValue = "refused_bad_value";
    /// <summary>FL-27a / F2: observation dated beyond the future-skew
    /// allowance ahead of service time — quarantined by the service
    /// (never judged, never learned).</summary>
    public const string RefusedFutureDated = "refused_future_dated";
    /// <summary>FL-27a / F2: observation older than the newest
    /// admitted sample for its profile — a replayed or backdated
    /// value must not rewind the learning window or the sustain
    /// clock.</summary>
    public const string RefusedStaleTimestamp = "refused_stale_timestamp";
    /// <summary>FL-27b / F9: the device already holds the maximum
    /// number of learned profiles — a NEW profile is refused rather
    /// than letting target-invention grow the store without bound.</summary>
    public const string RefusedProfileCap = "refused_profile_cap";
}

public sealed record AdmissionResult(string Outcome, string Detail);

// ---- the profile store ---------------------------------------------------

/// <summary>The learned-profile store: admitted history, profiles,
/// drift history, per-profile exclusion counters. Thread-safe; all
/// state moves under one gate.
///
/// ADMISSION (the poisoning defences, in order):
///  1. Unknown metric / non-finite value → refused outright.
///  2. Caller-flagged "under active alert for this metric" →
///     excluded (an alerting period never teaches the band).
///  3. Once a provisional band exists (≥ ProvisionalSamples),
///     a value outside the FROZEN admission range → excluded
///     (trimmed admission: the band cannot be taught by the very
///     values it would flag; FL-27a/F1 — the range is a frozen
///     snapshot refreshed only at recomputation, never recomputed
///     live from the admitted list it gates).
///  3b. A value older than the newest admitted sample → refused
///     (FL-27a/F2 stale-timestamp discipline).
///  4. Otherwise admitted into the rolling window.
/// RECOMPUTATION is rate-limited (MinProfileUpdateInterval of
/// observation time) and every recomputation appends a drift
/// snapshot; a material shift yields a ProfileDriftNotice.</summary>
public sealed class AnomalyProfileStore
{
    private sealed class ProfileState
    {
        public List<MetricObservation> Admitted = new();
        public LearnedProfile? Profile;
        public List<ProfileSnapshot> History = new();
        public DateTimeOffset? LastRecomputeUtc;
        public long Revision;
        public int ExcludedUnderAlert;
        public int ExcludedOutsideBand;
        public int DroppedForCap;
        public int RefusedStale;
        // FL-27a / F1: the FROZEN admission range. Admission is judged
        // against this snapshot — set at the first provisional freeze
        // and refreshed ONLY by a (rate-limited, movement-clamped)
        // recomputation — never against statistics recomputed live
        // from s.Admitted, which includes the attacker's own just-
        // admitted values and ratcheted edge-by-edge (D38 F1; the
        // DG-R27-01 fix bounded the factored band, not this range).
        public double? FrozenAdmitLow;
        public double? FrozenAdmitHigh;
    }

    private readonly Dictionary<AnomalyProfileKey, ProfileState> _byKey = new();
    private readonly object _gate = new();

    public IReadOnlyList<AnomalyProfileKey> Keys
    {
        get { lock (_gate) return _byKey.Keys.OrderBy(k => k.ToString(), StringComparer.Ordinal).ToList(); }
    }

    public LearnedProfile? GetProfile(AnomalyProfileKey key)
    {
        lock (_gate) return _byKey.TryGetValue(key, out var s) ? s.Profile : null;
    }

    public IReadOnlyList<ProfileSnapshot> DriftHistory(AnomalyProfileKey key)
    {
        lock (_gate) return _byKey.TryGetValue(key, out var s) ? s.History.ToList() : Array.Empty<ProfileSnapshot>();
    }

    /// <summary>Per-profile exclusion counters — the poisoning
    /// attempts are counted facts, visible to any surface.</summary>
    public (int UnderAlert, int OutsideBand, int DroppedForCap, int Admitted) Counters(AnomalyProfileKey key)
    {
        lock (_gate)
            return _byKey.TryGetValue(key, out var s)
                ? (s.ExcludedUnderAlert, s.ExcludedOutsideBand, s.DroppedForCap, s.Admitted.Count)
                : (0, 0, 0, 0);
    }

    /// <summary>FL-27a / F2: stale-timestamp refusals for one
    /// profile, counted like every other exclusion channel.</summary>
    public int StaleRefusals(AnomalyProfileKey key)
    {
        lock (_gate) return _byKey.TryGetValue(key, out var s) ? s.RefusedStale : 0;
    }

    /// <summary>The frozen admission range currently in force for a
    /// profile (null until the provisional freeze) — the range
    /// admission is actually judged against, exposed so a surface
    /// can show the real gate instead of a recomputed fiction.</summary>
    public (double Low, double High)? FrozenAdmissionRange(AnomalyProfileKey key)
    {
        lock (_gate)
            return _byKey.TryGetValue(key, out var s) && s.FrozenAdmitLow is { } lo && s.FrozenAdmitHigh is { } hi
                ? (lo, hi) : null;
    }

    /// <param name="serviceNow">FL-27a / F2: the service's clock for
    /// this admission, when the caller has one — the rolling-window
    /// cutoff runs on service time, not on the observation's own
    /// (caller-supplied) timestamp. Defaults to the observation time
    /// for direct store callers.</param>
    public AdmissionResult Admit(MetricObservation obs, bool underActiveAlert, double bandFactor,
        DateTimeOffset? serviceNow = null)
    {
        if (obs is null || string.IsNullOrWhiteSpace(obs.DeviceId) || string.IsNullOrWhiteSpace(obs.Metric))
            return new AdmissionResult(AdmissionOutcomes.RefusedBadValue, "observation carries no device/metric — refused");
        if (!AnomalyMetrics.All.Contains(obs.Metric))
            return new AdmissionResult(AdmissionOutcomes.RefusedUnknownMetric,
                $"metric '{obs.Metric}' is not a learned metric — refused (an unknown metric is a field that changes meaning)");
        if (double.IsNaN(obs.Value) || double.IsInfinity(obs.Value))
            return new AdmissionResult(AdmissionOutcomes.RefusedBadValue,
                $"value for {obs.Metric} is not finite — refused (a NaN learned into a band would poison every later verdict)");

        lock (_gate)
        {
            if (!_byKey.TryGetValue(obs.Key, out var s))
            {
                // FL-27b / F9: per-device profile cap. Without it a
                // feed inventing distinct targets grew _byKey (and
                // every service dictionary keyed by profile) without
                // bound — there was no eviction anywhere.
                var deviceProfiles = _byKey.Keys.Count(k =>
                    string.Equals(k.DeviceId, obs.Key.DeviceId, StringComparison.OrdinalIgnoreCase));
                if (deviceProfiles >= AnomalyLimits.MaxProfilesPerDevice)
                    return new AdmissionResult(AdmissionOutcomes.RefusedProfileCap,
                        $"device '{obs.Key.DeviceId}' already holds {deviceProfiles} learned profiles (cap {AnomalyLimits.MaxProfilesPerDevice}) — new profile for {obs.Key.Metric}/{obs.Key.Target} refused (profile growth is bounded; stale profiles are evicted by EvictStale and an admin may rebaseline)");
                _byKey[obs.Key] = s = new ProfileState();
            }

            // FL-27a / F2: stale-timestamp refusal. A value older
            // than the newest admitted sample is a replay or a
            // backdated injection: admitting it would rewind the
            // learning window and corrupt the sample span maturity
            // is computed from. Refused and counted.
            if (s.Admitted.Count > 0)
            {
                var newest = s.Admitted.Max(a => a.AtUtc);
                if (obs.AtUtc < newest)
                {
                    s.RefusedStale++;
                    return new AdmissionResult(AdmissionOutcomes.RefusedStaleTimestamp,
                        $"value at {obs.AtUtc:O} is older than the newest admitted sample at {newest:O} — refused (stale/replayed timestamps never rewind learning)");
                }
            }

            if (underActiveAlert)
            {
                s.ExcludedUnderAlert++;
                return new AdmissionResult(AdmissionOutcomes.ExcludedUnderActiveAlert,
                    "value observed while an anomaly alert is active for this metric — excluded from learning (alert periods never teach the band)");
            }

            // Trimmed admission against the FROZEN range (FL-27a /
            // F1): once a provisional profile can be computed, only
            // values within the frozen percentile spread (P05..P95
            // of the frozen snapshot, plus the min-half-width floor
            // of slack) are learned. This is stricter than the
            // detection band on purpose (destruction find RMM-27
            // D3): under a factored-band admission, values fed at
            // the band edge ratcheted the percentiles upward without
            // bound. The D38 F1 finding was the remaining half of
            // that ratchet: the spread itself was recomputed LIVE
            // from s.Admitted on every Admit, so each just-admitted
            // edge value widened the range for the next one, edge by
            // edge, with no cumulative cap. The range is now frozen
            // at the provisional freeze and refreshed only by a
            // recomputation — which is rate-limited (1h) and whose
            // percentile movement is clamped per update — so the
            // teachable range can move at most the clamped step per
            // hour, every step in the drift history. (Freezing also
            // removes the per-Admit full sort of the admitted list:
            // the range is cached, not recomputed — D38 F8's cost
            // on this path.)
            if (s.Admitted.Count >= AnomalyLimits.ProvisionalSamples)
            {
                // BD-SHARED-RMM-1 F4: the frozen trim previously
                // engaged at the PROVISIONAL threshold (10 samples)
                // — long before maturity (30 samples over 24h).
                // A metric whose regime legitimately changed after
                // its first quiet samples (a disk that fills, a
                // service that starts working) could then NEVER be
                // learned: every new-regime value fell outside the
                // frozen range and was excluded, forever — the
                // profile self-sealed. The frozen trim now engages
                // only once the profile is MATURE by the model's
                // own criteria (MinSamplesForMaturity over
                // MinLearningSpan, computed from the admitted
                // history). Before maturity, admission excludes
                // only GROSS outliers (beyond GrossOutlierSigma ×
                // MAD-sigma from the median) — poisoning spikes
                // still cannot teach, honest regime changes can.
                var span = s.Admitted.Max(a => a.AtUtc) - s.Admitted.Min(a => a.AtUtc);
                var mature = s.Admitted.Count >= AnomalyLimits.MinSamplesForMaturity &&
                             span >= AnomalyLimits.MinLearningSpan;
                if (!mature)
                {
                    var values = s.Admitted.Select(a => a.Value).ToList();
                    var sorted = values.OrderBy(v => v).ToList();
                    var med = RobustStats.Percentile(sorted, 50);
                    var sigma = Math.Max(RobustStats.MadSigma(values),
                        Math.Max(Math.Abs(med) * AnomalyLimits.MinHalfWidthFractionOfMedian,
                                 AnomalyLimits.MinHalfWidthAbsolute));
                    if (Math.Abs(obs.Value - med) > AnomalyLimits.GrossOutlierSigma * sigma)
                    {
                        s.ExcludedOutsideBand++;
                        return new AdmissionResult(AdmissionOutcomes.ExcludedOutsideBand,
                            $"value {obs.Value:F2} is a gross outlier for a still-learning profile (median {med:F2}, MAD-sigma {sigma:F2}, gate {AnomalyLimits.GrossOutlierSigma}σ) — excluded from learning; ordinary regime movement is admitted until the profile matures");
                    }
                }
                else
                {
                    if (s.FrozenAdmitLow is null || s.FrozenAdmitHigh is null)
                    {
                        var (fMedian, fP05, fP95, _, _) = RobustStats.Band(
                            s.Admitted.Select(a => a.Value).ToList(), bandFactor);
                        var fFloor = Math.Max(Math.Abs(fMedian) * AnomalyLimits.MinHalfWidthFractionOfMedian,
                                              AnomalyLimits.MinHalfWidthAbsolute);
                        s.FrozenAdmitLow = fP05 - fFloor;
                        s.FrozenAdmitHigh = fP95 + fFloor;
                    }
                    var admitLow = s.FrozenAdmitLow.Value;
                    var admitHigh = s.FrozenAdmitHigh.Value;
                    if (obs.Value < admitLow || obs.Value > admitHigh)
                    {
                        s.ExcludedOutsideBand++;
                        return new AdmissionResult(AdmissionOutcomes.ExcludedOutsideBand,
                            $"value {obs.Value:F2} outside the frozen trimmed admission range [{admitLow:F2}, {admitHigh:F2}] (frozen learned p05..p95 plus floor slack, refreshed only at recomputation) — excluded from learning (trimmed admission)");
                    }
                }
            }

            s.Admitted.Add(obs);
            // Rolling window + cap. FL-27a / F2: the window cutoff
            // runs on SERVICE time when the caller supplies it, not
            // on the observation's own timestamp.
            var cutoff = (serviceNow ?? obs.AtUtc) - AnomalyLimits.LearningWindow;
            s.Admitted.RemoveAll(a => a.AtUtc < cutoff);
            // FL-27a / F1: the moment the provisional threshold is
            // reached, freeze the admission range from the history
            // as it stands — the range exists exactly when the
            // provisional band exists, not from the next call on.
            // BD-SHARED-RMM-1 F4: the freeze now waits for
            // MATURITY — a range frozen from the first provisional
            // samples would be the self-sealing range the F4 fix
            // removed from the admission path.
            if (s.Admitted.Count >= AnomalyLimits.MinSamplesForMaturity &&
                s.Admitted.Max(a => a.AtUtc) - s.Admitted.Min(a => a.AtUtc) >= AnomalyLimits.MinLearningSpan &&
                (s.FrozenAdmitLow is null || s.FrozenAdmitHigh is null))
            {
                var (eMedian, eP05, eP95, _, _) = RobustStats.Band(
                    s.Admitted.Select(a => a.Value).ToList(), bandFactor);
                var eFloor = Math.Max(Math.Abs(eMedian) * AnomalyLimits.MinHalfWidthFractionOfMedian,
                                      AnomalyLimits.MinHalfWidthAbsolute);
                s.FrozenAdmitLow = eP05 - eFloor;
                s.FrozenAdmitHigh = eP95 + eFloor;
            }
            if (s.Admitted.Count > AnomalyLimits.MaxSamplesPerProfile)
            {
                var excess = s.Admitted.Count - AnomalyLimits.MaxSamplesPerProfile;
                s.Admitted = s.Admitted.OrderBy(a => a.AtUtc).Skip(excess).ToList();
                s.DroppedForCap += excess;
            }
            return new AdmissionResult(AdmissionOutcomes.Admitted, "admitted to learning history");
        }
    }

    /// <summary>Recompute the profile for a key, if the rate limit
    /// allows (or `force` — used by import verification and tests of
    /// the discipline itself; the service never forces). Returns
    /// the profile (possibly unchanged) and any material-drift
    /// notice. A recomputation with no admitted samples is a no-op.</summary>
    public (LearnedProfile? Profile, ProfileDriftNotice? Drift, bool RateLimited) Recompute(
        AnomalyProfileKey key, DateTimeOffset now, double bandFactor, bool force = false)
    {
        lock (_gate)
        {
            if (!_byKey.TryGetValue(key, out var s) || s.Admitted.Count == 0)
                return (s?.Profile, null, false);
            if (!force && s.LastRecomputeUtc is { } last && now - last < AnomalyLimits.MinProfileUpdateInterval)
                return (s.Profile, null, true);

            var values = s.Admitted.Select(a => a.Value).ToList();
            var (rawMedian, p05, p95, rawLow, rawHigh) = RobustStats.Band(values, bandFactor);
            var old = s.Profile;
            var revision = ++s.Revision;

            // Movement clamp (destruction find RMM-27 D3): against
            // an existing profile, the median and each band edge may
            // move at most MaxBandMoveFractionPerUpdate of the old
            // band width per recomputation. A genuine regime change
            // still moves the band — slowly, at the rate limit, with
            // every step in the drift history — and a poisoning feed
            // faces the same arithmetic.
            var median = rawMedian; var low = rawLow; var high = rawHigh;
            var p05c = p05; var p95c = p95;
            var clamped = false;
            ProfileDriftNotice? drift = null;
            var material = false;
            if (old is not null)
            {
                var oldWidth = old.BandHigh - old.BandLow;
                var maxMove = oldWidth * AnomalyLimits.MaxBandMoveFractionPerUpdate;
                double ClampMove(double raw, double oldValue)
                {
                    var moved = Math.Clamp(raw, oldValue - maxMove, oldValue + maxMove);
                    if (moved != raw) clamped = true;
                    return moved;
                }
                median = ClampMove(rawMedian, old.Median);
                low = ClampMove(rawLow, old.BandLow);
                high = ClampMove(rawHigh, old.BandHigh);
                // FL-27a / F1+F4: the percentiles are clamped with
                // the same per-update bound. They were previously
                // stored RAW while the median was clamped, so the
                // profile's own statistics disagreed with each other
                // (and with any honest recomputation) whenever the
                // clamp bit.
                p05c = ClampMove(p05, old.P05);
                p95c = ClampMove(p95, old.P95);
                var shift = Math.Abs(rawMedian - old.Median);
                if (shift > oldWidth * AnomalyLimits.MaterialDriftBandWidths)
                {
                    material = true;
                    drift = new ProfileDriftNotice(key, now, old.Median, median,
                        old.BandLow, old.BandHigh, low, high,
                        $"profile median would move {old.Median:F2} → {rawMedian:F2} (shift {shift:F2} > old band width {oldWidth:F2}) — " +
                        $"a material band shift is a reportable fact, surfaced here and in the audit chain, never silent" +
                        (clamped ? $"; the applied movement is clamped to {maxMove:F2} per update (the per-update bound), so the band follows a regime change slowly and visibly, by design" : ""));
                }
            }
            var profile = new LearnedProfile(
                key, s.Admitted.Count,
                s.Admitted.Min(a => a.AtUtc), s.Admitted.Max(a => a.AtUtc),
                median, p05c, p95c, low, high, bandFactor, now, revision);
            s.Profile = profile;
            s.LastRecomputeUtc = now;
            // FL-27a / F1: refresh the frozen admission range from
            // the CLAMPED percentiles of this recomputation. This is
            // the only post-freeze path that moves the range, so
            // cumulative admission-range growth is capped by the
            // per-update movement clamp at the hourly rate limit.
            var frozenFloor = Math.Max(Math.Abs(median) * AnomalyLimits.MinHalfWidthFractionOfMedian,
                                       AnomalyLimits.MinHalfWidthAbsolute);
            s.FrozenAdmitLow = p05c - frozenFloor;
            s.FrozenAdmitHigh = p95c + frozenFloor;
            s.History.Add(new ProfileSnapshot(now, revision, profile.SampleCount, median, low, high, material, clamped));
            if (s.History.Count > AnomalyLimits.MaxDriftHistoryPerProfile)
                s.History.RemoveRange(0, s.History.Count - AnomalyLimits.MaxDriftHistoryPerProfile);
            return (profile, drift, false);
        }
    }

    // ---- export / import (claim-checked, NOT authenticated) --------------

    /// <summary>The export shape: the profile PLUS the admitted
    /// samples it was computed from. Stats without samples are not
    /// exportable — an export that could assert maturity without
    /// evidence would be a forgery kit. FL-27a / F4: the claimed
    /// statistics are recomputed from the CURRENT admitted samples
    /// at export time — NOT copied from the stored profile, whose
    /// statistics are movement-clamped and as-of the last
    /// recomputation. Copying the profile's claims while sending
    /// the current samples made every honest round-trip whose
    /// profile had ever been clamped (or had learned since its last
    /// recomputation) fail the importer's claim check.</summary>
    public sealed record ProfileExport(
        string DeviceId, string Metric, string Target,
        IReadOnlyList<ExportedSample> Samples,
        double ClaimedMedian, double ClaimedP05, double ClaimedP95,
        int ClaimedSampleCount)
    {
        public IReadOnlyList<ExportedSample> Samples { get; init; } = Samples ?? Array.Empty<ExportedSample>();
    }

    public sealed record ExportedSample(double Value, DateTimeOffset AtUtc);

    public ProfileExport? Export(AnomalyProfileKey key, double bandFactor)
    {
        lock (_gate)
        {
            if (!_byKey.TryGetValue(key, out var s) || s.Profile is null || s.Admitted.Count == 0) return null;
            var samples = s.Admitted.OrderBy(a => a.AtUtc)
                .Select(a => new ExportedSample(a.Value, a.AtUtc)).ToList();
            // Claims recomputed RAW from exactly the samples being
            // sent (FL-27a / F4): the importer's check recomputes
            // the same statistics from the same samples, so an
            // honest export verifies by construction.
            var (median, p05, p95, _, _) = RobustStats.Band(samples.Select(x => x.Value).ToList(), bandFactor);
            return new ProfileExport(key.DeviceId, key.Metric, key.Target,
                samples, median, p05, p95, samples.Count);
        }
    }

    /// <summary>Import a profile export, hardened per FL-27a / F3:
    ///  * DEVICE BINDING: the export's device must equal
    ///    <paramref name="authorizedDeviceId"/> — the device the
    ///    caller is authorized to import for. An export for another
    ///    device is refused, never silently re-homed.
    ///  * The claimed statistics are NEVER trusted: stats and
    ///    maturity are recomputed from the embedded samples, and
    ///    any mismatch between claim and recomputation refuses the
    ///    import whole. This is an INTEGRITY check only — exports
    ///    are not signed or MAC'd, so it proves the export is
    ///    self-consistent, not that it is authentic.
    ///  * MERGE, never wholesale replace: samples are merged into
    ///    the profile's existing admitted history (exact
    ///    time+value duplicates dropped), then the SAME rolling
    ///    window and per-profile cap admission applies are applied,
    ///    with trimmed/dropped counts named in the result.
    ///  * NO RATE-LIMIT BYPASS: an import inside
    ///    MinProfileUpdateInterval of the profile's last
    ///    recomputation is refused whole BEFORE any mutation, and
    ///    the post-merge recomputation runs unforced — its result
    ///    is movement-clamped against the existing profile like
    ///    any other recomputation.</summary>
    public (bool Accepted, string Reason) Import(ProfileExport export, DateTimeOffset now, double bandFactor,
        string authorizedDeviceId, string? actor = null)
    {
        if (export is null) return (false, "no export — refused");
        if (string.IsNullOrWhiteSpace(export.DeviceId) || !AnomalyMetrics.All.Contains(export.Metric ?? ""))
            return (false, "export names no device or an unknown metric — refused");
        if (string.IsNullOrWhiteSpace(authorizedDeviceId) ||
            !string.Equals(export.DeviceId, authorizedDeviceId, StringComparison.OrdinalIgnoreCase))
            return (false, $"export is for device '{export.DeviceId}' but the import is authorized for '{authorizedDeviceId}' — refused (import is bound to the authorized device)");
        if (export.Samples.Count == 0)
            return (false, "export carries no samples — refused (maturity without evidence is forgery)");
        if (export.ClaimedSampleCount != export.Samples.Count)
            return (false, $"export claims {export.ClaimedSampleCount} samples but carries {export.Samples.Count} — refused (claim and evidence disagree)");
        foreach (var smp in export.Samples)
        {
            if (double.IsNaN(smp.Value) || double.IsInfinity(smp.Value))
                return (false, "export carries a non-finite sample — refused");
            if (smp.AtUtc > now.Add(AnomalyLimits.MaxObservationFutureSkew))
                return (false, "export carries a future-dated sample beyond the skew allowance — refused");
        }
        var (median, p05, p95, _, _) = RobustStats.Band(export.Samples.Select(x => x.Value).ToList(), bandFactor);
        bool Close(double a, double b) => Math.Abs(a - b) <= Math.Max(1e-9, Math.Abs(a) * 1e-9);
        if (!Close(median, export.ClaimedMedian) || !Close(p05, export.ClaimedP05) || !Close(p95, export.ClaimedP95))
            return (false, $"export's claimed statistics (median {export.ClaimedMedian:F4}, p05 {export.ClaimedP05:F4}, p95 {export.ClaimedP95:F4}) " +
                           $"do not match recomputation from its samples (median {median:F4}, p05 {p05:F4}, p95 {p95:F4}) — refused (self-inconsistent export; the claim check is an integrity check, not authentication)");

        var key = new AnomalyProfileKey(export.DeviceId, export.Metric, export.Target ?? "*");
        int merged, duplicates, trimmedForWindow, droppedForCap, excludedOutsideBand;
        LearnedProfile? profile;
        // BD-SHARED-RMM-1 F5: merge and recomputation now run
        // under ONE lock. Previously the lock was released between
        // them and the post-merge recompute could refuse on the
        // rate limit — Import then reported "refused" AFTER the
        // samples had already mutated the profile. The rate-limit
        // pre-check below still refuses BEFORE any mutation; the
        // recompute inside the same lock (the store lock is
        // reentrant) cannot race another writer into a refusal.
        lock (_gate)
        {
            if (!_byKey.TryGetValue(key, out var s))
            {
                // F5: the per-device profile cap applies to
                // imports too — Import previously created profiles
                // with no MaxProfilesPerDevice check at all.
                var deviceProfiles = _byKey.Keys.Count(k =>
                    string.Equals(k.DeviceId, export.DeviceId, StringComparison.OrdinalIgnoreCase));
                if (deviceProfiles >= AnomalyLimits.MaxProfilesPerDevice)
                    return (false, $"device '{export.DeviceId}' already holds {deviceProfiles} learned profiles (cap {AnomalyLimits.MaxProfilesPerDevice}) — import refused (profile growth is bounded)");
                _byKey[key] = s = new ProfileState();
            }
            // No rate-limit bypass (checked before ANY mutation):
            // an import may not force the band to move faster than
            // the recomputation discipline allows live learning to.
            if (s.LastRecomputeUtc is { } last && now - last < AnomalyLimits.MinProfileUpdateInterval)
                return (false, $"profile for {key} was recomputed at {last:O}, inside the minimum update interval — import refused whole (import does not bypass the recomputation rate limit; retry after {last + AnomalyLimits.MinProfileUpdateInterval:O})");

            // BD-SHARED-RMM-1 F5, reconciled: the finding asked
            // for imported samples to be judged against the
            // frozen admission range. That judgement was built
            // and then REMOVED on evidence: it broke the designed
            // import channel (RMM-27 F1/F3/F4) — imports are the
            // bulk-history path, and their poisoning defences are
            // the ones that path was designed with: the claim
            // check above (an export whose claimed statistics do
            // not recompute from its own samples refuses whole),
            // the recomputation rate limit (checked before any
            // mutation, below), and the per-recompute movement
            // CLAMP — an import into an existing profile moves
            // its band by at most the clamped step, with the move
            // recorded in the drift history (a fresh profile has
            // nothing to poison but itself). Judging bulk samples
            // by the live frozen band made honest regime imports
            // (the channel's purpose) impossible while adding no
            // bound the clamp does not already give. F5's other
            // limbs stand as fixed: the profile cap (above), the
            // single critical section, and the service-time
            // window cutoff (below).
            var seen = new HashSet<(DateTimeOffset, double)>(s.Admitted.Select(a => (a.AtUtc, a.Value)));
            var added = new List<MetricObservation>();
            duplicates = 0; excludedOutsideBand = 0;
            foreach (var x in export.Samples.OrderBy(x => x.AtUtc))
            {
                if (!seen.Add((x.AtUtc, x.Value))) { duplicates++; continue; }
                added.Add(new MetricObservation(export.DeviceId, export.Metric, export.Target ?? "*", x.Value, x.AtUtc));
            }
            var all = s.Admitted.Concat(added).OrderBy(a => a.AtUtc).ToList();
            // The admission window + cap, applied to the merged
            // history exactly as live admission applies them.
            // F5: the window cutoff runs on SERVICE time (the
            // import's `now`), not on the newest imported sample —
            // a backdated export previously defined its own window.
            var cutoff = now - AnomalyLimits.LearningWindow;
            trimmedForWindow = all.Count(a => a.AtUtc < cutoff);
            all.RemoveAll(a => a.AtUtc < cutoff);
            droppedForCap = 0;
            if (all.Count > AnomalyLimits.MaxSamplesPerProfile)
            {
                droppedForCap = all.Count - AnomalyLimits.MaxSamplesPerProfile;
                all = all.Skip(droppedForCap).ToList();
                s.DroppedForCap += droppedForCap;
            }
            merged = added.Count; // samples actually merged in (duplicates already excluded)
            s.Admitted = all;
            s.FrozenAdmitLow = null; // refreshed by the recomputation below
            s.FrozenAdmitHigh = null;
            var (recomputed, _, rateLimited) = Recompute(key, now, bandFactor, force: false);
            if (rateLimited || recomputed is null)
                return (false, $"import for {key} could not recompute without bypassing the rate limit — refused");
            profile = recomputed;
        }
        return (true, $"profile imported for {key} by {(string.IsNullOrWhiteSpace(actor) ? "unnamed actor" : actor)}: " +
                      $"{merged} new samples merged into existing history ({duplicates} exact duplicates skipped, " +
                      $"{trimmedForWindow} trimmed by the learning window, {droppedForCap} dropped for the per-profile cap); " +
                      $"profile now {profile.SampleCount} samples, {profile.MaturityReport} — maturity recomputed from samples, never taken from the export's claim; " +
                      $"claims verified by recomputation (integrity check only — exports are unsigned, this is not authentication)");
    }

    /// <summary>Total learned profiles currently held (all devices).</summary>
    public int ProfileCount { get { lock (_gate) return _byKey.Count; } }

    /// <summary>FL-27b / F9 — eviction: remove every profile whose
    /// newest admitted sample is older than
    /// AnomalyLimits.ProfileIdleEvictionAge (or which holds no
    /// samples at all). The age is set well beyond the 14-day
    /// learning window, so an evicted profile's history had already
    /// aged out of the window — eviction discards no live learning,
    /// it stops dead profiles (renamed disks, vanished processes,
    /// decommissioned targets) accumulating forever. Returns the
    /// number evicted; the service runs this each cycle.</summary>
    public int EvictStale(DateTimeOffset now)
    {
        lock (_gate)
        {
            var cutoff = now - AnomalyLimits.ProfileIdleEvictionAge;
            var stale = _byKey
                .Where(kv => kv.Value.Admitted.Count == 0 ||
                             kv.Value.Admitted.Max(a => a.AtUtc) < cutoff)
                .Select(kv => kv.Key).ToList();
            foreach (var k in stale) _byKey.Remove(k);
            return stale.Count;
        }
    }

    /// <summary>FL-27a / F5 — admin rebaseline: clear one profile's
    /// learned state entirely (admitted history, profile, drift
    /// history, frozen range, counters) so a genuine regime change
    /// can be learned fresh. Without this path a regime change was
    /// UNLEARNABLE on the observation path: trimmed admission
    /// excludes the new regime's values forever. The service wraps
    /// this with policy gating, a named actor, alert reset, and an
    /// audit event — the store-level act is deliberately bare.</summary>
    public (bool Existed, int SamplesCleared) Rebaseline(AnomalyProfileKey key)
    {
        lock (_gate)
        {
            if (!_byKey.TryGetValue(key, out var s)) return (false, 0);
            var cleared = s.Admitted.Count;
            _byKey.Remove(key);
            return (true, cleared);
        }
    }
}

// ---- verdicts --------------------------------------------------------------

public static class AnomalyVerdicts
{
    /// <summary>No profile / profile immature: NO verdict is
    /// produced — the evaluation reports the learning state.</summary>
    public const string Learning = "learning";
    public const string InsideBand = "inside_band";
    public const string OutsideBand = "outside_band";
}

/// <summary>One evaluation of one observed value against its
/// profile. OutsideBand carries the full numeric evidence (observed,
/// band, median, maturity, sample count) — the alert built from it
/// explains itself numerically, never a bare "anomaly detected".</summary>
public sealed record AnomalyEvaluation(
    AnomalyProfileKey Key,
    string Verdict,
    double ObservedValue,
    LearnedProfile? Profile,
    string Detail)
{
    public string EvidenceDetail => Profile is null
        ? Detail
        : $"observed={ObservedValue:F2} band=[{Profile.BandLow:F2}, {Profile.BandHigh:F2}] median={Profile.Median:F2} " +
          $"samples={Profile.SampleCount} maturity=({Profile.MaturityReport}) :: {Detail}";
}

public static class AnomalyEvaluator
{
    /// <summary>Pure evaluation: no profile or an immature profile
    /// yields Learning (never a verdict); a mature profile yields
    /// Inside/Outside against its band.</summary>
    public static AnomalyEvaluation Evaluate(AnomalyProfileKey key, double value, LearnedProfile? profile)
    {
        if (profile is null)
            return new AnomalyEvaluation(key, AnomalyVerdicts.Learning, value, null,
                "no learned profile yet — still learning (no verdict without data)");
        if (!profile.IsMature)
            return new AnomalyEvaluation(key, AnomalyVerdicts.Learning, value, profile,
                profile.MaturityReport);
        return value < profile.BandLow || value > profile.BandHigh
            ? new AnomalyEvaluation(key, AnomalyVerdicts.OutsideBand, value, profile,
                $"value {value:F2} is outside the learned band [{profile.BandLow:F2}, {profile.BandHigh:F2}] for {key.Metric} on {key.DeviceId}")
            : new AnomalyEvaluation(key, AnomalyVerdicts.InsideBand, value, profile,
                $"value {value:F2} inside learned band [{profile.BandLow:F2}, {profile.BandHigh:F2}]");
    }
}

// ---- alerting shape ----------------------------------------------------------

/// <summary>The RMM-01 alert kind anomaly findings ride, and the
/// condition-id discipline. Like RMM-19's baseline_drift it is
/// deliberately NOT in RMM-01's NeverSuppressible set: a maintenance
/// window may suppress an anomaly NOTIFICATION during planned work —
/// never the learning exclusions, the evaluation, or the audit.</summary>
public static class AnomalyAlerting
{
    public const string Kind = "metric_anomaly";
    public const string Source = "endpoint";
}

// ---- policy resolution --------------------------------------------------------

/// <summary>The resolved RMM-27 policy for one device, with every
/// clamp / fallback named in Notes.</summary>
public sealed record ResolvedAnomalyPolicy(
    string Sensitivity,
    double BandFactor,
    TimeSpan Sustain,
    string Severity,
    TimeSpan Cooldown,
    IReadOnlyList<string> Notes)
{
    public IReadOnlyList<string> Notes { get; init; } = Notes ?? Array.Empty<string>();
}

public static class AnomalyPolicyResolver
{
    public static ResolvedAnomalyPolicy Resolve(ManagementPolicyEngine engine, IDeviceFacts facts)
    {
        var eff = engine.ComputeEffective(facts);
        var notes = new List<string>();

        var sensitivity = AnomalyPolicyKeys.DefaultSensitivity;
        if (eff.Get(AnomalyPolicyKeys.Sensitivity) is { } s)
        {
            // FL-27b / F10: a PRESENT but blank sensitivity was
            // previously indistinguishable from an unset one — the
            // default applied with no note anywhere. Blank is a
            // policy authoring fact and is named like any other
            // fallback.
            if (string.IsNullOrWhiteSpace(s.Value))
                notes.Add($"sensitivity is set but blank — default '{sensitivity}' applies (named, never silently applied)");
            else
            {
                var v = s.Value.Trim().ToLowerInvariant();
                if (v is "low" or "medium" or "high") sensitivity = v;
                else notes.Add($"sensitivity '{s.Value}' is not low|medium|high — default '{sensitivity}' applies (named, never silently applied)");
            }
        }

        var sustain = AnomalyPolicyKeys.DefaultSustainSeconds;
        if (eff.Get(AnomalyPolicyKeys.SustainSeconds) is { } su)
        {
            if (int.TryParse(su.Value, out var v))
            {
                sustain = Math.Clamp(v, AnomalyPolicyKeys.MinSustainSeconds, AnomalyPolicyKeys.MaxSustainSeconds);
                if (sustain != v) notes.Add($"sustain {v}s clamped to {sustain}s (bounds {AnomalyPolicyKeys.MinSustainSeconds}–{AnomalyPolicyKeys.MaxSustainSeconds})");
            }
            else notes.Add($"sustain value '{su.Value}' is not a number — default {sustain}s applies");
        }
        // FL-27b / F10 honesty: at sustain = 0 a single outside-band
        // sample alerts — the "brief spike never alerts" mitigation
        // the design describes does not exist at this setting, and
        // the resolution says so rather than letting the doctrine
        // and the configuration quietly contradict each other.
        if (sustain == 0)
            notes.Add("sustain is 0s — a single outside-band sample can raise an anomaly alert; the sustained-duration mitigation ('a brief spike never alerts') does NOT apply at this setting");

        var severity = AlertSeverities.Warning;
        if (eff.Get(AnomalyPolicyKeys.Severity) is { } sev)
        {
            // FL-27b / F10: blank severity named, like sensitivity.
            if (string.IsNullOrWhiteSpace(sev.Value))
                notes.Add($"severity is set but blank — default '{severity}' applies (named, never silently applied)");
            else
            {
                var v = sev.Value.Trim().ToLowerInvariant();
                if (AlertSeverities.All.Contains(v)) severity = v;
                else notes.Add($"severity '{sev.Value}' is unknown — default '{severity}' applies");
            }
        }

        var cooldown = AnomalyPolicyKeys.DefaultCooldownSeconds;
        if (eff.Get(AnomalyPolicyKeys.CooldownSeconds) is { } cd)
        {
            if (int.TryParse(cd.Value, out var v))
            {
                cooldown = Math.Clamp(v, AnomalyPolicyKeys.MinCooldownSeconds, AnomalyPolicyKeys.MaxCooldownSeconds);
                if (cooldown != v) notes.Add($"cooldown {v}s clamped to {cooldown}s (bounds {AnomalyPolicyKeys.MinCooldownSeconds}–{AnomalyPolicyKeys.MaxCooldownSeconds})");
            }
            else notes.Add($"cooldown value '{cd.Value}' is not a number — default {cooldown}s applies");
        }

        return new ResolvedAnomalyPolicy(sensitivity, AnomalyPolicyKeys.BandFactorFor(sensitivity),
            TimeSpan.FromSeconds(sustain), severity, TimeSpan.FromSeconds(cooldown), notes);
    }
}
