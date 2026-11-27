using DeskGuest.Core.Services;
using DeskGuest.Shared.AnomalyBaselining;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.Monitoring;

namespace DeskGuest.Tests;

// FL-27a — permanent regressions for the D38 RMM-27 findings
// F1–F5 (verdict f1791c9e, reconciled in d38-sweep.md A3):
//   F1 admission-edge ratchet (live recomputation in Admit)
//   F2 ObserveObservations ignored its `now` (all timing on
//      caller-supplied observation timestamps)
//   F3 import replaced history wholesale, force-recomputed, and
//      carried no device/auth binding
//   F4 honest export→import round-trips broke (clamped profile
//      claims vs current admitted samples)
//   F5 regime change unlearnable on the Observe path; the
//      Learning branch never reset service-raised alerts (deadlock)
// Every test here fails against the pre-fix code for the reason
// named in its comment.
public class Rmm27FixTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    private const string Dev = "dev-1";
    private const string Scope = "co-1";

    public sealed class Rig
    {
        public ChainedAuditLog Audit = new();
        public AlertCenter Dir57 = new();
        public HealthAlertCentre Centre;
        public ManagementPolicyService Policies;
        public AnomalyDetectionService Service;

        public Rig()
        {
            Centre = new HealthAlertCentre(Audit, Dir57);
            Policies = new ManagementPolicyService(Audit, null);
            Service = new AnomalyDetectionService(Audit, Policies, Centre,
                id => StaticDeviceFacts.Of(id, Scope), now: () => T0);
        }

        public void PolicyDoc(string id, string key, string value)
        {
            var v = Policies.AdmitLocalDocument(new ManagementPolicyDocument(
                id, PolicyLevels.Org, Scope, new Dictionary<string, string> { [key] = value }, 1), "test");
            Assert.True(v.Allowed, v.Reason);
        }

        public void LearnCpu(double center = 50, string dev = Dev)
        {
            var obs = new List<MetricObservation>();
            for (var i = 0; i < 49; i++)
                obs.Add(new MetricObservation(dev, AnomalyMetrics.CpuPercent, "*",
                    center + (i % 3 - 1), T0.AddHours(i)));
            Service.ObserveObservations(dev, obs, T0.AddHours(48));
        }

        public AnomalyCycleResult FeedCpu(double value, DateTimeOffset at, string dev = Dev) =>
            Service.ObserveObservations(dev,
                new[] { new MetricObservation(dev, AnomalyMetrics.CpuPercent, "*", value, at) }, at);

        public AnomalyProfileKey CpuKey(string dev = Dev) => new(dev, AnomalyMetrics.CpuPercent, "*");
    }

    private static AnomalyProfileStore.ProfileExport HonestExport(
        string dev, IReadOnlyList<AnomalyProfileStore.ExportedSample> samples)
    {
        var (m, a, b, _, _) = RobustStats.Band(samples.Select(s => s.Value).ToList(), 2.0);
        return new AnomalyProfileStore.ProfileExport(dev, AnomalyMetrics.CpuPercent, "*", samples, m, a, b, samples.Count);
    }

    private static List<AnomalyProfileStore.ExportedSample> Samples(double value, int count, DateTimeOffset start, double stepHours = 1)
        => Enumerable.Range(0, count)
            .Select(i => new AnomalyProfileStore.ExportedSample(value, start.AddHours(stepHours * i))).ToList();

    // ================= F1 — frozen admission range =================

    // Pre-fix: Admit recomputed p05/p95 from the live admitted list
    // on every call, so admitted edge values widened the range for
    // the next value (the ratchet DG-R27-01 did not close).
    [Fact]
    public void F1_AdmissionRangeIsFrozen_InsideLiveEdgeValuesDoNotWidenIt()
    {
        // LANE W1 REPAIR (bd-shared-rmm-1 F4 supersedes the
        // freeze-at-provisional half of the original test): the
        // frozen trim now engages only at MATURITY
        // (MinSamplesForMaturity over MinLearningSpan) — freezing
        // at 10 samples self-sealed profiles against legitimate
        // regime change. The scenario therefore learns to
        // maturity first (30 hourly samples of 50); every
        // assertion below the setup is the original one, with the
        // same frozen range (47.5, 52.5).
        var store = new AnomalyProfileStore();
        var key = new AnomalyProfileKey(Dev, AnomalyMetrics.CpuPercent, "*");
        for (var i = 0; i < 30; i++)
            Assert.Equal(AdmissionOutcomes.Admitted,
                store.Admit(new MetricObservation(Dev, AnomalyMetrics.CpuPercent, "*", 50, T0.AddHours(i)), false, 2.0).Outcome);

        var frozen = store.FrozenAdmissionRange(key);
        Assert.NotNull(frozen);
        Assert.Equal((47.5, 52.5), frozen!.Value);

        // 20 values at 52: inside the frozen range, so learned —
        // but under live recomputation they would push p95 to 52
        // and the admission high to 54.5.
        for (var i = 0; i < 20; i++)
            Assert.Equal(AdmissionOutcomes.Admitted,
                store.Admit(new MetricObservation(Dev, AnomalyMetrics.CpuPercent, "*", 52, T0.AddHours(30 + i)), false, 2.0).Outcome);

        // The range did not move, and values the LIVE range would
        // now admit (53, 54) are still excluded by the frozen one.
        Assert.Equal((47.5, 52.5), store.FrozenAdmissionRange(key)!.Value);
        Assert.Equal(AdmissionOutcomes.ExcludedOutsideBand,
            store.Admit(new MetricObservation(Dev, AnomalyMetrics.CpuPercent, "*", 54, T0.AddHours(50)), false, 2.0).Outcome);
        Assert.Equal(AdmissionOutcomes.ExcludedOutsideBand,
            store.Admit(new MetricObservation(Dev, AnomalyMetrics.CpuPercent, "*", 53, T0.AddHours(51)), false, 2.0).Outcome);

        // Only a recomputation refreshes the range — from the data
        // actually admitted (median 52, p95 52, floor 2.6).
        store.Recompute(key, T0.AddHours(52), 2.0, force: true);
        var refreshed = store.FrozenAdmissionRange(key)!.Value;
        Assert.True(refreshed.High > 52.5, $"frozen range must refresh at recomputation, got {refreshed}");
        Assert.Equal(AdmissionOutcomes.Admitted,
            store.Admit(new MetricObservation(Dev, AnomalyMetrics.CpuPercent, "*", 54, T0.AddHours(53)), false, 2.0).Outcome);
    }

    // Pre-fix: no cumulative cap existed on the admission range at
    // all. Post-fix the range derives from movement-clamped
    // percentiles, so even a fully self-consistent regime import
    // moves the median exactly one clamped step per recomputation.
    [Fact]
    public void F1_CumulativeBandGrowth_IsCappedPerRecompute()
    {
        var store = new AnomalyProfileStore();
        var key = new AnomalyProfileKey(Dev, AnomalyMetrics.CpuPercent, "*");
        for (var i = 0; i < 40; i++)
            store.Admit(new MetricObservation(Dev, AnomalyMetrics.CpuPercent, "*", 50, T0.AddHours(i)), false, 2.0);
        store.Recompute(key, T0.AddHours(41), 2.0, force: true);
        Assert.Equal(50, store.GetProfile(key)!.Median); // band [45, 55], width 10

        // Regime import #1: raw median of the merged history is 125,
        // but the applied median moves exactly 0.25 × old width.
        var imp1 = HonestExport(Dev, Samples(200, 40, T0.AddHours(100)));
        Assert.True(store.Import(imp1, T0.AddHours(200), 2.0, Dev).Accepted);
        var after1 = store.GetProfile(key)!;
        Assert.Equal(52.5, after1.Median);
        Assert.Contains(store.DriftHistory(key), s => s.MoveClamped);

        // Regime import #2 (fresh sample times): raw median is now
        // 200; the step is again exactly the per-update cap of the
        // CURRENT band (width 15 → 3.75), not a leap to the regime.
        var imp2 = HonestExport(Dev, Samples(200, 40, T0.AddHours(150)));
        Assert.True(store.Import(imp2, T0.AddHours(201), 2.0, Dev).Accepted);
        var after2 = store.GetProfile(key)!;
        Assert.Equal(52.5 + (after1.BandHigh - after1.BandLow) * AnomalyLimits.MaxBandMoveFractionPerUpdate, after2.Median);
        Assert.True(after2.Median < 60, $"cumulative growth must stay stepwise, median ran to {after2.Median}");
    }

    // ================= F2 — timestamp discipline =================

    // Pre-fix: `now` was never referenced; a value dated a day in
    // the future was judged, learned, and could raise alerts.
    [Fact]
    public void F2_FutureDatedObservation_Quarantined_NeverJudgedNeverLearned()
    {
        var rig = new Rig();
        rig.PolicyDoc("p-sustain", AnomalyPolicyKeys.SustainSeconds, "0");
        rig.LearnCpu();
        var (_, _, _, admittedBefore) = rig.Service.Store.Counters(rig.CpuKey());

        var result = rig.Service.ObserveObservations(Dev,
            new[] { new MetricObservation(Dev, AnomalyMetrics.CpuPercent, "*", 500, T0.AddHours(100)) },
            T0.AddHours(50));

        Assert.Empty(result.Evaluations);
        var admission = Assert.Single(result.Admissions);
        Assert.Equal(AdmissionOutcomes.RefusedFutureDated, admission.Outcome);
        Assert.Empty(result.NewAlerts);
        Assert.Empty(rig.Centre.ActiveAlerts);
        var (_, _, _, admittedAfter) = rig.Service.Store.Counters(rig.CpuKey());
        Assert.Equal(admittedBefore, admittedAfter);
    }

    // Pre-fix: two observations whose TIMESTAMPS span the sustain
    // window satisfied sustain instantly, however they arrived.
    [Fact]
    public void F2_FutureTimestamps_CannotSatisfySustain()
    {
        var rig = new Rig();
        rig.PolicyDoc("p-sustain", AnomalyPolicyKeys.SustainSeconds, "60");
        rig.LearnCpu();
        var t = T0.AddHours(50);
        Assert.Empty(rig.FeedCpu(90, t).NewAlerts); // sustain clock starts, honestly
        // The second value claims to be 10 minutes later, but the
        // service clock has not advanced: it is future-dated beyond
        // skew and must be quarantined, not counted toward sustain.
        var forged = rig.Service.ObserveObservations(Dev,
            new[] { new MetricObservation(Dev, AnomalyMetrics.CpuPercent, "*", 90, t.AddMinutes(10)) }, t);
        Assert.Equal(AdmissionOutcomes.RefusedFutureDated, Assert.Single(forged.Admissions).Outcome);
        Assert.Empty(forged.NewAlerts);
        Assert.Empty(rig.Centre.ActiveAlerts);
    }

    // Pre-fix: Admit accepted any timestamp; a replayed old value
    // rewound the learning window.
    [Fact]
    public void F2_StaleTimestamp_RefusedByStore_AndCounted()
    {
        var store = new AnomalyProfileStore();
        var key = new AnomalyProfileKey(Dev, AnomalyMetrics.CpuPercent, "*");
        Assert.Equal(AdmissionOutcomes.Admitted,
            store.Admit(new MetricObservation(Dev, AnomalyMetrics.CpuPercent, "*", 50, T0.AddHours(10)), false, 2.0).Outcome);
        var stale = store.Admit(new MetricObservation(Dev, AnomalyMetrics.CpuPercent, "*", 50, T0.AddHours(5)), false, 2.0);
        Assert.Equal(AdmissionOutcomes.RefusedStaleTimestamp, stale.Outcome);
        Assert.Equal(1, store.StaleRefusals(key));
        Assert.Equal(1, store.Counters(key).Admitted);
        // The same instant is not stale (parallel readings exist).
        Assert.Equal(AdmissionOutcomes.Admitted,
            store.Admit(new MetricObservation(Dev, AnomalyMetrics.CpuPercent, "*", 51, T0.AddHours(10)), false, 2.0).Outcome);
    }

    // Pre-fix: recomputation was stamped with obs.AtUtc (the last
    // observation's caller-supplied time) and ran per-observation.
    [Fact]
    public void F2_RecomputeRunsOnServiceTime_AndRateLimitUsesItToo()
    {
        var rig = new Rig();
        // Backfill: 49 hourly samples ending at +48h, observed by a
        // service whose clock reads +100h.
        var obs = new List<MetricObservation>();
        for (var i = 0; i < 49; i++)
            obs.Add(new MetricObservation(Dev, AnomalyMetrics.CpuPercent, "*", 50 + (i % 3 - 1), T0.AddHours(i)));
        rig.Service.ObserveObservations(Dev, obs, T0.AddHours(100));
        var profile = rig.Service.ProfileFor(rig.CpuKey())!;
        Assert.Equal(49, profile.SampleCount);            // one end-of-cycle recompute over the whole batch
        Assert.Equal(T0.AddHours(100), profile.ComputedUtc); // stamped with SERVICE time, not obs time

        // A further value 30 service-minutes later is admitted, but
        // the recompute rate limit runs on service time: the profile
        // does not move yet.
        rig.Service.ObserveObservations(Dev,
            new[] { new MetricObservation(Dev, AnomalyMetrics.CpuPercent, "*", 50, T0.AddHours(49)) },
            T0.AddHours(100).AddMinutes(30));
        var unchanged = rig.Service.ProfileFor(rig.CpuKey())!;
        Assert.Equal(profile.Revision, unchanged.Revision);
        Assert.Equal(49, unchanged.SampleCount);

        // Past the service-time interval, the recompute lands.
        rig.Service.ObserveObservations(Dev,
            new[] { new MetricObservation(Dev, AnomalyMetrics.CpuPercent, "*", 50, T0.AddHours(50)) },
            T0.AddHours(101).AddMinutes(1));
        var moved = rig.Service.ProfileFor(rig.CpuKey())!;
        Assert.True(moved.Revision > profile.Revision);
        Assert.Equal(51, moved.SampleCount);
    }

    // ================= F3 — import hardening =================

    [Fact]
    public void F3_Import_BoundToAuthorizedDevice()
    {
        var store = new AnomalyProfileStore();
        var export = HonestExport(Dev, Samples(50, 40, T0));
        var refused = store.Import(export, T0.AddDays(3), 2.0, "dev-2");
        Assert.False(refused.Accepted);
        Assert.Contains("authorized", refused.Reason);
        Assert.Empty(store.Keys); // nothing was imported under either device
        Assert.True(store.Import(export, T0.AddDays(3), 2.0, Dev).Accepted);
    }

    // Pre-fix: import REPLACED the admitted history wholesale.
    [Fact]
    public void F3_Import_MergesIntoExistingHistory_DuplicatesNamed()
    {
        var store = new AnomalyProfileStore();
        var key = new AnomalyProfileKey(Dev, AnomalyMetrics.CpuPercent, "*");
        for (var i = 0; i < 40; i++)
            store.Admit(new MetricObservation(Dev, AnomalyMetrics.CpuPercent, "*", 50, T0.AddHours(i)), false, 2.0);
        store.Recompute(key, T0.AddHours(41), 2.0, force: true);

        var export = HonestExport(Dev, Samples(60, 40, T0.AddHours(100)));
        var first = store.Import(export, T0.AddHours(200), 2.0, Dev, actor: "test-admin");
        Assert.True(first.Accepted, first.Reason);
        Assert.Contains("40 new samples merged", first.Reason);
        Assert.Equal(80, store.Counters(key).Admitted); // merged, not replaced

        var again = store.Import(export, T0.AddHours(202), 2.0, Dev);
        Assert.True(again.Accepted, again.Reason);
        Assert.Contains("0 new samples merged", again.Reason);
        Assert.Contains("40 exact duplicates skipped", again.Reason);
        Assert.Equal(80, store.Counters(key).Admitted);
    }

    // Pre-fix: import nullified LastRecomputeUtc and force-
    // recomputed — a complete bypass of the rate limit.
    [Fact]
    public void F3_Import_InsideRateLimit_RefusedWhole_NothingMutates()
    {
        var store = new AnomalyProfileStore();
        var key = new AnomalyProfileKey(Dev, AnomalyMetrics.CpuPercent, "*");
        for (var i = 0; i < 40; i++)
            store.Admit(new MetricObservation(Dev, AnomalyMetrics.CpuPercent, "*", 50, T0.AddHours(i)), false, 2.0);
        store.Recompute(key, T0.AddHours(41), 2.0, force: true);

        // Samples timestamped just after the learned history, so
        // they are honestly past-dated at the +41:30 import attempt
        // (a future-dated export would refuse earlier, for skew).
        var export = HonestExport(Dev, Samples(60, 40, T0.AddHours(40), stepHours: 1.0 / 60));
        var refused = store.Import(export, T0.AddHours(41).AddMinutes(30), 2.0, Dev);
        Assert.False(refused.Accepted);
        Assert.Contains("rate limit", refused.Reason);
        Assert.Equal(40, store.Counters(key).Admitted);          // no mutation
        Assert.Equal(50, store.GetProfile(key)!.Median);         // no movement

        Assert.True(store.Import(export, T0.AddHours(43), 2.0, Dev).Accepted); // after the interval: fine
    }

    // Pre-fix: imported samples skipped the rolling window and the
    // per-profile cap that live admission applies.
    [Fact]
    public void F3_Import_AppliesWindowAndCap_NamedInResult()
    {
        // Window: samples spanning 419h; only those inside 14 days
        // of the newest survive the merge.
        var store = new AnomalyProfileStore();
        var key = new AnomalyProfileKey(Dev, AnomalyMetrics.CpuPercent, "*");
        var samples = Samples(50, 20, T0).Concat(Samples(50, 20, T0.AddHours(400))).ToList();
        var result = store.Import(HonestExport(Dev, samples), T0.AddHours(500), 2.0, Dev);
        Assert.True(result.Accepted, result.Reason);
        Assert.Contains("20 trimmed by the learning window", result.Reason);
        Assert.Equal(20, store.Counters(key).Admitted);

        // Cap: 5001 samples inside the window — oldest dropped,
        // counted, named.
        var store2 = new AnomalyProfileStore();
        var dense = Enumerable.Range(0, 5001)
            .Select(i => new AnomalyProfileStore.ExportedSample(50, T0.AddMinutes(i))).ToList();
        var capped = store2.Import(HonestExport(Dev, dense), T0.AddDays(10), 2.0, Dev);
        Assert.True(capped.Accepted, capped.Reason);
        Assert.Contains("1 dropped for the per-profile cap", capped.Reason);
        Assert.Equal(AnomalyLimits.MaxSamplesPerProfile, store2.Counters(key).Admitted);
        Assert.Equal(1, store2.Counters(key).DroppedForCap);
    }

    // ================= F4 — round-trip consistency =================

    [Fact]
    public void F4_HonestRoundTrip_Passes()
    {
        var source = new AnomalyProfileStore();
        var key = new AnomalyProfileKey(Dev, AnomalyMetrics.CpuPercent, "*");
        for (var i = 0; i < 49; i++)
            source.Admit(new MetricObservation(Dev, AnomalyMetrics.CpuPercent, "*", 50 + (i % 3 - 1), T0.AddHours(i)), false, 2.0);
        source.Recompute(key, T0.AddHours(50), 2.0, force: true);

        var export = source.Export(key, 2.0);
        Assert.NotNull(export);
        var target = new AnomalyProfileStore();
        var imported = target.Import(export!, T0.AddHours(60), 2.0, Dev);
        Assert.True(imported.Accepted, imported.Reason);
        var profile = target.GetProfile(key)!;
        Assert.True(profile.IsMature, profile.MaturityReport);
        Assert.Equal(export!.ClaimedMedian, profile.Median);
    }

    // Pre-fix: Export claimed the stored profile's CLAMPED median
    // (52.5) and as-of-recompute count while sending the current
    // admitted samples (raw median 125) — the importer's raw
    // recomputation refused the honest export as "tampered".
    [Fact]
    public void F4_RoundTrip_AfterClampedRecompute_StillVerifies()
    {
        var source = new AnomalyProfileStore();
        var key = new AnomalyProfileKey(Dev, AnomalyMetrics.CpuPercent, "*");
        for (var i = 0; i < 40; i++)
            source.Admit(new MetricObservation(Dev, AnomalyMetrics.CpuPercent, "*", 50, T0.AddHours(i)), false, 2.0);
        source.Recompute(key, T0.AddHours(41), 2.0, force: true);
        Assert.True(source.Import(HonestExport(Dev, Samples(200, 40, T0.AddHours(100))), T0.AddHours(200), 2.0, Dev).Accepted);
        Assert.Equal(52.5, source.GetProfile(key)!.Median); // clamped profile…
        Assert.Equal(80, source.Counters(key).Admitted);    // …over samples whose raw median is 125

        var export = source.Export(key, 2.0)!;
        Assert.Equal(125, export.ClaimedMedian); // claims now describe the SENT samples
        Assert.Equal(80, export.ClaimedSampleCount);

        var target = new AnomalyProfileStore();
        var imported = target.Import(export, T0.AddHours(300), 2.0, Dev);
        Assert.True(imported.Accepted, imported.Reason);
        Assert.Equal(125, target.GetProfile(key)!.Median); // fresh store: no clamp, raw truth
        Assert.True(target.GetProfile(key)!.IsMature);
    }

    // ================= F5 — relearn path + alert deadlock =================

    // Pre-fix: the Learning branch removed only the sustain clock.
    // A service-raised alert whose profile fell back to learning
    // stayed active forever, and alert-period exclusion then
    // blocked every future sample — the profile could never
    // relearn. (Here the fall-back is a store-level history clear,
    // standing in for window slide / external history replacement.)
    [Fact]
    public void F5_LearningVerdict_ResetsServiceRaisedAlert_DeadlockBroken()
    {
        var rig = new Rig();
        rig.PolicyDoc("p-sustain", AnomalyPolicyKeys.SustainSeconds, "0");
        rig.LearnCpu();
        var t = T0.AddHours(50);
        Assert.Single(rig.FeedCpu(90, t).NewAlerts);
        Assert.Single(rig.Centre.ActiveAlerts);

        rig.Service.Store.Rebaseline(rig.CpuKey()); // learned history gone; profile is learning again

        var learning = rig.FeedCpu(50, t.AddHours(1));
        Assert.All(learning.Evaluations, e => Assert.Equal(AnomalyVerdicts.Learning, e.Verdict));
        Assert.Single(learning.ResetAlerts);            // our alert was reset by the Learning branch
        Assert.Empty(rig.Centre.ActiveAlerts);

        // And learning flows again — the next value is admitted,
        // not excluded under a zombie alert.
        var next = rig.FeedCpu(50, t.AddHours(2));
        Assert.Equal(AdmissionOutcomes.Admitted, Assert.Single(next.Admissions).Outcome);
    }

    // Pre-fix: no relearn path existed at all — a genuine regime
    // change was excluded by trimmed admission forever.
    [Fact]
    public void F5_Rebaseline_LearnsNewRegime_AndIsAudited()
    {
        var rig = new Rig();
        rig.PolicyDoc("p-sustain", AnomalyPolicyKeys.SustainSeconds, "0");
        rig.LearnCpu();
        var t = T0.AddHours(50);
        Assert.Single(rig.FeedCpu(90, t).NewAlerts);
        for (var i = 0; i < 10; i++) rig.FeedCpu(200, t.AddHours(1 + i)); // the new regime, knocking
        Assert.Equal(50, rig.Service.ProfileFor(rig.CpuKey())!.Median);   // still unlearnable, by design

        // Gates: anonymous rebaseline refused; unknown metric refused.
        Assert.False(rig.Service.RebaselineProfile(Dev, AnomalyMetrics.CpuPercent, "*", " ", t.AddHours(20)).Done);
        Assert.False(rig.Service.RebaselineProfile(Dev, "telepathy_percent", "*", "admin", t.AddHours(20)).Done);

        var done = rig.Service.RebaselineProfile(Dev, AnomalyMetrics.CpuPercent, "*", "admin-1", t.AddHours(20));
        Assert.True(done.Done, done.Detail);
        Assert.Null(rig.Service.ProfileFor(rig.CpuKey()));
        Assert.Empty(rig.Centre.ActiveAlerts); // the alert went with the history it guarded
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "anomaly_profile_rebaseline" && e.Actor == "admin-1");

        // The regime is now learned fresh, under the ordinary
        // maturity discipline (30 samples / 24h span).
        var obs = new List<MetricObservation>();
        for (var i = 0; i < 30; i++)
            obs.Add(new MetricObservation(Dev, AnomalyMetrics.CpuPercent, "*", 200, t.AddHours(21 + i)));
        rig.Service.ObserveObservations(Dev, obs, t.AddHours(50));
        var profile = rig.Service.ProfileFor(rig.CpuKey())!;
        Assert.True(profile.IsMature, profile.MaturityReport);
        Assert.Equal(200, profile.Median);
    }
}
