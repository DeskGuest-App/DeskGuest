using DeskGuest.Core.Services;
using DeskGuest.Shared.AnomalyBaselining;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.Monitoring;

namespace DeskGuest.Tests;

// RMM-27 DESTRUCTION — hostile pass over the anomaly baselining.
// The attacker model: a compromised/failing endpoint (or a hostile
// sample source) trying to TEACH the baseline that bad is normal,
// forge maturity, flood the centre, or borrow another device's
// profile. Every break found converts to a fix + a test here.
public class Rmm27DestructionTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    private const string Dev = "dev-1";
    private const string DevB = "dev-2";
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
            // FL-27a amendment (disclosed in log-fix27a.md): cycle
            // `now` = end of the backfilled history (was its start;
            // `now` was ignored entirely — finding F2).
            Service.ObserveObservations(dev, obs, T0.AddHours(48));
        }

        public AnomalyCycleResult FeedCpu(double value, DateTimeOffset at, string dev = Dev) =>
            Service.ObserveObservations(dev,
                new[] { new MetricObservation(dev, AnomalyMetrics.CpuPercent, "*", value, at) }, at);

        public AnomalyProfileKey CpuKey(string dev = Dev) => new(dev, AnomalyMetrics.CpuPercent, "*");
    }

    // D1 — sustained bad values must not teach the band.
    [Fact]
    public void SustainedBadValues_CannotTeachTheBand()
    {
        var rig = new Rig();
        rig.LearnCpu();
        var before = rig.Service.ProfileFor(rig.CpuKey())!;
        // 200 samples of 500% CPU over 200 hours — a total poisoning feed.
        for (var i = 0; i < 200; i++)
            rig.FeedCpu(500, T0.AddHours(50 + i));
        var after = rig.Service.ProfileFor(rig.CpuKey())!;
        Assert.Equal(before.Median, after.Median);
        Assert.Equal(before.BandLow, after.BandLow);
        Assert.Equal(before.BandHigh, after.BandHigh);
        var (underAlert, outside, _, admitted) = rig.Service.Store.Counters(rig.CpuKey());
        // Every poison sample excluded and counted — the first few
        // as outside-band, the rest (after the anomaly alert raised)
        // as under-active-alert. Either way: none was learned.
        Assert.Equal(200, outside + underAlert);
        Assert.True(outside > 0 && underAlert > 0,
            $"expected both exclusion channels to fire (outside={outside}, underAlert={underAlert})");
        Assert.Equal(49, admitted);          // nothing new was learned
    }

    // D2 — values during an active alert never teach, even inside-band ones.
    [Fact]
    public void AlertPeriodValues_NeverTeach()
    {
        var rig = new Rig();
        rig.PolicyDoc("p-sustain", AnomalyPolicyKeys.SustainSeconds, "0");
        rig.LearnCpu();
        var t = T0.AddHours(50);
        Assert.Single(rig.FeedCpu(90, t).NewAlerts); // alert active now
        var (_, _, _, admittedBefore) = rig.Service.Store.Counters(rig.CpuKey());
        // A plausible-looking inside-band value while the alert is
        // active: it is judged (and resets the alert, since the
        // value is back inside the band) but it is NOT learned —
        // it was observed during an alert period.
        rig.FeedCpu(52, t.AddMinutes(10));
        var (underAlert, _, _, admittedAfter) = rig.Service.Store.Counters(rig.CpuKey());
        Assert.True(underAlert >= 1, $"alert-period exclusions not counted: {underAlert}");
        Assert.Equal(admittedBefore, admittedAfter);
    }

    // D3a — recomputation is rate-limited: rapid-fire recompute
    // attempts cannot move the band faster than the named interval.
    [Fact]
    public void Recompute_IsRateLimited()
    {
        var store = new AnomalyProfileStore();
        var key = new AnomalyProfileKey(Dev, AnomalyMetrics.CpuPercent, "*");
        for (var i = 0; i < 20; i++)
            store.Admit(new MetricObservation(Dev, AnomalyMetrics.CpuPercent, "*", 50, T0.AddMinutes(i)), false, 2.0);
        var (p1, _, limited1) = store.Recompute(key, T0.AddHours(1), 2.0);
        Assert.False(limited1);
        Assert.NotNull(p1);
        var (p2, _, limited2) = store.Recompute(key, T0.AddHours(1).AddMinutes(30), 2.0);
        Assert.True(limited2);
        Assert.Equal(p1!.Revision, p2!.Revision); // unchanged
    }

    // D3b — slow drift at the band edge is BOUNDED by trimmed
    // admission: creeping values can walk the band only within the
    // admitted range, never run away to the attacker's normal.
    [Fact]
    public void SlowDrift_BoundedByTrimmedAdmission()
    {
        var rig = new Rig();
        rig.LearnCpu(); // band [45, 55], median 50
        // Creep: always feed exactly the current band high — the
        // most favourable admission an attacker can get.
        for (var i = 0; i < 300; i++)
        {
            var p = rig.Service.ProfileFor(rig.CpuKey())!;
            rig.FeedCpu(p.BandHigh, T0.AddHours(50 + i));
        }
        var after = rig.Service.ProfileFor(rig.CpuKey())!;
        // Regression for the D3 break (band-edge ratchet: median ran
        // to ~7.9M before the fix). Under trimmed spread admission
        // the band-edge feeds are not learned at all, and the
        // per-update movement clamp bounds any residual motion:
        // the median stays at the honest centre.
        Assert.Equal(50, after.Median);
        var (_, outside, _, _) = rig.Service.Store.Counters(rig.CpuKey());
        Assert.Equal(300, outside); // every edge feed excluded, and counted
        // And the profile's history is kept, not silent.
        Assert.NotEmpty(rig.Service.Store.DriftHistory(rig.CpuKey()));
    }

    // D3c — a material band shift, when one does happen through
    // legitimate admitted data, is SURFACED (notice + audit), not silent.
    [Fact]
    public void MaterialDrift_IsSurfacedNotSilent()
    {
        var store = new AnomalyProfileStore();
        var key = new AnomalyProfileKey(Dev, AnomalyMetrics.CpuPercent, "*");
        for (var i = 0; i < 40; i++)
            store.Admit(new MetricObservation(Dev, AnomalyMetrics.CpuPercent, "*", 50, T0.AddHours(i)), false, 2.0);
        store.Recompute(key, T0.AddHours(41), 2.0, force: true);
        // A genuinely new regime arrives as raw admitted history via
        // import of honest samples (band far away, stats consistent):
        var samples = Enumerable.Range(0, 40)
            .Select(i => new AnomalyProfileStore.ExportedSample(200, T0.AddHours(100 + i))).ToList();
        var (median, p05, p95, _, _) = RobustStats.Band(samples.Select(s => s.Value).ToList(), 2.0);
        var export = new AnomalyProfileStore.ProfileExport(Dev, AnomalyMetrics.CpuPercent, "*", samples, median, p05, p95, 40);
        // FL-27a amendment: Import now requires the authorized device (F3 binding) — call sites pass Dev.
        var (accepted, _) = store.Import(export, T0.AddHours(200), 2.0, Dev);
        Assert.True(accepted);
        var history = store.DriftHistory(key);
        Assert.Contains(history, s => s.WasMaterialDrift);
    }

    // D4 — maturity forgery through import: claims are recomputed.
    [Fact]
    public void Import_MaturityForgeryRefused()
    {
        var store = new AnomalyProfileStore();
        // (a) Claim 1000 samples, carry 5.
        var five = Enumerable.Range(0, 5)
            .Select(i => new AnomalyProfileStore.ExportedSample(50, T0.AddHours(i))).ToList();
        var (m, a, b, _, _) = RobustStats.Band(five.Select(s => s.Value).ToList(), 2.0);
        var forged = new AnomalyProfileStore.ProfileExport(Dev, AnomalyMetrics.CpuPercent, "*", five, m, a, b, 1000);
        Assert.False(store.Import(forged, T0.AddDays(3), 2.0, Dev).Accepted);
        // (b) Tampered median with consistent count.
        var forty = Enumerable.Range(0, 40)
            .Select(i => new AnomalyProfileStore.ExportedSample(50, T0.AddHours(i))).ToList();
        var tampered = new AnomalyProfileStore.ProfileExport(Dev, AnomalyMetrics.CpuPercent, "*", forty, 9999, a, b, 40);
        Assert.False(store.Import(tampered, T0.AddDays(3), 2.0, Dev).Accepted);
        // (c) Honest samples, honest stats — but only 5 samples over
        // 4 hours: imports fine and is IMMATURE. Maturity is earned
        // from evidence, never asserted.
        var honest = new AnomalyProfileStore.ProfileExport(Dev, AnomalyMetrics.CpuPercent, "*", five, m, a, b, 5);
        Assert.True(store.Import(honest, T0.AddDays(3), 2.0, Dev).Accepted);
        var profile = store.GetProfile(new AnomalyProfileKey(Dev, AnomalyMetrics.CpuPercent, "*"));
        Assert.NotNull(profile);
        Assert.False(profile!.IsMature);
        // (d) Future-dated samples refused.
        var future = Enumerable.Range(0, 40)
            .Select(i => new AnomalyProfileStore.ExportedSample(50, T0.AddDays(30 + i))).ToList();
        var (fm, fa, fb, _, _) = RobustStats.Band(future.Select(s => s.Value).ToList(), 2.0);
        var futureExport = new AnomalyProfileStore.ProfileExport(Dev, AnomalyMetrics.CpuPercent, "*", future, fm, fa, fb, 40);
        Assert.False(store.Import(futureExport, T0.AddDays(3), 2.0, Dev).Accepted);
        // (e) No samples at all refused.
        var empty = new AnomalyProfileStore.ProfileExport(Dev, AnomalyMetrics.CpuPercent, "*",
            Array.Empty<AnomalyProfileStore.ExportedSample>(), 50, 50, 50, 0);
        Assert.False(store.Import(empty, T0.AddDays(3), 2.0, Dev).Accepted);
    }

    // D5 — flapping at the band edge cannot flood: sustain resets
    // on every inside value, so no alert ever completes.
    [Fact]
    public void FlappingAtBandEdge_NeverAlerts()
    {
        var rig = new Rig();
        rig.PolicyDoc("p-sustain", AnomalyPolicyKeys.SustainSeconds, "60");
        rig.LearnCpu();
        var t = T0.AddHours(50);
        for (var i = 0; i < 60; i++)
        {
            var r = rig.FeedCpu(i % 2 == 0 ? 90 : 50, t.AddSeconds(30 * i));
            Assert.Empty(r.NewAlerts);
        }
        Assert.Empty(rig.Centre.ActiveAlerts);
    }

    // D6 — sustained outside raises exactly ONE active alert
    // (centre dedup), however long it persists.
    [Fact]
    public void SustainedOutside_OneAlertNotAStream()
    {
        var rig = new Rig();
        rig.PolicyDoc("p-sustain", AnomalyPolicyKeys.SustainSeconds, "0");
        rig.LearnCpu();
        var t = T0.AddHours(50);
        for (var i = 0; i < 20; i++)
            rig.FeedCpu(90, t.AddMinutes(i));
        var active = rig.Centre.ActiveAlerts.Where(a => a.Kind == AnomalyAlerting.Kind).ToList();
        var alert = Assert.Single(active);
        Assert.True(alert.OccurrenceCount > 1); // refreshed, not duplicated
    }

    // D7 — cross-device bleed: device B has no profile and is never
    // judged by device A's; a foreign observation in A's batch is
    // neither learned nor judged.
    [Fact]
    public void CrossDeviceBleed_Impossible()
    {
        var rig = new Rig();
        rig.PolicyDoc("p-sustain", AnomalyPolicyKeys.SustainSeconds, "0");
        rig.LearnCpu(50, Dev);
        // Device B screams at 500: B is still learning — A's mature
        // band must not convict it.
        var resultB = rig.FeedCpu(500, T0.AddHours(50), DevB);
        Assert.All(resultB.Evaluations, e => Assert.Equal(AnomalyVerdicts.Learning, e.Verdict));
        Assert.Empty(resultB.NewAlerts);
        var profileB = rig.Service.ProfileFor(rig.CpuKey(DevB));
        Assert.True(profileB is null || !profileB.IsMature,
            "device B must not hold a mature profile borrowed from device A");
        // Foreign observation smuggled into A's batch:
        var mixed = rig.Service.ObserveObservations(Dev,
            new[] { new MetricObservation(DevB, AnomalyMetrics.CpuPercent, "*", 500, T0.AddHours(51)) },
            T0.AddHours(51));
        Assert.Empty(mixed.Evaluations);
        var a = rig.Service.ProfileFor(rig.CpuKey(Dev))!;
        Assert.Equal(50, a.Median); // untouched
    }

    // D8 — a hostile batch of extreme values during LEARNING cannot
    // widen the provisional band without bound: robust percentiles
    // keep the provisional band near the bulk of the data.
    [Fact]
    public void LearningPhase_ExtremeMinorityDoesNotOwnTheBand()
    {
        var store = new AnomalyProfileStore();
        var key = new AnomalyProfileKey(Dev, AnomalyMetrics.CpuPercent, "*");
        // 45 honest samples, then 5 extreme ones interleaved early
        // enough to be admitted before the provisional band exists
        // is impossible past sample 10 — extremes after that are
        // trimmed. Feed honest first 10, extremes, then honest.
        var t = T0;
        for (var i = 0; i < 10; i++) store.Admit(new MetricObservation(Dev, AnomalyMetrics.CpuPercent, "*", 50, t.AddHours(i)), false, 2.0);
        for (var i = 0; i < 5; i++)
        {
            var r = store.Admit(new MetricObservation(Dev, AnomalyMetrics.CpuPercent, "*", 100000, t.AddHours(10 + i)), false, 2.0);
            Assert.Equal(AdmissionOutcomes.ExcludedOutsideBand, r.Outcome);
        }
        var (profile, _, _) = store.Recompute(key, t.AddHours(20), 2.0, force: true);
        Assert.NotNull(profile);
        Assert.Equal(50, profile!.Median);
    }
}
