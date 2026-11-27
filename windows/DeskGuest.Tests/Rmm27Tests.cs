using DeskGuest.Core.Services;
using DeskGuest.Shared.AnomalyBaselining;
using DeskGuest.Shared.Baselines;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.Monitoring;

namespace DeskGuest.Tests;

// RMM-27 — Local anomaly baselining over RMM-01 history.
// Learned statistical norms (median/percentile bands), maturity
// discipline, sustained detection into RMM-01's centre with numeric
// evidence, policy control (toggle + sensitivity + sustain), and
// the learned-vs-declared distinction from RMM-19. All observations
// are synthetic; no real endpoint state is read.
public class Rmm27Tests
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

        /// <summary>Feed an hourly CPU history around `center`:
        /// 49 samples spanning 48h — enough for maturity.</summary>
        public void LearnCpu(double center = 50, string dev = Dev, DateTimeOffset? start = null)
        {
            var t = start ?? T0;
            var obs = new List<MetricObservation>();
            for (var i = 0; i < 49; i++)
                obs.Add(new MetricObservation(dev, AnomalyMetrics.CpuPercent, "*",
                    center + (i % 3 - 1), t.AddHours(i)));
            // FL-27a amendment (disclosed in log-fix27a.md): the
            // cycle `now` is the service time at the END of this
            // backfilled history. The helper previously passed the
            // START, which only worked because ObserveObservations
            // ignored `now` entirely (finding F2).
            Service.ObserveObservations(dev, obs, t.AddHours(48));
        }

        public AnomalyProfileKey CpuKey(string dev = Dev) => new(dev, AnomalyMetrics.CpuPercent, "*");

        public AnomalyCycleResult FeedCpu(double value, DateTimeOffset at, string dev = Dev) =>
            Service.ObserveObservations(dev,
                new[] { new MetricObservation(dev, AnomalyMetrics.CpuPercent, "*", value, at) }, at);
    }

    private static EndpointSample Sample(double? cpu = null, double? ram = null) => new(
        Dev, T0, cpu, ram,
        new[] { new DiskSample("C:", 20_000, 100_000, "OK", false) },
        Array.Empty<ServiceSample>(),
        new[] { new ProcessSample("Niagara", 500_000_000, null) },
        Array.Empty<AppSample>(), Array.Empty<EventLogSample>(), null, null,
        Array.Empty<GuestSample>(), Array.Empty<string>());

    // ---- extraction ---------------------------------------------------

    [Fact]
    public void Extractor_TakesOnlyHonestReadings()
    {
        var obs = MetricObservationExtractor.FromSample(Sample(cpu: 42, ram: 63));
        Assert.Contains(obs, o => o.Metric == AnomalyMetrics.CpuPercent && o.Value == 42);
        Assert.Contains(obs, o => o.Metric == AnomalyMetrics.RamPercent && o.Value == 63);
        Assert.Contains(obs, o => o.Metric == AnomalyMetrics.DiskFreePercent && o.Target == "C:" && o.Value == 20);
        Assert.Contains(obs, o => o.Metric == AnomalyMetrics.ProcessWorkingSetBytes && o.Target == "Niagara");

        var sparse = MetricObservationExtractor.FromSample(Sample());
        Assert.DoesNotContain(sparse, o => o.Metric == AnomalyMetrics.CpuPercent);
        Assert.DoesNotContain(sparse, o => o.Metric == AnomalyMetrics.RamPercent);
    }

    // ---- robust statistics ---------------------------------------------

    [Fact]
    public void RobustStats_MedianIgnoresSingleSpike()
    {
        var values = Enumerable.Repeat(50.0, 20).Append(1000.0).ToList();
        var (median, _, _, low, high) = RobustStats.Band(values, 2.0);
        Assert.Equal(50, median);
        Assert.True(high < 200, $"a single spike dragged the band: high={high}");
        Assert.True(low < 50 && high > 50);
    }

    [Fact]
    public void RobustStats_ConstantHistoryStillGetsNonZeroBand()
    {
        var (_, _, _, low, high) = RobustStats.Band(Enumerable.Repeat(50.0, 40).ToList(), 2.0);
        Assert.True(high - low > 0, "a constant history must not collapse the band to a point");
        Assert.Equal(45, low); Assert.Equal(55, high); // floor half-width 2.5 x factor 2
    }

    // ---- maturity --------------------------------------------------------

    [Fact]
    public void ImmatureProfile_ProducesNoVerdict_OnlyLearning()
    {
        var rig = new Rig();
        // 10 samples over 9 hours: provisional data, nowhere near mature.
        var obs = Enumerable.Range(0, 10)
            .Select(i => new MetricObservation(Dev, AnomalyMetrics.CpuPercent, "*", 50, T0.AddHours(i))).ToList();
        rig.Service.ObserveObservations(Dev, obs, T0.AddHours(9)); // FL-27a: service now = end of batch (was T0; `now` was ignored — F2)
        var result = rig.FeedCpu(9999, T0.AddHours(12));
        Assert.All(result.Evaluations, e => Assert.Equal(AnomalyVerdicts.Learning, e.Verdict));
        Assert.Empty(result.NewAlerts);
        Assert.Empty(rig.Centre.ActiveAlerts);
        var profile = rig.Service.ProfileFor(rig.CpuKey());
        Assert.NotNull(profile);
        Assert.False(profile!.IsMature);
        Assert.Contains("still learning", profile.MaturityReport);
    }

    [Fact]
    public void Maturity_RequiresSpanNotJustCount()
    {
        var rig = new Rig();
        // 40 samples in 39 minutes: count passes, span fails.
        var obs = Enumerable.Range(0, 40)
            .Select(i => new MetricObservation(Dev, AnomalyMetrics.CpuPercent, "*", 50, T0.AddMinutes(i))).ToList();
        rig.Service.ObserveObservations(Dev, obs, T0.AddMinutes(39)); // FL-27a: service now = end of batch (was T0; `now` was ignored — F2)
        rig.Service.Store.Recompute(rig.CpuKey(), T0.AddHours(2), 2.0, force: true);
        var profile = rig.Service.ProfileFor(rig.CpuKey());
        Assert.NotNull(profile);
        Assert.True(profile!.SampleCount >= AnomalyLimits.MinSamplesForMaturity);
        Assert.False(profile.IsMature);
    }

    [Fact]
    public void MatureProfile_InsideValueIsInside_NoAlert()
    {
        var rig = new Rig();
        rig.LearnCpu();
        var profile = rig.Service.ProfileFor(rig.CpuKey());
        Assert.NotNull(profile);
        Assert.True(profile!.IsMature, profile.MaturityReport);
        var result = rig.FeedCpu(51, T0.AddHours(50));
        Assert.Equal(AnomalyVerdicts.InsideBand, result.Evaluations.Single().Verdict);
        Assert.Empty(result.NewAlerts);
    }

    // ---- detection ---------------------------------------------------------

    [Fact]
    public void OutsideSustained_RaisesOneAlert_WithNumericEvidence()
    {
        var rig = new Rig();
        rig.PolicyDoc("p-sustain", AnomalyPolicyKeys.SustainSeconds, "60");
        rig.LearnCpu();
        var t = T0.AddHours(50);
        Assert.Empty(rig.FeedCpu(90, t).NewAlerts);                    // sustain starts
        Assert.Empty(rig.FeedCpu(90, t.AddSeconds(30)).NewAlerts);     // 30s < 60s
        var raised = rig.FeedCpu(90, t.AddSeconds(61));                // sustained
        var alert = Assert.Single(raised.NewAlerts);
        Assert.Equal(AnomalyAlerting.Kind, alert.Kind);
        Assert.Equal(AlertSeverities.Warning, alert.Severity);
        Assert.Contains("observed=90", alert.Detail);
        Assert.Contains("band=[", alert.Detail);
        Assert.Contains("samples=49", alert.Detail);
        Assert.Contains("sustained outside band", alert.Detail);
        // The alert lives in RMM-01's centre — no parallel path.
        Assert.Single(rig.Centre.ActiveAlerts);
    }

    [Fact]
    public void BriefExcursion_NeverAlerts()
    {
        var rig = new Rig();
        rig.PolicyDoc("p-sustain", AnomalyPolicyKeys.SustainSeconds, "600");
        rig.LearnCpu();
        var t = T0.AddHours(50);
        rig.FeedCpu(95, t);
        var back = rig.FeedCpu(50, t.AddMinutes(2)); // back inside well before 10 min
        Assert.Empty(back.NewAlerts);
        Assert.Empty(rig.Centre.ActiveAlerts);
    }

    [Fact]
    public void ReturnInsideBand_AutoResetsOwnAlert()
    {
        var rig = new Rig();
        rig.PolicyDoc("p-sustain", AnomalyPolicyKeys.SustainSeconds, "0");
        rig.LearnCpu();
        var t = T0.AddHours(50);
        Assert.Single(rig.FeedCpu(90, t).NewAlerts);
        var reset = rig.FeedCpu(50, t.AddMinutes(5));
        Assert.Single(reset.ResetAlerts);
        Assert.Empty(rig.Centre.ActiveAlerts);
    }

    // ---- policy ---------------------------------------------------------------

    [Fact]
    public void PolicyDisabled_NoLearningNoDetection()
    {
        var rig = new Rig();
        rig.PolicyDoc("p-off", AnomalyPolicyKeys.Enabled, "false");
        var result = rig.Service.ObserveObservations(Dev,
            new[] { new MetricObservation(Dev, AnomalyMetrics.CpuPercent, "*", 50, T0) }, T0);
        Assert.False(result.Ran);
        Assert.Contains("disabled by policy", result.NotRunReason);
        Assert.Empty(rig.Service.Store.Keys);
    }

    [Fact]
    public void PolicyResolver_ClampsAndNamesFallbacks()
    {
        var rig = new Rig();
        rig.PolicyDoc("p-clamp", AnomalyPolicyKeys.SustainSeconds, "99999");
        rig.PolicyDoc("p-sens", AnomalyPolicyKeys.Sensitivity, "extreme");
        var facts = StaticDeviceFacts.Of(Dev, Scope);
        var resolved = AnomalyPolicyResolver.Resolve(rig.Policies.Engine, facts);
        Assert.Equal(AnomalyPolicyKeys.MaxSustainSeconds, (int)resolved.Sustain.TotalSeconds);
        Assert.Equal("medium", resolved.Sensitivity);
        Assert.Contains(resolved.Notes, n => n.Contains("clamped"));
        Assert.Contains(resolved.Notes, n => n.Contains("sensitivity"));
    }

    [Fact]
    public void Sensitivity_NarrowsAndWidensBand()
    {
        var values = Enumerable.Range(0, 49).Select(i => 50.0 + (i % 3 - 1)).ToList();
        var (_, _, _, lowLow, highLow) = RobustStats.Band(values, AnomalyPolicyKeys.BandFactorFor("low"));
        var (_, _, _, lowHigh, highHigh) = RobustStats.Band(values, AnomalyPolicyKeys.BandFactorFor("high"));
        Assert.True(highLow - lowLow > highHigh - lowHigh,
            "low sensitivity must produce the wider band");
    }

    [Fact]
    public void Toggle_IsTheSeededRegistryKey()
    {
        var registry = FeatureToggleRegistry.Seeded();
        Assert.True(registry.TryGet(AnomalyPolicyKeys.Enabled, out var toggle));
        Assert.True(toggle!.DefaultEnabled);
        Assert.Equal("RMM-27", toggle.Directive);
    }

    // ---- admission refusals ------------------------------------------------------

    [Fact]
    public void UnknownMetric_AndNonFiniteValues_Refused()
    {
        var store = new AnomalyProfileStore();
        var unknown = store.Admit(new MetricObservation(Dev, "telepathy_percent", "*", 1, T0), false, 2.0);
        Assert.Equal(AdmissionOutcomes.RefusedUnknownMetric, unknown.Outcome);
        var nan = store.Admit(new MetricObservation(Dev, AnomalyMetrics.CpuPercent, "*", double.NaN, T0), false, 2.0);
        Assert.Equal(AdmissionOutcomes.RefusedBadValue, nan.Outcome);
        var inf = store.Admit(new MetricObservation(Dev, AnomalyMetrics.CpuPercent, "*", double.PositiveInfinity, T0), false, 2.0);
        Assert.Equal(AdmissionOutcomes.RefusedBadValue, inf.Outcome);
        Assert.Empty(store.Keys); // refusals create no profile state
        Assert.Null(store.GetProfile(new AnomalyProfileKey(Dev, AnomalyMetrics.CpuPercent, "*")));
    }

    // ---- learned vs declared -------------------------------------------------------

    [Fact]
    public void Learned_IsNotDeclared_DistinctKindsKeysAndModels()
    {
        Assert.NotEqual(AnomalyAlerting.Kind, DriftAlerting.Kind);
        Assert.NotEqual(AnomalyPolicyKeys.Enabled, BaselinePolicyKeys.Enabled);
        Assert.Contains("LEARNED", AnomalyHonesty.LearnedVsDeclared, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("no cloud calls", AnomalyHonesty.Method);
        Assert.Contains("NOT modelled", AnomalyHonesty.SeasonalityLimitation);
    }

    // ---- reporting -------------------------------------------------------------------

    [Fact]
    public void Report_CarriesProfilesMaturityAndHonesty()
    {
        var rig = new Rig();
        rig.LearnCpu();
        var report = rig.Service.BuildReport(Dev);
        var profile = Assert.Single(report.Profiles);
        Assert.True(profile.IsMature);
        Assert.Contains(report.Notes, n => n.Contains("no cloud calls"));
        Assert.Contains(report.Notes, n => n.Contains("excludedOutsideBand"));
        Assert.Equal(1, report.Seq);
        Assert.Equal(2, rig.Service.BuildReport(Dev).Seq);
    }

    [Fact]
    public void Observe_SamplePath_EndToEnd()
    {
        var rig = new Rig();
        var result = rig.Service.Observe(Sample(cpu: 42));
        Assert.True(result.Ran);
        Assert.Contains(result.Evaluations, e => e.Key.Metric == AnomalyMetrics.CpuPercent);
        Assert.Contains(result.Admissions, a => a.Outcome == AdmissionOutcomes.Admitted);
    }
}
