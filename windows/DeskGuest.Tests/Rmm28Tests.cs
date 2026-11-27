using DeskGuest.Core.Services;
using DeskGuest.Shared.Backup;
using DeskGuest.Shared.EndpointSecurity;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.HealthScoring;
using DeskGuest.Shared.Inventory;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.Monitoring;
using DeskGuest.Shared.Vulnerability;

namespace DeskGuest.Tests;

// RMM-28 — Endpoint health scoring (DEX-style), locally computed.
// The score IS its decomposition: components from the source
// systems' own shapes, weights from RMM-07 policy (versioned),
// unknowns excluded-and-labelled, snapshots immutable.
public static class Rmm28Kit
{
    public static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    public const string Scope = "co-1";
    public const string Dev = "dev-1";
    public const string Admin = "it-admin";

    public static MonitoringHealthInput Monitoring(string state = DeviceHealthStates.Healthy,
        DateTimeOffset? last = null, params HealthAlertEvent[] alerts) => new(
        new DeviceHealthView(Dev, state, last ?? T0, 7,
            alerts.Select(a => a.ConditionId).ToList(), "test view"),
        alerts);

    public static HealthAlertEvent Alert(string severity, string condition = "cond-1") => new(
        Guid.NewGuid().ToString("N"), Dev, condition, ConditionKinds.CpuHigh, severity,
        HealthAlertStates.Raised, T0, T0, 1, "test alert", null, null, null, null, "endpoint");

    public static ExposureWorkItem Exposure(string severity, bool kev = false,
        DateTimeOffset? slaDue = null, string state = ExposureStates.Open) => new(
        Id: ExposureWorkItem.IdFor(Dev, "CVE-2026-0001", "Widget") + "-" + Guid.NewGuid().ToString("N")[..6],
        Title: "Widget CVE", DeviceId: Dev, ScopeId: Scope, State: state, Owner: null,
        CreatedUtc: T0, UpdatedUtc: T0, ClosedUtc: null,
        CveId: "CVE-2026-0001", ProductName: "Widget",
        VulnerableVersions: new[] { "1.0" }, FixedInVersion: "2.0", FixedInOsBuild: null,
        CvssScore: 9.0, Severity: severity, IsKev: kev, Source: ExposureSources.Feed,
        FeedId: "feed-1", FeedContentHash: "abc", FirstSeenUtc: T0, LastSeenUtc: T0,
        SlaDueUtc: slaDue ?? T0.AddDays(30),
        PatchEntryId: null, RemediationRequestId: null, CompensatingControlId: null, Closure: null);

    public static FeedProvenance FreshFeed() =>
        new("feed-1", "local-import", 3, T0.AddDays(-1), T0.AddDays(-1), "hash", false, "feed fresh");

    public static FeedProvenance StaleFeed() =>
        new("feed-1", "local-import", 3, T0.AddDays(-30), T0.AddDays(-30), "hash", true,
            "STALE FEED: published 30 days ago");

    public static ExposureHealthInput ExposureInput(params ExposureWorkItem[] items) =>
        new(items, FreshFeed());

    public static BackupHealthFacts BackupOk() => new(
        Dev, T0.AddHours(-2), T0.AddHours(-2), "completed", 0, 3, 1_000_000,
        true, 55.0, false, T0);

    public static PostureHealthInput PostureOk() => new(
        new AvPostureReport(Dev, T0, new[]
        {
            new AvFinding("defender", AvPostureStates.Protected, "ok", "rmm17-av-protected", ConditionKinds.SecurityAvOff),
        }, true),
        IsolationStatus.Normal());

    public static DeviceInventoryRecord Inventory(DateTimeOffset? purchase = null,
        WarrantyInfo? warranty = null, DateTimeOffset? lastSeen = null) => new(
        Dev, Scope, "WS-1",
        new HardwareSnapshot("Dell Inc.", "OptiPlex 7010", "ABC1234", "Intel i7", 16,
            16_000_000_000, "Windows 11 Pro", "26100.1", "10.0.26100", "1.0",
            Array.Empty<DiskInfo>(), Array.Empty<PeripheralInfo>(), T0),
        Array.Empty<SoftwareItem>(), new Dictionary<string, string>(), new HashSet<string>(),
        T0.AddYears(-1), lastSeen ?? T0, T0, 4,
        PurchaseDateUtc: purchase ?? T0.AddYears(-1),
        Warranty: warranty ?? new WarrantyInfo("dell", "ABC1234", WarrantyInfo.StatusActive,
            T0.AddYears(2), "ProSupport", T0));

    public static HealthScoreInputs AllGood() => new(
        Monitoring(), ExposureInput(), BackupOk(), PostureOk(), Inventory());

    public static DeviceHealthScore Score(HealthScoreInputs inputs,
        HealthScoreWeights? weights = null, DateTimeOffset? now = null) =>
        HealthScoreEngine.Compute(Dev, Scope, inputs,
            weights ?? HealthScoreWeightsPolicy.Default, HealthStalenessBounds.Default, now ?? T0);

    public static HealthScoringService Service(
        FakeMonitoringFactsSource? mon = null, FakeExposureFactsSource? exp = null,
        FakeBackupHealthFactsProvider? bak = null, FakePostureFactsSource? pos = null,
        FakeInventoryFactsSource? inv = null, ManagementPolicyEngine? policy = null,
        ChainedAuditLog? audit = null, HealthScoreStore? store = null,
        Func<DateTimeOffset>? now = null)
    {
        audit ??= new ChainedAuditLog();
        policy ??= new ManagementPolicyEngine();
        return new HealthScoringService(audit, policy,
            id => StaticDeviceFacts.Of(id, Scope),
            mon, exp, bak, pos, inv, store, now ?? (() => T0));
    }

    public static (FakeMonitoringFactsSource, FakeExposureFactsSource, FakeBackupHealthFactsProvider,
        FakePostureFactsSource, FakeInventoryFactsSource) AllGoodFakes()
    {
        var inputs = AllGood();
        return (
            new FakeMonitoringFactsSource().Set(Dev, inputs.Monitoring!),
            new FakeExposureFactsSource().Set(Dev, inputs.Exposure!),
            new FakeBackupHealthFactsProvider().Set(inputs.Backup!),
            new FakePostureFactsSource().Set(Dev, inputs.Posture!),
            new FakeInventoryFactsSource().Set(inputs.Inventory!));
    }
}

public class Rmm28Tests
{
    private static readonly DateTimeOffset T0 = Rmm28Kit.T0;
    private const string Dev = Rmm28Kit.Dev;

    // ---- the happy path: a fully-known, healthy device -------------------

    [Fact]
    public void AllSourcesHealthy_ScoreIsComplete100_WithFullDecomposition()
    {
        var s = Rmm28Kit.Score(Rmm28Kit.AllGood());
        Assert.Equal(HealthScoreStates.Complete, s.State);
        Assert.Equal(100.0, s.Aggregate);
        Assert.Equal(1.0, s.CoverageFraction);
        Assert.Equal("default-1", s.WeightsVersion);
        Assert.Null(s.AggregateCapReason);
        Assert.Empty(s.UnknownComponents);
        Assert.Equal(5, s.Components.Count);
        foreach (var c in s.Components)
        {
            Assert.Equal(ComponentScoreStates.Scored, c.State);
            Assert.Equal(100.0, c.Value);
            Assert.NotEmpty(c.Facts);
            Assert.NotNull(c.InputTimestampUtc);
        }
        Assert.Null(HealthScoreIntegrity.Validate(s));
    }

    [Fact]
    public void Score_CarriesWeightsAndFactsPerComponent()
    {
        var s = Rmm28Kit.Score(Rmm28Kit.AllGood());
        var exposure = s.Component(HealthComponents.Exposure)!;
        Assert.Equal(0.30, exposure.Weight);
        Assert.Equal("0", exposure.FactValue("open_critical"));
        Assert.Equal("feed-1", exposure.FactValue("feed_id"));
        var monitoring = s.Component(HealthComponents.Monitoring)!;
        Assert.Equal(DeviceHealthStates.Healthy, monitoring.FactValue("health_state"));
    }

    // ---- component maths ---------------------------------------------------

    [Fact]
    public void Monitoring_CriticalAlertDeducts_WarningDeductsLess()
    {
        var crit = Rmm28Kit.Score(Rmm28Kit.AllGood() with
        {
            Monitoring = Rmm28Kit.Monitoring(DeviceHealthStates.Alerting, null,
                Rmm28Kit.Alert(AlertSeverities.Critical)),
        });
        Assert.Equal(60.0, crit.Component(HealthComponents.Monitoring)!.Value);

        var warn = Rmm28Kit.Score(Rmm28Kit.AllGood() with
        {
            Monitoring = Rmm28Kit.Monitoring(DeviceHealthStates.Alerting, null,
                Rmm28Kit.Alert(AlertSeverities.Warning), Rmm28Kit.Alert(AlertSeverities.Warning, "cond-2")),
        });
        Assert.Equal(70.0, warn.Component(HealthComponents.Monitoring)!.Value);
    }

    [Fact]
    public void Monitoring_DegradedMonitor_Is40_NotHealthy()
    {
        var s = Rmm28Kit.Score(Rmm28Kit.AllGood() with
        {
            Monitoring = Rmm28Kit.Monitoring(DeviceHealthStates.Degraded),
        });
        Assert.Equal(40.0, s.Component(HealthComponents.Monitoring)!.Value);
    }

    [Fact]
    public void Exposure_DeductionsBySeverity_KevAndOverdueCostExtra()
    {
        var s = Rmm28Kit.Score(Rmm28Kit.AllGood() with
        {
            Exposure = Rmm28Kit.ExposureInput(
                Rmm28Kit.Exposure("high"),
                Rmm28Kit.Exposure("medium", kev: true, slaDue: T0.AddDays(-1))),
        });
        // 100 - 20 (high) - 8 (medium) - 15 (kev) - 10 (overdue) = 47
        Assert.Equal(47.0, s.Component(HealthComponents.Exposure)!.Value);
        Assert.Equal("1", s.Component(HealthComponents.Exposure)!.FactValue("open_kev"));
        Assert.Equal("1", s.Component(HealthComponents.Exposure)!.FactValue("open_overdue"));
    }

    [Fact]
    public void Backup_NeverRan_Is25_CatalogueTampered_Is0()
    {
        var never = Rmm28Kit.Score(Rmm28Kit.AllGood() with
        {
            Backup = new BackupHealthFacts(Dev, null, null, null, 0, 0, 0, true, null, false, T0),
        });
        Assert.Equal(25.0, never.Component(HealthComponents.Backup)!.Value);

        var tampered = Rmm28Kit.Score(Rmm28Kit.AllGood() with
        {
            Backup = Rmm28Kit.BackupOk() with { CatalogueTampered = true },
        });
        Assert.Equal(0.0, tampered.Component(HealthComponents.Backup)!.Value);
    }

    [Fact]
    public void Posture_GapWithProtection_Is70_NoProtection_Is10_IsolatedCapsComponent()
    {
        // CONV-F4 AMENDED (disposition c — cross-directive input
        // change): this fixture originally expressed the gap as
        // "defender protected + other disabled, no required
        // product" and expected 70. That encoded RMM-17's PRE-D38
        // HasGap, under which any non-protected finding beside a
        // protected product held HasGap true (rmm17-findings.md
        // F9). RMM-17's gated D38-F9 fix (FL-17, ledger D17-09)
        // deliberately re-keyed HasGap: a gap is now
        // nothing-protected OR the org's REQUIRED product not
        // protected (AvPostureReport.HasGap in
        // EndpointSecurity.cs) — a non-required finding beside a
        // protected product is a finding, not a gap. The 70 branch
        // (AnyProtected && HasGap) is unchanged in this engine;
        // the fixture now expresses a real gap under the gated
        // semantics by making the disabled product the required
        // one, and pins the superseded shape at its gated value.
        var gap = Rmm28Kit.Score(Rmm28Kit.AllGood() with
        {
            Posture = new PostureHealthInput(
                new AvPostureReport(Dev, T0, new[]
                {
                    new AvFinding("defender", AvPostureStates.Protected, "ok", "c1", ConditionKinds.SecurityAvOff),
                    new AvFinding("other", AvPostureStates.Disabled, "off", "c2", ConditionKinds.SecurityAvOff),
                }, true, RequiredProductId: "other"),
                IsolationStatus.Normal()),
        });
        Assert.Equal("true", gap.Component(HealthComponents.Posture)!.FactValue("has_gap"));
        Assert.Equal(70.0, gap.Component(HealthComponents.Posture)!.Value);

        // The pre-F9 fixture shape under the gated semantics: no
        // required product, one product protected — HasGap is
        // false and the component scores a full 100 (the disabled
        // non-required product remains a recorded finding; it is
        // not a gap). If RMM-17's HasGap ever reverts, this fails.
        var nonRequired = Rmm28Kit.Score(Rmm28Kit.AllGood() with
        {
            Posture = new PostureHealthInput(
                new AvPostureReport(Dev, T0, new[]
                {
                    new AvFinding("defender", AvPostureStates.Protected, "ok", "c1", ConditionKinds.SecurityAvOff),
                    new AvFinding("other", AvPostureStates.Disabled, "off", "c2", ConditionKinds.SecurityAvOff),
                }, true),
                IsolationStatus.Normal()),
        });
        Assert.Equal("false", nonRequired.Component(HealthComponents.Posture)!.FactValue("has_gap"));
        Assert.Equal(100.0, nonRequired.Component(HealthComponents.Posture)!.Value);

        // No protection at all, with a disabled product present:
        // the 10 branch the test name has always claimed.
        var none = Rmm28Kit.Score(Rmm28Kit.AllGood() with
        {
            Posture = new PostureHealthInput(
                new AvPostureReport(Dev, T0, new[]
                {
                    new AvFinding("other", AvPostureStates.Disabled, "off", "c2", ConditionKinds.SecurityAvOff),
                }, false),
                IsolationStatus.Normal()),
        });
        Assert.Equal(10.0, none.Component(HealthComponents.Posture)!.Value);

        var isolated = Rmm28Kit.Score(Rmm28Kit.AllGood() with
        {
            Posture = Rmm28Kit.PostureOk() with
            {
                Isolation = new IsolationStatus(IsolationStates.Isolated, T0, "ransomware", "banner",
                    Array.Empty<DeskGuestChannelExemption>()),
            },
        });
        Assert.Equal(20.0, isolated.Component(HealthComponents.Posture)!.Value);
        Assert.Equal(IsolationStates.Isolated,
            isolated.Component(HealthComponents.Posture)!.FactValue("isolation_state"));
    }

    [Fact]
    public void Inventory_OldDeviceExpiredWarranty_ScoresLow_UnrecordedPurchase_IsNamedDeduction()
    {
        var old = Rmm28Kit.Score(Rmm28Kit.AllGood() with
        {
            Inventory = Rmm28Kit.Inventory(purchase: T0.AddYears(-8),
                warranty: new WarrantyInfo("dell", "ABC1234", WarrantyInfo.StatusExpired,
                    T0.AddYears(-1), "ProSupport", T0)),
        });
        // 100 - 40 (age > 7y) - 30 (warranty expired) = 30
        Assert.Equal(30.0, old.Component(HealthComponents.Inventory)!.Value);
        Assert.Equal("8.0", old.Component(HealthComponents.Inventory)!.FactValue("device_age_years"));
    }

    // ---- unknown discipline --------------------------------------------------

    [Fact]
    public void MissingSource_ComponentUnknown_AggregatePartial_CoverageShown()
    {
        var s = Rmm28Kit.Score(Rmm28Kit.AllGood() with { Backup = null });
        Assert.Equal(HealthScoreStates.Partial, s.State);
        Assert.Equal(new[] { HealthComponents.Backup }, s.UnknownComponents);
        var backup = s.Component(HealthComponents.Backup)!;
        Assert.Equal(ComponentScoreStates.Unknown, backup.State);
        Assert.Null(backup.Value);
        Assert.False(string.IsNullOrWhiteSpace(backup.UnknownReason));
        // Known weight = 1.0 - 0.20 = 0.80; aggregate over known only.
        Assert.Equal(0.8, s.CoverageFraction);
        Assert.Equal(100.0, s.Aggregate);
    }

    [Fact]
    public void AllSourcesMissing_AggregateIsNull_NotZeroNotHundred()
    {
        var s = Rmm28Kit.Score(new HealthScoreInputs(null, null, null, null, null));
        Assert.Null(s.Aggregate);
        Assert.Equal(0.0, s.CoverageFraction);
        Assert.Equal(HealthScoreStates.Partial, s.State);
        Assert.Equal(5, s.UnknownComponents.Count);
    }

    [Fact]
    public void StaleMonitoring_UnknownNotTrusted()
    {
        var s = Rmm28Kit.Score(Rmm28Kit.AllGood() with
        {
            Monitoring = Rmm28Kit.Monitoring(last: T0.AddHours(-2)),
        });
        var mon = s.Component(HealthComponents.Monitoring)!;
        Assert.Equal(ComponentScoreStates.Unknown, mon.State);
        Assert.Contains("staleness bound", mon.UnknownReason);
    }

    [Fact]
    public void StaleFeed_ExposureUnknown_EvenWithNoOpenItems()
    {
        var s = Rmm28Kit.Score(Rmm28Kit.AllGood() with
        {
            Exposure = new ExposureHealthInput(Array.Empty<ExposureWorkItem>(), Rmm28Kit.StaleFeed()),
        });
        var exp = s.Component(HealthComponents.Exposure)!;
        Assert.Equal(ComponentScoreStates.Unknown, exp.State);
        Assert.Contains("STALE", exp.UnknownReason);
        Assert.Equal(HealthScoreStates.Partial, s.State);
    }

    [Fact]
    public void NoFeedImported_ExposureUnknown()
    {
        var s = Rmm28Kit.Score(Rmm28Kit.AllGood() with
        {
            Exposure = new ExposureHealthInput(Array.Empty<ExposureWorkItem>(),
                FeedProvenance.None(T0)),
        });
        Assert.Equal(ComponentScoreStates.Unknown,
            s.Component(HealthComponents.Exposure)!.State);
    }

    [Fact]
    public void NeverReportedDevice_MonitoringUnknown()
    {
        var s = Rmm28Kit.Score(Rmm28Kit.AllGood() with
        {
            Monitoring = new MonitoringHealthInput(
                new DeviceHealthView(Dev, DeviceHealthStates.Unknown, null, 0,
                    Array.Empty<string>(), "no health report ever received"),
                Array.Empty<HealthAlertEvent>()),
        });
        Assert.Equal(ComponentScoreStates.Unknown,
            s.Component(HealthComponents.Monitoring)!.State);
    }

    // ---- weights are policy ---------------------------------------------------

    [Fact]
    public void Weights_ParseDefaults_AndCustomVersionIsDerivedAndStable()
    {
        var engine = new ManagementPolicyEngine();
        var facts = StaticDeviceFacts.Of(Dev, Rmm28Kit.Scope);
        var (def, defRefusals) = HealthScoreWeightsPolicy.Parse(engine.ComputeEffective(facts));
        Assert.Empty(defRefusals);
        Assert.Equal("default-1", def!.Version);

        var doc = new ManagementPolicyDocument("w-doc", PolicyLevels.Org, Rmm28Kit.Scope,
            new Dictionary<string, string> { ["rmm.health_scoring.weight.backup"] = "0.5" }, 1);
        Assert.True(engine.AddDocument(doc).Allowed);
        var (custom, _) = HealthScoreWeightsPolicy.Parse(engine.ComputeEffective(facts));
        Assert.StartsWith("custom-", custom!.Version);
        Assert.Equal(0.5, custom.WeightOf(HealthComponents.Backup));
        var (again, _) = HealthScoreWeightsPolicy.Parse(engine.ComputeEffective(facts));
        Assert.Equal(custom.Version, again!.Version);
    }

    [Fact]
    public void Weights_ExplicitVersionWins_MalformedRefusedByName()
    {
        var engine = new ManagementPolicyEngine();
        var facts = StaticDeviceFacts.Of(Dev, Rmm28Kit.Scope);
        Assert.True(engine.AddDocument(new ManagementPolicyDocument("w-doc", PolicyLevels.Org,
            Rmm28Kit.Scope, new Dictionary<string, string>
            {
                ["rmm.health_scoring.weights_version"] = "fleet-2026-q4",
                ["rmm.health_scoring.weight.monitoring"] = "0.4",
            }, 1)).Allowed);
        var (w, refusals) = HealthScoreWeightsPolicy.Parse(engine.ComputeEffective(facts));
        Assert.Empty(refusals);
        // FL-28a (F4) AMENDED: this test previously asserted the
        // explicit string wins verbatim ("fleet-2026-q4") — that
        // baked in the defect. The version is now content-bound:
        // "<label>@<canonical content hash>".
        Assert.StartsWith("fleet-2026-q4@", w!.Version);

        var bad = new ManagementPolicyEngine();
        Assert.True(bad.AddDocument(new ManagementPolicyDocument("w-bad", PolicyLevels.Org,
            Rmm28Kit.Scope, new Dictionary<string, string>
            { ["rmm.health_scoring.weight.backup"] = "lots" }, 1)).Allowed);
        var (w2, refusals2) = HealthScoreWeightsPolicy.Parse(bad.ComputeEffective(facts));
        Assert.Null(w2);
        Assert.Contains(refusals2, r => r.Contains("not a number"));
    }

    [Fact]
    public void CustomWeights_ChangeTheAggregate_AndScoreRecordsTheVersion()
    {
        var weights = new HealthScoreWeights("heavy-monitoring", new Dictionary<string, double>
        {
            [HealthComponents.Monitoring] = 0.9, [HealthComponents.Exposure] = 0.025,
            [HealthComponents.Backup] = 0.025, [HealthComponents.Posture] = 0.025,
            [HealthComponents.Inventory] = 0.025,
        });
        var inputs = Rmm28Kit.AllGood() with
        {
            Monitoring = Rmm28Kit.Monitoring(DeviceHealthStates.Alerting, null,
                Rmm28Kit.Alert(AlertSeverities.Critical)),
        };
        var s = Rmm28Kit.Score(inputs, weights);
        Assert.Equal("heavy-monitoring", s.WeightsVersion);
        // monitoring 60 * 0.9 + 100 * 0.1 = 64
        Assert.Equal(64.0, s.Aggregate);
    }

    // ---- snapshots, history, trend --------------------------------------------

    [Fact]
    public void Store_KeepsSnapshots_HistoryAndLatestAreAsRecorded()
    {
        var store = new HealthScoreStore();
        var s1 = Rmm28Kit.Score(Rmm28Kit.AllGood());
        var s2 = Rmm28Kit.Score(Rmm28Kit.AllGood() with { Backup = null }, now: T0.AddDays(1));
        Assert.True(store.Add(s1).Ok);
        Assert.True(store.Add(s2).Ok);
        Assert.Equal(2, store.Count);
        Assert.Equal(s2.ContentHash, store.Latest(Dev)!.ContentHash);
        Assert.Equal(2, store.History(Dev).Count);
        Assert.False(store.Add(s1).Ok); // exact duplicate refused
    }

    [Fact]
    public void Store_ExportImport_RoundTripsVerbatim()
    {
        var store = new HealthScoreStore();
        var s = Rmm28Kit.Score(Rmm28Kit.AllGood());
        var json = store.Export(s);
        var store2 = new HealthScoreStore();
        var (ok, _, imported) = store2.Import(json, T0); // W16: explicit clock — no-now Import read the wall clock in AddImported's gate
        Assert.True(ok);
        Assert.Equal(s.ContentHash, imported!.ContentHash);
        Assert.Equal(s.Aggregate, imported.Aggregate);
    }

    [Fact]
    public void Trend_DeltaWithinSameWeightsVersion_VersionChangeNamedNotRecomputed()
    {
        var store = new HealthScoreStore();
        var w2 = HealthScoreWeightsPolicy.Default with { Version = "v2" };
        Assert.True(store.Add(Rmm28Kit.Score(Rmm28Kit.AllGood())).Ok); // 100 under default-1
        var degraded = Rmm28Kit.AllGood() with
        {
            Monitoring = Rmm28Kit.Monitoring(DeviceHealthStates.Degraded),
        };
        Assert.True(store.Add(Rmm28Kit.Score(degraded, w2, T0.AddMinutes(30))).Ok);
        Assert.True(store.Add(Rmm28Kit.Score(Rmm28Kit.AllGood(), w2, T0.AddMinutes(45))).Ok);
        var trend = HealthTrendBuilder.Build(Dev, store.History(Dev));
        Assert.Equal(3, trend.Points.Count);
        // Trailing v2 run: degraded score -> 100. Degraded monitoring:
        // (40*.25 + 100*.75) = 85 → delta = 100 - 85 = 15.
        Assert.Equal(15.0, trend.SameVersionDelta);
        Assert.Contains(trend.Notes, n => n.Contains("weights version changed"));
        // History is verbatim: the first point still records default-1.
        Assert.Equal("default-1", trend.Points[0].WeightsVersion);
    }

    // ---- fleet report ------------------------------------------------------------

    [Fact]
    public void FleetReport_DistributionAndWorstFirst_WithDecomposition()
    {
        var good = Rmm28Kit.Score(Rmm28Kit.AllGood());
        var badInputs = Rmm28Kit.AllGood() with
        {
            Monitoring = Rmm28Kit.Monitoring(DeviceHealthStates.Down),
            Backup = null,
        };
        var bad = Rmm28Kit.Score(badInputs) with { DeviceId = "dev-2" };
        var report = HealthFleetReportBuilder.Build(new[] { good, bad }, Rmm28Kit.Scope, T0);
        Assert.Equal(1, report.Distribution["excellent_90_100"]);
        Assert.Equal(1, report.PartialCount);
        Assert.Equal("dev-2", report.WorstFirst[0].DeviceId);
        Assert.Equal(5, report.WorstFirst[0].Components.Count); // decomposition rides the listing
        Assert.Contains("rmm01.monitoring", report.Header.Inputs.Select(i => i.Source));
    }

    // ---- service -------------------------------------------------------------------

    [Fact]
    public void Service_ComputeScore_SnapshotsAndAudits()
    {
        var audit = new ChainedAuditLog();
        var (mon, exp, bak, pos, inv) = Rmm28Kit.AllGoodFakes();
        var svc = Rmm28Kit.Service(mon, exp, bak, pos, inv, audit: audit);
        var outcome = svc.ComputeScore(Dev, Rmm28Kit.Admin);
        Assert.True(outcome.Ok);
        Assert.Equal(100.0, outcome.Score!.Aggregate);
        Assert.NotNull(svc.Latest(Dev));
        Assert.Contains(audit.Entries, e => e.Kind == "health_score_computed");
        Assert.True(audit.Verify().Ok);
    }

    [Fact]
    public void Service_PolicyOff_RefusesByName_AndAuditsRefusal()
    {
        var audit = new ChainedAuditLog();
        var policy = new ManagementPolicyEngine();
        Assert.True(policy.AddDocument(new ManagementPolicyDocument("off", PolicyLevels.Org,
            Rmm28Kit.Scope, new Dictionary<string, string>
            { ["rmm.health_scoring.enabled"] = "false" }, 1)).Allowed);
        var (mon, exp, bak, pos, inv) = Rmm28Kit.AllGoodFakes();
        var svc = Rmm28Kit.Service(mon, exp, bak, pos, inv, policy, audit);
        var outcome = svc.ComputeScore(Dev, Rmm28Kit.Admin);
        Assert.False(outcome.Ok);
        Assert.Contains("OFF by policy", outcome.Reason);
        Assert.Null(svc.Latest(Dev));
        Assert.Contains(audit.Entries, e => e.Kind == "health_score_refused");
    }

    [Fact]
    public void Service_UnwiredSources_ScorePartialWithUnknownsNamed()
    {
        var svc = Rmm28Kit.Service(); // no sources wired at all
        var outcome = svc.ComputeScore(Dev, Rmm28Kit.Admin);
        Assert.True(outcome.Ok);
        Assert.Null(outcome.Score!.Aggregate);
        Assert.Equal(5, outcome.Score.UnknownComponents.Count);
    }

    [Fact]
    public void Service_WeightsFromPolicy_VersionRecordedOnScore()
    {
        var policy = new ManagementPolicyEngine();
        Assert.True(policy.AddDocument(new ManagementPolicyDocument("w", PolicyLevels.Org,
            Rmm28Kit.Scope, new Dictionary<string, string>
            { ["rmm.health_scoring.weights_version"] = "site-policy-7" }, 1)).Allowed);
        var (mon, exp, bak, pos, inv) = Rmm28Kit.AllGoodFakes();
        var svc = Rmm28Kit.Service(mon, exp, bak, pos, inv, policy);
        var outcome = svc.ComputeScore(Dev, Rmm28Kit.Admin);
        Assert.True(outcome.Ok);
        // FL-28a (F4) AMENDED: was Assert.Equal("site-policy-7") —
        // baked in the explicit-string-wins defect; the recorded
        // version is now the label bound to the weights content.
        Assert.StartsWith("site-policy-7@", outcome.Score!.WeightsVersion);
    }

    [Fact]
    public void Service_Adapters_OverRealSourceShapes()
    {
        // RMM-01 hub ingest + centre, RMM-05 store, RMM-04 store —
        // the real shapes, wired through the service's adapters.
        var audit = new ChainedAuditLog();
        var centre = new HealthAlertCentre(audit, new AlertCenter());
        var ingest = new HubHealthIngest(centre, TimeSpan.FromMinutes(15));
        var report = new DeviceHealthReport(Dev, 1, T0, "lib-1", "hash",
            MonitorStatuses.Ok, Array.Empty<string>(), Array.Empty<string>(),
            Array.Empty<HealthAlertEvent>());
        Assert.True(ingest.Ingest(report, T0).Accepted);

        var exposures = new ExposureStore();
        var inventory = new InventoryStore();
        Assert.True(inventory.ApplyBaseline(Rmm28Kit.Inventory(), T0).Accepted);

        var svc = new HealthScoringService(audit, new ManagementPolicyEngine(),
            id => StaticDeviceFacts.Of(id, Rmm28Kit.Scope),
            new HubMonitoringFactsSource(ingest, centre),
            new ExposureStoreFactsSource(exposures, _ => Rmm28Kit.FreshFeed()),
            new FakeBackupHealthFactsProvider().Set(Rmm28Kit.BackupOk()),
            new FakePostureFactsSource().Set(Dev, Rmm28Kit.PostureOk()),
            new InventoryStoreFactsSource(inventory),
            now: () => T0);
        var outcome = svc.ComputeScore(Dev, Rmm28Kit.Admin);
        Assert.True(outcome.Ok);
        Assert.Equal(HealthScoreStates.Complete, outcome.Score!.State);
        // The inventory store pins Warranty=null on a baseline
        // (warranty is hub-filled, never device-carried — RMM-04's
        // own rule), so the inventory component honestly deducts
        // for unknown warranty: 100 - 10 = 90, and the aggregate
        // is 25 + 30 + 20 + 15 + (90 x 0.10) = 99. The scorer
        // composes the store's facts; it does not re-derive the
        // warranty the fixture asserted.
        var inv = outcome.Score.Component(HealthComponents.Inventory)!;
        Assert.Equal(90.0, inv.Value);
        Assert.Equal("(unknown)", inv.FactValue("warranty_status"));
        Assert.Equal(99.0, outcome.Score.Aggregate);
    }
}
