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

// FL-28b — permanent regressions for the D38 RMM-28 findings
// F7–F12 (verdict c0dd9dd5, reconciled in d38-sweep.md A4):
//   F7 unrecognised severities priced at 0
//   F8 backup staleness computed on query-time GeneratedUtc;
//      RMM-06 evaluator fed RMM-28's bound
//   F9 future timestamps counted as fresh
//   F10 warranty re-derived from ExpiresUtc, RetrievedUtc ignored
//   F11 fleet buckets ignored coverage
//   F12 no per-device error isolation; unbounded store; hash
//      recomputed per access; 0.11 integrity tolerance
// Each test fails against the pre-FL-28b code for the reason named
// in its comment.
public class Rmm28Fix2Tests
{
    private static readonly DateTimeOffset T0 = Rmm28Kit.T0;
    private const string Dev = Rmm28Kit.Dev;
    private const string Scope = Rmm28Kit.Scope;

    // ================= F7 — unrecognised severity ==============

    // Pre-fix: an item whose severity matched no pricing bucket
    // cost exactly 0 and left no fact — it was silently free.
    [Fact]
    public void F7_UnrecognisedSeverity_ExposureUnknown_WithOpenUnclassifiedFact()
    {
        var s = Rmm28Kit.Score(Rmm28Kit.AllGood() with
        {
            Exposure = Rmm28Kit.ExposureInput(Rmm28Kit.Exposure("catastrophic")),
        });
        var exp = s.Component(HealthComponents.Exposure)!;
        Assert.Equal(ComponentScoreStates.Unknown, exp.State);
        Assert.Contains("unrecognised severity", exp.UnknownReason);
        Assert.Equal("1", exp.FactValue("open_unclassified"));
        Assert.Null(HealthScoreIntegrity.Validate(s));
    }

    // Control: a recognised "none" severity still scores clean.
    [Fact]
    public void F7_RecognisedNoneSeverity_StillScores()
    {
        var s = Rmm28Kit.Score(Rmm28Kit.AllGood() with
        {
            Exposure = Rmm28Kit.ExposureInput(Rmm28Kit.Exposure("none")),
        });
        var exp = s.Component(HealthComponents.Exposure)!;
        Assert.Equal(ComponentScoreStates.Scored, exp.State);
        Assert.Equal("0", exp.FactValue("open_unclassified"));
    }

    // ================= F8 — backup staleness ===================

    // Pre-fix: staleness was `now - GeneratedUtc`, and the facts
    // provider stamps GeneratedUtc with the QUERY time — so a
    // backup whose last success was 10 days ago scored fresh.
    [Fact]
    public void F8_StaleLastSuccess_Unknown_EvenThoughGeneratedUtcIsNow()
    {
        var s = Rmm28Kit.Score(Rmm28Kit.AllGood() with
        {
            Backup = Rmm28Kit.BackupOk() with
            {
                LastAttemptUtc = T0.AddDays(-10),
                LastSuccessUtc = T0.AddDays(-10),
                GeneratedUtc = T0,
            },
        });
        var bak = s.Component(HealthComponents.Backup)!;
        Assert.Equal(ComponentScoreStates.Unknown, bak.State);
        Assert.Contains("last successful backup", bak.UnknownReason);
    }

    // Pre-fix: findings were evaluated under RMM-28's own bound
    // (72h here), so a 60h-old success produced no stale finding.
    // Under RMM-06's own bound (48h, the RMM-13 report's bound)
    // the same backup carries the stale warning and prices at 80.
    // (60h sits between the two bounds: fresh for the component
    // under the 72h RMM-28 bound, stale for the finding under
    // RMM-06's 48h bound — exactly the disagreement F8 named.)
    [Fact]
    public void F8_FindingsEvaluatedUnderRmm06Bound_NotRmm28Bound()
    {
        var inputs = Rmm28Kit.AllGood() with
        {
            Backup = Rmm28Kit.BackupOk() with
            {
                LastAttemptUtc = T0.AddHours(-60),
                LastSuccessUtc = T0.AddHours(-60),
            },
        };
        var bounds = new HealthStalenessBounds(
            TimeSpan.FromHours(1), TimeSpan.FromHours(72),
            TimeSpan.FromHours(24), TimeSpan.FromHours(72));
        var s = HealthScoreEngine.Compute(Dev, Scope, inputs,
            HealthScoreWeightsPolicy.Default, bounds, T0);
        var bak = s.Component(HealthComponents.Backup)!;
        Assert.Equal(ComponentScoreStates.Scored, bak.State);
        Assert.Equal(80.0, bak.Value);
        Assert.NotNull(bak.FactValue("finding:backup_stale"));
    }

    // ================= F9 — future timestamps ==================

    // Pre-fix: `now - ts` went negative for future timestamps, so
    // future-dated source data counted as fresh indefinitely.
    [Fact]
    public void F9_FutureMonitoringReport_Unknown_NotFresh()
    {
        var s = Rmm28Kit.Score(Rmm28Kit.AllGood() with
        {
            Monitoring = Rmm28Kit.Monitoring(last: T0.AddHours(2)),
        });
        var mon = s.Component(HealthComponents.Monitoring)!;
        Assert.Equal(ComponentScoreStates.Unknown, mon.State);
        Assert.Contains("FUTURE", mon.UnknownReason);
    }

    [Fact]
    public void F9_FutureBackupActivity_Unknown_NotFresh()
    {
        var s = Rmm28Kit.Score(Rmm28Kit.AllGood() with
        {
            Backup = Rmm28Kit.BackupOk() with
            {
                LastAttemptUtc = T0.AddHours(2),
                LastSuccessUtc = T0.AddHours(2),
            },
        });
        var bak = s.Component(HealthComponents.Backup)!;
        Assert.Equal(ComponentScoreStates.Unknown, bak.State);
        Assert.Contains("FUTURE", bak.UnknownReason);
    }

    [Fact]
    public void F9_FuturePostureAndInventory_Unknown_NotFresh()
    {
        var posture = new PostureHealthInput(
            new AvPostureReport(Dev, T0.AddHours(2), new[]
            {
                new AvFinding("defender", AvPostureStates.Protected, "ok", "rmm17-av-protected", ConditionKinds.SecurityAvOff),
            }, true),
            IsolationStatus.Normal());
        var s = Rmm28Kit.Score(Rmm28Kit.AllGood() with
        {
            Posture = posture,
            Inventory = Rmm28Kit.Inventory(lastSeen: T0.AddHours(2)),
        });
        Assert.Equal(ComponentScoreStates.Unknown, s.Component(HealthComponents.Posture)!.State);
        Assert.Contains("FUTURE", s.Component(HealthComponents.Posture)!.UnknownReason);
        Assert.Equal(ComponentScoreStates.Unknown, s.Component(HealthComponents.Inventory)!.State);
        Assert.Contains("FUTURE", s.Component(HealthComponents.Inventory)!.UnknownReason);
    }

    // ================= F10 — warranty ==========================

    // Pre-fix: warranty was re-derived from ExpiresUtc against
    // `now` — a record whose STATUS says active but whose expiry
    // date has passed was priced as expired (-30), contradicting
    // RMM-04's recorded verdict.
    [Fact]
    public void F10_WarrantyPricedFromRecordedStatus_NotReDerivedExpiry()
    {
        var activeButPastExpiry = new WarrantyInfo("dell", "ABC1234",
            WarrantyInfo.StatusActive, T0.AddDays(-10), "ProSupport", T0);
        var s = Rmm28Kit.Score(Rmm28Kit.AllGood() with
        {
            Inventory = Rmm28Kit.Inventory(warranty: activeButPastExpiry),
        });
        var inv = s.Component(HealthComponents.Inventory)!;
        Assert.Equal(ComponentScoreStates.Scored, inv.State);
        // Active status, expiring within 90 days per the recorded
        // expiry: the -15 expiring-soon deduction, not -30.
        Assert.Equal(85.0, inv.Value);
        Assert.Null(HealthScoreIntegrity.Validate(s));
    }

    // Pre-fix: RetrievedUtc was never consulted — a years-old
    // lookup priced as current truth.
    [Fact]
    public void F10_StaleWarrantyRetrieval_InventoryUnknown()
    {
        var staleLookup = new WarrantyInfo("dell", "ABC1234",
            WarrantyInfo.StatusActive, T0.AddYears(2), "ProSupport", T0.AddDays(-100));
        var s = Rmm28Kit.Score(Rmm28Kit.AllGood() with
        {
            Inventory = Rmm28Kit.Inventory(warranty: staleLookup),
        });
        var inv = s.Component(HealthComponents.Inventory)!;
        Assert.Equal(ComponentScoreStates.Unknown, inv.State);
        Assert.Contains("warranty", inv.UnknownReason);
    }

    // ================= F11 — fleet buckets by coverage =========

    // Pre-fix: a partial-coverage 100 landed in excellent_90_100
    // beside a complete 100 — the bucket mixed two different
    // kinds of claim.
    [Fact]
    public void F11_PartialCoverageScore_GetsItsOwnBucket()
    {
        var complete = Rmm28Kit.Score(Rmm28Kit.AllGood());
        var partial = Rmm28Kit.Score(
            Rmm28Kit.AllGood() with { Backup = null, Posture = null },
            now: T0.AddHours(1));
        Assert.Equal(100.0, partial.Aggregate);
        Assert.True(partial.CoverageFraction < 1.0);
        var report = HealthFleetReportBuilder.Build(
            new[] { complete, partial }, Scope, T0);
        Assert.Equal(1, report.Distribution["excellent_90_100"]);
        Assert.Equal(1, report.Distribution["excellent_90_100_partial_coverage"]);
    }

    // ================= F12 — isolation / bounds / hash / tol ===

    private sealed class ThrowingMonitoring : IMonitoringFactsSource
    {
        public MonitoringHealthInput? Get(string deviceId, DateTimeOffset now)
        {
            if (deviceId == "dev-2")
                throw new InvalidOperationException("boom-dev2");
            return Rmm28Kit.Monitoring();
        }
    }

    // Pre-fix: a throwing facts source propagated out of
    // ComputeScore and aborted the whole ComputeFleet run.
    [Fact]
    public void F12_ThrowingSource_IsolatedToItsDevice_FleetContinues()
    {
        var (_, exp, bak, pos, inv) = Rmm28Kit.AllGoodFakes();
        var svc = new HealthScoringService(
            new ChainedAuditLog(), new ManagementPolicyEngine(),
            id => StaticDeviceFacts.Of(id, Scope),
            new ThrowingMonitoring(), exp, bak, pos, inv, null, () => T0);
        var (report, refusals) = svc.ComputeFleet(
            new[] { "dev-2", Dev }, Scope, Rmm28Kit.Admin);
        Assert.Contains(refusals, r => r.StartsWith("dev-2:") && r.Contains("boom-dev2"));
        Assert.Contains(report.WorstFirst, s => s.DeviceId == Dev);
        Assert.DoesNotContain(report.WorstFirst, s => s.DeviceId == "dev-2");
    }

    // Pre-fix: the snapshot store grew without bound.
    [Fact]
    public void F12_StoreRetention_CapsSnapshotsPerDevice_DroppingOldest()
    {
        var store = new HealthScoreStore();
        for (var i = 0; i < HealthScoreStore.MaxSnapshotsPerDevice + 1; i++)
        {
            var (ok, reason) = store.Add(Rmm28Kit.Score(
                Rmm28Kit.AllGood(), now: T0.AddMinutes(i)));
            Assert.True(ok, reason);
        }
        Assert.Equal(HealthScoreStore.MaxSnapshotsPerDevice, store.Count);
        var history = store.History(Dev);
        Assert.Equal(HealthScoreStore.MaxSnapshotsPerDevice, history.Count);
        Assert.Equal(T0.AddMinutes(1), history[0].ComputedUtc);
    }

    // Pre-fix: ContentHash recomputed from scratch per access.
    // Behavioural pin: repeated access is stable, matches the
    // canonical computation, and a `with` copy recomputes.
    [Fact]
    public void F12_ContentHash_StableAcrossAccesses_AndBoundToContent()
    {
        var s = Rmm28Kit.Score(Rmm28Kit.AllGood());
        var h1 = s.ContentHash;
        Assert.Equal(h1, s.ContentHash);
        Assert.Equal(HealthScoreHash.Compute(s), h1);
        var edited = s with { Aggregate = 42.0 };
        Assert.NotEqual(h1, edited.ContentHash);
    }

    // Pre-fix: tolerance 0.11 let an aggregate drift 0.08 from its
    // own decomposition and still validate.
    [Fact]
    public void F12_IntegrityTolerance_Tightened_DriftOfPoint08Refused()
    {
        var s = Rmm28Kit.Score(Rmm28Kit.AllGood());
        var tampered = s with { Aggregate = 99.92 };
        var refusal = HealthScoreIntegrity.Validate(tampered);
        Assert.NotNull(refusal);
        Assert.Contains("aggregate mismatch", refusal);
    }
}
