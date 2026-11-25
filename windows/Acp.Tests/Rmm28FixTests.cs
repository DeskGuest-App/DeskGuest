using System.Security.Cryptography;
using Acp.Core.Services;
using Acp.Shared.Enterprise;
using Acp.Shared.HealthScoring;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Monitoring;
using Acp.Shared.Vulnerability;

namespace Acp.Tests;

// FL-28a — permanent regression tests for the RMM-28 D38 blocker
// fixes (sweep verdict c0dd9dd5, findings F1–F6). Each test names
// the finding it pins.
public class Rmm28FixTests
{
    private static readonly DateTimeOffset T0 = Rmm28Kit.T0;
    private const string Dev = Rmm28Kit.Dev;
    private static readonly byte[] HubKey = SHA256.HashData("fl28a-test-hub-key"u8.ToArray());

    // ---- F1: fact-level integrity re-pricing -------------------------------

    [Fact]
    public void F1_Integrity_ComponentValueInflatedAgainstFacts_Refused()
    {
        // Attack the old integrity check could not see: inflate a
        // component VALUE and raise the aggregate to match, leaving
        // the facts honest. Aggregate-from-components recomputes
        // clean; facts-to-component re-pricing must refuse.
        var honest = Rmm28Kit.Score(Rmm28Kit.AllGood() with
        {
            Exposure = Rmm28Kit.ExposureInput(Rmm28Kit.Exposure("high")),
        });
        Assert.Equal(80.0, honest.Component(HealthComponents.Exposure)!.Value);
        Assert.Equal(94.0, honest.Aggregate);
        var forged = honest with
        {
            Aggregate = 100.0,
            Components = honest.Components.Select(c => c.Component == HealthComponents.Exposure
                ? c with { Value = 100.0 } : c).ToList(),
        };
        var refusal = HealthScoreIntegrity.Validate(forged);
        Assert.NotNull(refusal);
        Assert.Contains("component value mismatch", refusal);
        Assert.Contains("re-price", refusal);
        Assert.False(new HealthScoreStore().Add(forged).Ok);
    }

    [Fact]
    public void F1_Integrity_MissingCapFact_RefusedNotPricedAsZero()
    {
        // A scored exposure component whose open_critical fact was
        // stripped: the old FactInt priced the missing fact as 0
        // and the cap vanished. Now the snapshot refuses by name.
        var capped = Rmm28Kit.Score(Rmm28Kit.AllGood() with
        {
            Exposure = Rmm28Kit.ExposureInput(Rmm28Kit.Exposure("critical")),
        });
        Assert.Equal(49.0, capped.Aggregate);
        var stripped = capped with
        {
            // Uncapped aggregate over the remaining values, cap
            // reason erased — consistent with everything EXCEPT the
            // missing cap fact.
            Aggregate = 89.5,
            AggregateCapReason = null,
            Components = capped.Components.Select(c => c.Component == HealthComponents.Exposure
                ? c with { Facts = c.Facts.Where(f => f.Name != "open_critical").ToList() } : c).ToList(),
        };
        var refusal = HealthScoreIntegrity.Validate(stripped);
        Assert.NotNull(refusal);
        Assert.Contains("missing its cap facts", refusal);
    }

    [Fact]
    public void F1_KeyedStore_UnsignedImportRefused_SignedImportVerifies()
    {
        var score = Rmm28Kit.Score(Rmm28Kit.AllGood());

        var unkeyed = new HealthScoreStore();
        var unsignedJson = unkeyed.Export(score);

        var keyed = new HealthScoreStore(HubKey);
        var (okUnsigned, reasonUnsigned, _) = keyed.Import(unsignedJson, T0);
        Assert.False(okUnsigned);
        Assert.Contains("signature", reasonUnsigned);
        Assert.Equal(0, keyed.Count);

        var exporter = new HealthScoreStore(HubKey);
        Assert.True(exporter.Add(score).Ok);
        var signedJson = exporter.Export(exporter.Latest(Dev)!);
        var receiver = new HealthScoreStore(HubKey);
        var (ok, _, imported) = receiver.Import(signedJson, T0);
        Assert.True(ok);
        Assert.Equal(score.ContentHash, imported!.ContentHash);
        Assert.True(HealthScoreSigning.Verify(imported, HubKey));
    }

    [Fact]
    public void F1_KeyedStore_ForgedSignatureRefused_EvenWithValidHash()
    {
        var exporter = new HealthScoreStore(HubKey);
        Assert.True(exporter.Add(Rmm28Kit.Score(Rmm28Kit.AllGood())).Ok);
        var signedJson = exporter.Export(exporter.Latest(Dev)!);
        // Replace the signature with zeros: the public content hash
        // still matches its decomposition — only the keyed
        // signature stands between this and acceptance.
        var signed = exporter.Latest(Dev)!.Signature!;
        var forged = signedJson.Replace(signed, new string('0', signed.Length));
        Assert.NotEqual(signedJson, forged);
        var receiver = new HealthScoreStore(HubKey);
        var (ok, reason, _) = receiver.Import(forged, T0);
        Assert.False(ok);
        Assert.Contains("signature", reason);
        Assert.Equal(0, receiver.Count);
    }

    // ---- F2: caps on KNOWN facts regardless of scored state -----------------

    [Fact]
    public void F2_StaleFeedWithOpenCritical_CapsAggregate_DespiteExposureUnknown()
    {
        var s = Rmm28Kit.Score(Rmm28Kit.AllGood() with
        {
            Exposure = new ExposureHealthInput(
                new[] { Rmm28Kit.Exposure("critical") }, Rmm28Kit.StaleFeed()),
        });
        Assert.Equal(ComponentScoreStates.Unknown,
            s.Component(HealthComponents.Exposure)!.State);
        // Known components are all 100; without the cap the
        // aggregate would present 100. The KNOWN open critical
        // caps it at 49 even though the component is unscored.
        Assert.Equal(HealthScoreCaps.CriticalExposureCap, s.Aggregate);
        Assert.Contains("capped at 49", s.AggregateCapReason);
        Assert.Null(HealthScoreIntegrity.Validate(s));
    }

    [Fact]
    public void F2_StaleFeedWithOpenKev_CapsAggregate()
    {
        var s = Rmm28Kit.Score(Rmm28Kit.AllGood() with
        {
            Exposure = new ExposureHealthInput(
                new[] { Rmm28Kit.Exposure("low", kev: true) }, Rmm28Kit.StaleFeed()),
        });
        Assert.Equal(HealthScoreCaps.CriticalExposureCap, s.Aggregate);
        Assert.Contains("kev=1", s.AggregateCapReason);
    }

    // ---- F3: RMM-01 DOWN is authoritative regardless of report age -----------

    [Fact]
    public void F3_StaleDownReport_CapsAggregateAt39_DespiteMonitoringUnknown()
    {
        var s = Rmm28Kit.Score(Rmm28Kit.AllGood() with
        {
            Monitoring = Rmm28Kit.Monitoring(DeviceHealthStates.Down, last: T0.AddHours(-2)),
        });
        // RMM-28's own 1h staleness bound re-derives the component
        // UNKNOWN — but the recorded RMM-01 fact is DOWN, and the
        // ≤39 cap follows the fact, not the component state.
        Assert.Equal(ComponentScoreStates.Unknown,
            s.Component(HealthComponents.Monitoring)!.State);
        Assert.Equal(HealthScoreCaps.DeviceDownCap, s.Aggregate);
        Assert.Contains("DOWN", s.AggregateCapReason);
        Assert.Null(HealthScoreIntegrity.Validate(s));
    }

    // ---- F4: weights version is content-bound ---------------------------------

    [Fact]
    public void F4_ExplicitLabel_DifferentContent_DifferentVersions()
    {
        static string VersionFor(string monitoringWeight)
        {
            var engine = new ManagementPolicyEngine();
            Assert.True(engine.AddDocument(new ManagementPolicyDocument("w", PolicyLevels.Org,
                Rmm28Kit.Scope, new Dictionary<string, string>
                {
                    ["rmm.health_scoring.weights_version"] = "fleet-1",
                    ["rmm.health_scoring.weight.monitoring"] = monitoringWeight,
                }, 1)).Allowed);
            var (w, refusals) = HealthScoreWeightsPolicy.Parse(
                engine.ComputeEffective(StaticDeviceFacts.Of(Dev, Rmm28Kit.Scope)));
            Assert.Empty(refusals);
            return w!.Version;
        }
        var a = VersionFor("0.4");
        var b = VersionFor("0.5");
        Assert.StartsWith("fleet-1@", a);
        Assert.StartsWith("fleet-1@", b);
        Assert.NotEqual(a, b); // same label, different content — different version
        Assert.Equal(a, VersionFor("0.4")); // same content — same version, stable
    }

    [Fact]
    public void F4_Trend_BreaksOnRecordedWeightsContent_NotJustVersionString()
    {
        var wA = HealthScoreWeightsPolicy.Default with { Version = "vX" };
        var wB = new HealthScoreWeights("vX", new Dictionary<string, double>
        {
            [HealthComponents.Monitoring] = 0.9, [HealthComponents.Exposure] = 0.025,
            [HealthComponents.Backup] = 0.025, [HealthComponents.Posture] = 0.025,
            [HealthComponents.Inventory] = 0.025,
        });
        var store = new HealthScoreStore();
        Assert.True(store.Add(Rmm28Kit.Score(Rmm28Kit.AllGood(), wA)).Ok); // 100 under wA
        var degraded = Rmm28Kit.AllGood() with
        {
            Monitoring = Rmm28Kit.Monitoring(DeviceHealthStates.Degraded),
        };
        Assert.True(store.Add(Rmm28Kit.Score(degraded, wB, T0.AddMinutes(30))).Ok); // 46 under wB
        Assert.True(store.Add(Rmm28Kit.Score(Rmm28Kit.AllGood(), wB, T0.AddMinutes(45))).Ok); // 100 under wB
        var trend = HealthTrendBuilder.Build(Dev, store.History(Dev));
        // String-only grouping would run all three (delta 0). The
        // recorded-weights run is the trailing wB pair: 100 - 46.
        Assert.Equal(54.0, trend.SameVersionDelta);
        Assert.Contains(trend.Notes, n => n.Contains("weights CONTENT changed"));
    }

    // ---- F5: fleet reports honour scope + requested devices --------------------

    [Fact]
    public void F5_ComputeFleet_OnlyRequestedDevicesInScope()
    {
        var store = new HealthScoreStore();
        // Another device's snapshot and a same-device snapshot in
        // ANOTHER scope both sit in the store before the run.
        var other = Rmm28Kit.Score(Rmm28Kit.AllGood()) with { DeviceId = "dev-2" };
        Assert.True(store.Add(other).Ok);
        var foreignScope = Rmm28Kit.Score(Rmm28Kit.AllGood(), now: T0.AddHours(1)) with { ScopeId = "co-2" };
        Assert.True(store.Add(foreignScope).Ok);

        var (mon, exp, bak, pos, inv) = Rmm28Kit.AllGoodFakes();
        var svc = Rmm28Kit.Service(mon, exp, bak, pos, inv, store: store);
        var (report, refusals) = svc.ComputeFleet(new[] { Dev }, Rmm28Kit.Scope, Rmm28Kit.Admin);
        Assert.Empty(refusals);
        Assert.Single(report.WorstFirst);
        Assert.Equal(Dev, report.WorstFirst[0].DeviceId);
        Assert.Equal(Rmm28Kit.Scope, report.WorstFirst[0].ScopeId);
        Assert.Equal(1, report.Distribution["excellent_90_100"]);
    }

    [Fact]
    public void F5_ComputeFleet_RefusedThisRun_OldSnapshotExcludedAndNamed()
    {
        var store = new HealthScoreStore();
        Assert.True(store.Add(Rmm28Kit.Score(Rmm28Kit.AllGood())).Ok); // stale number on file
        var policy = new ManagementPolicyEngine();
        Assert.True(policy.AddDocument(new ManagementPolicyDocument("off", PolicyLevels.Org,
            Rmm28Kit.Scope, new Dictionary<string, string>
            { ["rmm.health_scoring.enabled"] = "false" }, 1)).Allowed);
        var (mon, exp, bak, pos, inv) = Rmm28Kit.AllGoodFakes();
        var svc = Rmm28Kit.Service(mon, exp, bak, pos, inv, policy, store: store);
        var (report, refusals) = svc.ComputeFleet(new[] { Dev }, Rmm28Kit.Scope, Rmm28Kit.Admin);
        Assert.Single(refusals);
        Assert.Empty(report.WorstFirst); // the old snapshot does NOT ride this run's report
        Assert.Equal(0, report.Distribution["excellent_90_100"]);
    }

    [Fact]
    public void F5_FleetReport_FiltersByScope()
    {
        var store = new HealthScoreStore();
        var foreignScope = Rmm28Kit.Score(Rmm28Kit.AllGood()) with { ScopeId = "co-2" };
        Assert.True(store.Add(foreignScope).Ok);
        var svc = Rmm28Kit.Service(store: store);
        Assert.Empty(svc.FleetReport(Rmm28Kit.Scope).WorstFirst);
        Assert.Single(svc.FleetReport("co-2").WorstFirst);
    }

    // ---- F6: import gates --------------------------------------------------------

    [Fact]
    public void F6_StoreImport_FutureDated_Refused()
    {
        var store = new HealthScoreStore();
        var json = store.Export(Rmm28Kit.Score(Rmm28Kit.AllGood()));
        var (ok, reason, _) = new HealthScoreStore().Import(json, now: T0.AddDays(-1));
        Assert.False(ok);
        Assert.Contains("future", reason);
    }

    [Fact]
    public void F6_StoreImport_ScopeMismatch_Refused()
    {
        var store = new HealthScoreStore();
        var json = store.Export(Rmm28Kit.Score(Rmm28Kit.AllGood()));
        var (ok, reason, _) = new HealthScoreStore().Import(json, T0, expectedScopeId: "co-999");
        Assert.False(ok);
        Assert.Contains("scope", reason);
    }

    [Fact]
    public void F6_Store_DuplicateDeviceTimestamp_DifferentContent_Refused()
    {
        var store = new HealthScoreStore();
        Assert.True(store.Add(Rmm28Kit.Score(Rmm28Kit.AllGood())).Ok);
        // Same device, same ComputedUtc, DIFFERENT decomposition —
        // the old duplicate check (identical hash only) admitted it.
        var rival = Rmm28Kit.Score(Rmm28Kit.AllGood() with { Backup = null });
        var (ok, reason) = store.Add(rival);
        Assert.False(ok);
        Assert.Contains("duplicate", reason);
        Assert.Equal(1, store.Count);
    }

    [Fact]
    public void F6_ImportedSnapshot_DoesNotShadowComputedLatest()
    {
        var store = new HealthScoreStore();
        var computed = Rmm28Kit.Score(Rmm28Kit.AllGood());
        Assert.True(store.Add(computed).Ok);
        // A LATER-dated import arrives (admitted at its own time):
        // Latest must still surface this hub's computed snapshot.
        var importedScore = Rmm28Kit.Score(Rmm28Kit.AllGood() with { Backup = null },
            now: T0.AddDays(10));
        var json = store.Export(importedScore);
        var (ok, _, admitted) = store.Import(json, now: T0.AddDays(10));
        Assert.True(ok);
        Assert.True(store.IsImported(admitted!));
        Assert.Equal(computed.ContentHash, store.Latest(Dev)!.ContentHash);
        Assert.Equal(computed.ContentHash, store.LatestAll().Single().ContentHash);
        Assert.Equal(2, store.History(Dev).Count); // history keeps both, verbatim
    }

    [Fact]
    public void F6_ServiceImport_AnonymousActor_AndFuture_AndUnknownDevice_Refused()
    {
        var svc = Rmm28Kit.Service();
        var json = new HealthScoreStore().Export(Rmm28Kit.Score(Rmm28Kit.AllGood()));

        var anon = svc.ImportSnapshot(json, "");
        Assert.False(anon.Ok);
        Assert.Contains("named actor", anon.Reason);

        var futureSvc = Rmm28Kit.Service(now: () => T0.AddDays(-1));
        var future = futureSvc.ImportSnapshot(json, Rmm28Kit.Admin);
        Assert.False(future.Ok);
        Assert.Contains("future", future.Reason);

        // A service whose device directory knows dev-1 only.
        var strict = new HealthScoringService(new ChainedAuditLog(), new ManagementPolicyEngine(),
            id => id == Dev ? StaticDeviceFacts.Of(id, Rmm28Kit.Scope) : null,
            null, null, null, null, null, now: () => T0);
        var ghostScore = Rmm28Kit.Score(Rmm28Kit.AllGood()) with { DeviceId = "dev-ghost" };
        var ghostJson = new HealthScoreStore().Export(ghostScore);
        var ghost = strict.ImportSnapshot(ghostJson, Rmm28Kit.Admin);
        Assert.False(ghost.Ok);
        Assert.Contains("not known to this hub", ghost.Reason);
    }

    [Fact]
    public void F6_ServiceImport_PolicyOff_Refused_AcceptedImportIsSegregated()
    {
        var audit = new ChainedAuditLog();
        var (mon, exp, bak, pos, inv) = Rmm28Kit.AllGoodFakes();
        var svc = Rmm28Kit.Service(mon, exp, bak, pos, inv, audit: audit);
        Assert.True(svc.ComputeScore(Dev, Rmm28Kit.Admin).Ok);
        var computedHash = svc.Latest(Dev)!.ContentHash;

        // Newer than the computed snapshot but inside the 5-minute
        // skew allowance — the strongest import that may be admitted.
        var importedScore = Rmm28Kit.Score(Rmm28Kit.AllGood() with { Backup = null },
            now: T0.AddMinutes(4));
        var json = new HealthScoreStore().Export(importedScore);
        var (ok, _) = svc.ImportSnapshot(json, Rmm28Kit.Admin, expectedScopeId: Rmm28Kit.Scope);
        Assert.True(ok);
        Assert.Equal(computedHash, svc.Latest(Dev)!.ContentHash); // computed still leads
        Assert.Contains(audit.Entries, e => e.Kind == "health_score_snapshot_imported");

        var scopeBad = svc.ImportSnapshot(json, Rmm28Kit.Admin, expectedScopeId: "co-999");
        Assert.False(scopeBad.Ok);
        Assert.Contains("scope", scopeBad.Reason);

        // Policy gate: health scoring OFF for the device refuses
        // the import too — imports are not a policy bypass.
        var offPolicy = new ManagementPolicyEngine();
        Assert.True(offPolicy.AddDocument(new ManagementPolicyDocument("off", PolicyLevels.Org,
            Rmm28Kit.Scope, new Dictionary<string, string>
            { ["rmm.health_scoring.enabled"] = "false" }, 1)).Allowed);
        var offSvc = Rmm28Kit.Service(policy: offPolicy);
        var off = offSvc.ImportSnapshot(json, Rmm28Kit.Admin);
        Assert.False(off.Ok);
        Assert.Contains("OFF by policy", off.Reason);
    }
}
