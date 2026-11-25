using System.Text.Json;
using Acp.Shared.Backup;
using Acp.Shared.Enterprise;
using Acp.Shared.HealthScoring;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Monitoring;
using Acp.Shared.Vulnerability;

namespace Acp.Tests;

// RMM-28 DESTRUCTION PASS — hostile attacks on the health score:
// laundering a critical device into a healthy number, absorbing
// unknowns, rewriting history via weights, spoofing components,
// double-counting facts, and forging snapshots. Every break found
// became a structural fix + a permanent regression test here.
public class Rmm28DestructionTests
{
    private static readonly DateTimeOffset T0 = Rmm28Kit.T0;
    private const string Dev = Rmm28Kit.Dev;

    // ---- score laundering -------------------------------------------------

    [Fact]
    public void Laundering_CriticalExposure_CapsAggregate_EvenAtTinyWeight()
    {
        // Attack: set the exposure weight near zero so a device with
        // an open CRITICAL exposure presents healthy.
        var weights = new HealthScoreWeights("rigged", new Dictionary<string, double>
        {
            [HealthComponents.Monitoring] = 0.30, [HealthComponents.Exposure] = 0.01,
            [HealthComponents.Backup] = 0.30, [HealthComponents.Posture] = 0.30,
            [HealthComponents.Inventory] = 0.09,
        });
        var inputs = Rmm28Kit.AllGood() with
        {
            Exposure = Rmm28Kit.ExposureInput(Rmm28Kit.Exposure("critical")),
        };
        var s = Rmm28Kit.Score(inputs, weights);
        Assert.NotNull(s.AggregateCapReason);
        Assert.Contains("capped at 49", s.AggregateCapReason);
        Assert.True(s.Aggregate <= HealthScoreCaps.CriticalExposureCap,
            $"critical-exposure device presented {s.Aggregate} — laundered");
    }

    [Fact]
    public void Laundering_KevExposure_CapsAggregate()
    {
        var inputs = Rmm28Kit.AllGood() with
        {
            Exposure = Rmm28Kit.ExposureInput(Rmm28Kit.Exposure("low", kev: true)),
        };
        var s = Rmm28Kit.Score(inputs);
        Assert.True(s.Aggregate <= HealthScoreCaps.CriticalExposureCap);
        Assert.Contains("kev=1", s.AggregateCapReason);
    }

    [Fact]
    public void Laundering_DownDevice_CapsAggregate()
    {
        var inputs = Rmm28Kit.AllGood() with
        {
            Monitoring = Rmm28Kit.Monitoring(DeviceHealthStates.Down),
        };
        var s = Rmm28Kit.Score(inputs);
        Assert.Equal(0.0, s.Component(HealthComponents.Monitoring)!.Value);
        Assert.True(s.Aggregate <= HealthScoreCaps.DeviceDownCap);
        Assert.Contains("DOWN", s.AggregateCapReason);
    }

    [Fact]
    public void Laundering_StaleInputs_CannotCertifyHealth()
    {
        // Attack: freeze every source at a moment the device was
        // healthy and let time pass — the score must degrade to
        // unknowns, never keep presenting the frozen 100.
        var later = T0.AddDays(10);
        var s = Rmm28Kit.Score(Rmm28Kit.AllGood(), now: later);
        Assert.Equal(HealthScoreStates.Partial, s.State);
        Assert.Contains(HealthComponents.Monitoring, s.UnknownComponents);
        Assert.Contains(HealthComponents.Backup, s.UnknownComponents);
        Assert.Contains(HealthComponents.Posture, s.UnknownComponents);
        Assert.Contains(HealthComponents.Inventory, s.UnknownComponents);
        // Exposure's feed was published T0-1d: by T0+10d RMM-05's own
        // provenance would say stale — simulated here via stale feed.
        var s2 = Rmm28Kit.Score(Rmm28Kit.AllGood() with
        {
            Exposure = new ExposureHealthInput(
                Array.Empty<ExposureWorkItem>(), Rmm28Kit.StaleFeed()),
        }, now: later);
        Assert.Equal(5, s2.UnknownComponents.Count);
        Assert.Null(s2.Aggregate);
    }

    [Fact]
    public void Laundering_StaleFeedWithZeroOpenItems_ExposureUnknown_NotPerfect()
    {
        var s = Rmm28Kit.Score(Rmm28Kit.AllGood() with
        {
            Exposure = new ExposureHealthInput(
                Array.Empty<ExposureWorkItem>(), Rmm28Kit.StaleFeed()),
        });
        Assert.Equal(ComponentScoreStates.Unknown,
            s.Component(HealthComponents.Exposure)!.State);
        // The mandated aggregation rule is exclude-and-label: the
        // aggregate over the KNOWN components may be 100, but it can
        // never present as a complete, fully-covered 100 — the
        // score is PARTIAL, the unknown is named, and coverage
        // shows exactly what fraction of the weights backs it.
        Assert.Equal(HealthScoreStates.Partial, s.State);
        Assert.Equal(new[] { HealthComponents.Exposure }, s.UnknownComponents);
        Assert.Equal(0.7, s.CoverageFraction);
    }

    // ---- unknown-averaging ---------------------------------------------------

    [Fact]
    public void UnknownAveraging_UnknownsExcludedAndLabelled_NeverZeroFilled()
    {
        // One terrible known component + four unknowns: a zero-fill
        // average would read 4; a treat-unknown-as-fine average
        // would read ~84. The honest aggregate is the known value,
        // labelled PARTIAL with coverage 0.25.
        var inputs = new HealthScoreInputs(
            Rmm28Kit.Monitoring(DeviceHealthStates.Degraded), null, null, null, null);
        var s = Rmm28Kit.Score(inputs);
        Assert.Equal(40.0, s.Aggregate);
        Assert.Equal(HealthScoreStates.Partial, s.State);
        Assert.Equal(0.25, s.CoverageFraction);
        Assert.Equal(4, s.UnknownComponents.Count);
    }

    [Fact]
    public void UnknownAveraging_PartialScoreCannotPresentAsComplete()
    {
        var s = Rmm28Kit.Score(Rmm28Kit.AllGood() with { Backup = null });
        var forged = s with { State = HealthScoreStates.Complete };
        var refusal = HealthScoreIntegrity.Validate(forged);
        Assert.NotNull(refusal);
        Assert.Contains("state mismatch", refusal);
    }

    // ---- weight tampering / history rewrite -----------------------------------

    [Fact]
    public void WeightTampering_NewWeights_DoNotRewriteHistoricalSnapshots()
    {
        var store = new HealthScoreStore();
        var before = Rmm28Kit.Score(Rmm28Kit.AllGood() with
        {
            Monitoring = Rmm28Kit.Monitoring(DeviceHealthStates.Alerting, null,
                Rmm28Kit.Alert(AlertSeverities.Warning)),
        });
        Assert.True(store.Add(before).Ok);
        var hashBefore = before.ContentHash;

        // Admin now changes weights drastically and scores again.
        var newWeights = new HealthScoreWeights("after", new Dictionary<string, double>
        {
            [HealthComponents.Monitoring] = 0.02, [HealthComponents.Exposure] = 0.30,
            [HealthComponents.Backup] = 0.30, [HealthComponents.Posture] = 0.28,
            [HealthComponents.Inventory] = 0.10,
        });
        var after = Rmm28Kit.Score(Rmm28Kit.AllGood() with
        {
            Monitoring = Rmm28Kit.Monitoring(DeviceHealthStates.Alerting, null,
                Rmm28Kit.Alert(AlertSeverities.Warning)),
        }, newWeights, T0.AddDays(1));
        Assert.True(store.Add(after).Ok);

        var history = store.History(Dev);
        Assert.Equal(2, history.Count);
        Assert.Equal(hashBefore, history[0].ContentHash);       // untouched
        Assert.Equal("default-1", history[0].WeightsVersion);   // judged under ITS weights
        Assert.Null(HealthScoreIntegrity.Validate(history[0]));
        Assert.Equal("after", history[1].WeightsVersion);
        Assert.NotEqual(history[0].Aggregate, history[1].Aggregate);
    }

    [Fact]
    public void WeightTampering_PoisonedWeights_RefusedByName()
    {
        var engine = new ManagementPolicyEngine();
        var facts = StaticDeviceFacts.Of(Dev, Rmm28Kit.Scope);
        Assert.True(engine.AddDocument(new ManagementPolicyDocument("neg", PolicyLevels.Org,
            Rmm28Kit.Scope, new Dictionary<string, string>
            { ["rmm.health_scoring.weight.exposure"] = "-5" }, 1)).Allowed);
        var (w, refusals) = HealthScoreWeightsPolicy.Parse(engine.ComputeEffective(facts));
        Assert.Null(w);
        Assert.Contains(refusals, r => r.Contains("non-negative"));

        var zero = new ManagementPolicyEngine();
        var zeroSettings = HealthComponents.All.ToDictionary(
            c => $"rmm.health_scoring.weight.{c}", _ => "0");
        Assert.True(zero.AddDocument(new ManagementPolicyDocument("zero", PolicyLevels.Org,
            Rmm28Kit.Scope, zeroSettings, 1)).Allowed);
        var (w2, refusals2) = HealthScoreWeightsPolicy.Parse(zero.ComputeEffective(facts));
        Assert.Null(w2);
        Assert.Contains(refusals2, r => r.Contains("sum to zero"));
    }

    [Fact]
    public void WeightTampering_ServiceRefusesToScoreUnderPoisonedPolicy()
    {
        var policy = new ManagementPolicyEngine();
        Assert.True(policy.AddDocument(new ManagementPolicyDocument("neg", PolicyLevels.Org,
            Rmm28Kit.Scope, new Dictionary<string, string>
            { ["rmm.health_scoring.weight.backup"] = "-1" }, 1)).Allowed);
        var (mon, exp, bak, pos, inv) = Rmm28Kit.AllGoodFakes();
        var svc = Rmm28Kit.Service(mon, exp, bak, pos, inv, policy);
        var outcome = svc.ComputeScore(Dev, Rmm28Kit.Admin);
        Assert.False(outcome.Ok);
        Assert.Contains("policy content refused", outcome.Reason);
        Assert.Null(svc.Latest(Dev));
    }

    // ---- component spoofing ------------------------------------------------------

    [Fact]
    public void Spoofing_FakeFactsCannotInflateAggregateBeyondDecomposition()
    {
        // Attack: hand the store a score whose aggregate was edited
        // up while its components stayed honest. The integrity
        // check recomputes from the decomposition and refuses.
        var honest = Rmm28Kit.Score(Rmm28Kit.AllGood() with
        {
            Monitoring = Rmm28Kit.Monitoring(DeviceHealthStates.Degraded),
        });
        Assert.Equal(85.0, honest.Aggregate);
        var inflated = honest with { Aggregate = 100.0 };
        var store = new HealthScoreStore();
        var (ok, reason) = store.Add(inflated);
        Assert.False(ok);
        Assert.Contains("aggregate mismatch", reason);
    }

    [Fact]
    public void Spoofing_UnknownComponentCarryingValue_Refused()
    {
        var s = Rmm28Kit.Score(Rmm28Kit.AllGood() with { Backup = null });
        var backup = s.Component(HealthComponents.Backup)!;
        var spoofed = s with
        {
            Components = s.Components.Select(c => c == backup
                ? c with { Value = 100.0 } : c).ToList(),
        };
        Assert.Contains("unknown is not a number", HealthScoreIntegrity.Validate(spoofed));
    }

    [Fact]
    public void Spoofing_DroppedComponent_Refused_NoBareNumbersExist()
    {
        var s = Rmm28Kit.Score(Rmm28Kit.AllGood());
        var stripped = s with
        {
            Components = s.Components.Where(c => c.Component != HealthComponents.Exposure).ToList(),
        };
        Assert.Contains("full decomposition", HealthScoreIntegrity.Validate(stripped));
    }

    [Fact]
    public void Spoofing_CapErasure_Refused()
    {
        // Attack: compute a capped score, then erase the cap reason
        // (keeping the capped number) to hide WHY it is low — or
        // raise the number and keep the reason. Both refuse.
        var s = Rmm28Kit.Score(Rmm28Kit.AllGood() with
        {
            Exposure = Rmm28Kit.ExposureInput(Rmm28Kit.Exposure("critical")),
        });
        Assert.NotNull(s.AggregateCapReason);
        var erased = s with { AggregateCapReason = null };
        Assert.Contains("names no cap reason", HealthScoreIntegrity.Validate(erased));
        var raised = s with { Aggregate = 95.0 };
        Assert.Contains("aggregate mismatch", HealthScoreIntegrity.Validate(raised));
    }

    // ---- double jeopardy / grace ---------------------------------------------------

    [Fact]
    public void DoubleJeopardy_OneAlertCountedOnce_OneExposureCountedOnce()
    {
        // A single critical alert deducts exactly once in
        // monitoring; a single critical exposure deducts exactly
        // once in exposure (severity + KEV + overdue are distinct
        // named facts about it, each priced once — see component
        // maths tests). No fact leaks into a second component:
        // backup/posture/inventory stay 100.
        var s = Rmm28Kit.Score(Rmm28Kit.AllGood() with
        {
            Monitoring = Rmm28Kit.Monitoring(DeviceHealthStates.Alerting, null,
                Rmm28Kit.Alert(AlertSeverities.Critical)),
            Exposure = Rmm28Kit.ExposureInput(Rmm28Kit.Exposure("critical")),
        });
        Assert.Equal(60.0, s.Component(HealthComponents.Monitoring)!.Value);
        Assert.Equal(65.0, s.Component(HealthComponents.Exposure)!.Value);
        Assert.Equal(100.0, s.Component(HealthComponents.Backup)!.Value);
        Assert.Equal(100.0, s.Component(HealthComponents.Posture)!.Value);
        Assert.Equal(100.0, s.Component(HealthComponents.Inventory)!.Value);
    }

    [Fact]
    public void Grace_MaintenanceSuppressionDoesNotReachTheScore()
    {
        // RMM-01 maintenance windows suppress ALERTING, never the
        // facts: an alert the centre holds active still costs in
        // the monitoring component — a window is not a grace rule
        // that hides a fault from the score. (The centre's active
        // list is the input shape; suppression lives in Raise, and
        // a suppressed firing never becomes an active alert — but
        // an ACTIVE one is never un-counted by a window.)
        var audit = new ChainedAuditLog();
        var centre = new HealthAlertCentre(audit, new AlertCenter());
        var outcome = centre.Raise(Dev, "cpu", ConditionKinds.CpuHigh,
            AlertSeverities.Critical, "cpu 99%", "endpoint", TimeSpan.Zero, T0);
        Assert.Equal(RaiseOutcome.New, outcome.Outcome);
        var input = new MonitoringHealthInput(
            new DeviceHealthView(Dev, DeviceHealthStates.Alerting, T0, 1,
                new[] { "cpu" }, "alerting"),
            centre.ActiveAlerts);
        var s = Rmm28Kit.Score(Rmm28Kit.AllGood() with { Monitoring = input });
        Assert.Equal(60.0, s.Component(HealthComponents.Monitoring)!.Value);
    }

    // ---- snapshot forgery via import -------------------------------------------------

    [Fact]
    public void Forgery_EditedSnapshotJson_RefusedByHash()
    {
        var store = new HealthScoreStore();
        var s = Rmm28Kit.Score(Rmm28Kit.AllGood() with
        {
            Monitoring = Rmm28Kit.Monitoring(DeviceHealthStates.Degraded),
        });
        var json = store.Export(s);
        Assert.Equal(85.0, s.Aggregate);
        // Attack: edit the aggregate in the exported JSON, keep the hash.
        var forged = json.Replace("\"Aggregate\": 85", "\"Aggregate\": 100");
        Assert.NotEqual(json, forged);
        var store2 = new HealthScoreStore();
        var (ok, reason, _) = store2.Import(forged, T0); // W16: explicit clock — no-now Import read the wall clock in AddImported's gate
        Assert.False(ok);
        Assert.Contains("content hash", reason);
        Assert.Equal(0, store2.Count);
    }

    [Fact]
    public void Forgery_RecomputedHashOverLyingDecomposition_StillRefused()
    {
        // Stronger attack: forge a score object in code (the hash
        // recomputes cleanly over the lie) whose decomposition
        // contradicts its aggregate. Integrity — not the hash — is
        // the second wall.
        var lie = new DeviceHealthScore(Dev, Rmm28Kit.Scope, T0, "default-1",
            HealthScoreStates.Complete, 100.0, 1.0, null,
            HealthScoreWeightsPolicy.Default.ByComponent.Select(kv => new ComponentScore(
                kv.Key, ComponentScoreStates.Scored, 10.0, kv.Value,
                "forged", T0, null,
                new[] { new ComponentFact("health_state", "healthy", T0) })).ToList());
        Assert.NotNull(HealthScoreIntegrity.Validate(lie));
        var store = new HealthScoreStore();
        var (ok, reason, _) = store.Import(store.Export(lie), T0); // W16: explicit clock (see above)
        Assert.False(ok);
        Assert.Contains("aggregate mismatch", reason);
    }

    [Fact]
    public void Forgery_ImportWithoutHash_Refused_AndDuplicateImport_Refused()
    {
        var store = new HealthScoreStore();
        var s = Rmm28Kit.Score(Rmm28Kit.AllGood());
        var json = store.Export(s);
        using var doc = JsonDocument.Parse(json);
        var stripped = new Dictionary<string, object?>();
        foreach (var p in doc.RootElement.EnumerateObject())
            if (p.Name != "ContentHash") stripped[p.Name] = p.Value.Clone();
        var noHash = JsonSerializer.Serialize(stripped);
        var (ok1, reason1, _) = store.Import(noHash, T0); // W16: explicit clock (see above)
        Assert.False(ok1);
        Assert.Contains("no content hash", reason1);

        var svc = Rmm28Kit.Service(store: store);
        Assert.True(svc.ImportSnapshot(json, Rmm28Kit.Admin).Ok);
        var dup = svc.ImportSnapshot(json, Rmm28Kit.Admin);
        Assert.False(dup.Ok);
        Assert.Contains("already recorded", dup.Reason);
    }

    [Fact]
    public void Forgery_ServiceImportRefusal_IsAudited()
    {
        var audit = new ChainedAuditLog();
        var svc = Rmm28Kit.Service(audit: audit);
        var (ok, _) = svc.ImportSnapshot("{\"not\":\"a score\"}", Rmm28Kit.Admin);
        Assert.False(ok);
        Assert.Contains(audit.Entries, e => e.Kind == "health_score_import_refused");
        Assert.True(audit.Verify().Ok);
    }
}
