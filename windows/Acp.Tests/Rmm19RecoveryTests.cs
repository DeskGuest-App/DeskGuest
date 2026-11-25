using Acp.Core.Services;
using Acp.Shared.Baselines;
using Acp.Shared.Enterprise;
using Acp.Shared.Inventory;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Monitoring;
using Acp.Shared.Security;

namespace Acp.Tests;

// RMM-19 RECOVERY LANE destruction pass (2026-11-21) — attacks the
// original RMM-19 lane did not cover, run against its shipped code:
//   R1 scope narrowing via POLICY (not a baseline revision) making
//      drift vanish — the alert reset must be NAMED as a clearing
//      by change, never a silent "drift cleared".
//   R2 a stale/replayed observation (ObservedUtc going backwards)
//      must judge nothing and clear nothing.
//   R3 the hub cross-check must not claim a disabled item was
//      checked (the evaluator never judges disabled items).
//   R4 setting keys match case-insensitively (the model's own
//      doctrine: setting comparison is ordinal-ignore-case).
//   R5 laundering via a NEW device-level document (different
//      baseline id, same item id) must still name the absorption.
//   R6 characterization: a revision admitted before any evaluation
//      claims NO absorption (nothing was on record to absorb).
public class Rmm19RecoveryTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    private const string Dev = "dev-1";
    private const string Scope = "co-1";

    private sealed class Rig
    {
        public DateTimeOffset Now = T0;
        public ChainedAuditLog Audit = new();
        public HealthAlertCentre Centre;
        public ManagementPolicyService Policies;
        public FakeObservedStateProvider Provider = new();
        public RecordingRemediationSink Remediation = new();
        public BaselineDriftService Service;
        public StaticDeviceFacts Facts = StaticDeviceFacts.Of(Dev, Scope);

        public Rig()
        {
            Centre = new HealthAlertCentre(Audit, new AlertCenter());
            Policies = new ManagementPolicyService(Audit, null);
            Service = new BaselineDriftService(Audit, Policies, Centre, null, Provider,
                id => id == Dev ? Facts : null, remediation: Remediation, now: () => Now);
        }

        public void PolicyDoc(string id, string key, string value)
        {
            var v = Policies.AdmitLocalDocument(new ManagementPolicyDocument(
                id, PolicyLevels.Org, Scope, new Dictionary<string, string> { [key] = value }, 1), "recovery");
            Assert.True(v.Allowed, v.Reason);
        }
    }

    private static BaselineItem Svc(string expected = "Running", bool enabled = true) =>
        BaselineItem.Create("svc-niagara", BaselineItemKinds.ServiceState, "Niagara",
            expected: expected, enabled: enabled, severity: AlertSeverities.Critical);

    private static BaselineDocument Doc(IReadOnlyList<BaselineItem> items, long rev = 1,
        string id = "base-site-servers", string level = PolicyLevels.Org, string target = Scope,
        DateTimeOffset? effective = null) =>
        new(id, rev, level, target, effective ?? T0, "admin-a", items, "baseline");

    private static ObservedEndpointState ObservedSvc(string state, DateTimeOffset? at = null) => new(
        Dev, at ?? T0, new[] { new ServiceSample("Niagara", state) }, null,
        Array.Empty<SoftwareItem>(), null,
        new HashSet<string> { ObservedSections.Services }, Array.Empty<string>());

    private static Rig DriftedRig()
    {
        var rig = new Rig();
        Assert.True(rig.Service.AdmitLocalBaseline(Doc(new[] { Svc() }), "setup", Dev).Allowed);
        rig.Provider.Set(ObservedSvc("Stopped"));
        var cycle = rig.Service.RunCycle(Dev, force: true);
        Assert.Equal(DriftOutcomes.Drifted, cycle.Evaluation!.Outcome);
        Assert.Single(rig.Centre.ActiveAlerts);
        return rig;
    }

    // ---- R1: scope narrowing via policy launders silently -------------

    [Fact]
    public void ScopeNarrowing_ViaPolicy_AlertClearingIsNamedAsChange_NeverSilent()
    {
        var rig = DriftedRig();
        // Attack: no baseline edit at all — policy scope drops the
        // service_state kind. The deviation leaves the comparison.
        rig.PolicyDoc("org-scope", BaselinePolicyKeys.ScopeKinds, "setting");
        rig.Now = T0.AddMinutes(10);
        var cycle = rig.Service.RunCycle(Dev, force: true);
        Assert.Equal(0, cycle.Evaluation!.ItemsJudged);
        // The drift alert may legitimately reset (the item is no
        // longer judged) — but the clearing MUST be named in the
        // audit chain as a clearing-by-change with its mechanism.
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "drift_alert_cleared_by_change" &&
            e.Detail.Contains("svc-niagara") && e.Detail.Contains("out_of_scope"));
    }

    [Fact]
    public void HonestClear_StateNowMatches_NoClearedByChangeEvent()
    {
        var rig = DriftedRig();
        rig.Provider.Set(ObservedSvc("Running", T0.AddMinutes(5)));
        rig.Now = T0.AddMinutes(10);
        var cycle = rig.Service.RunCycle(Dev, force: true);
        Assert.Equal(DriftOutcomes.Compliant, cycle.Evaluation!.Outcome);
        Assert.Single(cycle.ResetAlerts);
        Assert.DoesNotContain(rig.Audit.Entries, e => e.Kind == "drift_alert_cleared_by_change");
    }

    [Fact]
    public void ItemRemovedFromBaseline_AlertClearingIsNamedAsRemoval()
    {
        var rig = DriftedRig();
        // Remove the item via a device-level document set that no
        // longer carries it: admit an org r2 with an unrelated item.
        // (Absorption at admission is the store's record; the cycle's
        // clearing of the live alert must ALSO be named at reset.)
        Assert.True(rig.Service.AdmitLocalBaseline(Doc(new[]
        {
            BaselineItem.Create("svc-other", BaselineItemKinds.ServiceState, "Spooler", expected: "Running"),
        }, rev: 2), "recovery", Dev).Allowed);
        rig.Now = T0.AddMinutes(10);
        rig.Service.RunCycle(Dev, force: true);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "drift_alert_cleared_by_change" &&
            e.Detail.Contains("svc-niagara") && e.Detail.Contains("item_removed"));
        // The Niagara drift alert is gone. (The unrelated Spooler
        // item legitimately raises its OWN alert in the same cycle —
        // it is expected Running and not present — so the centre is
        // not empty; what must be empty is drift:svc-niagara.)
        Assert.DoesNotContain(rig.Centre.ActiveAlerts, a => a.ConditionId == "drift:svc-niagara");
        Assert.Contains(rig.Centre.Alerts, a => a.ConditionId == "drift:svc-niagara" && !a.IsActive);
    }

    // ---- R2: stale observation replay ----------------------------------

    [Fact]
    public void StaleObservation_ReplayedCompliantSnapshot_ClearsNothing_JudgesNothing()
    {
        var rig = DriftedRig(); // drift judged from observation at T0
        // Replay: an OLD snapshot (an hour before the drift
        // observation) in which the service was running.
        rig.Provider.Set(ObservedSvc("Running", T0.AddHours(-1)));
        rig.Now = T0.AddMinutes(10);
        var cycle = rig.Service.RunCycle(Dev, force: true);
        Assert.Contains("stale", cycle.NotRunReason ?? "");
        Assert.Single(rig.Centre.ActiveAlerts); // drift stands
        Assert.Equal(DriftOutcomes.Drifted, rig.Service.LastEvaluation(Dev)!.Outcome);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "drift_cycle_unknown" &&
            e.Detail.Contains("stale"));
    }

    [Fact]
    public void FreshObservation_AfterStaleRefusal_StillJudges()
    {
        var rig = DriftedRig();
        rig.Provider.Set(ObservedSvc("Running", T0.AddHours(-1)));
        rig.Now = T0.AddMinutes(10);
        rig.Service.RunCycle(Dev, force: true);
        rig.Provider.Set(ObservedSvc("Running", T0.AddMinutes(9)));
        rig.Now = T0.AddMinutes(11);
        var cycle = rig.Service.RunCycle(Dev, force: true);
        Assert.Equal(DriftOutcomes.Compliant, cycle.Evaluation!.Outcome);
        Assert.Empty(rig.Centre.ActiveAlerts);
    }

    // ---- R3: cross-check honesty for disabled items ---------------------

    private static DeviceInventoryRecord InventoryRecord(params SoftwareItem[] software) => new(
        DeviceId: Dev, ScopeId: Scope, Hostname: "WS-01",
        Hardware: new HardwareSnapshot("Dell Inc.", "OptiPlex 7010", "ABC1234", "Intel i7", 16,
            16_000_000_000, "Windows 11 Pro", "26100.1", "10.0.26100", "1.2.3",
            Array.Empty<DiskInfo>(), Array.Empty<PeripheralInfo>(), T0),
        Software: software, CustomFields: new Dictionary<string, string>(), Tags: new HashSet<string>(),
        FirstSeenUtc: T0, LastSeenUtc: T0, LastChangedUtc: T0, Revision: 0);

    [Fact]
    public void CrossCheck_DisabledSoftwareItem_IsUnchecked_NeverClaimedChecked()
    {
        var rig = new Rig();
        Assert.True(rig.Service.AdmitLocalBaseline(Doc(new[]
        {
            BaselineItem.Create("forbid-game", BaselineItemKinds.SoftwareForbidden, "Solitaire", enabled: false),
            BaselineItem.Create("req-app", BaselineItemKinds.SoftwareRequired, "Good App"),
        }), "setup", Dev).Allowed);
        rig.Provider.Set(new ObservedEndpointState(Dev, T0, Array.Empty<ServiceSample>(), null,
            new[] { new SoftwareItem("Good App", "1.0", null, null, null) }, null,
            new HashSet<string> { ObservedSections.Software }, Array.Empty<string>()));
        var eval = rig.Service.RunCycle(Dev, force: true).Evaluation!;
        var check = HubDriftCrossCheck.Check(eval, InventoryRecord(
            new SoftwareItem("Good App", "1.0", null, null, null)), rig.Service.EffectiveFor(Dev));
        Assert.Contains("forbid-game", check.UncheckedItemIds);
        Assert.DoesNotContain("forbid-game", check.CheckedItemIds);
        Assert.Contains("req-app", check.CheckedItemIds);
    }

    // ---- R4: setting key casing ------------------------------------------

    [Fact]
    public void SettingKey_DifferentCasing_StillMatches_NoFalseDrift()
    {
        var storeBaseline = new EffectiveBaseline(Dev, T0,
            new[]
            {
                new EffectiveBaselineItem(
                    BaselineItem.Create("set-tz", BaselineItemKinds.Setting, "timezone", expected: "Central"),
                    PolicyLevels.Org, "base-site-servers", 1),
            },
            new[] { "base-site-servers@r1" });
        var observed = new ObservedEndpointState(Dev, T0, Array.Empty<ServiceSample>(),
            new Dictionary<string, string> { ["TimeZone"] = "Central" },
            Array.Empty<SoftwareItem>(), null,
            new HashSet<string> { ObservedSections.Settings }, Array.Empty<string>());
        var eval = BaselineEvaluator.Evaluate(storeBaseline, observed, BaselineItemKinds.All, T0);
        Assert.Equal(DriftOutcomes.Compliant, eval.Outcome);
    }

    // ---- R5: laundering via a new override document -----------------------

    [Fact]
    public void Launder_ViaNewDeviceLevelDocument_AbsorptionStillNamed()
    {
        var rig = DriftedRig();
        // Attack: don't touch the org document — file a NEW
        // device-level document carrying the same item id with the
        // expectation moved onto the drifted value.
        var verdict = rig.Service.AdmitLocalBaseline(
            Doc(new[] { Svc(expected: "Stopped") }, id: "base-dev-override",
                level: PolicyLevels.Device, target: Dev), "attack", Dev);
        Assert.True(verdict.Allowed, verdict.Reason);
        Assert.Contains("ABSORBS 1 existing deviation", verdict.Reason);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "baseline_absorption_noted" &&
            e.Detail.Contains("svc-niagara"));
    }

    // ---- R6: no evaluation on record — no absorption claimed ---------------

    [Fact]
    public void RevisionAdmittedBeforeAnyEvaluation_ClaimsNoAbsorption()
    {
        var rig = new Rig();
        Assert.True(rig.Service.AdmitLocalBaseline(Doc(new[] { Svc() }), "setup", Dev).Allowed);
        var verdict = rig.Service.AdmitLocalBaseline(Doc(new[] { Svc(expected: "Stopped") }, rev: 2), "setup", Dev);
        Assert.True(verdict.Allowed, verdict.Reason);
        Assert.DoesNotContain("ABSORBS", verdict.Reason);
        Assert.Empty(rig.Service.Store.RevisionRecords[^1].Absorptions);
    }
}
