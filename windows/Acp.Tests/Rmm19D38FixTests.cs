using Acp.Core.Services;
using Acp.Shared.Baselines;
using Acp.Shared.Enterprise;
using Acp.Shared.Inventory;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Monitoring;
using Acp.Shared.Security;

namespace Acp.Tests;

// RMM-19 D38 FIX LANE — regression tests for the cross-review
// findings F1–F12 on packet 2b0aebee. Every test here pins a
// CONFIRMED finding's fix; the per-finding verdicts and the two
// partial rebuttals live in the lane log
// (~/workspace/builds/rmm-r-logs/log-rmm19-fix.md).
public class Rmm19D38FixTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    private const string Dev = "dev-1";
    private const string Dev2 = "dev-2";
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
        public StaticDeviceFacts Facts2 = StaticDeviceFacts.Of(Dev2, Scope);

        public Rig()
        {
            Centre = new HealthAlertCentre(Audit, new AlertCenter());
            Policies = new ManagementPolicyService(Audit, null);
            Service = new BaselineDriftService(Audit, Policies, Centre, null, Provider,
                id => id == Dev ? Facts : id == Dev2 ? Facts2 : null,
                remediation: Remediation, now: () => Now);
        }

        public PolicyVerdict Admit(BaselineDocument doc, string forDevice = Dev) =>
            Service.AdmitLocalBaseline(doc, "d38fix", forDevice);

        public DriftCycleResult Cycle(string device = Dev) => Service.RunCycle(device, force: true);
    }

    private static BaselineItem Svc(string id = "svc-niagara", string target = "Niagara",
        string expected = "Running", bool enabled = true) =>
        BaselineItem.Create(id, BaselineItemKinds.ServiceState, target, expected: expected,
            enabled: enabled, severity: AlertSeverities.Critical);

    private static BaselineItem Forbidden(string id, string target) =>
        BaselineItem.Create(id, BaselineItemKinds.SoftwareForbidden, target, severity: AlertSeverities.Critical);

    private static BaselineDocument Doc(IReadOnlyList<BaselineItem> items, long rev = 1,
        string id = "base-site-servers", string level = PolicyLevels.Org, string target = Scope,
        DateTimeOffset? effective = null) =>
        new(id, rev, level, target, effective ?? T0, "admin-a", items, "baseline");

    private static ObservedEndpointState SvcState(string device, string state, DateTimeOffset at) => new(
        device, at, new[] { new ServiceSample("Niagara", state) }, null,
        Array.Empty<SoftwareItem>(), null,
        new HashSet<string> { ObservedSections.Services }, Array.Empty<string>());

    private static Rig DriftedRig(string device = Dev)
    {
        var rig = new Rig();
        Assert.True(rig.Admit(Doc(new[] { Svc() })).Allowed);
        rig.Provider.Set(SvcState(device, "Stopped", T0));
        var cycle = rig.Cycle(device);
        Assert.Equal(DriftOutcomes.Drifted, cycle.Evaluation!.Outcome);
        return rig;
    }

    // ---- F1: expectation_moved naming, on every device -------------

    [Fact]
    public void F1_ExpectationMoved_AlertReset_IsNamedExpectationMoved_NotHonestClear()
    {
        var rig = DriftedRig();
        Assert.True(rig.Admit(Doc(new[] { Svc(expected: "Stopped") }, rev: 2)).Allowed);
        rig.Now = T0.AddMinutes(10);
        var cycle = rig.Cycle();
        Assert.Equal(DriftOutcomes.Compliant, cycle.Evaluation!.Outcome);
        var reset = Assert.Single(cycle.ResetAlerts);
        Assert.Contains("expectation_moved", reset.ResetReason ?? "");
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "drift_alert_cleared_by_change" &&
            e.Detail.Contains("svc-niagara") && e.Detail.Contains("expectation_moved"));
    }

    [Fact]
    public void F1_OrgRevision_AbsorbsDriftOnDeviceTheCallerDidNotName()
    {
        var rig = new Rig();
        Assert.True(rig.Admit(Doc(new[] { Svc() })).Allowed);
        // BOTH devices drift on the same org baseline item.
        rig.Provider.Set(SvcState(Dev, "Stopped", T0));
        rig.Provider.Set(SvcState(Dev2, "Stopped", T0));
        Assert.Equal(DriftOutcomes.Drifted, rig.Cycle(Dev).Evaluation!.Outcome);
        Assert.Equal(DriftOutcomes.Drifted, rig.Cycle(Dev2).Evaluation!.Outcome);
        // The laundering revision is admitted naming ONLY dev-1.
        var verdict = rig.Admit(Doc(new[] { Svc(expected: "Stopped") }, rev: 2), forDevice: Dev);
        Assert.True(verdict.Allowed, verdict.Reason);
        // dev-2's absorption is named: in the audit chain…
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "baseline_absorption_noted" &&
            e.Detail.Contains("device=dev-2") && e.Detail.Contains("svc-niagara") &&
            e.Detail.Contains("expectation_moved"));
        // …and in the admission verdict itself.
        Assert.Contains("dev-2", verdict.Reason);
        Assert.Contains("ALSO ABSORBS", verdict.Reason);
    }

    [Fact]
    public void F1_WrongCallerDeviceId_StillNamesAbsorptionForTheDriftedDevice()
    {
        var rig = DriftedRig();
        // Caller names a device with no drift on record at all.
        var verdict = rig.Service.AdmitLocalBaseline(
            Doc(new[] { Svc(expected: "Stopped") }, rev: 2), "d38fix", "dev-unknown");
        Assert.True(verdict.Allowed, verdict.Reason);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "baseline_absorption_noted" &&
            e.Detail.Contains("device=dev-1") && e.Detail.Contains("expectation_moved"));
        Assert.Contains("dev-1", verdict.Reason);
    }

    [Fact]
    public void F1_NullCallerDeviceId_StillNamesAbsorptionForTheDriftedDevice()
    {
        var rig = DriftedRig();
        var verdict = rig.Service.AdmitLocalBaseline(
            Doc(new[] { Svc(expected: "Stopped") }, rev: 2), "d38fix", null!);
        Assert.True(verdict.Allowed, verdict.Reason);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "baseline_absorption_noted" &&
            e.Detail.Contains("device=dev-1"));
    }

    // ---- F2: absorption survives a collector-gap cycle --------------

    [Fact]
    public void F2_GapCycleBetweenDriftAndLaunderingRevision_AbsorptionStillNamed()
    {
        var rig = DriftedRig();
        // Gap cycle: services section not collected. The alert
        // stays (proven before), and the last evaluation now has
        // NO deviation for the item.
        rig.Provider.Set(new ObservedEndpointState(Dev, T0.AddMinutes(5),
            Array.Empty<ServiceSample>(), null, Array.Empty<SoftwareItem>(), null,
            new HashSet<string> { ObservedSections.Software }, Array.Empty<string>()));
        rig.Now = T0.AddMinutes(10);
        var gap = rig.Cycle();
        Assert.Equal(DriftOutcomes.Unknown, gap.Evaluation!.Outcome);
        Assert.Empty(gap.Evaluation.Deviations);
        Assert.Single(rig.Centre.ActiveAlerts);
        // The laundering revision must STILL name the absorption —
        // it is judged against the drift on record, not against
        // the gap cycle's empty deviation list.
        var verdict = rig.Admit(Doc(new[] { Svc(expected: "Stopped") }, rev: 2,
            effective: T0.AddMinutes(10)));
        Assert.True(verdict.Allowed, verdict.Reason);
        Assert.Contains("ABSORBS 1 existing deviation", verdict.Reason);
        Assert.Contains("expectation_moved", verdict.Reason);
        var notice = Assert.Single(rig.Service.Store.RevisionRecords[^1].Absorptions);
        Assert.Equal("expectation_moved", notice.Mechanism);
        Assert.Equal("Stopped", notice.Observed);
    }

    [Fact]
    public void F2_GapCycleThenLaundering_NextGoodCycleResetIsNamedExpectationMoved()
    {
        var rig = DriftedRig();
        rig.Provider.Set(new ObservedEndpointState(Dev, T0.AddMinutes(5),
            Array.Empty<ServiceSample>(), null, Array.Empty<SoftwareItem>(), null,
            new HashSet<string> { ObservedSections.Software }, Array.Empty<string>()));
        rig.Now = T0.AddMinutes(10);
        rig.Cycle();
        Assert.True(rig.Admit(Doc(new[] { Svc(expected: "Stopped") }, rev: 2,
            effective: T0.AddMinutes(10))).Allowed);
        rig.Provider.Set(SvcState(Dev, "Stopped", T0.AddMinutes(15)));
        rig.Now = T0.AddMinutes(20);
        var cycle = rig.Cycle();
        Assert.Equal(DriftOutcomes.Compliant, cycle.Evaluation!.Outcome);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "drift_alert_cleared_by_change" &&
            e.Detail.Contains("expectation_moved"));
    }

    // ---- F3: stale guard bounds --------------------------------------

    [Fact]
    public void F3_FutureDatedSnapshot_Refused_AndDoesNotPoisonTheWatermark()
    {
        var rig = DriftedRig();
        // A compliant snapshot dated an hour in the future.
        rig.Provider.Set(SvcState(Dev, "Running", T0.AddHours(1)));
        rig.Now = T0.AddMinutes(10);
        var cycle = rig.Cycle();
        Assert.Contains("stale", cycle.NotRunReason ?? "");
        Assert.Single(rig.Centre.ActiveAlerts); // drift NOT cleared by the future snapshot
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "drift_cycle_unknown" &&
            e.Detail.Contains("future-dated"));
        // And the watermark was NOT poisoned: a genuine snapshot
        // minutes later still judges (pre-fix it read "stale"
        // against the future watermark and the device froze).
        rig.Provider.Set(SvcState(Dev, "Running", T0.AddMinutes(9)));
        rig.Now = T0.AddMinutes(11);
        var fresh = rig.Cycle();
        Assert.Equal(DriftOutcomes.Compliant, fresh.Evaluation!.Outcome);
        Assert.Empty(rig.Centre.ActiveAlerts);
    }

    [Fact]
    public void F3_AncientSnapshot_AsFirstObservation_Refused()
    {
        var rig = new Rig();
        Assert.True(rig.Admit(Doc(new[] { Svc() })).Allowed);
        // First observation this service has ever seen for the
        // device — and it is two days old. No watermark exists to
        // catch it; the age bound must.
        rig.Provider.Set(SvcState(Dev, "Running", T0.AddDays(-2)));
        var cycle = rig.Cycle();
        Assert.Contains("stale", cycle.NotRunReason ?? "");
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "drift_cycle_unknown" &&
            e.Detail.Contains("expired observation"));
        Assert.Empty(rig.Centre.Alerts);
    }

    [Fact]
    public void F3_EqualTimestampDifferentContent_Refused_IdenticalContent_Judges()
    {
        var rig = DriftedRig(); // drift judged from Stopped @ T0
        // Same instant, different content: a compliant snapshot
        // claiming the drift instant.
        rig.Provider.Set(SvcState(Dev, "Running", T0));
        rig.Now = T0.AddMinutes(10);
        var conflict = rig.Cycle();
        Assert.Contains("stale", conflict.NotRunReason ?? "");
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "drift_cycle_unknown" &&
            e.Detail.Contains("timestamp conflict"));
        Assert.Single(rig.Centre.ActiveAlerts);
        // The SAME snapshot re-presented (identical content, same
        // timestamp) is not a conflict: it judges — and still
        // finds the drift.
        rig.Provider.Set(SvcState(Dev, "Stopped", T0));
        var same = rig.Cycle();
        Assert.Equal(DriftOutcomes.Drifted, same.Evaluation!.Outcome);
    }

    // ---- F4: report freshness ----------------------------------------

    [Fact]
    public void F4_CompliantThenSilence_ReportGoesStaleUnknown_WithTimestamps()
    {
        var rig = new Rig();
        Assert.True(rig.Admit(Doc(new[] { Svc() })).Allowed);
        rig.Provider.Set(SvcState(Dev, "Running", T0));
        Assert.Equal(DriftOutcomes.Compliant, rig.Cycle().Evaluation!.Outcome);
        var fresh = rig.Service.BuildReport(Dev);
        Assert.Equal(DriftOutcomes.Compliant, fresh.Outcome);
        Assert.False(fresh.IsStale);
        Assert.Equal(T0, fresh.ObservedUtc);
        Assert.Equal(T0, fresh.EvaluatedUtc);
        // The provider dies; two hours pass with no judged cycle.
        rig.Provider.SetNull(Dev);
        rig.Now = T0.AddHours(2);
        rig.Cycle();
        var stale = rig.Service.BuildReport(Dev);
        Assert.True(stale.IsStale);
        Assert.Equal(DriftOutcomes.Unknown, stale.Outcome);
        Assert.Equal(T0, stale.ObservedUtc);
        Assert.Equal(T0, stale.EvaluatedUtc);
        Assert.Contains(stale.Indeterminate, g => g.Reason.Contains("silence is not health"));
    }

    [Fact]
    public void F4_ReportWithinStalenessBound_KeepsLastOutcome()
    {
        var rig = DriftedRig();
        rig.Now = T0.AddMinutes(30);
        var report = rig.Service.BuildReport(Dev);
        Assert.False(report.IsStale);
        Assert.Equal(DriftOutcomes.Drifted, report.Outcome);
    }

    // ---- F5/F6: hub cross-check ---------------------------------------

    private static DeviceInventoryRecord InventoryRecord(
        IReadOnlyList<SoftwareItem>? software = null,
        DateTimeOffset? firstSeen = null, DateTimeOffset? lastSeen = null,
        DateTimeOffset? lastChanged = null, long revision = 0) => new(
        DeviceId: Dev, ScopeId: Scope, Hostname: "WS-01",
        Hardware: new HardwareSnapshot("Dell Inc.", "OptiPlex 7010", "ABC1234", "Intel i7", 16,
            16_000_000_000, "Windows 11 Pro", "26100.1", "10.0.26100", "1.2.3",
            Array.Empty<DiskInfo>(), Array.Empty<PeripheralInfo>(), T0),
        Software: software ?? Array.Empty<SoftwareItem>(),
        CustomFields: new Dictionary<string, string>(), Tags: new HashSet<string>(),
        FirstSeenUtc: firstSeen ?? T0, LastSeenUtc: lastSeen ?? T0,
        LastChangedUtc: lastChanged ?? T0, Revision: revision);

    private static SoftwareItem Sw(string name, string version) => new(name, version, null, null, null);

    [Fact]
    public void F5_NeverPopulatedInventory_ChecksNothing_SoftwareItemsUnchecked()
    {
        var rig = new Rig();
        Assert.True(rig.Admit(Doc(new[] { Forbidden("forbid-game", "Solitaire") })).Allowed);
        // The (forging) agent reports the forbidden app absent.
        rig.Provider.Set(new ObservedEndpointState(Dev, T0, Array.Empty<ServiceSample>(), null,
            Array.Empty<SoftwareItem>(), null,
            new HashSet<string> { ObservedSections.Software }, Array.Empty<string>()));
        var eval = rig.Cycle().Evaluation!;
        Assert.Equal(DriftOutcomes.Compliant, eval.Outcome);
        // Hub record: empty, first sighting, revision 0 — it never
        // collected software, so it must NOT confirm the agent.
        var check = HubDriftCrossCheck.Check(eval, InventoryRecord(), rig.Service.EffectiveFor(Dev));
        Assert.Empty(check.CheckedItemIds);
        Assert.Contains("forbid-game", check.UncheckedItemIds);
    }

    [Fact]
    public void F5_PopulatedInventory_StillChecks_AndCatchesTheLie()
    {
        var rig = new Rig();
        Assert.True(rig.Admit(Doc(new[] { Forbidden("forbid-game", "Solitaire") })).Allowed);
        rig.Provider.Set(new ObservedEndpointState(Dev, T0, Array.Empty<ServiceSample>(), null,
            Array.Empty<SoftwareItem>(), null,
            new HashSet<string> { ObservedSections.Software }, Array.Empty<string>()));
        var eval = rig.Cycle().Evaluation!;
        var check = HubDriftCrossCheck.Check(eval,
            InventoryRecord(software: new[] { Sw("Solitaire", "3.2") }),
            rig.Service.EffectiveFor(Dev));
        Assert.Contains("forbid-game", check.CheckedItemIds);
        Assert.False(check.Clean);
        Assert.Contains(check.Discrepancies, d => d.Contains("forbid-game"));
    }

    [Fact]
    public void F5_StaleHubInventory_IsFlagged_NotSilentCorroboration()
    {
        var rig = new Rig();
        Assert.True(rig.Admit(Doc(new[] { Forbidden("forbid-game", "Solitaire") })).Allowed);
        rig.Provider.Set(new ObservedEndpointState(Dev, T0, Array.Empty<ServiceSample>(), null,
            Array.Empty<SoftwareItem>(), null,
            new HashSet<string> { ObservedSections.Software }, Array.Empty<string>()));
        var eval = rig.Cycle().Evaluation!;
        // Inventory last seen a week BEFORE the agent's observation.
        var check = HubDriftCrossCheck.Check(eval,
            InventoryRecord(software: new[] { Sw("Other App", "1.0") },
                firstSeen: T0.AddDays(-8), lastSeen: T0.AddDays(-7), lastChanged: T0.AddDays(-7)),
            rig.Service.EffectiveFor(Dev));
        Assert.Contains(check.Discrepancies, d => d.Contains("hub inventory was last seen"));
    }

    [Fact]
    public void F6_CaseDifferingAgentItemId_DoesNotCrashCrossCheck()
    {
        var rig = new Rig();
        Assert.True(rig.Admit(Doc(new[] { Forbidden("forbid-game", "Solitaire") })).Allowed);
        // Hand-built agent evaluation whose deviation carries the
        // item id in a different case than the hub baseline's.
        var agentEval = new DriftEvaluation(Dev, T0, T0, rig.Service.EffectiveFor(Dev).ContentHash,
            new[] { "base-site-servers@r1" }, DriftOutcomes.Drifted,
            new[]
            {
                new DriftDeviation("FORBID-GAME", BaselineItemKinds.SoftwareForbidden, "Solitaire",
                    "not installed", "installed (version 3.2)", "agent detail",
                    AlertSeverities.Critical, null, "base-site-servers", 1),
            },
            Array.Empty<DriftIndeterminate>(), 1, 0, 0);
        var check = HubDriftCrossCheck.Check(agentEval,
            InventoryRecord(software: new[] { Sw("Other App", "1.0") }),
            rig.Service.EffectiveFor(Dev));
        // No throw; the disagreement is reported by name.
        Assert.Contains(check.Discrepancies, d => d.Contains("forbid-game"));
    }

    // ---- F7: monitor-sample sections ----------------------------------

    [Fact]
    public void F7_MonitorSample_WatchedLists_DoNotPassUnobservedItems()
    {
        var sample = new EndpointSample(Dev, T0, null, null,
            Array.Empty<DiskSample>(), new[] { new ServiceSample("WatchedSvc", "Running") },
            Array.Empty<ProcessSample>(),
            new[] { new AppSample("WatchedApp", true, "1.0", null) },
            Array.Empty<EventLogSample>(), new SecurityStateSample(true, true, true),
            null, Array.Empty<GuestSample>(), Array.Empty<string>());
        var observed = ObservedStateFactory.FromMonitorSample(sample);
        Assert.False(observed.HasSection(ObservedSections.Services));
        Assert.False(observed.HasSection(ObservedSections.Software));
        var baseline = new EffectiveBaseline(Dev, T0,
            new[]
            {
                new EffectiveBaselineItem(Svc("svc-print", "Spooler", "Stopped"), PolicyLevels.Org, "base", 1),
                new EffectiveBaselineItem(Forbidden("forbid-game", "Solitaire"), PolicyLevels.Org, "base", 1),
            },
            new[] { "base@r1" });
        var eval = BaselineEvaluator.Evaluate(baseline, observed, BaselineItemKinds.All, T0);
        // Neither item was observed: BOTH are indeterminate. The
        // pre-fix factory marked both sections collected and both
        // items PASSED (missing service = Stopped satisfied;
        // missing app = forbidden absent).
        Assert.Equal(DriftOutcomes.Unknown, eval.Outcome);
        Assert.Empty(eval.Deviations);
        Assert.Equal(2, eval.Indeterminate.Count);
    }

    [Fact]
    public void F7_MonitorSample_ExplicitSoftwareList_StillClaimsSoftwareSection()
    {
        var sample = new EndpointSample(Dev, T0, null, null,
            Array.Empty<DiskSample>(), Array.Empty<ServiceSample>(),
            Array.Empty<ProcessSample>(), Array.Empty<AppSample>(),
            Array.Empty<EventLogSample>(), null, null,
            Array.Empty<GuestSample>(), Array.Empty<string>());
        var observed = ObservedStateFactory.FromMonitorSample(sample,
            software: new[] { Sw("Solitaire", "1.0") });
        Assert.True(observed.HasSection(ObservedSections.Software));
    }

    // ---- F8: effective-date games --------------------------------------

    [Fact]
    public void F8_NewDocumentId_WithPastEffectiveDate_Refused()
    {
        var store = new BaselineStore();
        // A brand-new device-level override id — no same-id
        // predecessor for the old forward-only check to compare
        // against — carrying an effective date a week in the past.
        var doc = Doc(new[] { Svc(expected: "Stopped") }, id: "base-dev-override",
            level: PolicyLevels.Device, target: Dev, effective: T0.AddDays(-7));
        var result = store.Admit(doc, T0);
        Assert.False(result.Accepted);
        Assert.Contains("forward-only", result.Reason);
        Assert.Empty(store.AllCurrent);
    }

    [Fact]
    public void F8_NewRevision_EffectiveBeforeAdmissionTime_Refused()
    {
        var store = new BaselineStore();
        Assert.True(store.Admit(Doc(new[] { Svc() }, rev: 1, effective: T0), T0).Accepted);
        // r2 is effective AFTER r1's date (passes the old same-id
        // check) but BEFORE the instant it is admitted.
        var r2 = Doc(new[] { Svc(expected: "Stopped") }, rev: 2, effective: T0.AddDays(1));
        var result = store.Admit(r2, T0.AddDays(2));
        Assert.False(result.Accepted);
        Assert.Contains("forward-only", result.Reason);
        Assert.Equal(1, store.Current("base-site-servers")!.Revision);
    }

    // ---- F9: locked store ----------------------------------------------

    [Fact]
    public void F9_DirectStoreAdmit_BypassingService_Refused_WhenServiceOwnsStore()
    {
        var rig = new Rig();
        Assert.True(rig.Service.Store.AdmissionLocked);
        var direct = rig.Service.Store.Admit(Doc(new[] { Svc() }), T0);
        Assert.False(direct.Accepted);
        Assert.Contains("owned by a BaselineDriftService", direct.Reason);
        Assert.Empty(rig.Service.Store.AllCurrent);
        // The service's own audited paths still admit.
        Assert.True(rig.Admit(Doc(new[] { Svc() })).Allowed);
        Assert.Single(rig.Service.Store.AllCurrent);
    }

    [Fact]
    public void F9_StandaloneStore_AdmitsFreely_ModelComponentUnaffected()
    {
        var store = new BaselineStore();
        Assert.False(store.AdmissionLocked);
        Assert.True(store.Admit(Doc(new[] { Svc() }), T0).Accepted);
    }

    // ---- F10: tracked-state pruning / eviction ---------------------------

    [Fact]
    public void F10_OperatorResetAlert_IsPrunedFromTracking_AndDeviceCanReDrift()
    {
        var rig = DriftedRig();
        var alert = Assert.Single(rig.Centre.ActiveAlerts);
        // An operator resets the alert outside the service.
        rig.Centre.Reset(alert.AlertId, "operator", "handled by hand", T0.AddMinutes(1));
        // Next cycle: the dead id is pruned, nothing is re-reset,
        // and the still-standing drift re-raises through the
        // centre's own discipline once judged again.
        rig.Provider.Set(SvcState(Dev, "Stopped", T0.AddMinutes(5)));
        rig.Now = T0.AddMinutes(10);
        var cycle = rig.Cycle();
        Assert.Empty(cycle.ResetAlerts);
        var report = rig.Service.BuildReport(Dev);
        Assert.DoesNotContain(alert.AlertId, report.ActiveDriftAlertIds);
    }

    [Fact]
    public void F10_PurgeDevice_EvictsAllPerDeviceState()
    {
        var rig = DriftedRig();
        rig.Service.BuildReport(Dev); // creates report-seq state
        rig.Service.PurgeDevice(Dev);
        Assert.Null(rig.Service.LastEvaluation(Dev));
        var report = rig.Service.BuildReport(Dev);
        Assert.Equal(DriftOutcomes.Unknown, report.Outcome); // no fabricated memory of the device
        Assert.Empty(report.ActiveDriftAlertIds);
    }

    // ---- F11: item-id whitespace collision --------------------------------

    [Fact]
    public void F11_WhitespacePaddedItemId_Refused_NoConditionCollision()
    {
        var store = new BaselineStore();
        var doc = Doc(new BaselineItem[]
        {
            Svc("svc", "Niagara", "Running"),
            Svc(" svc", "Spooler", "Running"),
        });
        var result = store.Admit(doc, T0);
        Assert.False(result.Accepted);
        Assert.Contains("whitespace", result.Reason);
        Assert.Empty(store.AllCurrent);
    }

    // ---- F12: absorption record honesty -------------------------------------

    [Fact]
    public void F12_RetargetedItem_AbsorptionNamedItemReplaced_NotExpectationMoved()
    {
        var rig = new Rig();
        Assert.True(rig.Admit(Doc(new[] { Svc() })).Allowed);
        // svc-niagara drifts (Niagara Stopped vs expected Running);
        // the snapshot also holds Spooler, Running.
        rig.Provider.Set(new ObservedEndpointState(Dev, T0,
            new[] { new ServiceSample("Niagara", "Stopped"), new ServiceSample("Spooler", "Running") },
            null, Array.Empty<SoftwareItem>(), null,
            new HashSet<string> { ObservedSections.Services }, Array.Empty<string>()));
        Assert.Equal(DriftOutcomes.Drifted, rig.Cycle().Evaluation!.Outcome);
        // Same item id, retargeted at a DIFFERENT service that
        // happens to be running — the old deviation disappears
        // because the item was swapped, not because an expectation
        // moved along a scale.
        var verdict = rig.Admit(Doc(new[]
        {
            BaselineItem.Create("svc-niagara", BaselineItemKinds.ServiceState, "Spooler",
                expected: "Running", severity: AlertSeverities.Critical),
        }, rev: 2));
        Assert.True(verdict.Allowed, verdict.Reason);
        var notice = Assert.Single(rig.Service.Store.RevisionRecords[^1].Absorptions);
        Assert.Equal("item_replaced", notice.Mechanism);
        Assert.Contains("Spooler", notice.NewExpected);
        Assert.Equal("Running", notice.OldExpected);
        Assert.Equal("Stopped", notice.Observed);
    }

    [Fact]
    public void F12_GapSnapshotAtAdmission_ClaimsNoExpectationMovedAbsorption()
    {
        // Store-level: the caller supplies an observed snapshot in
        // which the drifted item's section was never collected.
        // Analyze must not claim expectation_moved from a
        // disappearance it cannot re-judge.
        var store = new BaselineStore();
        var facts = StaticDeviceFacts.Of(Dev, Scope);
        Assert.True(store.Admit(Doc(new[] { Svc() }), T0).Accepted);
        var driftObs = SvcState(Dev, "Stopped", T0);
        var effective = store.ComputeEffective(facts, Array.Empty<string>(), T0);
        var eval = BaselineEvaluator.Evaluate(effective, driftObs, BaselineItemKinds.All, T0);
        Assert.Single(eval.Deviations);
        var gapObs = new ObservedEndpointState(Dev, T0, Array.Empty<ServiceSample>(), null,
            Array.Empty<SoftwareItem>(), null,
            new HashSet<string> { ObservedSections.Software }, Array.Empty<string>());
        var result = store.Admit(Doc(new[] { Svc(expected: "Stopped") }, rev: 2), T0,
            facts, Array.Empty<string>(), eval, gapObs, BaselineItemKinds.All);
        Assert.True(result.Accepted, result.Reason);
        Assert.Empty(result.Absorptions);
    }
}
