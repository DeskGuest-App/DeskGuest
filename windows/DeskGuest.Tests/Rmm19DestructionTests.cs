using System.Text;
using DeskGuest.Core.Services;
using DeskGuest.Shared.Baselines;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.Inventory;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.Monitoring;
using DeskGuest.Shared.Security;

namespace DeskGuest.Tests;

// RMM-19 DESTRUCTION PASS — hostile attacks on drift detection.
// Led by BASELINE LAUNDERING: editing the baseline to match the
// drifted state and claiming "no drift". Then: unsigned/stale
// delivery, observed-state lying, drift flooding, remediation-link
// abuse, version games, consent-floor reach, and silence-as-clear.
public class Rmm19DestructionTests
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

        public Rig(SignedCommandGate? gate = null)
        {
            Centre = new HealthAlertCentre(Audit, new AlertCenter());
            Policies = new ManagementPolicyService(Audit, null);
            Service = new BaselineDriftService(Audit, Policies, Centre, gate, Provider,
                id => id == Dev ? Facts : null, remediation: Remediation, now: () => Now);
        }

        public void PolicyDoc(string id, string key, string value)
        {
            var v = Policies.AdmitLocalDocument(new ManagementPolicyDocument(
                id, PolicyLevels.Org, Scope, new Dictionary<string, string> { [key] = value }, 1), "attack");
            Assert.True(v.Allowed, v.Reason);
        }
    }

    private static BaselineItem Svc(string expected = "Running", bool enabled = true) =>
        BaselineItem.Create("svc-niagara", BaselineItemKinds.ServiceState, "Niagara",
            expected: expected, enabled: enabled, severity: AlertSeverities.Critical);

    private static BaselineDocument Doc(IReadOnlyList<BaselineItem> items, long rev = 1,
        DateTimeOffset? effective = null, string author = "admin-a") =>
        new("base-site-servers", rev, PolicyLevels.Org, Scope, effective ?? T0, author, items, "baseline");

    private static ObservedEndpointState Observed(params ServiceSample[] services) => new(
        Dev, T0, services, null, Array.Empty<SoftwareItem>(), null,
        new HashSet<string> { ObservedSections.Services }, Array.Empty<string>());

    private static Rig DriftedRig()
    {
        var rig = new Rig();
        Assert.True(rig.Service.AdmitLocalBaseline(Doc(new[] { Svc() }), "attack-setup", Dev).Allowed);
        rig.Provider.Set(Observed(new ServiceSample("Niagara", "Stopped")));
        var cycle = rig.Service.RunCycle(Dev, force: true);
        Assert.Equal(DriftOutcomes.Drifted, cycle.Evaluation!.Outcome);
        Assert.Single(rig.Centre.ActiveAlerts);
        return rig;
    }

    // ---- LAUNDER: baseline edited to match the drifted state ------------

    [Fact]
    public void Launder_ExpectationMovedOntoDriftedValue_AbsorptionIsNamedEverywhere()
    {
        var rig = DriftedRig();
        // The attack: r2 simply expects the drifted state.
        var verdict = rig.Service.AdmitLocalBaseline(Doc(new[] { Svc(expected: "Stopped") }, rev: 2), "attack", Dev);
        Assert.True(verdict.Allowed, verdict.Reason);
        // ...but the absorption is NAMED in the admission itself,
        Assert.Contains("ABSORBS 1 existing deviation", verdict.Reason);
        Assert.Contains("expectation_moved", verdict.Reason);
        // in the permanent revision record,
        var record = rig.Service.Store.RevisionRecords[^1];
        var notice = Assert.Single(record.Absorptions);
        Assert.Equal("expectation_moved", notice.Mechanism);
        Assert.Equal("Running", notice.OldExpected);
        Assert.Equal("Stopped", notice.Observed);
        Assert.Equal("Stopped", notice.NewExpected);
        // and in the audit chain as its own event kind.
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "baseline_absorption_noted" &&
            e.Detail.Contains("svc-niagara") && e.Detail.Contains("expectation_moved"));
        // The drift alert is NOT retro-erased: it stands in history
        // until a fresh cycle judges against the new baseline.
        Assert.Single(rig.Centre.Alerts);
        // A fresh cycle now reads compliant — legitimately, because
        // the re-baseline was deliberate, attributed and recorded.
        var after = rig.Service.RunCycle(Dev, force: true);
        Assert.Equal(DriftOutcomes.Compliant, after.Evaluation!.Outcome);
    }

    [Fact]
    public void Launder_ItemRemoved_AbsorptionNamedAsRemoval()
    {
        var rig = DriftedRig();
        var verdict = rig.Service.AdmitLocalBaseline(
            Doc(new[] { BaselineItem.Create("other", BaselineItemKinds.ServiceState, "Spooler", expected: "Running") }, rev: 2),
            "attack", Dev);
        Assert.True(verdict.Allowed, verdict.Reason);
        var notice = Assert.Single(rig.Service.Store.RevisionRecords[^1].Absorptions);
        Assert.Equal("item_removed", notice.Mechanism);
        Assert.Equal("svc-niagara", notice.ItemId);
    }

    [Fact]
    public void Launder_ItemDisabled_AbsorptionNamedAsDisabled()
    {
        var rig = DriftedRig();
        var verdict = rig.Service.AdmitLocalBaseline(Doc(new[] { Svc(enabled: false) }, rev: 2), "attack", Dev);
        Assert.True(verdict.Allowed, verdict.Reason);
        var notice = Assert.Single(rig.Service.Store.RevisionRecords[^1].Absorptions);
        Assert.Equal("item_disabled", notice.Mechanism);
    }

    [Fact]
    public void Launder_ScopeNarrowed_AbsorptionNamedAtStoreLevel()
    {
        // Scope is policy, not baseline content: the store's
        // admission context carries the incoming scope, and a
        // deviation that vanishes because its kind left scope is
        // absorbed by name too.
        var store = new BaselineStore();
        var facts = StaticDeviceFacts.Of(Dev, Scope);
        Assert.True(store.Admit(Doc(new[] { Svc() }), T0).Accepted);
        var observed = Observed(new ServiceSample("Niagara", "Stopped"));
        var effective = store.ComputeEffective(facts, Array.Empty<string>(), T0);
        var eval = BaselineEvaluator.Evaluate(effective, observed, BaselineItemKinds.All, T0);
        Assert.Single(eval.Deviations);
        var result = store.Admit(Doc(new[] { Svc() }, rev: 2), T0,
            facts, Array.Empty<string>(), eval, observed,
            new HashSet<string> { BaselineItemKinds.Setting });
        Assert.True(result.Accepted, result.Reason);
        var notice = Assert.Single(result.Absorptions);
        Assert.Equal("out_of_scope", notice.Mechanism);
    }

    [Fact]
    public void Launder_HonestRevision_AbsorbsNothing_AndClaimsNothing()
    {
        var rig = DriftedRig();
        // A revision that tightens an UNRELATED item while the
        // drift stands: no absorption, no false comfort.
        var verdict = rig.Service.AdmitLocalBaseline(Doc(new BaselineItem[]
        {
            Svc(), BaselineItem.Create("svc-spooler", BaselineItemKinds.ServiceState, "Spooler", expected: "Running"),
        }, rev: 2), "attack", Dev);
        Assert.True(verdict.Allowed, verdict.Reason);
        Assert.DoesNotContain("ABSORBS", verdict.Reason);
        Assert.Empty(rig.Service.Store.RevisionRecords[^1].Absorptions);
        Assert.DoesNotContain(rig.Audit.Entries, e => e.Kind == "baseline_absorption_noted");
    }

    // ---- unsigned / stale / tampered delivery ----------------------------

    [Fact]
    public void TamperedSignedBaseline_Refused_StoreUnchanged()
    {
        var audit = new ChainedAuditLog();
        var customer = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var ring = new CustomerCommandKeyRing();
        ring.AddCurrent(customer.PublicKey);
        var gate = new SignedCommandGate(new SignedCommandVerifier(ring), audit);
        var rig = new Rig(gate) { Audit = audit };
        rig.Centre = new HealthAlertCentre(audit, new AlertCenter());
        rig.Policies = new ManagementPolicyService(audit, null);
        rig.Service = new BaselineDriftService(audit, rig.Policies, rig.Centre, gate, rig.Provider,
            id => id == Dev ? rig.Facts : null, remediation: rig.Remediation, now: () => rig.Now);
        var signer = new SignedCommandSigner(customer);
        var doc = Doc(new[] { Svc() });
        var envelope = signer.Sign(SignedCommandClasses.PolicyDelivery,
            Encoding.UTF8.GetBytes(doc.ToCanonicalJson()), T0, TimeSpan.FromMinutes(5));
        // Flip one payload byte after signing.
        var payload = Convert.FromBase64String(envelope.PayloadBase64);
        payload[10] ^= 0xFF;
        var tampered = envelope with { PayloadBase64 = Convert.ToBase64String(payload) };
        var verdict = rig.Service.ApplySignedBaseline(tampered, Dev);
        Assert.False(verdict.Allowed);
        Assert.Empty(rig.Service.Store.AllCurrent);
    }

    [Fact]
    public void VersionGames_OldRevisionAfterNew_Refused_AndSameRevisionConflict_Refused()
    {
        var store = new BaselineStore();
        Assert.True(store.Admit(Doc(new[] { Svc() }, rev: 2), T0).Accepted);
        var stale = store.Admit(Doc(new[] { Svc() }, rev: 1), T0);
        Assert.False(stale.Accepted);
        Assert.Contains("stale", stale.Reason);
        var conflict = store.Admit(Doc(new[] { Svc(expected: "Stopped") }, rev: 2), T0);
        Assert.False(conflict.Accepted);
        Assert.Contains("conflicts", conflict.Reason);
        Assert.Equal(2, store.Current("base-site-servers")!.Revision);
    }

    [Fact]
    public void VersionGames_BackdatedRevision_Refused()
    {
        var store = new BaselineStore();
        Assert.True(store.Admit(Doc(new[] { Svc() }, rev: 1, effective: T0.AddDays(7)), T0).Accepted);
        var backdated = store.Admit(Doc(new[] { Svc(expected: "Stopped") }, rev: 2, effective: T0), T0);
        Assert.False(backdated.Accepted);
        Assert.Contains("forward-only", backdated.Reason);
    }

    [Fact]
    public void PostAdmissionMutation_OfCallersList_ChangesNothingLive()
    {
        var store = new BaselineStore();
        var items = new List<BaselineItem> { Svc() };
        Assert.True(store.Admit(Doc(items, rev: 1), T0).Accepted);
        // The caller (or a bug, or a hostile holder of the list)
        // rewrites the expectation and adds an item AFTER admission.
        items[0] = Svc(expected: "Stopped");
        items.Add(BaselineItem.Create("injected", BaselineItemKinds.ServiceState, "Evil", expected: "Running"));
        var facts = StaticDeviceFacts.Of(Dev, Scope);
        var effective = store.ComputeEffective(facts, Array.Empty<string>(), T0);
        var item = Assert.Single(effective.Items);
        Assert.Equal("Running", item.Item.Expected);
    }

    // ---- observed-state lying ---------------------------------------------

    private static DeviceInventoryRecord InventoryRecord(params SoftwareItem[] software) => new(
        DeviceId: Dev, ScopeId: Scope, Hostname: "WS-01",
        Hardware: new HardwareSnapshot("Dell Inc.", "OptiPlex 7010", "ABC1234", "Intel i7", 16,
            16_000_000_000, "Windows 11 Pro", "26100.1", "10.0.26100", "1.2.3",
            Array.Empty<DiskInfo>(), Array.Empty<PeripheralInfo>(), T0),
        Software: software, CustomFields: new Dictionary<string, string>(), Tags: new HashSet<string>(),
        FirstSeenUtc: T0, LastSeenUtc: T0, LastChangedUtc: T0, Revision: 0);

    [Fact]
    public void AgentLies_ObservedForgedToMatchBaseline_HubInventoryExposesIt()
    {
        var rig = new Rig();
        rig.Service.AdmitLocalBaseline(new BaselineDocument("base-sw", 1, PolicyLevels.Org, Scope, T0, "admin-a",
            new[] { BaselineItem.Create("forbid-game", BaselineItemKinds.SoftwareForbidden, "Solitaire", severity: AlertSeverities.Critical) }, ""), "setup", Dev);
        // The agent's (forged) observed state: Solitaire absent.
        rig.Provider.Set(new ObservedEndpointState(Dev, T0, Array.Empty<ServiceSample>(), null,
            Array.Empty<SoftwareItem>(), null, new HashSet<string> { ObservedSections.Software }, Array.Empty<string>()));
        var eval = rig.Service.RunCycle(Dev, force: true).Evaluation!;
        Assert.Equal(DriftOutcomes.Compliant, eval.Outcome); // the lie works agent-side — stated honestly
        // The hub's inventory path holds the truth: Solitaire IS installed.
        var check = HubDriftCrossCheck.Check(eval,
            InventoryRecord(new SoftwareItem("Solitaire", "3.2", null, null, null)),
            rig.Service.EffectiveFor(Dev));
        Assert.False(check.Clean);
        Assert.Contains(check.Discrepancies, d => d.Contains("forbid-game") && d.Contains("hub inventory shows the deviation"));
    }

    [Fact]
    public void CrossCheck_BaselineHashMismatch_IsFlagged()
    {
        var rig = DriftedRig();
        var eval = rig.Service.LastEvaluation(Dev)!;
        // Hub side has since moved to a different effective baseline.
        var otherBaseline = new EffectiveBaseline(Dev, T0, Array.Empty<EffectiveBaselineItem>(), Array.Empty<string>());
        var check = HubDriftCrossCheck.Check(eval, InventoryRecord(), otherBaseline);
        Assert.Contains(check.Discrepancies, d => d.Contains("baseline mismatch"));
    }

    [Fact]
    public void CrossCheck_KindsWithoutSecondPath_AreNamedUnchecked_NeverClaimedChecked()
    {
        var rig = DriftedRig();
        var eval = rig.Service.LastEvaluation(Dev)!;
        var check = HubDriftCrossCheck.Check(eval, InventoryRecord(), rig.Service.EffectiveFor(Dev));
        Assert.Contains("svc-niagara", check.UncheckedItemIds);
        Assert.Empty(check.CheckedItemIds);
    }

    // ---- drift flooding ------------------------------------------------------

    [Fact]
    public void FlappingItem_CooldownBoundsReAlerts_NoUnboundedStream()
    {
        var rig = new Rig();
        rig.PolicyDoc("org-cool", BaselinePolicyKeys.DriftCooldownSeconds, "3600");
        Assert.True(rig.Service.AdmitLocalBaseline(Doc(new[] { Svc() }), "setup", Dev).Allowed);
        // D38 fix lane amendment: each flap observation now carries
        // its own advancing ObservedUtc. The original reused T0 for
        // all 20 cycles while the clock advanced — it DEPENDED on
        // equal-timestamp/different-content acceptance, which
        // finding F3c identifies as a stale-guard bypass.
        ObservedEndpointState At(string state, DateTimeOffset at) => new(
            Dev, at, new[] { new ServiceSample("Niagara", state) }, null,
            Array.Empty<SoftwareItem>(), null,
            new HashSet<string> { ObservedSections.Services }, Array.Empty<string>());
        // Flap 10 times inside the cooldown hour.
        for (var i = 0; i < 10; i++)
        {
            rig.Provider.Set(At("Stopped", rig.Now));
            rig.Service.RunCycle(Dev, force: true);
            rig.Provider.Set(At("Running", rig.Now.AddSeconds(30)));
            rig.Service.RunCycle(Dev, force: true);
            rig.Now = rig.Now.AddMinutes(1);
        }
        // Exactly ONE alert was ever created for the item: the
        // first raise; clears reset it, re-drifts inside the
        // cooldown are counted by the centre, not re-raised.
        Assert.Single(rig.Centre.Alerts);
        // After the cooldown, a fresh drift raises a fresh alert.
        rig.Now = T0.AddHours(2);
        rig.Provider.Set(At("Stopped", rig.Now));
        var late = rig.Service.RunCycle(Dev, force: true);
        Assert.Single(late.NewAlerts);
        Assert.Equal(2, rig.Centre.Alerts.Count);
    }

    // ---- remediation-link abuse --------------------------------------------------

    [Fact]
    public void RemediationAbuse_BaselineLinksUninstall_PolicyNeverApproved_ItNeverFires()
    {
        var rig = new Rig();
        // A baseline (even a properly signed one) links drift on a
        // forbidden app to an uninstall action. Policy says nothing.
        Assert.True(rig.Service.AdmitLocalBaseline(new BaselineDocument("base-sw", 1, PolicyLevels.Org, Scope, T0, "admin-a",
            new[]
            {
                BaselineItem.Create("forbid-game", BaselineItemKinds.SoftwareForbidden, "Solitaire",
                    remediationId: "remove-prohibited-app", severity: AlertSeverities.Critical),
            }, ""), "setup", Dev).Allowed);
        rig.Provider.Set(new ObservedEndpointState(Dev, T0, Array.Empty<ServiceSample>(), null,
            new[] { new SoftwareItem("Solitaire", "1.0", null, null, null) }, null,
            new HashSet<string> { ObservedSections.Software }, Array.Empty<string>()));
        var cycle = rig.Service.RunCycle(Dev, force: true);
        Assert.Single(cycle.NewAlerts);            // the drift reports…
        Assert.Empty(rig.Remediation.Dispatches);  // …and nothing executes.
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "drift_remediation_refused" &&
            e.Detail.Contains("remove-prohibited-app"));
    }

    [Fact]
    public void RemediationAbuse_AllowlistNamesADifferentAction_StillNeverFires()
    {
        var rig = new Rig();
        rig.PolicyDoc("org-auto", BaselinePolicyKeys.AutoRemediate, "true");
        rig.PolicyDoc("org-allow", BaselinePolicyKeys.RemediationAllowlist, "restart-print-spooler");
        Assert.True(rig.Service.AdmitLocalBaseline(new BaselineDocument("base-sw", 1, PolicyLevels.Org, Scope, T0, "admin-a",
            new[]
            {
                BaselineItem.Create("forbid-game", BaselineItemKinds.SoftwareForbidden, "Solitaire",
                    remediationId: "remove-prohibited-app", severity: AlertSeverities.Critical),
            }, ""), "setup", Dev).Allowed);
        rig.Provider.Set(new ObservedEndpointState(Dev, T0, Array.Empty<ServiceSample>(), null,
            new[] { new SoftwareItem("Solitaire", "1.0", null, null, null) }, null,
            new HashSet<string> { ObservedSections.Software }, Array.Empty<string>()));
        rig.Service.RunCycle(Dev, force: true);
        Assert.Empty(rig.Remediation.Dispatches);
    }

    // ---- consent floor + silence ---------------------------------------------------

    [Fact]
    public void ConsentFloor_BaselineItemNamingTheFloor_RefusesWholeDocument()
    {
        var store = new BaselineStore();
        var floorItem = BaselineItem.Create("sneaky", BaselineItemKinds.Setting, "audit.enabled", expected: "false");
        var result = store.Admit(new BaselineDocument("base-floor", 1, PolicyLevels.Org, Scope, T0, "admin-a",
            new[] { floorItem }, ""), T0);
        Assert.False(result.Accepted);
        Assert.Contains("consent floor", result.Reason);
        Assert.Empty(store.AllCurrent);
    }

    [Fact]
    public void Silence_ProviderDiesAfterDrift_AlertSurvives_OutcomeNeverCompliant()
    {
        var rig = DriftedRig();
        rig.Provider.SetNull(Dev);
        rig.Now = T0.AddMinutes(30);
        var cycle = rig.Service.RunCycle(Dev, force: true);
        Assert.True(cycle.Ran);
        Assert.Single(rig.Centre.ActiveAlerts);
        var report = rig.Service.BuildReport(Dev);
        Assert.Equal(DriftOutcomes.Drifted, report.Outcome); // last judged state stands
    }

    [Fact]
    public void WrongDeviceObservation_JudgesNothing()
    {
        var rig = DriftedRig();
        rig.Provider.Forced = new ObservedEndpointState("dev-other", T0,
            new[] { new ServiceSample("Niagara", "Running") }, null,
            Array.Empty<SoftwareItem>(), null,
            new HashSet<string> { ObservedSections.Services }, Array.Empty<string>());
        var cycle = rig.Service.RunCycle(Dev, force: true);
        Assert.Contains("mismatch", cycle.NotRunReason!);
        Assert.Single(rig.Centre.ActiveAlerts); // prior drift untouched
    }
}
