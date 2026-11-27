using System.Text;
using DeskGuest.Core.Services;
using DeskGuest.Shared.Baselines;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.Inventory;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.Monitoring;
using DeskGuest.Shared.Security;

namespace DeskGuest.Tests;

// RMM-19 — Desired-state baselines + endpoint drift detection.
// Per-item drift (expected vs observed, never a bare flag), signed
// baseline delivery with inheritance, versioned re-baselining from
// the effective date, cadence + scope as policy, drift as RMM-01
// conditions, and the remediation link gate. All collectors are
// fakes; no real endpoint state is read anywhere in this suite.
public class Rmm19Tests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    private const string Dev = "dev-1";
    private const string Scope = "co-1";

    // ---- fixtures ------------------------------------------------------

    public sealed class Rig
    {
        public DateTimeOffset Now = T0;
        public ChainedAuditLog Audit = new();
        public AlertCenter Dir57 = new();
        public HealthAlertCentre Centre;
        public ManagementPolicyService Policies;
        public FakeObservedStateProvider Provider = new();
        public RecordingRemediationSink Remediation = new();
        public BaselineDriftService Service;
        public StaticDeviceFacts Facts = StaticDeviceFacts.Of(Dev, Scope);

        public Rig(SignedCommandGate? gate = null)
        {
            Centre = new HealthAlertCentre(Audit, Dir57);
            Policies = new ManagementPolicyService(Audit, null);
            Service = new BaselineDriftService(Audit, Policies, Centre, gate, Provider,
                id => id == Dev ? Facts : null, remediation: Remediation, now: () => Now);
        }

        public void PolicyDoc(string id, string key, string value, string level = PolicyLevels.Org, string target = Scope)
        {
            var v = Policies.AdmitLocalDocument(new ManagementPolicyDocument(
                id, level, target, new Dictionary<string, string> { [key] = value }, 1), "test");
            Assert.True(v.Allowed, v.Reason);
        }

        public PolicyVerdict Admit(BaselineDocument doc) => Service.AdmitLocalBaseline(doc, "test", Dev);

        public DriftCycleResult Cycle(bool force = true) => Service.RunCycle(Dev, force);
    }

    private static BaselineItem Svc(string id = "svc-niagara", string target = "Niagara",
        string expected = "Running", string? remediation = null, bool enabled = true) =>
        BaselineItem.Create(id, BaselineItemKinds.ServiceState, target, expected: expected,
            remediationId: remediation, enabled: enabled, severity: AlertSeverities.Critical);

    private static BaselineItem Setting(string id, string target, string expected) =>
        BaselineItem.Create(id, BaselineItemKinds.Setting, target, expected: expected);

    private static BaselineItem Required(string id, string target, string? minVersion = null, string? remediation = null) =>
        BaselineItem.Create(id, BaselineItemKinds.SoftwareRequired, target, expectedVersion: minVersion, remediationId: remediation);

    private static BaselineItem Forbidden(string id, string target, string? remediation = null) =>
        BaselineItem.Create(id, BaselineItemKinds.SoftwareForbidden, target, remediationId: remediation, severity: AlertSeverities.Critical);

    private static BaselineItem Posture(string id, string target, string expected = "on") =>
        BaselineItem.Create(id, BaselineItemKinds.SecurityPosture, target, expected: expected, severity: AlertSeverities.Critical);

    private static BaselineDocument Doc(IReadOnlyList<BaselineItem> items, long rev = 1,
        string id = "base-site-servers", string level = PolicyLevels.Org, string target = Scope,
        DateTimeOffset? effective = null, string author = "admin-a") =>
        new(id, rev, level, target, effective ?? T0, author, items, "site server baseline");

    private static ObservedEndpointState Observed(
        IReadOnlyList<ServiceSample>? services = null,
        IReadOnlyDictionary<string, string>? settings = null,
        IReadOnlyList<SoftwareItem>? software = null,
        SecurityStateSample? security = null,
        DateTimeOffset? at = null, string deviceId = Dev)
    {
        var sections = new HashSet<string>();
        if (services is not null) sections.Add(ObservedSections.Services);
        if (settings is not null) sections.Add(ObservedSections.Settings);
        if (software is not null) sections.Add(ObservedSections.Software);
        if (security is not null) sections.Add(ObservedSections.Security);
        return new ObservedEndpointState(deviceId, at ?? T0,
            services ?? Array.Empty<ServiceSample>(), settings,
            software ?? Array.Empty<SoftwareItem>(), security, sections, Array.Empty<string>());
    }

    private static ServiceSample SvcObs(string name, string state) => new(name, state);
    private static SoftwareItem Sw(string name, string version) => new(name, version, null, null, null);

    private static Rig DriftedRig()
    {
        var rig = new Rig();
        Assert.True(rig.Admit(Doc(new[] { Svc() })).Allowed);
        rig.Provider.Set(Observed(services: new[] { SvcObs("Niagara", "Stopped") }));
        return rig;
    }

    // ---- evaluator: per-item drift ------------------------------------

    [Fact]
    public void CompliantState_EvaluatesCompliant_NoDeviations()
    {
        var rig = new Rig();
        rig.Admit(Doc(new BaselineItem[]
        {
            Svc(), Required("req-acrobat", "Adobe Acrobat", "24.0"), Posture("posture-av", "av"),
        }));
        rig.Provider.Set(Observed(
            services: new[] { SvcObs("Niagara", "Running") },
            software: new[] { Sw("Adobe Acrobat", "24.0.1") },
            security: new SecurityStateSample(true, true, true)));
        var result = rig.Cycle();
        Assert.Equal(DriftOutcomes.Compliant, result.Evaluation!.Outcome);
        Assert.Empty(result.Evaluation.Deviations);
        Assert.Empty(result.NewAlerts);
    }

    [Fact]
    public void ServiceStopped_DeviationNamesExpectedAndObserved()
    {
        var rig = DriftedRig();
        var result = rig.Cycle();
        Assert.Equal(DriftOutcomes.Drifted, result.Evaluation!.Outcome);
        var dev = Assert.Single(result.Evaluation.Deviations);
        Assert.Equal("svc-niagara", dev.ItemId);
        Assert.Equal("Running", dev.Expected);
        Assert.Equal("Stopped", dev.Observed);
        Assert.Contains("expected Running, observed Stopped", dev.Detail);
        Assert.Equal("base-site-servers", dev.SourceDocumentId);
        Assert.Equal(1, dev.SourceRevision);
    }

    [Fact]
    public void ServiceMissing_RunningExpected_Deviates_StopsExpected_Complies()
    {
        var rig = new Rig();
        rig.Admit(Doc(new BaselineItem[] { Svc(), Svc("svc-print", "Spooler", "Stopped") }));
        rig.Provider.Set(Observed(services: new[] { SvcObs("Other", "Running") }));
        var eval = rig.Cycle().Evaluation!;
        var dev = Assert.Single(eval.Deviations);
        Assert.Equal("svc-niagara", dev.ItemId);
        Assert.Equal("not present", dev.Observed);
    }

    [Fact]
    public void SettingMismatch_AndAbsentKey_BothDeviateByName()
    {
        var rig = new Rig();
        rig.Admit(Doc(new BaselineItem[]
        {
            Setting("set-tz", "timezone", "Central"), Setting("set-locale", "locale", "en-US"),
        }));
        rig.Provider.Set(Observed(settings: new Dictionary<string, string> { ["timezone"] = "UTC" }));
        var eval = rig.Cycle().Evaluation!;
        Assert.Equal(2, eval.Deviations.Count);
        Assert.Contains(eval.Deviations, d => d.ItemId == "set-tz" && d.Expected == "Central" && d.Observed == "UTC");
        Assert.Contains(eval.Deviations, d => d.ItemId == "set-locale" && d.Observed == "(absent)");
    }

    [Fact]
    public void SoftwareRequired_MissingAndOldVersion_Deviate_CurrentVersion_Complies()
    {
        var rig = new Rig();
        rig.Admit(Doc(new BaselineItem[]
        {
            Required("req-acrobat", "Adobe Acrobat", "10.0"),
            Required("req-agent", "Site Agent"),
            Required("req-ok", "Good App", "2.0"),
        }));
        rig.Provider.Set(Observed(software: new[] { Sw("Adobe Acrobat", "9.0"), Sw("Good App", "2.5") }));
        var eval = rig.Cycle().Evaluation!;
        Assert.Equal(2, eval.Deviations.Count);
        Assert.Contains(eval.Deviations, d => d.ItemId == "req-acrobat" && d.Observed == "version 9.0" && d.Expected == "version >= 10.0");
        Assert.Contains(eval.Deviations, d => d.ItemId == "req-agent" && d.Observed == "not installed");
    }

    [Fact]
    public void SoftwareForbidden_Present_DeviatesNamingVersion()
    {
        var rig = new Rig();
        rig.Admit(Doc(new[] { Forbidden("forbid-game", "Solitaire") }));
        rig.Provider.Set(Observed(software: new[] { Sw("Solitaire", "3.2") }));
        var dev = Assert.Single(rig.Cycle().Evaluation!.Deviations);
        Assert.Equal("not installed", dev.Expected);
        Assert.Equal("installed (version 3.2)", dev.Observed);
    }

    [Fact]
    public void SecurityPosture_Off_Deviates_UnreadReading_IsIndeterminate()
    {
        var rig = new Rig();
        rig.Admit(Doc(new BaselineItem[] { Posture("posture-av", "av"), Posture("posture-fw", "firewall") }));
        rig.Provider.Set(Observed(security: new SecurityStateSample(false, null, null)));
        var eval = rig.Cycle().Evaluation!;
        var dev = Assert.Single(eval.Deviations);
        Assert.Equal("posture-av", dev.ItemId);
        Assert.Equal("off", dev.Observed);
        var gap = Assert.Single(eval.Indeterminate);
        Assert.Equal("posture-fw", gap.ItemId);
    }

    [Fact]
    public void MissingSection_IsIndeterminate_OutcomeUnknown_NeverCompliant()
    {
        var rig = new Rig();
        rig.Admit(Doc(new[] { Svc() }));
        rig.Provider.Set(Observed(software: Array.Empty<SoftwareItem>())); // services section never collected
        var eval = rig.Cycle().Evaluation!;
        Assert.Equal(DriftOutcomes.Unknown, eval.Outcome);
        Assert.Single(eval.Indeterminate);
        Assert.Empty(eval.Deviations);
    }

    [Fact]
    public void DeviationPlusGap_OutcomeIsDrifted()
    {
        var rig = new Rig();
        rig.Admit(Doc(new BaselineItem[] { Svc(), Posture("posture-av", "av") }));
        rig.Provider.Set(Observed(services: new[] { SvcObs("Niagara", "Stopped") })); // no security section
        Assert.Equal(DriftOutcomes.Drifted, rig.Cycle().Evaluation!.Outcome);
    }

    [Fact]
    public void NoBaseline_OutcomeNoBaseline_NoAlerts()
    {
        var rig = new Rig();
        rig.Provider.Set(Observed(services: new[] { SvcObs("Niagara", "Stopped") }));
        var result = rig.Cycle();
        Assert.Equal(DriftOutcomes.NoBaseline, result.Evaluation!.Outcome);
        Assert.Empty(result.NewAlerts);
    }

    // ---- alert-centre bridging ------------------------------------------

    [Fact]
    public void Cycle_RaisesOneAlertPerDeviation_WithExpectedVsObservedDetail()
    {
        var rig = DriftedRig();
        var result = rig.Cycle();
        var alert = Assert.Single(result.NewAlerts);
        Assert.Equal(DriftAlerting.Kind, alert.Kind);
        Assert.Equal("drift:svc-niagara", alert.ConditionId);
        Assert.Contains("expected Running, observed Stopped", alert.Detail);
        Assert.Contains("base-site-servers@r1", alert.Detail);
        Assert.Single(rig.Centre.ActiveAlerts);
    }

    [Fact]
    public void Cycle_PersistentDrift_DedupsToOneActiveAlert()
    {
        var rig = DriftedRig();
        rig.Cycle();
        rig.Now = T0.AddMinutes(10);
        var second = rig.Cycle();
        Assert.Empty(second.NewAlerts);
        var active = Assert.Single(rig.Centre.ActiveAlerts);
        Assert.Equal(2, active.OccurrenceCount);
    }

    [Fact]
    public void Cycle_DriftClears_RaisedAlertAutoResets()
    {
        var rig = DriftedRig();
        rig.Cycle();
        // D38 fix lane: the clearing snapshot carries a FRESH
        // ObservedUtc — different content under the drift
        // snapshot's timestamp is now refused as a timestamp
        // conflict (finding F3c).
        rig.Provider.Set(Observed(services: new[] { SvcObs("Niagara", "Running") }, at: T0.AddMinutes(10)));
        rig.Now = T0.AddMinutes(10);
        var result = rig.Cycle();
        Assert.Equal(DriftOutcomes.Compliant, result.Evaluation!.Outcome);
        Assert.Single(result.ResetAlerts);
        Assert.Empty(rig.Centre.ActiveAlerts);
    }

    [Fact]
    public void Cycle_CollectorGapAfterDrift_DoesNotClearTheAlert()
    {
        var rig = DriftedRig();
        rig.Cycle();
        // D38 fix lane: fresh ObservedUtc (see F3c note above).
        rig.Provider.Set(Observed(software: Array.Empty<SoftwareItem>(), at: T0.AddMinutes(10))); // services gap
        rig.Now = T0.AddMinutes(10);
        var result = rig.Cycle();
        Assert.Equal(DriftOutcomes.Unknown, result.Evaluation!.Outcome);
        Assert.Empty(result.ResetAlerts);
        Assert.Single(rig.Centre.ActiveAlerts);
    }

    // ---- cadence + policy -------------------------------------------------

    [Fact]
    public void Cadence_NonForcedCycleInsideWindow_DoesNotObserve()
    {
        var rig = DriftedRig();
        rig.Cycle(force: false);
        Assert.Equal(1, rig.Provider.CallCount);
        rig.Now = T0.AddMinutes(2); // default cadence 300s
        var skipped = rig.Cycle(force: false);
        Assert.False(skipped.Ran);
        Assert.Contains("cadence", skipped.NotRunReason!);
        Assert.Equal(1, rig.Provider.CallCount);
        rig.Now = T0.AddMinutes(6);
        Assert.True(rig.Cycle(force: false).Ran);
        Assert.Equal(2, rig.Provider.CallCount);
    }

    [Fact]
    public void PolicyDisabled_NoComparison_NoAlerts_RefusalAudited()
    {
        var rig = DriftedRig();
        rig.PolicyDoc("org-off", BaselinePolicyKeys.Enabled, "false");
        var result = rig.Cycle();
        Assert.False(result.Ran);
        Assert.Empty(rig.Centre.Alerts);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "baseline_disabled");
    }

    [Fact]
    public void FeatureToggle_SeededOn()
    {
        var registry = FeatureToggleRegistry.Seeded();
        Assert.True(registry.TryGet(BaselinePolicyKeys.Enabled, out var t));
        Assert.True(t!.DefaultEnabled);
    }

    [Fact]
    public void PolicyScope_ExcludesSoftwareKinds_FromComparison()
    {
        var rig = new Rig();
        rig.Admit(Doc(new BaselineItem[] { Svc(), Forbidden("forbid-game", "Solitaire") }));
        rig.PolicyDoc("org-scope", BaselinePolicyKeys.ScopeKinds, "service_state");
        rig.Provider.Set(Observed(
            services: new[] { SvcObs("Niagara", "Running") },
            software: new[] { Sw("Solitaire", "1.0") }));
        var eval = rig.Cycle().Evaluation!;
        Assert.Equal(DriftOutcomes.Compliant, eval.Outcome);
        Assert.Equal(1, eval.ItemsJudged);
        Assert.Equal(1, eval.ItemsSkippedOutOfScope);
    }

    [Fact]
    public void PolicyScope_UnknownKindName_IsDroppedAndNamed()
    {
        var rig = new Rig();
        rig.PolicyDoc("org-scope", BaselinePolicyKeys.ScopeKinds, "service_state,bogus_kind");
        var policy = BaselinePolicyResolver.Resolve(rig.Policies.Engine, rig.Facts);
        Assert.Equal(new HashSet<string> { BaselineItemKinds.ServiceState }, policy.ScopeKinds);
        Assert.Contains(policy.Notes, n => n.Contains("bogus_kind"));
    }

    // ---- inheritance --------------------------------------------------------

    [Fact]
    public void Inheritance_GroupDocumentOverridesOrgItem_WithProvenance()
    {
        var rig = new Rig();
        rig.Policies.Engine.AddGroup(new GroupDefinition("grp-servers", "Servers", Array.Empty<GroupRule>()));
        var memberFacts = StaticDeviceFacts.Of(Dev, Scope, groups: new[] { "grp-servers" });
        var svc = new BaselineDriftService(rig.Audit, rig.Policies, rig.Centre, null, rig.Provider,
            id => memberFacts, remediation: rig.Remediation, now: () => rig.Now);
        Assert.True(svc.AdmitLocalBaseline(Doc(new[] { Svc() }), "test", Dev).Allowed);
        Assert.True(svc.AdmitLocalBaseline(Doc(new[] { Svc(expected: "Stopped") }, rev: 1,
            id: "base-group", level: PolicyLevels.Group, target: "grp-servers"), "test", Dev).Allowed);
        var effective = svc.EffectiveFor(Dev);
        var item = Assert.Single(effective.Items);
        Assert.Equal("Stopped", item.Item.Expected);
        Assert.Equal(PolicyLevels.Group, item.SourceLevel);
        Assert.Equal("base-group", item.SourceDocumentId);
    }

    [Fact]
    public void Inheritance_DeviceDocumentWinsOverOrgAndGroup()
    {
        var rig = new Rig();
        rig.Admit(Doc(new[] { Setting("set-tz", "timezone", "UTC") }));
        rig.Admit(Doc(new[] { Setting("set-tz", "timezone", "Eastern") }, id: "base-dev",
            level: PolicyLevels.Device, target: Dev));
        var effective = rig.Service.EffectiveFor(Dev);
        var item = Assert.Single(effective.Items);
        Assert.Equal("Eastern", item.Item.Expected);
        Assert.Equal(PolicyLevels.Device, item.SourceLevel);
    }

    [Fact]
    public void FutureEffectiveRevision_DoesNotJudgeUntilItsEffectiveDate()
    {
        var rig = new Rig();
        rig.Admit(Doc(new[] { Svc(expected: "Running") }, rev: 1, effective: T0));
        rig.Admit(Doc(new[] { Svc(expected: "Stopped") }, rev: 2, effective: T0.AddDays(1)));
        rig.Provider.Set(Observed(services: new[] { SvcObs("Niagara", "Stopped") }));
        // At T0 the NEW baseline is admitted but not in force: the
        // drift is still judged against r1 (deliberate re-baseline).
        Assert.Equal(DriftOutcomes.Drifted, rig.Cycle().Evaluation!.Outcome);
        rig.Now = T0.AddDays(2);
        // D38 fix lane: a FRESH observation at the later instant —
        // the T0 snapshot is beyond the max observation age by then
        // (finding F3b) and would refuse as expired.
        rig.Provider.Set(Observed(services: new[] { SvcObs("Niagara", "Stopped") }, at: T0.AddDays(2)));
        Assert.Equal(DriftOutcomes.Compliant, rig.Cycle().Evaluation!.Outcome);
    }

    // ---- signed delivery ------------------------------------------------------

    private static (Rig Rig, SignedCommandSigner Signer) SignedRig()
    {
        var audit = new ChainedAuditLog();
        var customer = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var ring = new CustomerCommandKeyRing();
        ring.AddCurrent(customer.PublicKey);
        var gate = new SignedCommandGate(new SignedCommandVerifier(ring), audit);
        var rig = new Rig(gate)
        {
            Audit = audit,
            Centre = new HealthAlertCentre(audit, new AlertCenter()),
        };
        // Rebuild the service against the signed rig's audit/centre.
        rig.Policies = new ManagementPolicyService(audit, null);
        rig.Service = new BaselineDriftService(audit, rig.Policies, rig.Centre, gate, rig.Provider,
            id => id == Dev ? rig.Facts : null, remediation: rig.Remediation, now: () => rig.Now);
        return (rig, new SignedCommandSigner(customer));
    }

    [Fact]
    public void SignedDelivery_VerifiedBaselineAppliesAndDrivesDrift()
    {
        var (rig, signer) = SignedRig();
        var doc = Doc(new[] { Svc() });
        var envelope = signer.Sign(SignedCommandClasses.PolicyDelivery,
            Encoding.UTF8.GetBytes(doc.ToCanonicalJson()), T0, TimeSpan.FromMinutes(5));
        var verdict = rig.Service.ApplySignedBaseline(envelope, Dev);
        Assert.True(verdict.Allowed, verdict.Reason);
        rig.Provider.Set(Observed(services: new[] { SvcObs("Niagara", "Stopped") }));
        Assert.Equal(DriftOutcomes.Drifted, rig.Cycle().Evaluation!.Outcome);
    }

    [Fact]
    public void SignedDelivery_NoGate_RefusesByName()
    {
        var rig = new Rig(); // gate: null
        var verdict = rig.Service.ApplySignedBaseline(null, Dev);
        Assert.False(verdict.Allowed);
        Assert.Contains("no customer command key", verdict.Reason);
        Assert.Empty(rig.Service.Store.AllCurrent);
    }

    // ---- remediation gate -------------------------------------------------------

    private static Rig RemediationRig()
    {
        var rig = new Rig();
        rig.Admit(Doc(new[] { Forbidden("forbid-game", "Solitaire", remediation: "remove-prohibited-app") }));
        rig.Provider.Set(Observed(software: new[] { Sw("Solitaire", "1.0") }));
        return rig;
    }

    [Fact]
    public void RemediationLink_PolicySilent_NeverDispatches_RefusalAudited()
    {
        var rig = RemediationRig();
        var result = rig.Cycle();
        Assert.Single(result.NewAlerts);
        Assert.Empty(rig.Remediation.Dispatches);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "drift_remediation_refused");
        Assert.Contains(result.RemediationOutcomes, o => o.StartsWith("refused:remove-prohibited-app"));
    }

    [Fact]
    public void RemediationLink_AllowlistedAndPolicyOn_Dispatches()
    {
        var rig = RemediationRig();
        rig.PolicyDoc("org-auto", BaselinePolicyKeys.AutoRemediate, "true");
        rig.PolicyDoc("org-allow", BaselinePolicyKeys.RemediationAllowlist, "remove-prohibited-app");
        var result = rig.Cycle();
        var dispatch = Assert.Single(rig.Remediation.Dispatches);
        Assert.Equal("remove-prohibited-app", dispatch.RemediationId);
        Assert.Contains(result.RemediationOutcomes, o => o.StartsWith("dispatched:remove-prohibited-app"));
    }

    [Fact]
    public void RemediationLink_AutoOnButNotAllowlisted_NeverDispatches()
    {
        var rig = RemediationRig();
        rig.PolicyDoc("org-auto", BaselinePolicyKeys.AutoRemediate, "true");
        rig.PolicyDoc("org-allow", BaselinePolicyKeys.RemediationAllowlist, "some-other-action");
        rig.Cycle();
        Assert.Empty(rig.Remediation.Dispatches);
    }

    [Fact]
    public void RemediationLink_EngineDisabledByPolicy_NeverDispatches()
    {
        var rig = RemediationRig();
        rig.PolicyDoc("org-auto", BaselinePolicyKeys.AutoRemediate, "true");
        rig.PolicyDoc("org-allow", BaselinePolicyKeys.RemediationAllowlist, "remove-prohibited-app");
        rig.PolicyDoc("org-engoff", MonitoringPolicyKeys.RemediationEnabled, "false");
        rig.Cycle();
        Assert.Empty(rig.Remediation.Dispatches);
    }

    // ---- reporting -----------------------------------------------------------------

    [Fact]
    public void Report_BeforeAnyCycle_IsUnknownNeverCompliant()
    {
        var rig = new Rig();
        var report = rig.Service.BuildReport(Dev);
        Assert.Equal(DriftOutcomes.Unknown, report.Outcome);
        Assert.Single(report.Indeterminate);
    }

    [Fact]
    public void Report_AfterDriftCycle_CarriesDeviationsAndActiveAlertIds()
    {
        var rig = DriftedRig();
        rig.Cycle();
        var report = rig.Service.BuildReport(Dev);
        Assert.Equal(DriftOutcomes.Drifted, report.Outcome);
        Assert.Single(report.Deviations);
        Assert.Single(report.ActiveDriftAlertIds);
        Assert.False(string.IsNullOrWhiteSpace(report.BaselineHash));
    }

    [Fact]
    public void Cycle_NoObservedState_Unknown_NothingRaisedNothingCleared()
    {
        var rig = DriftedRig();
        rig.Cycle();
        rig.Provider.SetNull(Dev);
        rig.Now = T0.AddMinutes(10);
        var result = rig.Cycle();
        Assert.True(result.Ran);
        Assert.Single(rig.Centre.ActiveAlerts); // yesterday's drift is not cleared by silence
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "drift_cycle_unknown");
    }

    // ---- admission validation ----------------------------------------------------------

    [Fact]
    public void Admission_UnknownKind_DuplicateItem_BadPostureTarget_AllRefuse()
    {
        var store = new BaselineStore();
        var badKind = Doc(new[] { BaselineItem.Create("x", "teleport_state", "T", expected: "Running") });
        Assert.False(store.Admit(badKind, T0).Accepted);
        var dup = Doc(new BaselineItem[] { Svc(), Svc() });
        Assert.False(store.Admit(dup, T0).Accepted);
        var badPosture = Doc(new[] { Posture("p", "bluetooth") });
        Assert.False(store.Admit(badPosture, T0).Accepted);
        var anonymous = new BaselineDocument("b-anon", 1, PolicyLevels.Org, Scope, T0, "", new[] { Svc() }, "");
        Assert.False(store.Admit(anonymous, T0).Accepted);
        Assert.Empty(store.AllCurrent);
    }

    [Fact]
    public void Admission_CreatesRevisionRecordTrail()
    {
        var store = new BaselineStore();
        Assert.True(store.Admit(Doc(new[] { Svc() }, rev: 1), T0).Accepted);
        Assert.True(store.Admit(Doc(new[] { Svc() }, rev: 2, effective: T0.AddHours(1)), T0).Accepted);
        Assert.Equal(2, store.RevisionRecords.Count);
        Assert.Equal(0, store.RevisionRecords[0].FromRevision);
        Assert.Equal(1, store.RevisionRecords[1].FromRevision);
        Assert.Equal(2, store.RevisionRecords[1].ToRevision);
    }

    // ---- observed-state factories ---------------------------------------------------------

    private static DeviceInventoryRecord InventoryRecord(params SoftwareItem[] software) => new(
        DeviceId: Dev, ScopeId: Scope, Hostname: "WS-01",
        Hardware: new HardwareSnapshot("Dell Inc.", "OptiPlex 7010", "ABC1234", "Intel i7", 16,
            16_000_000_000, "Windows 11 Pro", "26100.1", "10.0.26100", "1.2.3",
            Array.Empty<DiskInfo>(), Array.Empty<PeripheralInfo>(), T0),
        Software: software, CustomFields: new Dictionary<string, string>(), Tags: new HashSet<string>(),
        FirstSeenUtc: T0, LastSeenUtc: T0, LastChangedUtc: T0, Revision: 0);

    [Fact]
    public void ObservedFactory_FromInventory_MapsSoftwareSection()
    {
        var observed = ObservedStateFactory.FromInventory(InventoryRecord(Sw("Solitaire", "1.0")));
        Assert.True(observed.HasSection(ObservedSections.Software));
        Assert.False(observed.HasSection(ObservedSections.Services));
        var baseline = new EffectiveBaseline(Dev, T0,
            new[] { new EffectiveBaselineItem(Forbidden("forbid-game", "Solitaire"), PolicyLevels.Org, "base-site-servers", 1) },
            new[] { "base-site-servers@r1" });
        var eval = BaselineEvaluator.Evaluate(baseline, observed, BaselineItemKinds.All, T0);
        Assert.Equal(DriftOutcomes.Drifted, eval.Outcome);
    }

    [Fact]
    public void ObservedFactory_FromMonitorSample_MapsServicesAndSecurity()
    {
        var sample = new EndpointSample(Dev, T0, null, null,
            Array.Empty<DiskSample>(), new[] { SvcObs("Niagara", "Stopped") },
            Array.Empty<ProcessSample>(), Array.Empty<AppSample>(), Array.Empty<EventLogSample>(),
            new SecurityStateSample(true, true, true), null, Array.Empty<GuestSample>(), Array.Empty<string>());
        var observed = ObservedStateFactory.FromMonitorSample(sample);
        // D38 fix (F7): the monitor sample's service list is a
        // WATCHED subset, not a complete enumeration — the data is
        // carried but the Services section is NOT claimed
        // collected, so baseline service items are indeterminate
        // from this source, never passed on an unobserved absence.
        Assert.False(observed.HasSection(ObservedSections.Services));
        Assert.True(observed.HasSection(ObservedSections.Security));
        Assert.Equal("Stopped", observed.Services[0].State);
    }

    // ---- hub cross-check (agreeing case; the lying cases are destruction) -------

    [Fact]
    public void CrossCheck_AgentAndInventoryAgree_IsClean_AndNamesUncheckedKinds()
    {
        var rig = new Rig();
        rig.Admit(Doc(new BaselineItem[] { Svc(), Forbidden("forbid-game", "Solitaire") }));
        rig.Provider.Set(Observed(
            services: new[] { SvcObs("Niagara", "Running") },
            software: Array.Empty<SoftwareItem>()));
        var eval = rig.Cycle().Evaluation!;
        var check = HubDriftCrossCheck.Check(eval, InventoryRecord(), rig.Service.EffectiveFor(Dev));
        Assert.True(check.Clean, string.Join(";", check.Discrepancies));
        // D38 fix (F5): the inventory record here is EMPTY and
        // never populated (first sighting, revision 0, no
        // software) — it corroborates nothing, so forbid-game is
        // UNCHECKED, not "checked and clean". The original
        // assertion embodied the finding.
        Assert.Empty(check.CheckedItemIds);
        Assert.Contains("forbid-game", check.UncheckedItemIds);
        Assert.Contains("svc-niagara", check.UncheckedItemIds);
    }
}
