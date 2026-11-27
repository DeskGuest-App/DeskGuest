using DeskGuest.Core.Services;
using DeskGuest.Shared.Compliance;
using DeskGuest.Shared.Encryption;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.Monitoring;
using DeskGuest.Shared.Security;

namespace DeskGuest.Tests;

// RMM-18 — Disk-encryption enforcement + recovery-key escrow.
// Per-volume state honesty (unknown is a state; suspended ≠
// encrypted), policy requirement under the ceiling discipline,
// dual-control escrow reveal, the notice/deferral enable flow, and
// the RMM-01 / RMM-09 feed shapes. All drivers are fakes; NO real
// encryption operation happens anywhere in this suite.
public class Rmm18Tests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    private const string Dev = "dev-1";
    private const string Scope = "co-1";
    private const string AdminA = "admin-a";
    private const string AdminB = "admin-b";
    public const string KeyC = "111111-222222-333333-444444-555555-666666-777777-888888";
    public const string KeyD = "999999-888888-777777-666666-555555-444444-333333-222222";

    private static VolumeEncryptionState Vol(string id, string state, bool? protection = true, double? pct = 100) =>
        new(id, state, protection, pct, "recovery_password");

    public sealed class Rig
    {
        public DateTimeOffset Now = T0;
        public ChainedAuditLog Audit = new();
        public ManagementPolicyService Policies;
        public FakeEncryptionDriver Driver = new();
        public EncryptionEnforcementService Service;
        public StaticDeviceFacts Facts = StaticDeviceFacts.Of(Dev, Scope);

        public Rig()
        {
            Policies = new ManagementPolicyService(Audit, null);
            Service = new EncryptionEnforcementService(Audit, Policies, Driver,
                new DevOnlyPassThroughProtector(), id => id == Dev ? Facts : null, () => Now,
                a => a == AdminA || a == AdminB); // bd-shared-sec-1/F5: dual control fails closed unwired — rigs wire an authorizer
        }

        public void RequireAtOrg()
        {
            var v = Policies.AdmitLocalDocument(new ManagementPolicyDocument(
                "org-req", PolicyLevels.Org, Scope,
                new Dictionary<string, string> { [EncryptionPolicyKeys.Required] = "true" }, 1), "test");
            Assert.True(v.Allowed, v.Reason);
        }

        public DeviceEncryptionReport Report(params VolumeEncryptionState[] vols)
        {
            Driver = new FakeEncryptionDriver(vols);
            Service = new EncryptionEnforcementService(Audit, Policies, Driver,
                new DevOnlyPassThroughProtector(), id => id == Dev ? Facts : null, () => Now,
                a => a == AdminA || a == AdminB); // bd-shared-sec-1/F5: dual control fails closed unwired — rigs wire an authorizer
            var (ok, reason, report) = Service.ReportState(Dev, "agent");
            Assert.True(ok, reason);
            return report!;
        }
    }

    // ---- state honesty -----------------------------------------------------

    [Fact]
    public void AllVolumesEncrypted_ReportIsCompliantShape()
    {
        var rig = new Rig();
        var report = rig.Report(Vol("C:", VolumeEncryptionStates.Encrypted), Vol("D:", VolumeEncryptionStates.Encrypted));
        Assert.True(report.AllEncrypted);
        Assert.Equal(true, report.ToMonitorEncryptionEnabled());
    }

    [Fact]
    public void SuspendedVolume_IsNotEncrypted()
    {
        var rig = new Rig();
        var report = rig.Report(Vol("C:", VolumeEncryptionStates.Suspended, protection: false));
        Assert.False(report.AllEncrypted);
        Assert.Equal(false, report.ToMonitorEncryptionEnabled());
    }

    [Fact]
    public void EncryptedStateWithProtectionOff_IsNotEncrypted()
    {
        var rig = new Rig();
        var report = rig.Report(Vol("C:", VolumeEncryptionStates.Encrypted, protection: false));
        Assert.False(report.AllEncrypted);
        Assert.Equal(false, report.ToMonitorEncryptionEnabled());
    }

    [Fact]
    public void EncryptingVolume_IsNotYetEncrypted()
    {
        var rig = new Rig();
        var report = rig.Report(Vol("C:", VolumeEncryptionStates.Encrypting, protection: false, pct: 42));
        Assert.False(report.AllEncrypted);
        Assert.Equal(false, report.ToMonitorEncryptionEnabled());
    }

    [Fact]
    public void UnknownVolume_NeverReadsAsEncrypted()
    {
        var rig = new Rig();
        var report = rig.Report(Vol("C:", VolumeEncryptionStates.Unknown, protection: null, pct: null));
        Assert.False(report.AllEncrypted);
        Assert.Null(report.ToMonitorEncryptionEnabled());
    }

    [Fact]
    public void EmptyReport_IsNotCompliance()
    {
        var report = new DeviceEncryptionReport(Dev, Scope, Array.Empty<VolumeEncryptionState>(), T0);
        Assert.False(report.AllEncrypted);
        Assert.Null(report.ToMonitorEncryptionEnabled());
    }

    [Fact]
    public void MixedUnknownAndBad_BadWinsForMonitor()
    {
        var rig = new Rig();
        var report = rig.Report(
            Vol("C:", VolumeEncryptionStates.Unknown, protection: null, pct: null),
            Vol("D:", VolumeEncryptionStates.NotEncrypted, protection: false, pct: 0));
        Assert.Equal(false, report.ToMonitorEncryptionEnabled());
    }

    [Fact]
    public void UnavailableDriver_ReportsUnknownAndRefusesEnable()
    {
        var d = new UnavailableEncryptionDriver();
        var vols = d.ReadVolumes(Dev, T0);
        Assert.All(vols, v => Assert.Equal(VolumeEncryptionStates.Unknown, v.State));
        Assert.False(d.BeginEnable(Dev, "OS", T0).Ok);
        Assert.Null(d.ReadRecoveryKey(Dev, "OS", T0));
    }

    // ---- RMM-01 / RMM-09 feeds ------------------------------------------------

    [Fact]
    public void SecuritySample_FeedsRmm01EncryptionCondition()
    {
        var rig = new Rig();
        rig.Report(Vol("C:", VolumeEncryptionStates.NotEncrypted, protection: false, pct: 0));
        var sample = new EndpointSample(Dev, T0, null, null,
            Array.Empty<DiskSample>(), Array.Empty<ServiceSample>(), Array.Empty<ProcessSample>(),
            Array.Empty<AppSample>(), Array.Empty<EventLogSample>(),
            rig.Service.SecuritySampleFor(Dev), null, Array.Empty<GuestSample>(), Array.Empty<string>());
        var cond = MonitorCondition.Create("security-encryption-off", "Disk encryption off",
            ConditionKinds.SecurityEncryptionOff);
        var eval = ConditionEvaluator.Evaluate(cond, sample);
        Assert.Equal(ConditionOutcome.Firing, eval.Outcome);
    }

    [Fact]
    public void SecuritySample_NoReport_ConditionIsIndeterminateNotClear()
    {
        var rig = new Rig();
        var sample = new EndpointSample(Dev, T0, null, null,
            Array.Empty<DiskSample>(), Array.Empty<ServiceSample>(), Array.Empty<ProcessSample>(),
            Array.Empty<AppSample>(), Array.Empty<EventLogSample>(),
            rig.Service.SecuritySampleFor(Dev), null, Array.Empty<GuestSample>(), Array.Empty<string>());
        var cond = MonitorCondition.Create("security-encryption-off", "Disk encryption off",
            ConditionKinds.SecurityEncryptionOff);
        Assert.Equal(ConditionOutcome.Indeterminate, ConditionEvaluator.Evaluate(cond, sample).Outcome);
    }

    [Fact]
    public void SecurityStateFor_LandsInRmm09StoreShape()
    {
        var rig = new Rig();
        rig.Report(Vol("C:", VolumeEncryptionStates.Encrypted));
        var state = rig.Service.SecurityStateFor(Dev);
        Assert.NotNull(state);
        var store = new SecurityStateStore();
        Assert.True(store.Record(state!));
        Assert.Equal(true, store.Get(Dev)!.EncryptionEnabled);
    }

    [Fact]
    public void ComplianceFact_EncryptedDevice_Passes()
    {
        var rig = new Rig();
        rig.Report(Vol("C:", VolumeEncryptionStates.Encrypted));
        var fact = rig.Service.BuildComplianceFact(Dev);
        Assert.NotNull(fact);
        Assert.Equal(ComplianceFactKinds.EncryptionState, fact!.Kind);
        Assert.True(fact.Passing);
    }

    [Fact]
    public void ComplianceFact_UnencryptedDevice_Fails_UnknownDevice_HasNoFact()
    {
        var rig = new Rig();
        rig.Report(Vol("C:", VolumeEncryptionStates.NotEncrypted, protection: false, pct: 0));
        var fact = rig.Service.BuildComplianceFact(Dev);
        Assert.NotNull(fact);
        Assert.False(fact!.Passing);

        var rig2 = new Rig();
        rig2.Report(Vol("C:", VolumeEncryptionStates.Unknown, protection: null, pct: null));
        Assert.Null(rig2.Service.BuildComplianceFact(Dev)); // honestly unknown → missing_fact, never a guess
    }

    // ---- requirement + enforcement ---------------------------------------------

    [Fact]
    public void NoRequirement_NotRequiredOutcome()
    {
        var rig = new Rig();
        rig.Report(Vol("C:", VolumeEncryptionStates.NotEncrypted, protection: false, pct: 0));
        var verdict = rig.Service.EvaluateCompliance(Dev, AdminA);
        Assert.Equal(EncryptionComplianceOutcomes.NotRequired, verdict.Outcome);
    }

    [Fact]
    public void OrgRequirement_UnencryptedDevice_NonCompliantAndAudited()
    {
        var rig = new Rig();
        rig.RequireAtOrg();
        rig.Report(Vol("C:", VolumeEncryptionStates.NotEncrypted, protection: false, pct: 0));
        var verdict = rig.Service.EvaluateCompliance(Dev, AdminA);
        Assert.Equal(EncryptionComplianceOutcomes.NonCompliant, verdict.Outcome);
        Assert.Contains(verdict.OffendingVolumes, v => v.Contains("C:"));
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "encryption_noncompliant");
    }

    [Fact]
    public void OrgRequirement_EncryptedDevice_Compliant()
    {
        var rig = new Rig();
        rig.RequireAtOrg();
        rig.Report(Vol("C:", VolumeEncryptionStates.Encrypted), Vol("D:", VolumeEncryptionStates.Encrypted));
        Assert.Equal(EncryptionComplianceOutcomes.Compliant, rig.Service.EvaluateCompliance(Dev, AdminA).Outcome);
    }

    [Fact]
    public void OrgRequirement_UnknownVolume_OutcomeIsUnknownNeverCompliant()
    {
        var rig = new Rig();
        rig.RequireAtOrg();
        rig.Report(Vol("C:", VolumeEncryptionStates.Unknown, protection: null, pct: null));
        Assert.Equal(EncryptionComplianceOutcomes.Unknown, rig.Service.EvaluateCompliance(Dev, AdminA).Outcome);
    }

    [Fact]
    public void OrgRequirement_NoReport_OutcomeIsUnknown()
    {
        var rig = new Rig();
        rig.RequireAtOrg();
        Assert.Equal(EncryptionComplianceOutcomes.Unknown, rig.Service.EvaluateCompliance(Dev, AdminA).Outcome);
    }

    [Fact]
    public void GroupRequirement_AppliesToMembersOnly()
    {
        var rig = new Rig();
        rig.Policies.Engine.AddGroup(new GroupDefinition("grp-enc", "Encrypted class", Array.Empty<GroupRule>()));
        var member = StaticDeviceFacts.Of(Dev, Scope, groups: new[] { "grp-enc" });
        var svc = new EncryptionEnforcementService(rig.Audit, rig.Policies, rig.Driver,
            new DevOnlyPassThroughProtector(), id => member, () => rig.Now);
        var v = rig.Policies.AdmitLocalDocument(new ManagementPolicyDocument(
            "grp-req", PolicyLevels.Group, "grp-enc",
            new Dictionary<string, string> { [EncryptionPolicyKeys.Required] = "true" }, 1), "test");
        Assert.True(v.Allowed, v.Reason);
        Assert.True(svc.RequirementFor(Dev).Required);
        // The rig's own facts (no group) are not bound by the group doc.
        Assert.False(rig.Service.RequirementFor(Dev).Required);
    }

    // ---- escrow happy path --------------------------------------------------------

    [Fact]
    public void Escrow_ThenDualControlReveal_ReturnsKey()
    {
        var rig = new Rig();
        rig.Report(Vol("C:", VolumeEncryptionStates.Encrypted));
        rig.Driver.SetKey("C:", KeyC);
        var (ok, reason, escrowed, without) = rig.Service.EscrowRecoveryKeys(Dev, "agent");
        Assert.True(ok, reason);
        Assert.Single(escrowed);
        Assert.Empty(without);

        var meta = escrowed[0];
        var (rok, rreason, req) = rig.Service.Escrow.RequestReveal(meta.Ref, Dev, "C:", AdminA, "lost-laptop recovery", rig.Now);
        Assert.True(rok, rreason);
        Assert.True(rig.Service.Escrow.ApproveReveal(req!.RequestId, AdminB, rig.Now).Ok);
        var (vok, vreason, key) = rig.Service.Escrow.Reveal(req.RequestId, AdminA, rig.Now);
        Assert.True(vok, vreason);
        Assert.Equal(KeyC, key);
    }

    [Fact]
    public void Escrow_VolumeWithoutKey_IsNamedNotHidden()
    {
        var rig = new Rig();
        rig.Report(Vol("C:", VolumeEncryptionStates.Encrypted), Vol("D:", VolumeEncryptionStates.Encrypted));
        rig.Driver.SetKey("C:", KeyC);
        var (ok, _, escrowed, without) = rig.Service.EscrowRecoveryKeys(Dev, "agent");
        Assert.True(ok);
        Assert.Single(escrowed);
        Assert.Equal(new[] { "D:" }, without);
    }

    [Fact]
    public void Escrow_WithoutReport_Refuses()
    {
        var rig = new Rig();
        var (ok, reason, _, _) = rig.Service.EscrowRecoveryKeys(Dev, "agent");
        Assert.False(ok);
        Assert.Contains("no encryption state report", reason);
    }

    [Fact]
    public void Escrow_IsIdempotentForSameKey()
    {
        var escrow = new RecoveryKeyEscrow(new DevOnlyPassThroughProtector(), new ChainedAuditLog(), () => T0);
        var a = escrow.Escrow(Dev, "C:", Scope, KeyC, "recovery_password", "agent", T0);
        var b = escrow.Escrow(Dev, "C:", Scope, KeyC, "recovery_password", "agent", T0);
        Assert.Equal(a.Metadata!.Ref, b.Metadata!.Ref);
        Assert.Single(escrow.List(Dev));
    }

    // ---- enable flow happy paths ------------------------------------------------------

    [Fact]
    public void EnableFlow_NoticeAckProceed_CallsDriverOnce_AndLandsEncrypting()
    {
        var rig = new Rig();
        rig.Report(Vol("C:", VolumeEncryptionStates.NotEncrypted, protection: false, pct: 0));
        var (ok, reason, flow) = rig.Service.RequestEnable(Dev, "C:", AdminA);
        Assert.True(ok, reason);
        Assert.True(rig.Service.IssueUserNotice(flow!.FlowId, "agent", "endpoint-dialog:shown").Ok);
        Assert.True(rig.Service.AcknowledgeEnable(flow.FlowId, "device-user").Ok);
        var (pok, preason, done) = rig.Service.ProceedEnable(flow.FlowId, AdminA);
        Assert.True(pok, preason);
        Assert.Equal(EnableFlowStates.EnableStarted, done!.State);
        Assert.Equal(1, rig.Driver.BeginEnableCalls);
        // The honest post-enable state is encrypting, not encrypted.
        rig.Now = T0.AddMinutes(5);
        var report = rig.Service.ReportState(Dev, "agent").Report!;
        Assert.Equal(VolumeEncryptionStates.Encrypting, report.Volumes[0].State);
        Assert.False(report.AllEncrypted);
    }

    [Fact]
    public void EnableFlow_DeferralExpiry_AllowsProceed()
    {
        var rig = new Rig();
        rig.Report(Vol("C:", VolumeEncryptionStates.NotEncrypted, protection: false, pct: 0));
        var flow = rig.Service.RequestEnable(Dev, "C:", AdminA).Flow!;
        rig.Service.IssueUserNotice(flow.FlowId, "agent", "endpoint-dialog:shown");
        Assert.True(rig.Service.DeferEnable(flow.FlowId, "device-user", TimeSpan.FromHours(4)).Ok);
        Assert.False(rig.Service.ProceedEnable(flow.FlowId, AdminA).Ok); // still deferred
        rig.Now = T0.AddHours(5);
        Assert.True(rig.Service.ProceedEnable(flow.FlowId, AdminA).Ok);
    }

    [Fact]
    public void EnableFlow_DeferralBeyondCap_IsClampedAndStated()
    {
        var rig = new Rig();
        rig.Report(Vol("C:", VolumeEncryptionStates.NotEncrypted, protection: false, pct: 0));
        var flow = rig.Service.RequestEnable(Dev, "C:", AdminA).Flow!;
        rig.Service.IssueUserNotice(flow.FlowId, "agent", "endpoint-dialog:shown");
        var (ok, reason, deferred) = rig.Service.DeferEnable(flow.FlowId, "device-user", TimeSpan.FromDays(30));
        Assert.True(ok);
        Assert.Contains("CLAMPED", reason);
        Assert.Equal(T0.AddHours(EncryptionPolicyKeys.DefaultMaxDeferHours), deferred!.DeferredUntilUtc);
    }

    [Fact]
    public void EnableFlow_AlreadyEncrypted_Refuses()
    {
        var rig = new Rig();
        rig.Report(Vol("C:", VolumeEncryptionStates.Encrypted));
        Assert.False(rig.Service.RequestEnable(Dev, "C:", AdminA).Ok);
        Assert.Equal(0, rig.Driver.BeginEnableCalls);
    }

    // ---- policy toggle -----------------------------------------------------------------

    [Fact]
    public void PolicyToggleOff_RefusesOperations()
    {
        var rig = new Rig();
        var v = rig.Policies.AdmitLocalDocument(new ManagementPolicyDocument(
            "org-off", PolicyLevels.Org, Scope,
            new Dictionary<string, string> { [EncryptionPolicyKeys.Enabled] = "false" }, 1), "test");
        Assert.True(v.Allowed, v.Reason);
        Assert.False(rig.Service.ReportState(Dev, "agent").Ok);
        Assert.False(rig.Service.EscrowRecoveryKeys(Dev, "agent").Ok);
        Assert.False(rig.Service.RequestEnable(Dev, "C:", AdminA).Ok);
    }

    [Fact]
    public void FeatureToggle_SeededOn()
    {
        var registry = FeatureToggleRegistry.Seeded();
        Assert.True(registry.TryGet(EncryptionPolicyKeys.Enabled, out var t));
        Assert.True(t!.DefaultEnabled);
    }
}
