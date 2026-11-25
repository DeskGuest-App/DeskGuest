using Acp.Core.Services;
using Acp.Shared.Encryption;
using Acp.Shared.Enterprise;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Security;

namespace Acp.Tests;

// RMM-18 D38 FIX lane (packet d73d0923) — permanent regression
// tests, one per confirmed finding. See
// builds/rmm-r-logs/log-rmm18-fix.md for the claim-by-claim
// reconciliation.
public class Rmm18FixTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    private const string Dev = "dev-1";
    private const string Scope = "co-1";
    private const string AdminA = "admin-a";
    private const string AdminB = "admin-b";
    private const string KeyC = Rmm18Tests.KeyC;
    private const string KeyD = Rmm18Tests.KeyD;

    private static VolumeEncryptionState Vol(string id, string state, bool? protection = true, double? pct = 100) =>
        new(id, state, protection, pct, "recovery_password");

    private sealed class Rig
    {
        public DateTimeOffset Now = T0;
        public ChainedAuditLog Audit = new();
        public ManagementPolicyService Policies;
        public FakeEncryptionDriver Driver;
        public EncryptionEnforcementService Service;
        public StaticDeviceFacts Facts = StaticDeviceFacts.Of(Dev, Scope);

        public Rig(Func<string, bool>? authorizer = null, params VolumeEncryptionState[] vols)
        {
            Policies = new ManagementPolicyService(Audit, null);
            Driver = new FakeEncryptionDriver(vols);
            Service = new EncryptionEnforcementService(Audit, Policies, Driver,
                new DevOnlyPassThroughProtector(), id => id == Dev ? Facts : null, () => Now,
                // bd-shared-sec-1/F5: dual control fails closed when
                // unwired — a rig that passes no authorizer gets the
                // two named test admins, never an open door.
                authorizer ?? (a => a == AdminA || a == AdminB));
        }

        public void Admit(string id, string level, string target, string key, string value)
        {
            var v = Policies.AdmitLocalDocument(new ManagementPolicyDocument(
                id, level, target, new Dictionary<string, string> { [key] = value }, 1), "test");
            Assert.True(v.Allowed, v.Reason);
        }

        public string EscrowedRef()
        {
            Driver.SetKey("C:", KeyC);
            Assert.True(Service.ReportState(Dev, "agent").Ok);
            var (ok, reason, escrowed, _) = Service.EscrowRecoveryKeys(Dev, "agent");
            Assert.True(ok, reason);
            return escrowed[0].Ref;
        }
    }

    // ---- F1: the escrow owns its clock -------------------------------------

    [Fact]
    public void F1_BackdatedCallerNow_CannotResurrectExpiredApproval()
    {
        var rig = new Rig(null, Vol("C:", VolumeEncryptionStates.Encrypted));
        var refId = rig.EscrowedRef();
        var req = rig.Service.Escrow.RequestReveal(refId, Dev, "C:", AdminA, "recovery", rig.Now).Request!;
        rig.Now = T0.AddHours(2); // the approval window has REALLY passed
        // The attacker passes the request's own RequestedUtc as `now`.
        var approve = rig.Service.Escrow.ApproveReveal(req.RequestId, AdminB, req.RequestedUtc);
        Assert.False(approve.Ok);
        Assert.Contains("expired", approve.Reason);
    }

    [Fact]
    public void F1_BackdatedCallerNow_CannotRevealAfterRealExpiry()
    {
        var rig = new Rig(null, Vol("C:", VolumeEncryptionStates.Encrypted));
        var refId = rig.EscrowedRef();
        var req = rig.Service.Escrow.RequestReveal(refId, Dev, "C:", AdminA, "recovery", rig.Now).Request!;
        Assert.True(rig.Service.Escrow.ApproveReveal(req.RequestId, AdminB, rig.Now).Ok);
        rig.Now = T0.AddHours(2);
        var reveal = rig.Service.Escrow.Reveal(req.RequestId, AdminA, req.RequestedUtc);
        Assert.False(reveal.Ok);
        Assert.Null(reveal.KeyMaterial);
    }

    // ---- F2: actor normalisation + admin authorizer --------------------------

    [Fact]
    public void F2_WhitespaceVariantSelfApproval_Refuses()
    {
        var rig = new Rig(null, Vol("C:", VolumeEncryptionStates.Encrypted));
        var refId = rig.EscrowedRef();
        var req = rig.Service.Escrow.RequestReveal(refId, Dev, "C:", AdminA, "recovery", rig.Now).Request!;
        var sneaky = rig.Service.Escrow.ApproveReveal(req.RequestId, "admin-a ", rig.Now);
        Assert.False(sneaky.Ok);
        Assert.Contains("second, distinct admin", sneaky.Reason);
    }

    [Fact]
    public void F2_NonAdmin_CannotRequestOrApprove_WhenAuthorizerInjected()
    {
        var admins = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { AdminA, AdminB };
        var rig = new Rig(a => admins.Contains(a), Vol("C:", VolumeEncryptionStates.Encrypted));
        var refId = rig.EscrowedRef();
        var byMallory = rig.Service.Escrow.RequestReveal(refId, Dev, "C:", "mallory", "recovery", rig.Now);
        Assert.False(byMallory.Ok);
        Assert.Contains("not an authorized admin", byMallory.Reason);
        var req = rig.Service.Escrow.RequestReveal(refId, Dev, "C:", AdminA, "recovery", rig.Now).Request!;
        Assert.False(rig.Service.Escrow.ApproveReveal(req.RequestId, "mallory", rig.Now).Ok);
        Assert.True(rig.Service.Escrow.ApproveReveal(req.RequestId, AdminB, rig.Now).Ok);
    }

    // ---- F3: atomicity --------------------------------------------------------

    [Fact]
    public void F3_ConcurrentReveals_ExactlyOneReturnsTheKey()
    {
        var rig = new Rig(null, Vol("C:", VolumeEncryptionStates.Encrypted));
        var refId = rig.EscrowedRef();
        var req = rig.Service.Escrow.RequestReveal(refId, Dev, "C:", AdminA, "recovery", rig.Now).Request!;
        rig.Service.Escrow.ApproveReveal(req.RequestId, AdminB, rig.Now);
        var results = new (bool Ok, string Reason, string? KeyMaterial)[8];
        Parallel.For(0, results.Length, i => results[i] = rig.Service.Escrow.Reveal(req.RequestId, AdminA, rig.Now));
        Assert.Equal(1, results.Count(r => r.Ok));
        Assert.Equal(1, results.Count(r => r.KeyMaterial == KeyC));
    }

    [Fact]
    public void F3_ConcurrentProceeds_CallDriverExactlyOnce()
    {
        var rig = new Rig(null, Vol("C:", VolumeEncryptionStates.NotEncrypted, protection: false, pct: 0));
        rig.Service.ReportState(Dev, "agent");
        var flow = rig.Service.RequestEnable(Dev, "C:", AdminA).Flow!;
        rig.Service.IssueUserNotice(flow.FlowId, "agent", "endpoint-dialog:shown");
        rig.Service.AcknowledgeEnable(flow.FlowId, "device-user");
        var oks = new bool[8];
        Parallel.For(0, oks.Length, i => oks[i] = rig.Service.ProceedEnable(flow.FlowId, AdminA).Ok);
        Assert.Equal(1, oks.Count(o => o));
        Assert.Equal(1, rig.Driver.BeginEnableCalls);
    }

    [Fact]
    public void F3_ConcurrentApproveAndDeny_ExactlyOneDecisionWins()
    {
        var rig = new Rig(null, Vol("C:", VolumeEncryptionStates.Encrypted));
        var refId = rig.EscrowedRef();
        var req = rig.Service.Escrow.RequestReveal(refId, Dev, "C:", AdminA, "recovery", rig.Now).Request!;
        var oks = new bool[2];
        Parallel.For(0, 2, i => oks[i] = i == 0
            ? rig.Service.Escrow.ApproveReveal(req.RequestId, AdminB, rig.Now).Ok
            : rig.Service.Escrow.DenyReveal(req.RequestId, AdminB, rig.Now).Ok);
        Assert.Equal(1, oks.Count(o => o));
    }

    // ---- F4: reports age out ----------------------------------------------------

    [Fact]
    public void F4_StaleReport_StopsServingOnEveryFeed()
    {
        var rig = new Rig(null, Vol("C:", VolumeEncryptionStates.Encrypted));
        rig.Admit("org-req", PolicyLevels.Org, Scope, EncryptionPolicyKeys.Required, "true");
        rig.Service.ReportState(Dev, "agent");
        Assert.Equal(true, rig.Service.SecuritySampleFor(Dev).EncryptionEnabled);
        Assert.Equal(EncryptionComplianceOutcomes.Compliant, rig.Service.EvaluateCompliance(Dev, AdminA).Outcome);
        rig.Now = T0.AddHours(25); // agent dead for a day: the frozen report must stop passing
        Assert.Null(rig.Service.SecuritySampleFor(Dev).EncryptionEnabled);
        Assert.Null(rig.Service.BuildComplianceFact(Dev));
        Assert.Null(rig.Service.SecurityStateFor(Dev));
        Assert.Equal(EncryptionComplianceOutcomes.Unknown, rig.Service.EvaluateCompliance(Dev, AdminA).Outcome);
        Assert.False(rig.Service.HasFreshReport(Dev));
    }

    // ---- F5: notice evidence + distinct acknowledgement ---------------------------

    [Fact]
    public void F5_NoticeWithoutDeliveryEvidence_Refuses()
    {
        var rig = new Rig(null, Vol("C:", VolumeEncryptionStates.NotEncrypted, protection: false, pct: 0));
        rig.Service.ReportState(Dev, "agent");
        var flow = rig.Service.RequestEnable(Dev, "C:", AdminA).Flow!;
        var noEvidence = rig.Service.IssueUserNotice(flow.FlowId, "agent", "  ");
        Assert.False(noEvidence.Ok);
        Assert.Contains("delivery evidence", noEvidence.Reason);
        Assert.Equal(EnableFlowStates.NoticePending, rig.Service.GetFlow(flow.FlowId)!.State);
    }

    [Fact]
    public void F5_RequesterCannotAcknowledgeOwnEnable()
    {
        var rig = new Rig(null, Vol("C:", VolumeEncryptionStates.NotEncrypted, protection: false, pct: 0));
        rig.Service.ReportState(Dev, "agent");
        var flow = rig.Service.RequestEnable(Dev, "C:", AdminA).Flow!;
        rig.Service.IssueUserNotice(flow.FlowId, "agent", "endpoint-dialog:shown");
        Assert.False(rig.Service.AcknowledgeEnable(flow.FlowId, AdminA).Ok);
        Assert.False(rig.Service.AcknowledgeEnable(flow.FlowId, "admin-a ").Ok); // whitespace is not a second person
        var userAck = rig.Service.AcknowledgeEnable(flow.FlowId, "device-user");
        Assert.True(userAck.Ok);
        Assert.Equal("device-user", userAck.Flow!.AcknowledgedBy);
        Assert.Equal(0, rig.Driver.BeginEnableCalls); // nothing silent happened along the way
    }

    // ---- F6: toggle ceiling ---------------------------------------------------------

    [Fact]
    public void F6_DeviceLevelToggleOff_DoesNotDisableEnforcement()
    {
        var rig = new Rig(null, Vol("C:", VolumeEncryptionStates.Encrypted));
        rig.Admit("dev-off", PolicyLevels.Device, Dev, EncryptionPolicyKeys.Enabled, "false");
        Assert.True(rig.Service.ReportState(Dev, "agent").Ok); // device cannot switch off its own enforcement
        // The org-level off switch still works (the legitimate control).
        var rig2 = new Rig(null, Vol("C:", VolumeEncryptionStates.Encrypted));
        rig2.Admit("org-off", PolicyLevels.Org, Scope, EncryptionPolicyKeys.Enabled, "false");
        Assert.False(rig2.Service.ReportState(Dev, "agent").Ok);
    }

    // ---- F7: agent-supplied observation instants ---------------------------------------

    [Fact]
    public void F7_ObservedState_OlderReplayAndFutureDated_BothRefuse()
    {
        var rig = new Rig();
        var first = rig.Service.ReportObservedState(Dev, "agent",
            new[] { Vol("C:", VolumeEncryptionStates.Encrypted) }, T0);
        Assert.True(first.Ok, first.Reason);
        var replay = rig.Service.ReportObservedState(Dev, "agent",
            new[] { Vol("C:", VolumeEncryptionStates.Suspended, protection: false) }, T0.AddHours(-1));
        Assert.False(replay.Ok);
        Assert.Equal(VolumeEncryptionStates.Encrypted, rig.Service.LatestReport(Dev)!.Volumes[0].State);
        var future = rig.Service.ReportObservedState(Dev, "agent",
            new[] { Vol("C:", VolumeEncryptionStates.Suspended, protection: false) }, T0.AddHours(1));
        Assert.False(future.Ok);
        Assert.Contains("future-dated", future.Reason);
    }

    // ---- F8: supersede marker + protector ID ----------------------------------------------

    [Fact]
    public void F8_Rotation_MarksSuperseded_AndListingsCarryProtectorId()
    {
        var audit = new ChainedAuditLog();
        var escrow = new RecoveryKeyEscrow(new DevOnlyPassThroughProtector(), audit, () => T0);
        var first = escrow.Escrow(Dev, "C:", Scope, KeyC, "recovery_password", "agent", T0, keyProtectorId: "prot-1111").Metadata!;
        var second = escrow.Escrow(Dev, "C:", Scope, KeyD, "recovery_password", "agent", T0, keyProtectorId: "prot-2222").Metadata!;
        var list = escrow.List(Dev);
        Assert.Equal(2, list.Count);
        var oldEntry = list.Single(m => m.Ref == first.Ref);
        var newEntry = list.Single(m => m.Ref == second.Ref);
        Assert.False(oldEntry.IsCurrentForVolume);
        Assert.True(newEntry.IsCurrentForVolume);
        Assert.Equal("prot-1111", oldEntry.KeyProtectorId);
        Assert.Equal("prot-2222", newEntry.KeyProtectorId);
    }

    // ---- F9: deferral cap ceiling ------------------------------------------------------------

    [Fact]
    public void F9_DeviceCap_CannotLoosenOrgCap_ButCanTighten()
    {
        var rig = new Rig();
        rig.Admit("org-cap", PolicyLevels.Org, Scope, EncryptionPolicyKeys.MaxDeferHours, "24");
        rig.Admit("dev-cap", PolicyLevels.Device, Dev, EncryptionPolicyKeys.MaxDeferHours, "720");
        Assert.Equal(24, EncryptionRequirementResolver.MaxDeferHours(rig.Policies.Engine, rig.Facts));
        var rig2 = new Rig();
        rig2.Admit("org-cap", PolicyLevels.Org, Scope, EncryptionPolicyKeys.MaxDeferHours, "24");
        rig2.Admit("dev-cap", PolicyLevels.Device, Dev, EncryptionPolicyKeys.MaxDeferHours, "12");
        Assert.Equal(12, EncryptionRequirementResolver.MaxDeferHours(rig2.Policies.Engine, rig2.Facts));
    }

    [Fact]
    public void F9_ZeroCap_IsInvalid_NotAZeroDeferral()
    {
        var rig = new Rig();
        rig.Admit("org-cap0", PolicyLevels.Org, Scope, EncryptionPolicyKeys.MaxDeferHours, "0");
        Assert.Equal(EncryptionPolicyKeys.DefaultMaxDeferHours,
            EncryptionRequirementResolver.MaxDeferHours(rig.Policies.Engine, rig.Facts));
    }

    // ---- F10: evaluator honesty ------------------------------------------------------------------

    [Fact]
    public void F10_EncryptedWithProtectionNotRead_VerdictIsUnknown()
    {
        var report = new DeviceEncryptionReport(Dev, Scope,
            new[] { Vol("C:", VolumeEncryptionStates.Encrypted, protection: null) }, T0);
        var req = new EncryptionRequirement(true, PolicyLevels.Org, "org-req", false, "required");
        Assert.Equal(EncryptionComplianceOutcomes.Unknown,
            EncryptionComplianceEvaluator.Evaluate(report, req, Dev).Outcome);
    }

    [Fact]
    public void F10_EncryptedStateAt42Percent_NeverCountsAsEncrypted()
    {
        var report = new DeviceEncryptionReport(Dev, Scope,
            new[] { Vol("C:", VolumeEncryptionStates.Encrypted, protection: true, pct: 42) }, T0);
        Assert.False(report.AllEncrypted);
        Assert.Null(report.ToMonitorEncryptionEnabled());
        var req = new EncryptionRequirement(true, PolicyLevels.Org, "org-req", false, "required");
        Assert.Equal(EncryptionComplianceOutcomes.Unknown,
            EncryptionComplianceEvaluator.Evaluate(report, req, Dev).Outcome);
    }

    // ---- F11: audit escaping -------------------------------------------------------------------------

    [Fact]
    public void F11_SpoofedFieldsInReason_AreEscapedInAudit()
    {
        var rig = new Rig(null, Vol("C:", VolumeEncryptionStates.Encrypted));
        var refId = rig.EscrowedRef();
        rig.Service.Escrow.RequestReveal(refId, Dev, "C:", AdminA, "x approvedBy=admin-b device=dev-9", rig.Now);
        var requested = rig.Audit.Entries.Single(e => e.Kind == "encryption_key_reveal_requested");
        Assert.Contains("approvedBy%3Dadmin-b", requested.Detail);
        Assert.DoesNotContain(" approvedBy=admin-b", requested.Detail);
        Assert.True(rig.Audit.Verify().Ok); // chain intact; meaning unspoofed
    }

    // ---- F12: audit growth, duplicate flows, escrow gate ------------------------------------------------

    [Fact]
    public void F12_RepeatedEvaluation_AuditsNoncomplianceOncePerTransition()
    {
        var rig = new Rig(null, Vol("C:", VolumeEncryptionStates.NotEncrypted, protection: false, pct: 0));
        rig.Admit("org-req", PolicyLevels.Org, Scope, EncryptionPolicyKeys.Required, "true");
        rig.Service.ReportState(Dev, "agent");
        rig.Service.EvaluateCompliance(Dev, AdminA);
        rig.Service.EvaluateCompliance(Dev, AdminA);
        rig.Service.EvaluateCompliance(Dev, AdminA);
        Assert.Equal(1, rig.Audit.Entries.Count(e => e.Kind == "encryption_noncompliant"));
    }

    [Fact]
    public void F12_DuplicateOpenFlow_Refused()
    {
        var rig = new Rig(null, Vol("C:", VolumeEncryptionStates.NotEncrypted, protection: false, pct: 0));
        rig.Service.ReportState(Dev, "agent");
        Assert.True(rig.Service.RequestEnable(Dev, "C:", AdminA).Ok);
        var dup = rig.Service.RequestEnable(Dev, "C:", AdminA);
        Assert.False(dup.Ok);
        Assert.Contains("already exists", dup.Reason);
        Assert.Single(rig.Service.Flows);
    }

    [Fact]
    public void F12_ToggleOff_BlocksTheEscrowRevealPathToo()
    {
        var rig = new Rig(null, Vol("C:", VolumeEncryptionStates.Encrypted));
        var refId = rig.EscrowedRef();
        rig.Admit("org-off", PolicyLevels.Org, Scope, EncryptionPolicyKeys.Enabled, "false");
        var req = rig.Service.Escrow.RequestReveal(refId, Dev, "C:", AdminA, "recovery", rig.Now);
        Assert.False(req.Ok);
        Assert.Contains("policy gate", req.Reason);
    }

    [Fact]
    public void F12_TerminalRevealRequests_ArePrunedOnNextRequest()
    {
        var rig = new Rig(null, Vol("C:", VolumeEncryptionStates.Encrypted));
        var refId = rig.EscrowedRef();
        var req = rig.Service.Escrow.RequestReveal(refId, Dev, "C:", AdminA, "recovery", rig.Now).Request!;
        rig.Service.Escrow.ApproveReveal(req.RequestId, AdminB, rig.Now);
        Assert.True(rig.Service.Escrow.Reveal(req.RequestId, AdminA, rig.Now).Ok);
        var next = rig.Service.Escrow.RequestReveal(refId, Dev, "C:", AdminB, "second recovery", rig.Now);
        Assert.True(next.Ok, next.Reason);
        Assert.DoesNotContain(rig.Service.Escrow.Requests, r => r.RequestId == req.RequestId);
        Assert.Single(rig.Service.Escrow.Requests);
    }
}
