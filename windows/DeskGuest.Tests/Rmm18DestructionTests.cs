using System.Text;
using DeskGuest.Core.Services;
using DeskGuest.Shared.Encryption;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.Security;

namespace DeskGuest.Tests;

// RMM-18 DESTRUCTION PASS — hostile attacks on the escrow, the
// state honesty, and the enforcement ceiling:
//   * escrow extraction: every surface that could surface key
//     material (listings, audit text in ALL export formats, error
//     messages, result strings) is grepped for key-shaped strings;
//   * single-actor reveal: dual control is real, in every order;
//   * reveal without audit: the reveal's audit entry precedes the
//     key leaving the vault; there is no unaudited path;
//   * state lying: suspended / protection-off / mid-encryption
//     states can never be presented as encrypted on ANY surface;
//   * escrow substitution: a key bound to one device/volume cannot
//     be revealed against another, and tampered vault material
//     refuses instead of revealing the wrong key;
//   * ceiling bypass: a device-level policy document cannot weaken
//     an org requirement;
//   * silent encrypt: the driver is unreachable without notice +
//     (acknowledgement | expired deferral), in every flow order.
public class Rmm18DestructionTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    private const string Dev = "dev-1";
    private const string Dev2 = "dev-2";
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

        public Rig(params VolumeEncryptionState[] vols)
        {
            Policies = new ManagementPolicyService(Audit, null);
            Driver = new FakeEncryptionDriver(vols);
            Service = new EncryptionEnforcementService(Audit, Policies, Driver,
                new DevOnlyPassThroughProtector(), id => id == Dev ? Facts : null, () => Now,
                a => a == AdminA || a == AdminB); // bd-shared-sec-1/F5: authorizer wired (fail-closed unwired)
        }

        public string AllAuditText()
        {
            var sb = new StringBuilder();
            sb.Append(Audit.ExportJson("attacker", Now));
            sb.Append(Audit.ExportCsv("attacker", Now));
            sb.Append(Audit.ExportCef("attacker", Now));
            return sb.ToString();
        }
    }

    private static (Rig Rig, string Ref) EscrowedRig()
    {
        var rig = new Rig(Vol("C:", VolumeEncryptionStates.Encrypted));
        rig.Driver.SetKey("C:", KeyC);
        Assert.True(rig.Service.ReportState(Dev, "agent").Ok);
        var (ok, reason, escrowed, _) = rig.Service.EscrowRecoveryKeys(Dev, "agent");
        Assert.True(ok, reason);
        return (rig, escrowed[0].Ref);
    }

    // ---- escrow extraction ----------------------------------------------------

    [Fact]
    public void KeyMaterial_AppearsInNoListingAuditOrError()
    {
        var (rig, refId) = EscrowedRig();
        // Exercise every path: request, approve, reveal, plus refusals.
        var req = rig.Service.Escrow.RequestReveal(refId, Dev, "C:", AdminA, "recovery", rig.Now).Request!;
        rig.Service.Escrow.ApproveReveal(req.RequestId, AdminB, rig.Now);
        var revealed = rig.Service.Escrow.Reveal(req.RequestId, AdminA, rig.Now);
        Assert.True(revealed.Ok);
        rig.Service.Escrow.RequestReveal(refId, Dev2, "C:", AdminA, "wrong device", rig.Now);
        rig.Service.Escrow.Escrow(Dev, "C:", Scope, "", "recovery_password", "agent", rig.Now);

        var listing = string.Join("\n", rig.Service.Escrow.List().Select(m => m.ToString()));
        Assert.DoesNotContain(KeyC, listing);
        Assert.DoesNotContain(KeyC, rig.AllAuditText());
        // The fingerprint is fine to show; the key is not — and no
        // audit entry may carry even a 12-char slice of the key.
        Assert.DoesNotContain(KeyC[..12], rig.AllAuditText());
    }

    [Fact]
    public void EscrowMetadata_HasNoKeyFieldByConstruction()
    {
        var props = typeof(EscrowedKeyMetadata).GetProperties().Select(p => p.Name).ToList();
        // D38 F8 amendment: KeyProtectorId is an OS protector IDENTIFIER (the GUID the recovery screen shows), not key material — allowed alongside the fingerprint/type.
        Assert.DoesNotContain(props, n => n.Contains("Key") && n != "KeyFingerprint" && n != "KeyProtectorType" && n != "KeyProtectorId");
        var (rig, _) = EscrowedRig();
        var meta = rig.Service.Escrow.List(Dev)[0];
        Assert.Equal(EncryptionHash.Sha256Hex(KeyC), meta.KeyFingerprint);
    }

    // ---- single-actor reveal ------------------------------------------------------

    [Fact]
    public void SingleActor_CannotReveal_RequestApproveRevealAlone()
    {
        var (rig, refId) = EscrowedRig();
        var req = rig.Service.Escrow.RequestReveal(refId, Dev, "C:", AdminA, "recovery", rig.Now).Request!;
        // Self-approval refuses.
        var selfApprove = rig.Service.Escrow.ApproveReveal(req.RequestId, AdminA, rig.Now);
        Assert.False(selfApprove.Ok);
        Assert.Contains("second, distinct admin", selfApprove.Reason);
        // Reveal without approval refuses.
        var early = rig.Service.Escrow.Reveal(req.RequestId, AdminA, rig.Now);
        Assert.False(early.Ok);
        Assert.Null(early.KeyMaterial);
    }

    [Fact]
    public void Reveal_ByNonRequester_Refuses_EvenAfterApproval()
    {
        var (rig, refId) = EscrowedRig();
        var req = rig.Service.Escrow.RequestReveal(refId, Dev, "C:", AdminA, "recovery", rig.Now).Request!;
        Assert.True(rig.Service.Escrow.ApproveReveal(req.RequestId, AdminB, rig.Now).Ok);
        var byApprover = rig.Service.Escrow.Reveal(req.RequestId, AdminB, rig.Now);
        Assert.False(byApprover.Ok);
        Assert.Null(byApprover.KeyMaterial);
        var byStranger = rig.Service.Escrow.Reveal(req.RequestId, "mallory", rig.Now);
        Assert.False(byStranger.Ok);
    }

    [Fact]
    public void Reveal_IsSingleUse()
    {
        var (rig, refId) = EscrowedRig();
        var req = rig.Service.Escrow.RequestReveal(refId, Dev, "C:", AdminA, "recovery", rig.Now).Request!;
        rig.Service.Escrow.ApproveReveal(req.RequestId, AdminB, rig.Now);
        Assert.True(rig.Service.Escrow.Reveal(req.RequestId, AdminA, rig.Now).Ok);
        var replay = rig.Service.Escrow.Reveal(req.RequestId, AdminA, rig.Now);
        Assert.False(replay.Ok);
        Assert.Null(replay.KeyMaterial);
    }

    [Fact]
    public void DeniedRequest_RevealsNothing()
    {
        var (rig, refId) = EscrowedRig();
        var req = rig.Service.Escrow.RequestReveal(refId, Dev, "C:", AdminA, "recovery", rig.Now).Request!;
        Assert.True(rig.Service.Escrow.DenyReveal(req.RequestId, AdminB, rig.Now).Ok);
        Assert.False(rig.Service.Escrow.Reveal(req.RequestId, AdminA, rig.Now).Ok);
    }

    [Fact]
    public void ExpiredRequest_RevealsNothing_AndApprovalAfterExpiryRefuses()
    {
        var (rig, refId) = EscrowedRig();
        var req = rig.Service.Escrow.RequestReveal(refId, Dev, "C:", AdminA, "recovery", rig.Now).Request!;
        // D38 F1 amendment: expiry runs on the escrow's OWN clock — the rig clock must actually advance; passing a late `now` argument no longer does anything.
        rig.Now = rig.Now.AddHours(2);
        Assert.False(rig.Service.Escrow.ApproveReveal(req.RequestId, AdminB, rig.Now).Ok);
        Assert.Equal(RevealRequestStates.Expired, rig.Service.Escrow.GetRequest(req.RequestId)!.State);
    }

    [Fact]
    public void ApprovedButExpired_RevealRefuses()
    {
        var (rig, refId) = EscrowedRig();
        var req = rig.Service.Escrow.RequestReveal(refId, Dev, "C:", AdminA, "recovery", rig.Now).Request!;
        rig.Service.Escrow.ApproveReveal(req.RequestId, AdminB, rig.Now);
        rig.Now = rig.Now.AddHours(2); // D38 F1: advance the owned clock past the window
        var late = rig.Service.Escrow.Reveal(req.RequestId, AdminA, rig.Now);
        Assert.False(late.Ok);
        Assert.Null(late.KeyMaterial);
    }

    [Fact]
    public void RevealWithoutReason_Refuses()
    {
        var (rig, refId) = EscrowedRig();
        Assert.False(rig.Service.Escrow.RequestReveal(refId, Dev, "C:", AdminA, "", rig.Now).Ok);
        Assert.False(rig.Service.Escrow.RequestReveal(refId, Dev, "C:", "", "recovery", rig.Now).Ok);
    }

    // ---- reveal audit ----------------------------------------------------------------

    [Fact]
    public void EveryRevealStep_IsAudited_WithMetadataOnly()
    {
        var (rig, refId) = EscrowedRig();
        var req = rig.Service.Escrow.RequestReveal(refId, Dev, "C:", AdminA, "lost laptop", rig.Now).Request!;
        rig.Service.Escrow.ApproveReveal(req.RequestId, AdminB, rig.Now);
        rig.Service.Escrow.Reveal(req.RequestId, AdminA, rig.Now);
        var kinds = rig.Audit.Entries.Select(e => e.Kind).ToList();
        Assert.Contains("encryption_key_escrowed", kinds);
        Assert.Contains("encryption_key_reveal_requested", kinds);
        Assert.Contains("encryption_key_reveal_approved", kinds);
        Assert.Contains("encryption_key_revealed", kinds);
        var revealEntry = rig.Audit.Entries.Single(e => e.Kind == "encryption_key_revealed");
        Assert.Contains(Dev, revealEntry.Detail);
        Assert.Contains(AdminB, revealEntry.Detail);
        Assert.True(rig.Audit.Verify().Ok);
    }

    [Fact]
    public void RefusedReveals_AreAuditedToo()
    {
        var (rig, refId) = EscrowedRig();
        rig.Service.Escrow.Reveal("reveal-nonexistent", AdminA, rig.Now);
        rig.Service.Escrow.RequestReveal(refId, Dev2, "C:", AdminA, "wrong device", rig.Now);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "encryption_key_reveal_refused");
    }

    // ---- escrow substitution ------------------------------------------------------------

    [Fact]
    public void RevealRequest_AgainstWrongDevice_RefusesAtRequestTime()
    {
        var (rig, refId) = EscrowedRig();
        var wrong = rig.Service.Escrow.RequestReveal(refId, Dev2, "C:", AdminA, "substitution attempt", rig.Now);
        Assert.False(wrong.Ok);
        Assert.Contains("binding mismatch", wrong.Reason);
        var wrongVol = rig.Service.Escrow.RequestReveal(refId, Dev, "D:", AdminA, "substitution attempt", rig.Now);
        Assert.False(wrongVol.Ok);
    }

    [Fact]
    public void TamperedVaultMaterial_RefusesInsteadOfRevealingWrongKey()
    {
        // A protector whose Unprotect returns DIFFERENT material
        // than was protected (vault substitution / corruption): the
        // fingerprint check must refuse, never hand out the wrong key.
        var audit = new ChainedAuditLog();
        var escrow = new RecoveryKeyEscrow(new TamperingProtector(), audit, () => T0, a => a == AdminA || a == AdminB);
        var (ok, _, meta) = escrow.Escrow(Dev, "C:", Scope, KeyC, "recovery_password", "agent", T0);
        Assert.True(ok);
        var req = escrow.RequestReveal(meta!.Ref, Dev, "C:", AdminA, "recovery", T0).Request!;
        Assert.True(escrow.ApproveReveal(req.RequestId, AdminB, T0).Ok);
        var reveal = escrow.Reveal(req.RequestId, AdminA, T0);
        Assert.False(reveal.Ok);
        Assert.Null(reveal.KeyMaterial);
        Assert.Contains("SUBSTITUTION/TAMPER", reveal.Reason);
        Assert.DoesNotContain(KeyD, reveal.Reason);
    }

    private sealed class TamperingProtector : ISecretProtector
    {
        public string Name => "tampering-test";
        public bool IsRealProtection => false;
        public string Protect(string plaintext) => Convert.ToBase64String(Encoding.UTF8.GetBytes(KeyD));
        public string Unprotect(string protectedText) => Encoding.UTF8.GetString(Convert.FromBase64String(protectedText));
    }

    [Fact]
    public void KeyRotation_NewKeyEscrowsUnderNewRef_OldBindingStaysHonest()
    {
        var audit = new ChainedAuditLog();
        var escrow = new RecoveryKeyEscrow(new DevOnlyPassThroughProtector(), audit, () => T0, a => a == AdminA || a == AdminB);
        var first = escrow.Escrow(Dev, "C:", Scope, KeyC, "recovery_password", "agent", T0).Metadata!;
        var second = escrow.Escrow(Dev, "C:", Scope, KeyD, "recovery_password", "agent", T0.AddDays(1)).Metadata!;
        Assert.NotEqual(first.Ref, second.Ref);
        Assert.Equal(2, escrow.List(Dev).Count);
        // The old ref still reveals the OLD key under dual control —
        // rotation never silently rebinds a ref to new material.
        var req = escrow.RequestReveal(first.Ref, Dev, "C:", AdminA, "check old binding", T0.AddDays(1)).Request!;
        escrow.ApproveReveal(req.RequestId, AdminB, T0.AddDays(1));
        Assert.Equal(KeyC, escrow.Reveal(req.RequestId, AdminA, T0.AddDays(1)).KeyMaterial);
    }

    // ---- state lying ------------------------------------------------------------------------

    [Fact]
    public void SuspendedDevice_UnderRequirement_IsNonCompliant_OnEverySurface()
    {
        var rig = new Rig(Vol("C:", VolumeEncryptionStates.Suspended, protection: false));
        rig.Policies.AdmitLocalDocument(new ManagementPolicyDocument(
            "org-req", PolicyLevels.Org, Scope,
            new Dictionary<string, string> { [EncryptionPolicyKeys.Required] = "true" }, 1), "test");
        rig.Service.ReportState(Dev, "agent");
        Assert.Equal(EncryptionComplianceOutcomes.NonCompliant, rig.Service.EvaluateCompliance(Dev, AdminA).Outcome);
        Assert.Equal(false, rig.Service.SecuritySampleFor(Dev).EncryptionEnabled);
        var fact = rig.Service.BuildComplianceFact(Dev);
        Assert.NotNull(fact);
        Assert.False(fact!.Passing);
        Assert.NotNull(rig.Service.SecurityStateFor(Dev));
        Assert.Equal(false, rig.Service.SecurityStateFor(Dev)!.EncryptionEnabled);
    }

    [Fact]
    public void InvalidDriverState_RefusesWholeReport()
    {
        var rig = new Rig(Vol("C:", "totally_encrypted_trust_me", protection: true));
        var (ok, reason, _) = rig.Service.ReportState(Dev, "agent");
        Assert.False(ok);
        Assert.Contains("not a known encryption state", reason);
        Assert.Null(rig.Service.LatestReport(Dev));
    }

    [Fact]
    public void StaleReplay_CannotLaunderOldEncryptedOverNewSuspended()
    {
        var rig = new Rig(Vol("C:", VolumeEncryptionStates.Suspended, protection: false));
        Assert.True(rig.Service.ReportState(Dev, "agent").Ok);
        // A replayed older "encrypted" report (same instant — the
        // store demands strictly newer) refuses.
        rig.Driver.SetVolume(Vol("C:", VolumeEncryptionStates.Encrypted));
        var replay = rig.Service.ReportState(Dev, "agent");
        Assert.False(replay.Ok);
        Assert.Equal(VolumeEncryptionStates.Suspended, rig.Service.LatestReport(Dev)!.Volumes[0].State);
    }

    [Fact]
    public void DriverThrow_StateIsUnknown_NoReportRecorded()
    {
        var audit = new ChainedAuditLog();
        var policies = new ManagementPolicyService(audit, null);
        var svc = new EncryptionEnforcementService(audit, policies, new ThrowingDriver(),
            new DevOnlyPassThroughProtector(), id => StaticDeviceFacts.Of(Dev, Scope), () => T0);
        var (ok, reason, _) = svc.ReportState(Dev, "agent");
        Assert.False(ok);
        Assert.Contains("UNKNOWN", reason);
        Assert.Null(svc.LatestReport(Dev));
        Assert.Null(svc.SecuritySampleFor(Dev).EncryptionEnabled);
    }

    private sealed class ThrowingDriver : IEncryptionDriver
    {
        public string Name => "throwing";
        public IReadOnlyList<VolumeEncryptionState> ReadVolumes(string deviceId, DateTimeOffset now) =>
            throw new InvalidOperationException("driver died");
        public (bool Ok, string Reason) BeginEnable(string deviceId, string volumeId, DateTimeOffset now) => (false, "no");
        public string? ReadRecoveryKey(string deviceId, string volumeId, DateTimeOffset now) => null;
    }

    // ---- ceiling bypass -------------------------------------------------------------------------

    [Fact]
    public void DevicePolicy_CannotWeakenOrgRequirement()
    {
        var rig = new Rig(Vol("C:", VolumeEncryptionStates.NotEncrypted, protection: false, pct: 0));
        rig.Policies.AdmitLocalDocument(new ManagementPolicyDocument(
            "org-req", PolicyLevels.Org, Scope,
            new Dictionary<string, string> { [EncryptionPolicyKeys.Required] = "true" }, 1), "test");
        var weaken = rig.Policies.AdmitLocalDocument(new ManagementPolicyDocument(
            "dev-weaken", PolicyLevels.Device, Dev,
            new Dictionary<string, string> { [EncryptionPolicyKeys.Required] = "false" }, 1), "test");
        Assert.True(weaken.Allowed, weaken.Reason); // the document is admissible policy; it just cannot win
        var req = rig.Service.RequirementFor(Dev);
        Assert.True(req.Required);
        Assert.True(req.DeviceAttemptedWeaken);
        Assert.Contains("ceiling discipline", req.Summary);
        rig.Service.ReportState(Dev, "agent");
        Assert.Equal(EncryptionComplianceOutcomes.NonCompliant, rig.Service.EvaluateCompliance(Dev, AdminA).Outcome);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "encryption_policy_weaken_attempt");
    }

    [Fact]
    public void DevicePolicy_CanTighten_ItsOwnRequirement()
    {
        var rig = new Rig(Vol("C:", VolumeEncryptionStates.Encrypted));
        rig.Policies.AdmitLocalDocument(new ManagementPolicyDocument(
            "dev-req", PolicyLevels.Device, Dev,
            new Dictionary<string, string> { [EncryptionPolicyKeys.Required] = "true" }, 1), "test");
        var req = rig.Service.RequirementFor(Dev);
        Assert.True(req.Required);
        Assert.Equal(PolicyLevels.Device, req.RequiredByLevel);
    }

    // ---- silent encrypt ----------------------------------------------------------------------------

    [Fact]
    public void Proceed_WithoutNotice_NeverCallsDriver()
    {
        var rig = new Rig(Vol("C:", VolumeEncryptionStates.NotEncrypted, protection: false, pct: 0));
        rig.Service.ReportState(Dev, "agent");
        var flow = rig.Service.RequestEnable(Dev, "C:", AdminA).Flow!;
        var proceed = rig.Service.ProceedEnable(flow.FlowId, AdminA);
        Assert.False(proceed.Ok);
        Assert.Contains("NEVER starts silently", proceed.Reason);
        Assert.Equal(0, rig.Driver.BeginEnableCalls);
    }

    [Fact]
    public void Proceed_WithNoticeButNoAckOrDeferral_NeverCallsDriver()
    {
        var rig = new Rig(Vol("C:", VolumeEncryptionStates.NotEncrypted, protection: false, pct: 0));
        rig.Service.ReportState(Dev, "agent");
        var flow = rig.Service.RequestEnable(Dev, "C:", AdminA).Flow!;
        rig.Service.IssueUserNotice(flow.FlowId, "agent", "endpoint-dialog:shown");
        Assert.False(rig.Service.ProceedEnable(flow.FlowId, AdminA).Ok);
        Assert.Equal(0, rig.Driver.BeginEnableCalls);
    }

    [Fact]
    public void Proceed_DuringDeferral_NeverCallsDriver()
    {
        var rig = new Rig(Vol("C:", VolumeEncryptionStates.NotEncrypted, protection: false, pct: 0));
        rig.Service.ReportState(Dev, "agent");
        var flow = rig.Service.RequestEnable(Dev, "C:", AdminA).Flow!;
        rig.Service.IssueUserNotice(flow.FlowId, "agent", "endpoint-dialog:shown");
        rig.Service.DeferEnable(flow.FlowId, "device-user", TimeSpan.FromHours(10));
        rig.Now = T0.AddHours(9);
        Assert.False(rig.Service.ProceedEnable(flow.FlowId, AdminA).Ok);
        Assert.Equal(0, rig.Driver.BeginEnableCalls);
    }

    [Fact]
    public void Acknowledge_BeforeNotice_Refuses()
    {
        var rig = new Rig(Vol("C:", VolumeEncryptionStates.NotEncrypted, protection: false, pct: 0));
        rig.Service.ReportState(Dev, "agent");
        var flow = rig.Service.RequestEnable(Dev, "C:", AdminA).Flow!;
        Assert.False(rig.Service.AcknowledgeEnable(flow.FlowId, "device-user").Ok);
        Assert.False(rig.Service.DeferEnable(flow.FlowId, "device-user", TimeSpan.FromHours(1)).Ok);
        Assert.Equal(0, rig.Driver.BeginEnableCalls);
    }

    [Fact]
    public void DoubleProceed_CallsDriverOnce()
    {
        var rig = new Rig(Vol("C:", VolumeEncryptionStates.NotEncrypted, protection: false, pct: 0));
        rig.Service.ReportState(Dev, "agent");
        var flow = rig.Service.RequestEnable(Dev, "C:", AdminA).Flow!;
        rig.Service.IssueUserNotice(flow.FlowId, "agent", "endpoint-dialog:shown");
        rig.Service.AcknowledgeEnable(flow.FlowId, "device-user");
        Assert.True(rig.Service.ProceedEnable(flow.FlowId, AdminA).Ok);
        Assert.False(rig.Service.ProceedEnable(flow.FlowId, AdminA).Ok);
        Assert.Equal(1, rig.Driver.BeginEnableCalls);
    }

    [Fact]
    public void DriverRefusal_LandsFlowFailed_NamedNotRetried()
    {
        var audit = new ChainedAuditLog();
        var policies = new ManagementPolicyService(audit, null);
        var svc = new EncryptionEnforcementService(audit, policies, new RefusingEnableDriver(),
            new DevOnlyPassThroughProtector(), id => StaticDeviceFacts.Of(Dev, Scope), () => T0);
        Assert.True(svc.ReportState(Dev, "agent").Ok);
        var flow = svc.RequestEnable(Dev, "C:", AdminA).Flow!;
        svc.IssueUserNotice(flow.FlowId, "agent", "endpoint-dialog:shown");
        svc.AcknowledgeEnable(flow.FlowId, "device-user");
        var (ok, reason, done) = svc.ProceedEnable(flow.FlowId, AdminA);
        Assert.False(ok);
        Assert.Contains("TPM not ready", reason);
        Assert.Equal(EnableFlowStates.Failed, done!.State);
        // A failed flow cannot be re-proceeded (no silent retry).
        Assert.False(svc.ProceedEnable(flow.FlowId, AdminA).Ok);
    }

    private sealed class RefusingEnableDriver : IEncryptionDriver
    {
        public string Name => "refusing-enable";
        public IReadOnlyList<VolumeEncryptionState> ReadVolumes(string deviceId, DateTimeOffset now) =>
            new[] { Vol("C:", VolumeEncryptionStates.NotEncrypted, protection: false, pct: 0) };
        public (bool Ok, string Reason) BeginEnable(string deviceId, string volumeId, DateTimeOffset now) =>
            (false, "TPM not ready on this endpoint — enable refused by the OS driver");
        public string? ReadRecoveryKey(string deviceId, string volumeId, DateTimeOffset now) => null;
    }
}
