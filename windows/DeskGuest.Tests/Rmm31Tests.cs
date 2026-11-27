using System.Text;
using DeskGuest.Core.Services;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.MdmSubset;
using DeskGuest.Shared.Security;

namespace DeskGuest.Tests;

// RMM-31 — MDM subset: device-state facts, three-tier restrictions
// (enforce/detect/impossible), compliance preserving tier wording,
// signed+noticed actions, push-transit honesty, one-shot locate.
public class Rmm31Tests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    private const string Dev = "phone-1";
    private const string Scope = "co-1";
    private const string Admin = "ops-admin";

    private sealed class Rig
    {
        public DateTimeOffset Now = T0;
        public ChainedAuditLog Audit = new();
        public ManagementPolicyEngine Policy = new();
        public RecordingMdmActionExecutor Executor = new();
        public DeviceIdentity Customer = new(new DevOnlyPassThroughProtector());
        public SignedCommandSigner Signer;
        public MdmSubsetService Svc;
        public StaticDeviceFacts Facts = StaticDeviceFacts.Of(Dev, Scope);

        public Rig(bool enableMdm = true)
        {
            var ring = new CustomerCommandKeyRing(); ring.AddCurrent(Customer.PublicKey);
            var gate = new SignedCommandGate(new SignedCommandVerifier(ring), Audit);
            Signer = new SignedCommandSigner(Customer);
            // D38-FIX AMENDMENT (disclosed): the rig models a
            // PLATFORM-shape deployment, so it passes the new
            // construction-time shape explicitly (default is now
            // self-hosted, fail-closed — F10).
            Svc = new MdmSubsetService(Audit, Policy, gate, Executor, id => id == Dev ? Facts : null, () => Now, deploymentSelfHostedShape: false);
            if (enableMdm) SetPolicy(MdmKeys.FeatureEnabled, "true", "doc-mdm-on");
        }
        public void SetPolicy(string key, string value, string docId) =>
            Policy.AddDocument(new ManagementPolicyDocument(docId, "org", Scope, new Dictionary<string, string> { [key] = value }, 1));
        public SignedCommandEnvelope Sign(MdmActionRequest req) =>
            Signer.Sign(SignedCommandClasses.BackgroundAction, Encoding.UTF8.GetBytes(req.CanonicalPayload()), Now, TimeSpan.FromMinutes(10));
    }

    private static MdmDeviceState State(string ownership = MdmOwnership.Personal, bool? enc = true,
        string lockStrength = ScreenLockStrengths.Password, IReadOnlyList<string>? applied = null, DateTimeOffset? reported = null) =>
        new(Dev, Scope, MdmPlatforms.Android, ownership, "Android 15", enc, lockStrength,
            "0.4.9", new[] { "io.deskguest.app" }, applied ?? Array.Empty<string>(), reported ?? T0);

    private static MdmActionRequest Action(string kind, string id = "cmd-1", IReadOnlyList<string>? targets = null,
        string notice = "Your administrator locked this device. Contact IT.", DateTimeOffset? issued = null, DateTimeOffset? expires = null) =>
        new(id, Dev, kind, targets ?? Array.Empty<string>(), notice, issued ?? T0, expires ?? T0.AddMinutes(10));

    [Fact]
    public void TierTable_PersonalDevice_MostlyDetectOrImpossible_NeverEnforceInflated()
    {
        Assert.Equal(MdmTiers.Detect, MdmRestrictions.For("require_encryption")!.TierFor(MdmOwnership.Personal));
        Assert.Equal(MdmTiers.Detect, MdmRestrictions.For("require_screen_lock")!.TierFor(MdmOwnership.Personal));
        Assert.Equal(MdmTiers.Impossible, MdmRestrictions.For("prevent_deskguest_removal")!.TierFor(MdmOwnership.Personal));
        Assert.Equal(MdmTiers.Impossible, MdmRestrictions.For("kiosk_mode")!.TierFor(MdmOwnership.Personal));
        Assert.Equal(MdmTiers.Enforce, MdmRestrictions.For("kiosk_mode")!.TierFor(MdmOwnership.DeviceOwner));
        Assert.Equal(MdmTiers.Impossible, MdmRestrictions.For("kiosk_mode")!.TierFor(MdmOwnership.ProfileOwner));
        Assert.Equal(MdmTiers.Impossible, MdmRestrictions.For("require_encryption")!.TierFor(MdmOwnership.Unknown));
    }

    [Fact]
    public void SeededToggle_DefaultIsOff_RegistryTruth()
    {
        var reg = FeatureToggleRegistry.Seeded();
        Assert.True(reg.TryGet(MdmKeys.FeatureEnabled, out var t));
        Assert.False(t!.DefaultEnabled);
    }

    [Fact]
    public void FeatureDisabledByDefault_ActionsAndStateRefuse()
    {
        var rig = new Rig(enableMdm: false);
        var (_, reason) = rig.Svc.ReportState(State(), Admin);
        Assert.Contains("disabled by policy", reason);
    }

    [Fact]
    public void StateReport_Recorded_AndComplianceDetectTier_NamedAsDetectionNotEnforcement()
    {
        var rig = new Rig();
        rig.SetPolicy(MdmKeys.Restrictions, "require_encryption,require_screen_lock", "doc-restr");
        var (stored, _) = rig.Svc.ReportState(State(enc: false, lockStrength: ScreenLockStrengths.None), Admin);
        Assert.NotNull(stored);
        var (verdicts, _) = rig.Svc.EvaluateCompliance(Dev, Admin);
        Assert.NotNull(verdicts);
        var enc = verdicts!.Single(v => v.RestrictionId == "require_encryption");
        Assert.Equal(MdmTiers.Detect, enc.Tier);
        Assert.Equal(MdmComplianceOutcomes.DetectedNonCompliant, enc.Outcome);
        Assert.Contains("detection only", enc.Detail);
        Assert.DoesNotContain("ENFORCED", enc.Detail);
        Assert.False(enc.IsSatisfied);
    }

    [Fact]
    public void Compliance_DetectCompliant_WhenSubstanceHolds_StillLabelledDetected()
    {
        var rig = new Rig();
        rig.SetPolicy(MdmKeys.Restrictions, "require_encryption", "doc-restr");
        rig.Svc.ReportState(State(enc: true), Admin);
        var (verdicts, _) = rig.Svc.EvaluateCompliance(Dev, Admin);
        var v = verdicts!.Single();
        Assert.Equal(MdmComplianceOutcomes.DetectedCompliant, v.Outcome);
        Assert.Contains("DETECTED compliant", v.Detail);
        Assert.True(v.IsSatisfied);
    }

    [Fact]
    public void Compliance_ImpossibleRestriction_NeverSatisfied()
    {
        var rig = new Rig();
        rig.SetPolicy(MdmKeys.Restrictions, "kiosk_mode", "doc-restr");
        rig.Svc.ReportState(State(), Admin);
        var (verdicts, reason) = rig.Svc.EvaluateCompliance(Dev, Admin);
        var v = verdicts!.Single();
        Assert.Equal(MdmComplianceOutcomes.ImpossibleNotApplicable, v.Outcome);
        Assert.False(v.IsSatisfied);
        // D38-FIX AMENDMENT (disclosed): the headline no longer uses
        // the blended "0/1 satisfied" form (F8) — enforced and
        // detected are counted separately.
        Assert.Contains("0 enforced-satisfied, 0 detected-satisfied, of 1 desired", reason);
    }

    [Fact]
    public void Compliance_EnforceTier_DeviceOwner_AppliedIsCompliant_NotAppliedIsMissing()
    {
        var rig = new Rig();
        rig.SetPolicy(MdmKeys.Restrictions, "kiosk_mode,require_encryption", "doc-restr");
        rig.Svc.ReportState(State(ownership: MdmOwnership.DeviceOwner, applied: new[] { "kiosk_mode" }), Admin);
        var (verdicts, _) = rig.Svc.EvaluateCompliance(Dev, Admin);
        Assert.Equal(MdmComplianceOutcomes.EnforcedCompliant, verdicts!.Single(v => v.RestrictionId == "kiosk_mode").Outcome);
        Assert.Equal(MdmComplianceOutcomes.EnforcedCompliant, verdicts.Single(v => v.RestrictionId == "require_encryption").Outcome);
    }

    [Fact]
    public void Compliance_NoState_UnknownNotCompliant()
    {
        var rig = new Rig();
        var (verdicts, reason) = rig.Svc.EvaluateCompliance(Dev, Admin);
        Assert.Null(verdicts);
        Assert.Contains("UNKNOWN", reason);
    }

    [Fact]
    public void Compliance_StaleState_UnknownOutcome()
    {
        var rig = new Rig();
        rig.SetPolicy(MdmKeys.Restrictions, "require_encryption", "doc-restr");
        rig.Svc.ReportState(State(reported: T0.AddDays(-2)), Admin);
        var (verdicts, _) = rig.Svc.EvaluateCompliance(Dev, Admin);
        Assert.Equal(MdmComplianceOutcomes.UnknownStaleState, verdicts!.Single().Outcome);
    }

    [Fact]
    public void LockAction_SignedAndNoticed_Executes_NoticePrecedesInAudit()
    {
        var rig = new Rig();
        rig.Svc.ReportState(State(), Admin);
        var req = Action(MdmActionKinds.Lock);
        var (outcome, _) = rig.Svc.ExecuteAction(req, rig.Sign(req), "deskguest_direct", true, Admin);
        Assert.NotNull(outcome);
        Assert.True(outcome!.Executed);
        Assert.NotNull(outcome.Notice);
        Assert.Single(rig.Svc.Notices);
        var kinds = rig.Audit.Entries.Select(e => e.Kind).ToList();
        Assert.True(kinds.IndexOf("mdm_action_notice_recorded") < kinds.IndexOf("mdm_action_executed"));
    }

    [Fact]
    public void UnsignedAction_RefusedAndAudited()
    {
        var rig = new Rig();
        rig.Svc.ReportState(State(), Admin);
        var (outcome, reason) = rig.Svc.ExecuteAction(Action(MdmActionKinds.Lock), null, "deskguest_direct", true, Admin);
        Assert.Null(outcome);
        Assert.Contains("signed-command gate refused", reason);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "mdm_action_refused");
        Assert.Empty(rig.Executor.Executed);
    }

    [Fact]
    public void WipeDeskGuestData_Executes_WithDeskGuestTargetsOnly()
    {
        var rig = new Rig();
        rig.Svc.ReportState(State(), Admin);
        var req = Action(MdmActionKinds.WipeDeskGuestData, targets: new[] { DeskGuestWipeTargets.AppData, DeskGuestWipeTargets.Credentials });
        var (outcome, _) = rig.Svc.ExecuteAction(req, rig.Sign(req), "deskguest_direct", true, Admin);
        Assert.True(outcome!.Executed);
    }

    [Fact]
    public void FullWipe_OnPersonalDevice_RefusedImpossible_DeskGuestWipeNotSubstituted()
    {
        var rig = new Rig();
        rig.Svc.ReportState(State(), Admin);
        var req = Action(MdmActionKinds.WipeFullDevice);
        var (outcome, reason) = rig.Svc.ExecuteAction(req, rig.Sign(req), "deskguest_direct", true, Admin);
        Assert.Null(outcome);
        Assert.Contains("IMPOSSIBLE", reason);
        Assert.Contains("never silently substituted", reason);
        Assert.Empty(rig.Executor.Executed);
    }

    [Fact]
    public void FullWipe_OnDeviceOwner_Executes()
    {
        var rig = new Rig();
        rig.Svc.ReportState(State(ownership: MdmOwnership.DeviceOwner), Admin);
        var req = Action(MdmActionKinds.WipeFullDevice);
        var (outcome, _) = rig.Svc.ExecuteAction(req, rig.Sign(req), "deskguest_direct", true, Admin);
        Assert.True(outcome!.Executed);
    }

    [Fact]
    public void PasscodeReset_OnProfileOwner_Refused()
    {
        var rig = new Rig();
        rig.Svc.ReportState(State(ownership: MdmOwnership.ProfileOwner), Admin);
        var req = Action(MdmActionKinds.PasscodeReset);
        var (outcome, reason) = rig.Svc.ExecuteAction(req, rig.Sign(req), "deskguest_direct", true, Admin);
        Assert.Null(outcome);
        Assert.Contains("passcode reset", reason);
    }

    [Fact]
    public void LocateOnce_Executes_ThenRateLimited_ThenDailyCap()
    {
        var rig = new Rig();
        rig.Svc.ReportState(State(), Admin);
        var first = Action(MdmActionKinds.LocateOnce, id: "loc-1", notice: "Your administrator located this device once.");
        var (o1, _) = rig.Svc.ExecuteAction(first, rig.Sign(first), "deskguest_direct", true, Admin);
        Assert.True(o1!.Executed);
        // D38-FIX AMENDMENT (disclosed): notice text now has a
        // minimum substance (F9) — "again" is no longer a notice.
        var second = Action(MdmActionKinds.LocateOnce, id: "loc-2", notice: "Locating this device again per admin request.");
        var (o2, reason2) = rig.Svc.ExecuteAction(second, rig.Sign(second), "deskguest_direct", true, Admin);
        Assert.Null(o2);
        Assert.Contains("de-facto tracking", reason2);
    }

    [Fact]
    public void Transit_PlatformPush_RefusedInSelfHosted_NamedInPlatformShape()
    {
        var rig = new Rig();
        var (_, reason) = rig.Svc.DescribeTransit("platform_push_apns_fcm", selfHostedShape: true);
        Assert.Contains("NOT part of the self-hosted shape", reason);
        var (t, note) = rig.Svc.DescribeTransit("platform_push_apns_fcm", selfHostedShape: false);
        Assert.NotNull(t);
        Assert.Contains("APNs", note);
        var (_, directNote) = rig.Svc.DescribeTransit("deskguest_direct", selfHostedShape: true);
        Assert.Contains("sleeping", directNote);
    }

    [Fact]
    public void NoContinuousLocateKind_Exists()
    {
        Assert.DoesNotContain(MdmActionKinds.All, k => k.Contains("track") || k.Contains("continuous") || k.Contains("geofence"));
    }

    [Fact]
    public void UnavailableExecutor_ReportsNotExecutedHonestly()
    {
        var audit = new ChainedAuditLog();
        var policy = new ManagementPolicyEngine();
        policy.AddDocument(new ManagementPolicyDocument("doc-on", "org", Scope, new Dictionary<string, string> { [MdmKeys.FeatureEnabled] = "true" }, 1));
        var customer = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var ring = new CustomerCommandKeyRing(); ring.AddCurrent(customer.PublicKey);
        var svc = new MdmSubsetService(audit, policy, new SignedCommandGate(new SignedCommandVerifier(ring), audit),
            new UnavailableMdmActionExecutor(), id => StaticDeviceFacts.Of(Dev, Scope), () => T0);
        var signer = new SignedCommandSigner(customer);
        svc.ReportState(State(), Admin);
        var req = Action(MdmActionKinds.Lock);
        var env = signer.Sign(SignedCommandClasses.BackgroundAction, Encoding.UTF8.GetBytes(req.CanonicalPayload()), T0, TimeSpan.FromMinutes(10));
        var (outcome, reason) = svc.ExecuteAction(req, env, "deskguest_direct", true, Admin);
        Assert.NotNull(outcome);
        Assert.False(outcome!.Executed);
        Assert.Contains("NOT executed", reason);
        Assert.Single(svc.Notices); // notice still recorded — the attempt is visible on-device
    }
}
