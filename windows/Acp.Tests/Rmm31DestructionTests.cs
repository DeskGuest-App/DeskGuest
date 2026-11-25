using System.Text;
using Acp.Core.Services;
using Acp.Shared.Enterprise;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.MdmSubset;
using Acp.Shared.Security;

namespace Acp.Tests;

// RMM-31 DESTRUCTION — capability inflation, silent action, wipe
// scope creep, locate abuse, policy laundering, command replay.
public class Rmm31DestructionTests
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
        public Rig()
        {
            var ring = new CustomerCommandKeyRing(); ring.AddCurrent(Customer.PublicKey);
            Signer = new SignedCommandSigner(Customer);
            // D38-FIX AMENDMENT (disclosed): platform-shape rig —
            // passes the new construction-time deployment shape
            // explicitly (default is self-hosted — F10).
            Svc = new MdmSubsetService(Audit, Policy, new SignedCommandGate(new SignedCommandVerifier(ring), Audit),
                Executor, id => id == Dev ? StaticDeviceFacts.Of(Dev, Scope) : null, () => Now, deploymentSelfHostedShape: false);
            Policy.AddDocument(new ManagementPolicyDocument("doc-on", "org", Scope, new Dictionary<string, string> { [MdmKeys.FeatureEnabled] = "true" }, 1));
        }
        public SignedCommandEnvelope Sign(MdmActionRequest req, DeviceIdentity? key = null, DateTimeOffset? at = null, TimeSpan? ttl = null) =>
            (key is null ? Signer : new SignedCommandSigner(key)).Sign(SignedCommandClasses.BackgroundAction,
                Encoding.UTF8.GetBytes(req.CanonicalPayload()), at ?? Now, ttl ?? TimeSpan.FromMinutes(10));
    }

    private static MdmDeviceState State(string ownership = MdmOwnership.Personal, IReadOnlyList<string>? applied = null) =>
        new(Dev, Scope, MdmPlatforms.Android, ownership, "Android 15", true, ScreenLockStrengths.Password,
            "0.4.9", new[] { "io.agenticcontrol.app" }, applied ?? Array.Empty<string>(), T0);

    private static MdmActionRequest Action(string kind, string id = "cmd-1", IReadOnlyList<string>? targets = null,
        // D38-FIX AMENDMENT (disclosed): the old default "notice"
        // (6 chars) is below the new minimum notice substance (F9).
        string notice = "Device notice: administrator action.", DateTimeOffset? issued = null, DateTimeOffset? expires = null) =>
        new(id, Dev, kind, targets ?? Array.Empty<string>(), notice, issued ?? T0, expires ?? T0.AddMinutes(10));

    // D31-01 capability inflation via state report: personal device
    // claims an impossible-tier restriction as applied.
    [Fact]
    public void D31_01_PersonalDevice_ClaimingKioskApplied_ReportRefusedWhole()
    {
        var rig = new Rig();
        var (stored, reason) = rig.Svc.ReportState(State(applied: new[] { "kiosk_mode" }), Admin);
        Assert.Null(stored);
        Assert.Contains("CAPABILITY INFLATION", reason);
        Assert.Null(rig.Svc.StateFor(Dev));
    }

    // D31-02 capability inflation: profile-owner claims kiosk applied.
    [Fact]
    public void D31_02_ProfileOwner_ClaimingKioskApplied_Refused()
    {
        var rig = new Rig();
        var (stored, _) = rig.Svc.ReportState(State(ownership: MdmOwnership.ProfileOwner, applied: new[] { "kiosk_mode" }), Admin);
        Assert.Null(stored);
    }

    // D31-03 silent action: empty notice text can never execute.
    [Fact]
    public void D31_03_ActionWithEmptyNotice_Refused_NothingExecutes_NoNoticeRecorded()
    {
        var rig = new Rig();
        rig.Svc.ReportState(State(), Admin);
        var req = Action(MdmActionKinds.Lock, notice: "  ");
        var (outcome, reason) = rig.Svc.ExecuteAction(req, rig.Sign(req), "acp_direct", true, Admin);
        Assert.Null(outcome);
        Assert.Contains("notice", reason);
        Assert.Empty(rig.Executor.Executed);
        Assert.Empty(rig.Svc.Notices);
    }

    // D31-04 wipe scope creep: ACP wipe targeting non-ACP data.
    [Fact]
    public void D31_04_AcpWipe_WithNonAcpTarget_Refused()
    {
        var rig = new Rig();
        rig.Svc.ReportState(State(), Admin);
        var req = Action(MdmActionKinds.WipeAcpData, targets: new[] { AcpWipeTargets.AppData, "user_photos" });
        var (outcome, reason) = rig.Svc.ExecuteAction(req, rig.Sign(req), "acp_direct", true, Admin);
        Assert.Null(outcome);
        Assert.Contains("NOT ACP data", reason);
        Assert.Empty(rig.Executor.Executed);
        // Model-level: the request itself is invalid.
        Assert.NotNull(req.Validate(T0));
    }

    // D31-05 wipe targets smuggled onto a non-wipe action.
    [Fact]
    public void D31_05_LockCarryingWipeTargets_Refused()
    {
        var req = Action(MdmActionKinds.Lock, targets: new[] { AcpWipeTargets.AppData });
        Assert.NotNull(req.Validate(T0));
    }

    // D31-06 locate abuse: daily cap stops polling-as-tracking even
    // when each individual locate is spaced past the interval.
    [Fact]
    public void D31_06_LocateDailyCap_RefusesSeventhLocate()
    {
        var rig = new Rig();
        rig.Svc.ReportState(State(), Admin);
        for (var i = 1; i <= MdmLimits.DefaultLocateMaxPerDay; i++)
        {
            rig.Now = T0.AddMinutes(20 * i);
            var req = Action(MdmActionKinds.LocateOnce, id: $"loc-{i}", issued: rig.Now, expires: rig.Now.AddMinutes(10));
            var (o, r) = rig.Svc.ExecuteAction(req, rig.Sign(req), "acp_direct", true, Admin);
            Assert.True(o is not null && o.Executed, $"locate {i} should execute: {r}");
        }
        rig.Now = T0.AddMinutes(20 * (MdmLimits.DefaultLocateMaxPerDay + 1));
        var extra = Action(MdmActionKinds.LocateOnce, id: "loc-extra", issued: rig.Now, expires: rig.Now.AddMinutes(10));
        var (ox, rx) = rig.Svc.ExecuteAction(extra, rig.Sign(extra), "acp_direct", true, Admin);
        Assert.Null(ox);
        Assert.Contains("daily cap", rx);
    }

    // D31-07 policy laundering: detect-tier verdict can never be
    // relabelled enforced — outcome strings + detail are tier-bound.
    [Fact]
    public void D31_07_DetectTierVerdict_NeverReadsEnforced()
    {
        var rig = new Rig();
        rig.Policy.AddDocument(new ManagementPolicyDocument("doc-r", "org", Scope,
            new Dictionary<string, string> { [MdmKeys.Restrictions] = "require_encryption,prevent_acp_removal" }, 1));
        rig.Svc.ReportState(State(), Admin);
        var (verdicts, _) = rig.Svc.EvaluateCompliance(Dev, Admin);
        foreach (var v in verdicts!)
        {
            Assert.NotEqual(MdmComplianceOutcomes.EnforcedCompliant, v.Outcome);
            if (v.Tier == MdmTiers.Detect) Assert.Contains("DETECT", v.TierLabel);
            if (v.Tier == MdmTiers.Impossible) Assert.False(v.IsSatisfied);
        }
    }

    // D31-08 command replay: same envelope twice — nonce wall.
    [Fact]
    public void D31_08_ReplayedEnvelope_RefusedSecondTime()
    {
        var rig = new Rig();
        rig.Svc.ReportState(State(), Admin);
        var req = Action(MdmActionKinds.Lock);
        var env = rig.Sign(req);
        var (o1, _) = rig.Svc.ExecuteAction(req, env, "acp_direct", true, Admin);
        Assert.True(o1!.Executed);
        var (o2, reason) = rig.Svc.ExecuteAction(req, env, "acp_direct", true, Admin);
        Assert.Null(o2);
        Assert.Contains("replay", reason, StringComparison.OrdinalIgnoreCase);
        Assert.Single(rig.Executor.Executed);
    }

    // D31-09 stale command: long-TTL / expired lock must not execute late.
    [Fact]
    public void D31_09_StaleAndOverLongTtlCommands_Refused()
    {
        var rig = new Rig();
        rig.Svc.ReportState(State(), Admin);
        var stale = Action(MdmActionKinds.Lock, id: "cmd-stale", issued: T0.AddHours(-2), expires: T0.AddMinutes(-1));
        Assert.NotNull(stale.Validate(T0));
        var longTtl = Action(MdmActionKinds.WipeFullDevice, id: "cmd-long", issued: T0, expires: T0.AddHours(6));
        Assert.Contains("freshness cap", longTtl.Validate(T0)!);
    }

    // D31-10 signature swap: envelope signed for lock A presented for lock B.
    [Fact]
    public void D31_10_SignatureForOneAction_DoesNotAuthorizeAnother()
    {
        var rig = new Rig();
        rig.Svc.ReportState(State(ownership: MdmOwnership.DeviceOwner), Admin);
        var lockReq = Action(MdmActionKinds.Lock, id: "cmd-lock");
        var wipeReq = Action(MdmActionKinds.WipeFullDevice, id: "cmd-wipe");
        var (outcome, reason) = rig.Svc.ExecuteAction(wipeReq, rig.Sign(lockReq), "acp_direct", true, Admin);
        Assert.Null(outcome);
        Assert.Contains("does not match", reason);
        Assert.Empty(rig.Executor.Executed);
    }

    // D31-11 forged signer: attacker key never verifies.
    [Fact]
    public void D31_11_ForgedSigner_Refused()
    {
        var rig = new Rig();
        rig.Svc.ReportState(State(), Admin);
        var attacker = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var req = Action(MdmActionKinds.Lock);
        var (outcome, _) = rig.Svc.ExecuteAction(req, rig.Sign(req, key: attacker), "acp_direct", true, Admin);
        Assert.Null(outcome);
        Assert.Empty(rig.Executor.Executed);
    }

    // D31-12 platform push smuggled into self-hosted shape at action time.
    [Fact]
    public void D31_12_PlatformPushTransport_InSelfHostedShape_ActionRefused()
    {
        var rig = new Rig();
        rig.Svc.ReportState(State(), Admin);
        var req = Action(MdmActionKinds.Lock);
        var (outcome, reason) = rig.Svc.ExecuteAction(req, rig.Sign(req), "platform_push_apns_fcm", selfHostedShape: true, Admin);
        Assert.Null(outcome);
        Assert.Contains("self-hosted", reason);
        Assert.Empty(rig.Executor.Executed);
    }

    // D31-13 unknown ownership claims nothing: tier impossible across the board.
    [Fact]
    public void D31_13_UnknownOwnership_AllTiersImpossible()
    {
        foreach (var def in MdmRestrictions.All)
            Assert.Equal(MdmTiers.Impossible, def.TierFor(MdmOwnership.Unknown));
    }
}
