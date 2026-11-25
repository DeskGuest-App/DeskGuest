using System.Text;
using Acp.Core.Services;
using Acp.Shared.Enterprise;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.MdmSubset;
using Acp.Shared.Security;

namespace Acp.Tests;

// RMM-31 D38 FIX lane — regression tests for packet 045c9412
// findings F1–F12. Every test pins a CONFIRMED finding's fix;
// F3's pin is the structural non-retention of any location result.
public class Rmm31FixTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    private const string Dev = "phone-1";
    private const string Scope = "co-1";
    private const string Admin = "ops-admin";
    private const string GoodNotice = "Your administrator performed this action. Contact IT.";

    private sealed class Rig
    {
        public DateTimeOffset Now = T0;
        public ChainedAuditLog Audit = new();
        public ManagementPolicyEngine Policy = new();
        public RecordingMdmActionExecutor Executor = new();
        public DeviceIdentity Customer = new(new DevOnlyPassThroughProtector());
        public SignedCommandSigner Signer;
        public MdmSubsetService Svc;

        public Rig(bool shape = false, Func<string, IDeviceFacts?>? facts = null, Func<DateTimeOffset>? clock = null)
        {
            var ring = new CustomerCommandKeyRing(); ring.AddCurrent(Customer.PublicKey);
            Signer = new SignedCommandSigner(Customer);
            Svc = new MdmSubsetService(Audit, Policy, new SignedCommandGate(new SignedCommandVerifier(ring), Audit),
                Executor, facts ?? (id => id == Dev ? StaticDeviceFacts.Of(Dev, Scope) : null),
                clock ?? (() => Now), deploymentSelfHostedShape: shape);
            Policy.AddDocument(new ManagementPolicyDocument("doc-on", "org", Scope, new Dictionary<string, string> { [MdmKeys.FeatureEnabled] = "true" }, 1));
        }
        public void SetPolicy(string key, string value, string docId) =>
            Policy.AddDocument(new ManagementPolicyDocument(docId, "org", Scope, new Dictionary<string, string> { [key] = value }, 1));
        public SignedCommandEnvelope Sign(MdmActionRequest req) =>
            Signer.Sign(SignedCommandClasses.BackgroundAction, Encoding.UTF8.GetBytes(req.CanonicalPayload()), Now, TimeSpan.FromMinutes(10));
    }

    private static MdmDeviceState State(string ownership = MdmOwnership.Personal, bool? enc = true,
        string scope = Scope, IReadOnlyList<string>? applied = null, DateTimeOffset? reported = null,
        IReadOnlyList<string>? apps = null, string deviceId = Dev) =>
        new(deviceId, scope, MdmPlatforms.Android, ownership, "Android 15", enc, ScreenLockStrengths.Password,
            "0.4.9", apps ?? new[] { "io.agenticcontrol.app" }, applied ?? Array.Empty<string>(), reported ?? T0);

    private static MdmActionRequest Action(string kind, string id = "cmd-1", IReadOnlyList<string>? targets = null,
        string notice = GoodNotice, DateTimeOffset? issued = null, DateTimeOffset? expires = null) =>
        new(id, Dev, kind, targets ?? Array.Empty<string>(), notice, issued ?? T0, expires ?? T0.AddMinutes(10));

    // ---- F1: state-report authentication/binding -------------------

    [Fact]
    public void Fx31_F1_ScopeMismatchReport_RefusedAndAudited_NothingStored()
    {
        var rig = new Rig();
        var (stored, reason) = rig.Svc.ReportState(State(scope: "co-OTHER"), Admin);
        Assert.Null(stored);
        Assert.Contains("does not match the enrolled scope", reason);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "mdm_state_refused");
        Assert.Null(rig.Svc.StateFor(Dev));
    }

    [Fact]
    public void Fx31_F1_OutOfOrderReport_NeverOverwritesNewerState()
    {
        var rig = new Rig();
        rig.Svc.ReportState(State(reported: T0), Admin);
        var (stored, reason) = rig.Svc.ReportState(State(ownership: MdmOwnership.DeviceOwner, reported: T0.AddHours(-1)), Admin);
        Assert.Null(stored);
        Assert.Contains("does not advance the stored report", reason);
        Assert.Equal(MdmOwnership.Personal, rig.Svc.StateFor(Dev)!.Ownership);
        // An equal-timestamp report is also refused; a newer one lands.
        Assert.Null(rig.Svc.ReportState(State(reported: T0), Admin).State);
        // The service clock must reach the newer report's time —
        // a report dated an hour ahead of the clock is future-dated
        // and refused by the model's own guard (correctly).
        rig.Now = T0.AddHours(1);
        Assert.NotNull(rig.Svc.ReportState(State(reported: T0.AddHours(1)), Admin).State);
    }

    [Fact]
    public void Fx31_F1_OwnershipEscalationClaim_IsAuditedByName()
    {
        var rig = new Rig();
        rig.Svc.ReportState(State(reported: T0), Admin);
        rig.Now = T0.AddHours(1); // clock reaches the newer report's time (not future-dated)
        var (stored, reason) = rig.Svc.ReportState(State(ownership: MdmOwnership.DeviceOwner, reported: T0.AddHours(1)), Admin);
        Assert.NotNull(stored);
        Assert.Contains("SELF-REPORTED", reason);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "mdm_state_ownership_escalation");
    }

    [Fact]
    public void Fx31_F1_FactsForAnotherDevice_RefuseTheGate()
    {
        var rig = new Rig(facts: _ => StaticDeviceFacts.Of("someone-else", Scope));
        var (stored, reason) = rig.Svc.ReportState(State(), Admin);
        Assert.Null(stored);
        Assert.Contains("device binding mismatch", reason);
    }

    // ---- F2: locate ceilings ---------------------------------------

    [Fact]
    public void Fx31_F2_PolicyCannotLoosenLocateBelowTheFloor()
    {
        var rig = new Rig();
        rig.SetPolicy(MdmKeys.LocateMinIntervalMinutes, "1", "doc-loc-interval");
        rig.SetPolicy(MdmKeys.LocateMaxPerDay, "100000", "doc-loc-cap");
        rig.Svc.ReportState(State(), Admin);
        var first = Action(MdmActionKinds.LocateOnce, id: "loc-1");
        Assert.True(rig.Svc.ExecuteAction(first, rig.Sign(first), "acp_direct", true, Admin).Outcome!.Executed);
        // 5 minutes later policy says fine (1-minute interval) — the
        // hard 15-minute floor refuses.
        rig.Now = T0.AddMinutes(5);
        var second = Action(MdmActionKinds.LocateOnce, id: "loc-2", issued: rig.Now, expires: rig.Now.AddMinutes(10));
        var (o2, reason2) = rig.Svc.ExecuteAction(second, rig.Sign(second), "acp_direct", true, Admin);
        Assert.Null(o2);
        Assert.Contains("minimum interval", reason2);
    }

    [Fact]
    public void Fx31_F2_LimiterClampsEvenDirectCallers_AndCapsPerRolling24h()
    {
        var limiter = new LocateRateLimiter();
        // Absurd caller-supplied limits are clamped to the ceilings.
        for (var i = 0; i < MdmLimits.LocateMaxPer24hCeiling; i++)
        {
            var t = T0.AddMinutes(20 * i);
            Assert.True(limiter.TryAcquire(Dev, t, TimeSpan.FromMinutes(1), 100000).Ok, $"acquire {i}");
        }
        var (ok, why) = limiter.TryAcquire(Dev, T0.AddMinutes(20 * MdmLimits.LocateMaxPer24hCeiling), TimeSpan.FromMinutes(1), 100000);
        Assert.False(ok);
        Assert.Contains("daily cap", why);
    }

    [Fact]
    public void Fx31_F2_MidnightBoundaryBuysNoExtraLocates()
    {
        var limiter = new LocateRateLimiter();
        var start = new DateTimeOffset(2026, 11, 21, 23, 0, 0, TimeSpan.Zero);
        for (var i = 0; i < 6; i++)
            Assert.True(limiter.TryAcquire(Dev, start.AddMinutes(20 * i), TimeSpan.FromMinutes(15), 6).Ok, $"acquire {i}");
        // 01:00 the NEXT calendar day: the old calendar-day counter
        // allowed this; the rolling 24h window refuses.
        var (ok, _) = limiter.TryAcquire(Dev, start.AddHours(2), TimeSpan.FromMinutes(15), 6);
        Assert.False(ok);
    }

    [Fact]
    public void Fx31_F2_LimiterSnapshotRestore_KeepsCountersAcrossRestart()
    {
        var a = new LocateRateLimiter();
        Assert.True(a.TryAcquire(Dev, T0, TimeSpan.FromMinutes(15), 6).Ok);
        var b = new LocateRateLimiter();
        b.Restore(a.Snapshot(), T0);
        Assert.Equal(1, b.CountFor(Dev));
        Assert.False(b.TryAcquire(Dev, T0.AddMinutes(1), TimeSpan.FromMinutes(15), 6).Ok);
        // Stale entries are pruned, not carried forever (F12).
        var c = new LocateRateLimiter();
        Assert.True(c.TryAcquire(Dev, T0, TimeSpan.FromMinutes(15), 6).Ok);
        Assert.True(c.TryAcquire(Dev, T0.AddHours(25), TimeSpan.FromMinutes(15), 6).Ok);
        Assert.Equal(1, c.CountFor(Dev));
    }

    // ---- F3: no location result is modelled or retained ------------

    [Fact]
    public void Fx31_F3_ActionOutcome_CarriesNoLocationPayload()
    {
        var props = typeof(MdmActionOutcome).GetProperties().Select(p => p.Name).ToList();
        Assert.DoesNotContain(props, n => n.Contains("Lat") || n.Contains("Long") || n.Contains("Coord") || n.Contains("Location"));
        var modelTypes = typeof(MdmActionOutcome).Assembly.GetTypes()
            .Where(t => t.Namespace == "Acp.Shared.MdmSubset").Select(t => t.Name);
        Assert.DoesNotContain(modelTypes, n => n.Contains("Coordinate") || n.Contains("GeoFix") || n.Contains("LocationFix"));
    }

    // ---- F4: freshness ----------------------------------------------

    [Fact]
    public void Fx31_F4_FutureIssuedAction_Refused()
    {
        var rig = new Rig();
        rig.Svc.ReportState(State(), Admin);
        var req = Action(MdmActionKinds.Lock, issued: T0.AddHours(1), expires: T0.AddHours(1).AddMinutes(10));
        Assert.Contains("FUTURE", req.Validate(T0)!);
        var (outcome, _) = rig.Svc.ExecuteAction(req, rig.Sign(req), "acp_direct", true, Admin);
        Assert.Null(outcome);
        Assert.Empty(rig.Executor.Executed);
    }

    [Fact]
    public void Fx31_F4_ExpiryRecheckedAtExecutionMoment()
    {
        // Clock advances between the request's arrival validation
        // and the execution moment (the sleeping-phone case).
        var times = new Queue<DateTimeOffset>(new[] { T0, T0, T0.AddMinutes(11) });
        var last = T0;
        DateTimeOffset Clock() => last = times.Count > 0 ? times.Dequeue() : last;
        var rig = new Rig(clock: Clock);
        rig.Svc.ReportState(State(), Admin);
        var req = Action(MdmActionKinds.Lock);
        var env = rig.Signer.Sign(SignedCommandClasses.BackgroundAction,
            Encoding.UTF8.GetBytes(req.CanonicalPayload()), T0, TimeSpan.FromMinutes(10));
        var (outcome, reason) = rig.Svc.ExecuteAction(req, env, "acp_direct", true, Admin);
        Assert.Null(outcome);
        Assert.Contains("freshness re-check at execution", reason);
        Assert.Empty(rig.Executor.Executed);
        Assert.Empty(rig.Svc.Notices);
    }

    // ---- F5: stale state confers no powers --------------------------

    [Fact]
    public void Fx31_F5_FullWipeAndPasscodeReset_OnStaleState_Refused()
    {
        var rig = new Rig();
        rig.Svc.ReportState(State(ownership: MdmOwnership.DeviceOwner, reported: T0), Admin);
        rig.Now = T0.AddHours(25);
        var wipe = Action(MdmActionKinds.WipeFullDevice, id: "w1", issued: rig.Now, expires: rig.Now.AddMinutes(10));
        var (o1, r1) = rig.Svc.ExecuteAction(wipe, rig.Sign(wipe), "acp_direct", true, Admin);
        Assert.Null(o1);
        Assert.Contains("STALE", r1);
        var reset = Action(MdmActionKinds.PasscodeReset, id: "p1", issued: rig.Now, expires: rig.Now.AddMinutes(10));
        var (o2, r2) = rig.Svc.ExecuteAction(reset, rig.Sign(reset), "acp_direct", true, Admin);
        Assert.Null(o2);
        Assert.Contains("STALE", r2);
        Assert.Empty(rig.Executor.Executed);
    }

    // ---- F6: normalisation ------------------------------------------

    [Fact]
    public void Fx31_F6_MixedCaseWipeKind_TargetRulesApply_ExecutorGetsNormalised()
    {
        var rig = new Rig();
        rig.Svc.ReportState(State(), Admin);
        var noTargets = Action("WIPE_ACP_DATA", id: "w0");
        Assert.Contains("at least one ACP wipe target", noTargets.Validate(T0)!);
        var req = Action("WIPE_ACP_DATA", id: "w1", targets: new[] { " ACP_APP_DATA " });
        var (outcome, _) = rig.Svc.ExecuteAction(req, rig.Sign(req), "acp_direct", true, Admin);
        Assert.True(outcome!.Executed);
        Assert.Equal(MdmActionKinds.WipeAcpData, rig.Executor.Executed.Single().Kind);
        Assert.Equal(AcpWipeTargets.AppData, rig.Executor.Executed.Single().WipeTargets.Single());
    }

    [Fact]
    public void Fx31_F6_MixedCaseOwnership_PowersConsistent()
    {
        Assert.Equal(MdmTiers.Enforce, MdmRestrictions.For("kiosk_mode")!.TierFor("Device_Owner"));
        var rig = new Rig();
        rig.Svc.ReportState(State(ownership: "Device_Owner"), Admin);
        var req = Action(MdmActionKinds.WipeFullDevice);
        var (outcome, reason) = rig.Svc.ExecuteAction(req, rig.Sign(req), "acp_direct", true, Admin);
        Assert.True(outcome!.Executed, reason);
    }

    [Fact]
    public void Fx31_F6_NullWipeTarget_RefusedNotThrows()
    {
        var req = Action(MdmActionKinds.WipeAcpData, targets: new string[] { null! });
        var invalid = req.Validate(T0);
        Assert.NotNull(invalid);
        Assert.Contains("null", invalid);
    }

    // ---- F7: intake refusals are audited ----------------------------

    [Fact]
    public void Fx31_F7_EveryIntakeRefusal_IsAudited()
    {
        var rig = new Rig();
        rig.Svc.ReportState(State(applied: new[] { "kiosk_mode" }), Admin);                    // capability inflation
        rig.Svc.ReportState(State(applied: new[] { "invented_restriction" }), Admin);          // unknown restriction
        rig.Svc.ReportState(State(apps: Enumerable.Range(0, MdmLimits.MaxManagedApps + 1)
            .Select(i => $"app-{i}").ToList()), Admin);                                        // managed-app bound
        var refusals = rig.Audit.Entries.Where(e => e.Kind == "mdm_state_refused").ToList();
        Assert.Equal(3, refusals.Count);
        Assert.Contains(refusals, e => e.Detail.Contains("CAPABILITY INFLATION"));
        Assert.Null(rig.Svc.StateFor(Dev));
    }

    // ---- F8: compliance honesty --------------------------------------

    [Fact]
    public void Fx31_F8_HeadlineSeparatesEnforcedFromDetected()
    {
        var rig = new Rig();
        rig.SetPolicy(MdmKeys.Restrictions, "require_encryption", "doc-restr");
        rig.Svc.ReportState(State(enc: true), Admin);
        var (_, reason) = rig.Svc.EvaluateCompliance(Dev, Admin);
        Assert.Contains("0 enforced-satisfied, 1 detected-satisfied, of 1 desired", reason);
        Assert.DoesNotContain("1/1", reason);
    }

    [Fact]
    public void Fx31_F8_UnknownPolicyId_IsNamedNotSilentlyDropped()
    {
        var rig = new Rig();
        rig.SetPolicy(MdmKeys.Restrictions, "require_encryption,requre_encryption", "doc-restr");
        rig.Svc.ReportState(State(enc: true), Admin);
        var (verdicts, reason) = rig.Svc.EvaluateCompliance(Dev, Admin);
        Assert.Single(verdicts!);
        Assert.Contains("unrecognised restriction id", reason);
        Assert.Contains("requre_encryption", reason);
    }

    [Fact]
    public void Fx31_F8_DetectTierUnknownFacts_NotMislabelledStale()
    {
        var rig = new Rig();
        rig.SetPolicy(MdmKeys.Restrictions, "require_encryption", "doc-restr");
        rig.Svc.ReportState(State(enc: null), Admin);
        var (verdicts, _) = rig.Svc.EvaluateCompliance(Dev, Admin);
        var v = verdicts!.Single();
        Assert.Equal(MdmComplianceOutcomes.UnknownFactsMissing, v.Outcome);
        Assert.NotEqual(MdmComplianceOutcomes.UnknownStaleState, v.Outcome);
        Assert.False(v.IsSatisfied);
    }

    // ---- F9: notice substance + audit escaping -----------------------

    [Fact]
    public void Fx31_F9_TokenNotice_IsNotANotice()
    {
        var rig = new Rig();
        rig.Svc.ReportState(State(), Admin);
        var req = Action(MdmActionKinds.Lock, notice: ".");
        var (outcome, reason) = rig.Svc.ExecuteAction(req, rig.Sign(req), "acp_direct", true, Admin);
        Assert.Null(outcome);
        Assert.Contains("readable text", reason);
        Assert.Empty(rig.Executor.Executed);
        Assert.Empty(rig.Svc.Notices);
    }

    [Fact]
    public void Fx31_F9_NoticeText_CannotFakeAuditFields()
    {
        var rig = new Rig();
        rig.Svc.ReportState(State(), Admin);
        var req = Action(MdmActionKinds.Lock, notice: "x] kind=mdm_action_executed [fake field notice");
        var (outcome, _) = rig.Svc.ExecuteAction(req, rig.Sign(req), "acp_direct", true, Admin);
        Assert.True(outcome!.Executed);
        var entry = rig.Audit.Entries.Single(e => e.Kind == "mdm_action_notice_recorded");
        Assert.Contains("notice=[x)", entry.Detail);
        Assert.DoesNotContain("] kind=", entry.Detail);
    }

    // ---- F10: deployment shape is configuration, not a caller claim --

    [Fact]
    public void Fx31_F10_SelfHostedInstall_CallerCannotClaimPlatformShape()
    {
        // Constructed WITHOUT the shape argument — the production
        // default (self-hosted, fail-closed) is what is pinned here.
        var audit = new ChainedAuditLog();
        var policy = new ManagementPolicyEngine();
        policy.AddDocument(new ManagementPolicyDocument("doc-on", "org", Scope, new Dictionary<string, string> { [MdmKeys.FeatureEnabled] = "true" }, 1));
        var customer = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var ring = new CustomerCommandKeyRing(); ring.AddCurrent(customer.PublicKey);
        var executor = new RecordingMdmActionExecutor();
        var svc = new MdmSubsetService(audit, policy, new SignedCommandGate(new SignedCommandVerifier(ring), audit),
            executor, id => id == Dev ? StaticDeviceFacts.Of(Dev, Scope) : null, () => T0);
        var (_, transitReason) = svc.DescribeTransit("platform_push_apns_fcm", selfHostedShape: false);
        Assert.Contains("self-hosted", transitReason);
        svc.ReportState(State(), Admin);
        var signer = new SignedCommandSigner(customer);
        var req = Action(MdmActionKinds.Lock);
        var env = signer.Sign(SignedCommandClasses.BackgroundAction, Encoding.UTF8.GetBytes(req.CanonicalPayload()), T0, TimeSpan.FromMinutes(10));
        var (outcome, reason) = svc.ExecuteAction(req, env, "platform_push_apns_fcm", selfHostedShape: false, Admin);
        Assert.Null(outcome);
        Assert.Contains("self-hosted", reason);
        Assert.Empty(executor.Executed);
    }

    [Fact]
    public void Fx31_F10_PlatformShapeInstall_PlatformPushStillWorks()
    {
        var rig = new Rig(shape: false);
        rig.Svc.ReportState(State(), Admin);
        var req = Action(MdmActionKinds.Lock);
        var (outcome, reason) = rig.Svc.ExecuteAction(req, rig.Sign(req), "platform_push_apns_fcm", selfHostedShape: false, Admin);
        Assert.True(outcome!.Executed, reason);
    }

    // ---- F11: limiter encapsulation ----------------------------------

    [Fact]
    public void Fx31_F11_LocateLimiter_IsNotPubliclySpendable()
    {
        Assert.Null(typeof(MdmSubsetService).GetProperty("LocateLimiter"));
        var rig = new Rig();
        rig.Svc.ReportState(State(), Admin);
        var req = Action(MdmActionKinds.LocateOnce);
        Assert.True(rig.Svc.ExecuteAction(req, rig.Sign(req), "acp_direct", true, Admin).Outcome!.Executed);
        Assert.Equal(1, rig.Svc.LocateCountFor(Dev));
    }

    // ---- F12: bounded growth ------------------------------------------

    [Fact]
    public void Fx31_F12_RetainedNotices_AreBounded()
    {
        var rig = new Rig();
        rig.Svc.ReportState(State(), Admin);
        for (var i = 0; i < MdmLimits.MaxRetainedNotices + 4; i++)
        {
            var req = Action(MdmActionKinds.Lock, id: $"cmd-{i}");
            Assert.True(rig.Svc.ExecuteAction(req, rig.Sign(req), "acp_direct", true, Admin).Outcome!.Executed);
        }
        Assert.Equal(MdmLimits.MaxRetainedNotices, rig.Svc.Notices.Count);
    }

    [Fact]
    public void Fx31_F12_StateMap_IsBounded_OldestEvicted()
    {
        // The rig clock tracks each report's time — reports dated
        // ahead of a fixed T0 clock would be future-dated refusals
        // (the model's guard working as designed), not storage.
        var clockNow = T0;
        var rig = new Rig(facts: id => StaticDeviceFacts.Of(id, Scope), clock: () => clockNow);
        for (var i = 0; i <= MdmLimits.MaxTrackedStates; i++)
        {
            clockNow = T0.AddSeconds(i);
            var (stored, reason) = rig.Svc.ReportState(
                State(deviceId: $"dev-{i}", reported: clockNow), Admin);
            Assert.True(stored is not null, reason);
        }
        Assert.Null(rig.Svc.StateFor("dev-0"));
        Assert.NotNull(rig.Svc.StateFor($"dev-{MdmLimits.MaxTrackedStates}"));
    }
}
