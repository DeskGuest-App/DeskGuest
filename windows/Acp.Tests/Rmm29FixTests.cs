using System.Text;
using Acp.Core.Services;
using Acp.Shared.Enterprise;
using Acp.Shared.Jobs;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Provisioning;
using Acp.Shared.Security;

namespace Acp.Tests;

// RMM-29 — D38 FIX lane regression tests (packet 5f9036d2, FAIL,
// 12 findings). Each test names the finding it pins. Fakes only;
// nothing here images a real machine.
public class Rmm29FixTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    private const string Dev = "dev-1";
    private const string Scope = "co-1";
    private const string User1 = "user-1";
    private const string User2 = "user-2";

    private static Rmm29Tests.Rig NewRig()
    {
        var rig = new Rmm29Tests.Rig();
        Assert.Null(rig.Images.Admit(Rmm29Tests.Image()));
        return rig;
    }

    private sealed class FlakyEnrollmentSink : IProvisioningEnrollmentSink
    {
        private bool _broken = true;
        public void Heal() => _broken = false;
        public void Enroll(string deviceId, string imageId, string imageVersion)
        {
            if (_broken) throw new InvalidOperationException("hub unreachable");
        }
    }

    private sealed class ThrowOnceImagingExecutor : IImagingExecutor
    {
        private bool _thrown;
        public int CallCount { get; private set; }
        public ImagingApplyResult ApplyImage(ImagingApplyRequest request)
        {
            CallCount++;
            if (!_thrown) { _thrown = true; throw new InvalidOperationException("power cut mid-apply"); }
            return new ImagingApplyResult(true, request.Image.BaseImageHash, "applied",
                request.Image.DriverPackHash, request.Image.UnattendHash);
        }
    }

    private static ProvisioningRunner RunnerWith(Rmm29Tests.Rig rig, IProvisioningEnrollmentSink enrollment) =>
        new(rig.Gate, rig.Audit, rig.Profiles, rig.Capture, rig.Imaging, enrollment, rig.Tokens,
            rig.Images.Get, rig.Images.IsRevoked, d => rig.Accepted.Contains(d),
            id => rig.Decisions.TryGetValue(id ?? "", out var dec) ? dec : null,
            d => Scope, d => rig.DevicesWithProfiles.Contains(d));

    // ---- F1: apply discipline / park --------------------------------

    [Fact]
    public void F1_ResumeAfterPostApplyFailure_DoesNotReapply_Completes()
    {
        var rig = NewRig();
        var flaky = new FlakyEnrollmentSink();
        var runner = RunnerWith(rig, flaky);
        var req = Rmm29Tests.Rig.ReimageReq();
        var first = runner.Run(req, rig.EnvelopeFor(req), new JobJournal(), () => true, T0);
        Assert.Equal(ProvisioningStates.FailedEnroll, first.State); // apply DONE, enroll failed
        Assert.Equal(1, rig.Imaging.CallCount);
        flaky.Heal();
        var resumed = runner.ResumeRun(req, rig.EnvelopeFor(req), new JobJournal(), () => true, T0);
        Assert.Equal(ProvisioningStates.Completed, resumed.State);
        Assert.Equal(1, rig.Imaging.CallCount); // the device was NOT re-imaged
    }

    [Fact]
    public void F1_UncertainApply_ParksOnResume_RetryDecisionAllowsExactlyOneReapply()
    {
        var rig = NewRig();
        var exec = new ThrowOnceImagingExecutor();
        var runner = new ProvisioningRunner(rig.Gate, rig.Audit, rig.Profiles, rig.Capture,
            exec, rig.Enrollment, rig.Tokens, rig.Images.Get, rig.Images.IsRevoked,
            d => rig.Accepted.Contains(d), id => null, d => Scope, d => false);
        var req = Rmm29Tests.Rig.ReimageReq();
        var first = runner.Run(req, rig.EnvelopeFor(req), new JobJournal(), () => true, T0);
        Assert.Equal(ProvisioningStates.FailedApply, first.State);
        Assert.Contains("parked for a human decision", first.Reason);
        Assert.Equal(1, exec.CallCount);
        // Resume with NO human decision: re-validates, then PARKS —
        // apply is not re-attempted on a guess.
        var parked = runner.ResumeRun(req, rig.EnvelopeFor(req), new JobJournal(), () => true, T0);
        Assert.Equal(ProvisioningStates.Parked, parked.State);
        Assert.Equal(1, exec.CallCount);
        // The human decides: retry. Exactly one further attempt.
        Assert.True(runner.ResolveParkedApply(req.RunId, ProvisioningParkDecision.RetryApply, "senior-tech", T0));
        var resumed = runner.ResumeRun(req, rig.EnvelopeFor(req), new JobJournal(), () => true, T0);
        Assert.Equal(ProvisioningStates.Completed, resumed.State);
        Assert.Equal(2, exec.CallCount);
        // Nothing left parked afterwards:
        Assert.False(runner.ResolveParkedApply(req.RunId, ProvisioningParkDecision.RetryApply, "senior-tech", T0));
    }

    [Fact]
    public void F1_ParkFailRunDecision_EndsRun_AndServiceMarksIdTerminal()
    {
        var (svc, policy, exec) = BuildService(new ThrowOnceImagingExecutor(),
            StaticDeviceFacts.Of(Dev, Scope));
        Assert.True(svc.AdmitImage(Rmm29Tests.Image(), "admin").Allowed);
        svc.RecordDeviceAcceptance(Dev, "endpoint-tech");
        EnablePolicy(policy);
        var req = Rmm29Tests.Rig.ReimageReq();
        var first = svc.RunProvisioning(req, "admin");
        Assert.Equal(ProvisioningStates.FailedApply, first.State);
        Assert.Equal(1, exec.CallCount);
        var verdict = svc.ResolveParkedApply(req.RunId, ProvisioningParkDecision.FailRun, "boss");
        Assert.True(verdict.Allowed, verdict.Reason);
        // The id is terminal now: neither verb runs it again.
        var again = svc.RunProvisioning(Rmm29Tests.Rig.ReimageReq(), "admin");
        Assert.Equal(ProvisioningStates.Refused, again.State);
        Assert.Contains("single-execution", again.Reason);
        Assert.Equal(1, exec.CallCount);
    }

    // ---- F2: Run() never re-runs an id -------------------------------

    [Fact]
    public void F2_PlainRun_SameIdAsCompletedBareMetalRun_Refused_TokenSkipNeverApplies()
    {
        var rig = NewRig();
        var img = Rmm29Tests.Image();
        var code = rig.Tokens.Mint(img.Id, img.Version, img.ContentHash, Scope, "admin", T0);
        var req = new ProvisioningRunRequest("run-bm-f2", img, Dev, ProvisioningModes.BareMetal, null, null, null, code);
        Assert.Equal(ProvisioningStates.Completed, rig.Run(req).State);
        Assert.Equal(1, rig.Imaging.CallCount);
        // The attack: plain Run() with the SAME id — before the fix
        // the per-run redeemed set skipped redemption and the
        // device was re-imaged with no valid token.
        var rerun = rig.Runner.Run(req, rig.EnvelopeFor(req), new JobJournal(), () => true, T0);
        Assert.Equal(ProvisioningStates.Refused, rerun.State);
        Assert.Contains("executes once", rerun.Reason);
        Assert.Equal(1, rig.Imaging.CallCount);
    }

    [Fact]
    public void F2_PlainRun_SameIdAsFailedRun_Refused()
    {
        var rig = NewRig();
        var runner = RunnerWith(rig, new FlakyEnrollmentSink());
        var req = Rmm29Tests.Rig.ReimageReq();
        Assert.Equal(ProvisioningStates.FailedEnroll,
            runner.Run(req, rig.EnvelopeFor(req), new JobJournal(), () => true, T0).State);
        var rerun = runner.Run(req, rig.EnvelopeFor(req), new JobJournal(), () => true, T0);
        Assert.Equal(ProvisioningStates.Refused, rerun.State);
        Assert.Equal(1, rig.Imaging.CallCount);
    }

    // ---- F3: resume binding -------------------------------------------

    [Fact]
    public void F3_ResumeWithDifferentImageOrDevice_Refused_RecordIntact_ThenTrueResumeCompletes()
    {
        var rig = NewRig();
        var flaky = new FlakyEnrollmentSink();
        var runner = RunnerWith(rig, flaky);
        var req = Rmm29Tests.Rig.ReimageReq();
        Assert.Equal(ProvisioningStates.FailedEnroll,
            runner.Run(req, rig.EnvelopeFor(req), new JobJournal(), () => true, T0).State);

        // Resume naming a DIFFERENT image (same id/version, other content):
        var otherImage = Rmm29Tests.Rig.ReimageReq(image: Rmm29Tests.Image(driverSeed: "drivers-ATTACKER"));
        var r1 = runner.ResumeRun(otherImage, rig.EnvelopeFor(otherImage), new JobJournal(), () => true, T0);
        Assert.Equal(ProvisioningStates.Refused, r1.State);
        Assert.Contains("does not match the failed run's recorded binding", r1.Reason);

        // Resume naming a DIFFERENT device (profile of dev-1 onto dev-2):
        var otherDevice = Rmm29Tests.Rig.ReimageReq(device: "dev-2");
        var r2 = runner.ResumeRun(otherDevice, rig.EnvelopeFor(otherDevice), new JobJournal(), () => true, T0);
        Assert.Equal(ProvisioningStates.Refused, r2.State);

        // The failed record is undisturbed, and the TRUE resume completes:
        Assert.Equal(ProvisioningStates.FailedEnroll, runner.GetRun(req.RunId)!.State);
        flaky.Heal();
        var resumed = runner.ResumeRun(req, rig.EnvelopeFor(req), new JobJournal(), () => true, T0);
        Assert.Equal(ProvisioningStates.Completed, resumed.State);
        Assert.Equal(1, rig.Imaging.CallCount);
    }

    // ---- F4: envelope binds target user + decision id ------------------

    [Fact]
    public void F4_Payload_BindsTargetUserAndDecisionId()
    {
        var img = Rmm29Tests.Image();
        var baseline = ProvisioningBinding.Payload("run", img, Dev, "mh", ProvisioningModes.Reimage, User1, "dec-1");
        Assert.NotEqual(baseline,
            ProvisioningBinding.Payload("run", img, Dev, "mh", ProvisioningModes.Reimage, User2, "dec-1"));
        Assert.NotEqual(baseline,
            ProvisioningBinding.Payload("run", img, Dev, "mh", ProvisioningModes.Reimage, User1, "dec-2"));
        Assert.NotEqual(baseline,
            ProvisioningBinding.Payload("run", img, Dev, "mh", ProvisioningModes.Reimage, null, null));
    }

    [Fact]
    public void F4_EnvelopeSignedForDifferentTargetUser_RunnerRefuses()
    {
        var rig = NewRig();
        var req = Rmm29Tests.Rig.ReimageReq(targetUser: User2);
        // Envelope honestly signed — but for target user "user-9".
        // Before the fix the target user travelled unsigned, so
        // this envelope authorized the redirect.
        var payload = ProvisioningBinding.Payload(req.RunId, req.Image, req.DeviceId,
            ProvisioningBinding.CaptureManifestHash(req.CaptureManifest!), req.Mode, "user-9", null);
        var env = rig.Signer.Sign(SignedCommandClasses.Provisioning,
            Encoding.UTF8.GetBytes(payload), T0, TimeSpan.FromMinutes(30));
        var result = rig.Runner.Run(req, env, new JobJournal(), () => true, T0);
        Assert.Equal(ProvisioningStates.Refused, result.State);
        Assert.Contains("target user and decision", result.Reason);
        Assert.Equal(0, rig.Imaging.CallCount);
    }

    // ---- F5: token scope ------------------------------------------------

    [Fact]
    public void F5_TokenMintedForOtherScope_RefusedBeforeApply_NotConsumed()
    {
        var rig = NewRig();
        var img = Rmm29Tests.Image();
        var code = rig.Tokens.Mint(img.Id, img.Version, img.ContentHash, "co-OTHER", "admin", T0);
        var req = new ProvisioningRunRequest("run-bm-f5", img, Dev, ProvisioningModes.BareMetal, null, null, null, code);
        var result = rig.Run(req); // rig devices live in scope co-1
        Assert.Equal(ProvisioningStates.FailedValidation, result.State);
        Assert.Equal(0, rig.Imaging.CallCount);
        Assert.False(rig.Tokens.WasConsumed(code)); // binding mismatch does not consume
        // …and the token still redeems for its OWN scope at model level:
        Assert.NotNull(rig.Tokens.Redeem(code, img.Id, img.Version, img.ContentHash, T0, "co-OTHER"));
    }

    // ---- F6: decision register discipline --------------------------------

    [Fact]
    public void F6_ServiceRegister_OnlyApproverMayRecord_NoSilentOverwrite()
    {
        var rig = new Rmm29Tests.ServiceRig();
        var decision = new CrossUserRestoreDecision("dec-f6", User1, User2,
            "requester", "approver", T0, "desk move");
        // A requester writing "approved_by=approver" alone:
        Assert.False(rig.Service.RecordCrossUserDecision(decision, "requester").Allowed);
        Assert.False(rig.Service.RecordCrossUserDecision(decision, "mallory").Allowed);
        // The approver records their own decision:
        Assert.True(rig.Service.RecordCrossUserDecision(decision, "approver").Allowed);
        // Identical re-record is an idempotent no-op…
        Assert.True(rig.Service.RecordCrossUserDecision(decision, "approver").Allowed);
        // …but a different decision under the same id refuses:
        var altered = decision with { TargetUserId = "user-3" };
        Assert.False(rig.Service.RecordCrossUserDecision(altered, "approver").Allowed);
    }

    [Fact]
    public void F6_ExpiredDecision_RefusedAtRestore()
    {
        var rig = NewRig();
        var stale = new CrossUserRestoreDecision("dec-old", User1, User2,
            "requester", "approver", T0.AddHours(-25), "decided yesterday");
        rig.Decisions["dec-old"] = stale;
        var req = Rmm29Tests.Rig.ReimageReq(targetUser: User2, decision: stale);
        var result = rig.Run(req);
        Assert.Equal(ProvisioningStates.FailedRestore, result.State);
        Assert.Contains("expired", result.Reason);
    }

    [Fact]
    public void F6_DecisionBoundToOtherRun_RefusedAtRestore()
    {
        var rig = NewRig();
        var bound = new CrossUserRestoreDecision("dec-bound", User1, User2,
            "requester", "approver", T0, "for another run", RunId: "run-someone-else");
        rig.Decisions["dec-bound"] = bound;
        var req = Rmm29Tests.Rig.ReimageReq(targetUser: User2, decision: bound);
        var result = rig.Run(req);
        Assert.Equal(ProvisioningStates.FailedRestore, result.State);
        Assert.Contains("bound to a different run", result.Reason);
    }

    // ---- F7: no-register runner refuses presented decisions --------------

    [Fact]
    public void F7_RunnerWithoutRegister_FabricatedDecision_Refused()
    {
        var rig = NewRig();
        // Runner built WITHOUT the decision lookup (the default) —
        // before the fix a fabricated decision object passed here.
        var runner = new ProvisioningRunner(rig.Gate, rig.Audit, rig.Profiles, rig.Capture,
            rig.Imaging, rig.Enrollment, rig.Tokens, rig.Images.Get, rig.Images.IsRevoked,
            d => rig.Accepted.Contains(d));
        var fabricated = new CrossUserRestoreDecision("dec-forged", User1, User2,
            "requester", "approver", T0, "forged paperwork");
        var req = Rmm29Tests.Rig.ReimageReq(targetUser: User2, decision: fabricated);
        var result = runner.Run(req, rig.EnvelopeFor(req), new JobJournal(), () => true, T0);
        Assert.Equal(ProvisioningStates.FailedRestore, result.State);
        Assert.Contains("no audited cross-user decision register is wired", result.Reason);
    }

    // ---- F8: bare-metal on a device holding profiles -----------------------

    [Fact]
    public void F8_BareMetal_DeviceWithProfiles_Refused_TokenNotConsumed()
    {
        var rig = NewRig();
        rig.DevicesWithProfiles.Add(Dev);
        var img = Rmm29Tests.Image();
        var code = rig.Tokens.Mint(img.Id, img.Version, img.ContentHash, Scope, "admin", T0);
        var req = new ProvisioningRunRequest("run-bm-f8", img, Dev, ProvisioningModes.BareMetal, null, null, null, code);
        var result = rig.Run(req);
        Assert.Equal(ProvisioningStates.Refused, result.State);
        Assert.Contains("holds existing user profiles", result.Reason);
        Assert.Equal(0, rig.Imaging.CallCount);
        Assert.False(rig.Tokens.WasConsumed(code));
    }

    [Fact]
    public void F8_Service_BareMetal_DeviceWithProfileFact_Refused()
    {
        var facts = StaticDeviceFacts.Of(Dev, Scope, attributes: new Dictionary<string, string>
        {
            ["profile_present"] = "true",
        });
        var (svc, policy, imaging) = BuildService(new FakeImagingExecutor(), facts);
        Assert.True(svc.AdmitImage(Rmm29Tests.Image(), "admin").Allowed);
        svc.RecordDeviceAcceptance(Dev, "endpoint-tech");
        EnablePolicy(policy);
        var (code, mint) = svc.MintProvisioningToken("gold", "1.0.0", Scope, "admin");
        Assert.True(mint.Allowed, mint.Reason);
        var req = new ProvisioningRunRequest("run-bm-f8s", Rmm29Tests.Image(), Dev,
            ProvisioningModes.BareMetal, null, null, null, code);
        var result = svc.RunProvisioning(req, "admin");
        Assert.Equal(ProvisioningStates.Refused, result.State);
        Assert.Contains("holds existing user profiles", result.Reason);
        Assert.Equal(0, imaging.CallCount);
    }

    // ---- F10: concurrency ---------------------------------------------------

    [Fact]
    public void F10_ConcurrentRuns_SameRunId_ExactlyOneApplies()
    {
        var rig = NewRig();
        var req = Rmm29Tests.Rig.ReimageReq();
        var env1 = rig.EnvelopeFor(req);
        var env2 = rig.EnvelopeFor(req);
        var results = new ProvisioningRunResult?[2];
        Parallel.Invoke(
            () => results[0] = rig.Runner.Run(req, env1, new JobJournal(), () => true, T0),
            () => results[1] = rig.Runner.Run(req, env2, new JobJournal(), () => true, T0));
        Assert.Equal(1, results.Count(r => r!.State == ProvisioningStates.Completed));
        Assert.Equal(1, rig.Imaging.CallCount); // apply ran exactly once
    }

    // ---- F11: every pinned component verified --------------------------------

    [Fact]
    public void F11_SubstitutedDriverPack_ReportedHashMismatch_FailsApply()
    {
        var rig = NewRig();
        rig.Imaging.ApplyDriverHash(Rmm29Tests.H("attacker-driver-pack"));
        var result = rig.Run(Rmm29Tests.Rig.ReimageReq());
        Assert.Equal(ProvisioningStates.FailedApply, result.State);
        Assert.Contains("driver pack", result.Reason);
    }

    [Fact]
    public void F11_PinnedUnattend_WrongReportedHash_FailsApply()
    {
        var rig = NewRig();
        // Convergence reconciliation (2026-11-22): NewRig already admits
        // the default "gold"/"1.0.0" image; re-admitting the same
        // id+version with different content is a conflict by the base
        // suite's own contract (Rmm29Tests
        // ImageRepository_SameIdVersionDifferentContent_Conflicts).
        // The variant therefore carries its own id so admission succeeds
        // and the pinned-unattend check is what the run exercises.
        var img = Rmm29Tests.Image(id: "gold-unattend") with { UnattendHash = Rmm29Tests.H("unattend-v1") };
        Assert.Null(rig.Images.Admit(img));
        rig.Imaging.ApplyUnattendHash(Rmm29Tests.H("unattend-ATTACKER"));
        var req = Rmm29Tests.Rig.ReimageReq(image: img);
        var result = rig.Run(req);
        Assert.Equal(ProvisioningStates.FailedApply, result.State);
        Assert.Contains("unattend", result.Reason);
    }

    // ---- F12: pruning + path segments ------------------------------------------

    [Fact]
    public void F12_ManifestPath_DotDotSubstringName_Accepted_TraversalStillRefused()
    {
        var legit = new ProfileCaptureManifest(Dev, User1,
            new[] { new ProfileManifestEntry("Documents/file..txt", ProfileCategories.Documents) });
        Assert.Null(legit.Validate());
        var traversal = new ProfileCaptureManifest(Dev, User1,
            new[] { new ProfileManifestEntry("Documents/../escape.txt", ProfileCategories.Documents) });
        Assert.NotNull(traversal.Validate());
    }

    [Fact]
    public void F12_ConsumedTokenHashes_PrunedAfterRetention_ReplayStillRefused()
    {
        var tokens = new ProvisioningTokenService();
        var img = Rmm29Tests.Image();
        var code = tokens.Mint(img.Id, img.Version, img.ContentHash, Scope, "admin", T0);
        Assert.NotNull(tokens.Redeem(code, img.Id, img.Version, img.ContentHash, T0, Scope));
        Assert.True(tokens.WasConsumed(code));
        // A later redemption (past the retention horizon) prunes the
        // consumed set — but replay of the old code STILL refuses,
        // because its pending entry is long gone:
        var code2 = tokens.Mint(img.Id, img.Version, img.ContentHash, Scope, "admin", T0.AddHours(3));
        Assert.NotNull(tokens.Redeem(code2, img.Id, img.Version, img.ContentHash, T0.AddHours(3), Scope));
        Assert.False(tokens.WasConsumed(code));
        Assert.Null(tokens.Redeem(code, img.Id, img.Version, img.ContentHash, T0.AddHours(3), Scope));
    }

    // ---- manual service construction (executor / facts variants) -------------

    private static void EnablePolicy(ManagementPolicyEngine policy) => policy.AddDocument(
        new ManagementPolicyDocument("doc-prov", PolicyLevels.Org, Scope,
            new Dictionary<string, string> { [ProvisioningPolicyKeys.ProvisioningEnabled] = "true" }, 1));

    private static (ProvisioningService Service, ManagementPolicyEngine Policy, TExecutor Imaging)
        BuildService<TExecutor>(TExecutor imaging, IDeviceFacts facts) where TExecutor : IImagingExecutor
    {
        var audit = new ChainedAuditLog();
        var policy = new ManagementPolicyEngine();
        var protector = new DevOnlyPassThroughProtector();
        var customer = new DeviceIdentity(protector);
        var ring = new CustomerCommandKeyRing();
        ring.AddCurrent(customer.PublicKey);
        var gate = new SignedCommandGate(new SignedCommandVerifier(ring), audit);
        var signer = new SignedCommandSigner(customer);
        var svc = new ProvisioningService(audit, policy,
            id => id == facts.DeviceId ? facts : null, signer, gate, protector,
            Rmm29Tests.FullSource(), imaging, new FakeEnrollmentSink(), null, () => T0);
        return (svc, policy, imaging);
    }
}
