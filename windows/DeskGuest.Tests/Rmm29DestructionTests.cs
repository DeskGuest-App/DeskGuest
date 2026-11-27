using System.Text;
using System.Text.Json;
using DeskGuest.Shared.Jobs;
using DeskGuest.Shared.Provisioning;
using DeskGuest.Shared.Security;

namespace DeskGuest.Tests;

// RMM-29 — DESTRUCTION pass. Hostile attacks on the provisioning
// model + runner + service, fakes only. Each test names the attack;
// a break becomes a fix + this permanent regression (ledger-rmm29).
public class Rmm29DestructionTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    private const string Dev = "dev-1";
    private const string User1 = "user-1";
    private const string User2 = "user-2";

    private static Rmm29Tests.Rig NewRig()
    {
        var rig = new Rmm29Tests.Rig();
        Assert.Null(rig.Images.Admit(Rmm29Tests.Image()));
        return rig;
    }

    // ---- unverified capture must never reach apply ---------------------

    [Fact]
    public void Attack_CaptureMissingDeclaredEntry_BlocksApply()
    {
        var rig = NewRig();
        rig.Capture = new FakeProfileCaptureSource().Add("Documents/report.txt", "partial only");
        // rebuild the runner against the sabotaged capture source:
        var runner = new ProvisioningRunner(rig.Gate, rig.Audit, rig.Profiles, rig.Capture,
            rig.Imaging, rig.Enrollment, rig.Tokens, rig.Images.Get, rig.Images.IsRevoked,
            d => rig.Accepted.Contains(d), id => null);
        var req = Rmm29Tests.Rig.ReimageReq();
        var env = rig.EnvelopeFor(req);
        var result = runner.Run(req, env, new JobJournal(), () => true, T0);
        Assert.Equal(ProvisioningStates.FailedCaptureUnverified, result.State);
        Assert.Equal(0, rig.Imaging.CallCount); // apply NEVER ran
    }

    [Fact]
    public void Attack_CaptureSourceThrows_BlocksApply()
    {
        var rig = NewRig();
        var throwing = new FakeProfileCaptureSource().ThenThrow(new IOException("disk gone"));
        var runner = new ProvisioningRunner(rig.Gate, rig.Audit, rig.Profiles, throwing,
            rig.Imaging, rig.Enrollment, rig.Tokens, rig.Images.Get, rig.Images.IsRevoked,
            d => rig.Accepted.Contains(d), id => null);
        var req = Rmm29Tests.Rig.ReimageReq();
        var result = runner.Run(req, rig.EnvelopeFor(req), new JobJournal(), () => true, T0);
        Assert.Equal(ProvisioningStates.FailedCaptureUnverified, result.State);
        Assert.Equal(0, rig.Imaging.CallCount);
    }

    [Fact]
    public void Attack_CaptureProducesUndeclaredEntry_Refused()
    {
        var engine = new ProfileMigrationEngine(new DevOnlyPassThroughProtector());
        var greedy = Rmm29Tests.FullSource().Add("Settings/extra-secret.txt", "not declared");
        var (pkg, reason) = engine.CaptureAndSeal(Rmm29Tests.Manifest(), greedy, T0);
        Assert.Null(pkg);
        Assert.Contains("undeclared", reason);
    }

    // ---- image substitution between authorization and apply -------------

    [Fact]
    public void Attack_ImageSubstitutedBetweenAuthorizationAndApply_RefusedAtApply()
    {
        var rig = NewRig();
        var calls = 0;
        rig.LookupOverride = (id, v) =>
        {
            calls++;
            // validate sees the authorized definition; the apply-time
            // re-fetch sees a SUBSTITUTED one (different driver pack):
            return calls <= 1 ? Rmm29Tests.Image() : Rmm29Tests.Image(driverSeed: "drivers-ATTACKER");
        };
        var result = rig.Run(Rmm29Tests.Rig.ReimageReq());
        Assert.Equal(ProvisioningStates.FailedApply, result.State);
        Assert.Contains("substituted", result.Reason);
        Assert.Equal(0, rig.Imaging.CallCount); // executor never invoked with the wrong image
    }

    [Fact]
    public void Attack_ExecutorAppliesDifferentBaseImage_RunFailsByName()
    {
        var rig = NewRig();
        rig.Imaging.ApplyHash(Rmm29Tests.H("attacker-base-image"));
        var result = rig.Run(Rmm29Tests.Rig.ReimageReq());
        Assert.Equal(ProvisioningStates.FailedApply, result.State);
        Assert.Contains("NOT the authorized image", result.Reason);
    }

    [Fact]
    public void Attack_ImageRevokedBetweenAuthorizationAndRun_Refused()
    {
        var rig = NewRig();
        Assert.True(rig.Images.Revoke("gold", "1.0.0"));
        var result = rig.Run(Rmm29Tests.Rig.ReimageReq());
        Assert.Equal(ProvisioningStates.FailedValidation, result.State);
        Assert.Equal(0, rig.Imaging.CallCount);
    }

    // ---- token reuse / replay ---------------------------------------------

    [Fact]
    public void Attack_TokenReplay_SecondRunRefusedBeforeApply()
    {
        var rig = NewRig();
        var img = Rmm29Tests.Image();
        var code = rig.Tokens.Mint(img.Id, img.Version, img.ContentHash, "co-1", "admin", T0);
        var req1 = new ProvisioningRunRequest("run-bm-1", img, Dev, ProvisioningModes.BareMetal, null, null, null, code);
        Assert.Equal(ProvisioningStates.Completed, rig.Run(req1).State);
        Assert.Equal(1, rig.Imaging.CallCount);
        // REPLAY: a second run presenting the same (now consumed) code:
        var req2 = new ProvisioningRunRequest("run-bm-2", img, Dev, ProvisioningModes.BareMetal, null, null, null, code);
        var replay = rig.Run(req2);
        Assert.Equal(ProvisioningStates.FailedValidation, replay.State);
        Assert.Equal(1, rig.Imaging.CallCount); // apply NEVER ran for the replay
    }

    [Fact]
    public void Attack_TokenForOtherImageOrExpired_RefusedBeforeApply()
    {
        var rig = NewRig();
        var img = Rmm29Tests.Image();
        var otherCode = rig.Tokens.Mint(img.Id, img.Version, Rmm29Tests.H("some-other-image"), "co-1", "admin", T0);
        var req = new ProvisioningRunRequest("run-bm-x", img, Dev, ProvisioningModes.BareMetal, null, null, null, otherCode);
        var result = rig.Run(req);
        Assert.Equal(ProvisioningStates.FailedValidation, result.State);
        Assert.Equal(0, rig.Imaging.CallCount);

        var rig2 = NewRig();
        var expired = rig2.Tokens.Mint(img.Id, img.Version, img.ContentHash, "co-1", "admin",
            T0.AddHours(-2), TimeSpan.FromMinutes(30));
        var req2 = new ProvisioningRunRequest("run-bm-y", img, Dev, ProvisioningModes.BareMetal, null, null, null, expired);
        Assert.Equal(ProvisioningStates.FailedValidation, rig2.Run(req2).State);
        Assert.Equal(0, rig2.Imaging.CallCount);
    }

    // ---- cross-user restore --------------------------------------------------

    [Fact]
    public void Attack_CrossUserRestore_WithoutDecision_FailsRestoreByName()
    {
        var rig = NewRig();
        var req = Rmm29Tests.Rig.ReimageReq(targetUser: User2);
        var result = rig.Run(req);
        Assert.Equal(ProvisioningStates.FailedRestore, result.State);
        Assert.Contains("cross-user restore requires a separate audited decision", result.Reason);
    }

    [Fact]
    public void Attack_CrossUserRestore_SelfApprovedDecision_Refused()
    {
        var rig = NewRig();
        var selfApproved = new CrossUserRestoreDecision("dec-self", User1, User2,
            "mallory", "mallory", T0, "trust me");
        rig.Decisions["dec-self"] = selfApproved; // even registered, self-approval is no approval
        var req = Rmm29Tests.Rig.ReimageReq(targetUser: User2, decision: selfApproved);
        var result = rig.Run(req);
        Assert.Equal(ProvisioningStates.FailedRestore, result.State);
    }

    [Fact]
    public void Attack_CrossUserRestore_FabricatedDecisionNotInRegister_Refused()
    {
        // D29-03 regression: a decision object invented by the caller
        // (never recorded in the audited register) must not restore.
        var rig = NewRig();
        var fabricated = new CrossUserRestoreDecision("dec-forged", User1, User2,
            "requester", "approver", T0, "forged paperwork");
        var req = Rmm29Tests.Rig.ReimageReq(targetUser: User2, decision: fabricated);
        var result = rig.Run(req);
        Assert.Equal(ProvisioningStates.FailedRestore, result.State);
        Assert.Contains("not the audited decision", result.Reason);
    }

    [Fact]
    public void Control_CrossUserRestore_RegisteredDecision_Completes()
    {
        var rig = NewRig();
        var decision = new CrossUserRestoreDecision("dec-ok", User1, User2,
            "requester", "approver", T0, "employee changed desks");
        rig.Decisions["dec-ok"] = decision;
        var req = Rmm29Tests.Rig.ReimageReq(targetUser: User2, decision: decision);
        var result = rig.Run(req);
        Assert.Equal(ProvisioningStates.Completed, result.State);
    }

    [Fact]
    public void Attack_CrossUserRestore_DecisionForDifferentPair_Refused()
    {
        var engine = new ProfileMigrationEngine(new DevOnlyPassThroughProtector());
        var (pkg, _) = engine.CaptureAndSeal(Rmm29Tests.Manifest(), Rmm29Tests.FullSource(), T0);
        var wrongPair = new CrossUserRestoreDecision("dec-wrong", User1, "user-3",
            "requester", "approver", T0, "wrong target");
        var (ok, reason, _, _) = engine.Restore(pkg, Dev, User2, wrongPair);
        Assert.False(ok);
        Assert.Contains("does not name this source", reason);
    }

    // ---- profile package tampering --------------------------------------------

    [Fact]
    public void Attack_ProfilePackage_ContentTampered_VerifyRefuses()
    {
        var protector = new DevOnlyPassThroughProtector();
        var engine = new ProfileMigrationEngine(protector);
        var (pkg, _) = engine.CaptureAndSeal(Rmm29Tests.Manifest(), Rmm29Tests.FullSource(), T0);
        Assert.NotNull(pkg);
        // attacker reseals DIFFERENT content under the same manifest
        // (in the current sealed format, binding header included):
        var forgedContent = JsonSerializer.Serialize(new
        {
            sourceDeviceId = Dev, sourceUserId = User1,
            items = new[]
            {
                new { path = "Documents/report.txt", content = Convert.ToBase64String(Encoding.UTF8.GetBytes("FORGED!! numbers!")) },
                new { path = "Settings/app.ini", content = Convert.ToBase64String(Encoding.UTF8.GetBytes("theme=dark")) },
            },
        });
        var forgedBlob = protector.Protect(Convert.ToBase64String(Encoding.UTF8.GetBytes(forgedContent)));
        var tampered = pkg with { SealedContentBase64 = forgedBlob };
        var (ok, reason) = engine.Verify(tampered);
        Assert.False(ok);
        Assert.Contains("hash mismatch", reason);
        var (rok, _, _, _) = engine.Restore(tampered, Dev, User1, null);
        Assert.False(rok);
    }

    [Fact]
    public void Attack_ProfilePackage_ManifestHashOrEntriesTampered_VerifyRefuses()
    {
        var engine = new ProfileMigrationEngine(new DevOnlyPassThroughProtector());
        var (pkg, _) = engine.CaptureAndSeal(Rmm29Tests.Manifest(), Rmm29Tests.FullSource(), T0);
        Assert.NotNull(pkg);
        var (ok1, _) = engine.Verify(pkg with { ManifestHash = Rmm29Tests.H("forged-manifest") });
        Assert.False(ok1);
        var entries = pkg.Entries.Select(e => e with { Sha256 = Rmm29Tests.H("forged-entry") }).ToList();
        var (ok2, _) = engine.Verify(pkg with { Entries = entries });
        Assert.False(ok2);
        // source-binding tamper: rebind the package to another user:
        var (ok3, _) = engine.Verify(pkg with { SourceUserId = User2 });
        Assert.False(ok3);
        // F9 (D38 rmm29): rebind AND recompute the manifest hash so
        // the unkeyed hash agrees with the rebound record — the
        // SEALED binding inside the blob still names the original
        // user, so verification must still refuse:
        var rebound = pkg with
        {
            SourceUserId = User2,
            ManifestHash = ProfilePackage.ComputeManifestHash(pkg.SourceDeviceId, User2, pkg.Entries),
        };
        var (ok4, why4) = engine.Verify(rebound);
        Assert.False(ok4);
        Assert.Contains("sealed source binding", why4);
    }

    [Fact]
    public void Attack_ProfilePackage_DuplicatePathContent_VerifyRefusesNotThrows()
    {
        // D29-02 regression: crafted content holding one path twice
        // (count still matches the manifest) must REFUSE, not throw.
        var protector = new DevOnlyPassThroughProtector();
        var engine = new ProfileMigrationEngine(protector);
        var (pkg, _) = engine.CaptureAndSeal(Rmm29Tests.Manifest(), Rmm29Tests.FullSource(), T0);
        Assert.NotNull(pkg);
        var dupContent = JsonSerializer.Serialize(new
        {
            sourceDeviceId = Dev, sourceUserId = User1,
            items = new[]
            {
                new { path = "Documents/report.txt", content = Convert.ToBase64String(Encoding.UTF8.GetBytes("quarterly numbers")) },
                new { path = "Documents/report.txt", content = Convert.ToBase64String(Encoding.UTF8.GetBytes("quarterly numbers")) },
            },
        });
        var dupBlob = protector.Protect(Convert.ToBase64String(Encoding.UTF8.GetBytes(dupContent)));
        var (ok, reason) = engine.Verify(pkg with { SealedContentBase64 = dupBlob });
        Assert.False(ok);
        Assert.Contains("more than once", reason);
    }

    // ---- resume discipline -------------------------------------------------------

    [Fact]
    public void Attack_ResumeIntoApply_AfterImageRevoked_RevalidatesAndRefuses()
    {
        var rig = NewRig();
        rig.Imaging.ThenFail("winpe exploded");
        var req = Rmm29Tests.Rig.ReimageReq();
        var first = rig.Run(req);
        Assert.Equal(ProvisioningStates.FailedApply, first.State);
        Assert.Equal(1, rig.Imaging.CallCount);
        // the world changes while the run sits failed: image revoked,
        // executor now healthy. A resume must NOT sail into apply on
        // yesterday's validation:
        Assert.True(rig.Images.Revoke("gold", "1.0.0"));
        // Resume state lives on the runner that ran pass 1. The
        // resume must fail at VALIDATE (image now revoked), never
        // reaching apply again:
        var resumed = rig.Runner.ResumeRun(req, rig.EnvelopeFor(req), new JobJournal(), () => true, T0);
        Assert.Equal(ProvisioningStates.FailedValidation, resumed.State);
        Assert.Equal(1, rig.Imaging.CallCount); // apply NOT attempted again
    }

    [Fact]
    public void Attack_Resume_CompletedOrUnknownRun_Refused()
    {
        var rig = NewRig();
        var req = Rmm29Tests.Rig.ReimageReq();
        Assert.Equal(ProvisioningStates.Completed, rig.Run(req).State);
        var again = rig.Runner.ResumeRun(req, rig.EnvelopeFor(req), new JobJournal(), () => true, T0);
        Assert.Equal(ProvisioningStates.Refused, again.State);
        var ghost = Rmm29Tests.Rig.ReimageReq(runId: "run-never-existed");
        var ghostResult = rig.Runner.ResumeRun(ghost, rig.EnvelopeFor(ghost), new JobJournal(), () => true, T0);
        Assert.Equal(ProvisioningStates.Refused, ghostResult.State);
        Assert.Equal(1, rig.Imaging.CallCount);
    }

    [Fact]
    public void Control_Resume_FailedRunWithWorldIntact_CompletesAfterRevalidation()
    {
        var rig = NewRig();
        // enrollment throws on pass 1 (post-apply failure), healthy after:
        var flaky = new FlakyEnrollmentSink();
        var runner = new ProvisioningRunner(rig.Gate, rig.Audit, rig.Profiles, rig.Capture,
            rig.Imaging, flaky, rig.Tokens, rig.Images.Get, rig.Images.IsRevoked,
            d => rig.Accepted.Contains(d), id => null);
        var req = Rmm29Tests.Rig.ReimageReq();
        var first = runner.Run(req, rig.EnvelopeFor(req), new JobJournal(), () => true, T0);
        Assert.Equal(ProvisioningStates.FailedEnroll, first.State);
        flaky.Heal();
        var resumed = runner.ResumeRun(req, rig.EnvelopeFor(req), new JobJournal(), () => true, T0);
        Assert.Equal(ProvisioningStates.Completed, resumed.State);
        Assert.Contains("re-validated", resumed.Reason);
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

    // ---- device that never accepted ------------------------------------------------

    [Fact]
    public void Attack_DeviceNeverAccepted_NeverImaged()
    {
        var rig = new Rmm29Tests.Rig(); // NOTE: no image admitted needed — acceptance is checked first
        rig.Accepted.Clear();
        Assert.Null(rig.Images.Admit(Rmm29Tests.Image()));
        var result = rig.Run(Rmm29Tests.Rig.ReimageReq());
        Assert.Equal(ProvisioningStates.Refused, result.State);
        Assert.Contains("no endpoint-local acceptance", result.Reason);
        Assert.Equal(0, rig.Imaging.CallCount);
        Assert.Equal(0, rig.Capture.CallCount);
    }

    [Fact]
    public void Attack_NoGateWired_RefusesUnsignedWorld()
    {
        var rig = NewRig();
        var runner = new ProvisioningRunner(null, rig.Audit, rig.Profiles, rig.Capture,
            rig.Imaging, rig.Enrollment, rig.Tokens, rig.Images.Get, rig.Images.IsRevoked,
            d => rig.Accepted.Contains(d), id => null);
        var req = Rmm29Tests.Rig.ReimageReq();
        var result = runner.Run(req, null, new JobJournal(), () => true, T0);
        Assert.Equal(ProvisioningStates.Refused, result.State);
        Assert.Equal(0, rig.Imaging.CallCount);
    }
}
