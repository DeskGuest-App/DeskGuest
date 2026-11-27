using System.Text;
using DeskGuest.Core.Services;
using DeskGuest.Shared.Distribution;
using DeskGuest.Shared.Jobs;
using DeskGuest.Shared.Patching;
using DeskGuest.Shared.Security;

namespace DeskGuest.Tests;

// RMM-02 DESTRUCTION PASS — hostile attacks on patch management.
// Attacker models: a compromised hub (holds no customer signing
// key), a malicious catalogue feed, a threshold gamer inside the
// rollout process, a user deferring reboots forever, and an
// attacker with write access to the endpoint's journal file.
// Every test is a permanent regression: if it ever fails, the
// corresponding attack succeeded.
public class Rmm02DestructionTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    private static byte[] Payload => Encoding.UTF8.GetBytes("contoso-app-2.0-payload-bytes");
    private static byte[] EvilPayload => Encoding.UTF8.GetBytes("evil-payload-that-was-never-curated!!");

    private static (ContentManifest Manifest, IReadOnlyList<IContentSource> Sources) SourceFor(byte[] payload)
    {
        var manifest = ContentManifest.Build(payload, 16, "test");
        var store = new PeerContentStore();
        store.PutVerified(manifest, payload);
        return (manifest, new IContentSource[] { new StoreContentSource("hub", store, isHub: true) });
    }

    private static SignedCommandEnvelope EnvFor(Rmm02Tests.Rig rig, PatchCatalogueEntry entry, string deviceId = "dev1") =>
        rig.Signer.Sign(SignedCommandClasses.PatchDeploy,
            Encoding.UTF8.GetBytes(PatchService.DeployPayload(entry.Id, deviceId, entry.ContentHash)),
            T0, TimeSpan.FromHours(2));

    private static Rmm02Tests.Rig RigWithApprovedEntry(out PatchCatalogueEntry entry)
    {
        var rig = Rmm02Tests.NewRig();
        entry = Rmm02Tests.ThirdParty();
        rig.Service.AdmitEntries(new[] { entry }, "attack setup");
        rig.Service.Decide(Rmm02Tests.Facts(), entry.Id, "*", approve: true, decidedBy: "admin-1");
        return rig;
    }

    // ---- unapproved deployment ------------------------------------

    [Fact]
    public void ATTACK_UnapprovedPatch_NeverDeploys_NoJobNoApply()
    {
        var rig = Rmm02Tests.NewRig();
        var entry = Rmm02Tests.ThirdParty();
        rig.Service.AdmitEntries(new[] { entry }, "attack setup");
        // NO approval of any kind; policy is manual-only by default.
        var (manifest, sources) = SourceFor(Payload);
        var applier = new Rmm02Tests.FakeApplier();
        // Even with a perfectly signed envelope, approval gates first-class:
        var result = rig.Service.Deploy(Rmm02Tests.Facts(), entry.Id, EnvFor(rig, entry), manifest, sources, applier, "/tmp/p.bin");
        Assert.False(result.Ok);
        Assert.Contains("NEVER deploys", result.Reason);
        Assert.Equal(0, applier.Calls);
        Assert.Empty(rig.Service.Journal.ListJobs());
    }

    [Fact]
    public void ATTACK_RejectedPatch_NeverDeploys_EvenWithSignedEnvelope()
    {
        var rig = Rmm02Tests.NewRig();
        var entry = Rmm02Tests.ThirdParty();
        rig.Service.AdmitEntries(new[] { entry }, "attack setup");
        rig.Service.Decide(Rmm02Tests.Facts(), entry.Id, "*", approve: false, decidedBy: "admin-1");
        var (manifest, sources) = SourceFor(Payload);
        var applier = new Rmm02Tests.FakeApplier();
        var result = rig.Service.Deploy(Rmm02Tests.Facts(), entry.Id, EnvFor(rig, entry), manifest, sources, applier, "/tmp/p.bin");
        Assert.False(result.Ok);
        Assert.Contains("REJECTED", result.Reason);
        Assert.Equal(0, applier.Calls);
    }

    [Fact]
    public void ATTACK_UnsignedOrForgedDeploy_Refused()
    {
        var rig = RigWithApprovedEntry(out var entry);
        var (manifest, sources) = SourceFor(Payload);
        // no envelope at all:
        Assert.False(rig.Service.Deploy(Rmm02Tests.Facts(), entry.Id, null, manifest, sources,
            new Rmm02Tests.FakeApplier(), "/tmp/p.bin").Ok);
        // envelope forged by an attacker key (the compromised hub's own):
        var attacker = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var forged = new SignedCommandSigner(attacker).Sign(SignedCommandClasses.PatchDeploy,
            Encoding.UTF8.GetBytes(PatchService.DeployPayload(entry.Id, "dev1", entry.ContentHash)),
            T0, TimeSpan.FromHours(1));
        var result = rig.Service.Deploy(Rmm02Tests.Facts(), entry.Id, forged, manifest, sources,
            new Rmm02Tests.FakeApplier(), "/tmp/p.bin");
        Assert.False(result.Ok);
        Assert.Empty(rig.Service.Journal.ListJobs());
    }

    [Fact]
    public void ATTACK_EnvelopeMintedForAnotherPatchOrDevice_Refused()
    {
        var rig = RigWithApprovedEntry(out var entry);
        var (manifest, sources) = SourceFor(Payload);
        // genuine customer signature, but the payload binds a DIFFERENT device:
        var wrongDevice = rig.Signer.Sign(SignedCommandClasses.PatchDeploy,
            Encoding.UTF8.GetBytes(PatchService.DeployPayload(entry.Id, "dev-other", entry.ContentHash)),
            T0, TimeSpan.FromHours(1));
        Assert.False(rig.Service.Deploy(Rmm02Tests.Facts(), entry.Id, wrongDevice, manifest, sources,
            new Rmm02Tests.FakeApplier(), "/tmp/p.bin").Ok);
        // genuine signature, binds a different patch id:
        var wrongPatch = rig.Signer.Sign(SignedCommandClasses.PatchDeploy,
            Encoding.UTF8.GetBytes(PatchService.DeployPayload("KB9999999", "dev1", entry.ContentHash)),
            T0, TimeSpan.FromHours(1));
        var result = rig.Service.Deploy(Rmm02Tests.Facts(), entry.Id, wrongPatch, manifest, sources,
            new Rmm02Tests.FakeApplier(), "/tmp/p.bin");
        Assert.False(result.Ok);
        Assert.Contains("does not bind THIS patch", result.Reason);
        Assert.Empty(rig.Service.Journal.ListJobs());
    }

    [Fact]
    public void ATTACK_DeployWithNoGateWired_Refuses()
    {
        var rig = Rmm02Tests.NewRig(withGate: false);
        var entry = Rmm02Tests.ThirdParty();
        rig.Service.AdmitEntries(new[] { entry }, "attack setup");
        rig.Service.Decide(Rmm02Tests.Facts(), entry.Id, "*", approve: true, decidedBy: "admin-1");
        var (manifest, sources) = SourceFor(Payload);
        // The envelope is genuine — but this endpoint has no gate,
        // so nothing can be verified, so nothing deploys.
        var env = new SignedCommandSigner(rig.Customer).Sign(SignedCommandClasses.PatchDeploy,
            Encoding.UTF8.GetBytes(PatchService.DeployPayload(entry.Id, "dev1", entry.ContentHash)),
            T0, TimeSpan.FromHours(1));
        var result = rig.Service.Deploy(Rmm02Tests.Facts(), entry.Id, env, manifest, sources,
            new Rmm02Tests.FakeApplier(), "/tmp/p.bin");
        Assert.False(result.Ok);
        Assert.Contains("RMM-03", result.Reason);
    }

    // ---- catalogue poisoning ---------------------------------------

    [Fact]
    public void ATTACK_PayloadHashMismatch_RefusedBeforeDistribution()
    {
        var rig = RigWithApprovedEntry(out var entry);
        // The payload on offer is NOT the payload the admin pinned:
        var (evilManifest, evilSources) = SourceFor(EvilPayload);
        var applier = new Rmm02Tests.FakeApplier();
        var result = rig.Service.Deploy(Rmm02Tests.Facts(), entry.Id, EnvFor(rig, entry), evilManifest, evilSources, applier, "/tmp/p.bin");
        Assert.False(result.Ok);
        Assert.Contains("payload hash mismatch", result.Reason);
        Assert.Equal(0, applier.Calls);
        Assert.Empty(rig.Service.Journal.ListJobs()); // refused BEFORE any job/distribution
        Assert.False(rig.Service.ContentStore.Has(evilManifest.ContentHash));
    }

    [Fact]
    public void ATTACK_CatalogueEntrySwappedAfterApproval_ApprovalDiesWithOldContent()
    {
        var rig = RigWithApprovedEntry(out var entry);
        // The admin (or a poisoned feed) swaps the payload pin under
        // the SAME entry id at a new revision, after approval:
        var swapped = Rmm02Tests.ThirdParty(revision: 2, payloadHash: ContentManifest.HashOf(EvilPayload));
        Assert.True(rig.Service.Catalogue.AddOrReplace(swapped).Accepted);
        var check = rig.Service.Approvals.CheckCurrent(swapped, "dev1");
        Assert.False(check.Approved);
        Assert.Contains("DIFFERENT content", check.Reason);
        // Deploying the swapped content with the evil payload and a
        // fresh envelope binding the NEW hash still refuses — the
        // approval never transferred:
        var (evilManifest, evilSources) = SourceFor(EvilPayload);
        var result = rig.Service.Deploy(Rmm02Tests.Facts(), entry.Id, EnvFor(rig, swapped), evilManifest, evilSources,
            new Rmm02Tests.FakeApplier(), "/tmp/p.bin");
        Assert.False(result.Ok);
        Assert.Empty(rig.Service.Journal.ListJobs());
    }

    [Fact]
    public void ATTACK_CveRemapAfterApproval_AlsoKillsTheApproval()
    {
        var rig = RigWithApprovedEntry(out var entry);
        // A "harmless metadata edit" — CVE list changed — is a
        // content change: approvals bind content, all of it.
        var remapped = Rmm02Tests.ThirdParty(revision: 2) with { CveIds = new[] { "CVE-2024-55555" } };
        Assert.True(rig.Service.Catalogue.AddOrReplace(remapped).Accepted);
        Assert.False(rig.Service.Approvals.CheckCurrent(remapped, "dev1").Approved);
        // and malformed CVE content never enters the catalogue at all:
        Assert.False(rig.Service.Catalogue.AddOrReplace(
            Rmm02Tests.ThirdParty(revision: 3) with { CveIds = new[] { "not-a-cve" } }).Accepted);
    }

    [Fact]
    public void ATTACK_UnpinnedPayloadForOsChannelEntry_Refused()
    {
        var rig = Rmm02Tests.NewRig();
        var kb = Rmm02Tests.OsKb();
        rig.Service.AdmitEntries(new[] { kb }, "attack setup");
        rig.Service.Decide(Rmm02Tests.Facts(), kb.Id, "*", approve: true, decidedBy: "admin-1");
        // An OS-channel entry pins no payload — so ANY payload
        // presented for it is unpinned by definition and refuses:
        var (manifest, sources) = SourceFor(Payload);
        var env = rig.Signer.Sign(SignedCommandClasses.PatchDeploy,
            Encoding.UTF8.GetBytes(PatchService.DeployPayload(kb.Id, "dev1", kb.ContentHash)), T0, TimeSpan.FromHours(1));
        var result = rig.Service.Deploy(Rmm02Tests.Facts(), kb.Id, env, manifest, sources,
            new Rmm02Tests.FakeApplier(), "/tmp/kb.msu");
        Assert.False(result.Ok);
        Assert.Contains("unpinned", result.Reason);
    }

    // ---- ring gaming -------------------------------------------------

    [Fact]
    public void ATTACK_DoubleCountedSuccess_Refused()
    {
        var plan = new RolloutPlan("g1", "Contoso.App", Rmm02Tests.ThirdParty().ContentHash, new[]
        {
            new RingDefinition("test", 0, 0.5, new[] { "dev1", "dev2" }),
        });
        plan.StartRing("test");
        Assert.True(plan.RecordOutcome("test", "dev1", true, T0).Ok);
        // the same device "succeeding" again must not move the numbers:
        var again = plan.RecordOutcome("test", "dev1", true, T0);
        Assert.False(again.Ok);
        Assert.Equal(1, plan.StatusOf("test").Succeeded);
    }

    [Fact]
    public void ATTACK_FailureHiddenByLaterSuccess_Refused()
    {
        var plan = new RolloutPlan("g2", "Contoso.App", Rmm02Tests.ThirdParty().ContentHash, new[]
        {
            new RingDefinition("test", 0, 0.5, new[] { "dev1", "dev2" }),
        });
        plan.StartRing("test");
        Assert.True(plan.RecordOutcome("test", "dev1", false, T0).Ok);
        var overwrite = plan.RecordOutcome("test", "dev1", true, T0);
        Assert.False(overwrite.Ok);
        Assert.Equal(1, plan.StatusOf("test").Failed);
        Assert.Equal(0, plan.StatusOf("test").Succeeded);
        // a non-member cannot inject an outcome either:
        Assert.False(plan.RecordOutcome("test", "stranger-device", true, T0).Ok);
    }

    [Fact]
    public void ATTACK_HaltedRing_DeployGateAndUnsignedResume_Refused()
    {
        var rig = Rmm02Tests.NewRig();
        var entry = Rmm02Tests.ThirdParty();
        rig.Service.AdmitEntries(new[] { entry }, "attack setup");
        rig.Service.Decide(Rmm02Tests.Facts(), entry.Id, "*", approve: true, decidedBy: "admin-1");
        var plan = new RolloutPlan("g3", entry.Id, entry.ContentHash, new[]
        {
            new RingDefinition("test", 0, 0.75, new[] { "dev1", "b", "c", "d" }),
        });
        rig.Service.Rollouts.Add(plan);
        plan.StartRing("test");
        plan.RecordOutcome("test", "b", false, T0);
        plan.RecordOutcome("test", "c", false, T0);
        Assert.Equal(RingStates.Halted, plan.StatusOf("test").State);
        // deployment to a halted ring's device refuses at the ring gate:
        var (manifest, sources) = SourceFor(Payload);
        var gated = rig.Service.Deploy(Rmm02Tests.Facts(), entry.Id, EnvFor(rig, entry), manifest, sources,
            new Rmm02Tests.FakeApplier(), "/tmp/p.bin");
        Assert.False(gated.Ok);
        Assert.Contains("halted", gated.Reason);
        // unsigned resume refuses:
        Assert.False(rig.Service.ResumeRing("g3", "test", null, "admin-1").Ok);
        // a resume envelope binding the WRONG evidence refuses:
        var wrongEvidence = rig.Signer.Sign(SignedCommandClasses.PatchDeploy,
            Encoding.UTF8.GetBytes("ring_resume|g3|test|deadbeef"), T0, TimeSpan.FromHours(1));
        Assert.False(rig.Service.ResumeRing("g3", "test", wrongEvidence, "admin-1").Ok);
        Assert.Equal(RingStates.Halted, plan.StatusOf("test").State);
    }

    [Fact]
    public void ATTACK_ResumeDecisionReplayedAgainstSecondHalt_Refused()
    {
        var plan = new RolloutPlan("g4", "Contoso.App", Rmm02Tests.ThirdParty().ContentHash, new[]
        {
            new RingDefinition("pilot", 0, 0.75, new[] { "a", "b", "c", "d" }),
        });
        plan.StartRing("pilot");
        plan.RecordOutcome("pilot", "a", false, T0);
        plan.RecordOutcome("pilot", "b", false, T0);
        var halt1 = plan.StatusOf("pilot").HaltEvidence!;
        var decision1 = new ApprovalDecisionRecord(plan.EntryId, plan.EntryContentHash, "ring:g4:pilot",
            ApprovalDecisions.Approved, "admin-1", T0, $"ring_resume:g4:pilot:{halt1.EvidenceHash}");
        Assert.True(plan.ResumeHalted("pilot", decision1).Ok);
        // the ring halts AGAIN, on different evidence (a third failure):
        plan.RecordOutcome("pilot", "c", false, T0.AddMinutes(30));
        var halted2 = plan.StatusOf("pilot");
        Assert.Equal(RingStates.Halted, halted2.State);
        Assert.NotEqual(halt1.EvidenceHash, halted2.HaltEvidence!.EvidenceHash);
        // replaying the FIRST halt's decision against the second halt refuses:
        var replay = plan.ResumeHalted("pilot", decision1);
        Assert.False(replay.Ok);
        Assert.Contains("does not bind THIS halt", replay.Reason);
    }

    // ---- reboot abuse --------------------------------------------------

    [Fact]
    public void ATTACK_DeferForever_RefusedAtTheLimit()
    {
        var rig = Rmm02Tests.NewRig();
        rig.Service.RebootPolicy = Shared.Patching.RebootPolicy.Default with { MaxDeferrals = 1 };
        rig.Service.AdmitEntries(new[] { Rmm02Tests.OsKb() }, "attack setup");
        Assert.True(rig.Service.RecordDeferral("KB5034441", "dev1").Ok);
        for (var i = 0; i < 5; i++)
            Assert.False(rig.Service.RecordDeferral("KB5034441", "dev1").Ok);
        Assert.Equal(1, rig.Service.DeferralCount("KB5034441", "dev1"));
    }

    [Fact]
    public void ATTACK_ForcedRebootOutsideWindow_NonCritical_Refused()
    {
        var policy = Shared.Patching.RebootPolicy.Default;
        var entry = Rmm02Tests.ThirdParty() with { RequiresReboot = true, Severity = "high" }; // not critical
        var mondayNoon = new DateTimeOffset(2026, 11, 23, 12, 0, 0, TimeSpan.Zero);
        // even with deferrals exhausted and a year elapsed, a
        // NON-critical patch never enforces outside its window:
        var decision = Shared.Patching.RebootGate.Evaluate(entry, policy, mondayNoon.AddDays(-365), 99, mondayNoon);
        Assert.False(decision.RebootPermittedNow); // enforcement may be DUE, but it fires at the window — never outside it for a non-critical patch
    }

    // ---- offline-queue forgery -------------------------------------------

    [Fact]
    public void ATTACK_TamperedJournalFile_FailsClosed_OnRestart()
    {
        var rig = Rmm02Tests.NewRig();
        var entry = Rmm02Tests.ThirdParty();
        var journal = new JobJournal(rig.Endpoint);
        var env = rig.Signer.Sign(SignedCommandClasses.PatchDeploy,
            Encoding.UTF8.GetBytes(PatchService.DeployPayload(entry.Id, "dev1", entry.ContentHash)), T0, TimeSpan.FromHours(2));
        var job = journal.CreateJob(JobKinds.PatchRun, "dev1", PatchRunSteps.For(entry), env, T0)!;
        journal.StartJob(job.Id, T0);
        journal.BeginStep(job.Id, PatchRunSteps.Fetch, T0);
        journal.SaveToFile(rig.Service.JournalPath);
        // the attacker edits the persisted journal: fetch "completes" itself:
        var raw = File.ReadAllText(rig.Service.JournalPath);
        var tampered = raw.Replace("step_started", "step_completed");
        Assert.NotEqual(raw, tampered);
        File.WriteAllText(rig.Service.JournalPath, tampered);
        // restart: the chain (and endpoint signatures) expose it;
        // the job fails journal_tampered and NOTHING resumes:
        var report = rig.Service.Start(Rmm02Tests.Facts());
        Assert.False(report.ChainOk);
        var state = rig.Service.BuildStateReport(Rmm02Tests.Facts());
        var summary = Assert.Single(state.Jobs);
        Assert.Equal(JobStates.Failed, summary.State);
        Assert.Equal(JobFailureReasons.JournalTampered, summary.FailureReason);
    }

    [Fact]
    public void ATTACK_ApplierFailure_FailsTheRun_AndRecordsRingFailure()
    {
        var rig = Rmm02Tests.NewRig();
        var entry = Rmm02Tests.ThirdParty();
        rig.Service.AdmitEntries(new[] { entry }, "attack setup");
        rig.Service.Decide(Rmm02Tests.Facts(), entry.Id, "*", approve: true, decidedBy: "admin-1");
        var plan = new RolloutPlan("g5", entry.Id, entry.ContentHash, new[]
        {
            new RingDefinition("test", 0, 1.0, new[] { "dev1", "dev2" }),
        });
        rig.Service.Rollouts.Add(plan);
        plan.StartRing("test");
        var (manifest, sources) = SourceFor(Payload);
        var failing = new Rmm02Tests.FakeApplier { Fail = true };
        var result = rig.Service.Deploy(Rmm02Tests.Facts(), entry.Id, EnvFor(rig, entry), manifest, sources, failing, "/tmp/p.bin");
        Assert.False(result.Ok);
        var job = rig.Service.Journal.GetJob(result.JobId!)!;
        Assert.Equal(JobStates.Failed, job.State);
        Assert.Contains("step_failed:apply_patch", job.FailureReason);
        // the failure is VISIBLE in the ring (1 failure of 2 at a
        // 100% threshold halts the ring — it cannot be laundered):
        var status = plan.StatusOf("test");
        Assert.Equal(1, status.Failed);
        Assert.Equal(RingStates.Halted, status.State);
    }
}
