using System.Text;
using Acp.Core.Services;
using Acp.Shared.Distribution;
using Acp.Shared.Enterprise;
using Acp.Shared.Jobs;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Patching;
using Acp.Shared.Security;

namespace Acp.Tests;

// RMM-02 D38 FIX LANE — regression tests for packet
// 11e17009-5d16-49ba-a714-d48e940d6683 (12 findings). Every test
// here pins a CONFIRMED break: it fails against the pre-fix code
// and passes against the fixed code. Attacker models and claim
// mapping live in builds/rmm-r-logs/ledger-rmm02-fix.md.
public class Rmm02D38FixTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    private static byte[] Payload => Encoding.UTF8.GetBytes("contoso-app-2.0-payload-bytes");
    private static string PayloadHash => ContentManifest.HashOf(Payload);

    private static (ContentManifest Manifest, IReadOnlyList<IContentSource> Sources) HubSource(byte[] payload)
    {
        var manifest = ContentManifest.Build(payload, 16, "test");
        var store = new PeerContentStore();
        Assert.True(store.PutVerified(manifest, payload));
        return (manifest, new IContentSource[] { new StoreContentSource("hub", store, isHub: true) });
    }

    private static SignedCommandEnvelope DeployEnv(Rmm02Tests.Rig rig, PatchCatalogueEntry entry, string deviceId = "dev1") =>
        rig.Signer.Sign(SignedCommandClasses.PatchDeploy,
            Encoding.UTF8.GetBytes(PatchService.DeployPayload(entry.Id, deviceId, entry.ContentHash)),
            T0, TimeSpan.FromHours(2));

    /// <summary>A second PatchService over the SAME data dir — the
    /// honest restart simulation (new object graph, only files
    /// survive).</summary>
    private static PatchService Restarted(Rmm02Tests.Rig rig, Func<DateTimeOffset>? now = null)
    {
        var gate = new SignedCommandGate(new SignedCommandVerifier(rig.Ring), rig.Audit);
        return new PatchService(rig.DataDir, rig.Audit, rig.Policies, gate, rig.Endpoint, rig.Ring,
            now: now ?? (() => T0));
    }

    private sealed class InspectingApplier : IPatchApplier
    {
        public string? SeenPayloadPath;
        public bool WalHadApplyStepStarted;
        public string? JournalPath;
        public string OsKind => "windows";
        public bool CanApply(PatchCatalogueEntry entry) => true;
        public PatchApplyResult BuildApply(PatchApplyRequest request)
        {
            SeenPayloadPath = request.PayloadPath;
            if (JournalPath is not null && File.Exists(JournalPath + ".wal"))
                WalHadApplyStepStarted = File.ReadAllText(JournalPath + ".wal").Contains("step=apply_patch");
            return new PatchApplyResult(true, "inspecting applier plan built",
                new PatchCommandPlan(OsKind, "fake.exe", new[] { request.Entry.Id }, "install"),
                new PatchCommandPlan(OsKind, "fake.exe", new[] { "verify", request.Entry.Id }, "verify"));
        }
    }

    private sealed class ThrowingApplier : IPatchApplier
    {
        public string OsKind => "windows";
        public bool CanApply(PatchCatalogueEntry entry) => true;
        public PatchApplyResult BuildApply(PatchApplyRequest request) =>
            throw new InvalidOperationException("simulated process death mid-apply");
    }

    private static Rmm02Tests.Rig RigWithApproved(out PatchCatalogueEntry entry)
    {
        var rig = Rmm02Tests.NewRig();
        entry = Rmm02Tests.ThirdParty();
        rig.Service.AdmitEntries(new[] { entry }, "d38-fix setup");
        rig.Service.Decide(Rmm02Tests.Facts(), entry.Id, "*", approve: true, decidedBy: "admin-1");
        return rig;
    }

    // ---- F1: journal durability before the non-idempotent step ------

    [Fact]
    public void D38F1_ApplyStepStarted_IsOnDisk_BeforeTheApplierRuns()
    {
        var rig = RigWithApproved(out var entry);
        var (manifest, sources) = HubSource(Payload);
        var applier = new InspectingApplier { JournalPath = rig.Service.JournalPath };
        var result = rig.Service.Deploy(Rmm02Tests.Facts(), entry.Id, DeployEnv(rig, entry), manifest, sources, applier, "/tmp/p.bin");
        Assert.True(result.Ok, result.Reason);
        // At the instant the applier was invoked, the write-ahead
        // journal ALREADY carried step_started for apply_patch —
        // a crash inside BuildApply leaves a journal that parks.
        Assert.True(applier.WalHadApplyStepStarted);
        Assert.Null(rig.Service.Journal.PersistenceError);
    }

    [Fact]
    public void D38F1_CrashMidApply_RestartParksTheJob_NeverInvisible()
    {
        var rig = RigWithApproved(out var entry);
        var (manifest, sources) = HubSource(Payload);
        // The applier dies mid-apply (the process-death shape):
        Assert.Throws<InvalidOperationException>(() =>
            rig.Service.Deploy(Rmm02Tests.Facts(), entry.Id, DeployEnv(rig, entry), manifest, sources, new ThrowingApplier(), "/tmp/p.bin"));
        // Restart over the same data dir: the job EXISTS on disk,
        // mid-apply, and the resume pass parks it for a human.
        var svc2 = Restarted(rig);
        var report = svc2.Start(Rmm02Tests.Facts());
        Assert.True(report.ChainOk);
        var state = svc2.BuildStateReport(Rmm02Tests.Facts());
        var summary = Assert.Single(state.Jobs);
        Assert.Equal(JobStates.Parked, summary.State);
        Assert.Equal(JobFailureReasons.NonIdempotentUncertain, summary.FailureReason);
    }

    // ---- F2: verified bytes are the applied bytes ---------------------

    [Fact]
    public void D38F2_ApplierReceivesVerifiedBytes_NeverTheCallerPath()
    {
        var rig = RigWithApproved(out var entry);
        var (manifest, sources) = HubSource(Payload);
        // The caller points payloadPath at attacker bytes:
        var evilPath = Path.Combine(TestUtil.TempDir(), "evil.bin");
        File.WriteAllBytes(evilPath, Encoding.UTF8.GetBytes("evil-bytes-the-caller-chose"));
        var applier = new InspectingApplier();
        var result = rig.Service.Deploy(Rmm02Tests.Facts(), entry.Id, DeployEnv(rig, entry), manifest, sources, applier, evilPath);
        Assert.True(result.Ok, result.Reason);
        Assert.NotEqual(evilPath, applier.SeenPayloadPath);
        Assert.Contains("patch-payloads", applier.SeenPayloadPath);
        Assert.Equal(Payload, File.ReadAllBytes(applier.SeenPayloadPath!));
    }

    // ---- F3: state survives restart -----------------------------------

    [Fact]
    public void D38F3_Restart_StandingReject_HaltedRing_Deferrals_AllSurvive()
    {
        var rig = Rmm02Tests.NewRig();
        var entry = Rmm02Tests.ThirdParty();
        var kb = Rmm02Tests.OsKb();
        rig.Service.AdmitEntries(new[] { entry, kb }, "d38-fix setup");
        // a standing fleet REJECT for the third-party entry:
        Assert.True(rig.Service.Decide(Rmm02Tests.Facts(), entry.Id, "*", approve: false, decidedBy: "admin-1").Ok);
        // a halted ring for the KB entry:
        var plan = new RolloutPlan("plan-f3", kb.Id, kb.ContentHash, new[]
        {
            new RingDefinition("pilot", 0, 0.75, new[] { "a", "b", "c", "d" }),
        });
        Assert.True(rig.Service.RegisterPlan(plan).Ok);
        plan.StartRing("pilot");
        plan.RecordOutcome("pilot", "a", false, T0);
        plan.RecordOutcome("pilot", "b", false, T0);
        Assert.Equal(RingStates.Halted, plan.StatusOf("pilot").State);
        Assert.True(rig.Service.CheckpointState());
        // a deferral against the KB:
        Assert.True(rig.Service.RecordDeferral(kb.Id, "dev1").Ok);

        // RESTART — everything above must still be true:
        var svc2 = Restarted(rig);
        Assert.NotNull(svc2.Catalogue.Get(entry.Id));
        var check = svc2.Approvals.CheckCurrent(svc2.Catalogue.Get(entry.Id)!, "dev1");
        Assert.False(check.Approved);
        Assert.Contains("REJECTED", check.Reason);
        var restored = svc2.Rollouts.Get("plan-f3");
        Assert.NotNull(restored);
        var status = restored!.StatusOf("pilot");
        Assert.Equal(RingStates.Halted, status.State);
        Assert.NotNull(status.HaltEvidence);
        Assert.Equal(2, status.Failed);
        Assert.Equal(1, svc2.DeferralCount(kb.Id, "dev1"));
    }

    [Fact]
    public void D38F3_CorruptStateFile_DeployAndDecisionsRefuse_NamedBroken()
    {
        var dir = TestUtil.TempDir();
        File.WriteAllText(Path.Combine(dir, "patch-state.json"), "{ this is not patch state");
        var rig = Rmm02Tests.NewRig();
        var svc = new PatchService(dir, rig.Audit, rig.Policies, null, rig.Endpoint, rig.Ring, now: () => T0);
        Assert.Contains("BROKEN", svc.StateStoreState);
        var entry = Rmm02Tests.ThirdParty();
        var deploy = svc.Deploy(Rmm02Tests.Facts(), entry.Id, null, null,
            Array.Empty<IContentSource>(), new Rmm02Tests.FakeApplier(), "/tmp/p.bin");
        Assert.False(deploy.Ok);
        Assert.Contains("BROKEN", deploy.Reason);
        Assert.False(svc.AdmitEntries(new[] { entry }, "test").Ok);
    }

    // ---- F4: a halt survives a content revision ------------------------

    [Fact]
    public void D38F4_HaltedRing_BlocksRevisedContent_ForHaltedDevicesOnly()
    {
        var rig = Rmm02Tests.NewRig();
        var r1 = Rmm02Tests.ThirdParty();
        rig.Service.AdmitEntries(new[] { r1 }, "d38-fix setup");
        rig.Service.Decide(Rmm02Tests.Facts(), r1.Id, "*", approve: true, decidedBy: "admin-1");
        var plan = new RolloutPlan("plan-f4", r1.Id, r1.ContentHash, new[]
        {
            new RingDefinition("pilot", 0, 0.75, new[] { "dev1", "b", "c", "d" }),
        });
        rig.Service.Rollouts.Add(plan);
        plan.StartRing("pilot");
        plan.RecordOutcome("pilot", "b", false, T0);
        plan.RecordOutcome("pilot", "c", false, T0);
        Assert.Equal(RingStates.Halted, plan.StatusOf("pilot").State);

        // The admin admits r2 (cosmetic title edit ⇒ new hash) and
        // approves it. The halted cohort must STILL not deploy:
        var r2 = Rmm02Tests.ThirdParty(revision: 2) with { Title = "Contoso App 2.0 (cosmetic relabel)" };
        Assert.True(rig.Service.AdmitEntries(new[] { r2 }, "d38-fix setup").Ok);
        Assert.True(rig.Service.Decide(Rmm02Tests.Facts(), r2.Id, "*", approve: true, decidedBy: "admin-1").Ok);
        var (manifest, sources) = HubSource(Payload);
        var gated = rig.Service.Deploy(Rmm02Tests.Facts(), r2.Id, DeployEnv(rig, r2), manifest, sources,
            new Rmm02Tests.FakeApplier(), "/tmp/p.bin");
        Assert.False(gated.Ok);
        Assert.Contains("earlier content revision", gated.Reason);
        // A device OUTSIDE the halted cohort is not gated by it:
        var outsider = rig.Service.Deploy(Rmm02Tests.Facts("dev9"), r2.Id, DeployEnv(rig, r2, "dev9"), manifest, sources,
            new Rmm02Tests.FakeApplier(), "/tmp/p.bin");
        Assert.True(outsider.Ok, outsider.Reason);
    }

    // ---- F5: plan construction is not ring success ----------------------

    [Fact]
    public void D38F5_DeployRecordsNoRingSuccess_InstallFailureHaltsViaConfirmInstall()
    {
        var rig = RigWithApproved(out var entry);
        var plan = new RolloutPlan("plan-f5", entry.Id, entry.ContentHash, new[]
        {
            new RingDefinition("test", 0, 1.0, new[] { "dev1" }),
        });
        rig.Service.Rollouts.Add(plan);
        plan.StartRing("test");
        var (manifest, sources) = HubSource(Payload);
        var result = rig.Service.Deploy(Rmm02Tests.Facts(), entry.Id, DeployEnv(rig, entry), manifest, sources,
            new Rmm02Tests.FakeApplier(), "/tmp/p.bin");
        Assert.True(result.Ok, result.Reason);
        // The deploy built plans — the ring has seen NOTHING:
        var after = plan.StatusOf("test");
        Assert.Equal(RingStates.InProgress, after.State);
        Assert.Equal(0, after.Succeeded);
        Assert.Equal(0, after.Failed);
        // Install evidence arrives — and it is a FAILURE:
        var confirmed = rig.Service.ConfirmInstall(entry.Id, "dev1", verified: false, evidence: "test: installer exit 1603");
        Assert.True(confirmed.Ok, confirmed.Reason);
        var status = plan.StatusOf("test");
        Assert.Equal(1, status.Failed);
        Assert.Equal(RingStates.Halted, status.State); // 0% < 100% threshold, unreachable
    }

    // ---- F6: deploy never manufactures an approval -----------------------

    [Fact]
    public void D38F6_SwappedContent_DeployDoesNotAutoApprove_ExplicitEvaluationDoes()
    {
        var rig = Rmm02Tests.NewRig();
        rig.Service.ApprovalPolicy = new ApprovalPolicy(new[]
        {
            new ApprovalRule("auto-security", ApprovalMode.AutoApprove, Classification: "security"),
        });
        var r1 = Rmm02Tests.ThirdParty();
        rig.Service.AdmitEntries(new[] { r1 }, "d38-fix setup");
        // Deliberate evaluation approves r1; r1 deploys:
        Assert.Equal(ApprovalMode.AutoApprove, rig.Service.AutoEvaluate(Rmm02Tests.Facts(), r1.Id, "dev1").Mode);
        var (manifest, sources) = HubSource(Payload);
        Assert.True(rig.Service.Deploy(Rmm02Tests.Facts(), r1.Id, DeployEnv(rig, r1), manifest, sources,
            new Rmm02Tests.FakeApplier(), "/tmp/p.bin").Ok);

        // Content is swapped at r2 (payload pin changed). A deploy
        // attempt must NOT launder it through the auto rule:
        var evil = Encoding.UTF8.GetBytes("evil-payload-that-was-never-curated!!");
        var r2 = Rmm02Tests.ThirdParty(revision: 2, payloadHash: ContentManifest.HashOf(evil));
        Assert.True(rig.Service.AdmitEntries(new[] { r2 }, "d38-fix setup").Ok);
        var (evilManifest, evilSources) = HubSource(evil);
        var applier = new Rmm02Tests.FakeApplier();
        var refused = rig.Service.Deploy(Rmm02Tests.Facts(), r2.Id, DeployEnv(rig, r2), evilManifest, evilSources, applier, "/tmp/p.bin");
        Assert.False(refused.Ok);
        Assert.Equal(0, applier.Calls);
        Assert.DoesNotContain(rig.Service.Approvals.Records, r => r.EntryContentHash == r2.ContentHash);
        // The deliberate act still works — evaluation is an
        // operator/policy decision, recorded and audited:
        Assert.Equal(ApprovalMode.AutoApprove, rig.Service.AutoEvaluate(Rmm02Tests.Facts(), r2.Id, "dev1").Mode);
        Assert.Contains(rig.Service.Approvals.Records, r => r.EntryContentHash == r2.ContentHash);
    }

    // ---- F7: revocation --------------------------------------------------

    [Fact]
    public void D38F7_FleetApproval_RevokedBySupersedingFleetReject()
    {
        var rig = RigWithApproved(out var entry);
        Assert.True(rig.Service.Approvals.CheckCurrent(entry, "dev1").Approved);
        // A plain contradicting decision still refuses (history is
        // not silently rewritten):
        var plain = rig.Service.Decide(Rmm02Tests.Facts(), entry.Id, "*", approve: false, decidedBy: "admin-1");
        Assert.False(plain.Ok);
        Assert.True(rig.Service.Approvals.CheckCurrent(entry, "dev1").Approved);
        // The explicit supersede IS the revocation:
        var revoked = rig.Service.Decide(Rmm02Tests.Facts(), entry.Id, "*", approve: false, decidedBy: "admin-1", supersede: true);
        Assert.True(revoked.Ok, revoked.Reason);
        var check = rig.Service.Approvals.CheckCurrent(entry, "dev1");
        Assert.False(check.Approved);
        Assert.Contains("REJECTED", check.Reason);
        // …and deployment now refuses for the SAME content:
        var (manifest, sources) = HubSource(Payload);
        var deploy = rig.Service.Deploy(Rmm02Tests.Facts(), entry.Id, DeployEnv(rig, entry), manifest, sources,
            new Rmm02Tests.FakeApplier(), "/tmp/p.bin");
        Assert.False(deploy.Ok);
        // Both decisions remain in the record (append-only):
        Assert.Equal(2, rig.Service.Approvals.Records.Count(r => r.EntryId == entry.Id));
    }

    // ---- F9: nonce store durability ---------------------------------------

    private static (DeviceIdentity Customer, SignedCommandSigner Signer, CustomerCommandKeyRing Ring) NonceRig()
    {
        var customer = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var ring = new CustomerCommandKeyRing();
        ring.AddCurrent(customer.PublicKey);
        return (customer, new SignedCommandSigner(customer), ring);
    }

    [Fact]
    public void D38F9_DeletedNonceStore_IsStoreLost_NeverFresh()
    {
        var (_, signer, _) = NonceRig();
        var path = Path.Combine(TestUtil.TempDir(), "nonces.json");
        var store = new PersistedNonceStore(path);
        var env = signer.Sign(SignedCommandClasses.ShellExec, Encoding.UTF8.GetBytes("echo once"), T0, TimeSpan.FromMinutes(30));
        Assert.True(store.TryRegister(env, T0.AddMinutes(1)));
        Assert.True(File.Exists(path + ".anchor")); // the anchor is written with the store
        File.Delete(path); // deletion — simpler than wholesale replacement
        var reloaded = new PersistedNonceStore(path);
        Assert.True(reloaded.IsBroken);
        Assert.Contains("store_lost", reloaded.State);
        var env2 = signer.Sign(SignedCommandClasses.ShellExec, Encoding.UTF8.GetBytes("echo twice"), T0, TimeSpan.FromMinutes(30));
        Assert.False(reloaded.TryRegister(env2, T0.AddMinutes(2)));
    }

    [Fact]
    public void D38F9_ReplacedNonceStore_AnchorMismatch_Refuses()
    {
        var (_, signer, _) = NonceRig();
        var path = Path.Combine(TestUtil.TempDir(), "nonces.json");
        var store = new PersistedNonceStore(path);
        var env = signer.Sign(SignedCommandClasses.ShellExec, Encoding.UTF8.GetBytes("echo keepme"), T0, TimeSpan.FromMinutes(30));
        Assert.True(store.TryRegister(env, T0.AddMinutes(1)));
        // The file is replaced with an empty (valid-shaped) store:
        File.WriteAllText(path, "{\"FloorUtc\":null,\"Nonces\":[]}");
        var reloaded = new PersistedNonceStore(path);
        Assert.True(reloaded.IsBroken);
        Assert.Contains("anchor", reloaded.State);
    }

    [Fact]
    public void D38F9_ClockRollback_PrunedNonce_StillRefused()
    {
        var (_, signer, _) = NonceRig();
        var path = Path.Combine(TestUtil.TempDir(), "nonces.json");
        var store = new PersistedNonceStore(path);
        var shortLived = signer.Sign(SignedCommandClasses.ShellExec, Encoding.UTF8.GetBytes("echo short"), T0, TimeSpan.FromMinutes(5));
        Assert.True(store.TryRegister(shortLived, T0.AddMinutes(1)));
        // Time passes beyond expiry + margin; a fresh registration
        // prunes the short-lived nonce and persists the floor:
        var later = signer.Sign(SignedCommandClasses.ShellExec, Encoding.UTF8.GetBytes("echo later"), T0, TimeSpan.FromHours(2));
        Assert.True(store.TryRegister(later, T0.AddMinutes(20)));
        // RESTART with the wall clock moved BACK inside the
        // short-lived envelope's TTL: its nonce is pruned, but the
        // store's monotonic floor refuses it anyway.
        var reloaded = new PersistedNonceStore(path);
        Assert.False(reloaded.IsBroken);
        Assert.False(reloaded.TryRegister(shortLived, T0.AddMinutes(2)));
    }

    // ---- F10: catalogue hash + retirement ----------------------------------

    [Fact]
    public void D38F10_ContentHash_NoFieldBoundaryCollision_NoCvssRoundingCollision()
    {
        PatchCatalogueEntry OsEntry(string? product, string? fixedIn, double? cvss) => new(
            Id: "KB1", Title: "t", Kind: PatchKinds.Os, TargetOs: "windows",
            ProductName: product, FixedInVersion: fixedIn, KbId: "KB1", FixedInOsBuild: "100",
            Classification: "security", Severity: "high", CvssScore: cvss,
            CveIds: new[] { "CVE-2024-12345" }, PayloadHash: null, PayloadLabel: null,
            RequiresReboot: false, Revision: 1);
        // The v1 '|' join hashed these two entries identically:
        Assert.NotEqual(OsEntry("X|1", "", 7.5).ContentHash, OsEntry("X", "1|", 7.5).ContentHash);
        // F1 CVSS rendering merged 8.96 and 9.04 into "9.0" — one
        // below and one AT the critical CVSS ≥ 9 cutoff:
        Assert.NotEqual(OsEntry("X", "1", 8.96).ContentHash, OsEntry("X", "1", 9.04).ContentHash);
        Assert.False(RebootGate.IsCritical(OsEntry("X", "1", 8.96)));
        Assert.True(RebootGate.IsCritical(OsEntry("X", "1", 9.04)));
    }

    [Fact]
    public void D38F10_RetiredEntry_OldRevisionCannotBeReadmitted()
    {
        var rig = RigWithApproved(out var entry);
        Assert.True(rig.Service.RetireEntry(entry.Id, "d38-fix test").Ok);
        Assert.Null(rig.Service.Catalogue.Get(entry.Id));
        // Remove + re-admit was the rollback: the SAME revision
        // (whose approval still stands in the store) refuses:
        var readmit = rig.Service.Catalogue.AddOrReplace(entry);
        Assert.False(readmit.Accepted);
        Assert.Contains("RETIRED", readmit.Reason);
        // A genuinely new revision may be admitted — but it is new
        // content, and the old approval does not follow it:
        var r2 = Rmm02Tests.ThirdParty(revision: 2);
        Assert.True(rig.Service.Catalogue.AddOrReplace(r2).Accepted);
        Assert.False(rig.Service.Approvals.CheckCurrent(r2, "dev1").Approved);
    }

    // ---- F11: ring structure + resume semantics ------------------------------

    [Fact]
    public void D38F11_DeviceInTwoRings_AndZeroThreshold_RefusedAtConstruction()
    {
        var hash = Rmm02Tests.ThirdParty().ContentHash;
        Assert.Throws<ArgumentException>(() => new RolloutPlan("dup", "Contoso.App", hash, new[]
        {
            new RingDefinition("test", 0, 0.5, new[] { "dev1" }),
            new RingDefinition("fleet", 1, 0.5, new[] { "dev1", "dev2" }),
        }));
        Assert.Throws<ArgumentException>(() => new RolloutPlan("zero", "Contoso.App", hash, new[]
        {
            new RingDefinition("test", 0, 0.0, new[] { "dev1" }),
        }));
    }

    [Fact]
    public void D38F11_ResumedRing_CompletesOnOutstandingCohort()
    {
        var plan = new RolloutPlan("plan-f11", "Contoso.App", Rmm02Tests.ThirdParty().ContentHash, new[]
        {
            new RingDefinition("pilot", 0, 0.75, new[] { "a", "b", "c", "d" }),
        });
        plan.StartRing("pilot");
        plan.RecordOutcome("pilot", "a", false, T0);
        plan.RecordOutcome("pilot", "b", false, T0);
        var halt = plan.StatusOf("pilot").HaltEvidence!;
        var decision = new ApprovalDecisionRecord(plan.EntryId, plan.EntryContentHash, "ring:plan-f11:pilot",
            ApprovalDecisions.Approved, "admin-1", T0, $"ring_resume:plan-f11:pilot:{halt.EvidenceHash}");
        Assert.True(plan.ResumeHalted("pilot", decision).Ok);
        // Pre-fix, the next outcome re-halted instantly (the known
        // failures already capped the ring below threshold). Now
        // the outstanding cohort decides:
        Assert.True(plan.RecordOutcome("pilot", "c", true, T0.AddMinutes(10)).Ok);
        Assert.Equal(RingStates.InProgress, plan.StatusOf("pilot").State);
        Assert.True(plan.RecordOutcome("pilot", "d", true, T0.AddMinutes(20)).Ok);
        Assert.Equal(RingStates.Complete, plan.StatusOf("pilot").State);
        // The failures were never erased from the record:
        Assert.Equal(2, plan.StatusOf("pilot").Failed);
    }

    [Fact]
    public void D38F11_ResumeWhenEveryDeviceAlreadyReported_CompletesTheRing()
    {
        var plan = new RolloutPlan("plan-f11b", "Contoso.App", Rmm02Tests.ThirdParty().ContentHash, new[]
        {
            new RingDefinition("test", 0, 1.0, new[] { "a", "b" }),
        });
        plan.StartRing("test");
        plan.RecordOutcome("test", "a", true, T0);
        plan.RecordOutcome("test", "b", false, T0); // all in, 50% < 100% ⇒ halt
        Assert.Equal(RingStates.Halted, plan.StatusOf("test").State);
        var halt = plan.StatusOf("test").HaltEvidence!;
        var decision = new ApprovalDecisionRecord(plan.EntryId, plan.EntryContentHash, "ring:plan-f11b:test",
            ApprovalDecisions.Approved, "admin-1", T0, $"ring_resume:plan-f11b:test:{halt.EvidenceHash}");
        var resumed = plan.ResumeHalted("test", decision);
        Assert.True(resumed.Ok, resumed.Reason);
        Assert.Equal(RingStates.Complete, plan.StatusOf("test").State);
    }

    // ---- F12: reboot anchor ---------------------------------------------------

    [Fact]
    public void D38F12_CriticalDeadline_Reachable_FromPersistedAnchor()
    {
        var clock = T0;
        var rig = Rmm02Tests.NewRig();
        var svc = new PatchService(rig.DataDir, rig.Audit, rig.Policies,
            new SignedCommandGate(new SignedCommandVerifier(rig.Ring), rig.Audit),
            rig.Endpoint, rig.Ring, now: () => clock);
        var kb = Rmm02Tests.OsKb(); // critical, requires reboot, 72h enforcement
        svc.AdmitEntries(new[] { kb }, "d38-fix setup");
        svc.Decide(Rmm02Tests.Facts(), kb.Id, "*", approve: true, decidedBy: "admin-1");
        var env = rig.Signer.Sign(SignedCommandClasses.PatchDeploy,
            Encoding.UTF8.GetBytes(PatchService.DeployPayload(kb.Id, "dev1", kb.ContentHash)),
            clock, TimeSpan.FromHours(2));
        var deployed = svc.Deploy(Rmm02Tests.Facts(), kb.Id, env, null,
            Array.Empty<IContentSource>(), new Rmm02Tests.FakeApplier(), "/tmp/kb.msu");
        Assert.True(deployed.Ok, deployed.Reason);
        Assert.Equal(RebootStates.PendingWindow, deployed.Reboot!.State); // deadline cannot have passed at deploy time
        // 100 hours later the SAME evaluation reaches enforcement —
        // pre-fix the anchor was re-set to "now" on every look, so
        // this state was unreachable in the wiring:
        clock = T0.AddHours(100);
        var later = svc.EvaluateReboot(kb.Id, "dev1");
        Assert.True(later.Ok, later.Reason);
        Assert.Equal(RebootStates.Enforced, later.Decision!.State);
        Assert.True(later.Decision.RebootPermittedNow);
        // Deferrals bind content and survive restart:
        Assert.True(svc.RecordDeferral(kb.Id, "dev1").Ok);
        var svc2 = Restarted(rig, () => clock);
        Assert.Equal(1, svc2.DeferralCount(kb.Id, "dev1"));
        var restored = svc2.EvaluateReboot(kb.Id, "dev1");
        Assert.True(restored.Ok, restored.Reason);
        Assert.Equal(RebootStates.Enforced, restored.Decision!.State);
    }
}
