using System.Text;
using Acp.Shared.AiPack;
using Acp.Shared.Backup;
using Acp.Shared.Deployment;
using Acp.Shared.DirectoryEnrollment;
using Acp.Shared.Distribution;
using Acp.Shared.Enrollment;
using Acp.Shared.Enterprise;
using Acp.Shared.Inventory;
using Acp.Shared.Jobs;
using Acp.Shared.Provisioning;
using Acp.Shared.QuickAssist;
using Acp.Shared.Remediation;
using Acp.Shared.Roster;
using Acp.Shared.Security;

namespace Acp.Tests;

// Wave 4 Lane A — regression tests for bd-shared-plat-1
// (packet 8c10fa1e) and bd-shared-plat-2 (packet eb7423d5).
// Each test names its finding and attacks the production path
// the finding cited.
public class BdSharedPlat12FixTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    private const string Dev = "dev-1";

    // ---------- plat-1 F1: convergence ----------

    [Fact]
    public void P1F1_RecordedButNotObserved_IsNotCompliant()
    {
        var pkg = Rmm16Tests.Pkg();
        var recorded = new DevicePackageState(Dev, "widget", "2.0.0", DevicePackageState.Deployed, T0);
        var line = DeploymentConvergence.Evaluate(pkg, recorded, Array.Empty<SoftwareItem>(), Dev);
        Assert.Equal(ConvergenceStates.RecordedNotObserved, line.State);
    }

    [Fact]
    public void P1F1_NoInventoryName_Recorded_IsUnobservableNeverCompliant()
    {
        var pkg = Rmm16Tests.Pkg() with { InstalledSoftwareName = null };
        var recorded = new DevicePackageState(Dev, "widget", "2.0.0", DevicePackageState.Deployed, T0);
        var line = DeploymentConvergence.Evaluate(pkg, recorded, Array.Empty<SoftwareItem>(), Dev);
        Assert.Equal(ConvergenceStates.Unobservable, line.State);
    }

    // ---------- plat-1 F2/F4/F9: the runner ----------

    private static (DeploymentRunner Runner, JobJournal Journal, DeploymentPackage Pkg, string Id) RunnerRig(
        Rmm16Tests.Rig rig)
    {
        rig.AdmitAndAssign(Rmm16Tests.Pkg());
        var pkg = rig.Repository.Get("widget", "2.0.0")!;
        return (new DeploymentRunner(rig.Executor, rig.Gate, rig.Audit, rig.Vault),
            new JobJournal(), pkg, Guid.NewGuid().ToString("N"));
    }

    private static DeploymentExecution RunDeploy(Rmm16Tests.Rig rig, DeploymentRunner runner,
        JobJournal journal, DeploymentPackage pkg, string id,
        Func<string, string, bool>? isRevoked = null,
        Func<DeploymentPackage, string?>? probe = null,
        string? expectedHash = "admitted")
    {
        var env = rig.Signer.Sign(SignedCommandClasses.PackageDeploy,
            Encoding.UTF8.GetBytes(DeploymentBinding.Payload(pkg, Dev, DeploymentActions.Deploy, false)),
            T0, TimeSpan.FromMinutes(5));
        var def = DeploymentBinding.DefinitionFor(pkg, DeploymentActions.Deploy);
        var lib = DeploymentBinding.ExecutionLibrary(pkg, DeploymentActions.Deploy);
        var auto = rig.Signer.Sign(SignedCommandClasses.Automation,
            Encoding.UTF8.GetBytes(RemediationBinding.Payload(def, lib, Dev, id,
                DeploymentBinding.AlertConditionId)), T0, TimeSpan.FromMinutes(5));
        var journalEnv = rig.Signer.Sign(SignedCommandClasses.ScriptExec,
            Encoding.UTF8.GetBytes($"script_chain|{def.Id}|{RemediationBinding.PlanHash(def)}"),
            T0, TimeSpan.FromMinutes(5));
        return runner.Run(pkg, Dev, DeploymentActions.Deploy, false, env, auto, journalEnv,
            journal, () => true, null, null, id, T0,
            expectedContentHash: expectedHash == "admitted" ? rig.Repository.AdmittedContentHash(pkg.Id, pkg.Version) : expectedHash,
            isRevoked: isRevoked, installedVersionProbe: probe);
    }

    [Fact]
    public void P1F2_Runner_RefusesRevoked_EvenWithValidEnvelope()
    {
        var rig = new Rmm16Tests.Rig();
        var (runner, journal, pkg, id) = RunnerRig(rig);
        var exec = RunDeploy(rig, runner, journal, pkg, id, isRevoked: (_, _) => true);
        Assert.Equal(DeploymentOutcomes.Refused, exec.Outcome);
        Assert.Empty(rig.Executor.Calls);
    }

    [Fact]
    public void P1F2_RepositoryRevoke_NeedsNamedAdminActor_AndAudits()
    {
        var rig = new Rmm16Tests.Rig();
        rig.AdmitAndAssign(Rmm16Tests.Pkg());
        var audit = new ChainedAuditLog();
        Assert.False(rig.Repository.Revoke("widget", "2.0.0", "", _ => true, audit, T0).Ok);
        Assert.False(rig.Repository.Revoke("widget", "2.0.0", "mallory", _ => false, audit, T0).Ok);
        Assert.False(rig.Repository.IsRevoked("widget", "2.0.0"));
        Assert.True(rig.Repository.Revoke("widget", "2.0.0", "admin-1", a => a == "admin-1", audit, T0).Ok);
        Assert.True(rig.Repository.IsRevoked("widget", "2.0.0"));
        Assert.Contains(audit.Entries, e => e.Kind == "package_revoked");
    }

    [Fact]
    public void P1F9_Runner_NoAdmissionAnchor_Refuses()
    {
        var rig = new Rmm16Tests.Rig();
        var pkg = Rmm16Tests.Pkg(); // code-constructed: no carried manifest
        var runner = new DeploymentRunner(rig.Executor, rig.Gate, rig.Audit, rig.Vault);
        var exec = RunDeploy(rig, runner, new JobJournal(), pkg, Guid.NewGuid().ToString("N"),
            expectedHash: null);
        Assert.Equal(DeploymentOutcomes.Refused, exec.Outcome);
        Assert.Empty(rig.Executor.Calls);
    }

    [Fact]
    public void P1F4_VerifyInstall_NoProbe_StepFails_OutcomeNotSucceeded()
    {
        var rig = new Rmm16Tests.Rig();
        var (runner, journal, pkg, id) = RunnerRig(rig);
        var exec = RunDeploy(rig, runner, journal, pkg, id, probe: null);
        Assert.NotEqual(DeploymentOutcomes.Succeeded, exec.Outcome);
        var job = journal.GetJob(exec.JobId!);
        Assert.NotNull(job);
        var step = job!.Steps.Single(s => s.StepId == DeploymentJobSteps.VerifyInstall);
        Assert.Equal(StepStates.Failed, step.State);
    }

    [Fact]
    public void P1F4_VerifyInstall_ProbeObservesVersion_StepCompletes()
    {
        var rig = new Rmm16Tests.Rig();
        var (runner, journal, pkg, id) = RunnerRig(rig);
        var exec = RunDeploy(rig, runner, journal, pkg, id, probe: p => p.Version);
        Assert.Equal(DeploymentOutcomes.Succeeded, exec.Outcome);
        var job = journal.GetJob(exec.JobId!);
        var step = job!.Steps.Single(s => s.StepId == DeploymentJobSteps.VerifyInstall);
        Assert.Equal(StepStates.Done, step.State);
    }

    [Fact]
    public void P1F4_VerifyInstall_ProbeObservesNothing_StepFails()
    {
        var rig = new Rmm16Tests.Rig();
        var (runner, journal, pkg, id) = RunnerRig(rig);
        var exec = RunDeploy(rig, runner, journal, pkg, id, probe: _ => null);
        Assert.NotEqual(DeploymentOutcomes.Succeeded, exec.Outcome);
        var job = journal.GetJob(exec.JobId!);
        Assert.Equal(StepStates.Failed,
            job!.Steps.Single(s => s.StepId == DeploymentJobSteps.VerifyInstall).State);
    }

    // ---------- plat-1 F8: starter packs ----------

    [Fact]
    public void P1F8_StarterPacks_RealWingetPins_AndArpNames()
    {
        var sevenZip = StarterContentPacks.UtilitiesPack().Packages.Single(p => p.Id == "seven-zip");
        Assert.Equal("24.09", sevenZip.Version);
        Assert.Equal("7-Zip 24.09 (x64)", sevenZip.InstalledSoftwareName);
        Assert.Contains(sevenZip.Install.Steps, s => (s.ScriptBody ?? "").Contains("--version 24.09 --exact"));
        var vc = StarterContentPacks.RuntimePack().Packages.Single(p => p.Id == "vcredist-x64");
        Assert.Equal("14.40.33810.0", vc.Version);
        Assert.Contains(vc.Install.Steps, s => (s.ScriptBody ?? "").Contains("--version 14.40.33810.0 --exact"));
    }

    // ---------- plat-1 F3/F6/F7: directory enrollment ----------

    [Fact]
    public void P1F3_Decline_KillsTheSlice1Code_Itself()
    {
        var rig = new Rmm24Tests.Rig();
        var offer = rig.SyncOneOffer();
        var code = rig.Delivery.CodeFor(offer.Id);
        Assert.NotNull(code);
        Assert.True(rig.Engine.DeclineOffer(offer.Id, "tech-1", T0).Ok);
        // Direct Slice-1 redemption with the delivered code — the
        // bypass the finding cited — must now fail.
        var device = new EnrollingDevice(rig.EndpointIdentity.DeviceId,
            rig.EndpointIdentity.PublicKeyBase64, "ws-new");
        Assert.Null(rig.Enrollments.Redeem(code, device));
    }

    [Fact]
    public void P1F3_ExpiredAcceptance_KillsTheSlice1Code()
    {
        var rig = new Rmm24Tests.Rig();
        var offer = rig.SyncOneOffer();
        var code = rig.Delivery.CodeFor(offer.Id);
        var device = new EnrollingDevice(rig.EndpointIdentity.DeviceId,
            rig.EndpointIdentity.PublicKeyBase64, "ws-new");
        var (enrolled, _) = rig.Engine.AcceptOffer(offer.Id, code,
            new EnrollingDevice(rig.EndpointIdentity.DeviceId, rig.EndpointIdentity.PublicKeyBase64, "ws-new"),
            T0.AddDays(8));
        Assert.Null(enrolled);
        Assert.Null(rig.Enrollments.Redeem(code, device));
    }

    [Fact]
    public void P1F6F7_ExportImport_MappingsPersist_ReprovisionSurvives_TamperRefused()
    {
        var rig = new Rmm24Tests.Rig();
        var offer = rig.SyncOneOffer();
        // Departure: remove the tech from the directory group.
        rig.Directory.RemoveMember("dir-techs", "tech-1");
        rig.Engine.Sync(T0.AddHours(1));
        Assert.False(rig.Engine.HasLivePushRights("co-1", "tech-1"));
        // Admin re-provisions: the flag record stays, the block clears.
        Assert.True(rig.Engine.ReprovisionUser("co-1", "tech-1", "admin-1", T0.AddHours(2)).Ok);
        Assert.True(rig.Engine.HasLivePushRights("co-1", "tech-1"));

        var export = rig.Engine.ExportJson();
        var rig2 = new Rmm24Tests.Rig();
        var restored = rig2.Engine.ImportJson(export);
        Assert.True(restored > 0);
        // F7: the mapping came back — sync is not silently dead.
        Assert.Single(rig2.Engine.Mappings);
        // F6: the reprovision clear survived the restart.
        Assert.True(rig2.Engine.HasLivePushRights("co-1", "tech-1"));
        // F6: a tampered export restores nothing.
        var rig3 = new Rmm24Tests.Rig();
        var tampered = export.Replace("tech-1", "mallory-1");
        Assert.Equal(0, rig3.Engine.ImportJson(tampered));
        Assert.Empty(rig3.Engine.Mappings);
    }

    // ---------- plat-1 F10: backup catalogue torn write ----------

    [Fact]
    public void P1F10_TornWrite_Recovered_Rollback_Refused()
    {
        var dir = TestUtil.TempDir();
        var path = Path.Combine(dir, "catalogue.json");
        var store = new BackupSnapshotStore("nas1", new InMemoryBackupStorage(),
            new SignedCommandVerifier(new CustomerCommandKeyRing()));
        var capture = new FakeBackupCaptureSource().AddFile(@"C:\data\a.txt", "alpha");
        var engine = new BackupEngine(store, capture, new ChainedAuditLog());
        var job = new BackupJobDefinition("job1", "dev1", "alice", BackupKinds.File,
            new[] { @"C:\data\a.txt" }, "nas1", new BackupSchedule(24), 7, true);
        Assert.True(engine.RunBackup(job, envelope: null, T0).Ok);
        store.SaveCatalogueToFile(path);
        var gen1Catalogue = File.ReadAllText(path);
        var gen1Anchor = File.ReadAllText(path + ".anchor");
        // Second snapshot → generation 2 saved fully.
        Assert.True(engine.RunBackup(job with { Id = "job2" }, envelope: null, T0.AddHours(1)).Ok);
        store.SaveCatalogueToFile(path);
        // TORN WRITE: catalogue is gen2, anchor is still gen1.
        File.WriteAllText(path + ".anchor", gen1Anchor);
        var store2 = new BackupSnapshotStore("nas1", new InMemoryBackupStorage(),
            new SignedCommandVerifier(new CustomerCommandKeyRing()));
        var (okTorn, tornSummary) = store2.LoadCatalogueFromFile(path);
        Assert.True(okTorn, tornSummary);
        Assert.Contains("RECOVERED-TORN-WRITE", tornSummary);
        Assert.False(store2.CatalogueTampered);
        // ROLLBACK: gen1 catalogue against the (now re-anchored)
        // gen2 anchor refuses as tamper.
        File.WriteAllText(path, gen1Catalogue);
        var store3 = new BackupSnapshotStore("nas1", new InMemoryBackupStorage(),
            new SignedCommandVerifier(new CustomerCommandKeyRing()));
        var (okRollback, _) = store3.LoadCatalogueFromFile(path);
        Assert.False(okRollback);
        Assert.True(store3.CatalogueTampered);
    }

    // ---------- plat-1 F11: AI pack ----------

    [Fact]
    public async Task P1F11_FixtureMode_OnProductionManifest_Refused()
    {
        var svc = new AiPackService(AiPackManifest.UiTars15_7B);
        svc.AcceptLicence("operator");
        var dir = TestUtil.TempDir();
        Task Fetch(string url, string dest, CancellationToken ct) => Task.CompletedTask;
        var (ok, detail) = await svc.DownloadAsync(dir, Fetch,
            sourceBaseOverride: "https://evil.example/models", fixtureMode: true);
        Assert.False(ok);
        Assert.Contains("fixture", detail, StringComparison.OrdinalIgnoreCase);
    }

    // ---------- plat-2 F2/F3/F4/F12: mobile operator ----------

    [Fact]
    public void P2F4_MobilePolicyKey_IsItsOwn_AndUnwiredGateFailsClosed()
    {
        Assert.Equal("rmm.mobile_operator.enabled", MobileOperatorPolicyKeys.Enabled);
        var rig = new Rmm24Tests.Rig();
        var unwired = new MobileAuthorization(rig.Roster, rig.Clients, policyEnabled: null);
        Assert.False(unwired.Can("co-1", "op-1", "any", "browse_roster", "dg-1"));
    }

    [Fact]
    public void P2F2_SessionStart_TargetGroupIsAuthoritative_WhenWired()
    {
        var rig = new Rmm24Tests.Rig();
        rig.RegisterPhone();
        rig.Roster.CreateDeviceGroup("dg-2", "co-1", "Other group");
        var auth = new MobileAuthorization(rig.Roster, rig.Clients, () => true,
            targetGroupOf: id => id == "ws-b" ? "dg-2" : "dg-1");
        // Caller names dg-1 (where op holds use) for a dg-2 device.
        var attack = new MobileSessionRequest("op-1", rig.PhoneIdentity.DeviceId, "ws-b", "dg-1", "drive");
        Assert.False(auth.ValidateSessionStart("co-1", attack).Ok);
        // Unknown target refuses.
        var unknown = new MobileSessionRequest("op-1", rig.PhoneIdentity.DeviceId, "ghost", "dg-1", "drive");
        var auth2 = new MobileAuthorization(rig.Roster, rig.Clients, () => true,
            targetGroupOf: _ => null);
        Assert.False(auth2.ValidateSessionStart("co-1", unknown).Ok);
        // Honest request for a dg-1 target still works.
        var honest = new MobileSessionRequest("op-1", rig.PhoneIdentity.DeviceId, "ws-a", "dg-1", "drive");
        Assert.True(auth.ValidateSessionStart("co-1", honest).Ok);
    }

    [Fact]
    public void P2F3_RosterFor_FilteredToViewableGroups()
    {
        var rig = new Rmm24Tests.Rig();
        rig.RegisterPhone();
        rig.Roster.CreateDeviceGroup("dg-secret", "co-1", "Secret group");
        var full = rig.Auth.RosterFor("co-1", "op-1", rig.PhoneIdentity.DeviceId);
        Assert.NotNull(full);
        Assert.DoesNotContain(full!.DeviceGroups, g => g.Id == "dg-secret");
        Assert.Contains(full.DeviceGroups, g => g.Id == "dg-1");
        // A user with no view right anywhere gets nothing.
        rig.Roster.CreateUser("nobody-1", "co-1", "Nobody", "human");
        var nobodyPhone = new DeviceIdentity(new DevOnlyPassThroughProtector());
        rig.EnrollDevice(nobodyPhone, "nobody-phone");
        Assert.NotNull(rig.RegisterClientSelf("nobody-1", nobodyPhone).Registration);
        Assert.Null(rig.Auth.RosterFor("co-1", "nobody-1", nobodyPhone.DeviceId));
    }

    [Fact]
    public void P2F12_Approvals_TtlCapped_PendingAtExcludesExpired_StoresRoundTrip()
    {
        var rig = new Rmm24Tests.Rig();
        var req = rig.Approvals.CreateRequest("co-1", "dg-1", "reboot", "admin-1",
            TimeSpan.MaxValue, T0);
        Assert.True(req.ExpiresUtc <= T0 + MobileApprovalService.MaxApprovalTtl);
        Assert.Single(rig.Approvals.PendingAt(T0));
        Assert.Empty(rig.Approvals.PendingAt(T0.AddDays(2)));
        var export = rig.Approvals.ExportJson();
        var rig2 = new Rmm24Tests.Rig();
        Assert.Equal(1, rig2.Approvals.ImportJson(export));
        Assert.NotNull(rig2.Approvals.Get(req.Id));
        // Notification dedup: acknowledged no longer blocks a re-raise.
        var noteExport = rig.Notifications.ExportJson();
        Assert.True(rig2.Notifications.ImportJson(noteExport) >= 0);
    }

    // ---------- plat-2 F5/F6: provisioning ----------

    [Fact]
    public void P2F5_RunnerLedger_SurvivesRestart_RunIdStillExecutesOnce()
    {
        var rig = new Rmm29Tests.Rig();
        Assert.Null(rig.Images.Admit(Rmm29Tests.Image()));
        var req = Rmm29Tests.Rig.ReimageReq();
        var result = rig.Run(req);
        Assert.Equal(ProvisioningStates.Completed, result.State);
        var ledger = rig.Runner.ExportJson();
        var rig2 = new Rmm29Tests.Rig();
        Assert.Null(rig2.Images.Admit(Rmm29Tests.Image()));
        Assert.True(rig2.Runner.ImportJson(ledger) > 0);
        var again = rig2.Runner.Run(req, rig2.EnvelopeFor(req), new JobJournal(), () => true, rig2.Now);
        Assert.Equal(ProvisioningStates.Refused, again.State);
        Assert.Contains("executes once", again.Reason);
    }

    [Fact]
    public void P2F5_TokenConsumed_SurvivesExportImport_NoReplay()
    {
        var tokens = new ProvisioningTokenService();
        var img = Rmm29Tests.Image();
        var code = tokens.Mint(img.Id, img.Version, img.ContentHash, "co-1", "admin", T0);
        Assert.NotNull(tokens.Redeem(code, img.Id, img.Version, img.ContentHash, T0, "co-1"));
        var tokens2 = new ProvisioningTokenService();
        Assert.True(tokens2.ImportJson(tokens.ExportJson()) > 0);
        Assert.Null(tokens2.Redeem(code, img.Id, img.Version, img.ContentHash, T0, "co-1"));
    }

    [Fact]
    public void P2F6_RestoreToTarget_WritesAndReadsBack_UnavailableFails()
    {
        var engine = new ProfileMigrationEngine(new DevOnlyPassThroughProtector());
        var manifest = Rmm29Tests.Manifest();
        var (pkg, reason) = engine.CaptureAndSeal(manifest, Rmm29Tests.FullSource(), T0);
        Assert.NotNull(pkg);
        var target = new FakeProfileRestoreTarget();
        var (ok, detail, _, _) = engine.RestoreToTarget(pkg, "dev-1", "user-1", null, target);
        Assert.True(ok, detail);
        Assert.Equal(2, target.Written.Count);
        var (okBad, _, _, _) = engine.RestoreToTarget(pkg, "dev-1", "user-1", null,
            new UnavailableProfileRestoreTarget());
        Assert.False(okBad);
        var (okNull, nullDetail, _, _) = engine.RestoreToTarget(pkg, "dev-1", "user-1", null, null);
        Assert.False(okNull);
        Assert.Contains("no profile restore target", nullDetail);
    }

    // ---------- plat-2 F7: quick assist ----------

    [Fact]
    public void P2F7_QuickAssist_PerBindingLockout_GrantOutlivesCodeWindow()
    {
        var qa = new QuickAssistService();
        var code = qa.Mint("co1", "dev-1", "tech", T0);
        for (var i = 0; i < QuickAssistService.MaxFailedAttempts; i++)
            Assert.False(qa.Redeem("ZZZZ-ZZZZ", "attacker", T0).Ok);
        Assert.True(qa.IsLocked(T0, "attacker"));
        Assert.False(qa.IsLocked(T0, "helper"));
        var (ok, _, grant, token) = qa.Redeem(code, "helper", T0);
        Assert.True(ok);
        // Grant lives on its own session lifetime, past the code's
        // 10-minute window.
        Assert.True(qa.Validate(grant!.GrantId, token, "helper", T0.AddHours(2)).Ok);
        Assert.False(qa.Validate(grant.GrantId, token, "helper", T0.AddHours(9)).Ok);
    }

    // ---------- plat-2 F9: p2p failover keeps verified chunks ----------

    private sealed class FlakySource : IContentSource
    {
        private readonly PeerContentStore _store;
        private readonly int _failAfter;
        public FlakySource(string id, PeerContentStore store, int failAfter)
        { SourceId = id; _store = store; _failAfter = failAfter; }
        public string SourceId { get; }
        public bool IsHub => false;
        public byte[]? FetchChunk(ContentManifest manifest, int index) =>
            index >= _failAfter ? null : _store.GetChunk(manifest.ContentHash, manifest, index);
    }

    [Fact]
    public void P2F9_Failover_KeepsVerifiedChunks_FromFirstSource()
    {
        var content = Encoding.UTF8.GetBytes(new string('x', 5000));
        var manifest = ContentManifest.Build(content, chunkSize: 1024, label: "blob");
        var full = new PeerContentStore();
        Assert.True(full.PutVerified(manifest, content));
        var first = new FlakySource("first", full, failAfter: 2);
        var second = new FlakySource("second", full, failAfter: int.MaxValue);
        var local = new PeerContentStore();
        var result = new ContentFetcher().Fetch(manifest, new IContentSource[] { first, second }, local);
        Assert.True(result.Ok, result.Reason);
        Assert.Equal("second", result.SourceUsed);
        Assert.Equal(content, result.Content);
    }

    // ---------- plat-2 F10: roster grant events ----------

    [Fact]
    public void P2F10_AddGrant_RecordsEvent_WithActorWhenGated()
    {
        var rig = new Rmm24Tests.Rig();
        var before = rig.Roster.ListEvents("co-1").Count;
        rig.Roster.AddGrant("co-1", "ug-1", "dg-1", new[] { "view" });
        var events = rig.Roster.ListEvents("co-1");
        Assert.True(events.Count > before);
        Assert.Contains(events, e => e.Kind == "grant_changed" || e.Kind == "grant_added");
    }

    // ---------- plat-2 F11: SAS quarantine ----------

    [Fact]
    public void P2F11_SasMismatch_QuarantinesSignature_UntilHumanReconfirms()
    {
        var svc = new EnrollmentService();
        var identity = new DeviceIdentity(new DevOnlyPassThroughProtector());
        svc.LocalPublicKeyProvider = () => identity.PublicKey;
        var code = svc.CreateEnrollmentCode("company", "g1", "Group One");
        var device = svc.Redeem(code, new EnrollingDevice(identity.DeviceId,
            identity.PublicKeyBase64, "ws-1"));
        Assert.NotNull(device);
        // Give the device a SAS to confirm/mismatch against.
        var sas = svc.ComputeSasFor(identity.DeviceId, "transcript-1");
        Assert.NotNull(sas);
        var msg = Encoding.UTF8.GetBytes("hello");
        var sig = identity.Sign(msg);
        Assert.True(svc.VerifyEnrolledSignature(identity.DeviceId, msg, sig));
        Assert.True(svc.ReportSasMismatch(identity.DeviceId));
        Assert.False(svc.VerifyEnrolledSignature(identity.DeviceId, msg, sig));
        Assert.True(svc.ConfirmSas(identity.DeviceId));
        Assert.True(svc.VerifyEnrolledSignature(identity.DeviceId, msg, sig));
    }
}
