using System.Text;
using DeskGuest.Core.Services;
using DeskGuest.Shared.Distribution;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.Inventory;
using DeskGuest.Shared.Jobs;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.Patching;
using DeskGuest.Shared.Security;

namespace DeskGuest.Tests;

// RMM-02 — Patch management: catalogue, scan, approvals, rings,
// reboot handling, deployment through the PatchRun journal.
// Live patching is never exercised: appliers are fakes / command-
// plan shapes only (proof PENDING, per the lane assignment).
public class Rmm02Tests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);

    private static DeviceIdentity NewIdentity() => new(new DevOnlyPassThroughProtector());
    private static byte[] Payload => Encoding.UTF8.GetBytes("contoso-app-2.0-payload-bytes");
    private static string PayloadHash => ContentManifest.HashOf(Payload);

    internal static PatchCatalogueEntry ThirdParty(long revision = 1, string? payloadHash = null, string severity = "high") => new(
        Id: "Contoso.App", Title: "Contoso App 2.0", Kind: PatchKinds.ThirdParty, TargetOs: "windows",
        ProductName: "Contoso App", FixedInVersion: "2.0", KbId: null, FixedInOsBuild: null,
        Classification: "security", Severity: severity, CvssScore: 7.5,
        CveIds: new[] { "CVE-2024-12345" }, PayloadHash: payloadHash ?? PayloadHash,
        PayloadLabel: "Contoso.App", RequiresReboot: false, Revision: revision);

    internal static PatchCatalogueEntry OsKb(long revision = 1) => new(
        Id: "KB5034441", Title: "Windows security update KB5034441", Kind: PatchKinds.Os, TargetOs: "windows",
        ProductName: null, FixedInVersion: null, KbId: "KB5034441", FixedInOsBuild: "22631.3000",
        Classification: "security", Severity: "critical", CvssScore: 9.1,
        CveIds: new[] { "CVE-2024-99999" }, PayloadHash: null, PayloadLabel: null,
        RequiresReboot: true, Revision: revision);

    internal sealed class FakeApplier : IPatchApplier
    {
        public int Calls;
        public bool Fail;
        public string OsKind => "windows";
        public bool CanApply(PatchCatalogueEntry entry) => true;
        public PatchApplyResult BuildApply(PatchApplyRequest request)
        {
            Calls++;
            if (Fail) return new PatchApplyResult(false, "fake applier configured to fail", null, null);
            return new PatchApplyResult(true, "fake applier plan built",
                new PatchCommandPlan(OsKind, "fake.exe", new[] { request.Entry.Id }, "install"),
                new PatchCommandPlan(OsKind, "fake.exe", new[] { "verify", request.Entry.Id }, "verify"));
        }
    }

    internal sealed record Rig(
        DeviceIdentity Customer, SignedCommandSigner Signer, CustomerCommandKeyRing Ring,
        ChainedAuditLog Audit, ManagementPolicyService Policies, PatchService Service,
        string DataDir, DeviceIdentity Endpoint);

    internal static Rig NewRig(bool withGate = true)
    {
        var customer = NewIdentity();
        var ring = new CustomerCommandKeyRing();
        ring.AddCurrent(customer.PublicKey);
        var audit = new ChainedAuditLog();
        var gate = withGate
            ? new SignedCommandGate(new SignedCommandVerifier(ring), audit)
            : null;
        var policies = new ManagementPolicyService(audit, gate, now: () => T0);
        var endpoint = NewIdentity();
        var dir = TestUtil.TempDir();
        var svc = new PatchService(dir, audit, policies, gate, endpoint, ring, now: () => T0);
        return new Rig(customer, new SignedCommandSigner(customer), ring, audit, policies, svc, dir, endpoint);
    }

    internal static IDeviceFacts Facts(string deviceId = "dev1") =>
        StaticDeviceFacts.Of(deviceId, "scope1");

    internal static DeviceInventoryRecord Record(string deviceId, string osName, string osBuild,
        params (string Name, string Version)[] software) => new(
            DeviceId: deviceId, ScopeId: "scope1", Hostname: "host-" + deviceId,
            Hardware: new HardwareSnapshot("Contoso", "Model", null, "CPU", 4, 16L << 30,
                osName, osBuild, osBuild, null, Array.Empty<DiskInfo>(), Array.Empty<PeripheralInfo>(), T0),
            Software: software.Select(s => new SoftwareItem(s.Name, s.Version, "Contoso", null, null)).ToList(),
            CustomFields: new Dictionary<string, string>(), Tags: new HashSet<string>(),
            FirstSeenUtc: T0, LastSeenUtc: T0, LastChangedUtc: T0, Revision: 1);

    private static SignedCommandEnvelope DeployEnv(Rig rig, PatchCatalogueEntry entry, string deviceId = "dev1") =>
        rig.Signer.Sign(SignedCommandClasses.PatchDeploy,
            Encoding.UTF8.GetBytes(PatchService.DeployPayload(entry.Id, deviceId, entry.ContentHash)),
            T0, TimeSpan.FromHours(2));

    private static (ContentManifest Manifest, IReadOnlyList<IContentSource> Sources) HubSource(byte[] payload)
    {
        var manifest = ContentManifest.Build(payload, 16, "test");
        var store = new PeerContentStore();
        Assert.True(store.PutVerified(manifest, payload));
        return (manifest, new IContentSource[] { new StoreContentSource("hub", store, isHub: true) });
    }

    // ---- catalogue ------------------------------------------------

    [Fact]
    public void RMM02_Catalogue_AdmissionValidation_AndRevisionDiscipline()
    {
        var cat = new PatchCatalogue();
        Assert.True(cat.AddOrReplace(ThirdParty()).Accepted);
        // malformed CVE, bad hash, CVSS out of range, unpinned third-party:
        Assert.False(cat.AddOrReplace(ThirdParty() with { CveIds = new[] { "CVE-24-1" } }).Accepted);
        Assert.False(cat.AddOrReplace(ThirdParty() with { PayloadHash = "not-a-hash" }).Accepted);
        Assert.False(cat.AddOrReplace(ThirdParty() with { CvssScore = 11.0 }).Accepted);
        Assert.False(cat.AddOrReplace(ThirdParty() with { PayloadHash = null }).Accepted);
        // same revision, different content = the post-approval swap shape:
        var conflict = cat.AddOrReplace(ThirdParty() with { Title = "Swapped title" });
        Assert.False(conflict.Accepted);
        Assert.Contains("conflicts", conflict.Reason);
        // stale revision refuses; a NEW revision replaces (and re-hashes):
        Assert.False(cat.AddOrReplace(ThirdParty(revision: 0)).Accepted);
        var before = cat.Get("Contoso.App")!.ContentHash;
        Assert.True(cat.AddOrReplace(ThirdParty(revision: 2) with { Title = "Contoso App 2.0 (rev2)" }).Accepted);
        Assert.NotEqual(before, cat.Get("Contoso.App")!.ContentHash);
    }

    [Fact]
    public void RMM02_WinGetManifestImport_Atomic_AndValidated()
    {
        var rig = NewRig();
        var good = """
            {"packages":[{"PackageIdentifier":"Contoso.App","PackageName":"Contoso App","Version":"2.0","InstallerSha256":"__HASH__",
              "deskguest":{"classification":"security","severity":"high","cveIds":["CVE-2024-12345"],"cvss":7.5}}]}
            """.Replace("__HASH__", PayloadHash);
        var ok = rig.Service.ImportWinGetManifest(good, revision: 1, via: "test import");
        Assert.True(ok.Ok, ok.Reason);
        Assert.NotNull(rig.Service.Catalogue.Get("Contoso.App"));
        // a manifest with one bad package imports NOTHING (atomic):
        var bad = """
            {"packages":[
              {"PackageIdentifier":"Good.One","PackageName":"Good One","Version":"1.0","InstallerSha256":"__HASH__"},
              {"PackageIdentifier":"Bad.One","PackageName":"Bad One","Version":"1.0"}]}
            """.Replace("__HASH__", PayloadHash);
        var refused = rig.Service.ImportWinGetManifest(bad, revision: 1, via: "test import");
        Assert.False(refused.Ok);
        Assert.Null(rig.Service.Catalogue.Get("Good.One"));
    }

    // ---- scan -------------------------------------------------------

    [Fact]
    public void RMM02_Scan_ThirdPartyAndOs_MissingDetermination()
    {
        var cat = new PatchCatalogue();
        cat.AddOrReplace(ThirdParty());
        cat.AddOrReplace(OsKb());
        // installed 1.5 < fixed 2.0 ⇒ missing; build 22631.1000 < 22631.3000 ⇒ missing:
        var missing = PatchScanner.DetermineMissing(
            Record("dev1", "Windows 11 Pro", "22631.1000", ("Contoso App", "1.5")), cat);
        Assert.Equal(2, missing.Count);
        Assert.Contains(missing, m => m.EntryId == "Contoso.App" && m.InstalledVersion == "1.5" && m.CveIds.Contains("CVE-2024-12345"));
        Assert.Contains(missing, m => m.EntryId == "KB5034441" && m.RequiresReboot);
        // up to date on both ⇒ nothing missing:
        Assert.Empty(PatchScanner.DetermineMissing(
            Record("dev1", "Windows 11 Pro", "22631.3000", ("Contoso App", "2.0")), cat));
        // product not installed ⇒ not a gap; wrong OS ⇒ not a gap:
        Assert.Empty(PatchScanner.DetermineMissing(Record("dev1", "Windows 11 Pro", "22631.3000"), cat));
        Assert.Empty(PatchScanner.DetermineMissing(
            Record("dev1", "Ubuntu Linux 24.04", "1000", ("Contoso App", "1.0")), cat));
    }

    [Fact]
    public void RMM02_Scan_VersionSemantics_NineIsOlderThanTen()
    {
        var cat = new PatchCatalogue();
        cat.AddOrReplace(ThirdParty() with { FixedInVersion = "10.0" });
        var missing = PatchScanner.DetermineMissing(
            Record("dev1", "Windows 11 Pro", "22631.3000", ("Contoso App", "9.0")), cat);
        Assert.Single(missing); // string order would say "9.0" > "10.0"; version order knows better
    }

    [Fact]
    public void RMM02_Targeting_RidesInventoryQueryEngine()
    {
        var store = new InventoryStore();
        Assert.True(store.ApplyBaseline(Record("dev1", "Windows 11 Pro", "22631.3000", ("Contoso App", "1.5")), T0).Accepted);
        Assert.True(store.ApplyBaseline(Record("dev2", "Windows 11 Pro", "22631.3000", ("Contoso App", "2.0")), T0).Accepted);
        Assert.True(store.ApplyBaseline(Record("dev3", "Windows 11 Pro", "22631.3000", ("Other App", "1.0")), T0).Accepted);
        var targets = PatchTargeting.FindTargets(store, ThirdParty(), T0);
        Assert.Equal(new[] { "dev1" }, targets);
    }

    // ---- approvals ----------------------------------------------------

    [Fact]
    public void RMM02_ApprovalRules_AutoManualReject_ByClassificationSeverityKb()
    {
        var policy = new ApprovalPolicy(new[]
        {
            new ApprovalRule("reject-test-kb", ApprovalMode.Reject, KbId: "KB0000000"),
            new ApprovalRule("auto-low", ApprovalMode.AutoApprove, Severity: "low"),
            new ApprovalRule("manual-critical", ApprovalMode.RequireManual, Severity: "critical"),
        });
        Assert.Equal(ApprovalMode.AutoApprove, policy.Evaluate(ThirdParty() with { Severity = "low" }).Mode);
        Assert.Equal(ApprovalMode.RequireManual, policy.Evaluate(OsKb()).Mode); // critical severity rule
        Assert.Equal(ApprovalMode.Reject, policy.Evaluate(OsKb() with { KbId = "KB0000000", Id = "KB0000000" }).Mode);
        // no rule matches ⇒ manual (fail closed), never auto:
        Assert.Equal(ApprovalMode.RequireManual, policy.Evaluate(ThirdParty()).Mode);
        Assert.Equal(ApprovalMode.RequireManual, ApprovalPolicy.ManualOnly.Evaluate(ThirdParty()).Mode);
    }

    [Fact]
    public void RMM02_ApprovalStore_ContradictionRefused_RejectBeatsFleetApproval()
    {
        var store = new PatchApprovalStore();
        var entry = ThirdParty();
        Assert.True(store.Record(new ApprovalDecisionRecord(entry.Id, entry.ContentHash, "*",
            ApprovalDecisions.Approved, "admin-a", T0, "manual approval")).Recorded);
        // a device-scope reject beats the fleet approval for that device:
        Assert.True(store.Record(new ApprovalDecisionRecord(entry.Id, entry.ContentHash, "dev9",
            ApprovalDecisions.Rejected, "admin-b", T0, "manual rejection")).Recorded);
        Assert.False(store.CheckCurrent(entry, "dev9").Approved);
        Assert.True(store.CheckCurrent(entry, "dev1").Approved);
        // contradicting the standing fleet decision at the same scope refuses:
        Assert.False(store.Record(new ApprovalDecisionRecord(entry.Id, entry.ContentHash, "*",
            ApprovalDecisions.Rejected, "admin-c", T0, "manual rejection")).Recorded);
        // a decision with no decider is not a decision:
        Assert.False(store.Record(new ApprovalDecisionRecord(entry.Id, entry.ContentHash, "*",
            ApprovalDecisions.Approved, "", T0, "manual approval")).Recorded);
    }

    // ---- deployment ---------------------------------------------------

    [Fact]
    public void RMM02_Deploy_HappyPath_JobCompletes_AuditChained()
    {
        var rig = NewRig();
        var entry = ThirdParty();
        rig.Service.AdmitEntries(new[] { entry }, "test");
        Assert.True(rig.Service.Decide(Facts(), entry.Id, "dev1", approve: true, decidedBy: "admin-1").Ok);
        var (manifest, sources) = HubSource(Payload);
        var applier = new FakeApplier();
        var result = rig.Service.Deploy(Facts(), entry.Id, DeployEnv(rig, entry), manifest, sources, applier, "/tmp/payload.bin");
        Assert.True(result.Ok, result.Reason);
        Assert.Equal(1, applier.Calls);
        var job = rig.Service.Journal.GetJob(result.JobId!)!;
        Assert.Equal(JobStates.Done, job.State);
        Assert.Equal(5, job.CompletedSteps);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "patch_deployed");
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "patch_approved");
        Assert.True(rig.Audit.Verify().Ok);
        // the journal persisted to the Core data-dir shape:
        Assert.True(File.Exists(rig.Service.JournalPath));
    }

    [Fact]
    public void RMM02_Deploy_AutoApprovalRule_RecordsTheRuleAsDecider()
    {
        // SUPERSEDED SEMANTICS (D38 F6, fix lane): this test
        // originally asserted that DEPLOY itself ran the auto rule
        // and recorded the approval. That deploy-time re-evaluation
        // was the laundering seam — Deploy now only CHECKS currency;
        // auto-evaluation is the explicit AutoEvaluate act below.
        var rig = NewRig();
        rig.Service.ApprovalPolicy = new ApprovalPolicy(new[]
        {
            new ApprovalRule("auto-security-high", ApprovalMode.AutoApprove, Classification: "security", Severity: "high"),
        });
        var entry = ThirdParty();
        rig.Service.AdmitEntries(new[] { entry }, "test");
        var evaluated = rig.Service.AutoEvaluate(Facts(), entry.Id, "dev1");
        Assert.Equal(ApprovalMode.AutoApprove, evaluated.Mode);
        var (manifest, sources) = HubSource(Payload);
        var result = rig.Service.Deploy(Facts(), entry.Id, DeployEnv(rig, entry), manifest, sources, new FakeApplier(), "/tmp/p.bin");
        Assert.True(result.Ok, result.Reason);
        Assert.Contains(rig.Service.Approvals.Records,
            r => r.Decision == ApprovalDecisions.Approved && r.DecidedBy == "policy:auto-security-high");
    }

    [Fact]
    public void RMM02_Deploy_OsChannelPatch_NoPayloadRides()
    {
        var rig = NewRig();
        var entry = OsKb();
        rig.Service.AdmitEntries(new[] { entry }, "test");
        rig.Service.Decide(Facts(), entry.Id, "*", approve: true, decidedBy: "admin-1");
        var result = rig.Service.Deploy(Facts(), entry.Id, DeployEnv(rig, entry), null,
            Array.Empty<IContentSource>(), new FakeApplier(), "/tmp/kb.msu");
        Assert.True(result.Ok, result.Reason);
        Assert.Equal(RebootStates.PendingWindow, result.Reboot!.State); // Saturday noon is outside the weekday-night window
    }

    [Fact]
    public void RMM02_PolicyToggleOff_ScanAndDeployRefuse()
    {
        var rig = NewRig();
        rig.Policies.AdmitLocalDocument(new ManagementPolicyDocument(
            "patch-off", PolicyLevels.Device, "dev1",
            new Dictionary<string, string> { ["rmm.patch.enabled"] = "false" }, 1), "test");
        var entry = ThirdParty();
        rig.Service.AdmitEntries(new[] { entry }, "test");
        var scan = rig.Service.Scan(Facts(), Record("dev1", "Windows 11 Pro", "22631.1000", ("Contoso App", "1.5")));
        Assert.False(scan.Ok);
        var (manifest, sources) = HubSource(Payload);
        var deploy = rig.Service.Deploy(Facts(), entry.Id, DeployEnv(rig, entry), manifest, sources, new FakeApplier(), "/tmp/p.bin");
        Assert.False(deploy.Ok);
        Assert.Contains("rmm.patch.enabled", deploy.Reason);
    }

    // ---- rings ---------------------------------------------------------

    private static RolloutPlan TwoRingPlan(PatchCatalogueEntry entry) => new("plan-1", entry.Id, entry.ContentHash, new[]
    {
        new RingDefinition("test", 0, 1.0, new[] { "dev1" }),
        new RingDefinition("fleet", 1, 0.8, new[] { "dev2", "dev3", "dev4", "dev5", "dev6" }),
    });

    [Fact]
    public void RMM02_Rings_OrderEnforced_ThresholdCompletes()
    {
        var plan = TwoRingPlan(ThirdParty());
        Assert.False(plan.StartRing("fleet").Ok); // test ring not complete
        Assert.True(plan.StartRing("test").Ok);
        Assert.True(plan.RecordOutcome("test", "dev1", true, T0).Ok);
        Assert.Equal(RingStates.Complete, plan.StatusOf("test").State);
        Assert.True(plan.StartRing("fleet").Ok);
        foreach (var d in new[] { "dev2", "dev3", "dev4", "dev5" })
            Assert.True(plan.RecordOutcome("fleet", d, true, T0).Ok);
        // 4/5 = 80% meets the 0.8 threshold exactly when the last outcome lands:
        var last = plan.RecordOutcome("fleet", "dev6", false, T0);
        Assert.True(last.Ok);
        Assert.Equal(RingStates.Complete, plan.StatusOf("fleet").State);
    }

    [Fact]
    public void RMM02_Ring_HaltsEarly_WhenThresholdBecomesUnreachable()
    {
        var plan = new RolloutPlan("plan-halt", "Contoso.App", ThirdParty().ContentHash, new[]
        {
            new RingDefinition("pilot", 0, 0.75, new[] { "a", "b", "c", "d" }),
        });
        Assert.True(plan.StartRing("pilot").Ok);
        Assert.True(plan.RecordOutcome("pilot", "a", false, T0).Ok);
        Assert.Equal(RingStates.InProgress, plan.StatusOf("pilot").State); // 3/4 still reachable
        var second = plan.RecordOutcome("pilot", "b", false, T0);
        Assert.True(second.Ok);
        var status = plan.StatusOf("pilot");
        Assert.Equal(RingStates.Halted, status.State); // best possible now 2/4 = 50% < 75%
        Assert.NotNull(status.HaltEvidence);
        Assert.Equal(2, status.HaltEvidence!.Failed);
        Assert.Contains("unreachable", status.HaltEvidence.Reason);
        // a halted ring records no further outcomes and cannot restart:
        Assert.False(plan.RecordOutcome("pilot", "c", true, T0).Ok);
        Assert.False(plan.StartRing("pilot").Ok);
    }

    [Fact]
    public void RMM02_RingGate_BlocksDeploy_UntilRingInProgress_AndRecordsOutcome()
    {
        var rig = NewRig();
        var entry = ThirdParty();
        rig.Service.AdmitEntries(new[] { entry }, "test");
        rig.Service.Decide(Facts(), entry.Id, "*", approve: true, decidedBy: "admin-1");
        var plan = TwoRingPlan(entry);
        Assert.True(rig.Service.Rollouts.Add(plan).Ok);
        var (manifest, sources) = HubSource(Payload);
        // ring not started ⇒ gated:
        var gated = rig.Service.Deploy(Facts(), entry.Id, DeployEnv(rig, entry), manifest, sources, new FakeApplier(), "/tmp/p.bin");
        Assert.False(gated.Ok);
        Assert.Contains("ring", gated.Reason);
        // ring in progress ⇒ deploys. SUPERSEDED SEMANTICS
        // (D38 F5, fix lane): the deploy alone no longer completes
        // the ring — building an apply plan is not an installation.
        // The ring outcome lands only when install is CONFIRMED:
        Assert.True(plan.StartRing("test").Ok);
        var ok = rig.Service.Deploy(Facts(), entry.Id, DeployEnv(rig, entry), manifest, sources, new FakeApplier(), "/tmp/p.bin");
        Assert.True(ok.Ok, ok.Reason);
        Assert.Equal(RingStates.InProgress, plan.StatusOf("test").State);
        Assert.Equal(0, plan.StatusOf("test").Succeeded);
        var confirmed = rig.Service.ConfirmInstall(entry.Id, "dev1", verified: true, evidence: "test: inventory shows fixed version");
        Assert.True(confirmed.Ok, confirmed.Reason);
        Assert.Equal(RingStates.Complete, plan.StatusOf("test").State); // 1/1 at threshold 1.0
    }

    [Fact]
    public void RMM02_RingResume_SignedDecision_MovesHaltedRing()
    {
        var rig = NewRig();
        var entry = ThirdParty();
        rig.Service.AdmitEntries(new[] { entry }, "test");
        var plan = new RolloutPlan("plan-r", entry.Id, entry.ContentHash, new[]
        {
            new RingDefinition("pilot", 0, 0.75, new[] { "a", "b", "c", "d" }),
        });
        rig.Service.Rollouts.Add(plan);
        plan.StartRing("pilot");
        plan.RecordOutcome("pilot", "a", false, T0);
        plan.RecordOutcome("pilot", "b", false, T0);
        var halted = plan.StatusOf("pilot");
        Assert.Equal(RingStates.Halted, halted.State);
        var payload = $"ring_resume|plan-r|pilot|{halted.HaltEvidence!.EvidenceHash}";
        var env = rig.Signer.Sign(SignedCommandClasses.PatchDeploy, Encoding.UTF8.GetBytes(payload), T0, TimeSpan.FromHours(1));
        var resumed = rig.Service.ResumeRing("plan-r", "pilot", env, "admin-1");
        Assert.True(resumed.Ok, resumed.Reason);
        Assert.Equal(RingStates.InProgress, plan.StatusOf("pilot").State);
        // recorded outcomes STAND after resume (the failures are not erased):
        Assert.Equal(2, plan.StatusOf("pilot").Failed);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "patch_ring_resumed");
    }

    // ---- reboot ----------------------------------------------------------

    [Fact]
    public void RMM02_RebootGate_WindowDeferralAndCriticalDeadline()
    {
        var policy = RebootPolicy.Default; // weekday nights 01:00–04:00, 2 deferrals, critical 72h
        var kb = OsKb(); // critical, requires reboot
        var mondayNight = new DateTimeOffset(2026, 11, 23, 2, 0, 0, TimeSpan.Zero); // Monday 02:00
        var mondayNoon = new DateTimeOffset(2026, 11, 23, 12, 0, 0, TimeSpan.Zero);
        // in window ⇒ permitted:
        Assert.True(RebootGate.Evaluate(kb, policy, mondayNoon.AddDays(-1), 0, mondayNight).RebootPermittedNow);
        // outside window, deferrals remain ⇒ pending, not permitted:
        var pending = RebootGate.Evaluate(kb, policy, mondayNoon.AddHours(-1), 0, mondayNoon);
        Assert.Equal(RebootStates.PendingWindow, pending.State);
        Assert.False(pending.RebootPermittedNow);
        // deferrals exhausted outside window ⇒ enforced at next window, NOT now:
        var exhausted = RebootGate.Evaluate(kb, policy, mondayNoon.AddHours(-1), 2, mondayNoon);
        Assert.Equal(RebootStates.Enforced, exhausted.State);
        Assert.False(exhausted.RebootPermittedNow);
        // critical deadline passed ⇒ enforced NOW even outside the window:
        var deadline = RebootGate.Evaluate(kb, policy, mondayNoon.AddHours(-100), 0, mondayNoon);
        Assert.Equal(RebootStates.Enforced, deadline.State);
        Assert.True(deadline.RebootPermittedNow);
        // non-reboot patch ⇒ not required:
        Assert.Equal(RebootStates.NotRequired,
            RebootGate.Evaluate(ThirdParty(), policy, T0, 0, mondayNoon).State);
    }

    [Fact]
    public void RMM02_DeferralLimit_IsHard_InService()
    {
        var rig = NewRig();
        rig.Service.RebootPolicy = RebootPolicy.Default with { MaxDeferrals = 2 };
        rig.Service.AdmitEntries(new[] { OsKb() }, "test");
        Assert.True(rig.Service.RecordDeferral("KB5034441", "dev1").Ok);
        Assert.True(rig.Service.RecordDeferral("KB5034441", "dev1").Ok);
        var third = rig.Service.RecordDeferral("KB5034441", "dev1");
        Assert.False(third.Ok);
        Assert.Equal(2, rig.Service.DeferralCount("KB5034441", "dev1"));
    }

    // ---- appliers + steps --------------------------------------------------

    [Fact]
    public void RMM02_ApplierShapes_BuildCleanCommandPlans_PerOs()
    {
        var win = new WindowsPatchApplier();
        var third = win.BuildApply(new PatchApplyRequest(ThirdParty(), "/tmp/p.bin", "dev1"));
        Assert.True(third.Ok, third.Detail);
        Assert.Equal("winget", third.InstallPlan!.Executable);
        Assert.Contains("Contoso.App", third.InstallPlan.Arguments);
        var kb = win.BuildApply(new PatchApplyRequest(OsKb(), "/tmp/kb.msu", "dev1"));
        Assert.Equal("wusa.exe", kb.InstallPlan!.Executable);
        var cab = win.BuildApply(new PatchApplyRequest(OsKb(), "/tmp/kb.cab", "dev1"));
        Assert.Equal("dism.exe", cab.InstallPlan!.Executable);

        var mac = new MacOsPatchApplier();
        var macKb = OsKb() with { TargetOs = "macos", KbId = "macOS-14.2", Id = "macOS-14.2" };
        Assert.Equal("/usr/sbin/softwareupdate", mac.BuildApply(new PatchApplyRequest(macKb, "/tmp/x", "dev1")).InstallPlan!.Executable);

        var linux = new LinuxPatchApplier();
        var linuxEntry = ThirdParty() with { TargetOs = "linux" };
        var apt = linux.BuildApply(new PatchApplyRequest(linuxEntry, "/tmp/x.deb", "dev1"));
        Assert.Equal("apt-get", apt.InstallPlan!.Executable);
        // UPDATED (Wave 2 Lane B, 2026-11-22) for bd-shared-rmm-2/F1:
        // a staged .deb payload installs FROM THE VERIFIED LOCAL FILE,
        // not from the repository at "package=version" — the old
        // assertion encoded exactly the supply-chain gap F1 names.
        Assert.Contains("/tmp/x.deb", apt.InstallPlan.Arguments);
        Assert.DoesNotContain("Contoso.App=2.0", apt.InstallPlan.Arguments);
    }

    [Fact]
    public void RMM02_RunSteps_HonestIdempotencyMarks()
    {
        var steps = PatchRunSteps.For(ThirdParty());
        Assert.Equal(StepIdempotency.Idempotent, steps.Single(s => s.StepId == PatchRunSteps.Fetch).Idempotency);
        Assert.Equal(StepIdempotency.Idempotent, steps.Single(s => s.StepId == PatchRunSteps.VerifyPayload).Idempotency);
        // apply is the one step whose mid-flight interruption is
        // genuinely unknowable — it must NOT claim idempotency:
        Assert.Equal(StepIdempotency.NonIdempotent, steps.Single(s => s.StepId == PatchRunSteps.Apply).Idempotency);
        Assert.Equal(StepIdempotency.Idempotent, steps.Single(s => s.StepId == PatchRunSteps.VerifyInstall).Idempotency);
        Assert.Equal(StepIdempotency.Idempotent, steps.Single(s => s.StepId == PatchRunSteps.RebootGateStep).Idempotency);
    }

    // ---- offline convergence (RMM-15 consumption) ----------------------------

    [Fact]
    public void RMM02_OfflineConvergence_ParkedRun_SurfacesOnRestart_NeverAutoResolved()
    {
        var rig = NewRig();
        var entry = ThirdParty();
        // A run that crashed MID-APPLY (the non-idempotent step):
        var journal = new JobJournal(rig.Endpoint);
        var env = DeployEnv(rig, entry);
        var job = journal.CreateJob(JobKinds.PatchRun, "dev1", PatchRunSteps.For(entry), env, T0)!;
        journal.StartJob(job.Id, T0);
        journal.BeginStep(job.Id, PatchRunSteps.Fetch, T0);
        journal.CompleteStep(job.Id, PatchRunSteps.Fetch, T0);
        journal.BeginStep(job.Id, PatchRunSteps.VerifyPayload, T0);
        journal.CompleteStep(job.Id, PatchRunSteps.VerifyPayload, T0);
        journal.BeginStep(job.Id, PatchRunSteps.Apply, T0); // <-- crash here
        journal.SaveToFile(rig.Service.JournalPath);

        // The endpoint restarts: PatchService.Start imports + resumes.
        var report = rig.Service.Start(Facts());
        Assert.True(report.ChainOk);
        var state = rig.Service.BuildStateReport(Facts());
        var summary = Assert.Single(state.Jobs);
        Assert.Equal(JobStates.Parked, summary.State); // parked for a human, NOT resumed, NOT failed silently
        Assert.Equal(JobFailureReasons.NonIdempotentUncertain, summary.FailureReason);
        // a second start pass leaves the parked job exactly as it was:
        rig.Service.Start(Facts());
        Assert.Equal(JobStates.Parked, rig.Service.Journal.GetJob(job.Id)!.State);
    }

    [Fact]
    public void RMM02_SignedCatalogueDelivery_VerifiesBeforeParsing()
    {
        var rig = NewRig();
        var entries = new[] { ThirdParty() };
        var json = System.Text.Json.JsonSerializer.Serialize(entries);
        var env = rig.Signer.Sign(SignedCommandClasses.PatchDeploy, Encoding.UTF8.GetBytes(json), T0, TimeSpan.FromHours(1));
        var ok = rig.Service.ImportCatalogueSigned(env);
        Assert.True(ok.Ok, ok.Reason);
        Assert.NotNull(rig.Service.Catalogue.Get("Contoso.App"));
        // an unsigned delivery (no envelope) refuses and admits nothing new:
        var refused = rig.Service.ImportCatalogueSigned(null);
        Assert.False(refused.Ok);
    }
}
