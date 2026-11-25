using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Acp.Core.Ipc;
using Acp.Core.Services;
using Acp.Shared.Enterprise;
using Acp.Shared.Enrollment;
using Acp.Shared.Hub;
using Acp.Shared.Inventory;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Reporting;
using Acp.Shared.Roster;
using Acp.Shared.Runbooks;
using Acp.Shared.Security;
using Acp.Shared.Sessions;
using Acp.Shared.SoftwareMetering;
using Acp.Shared.Streaming;
using Acp.Shared.Tools;
using Acp.Shared.Vulnerability;

namespace Acp.Tests;

// BD-WIN-CORE-4 fix lane — permanent regression tests for the
// reconciled bd-win-core-4 packet (6dc29225). One or more tests
// per CONFIRMED finding; F1 was a packet-labelling artefact
// (payload was Services-only by construction) and has no code test.
public class BdWinCore4FixTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 22, 12, 0, 0, TimeSpan.Zero);

    // ================= F2/F11: StreamService =================

    private sealed class FakeChannel : IAgentChannel
    {
        public bool AgentConnected { get; set; } = true;
        public List<(string Tool, string Args)> Calls { get; } = new();
        public Func<string, string, ToolResult> Handler { get; set; } = (_, _) => ToolResult.Success("ok");
        public Task<ToolResult> CallDesktopToolAsync(string tool, string argumentsJson, CancellationToken ct)
        {
            lock (Calls) Calls.Add((tool, argumentsJson));
            return Task.FromResult(Handler(tool, argumentsJson));
        }
        public int CountTool(string tool) { lock (Calls) return Calls.Count(c => c.Tool == tool); }
        public int InputToolCalls => CountTool("mouse_move_rel") + CountTool("mouse_move_abs_stream")
            + CountTool("button_here") + CountTool("key_press") + CountTool("type_text") + CountTool("scroll");
    }

    private sealed class StreamFixture
    {
        public RosterService Roster { get; }
        public SessionService Sessions { get; }
        public FakeChannel Channel { get; } = new();
        public StreamService Service { get; }
        public string DeviceId { get; }

        public StreamFixture()
        {
            var enrollments = new EnrollmentService();
            Roster = new RosterService(enrollments);
            Assert.NotNull(Roster.CreateScope("company-1", "company", "Company A"));
            Assert.NotNull(Roster.CreateUser("admin", "company-1", "Admin", "human"));
            Assert.True(Roster.AddCompanyAdmin("company-1", "admin"));
            Assert.NotNull(Roster.CreateUser("host", "company-1", "Host User", "human"));
            Assert.NotNull(Roster.CreateUser("ctrl", "company-1", "Controller", "human"));
            Assert.NotNull(Roster.CreateUser("peer", "company-1", "Peer", "human"));
            Assert.NotNull(Roster.CreateUserGroup("ug-1", "company-1", "Techs", new[] { "ctrl", "host", "peer" }));
            Assert.NotNull(Roster.CreateDeviceGroup("dg-1", "company-1", "Fleet", new[] { "lan", "hub" }));
            Assert.NotNull(Roster.AddGrant("company-1", "ug-1", "dg-1", new[] { "use" }));
            var identity = new DeviceIdentity(new DevOnlyPassThroughProtector());
            var code = enrollments.CreateEnrollmentCode("company", "dg-1", "Fleet");
            var device = enrollments.Redeem(code, new EnrollingDevice(identity.DeviceId, identity.PublicKeyBase64, "Site PC"));
            Assert.NotNull(device);
            DeviceId = device!.DeviceId;
            Sessions = new SessionService(Roster, enrollments);
            Channel.Handler = (tool, _) => tool switch
            {
                "stream_start" => ToolResult.Success("{\"streaming\":true}"),
                "stream_frame" => ToolResult.Success(FrameJson(1)),
                _ => ToolResult.Success("ok"),
            };
            Service = new StreamService(Channel, Sessions, () => true, () => false,
                displayName: (scope, user) => Roster.GetUser(scope, user)?.DisplayName);
        }

        public string ActiveSession(string? floorTo = null)
        {
            var s = Sessions.CreateSession("company-1", DeviceId, "ctrl", "attended", "lan", "none");
            Assert.NotNull(s);
            Assert.True(Sessions.AcceptSession(s!.Id, "host", SessionAcceptOrigin.EndpointLocal));
            Assert.True(Sessions.StartSession(s.Id));
            Assert.True(Sessions.AddParticipant(s.Id, "peer", "controller", "ctrl"));
            if (floorTo is not null) Assert.True(Sessions.GrantFloor(s.Id, floorTo, "host"));
            return s.Id;
        }

        private static string FrameJson(long seq)
        {
            var header = new StreamProtocol.FrameHeader(seq, 100, 1_700_000_000_000, true, 1920, 1080, 0,
                "h264", "Test MFT", true, "dxgi", null, 3, 4);
            var au = new byte[] { 0, 0, 0, 1, 7, 0x64, 0x00 }.Concat(new byte[] { 0, 0, 0, 1, 8, 0xEE })
                .Concat(new byte[] { 0, 0, 0, 1, 5, 0x88 }).ToArray();
            var body = StreamProtocol.Pack(header, au);
            return JsonSerializer.Serialize(new { seq, data = Convert.ToBase64String(body) });
        }

        public string InputBody(string sessionId, string bodyUserId) =>
            JsonSerializer.Serialize(new { sessionId, userId = bodyUserId, @event = new { type = "key", key = "enter" } });
        public string StartBody(string sessionId, string bodyUserId) =>
            JsonSerializer.Serialize(new { sessionId, userId = bodyUserId, monitor = 0 });
    }

    [Fact]
    public async Task F2_Input_BodyNamesFloorHolder_AuthenticatedWatcher_Refused()
    {
        var f = new StreamFixture();
        var id = f.ActiveSession(floorTo: "ctrl");
        // The body CLAIMS to be the floor holder (ctrl); the
        // authenticated identity is the watcher (peer). Pre-fix the
        // body claim drove the desktop.
        var reply = await f.Service.PostInputAsync(f.InputBody(id, "ctrl"), "peer", default);
        Assert.Equal(403, reply.Status);
        Assert.Equal(0, f.Channel.InputToolCalls);
    }

    [Fact]
    public async Task F2_Input_NoAuthenticatedIdentity_401_BodyClaimBuysNothing()
    {
        var f = new StreamFixture();
        var id = f.ActiveSession(floorTo: "ctrl");
        var reply = await f.Service.PostInputAsync(f.InputBody(id, "ctrl"), null, default);
        Assert.Equal(401, reply.Status);
        Assert.Equal(0, f.Channel.InputToolCalls);
        // And the genuine holder under its authenticated identity works.
        Assert.Equal(200, (await f.Service.PostInputAsync(f.InputBody(id, "anyone"), "ctrl", default)).Status);
        Assert.Equal(1, f.Channel.InputToolCalls);
    }

    [Fact]
    public async Task F2_FrameAndStop_NonParticipantAuthenticated_Refused()
    {
        var f = new StreamFixture();
        var id = f.ActiveSession(floorTo: "ctrl");
        Assert.Equal(200, (await f.Service.StartAsync(f.StartBody(id, "x"), "ctrl", default)).Status);
        Assert.Equal(403, (await f.Service.GetFrameAsync(id, 0, "ghost", default)).Status);
        var stop = await f.Service.StopAsync(JsonSerializer.Serialize(new { sessionId = id }), "ghost", default);
        Assert.Equal(403, stop.Status);
        Assert.True(f.Service.IsStreaming(id)); // someone else's stream survives
        Assert.Equal(200, (await f.Service.GetFrameAsync(id, 0, "peer", default)).Status); // participant may view
    }

    [Fact]
    public async Task F11_SecondSessionStart_Refused_SingleCapturePerHost_StatsDieWithBinding()
    {
        var f = new StreamFixture();
        var id1 = f.ActiveSession(floorTo: "ctrl");
        var id2 = f.ActiveSession(floorTo: "ctrl");
        Assert.Equal(200, (await f.Service.StartAsync(f.StartBody(id1, "x"), "ctrl", default)).Status);
        var second = await f.Service.StartAsync(f.StartBody(id2, "x"), "ctrl", default);
        Assert.Equal(409, second.Status);
        Assert.Contains("single capture stream", Encoding.UTF8.GetString(second.Body));
        Assert.Equal(200, (await f.Service.StopAsync(JsonSerializer.Serialize(new { sessionId = id1 }), "ctrl", default)).Status);
        Assert.Equal(0, f.Service.Stats(id1).Started); // stats entry removed at teardown
    }

    // ================= F3: Tailscale Funnel parsing =================

    private static bool? Funnel(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return TailscaleCliProbe.ParseAllowFunnel(doc.RootElement);
    }

    [Fact]
    public void F3_Funnel_CompactJson_TrueEntryDetected()
    {
        // Pre-fix: the exact-whitespace substring '"AllowFunnel": {'
        // missed this compact shape and reported Funnel off.
        Assert.True(Funnel("{\"AllowFunnel\":{\"host.example:443\":true}}"));
        Assert.True(Funnel("{ \"AllowFunnel\" : { \"host.example:443\" : true } }"));
    }

    [Fact]
    public void F3_Funnel_AbsentOrEmpty_False_UnexpectedShape_Null()
    {
        Assert.False(Funnel("{\"TCP\":{}}"));
        Assert.False(Funnel("{\"AllowFunnel\":{}}"));
        Assert.False(Funnel("{\"AllowFunnel\":{\"h:443\":false}}"));
        Assert.Null(Funnel("{\"AllowFunnel\":\"yes\"}")); // unexpected shape → probe unreliable
    }

    // ================= F4: vulnerability reporting =================

    [Fact]
    public void F4_Posture_PolicyOff_RendersNotEvaluated_NotCleanFleet()
    {
        var input = new ReportBuilders.VulnPostureInput(0, 0, 0, 0, 0, 0,
            Acp.Shared.Vulnerability.FeedProvenance.None(T0),
            PolicyEnabled: false, RefusalReason: "disabled by policy (test)");
        var report = ReportBuilders.VulnerabilityPosture(input, "", T0);
        Assert.Equal(0, report.Counts["policy_enabled"]);
        Assert.Contains(report.Notes, n => n.Contains("not evaluated (policy off)"));
        Assert.Contains(report.Rows.SelectMany(r => r), v => v == "false");
    }

    [Fact]
    public void F4_ReadOnlyBuild_NoReopen_NoAuditWrite_GatedBuildStillReopens()
    {
        var rig = Rmm05Tests.RigWithFleet();
        rig.Service.ImportFeed(Rmm05Tests.Feed(), "admin");
        rig.Service.RunCorrelation(Rmm05Tests.Facts());
        var item = Assert.Single(rig.Service.Exposures.OpenItems());
        Assert.True(rig.Service.RecordCompensatingControl(item.Id,
            "Short-lived isolation control.", "owner-a", T0.AddDays(3), "doc", "tech").Ok);
        Assert.True(rig.Service.CloseWithControlEvidence(item.Id, "tech").Ok);
        rig.Clock.Now = T0.AddDays(4); // review date passed
        var auditCount = rig.Audit.Entries.Count;
        var readOnly = rig.Service.BuildReportReadOnly(Rmm05Tests.Facts());
        Assert.Equal(auditCount, rig.Audit.Entries.Count); // the read wrote nothing
        Assert.Equal(ExposureStates.Closed, rig.Service.Exposures.Get(item.Id)!.State); // not reopened
        Assert.Equal(0, readOnly.OpenCount);
        // The gated build keeps the old, audited behaviour.
        var gated = rig.Service.BuildReport(Rmm05Tests.Facts());
        Assert.Equal(ExposureStates.Open, rig.Service.Exposures.Get(item.Id)!.State);
        Assert.Equal(1, gated.OpenCount);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "vuln_exposure_reopened");
    }

    [Fact]
    public void F4_ReportingFleetRead_PolicyOff_SaysNotEvaluated()
    {
        var rig = Rmm05Tests.NewRig();
        // LANE W1 REPAIR (owed U4 re-verification of this filter):
        // the original construction targeted "" — policy admission
        // refuses a document with an empty target ("needs an id
        // and a target"), so the policy silently never landed and
        // the posture rendered policy_enabled=1. The org-wide
        // target is "*"; the admission verdict is now asserted so
        // a silent no-op fails HERE, not downstream.
        var admit = rig.Policies.AdmitLocalDocument(new ManagementPolicyDocument(
            "vuln-off", PolicyLevels.Org, "*",
            new Dictionary<string, string> { [VulnerabilityPolicyKeys.Enabled] = "false" }, 1), "test");
        Assert.True(admit.Allowed, admit.Reason);
        var reporting = new ReportingService(rig.Audit, rig.Policies, rig.Inventory,
            new DeviceIdentity(new DevOnlyPassThroughProtector()), vuln: rig.Service, now: () => T0);
        var result = reporting.FleetMcp.Call("fleet.vulnerability_posture", "",
            new HashSet<string> { FleetScopes.Read }, null, T0, "tester");
        Assert.True(result.Ok);
        Assert.Contains("not evaluated (policy off)", result.Text);
    }

    // ================= F5: fleet grant consumption audit =================

    [Fact]
    public void F5_PolicyOffCall_NeverRecordsGrantConsumed_RealRedemptionDoes()
    {
        var rig = Rmm13Tests.NewRig();
        rig.Service.FleetMcp.RegisterAction("fleet.test_action", "test action");
        var facts = Rmm13Tests.Facts();
        var scopes = new HashSet<string> { FleetScopes.Act };
        Rmm13Tests.SetPolicy(rig, "scope1", ReportingPolicyKeys.FleetMcpEnabled, "false");
        var denied = rig.Service.CallFleetTool(facts, "fleet.test_action", "{}",
            scopes, "apg-not-a-real-grant", "caller-1");
        Assert.False(denied.Ok);
        Assert.DoesNotContain(rig.Audit.Entries, e => e.Kind == "fleet_grant_consumed");

        var rig2 = Rmm13Tests.NewRig();
        rig2.Service.FleetMcp.RegisterAction("fleet.test_action", "test action");
        var grant = rig2.Service.GrantFleetApproval("fleet.test_action", "approver-1", "approver-2",
            TimeSpan.FromMinutes(5), argumentsJson: "{}", redeemingCaller: "caller-1");
        Assert.True(grant.Ok);
        var done = rig2.Service.CallFleetTool(facts, "fleet.test_action", "{}",
            scopes, grant.Grant!.GrantId, "caller-1");
        Assert.True(done.Ok);
        Assert.True(done.GrantConsumed);
        Assert.Contains(rig2.Audit.Entries, e => e.Kind == "fleet_grant_consumed");
    }

    // ================= F6: runbook approver/attester registry =================

    private RunbookService NewRunbookService(IEnumerable<string>? approvers, IEnumerable<string>? attesters)
    {
        var audit = new ChainedAuditLog();
        var engine = new ManagementPolicyEngine();
        var facts = StaticDeviceFacts.Of("dev1", "scope1");
        return new RunbookService(audit, engine, _ => facts, null, null,
            new Acp.Shared.Remediation.RecordingRemediationStepExecutor(),
            new RecordingRunbookCheckEvaluator(),
            () => Acp.Shared.Remediation.AutomationLibrary.Default(),
            now: () => T0,
            authorisedApproverIds: approvers, authorisedAttesterIds: attesters);
    }

    [Fact]
    public void F6_UnnamedApproval_AnySecondStringRefused_RegistryActorAccepted()
    {
        var svc = NewRunbookService(approvers: new[] { "lead-1" }, attesters: new[] { "lead-1" });
        Assert.True(svc.AdmitLocalLibrary(new RunbookLibrary("t", 1, new[]
        {
            RunbookDefinition.Create("gated", "gated", new[]
            {
                RunbookStep.Automated("a1", "step", "clear-temp", requiresApproval: true),
            }),
        }), "test").Allowed);
        var (run, _) = svc.StartRun("gated", "dev1", "tech-1", null, T0);
        Assert.Equal(RunbookRunStatuses.PausedAwaitingApproval, run!.Status);
        Assert.False(svc.ApproveStep(run.RunId, "a1", "made-up-name", T0).Ok);
        Assert.True(svc.ApproveStep(run.RunId, "a1", "lead-1", T0).Ok);
    }

    [Fact]
    public void F6_UnnamedAttestation_AnySecondStringRefused_RegistryActorAccepted()
    {
        var svc = NewRunbookService(approvers: new[] { "lead-1" }, attesters: new[] { "lead-1" });
        Assert.True(svc.AdmitLocalLibrary(new RunbookLibrary("t", 1, new[]
        {
            RunbookDefinition.Create("human", "human", new[]
            {
                RunbookStep.Human("h1", "confirm", "confirm it", requireDistinctAttester: true),
            }),
        }), "test").Allowed);
        var (run, _) = svc.StartRun("human", "dev1", "tech-1", null, T0);
        Assert.Equal(RunbookRunStatuses.PausedAwaitingAttestation, run!.Status);
        Assert.False(svc.Attest(run.RunId, "h1", "made-up-name", T0).Ok);
        Assert.True(svc.Attest(run.RunId, "h1", "lead-1", T0).Ok);
    }

    // ================= F7: deployment import atomicity =================

    [Fact]
    public void F7_ImportState_BrokenLaterElement_ImportsNothing()
    {
        var rig = new Rmm16Tests.Rig();
        var payload = JsonSerializer.Serialize(new
        {
            Assignments = new[] { new { PackageId = "widget", Version = "1.0.0", GroupIds = new[] { "grp" } } },
            State = new[] { new { DeviceId = "dev1", PackageId = "widget", InstalledVersion = "1.0.0", Status = "deployed" } }, // UpdatedUtc missing → throws
            PackRevisions = Array.Empty<object>(),
        });
        var wrapped = HubPersistence.Wrap("acp-software-deployment-state-v1", payload);
        Assert.Equal(0, rig.Service.ImportStateJson(wrapped));
        Assert.Empty(rig.Service.Assignments); // pre-fix: the assignment had already landed
        Assert.Null(rig.Service.StateFor("dev-1", "widget"));
    }

    // ================= F8: runbook run persistence =================

    [Fact]
    public void F8_ParkedRun_ExportImport_ResumesAtHumanStep()
    {
        var svc = NewRunbookService(approvers: new[] { "lead-1" }, attesters: new[] { "lead-1" });
        Assert.True(svc.AdmitLocalLibrary(new RunbookLibrary("t", 1, new[]
        {
            RunbookDefinition.Create("human", "human", new[]
            {
                RunbookStep.Human("h1", "confirm", "confirm it", requireDistinctAttester: true),
            }),
        }), "test").Allowed);
        var (run, _) = svc.StartRun("human", "dev1", "tech-1", null, T0);
        Assert.Equal(RunbookRunStatuses.PausedAwaitingAttestation, run!.Status);
        var exported = svc.ExportRunsJson();

        var svc2 = NewRunbookService(approvers: new[] { "lead-1" }, attesters: new[] { "lead-1" });
        Assert.Equal(1, svc2.ImportRunsJson(exported));
        var restored = svc2.GetRun(run.RunId);
        Assert.NotNull(restored);
        Assert.Equal(RunbookRunStatuses.PausedAwaitingAttestation, restored!.Status);
        // The parked run can still be decided after the "restart".
        Assert.True(svc2.Attest(run.RunId, "h1", "lead-1", T0).Ok);
        Assert.Equal(RunbookRunStatuses.Succeeded, svc2.GetRun(run.RunId)!.Status);
        // Tampered export imports nothing.
        var svc3 = NewRunbookService(null, null);
        Assert.Equal(0, svc3.ImportRunsJson(exported.Replace("human", "humax")));
    }

    // ================= F9: metering scope binding =================

    [Fact]
    public void F9_CrossScopeReads_Refused_SameScopeReads_Work()
    {
        var audit = new ChainedAuditLog();
        var engine = new ManagementPolicyEngine();
        var svcPolicies = new ManagementPolicyService(audit, null, engine, () => T0);
        var inventory = new InventoryStore();
        var svc = new SoftwareMeteringService(audit, svcPolicies, inventory, () => T0);
        var factsA = StaticDeviceFacts.Of("hub", "scope-a");
        var factsB = StaticDeviceFacts.Of("hub", "scope-b");
        Assert.True(svc.AddEntitlement(factsB, new LicenceEntitlement(
            "ent-b", "scope-b", "Widget", null, 5, null, "PO on file", "admin", T0, 1)).Ok);
        // Caller in scope-a naming scope-b: pre-fix this returned B's claims.
        Assert.Empty(svc.CurrentEntitlements(factsA, "scope-b"));
        Assert.Single(svc.CurrentEntitlements(factsB, "scope-b"));
        var (ok, _, reportB) = svc.GenerateReport(factsB);
        Assert.True(ok);
        Assert.Null(svc.GetStoredReport(factsA, reportB!.Header.ReportId)); // bare id is not a scope credential
        Assert.NotNull(svc.GetStoredReport(factsB, reportB.Header.ReportId));
        Assert.Empty(svc.ListStoredReports(factsA, "scope-b"));
    }

    // ================= F10: update pointer / slot integrity =================

    private static byte[] MakeZip(string content)
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            var entry = zip.CreateEntry("app.txt");
            using var w = new StreamWriter(entry.Open());
            w.Write(content);
        }
        return ms.ToArray();
    }

    [Fact]
    public async Task F10_CorruptMainPointer_FallsBackToLastKnownGood_NotSlotA()
    {
        var root = TestUtil.TempDir();
        using var verifier = new RsaUpdateSignatureVerifier();
        var updates = new UpdateManager(root, verifier, _ => Task.FromResult(true));
        var package = MakeZip("v2-content");
        Assert.True(updates.StagePackage(package, verifier.Sign(package), "2.0.0").Ok);
        Assert.True((await updates.ApplyStagedAsync(default)).Ok);
        Assert.Equal(UpdateSlot.B, updates.Status().ActiveSlot);
        await File.WriteAllTextAsync(Path.Combine(root, "active-slot.json"), "{torn");
        var status = updates.Status(); // backup carries B / 2.0.0 — pre-fix this said A / 0.1.0
        Assert.Equal(UpdateSlot.B, status.ActiveSlot);
        Assert.Equal("2.0.0", status.ActiveVersion);
    }

    [Fact]
    public async Task F10_TamperedStagedSlot_ApplyRefused_PointerUnchanged()
    {
        var root = TestUtil.TempDir();
        using var verifier = new RsaUpdateSignatureVerifier();
        var updates = new UpdateManager(root, verifier, _ => Task.FromResult(true));
        var package = MakeZip("genuine");
        Assert.True(updates.StagePackage(package, verifier.Sign(package), "2.0.0").Ok);
        var idleDir = Path.Combine(root, "slots", "B");
        await File.WriteAllTextAsync(Path.Combine(idleDir, "app.txt"), "tampered");
        var (ok, message) = await updates.ApplyStagedAsync(default);
        Assert.False(ok);
        Assert.Contains("no longer match", message);
        Assert.Equal(UpdateSlot.A, updates.Status().ActiveSlot);
        Assert.Equal("2.0.0", updates.Status().StagedVersion);
    }

    [Fact]
    public async Task F10_PolicyGate_GuardsApply_NotOnlyStage()
    {
        var root = TestUtil.TempDir();
        using var verifier = new RsaUpdateSignatureVerifier();
        var allow = true;
        var updates = new UpdateManager(root, verifier, _ => Task.FromResult(true),
            policyGate: v => allow ? (true, "") : (false, $"policy refuses version {v}"));
        var package = MakeZip("v2");
        Assert.True(updates.StagePackage(package, verifier.Sign(package), "2.0.0").Ok);
        allow = false; // policy changes between stage and apply
        var (ok, message) = await updates.ApplyStagedAsync(default);
        Assert.False(ok);
        Assert.Contains("policy refuses", message);
        Assert.Equal(UpdateSlot.A, updates.Status().ActiveSlot);
    }

    // ================= F12: rollback binary verification =================

    [Fact]
    public async Task F12_UnverifiedRollbackBinary_NeverSwappedIn()
    {
        var dir = TestUtil.TempDir();
        var exe = Path.Combine(dir, "AcpCore.exe");
        await File.WriteAllTextAsync(exe, "new-binary");
        await File.WriteAllTextAsync(exe + ".prev1", "attacker-dropped"); // no .sha256 sidecar
        var svc = new ScriptSvc();
        svc.StartResults.Enqueue(false); svc.StartResults.Enqueue(false); svc.StartResults.Enqueue(false);
        var tick = T0;
        var watchdog = new RestartWatchdog(svc, new FakeSink(),
            delay: (d, ct) => Task.CompletedTask, now: () => tick += TimeSpan.FromSeconds(1))
        { GracePeriod = TimeSpan.Zero, PollInterval = TimeSpan.Zero };
        var outcome = await watchdog.RunAsync("AcpCore", exe);
        Assert.Equal("failed", outcome.State);
        Assert.False(outcome.RollbackUsed);
        Assert.Contains("FAILED verification", outcome.Detail);
        Assert.Equal("new-binary", await File.ReadAllTextAsync(exe)); // untouched
    }

    [Fact]
    public void F12_VerifyRollbackBinary_SidecarHashLaw()
    {
        var dir = TestUtil.TempDir();
        var prev = Path.Combine(dir, "AcpCore.exe.prev1");
        File.WriteAllText(prev, "old-binary");
        Assert.False(RestartWatchdog.VerifyRollbackBinary(prev)); // no sidecar
        File.WriteAllText(prev + ".sha256",
            Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(prev))).ToLowerInvariant());
        Assert.True(RestartWatchdog.VerifyRollbackBinary(prev));
        File.WriteAllText(prev, "tampered");
        Assert.False(RestartWatchdog.VerifyRollbackBinary(prev)); // hash mismatch
    }

    // REGRESSION (watchdog-rollback diagnosis lane): the F12
    // sidecar itself matches FindRollbackBinary's "<exe>.prev*"
    // enumeration and is written AFTER its binary, so an
    // unfiltered newest-first pick returned the .sha256 text
    // file as the rollback "binary" — verification then refused
    // it and rollback NEVER happened in exactly the installer
    // layout F12 mandates. Enumeration must consider only real
    // binary candidates; verification is unchanged.
    [Fact]
    public void F12_FindRollbackBinary_SidecarIsNeverTheBinary()
    {
        var dir = TestUtil.TempDir();
        var exe = Path.Combine(dir, "AcpCore.exe");
        File.WriteAllText(exe, "new-binary");
        var prev = exe + ".prev1";
        File.WriteAllText(prev, "old-binary");
        // The installer-recorded sidecar, written last (newest).
        File.WriteAllText(prev + ".sha256",
            Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(prev))).ToLowerInvariant());
        // An orphan sidecar with no binary at all, newest of all:
        // still not a binary candidate.
        File.WriteAllText(exe + ".prev9.sha256",
            Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(prev))).ToLowerInvariant());
        Assert.Equal(prev, RestartWatchdog.FindRollbackBinary(exe));
    }

    [Fact]
    public async Task F12_Rollback_SidecarBesideRealPrevBinary_RollsBackAndVerifies()
    {
        var dir = TestUtil.TempDir();
        var exe = Path.Combine(dir, "AcpCore.exe");
        await File.WriteAllTextAsync(exe, "new-binary");
        var prev = exe + ".prev1";
        await File.WriteAllTextAsync(prev, "old-binary");
        await File.WriteAllTextAsync(prev + ".sha256",
            Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(prev))).ToLowerInvariant());
        var svc = new ScriptSvc();
        svc.StartResults.Enqueue(false); svc.StartResults.Enqueue(false); svc.StartResults.Enqueue(false);
        svc.StartResults.Enqueue(true); // the rolled-back binary starts
        var tick = T0;
        var watchdog = new RestartWatchdog(svc, new FakeSink(),
            delay: (d, ct) => Task.CompletedTask, now: () => tick += TimeSpan.FromSeconds(1))
        { GracePeriod = TimeSpan.Zero, PollInterval = TimeSpan.Zero };
        var outcome = await watchdog.RunAsync("AcpCore", exe);
        Assert.Equal("rolled_back", outcome.State);
        Assert.True(outcome.RollbackUsed);
        // The REAL previous binary — not its sidecar — was swapped
        // in, and it passed F12 verification to get there.
        Assert.Equal("old-binary", await File.ReadAllTextAsync(exe));
    }

    private sealed class ScriptSvc : Acp.Core.Modules.IServiceProvider
    {
        public bool Available => true;
        public string State = "Running";
        public Queue<bool> StartResults { get; } = new();
        public IReadOnlyList<Acp.Core.Modules.ServiceInfo> List() =>
            new[] { new Acp.Core.Modules.ServiceInfo("AcpCore", "AcpCore", State, "Automatic") };
        public Acp.Core.Modules.ServiceInfo? Status(string name) => new(name, name, State, "Automatic");
        public void Start(string name) { if ((StartResults.Count > 0 ? StartResults.Dequeue() : true)) State = "Running"; }
        public void Stop(string name) => State = "Stopped";
        public void Restart(string name) { }
    }

    private sealed class FakeSink : IRestartOutcomeSink
    {
        public List<RestartOutcome> Outcomes { get; } = new();
        public void WriteOutcome(RestartOutcome outcome) => Outcomes.Add(outcome);
        public void Loud(string detail) { }
    }
}
