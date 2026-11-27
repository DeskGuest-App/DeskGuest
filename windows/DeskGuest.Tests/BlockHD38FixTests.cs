using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DeskGuest.Core.Modules;
using DeskGuest.Core.Services;
using DeskGuest.Shared.Enrollment;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.Presence;
using DeskGuest.Shared.Roster;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.Sessions;
using DeskGuest.Shared.Tools;
using IServiceProvider = DeskGuest.Core.Modules.IServiceProvider;

namespace DeskGuest.Tests;

/// <summary>Block H D38 FIX lane — regression tests for the 12
/// cross-review findings (packet 976cfa4d, FAIL).
/// F1 rotation-pending persistence, F2 rotate authority,
/// F3 MCP actor binding, F4 watchdog target identity,
/// F5 rollback swap honesty, F6 policy fail-closed,
/// F7 tunnel policy on import/liveness, F9 grant re-reads,
/// F10 device-presence stops, F11 outcome channel,
/// F12 second-factor throttle DoS. (F8 was rebutted by tree
/// evidence — see the lane log; no code change, no test.)</summary>
public class BlockHD38FixTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);

    // ---- shared world (BlockHTests fixture shape) ----

    private sealed class World
    {
        public required EnrollmentService Enrollments { get; init; }
        public required RosterService Roster { get; init; }
        public SessionService Sessions { get; set; } = null!;
        public required string DeviceId { get; init; }
        public HashSet<string> Disabled { get; } = new();
    }

    private static World Setup()
    {
        var enrollments = new EnrollmentService();
        var roster = new RosterService(enrollments);
        Assert.NotNull(roster.CreateScope("personal-1", "personal", "Personal"));
        Assert.NotNull(roster.CreateScope("company-1", "company", "Company A"));
        Assert.NotNull(roster.CreateUser("owner", "personal-1", "Owner One", "human"));
        Assert.NotNull(roster.CreateUser("admin", "company-1", "Admin", "human"));
        Assert.True(roster.AddCompanyAdmin("company-1", "admin"));
        Assert.NotNull(roster.CreateUser("host", "company-1", "Host User", "human"));
        Assert.NotNull(roster.CreateUser("ctrl", "company-1", "Controller", "human"));
        Assert.NotNull(roster.CreateUser("peer", "company-1", "Peer", "human"));
        Assert.NotNull(roster.CreateUser("ai-1", "company-1", "Agent One", "ai", pairedByUserId: "admin"));
        Assert.NotNull(roster.CreateUserGroup("ug-1", "company-1", "Techs",
            new[] { "ctrl", "host", "peer", "ai-1" }));
        Assert.NotNull(roster.CreateDeviceGroup("dg-1", "company-1", "Fleet", new[] { "lan", "hub" }));
        Assert.NotNull(roster.AddGrant("company-1", "ug-1", "dg-1", new[] { "use" }));

        var identity = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var code = enrollments.CreateEnrollmentCode("company", "dg-1", "Fleet");
        var device = enrollments.Redeem(code, new EnrollingDevice(identity.DeviceId, identity.PublicKeyBase64, "Site PC"));
        Assert.NotNull(device);

        var w = new World { Enrollments = enrollments, Roster = roster, Sessions = null!, DeviceId = device!.DeviceId };
        w.Sessions = new SessionService(roster, enrollments,
            (scopeId, key) => w.Disabled.Contains(key)
                ? new PolicyVerdict(false, $"feature '{key}' disabled by test policy")
                : new PolicyVerdict(true, "permitted by test policy"),
            (scopeId, key) => false);
        return w;
    }

    private static string ActiveSession(World w, string initiator = "ctrl")
    {
        var s = w.Sessions.CreateSession("company-1", w.DeviceId, initiator, "attended", "lan");
        Assert.NotNull(s);
        Assert.True(w.Sessions.AcceptSession(s!.Id, "host", SessionAcceptOrigin.EndpointLocal));
        Assert.True(w.Sessions.StartSession(s.Id));
        return s.Id;
    }

    private static ToolExecutionContext Ctx(string agentName = "test-agent", string dataDir = "unused",
        IReadOnlySet<string>? gates = null) =>
        new(new Pairing("p1", agentName, Scopes.All, T0, null, null, false),
            TestUtil.Session(), TestUtil.State(), gates ?? new HashSet<string>(), dataDir);

    private static JsonElement Args(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.Clone();
    }

    // ================= F1 + F2: break-glass =================

    private static string Sha256Hex(string s) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(s))).ToLowerInvariant();

    private static EnterpriseService BreakGlassWorld(string dataDir)
    {
        var holders = new[]
        {
            new { holderId = "holder-a", secretSha256 = Sha256Hex("secret-a") },
            new { holderId = "holder-b", secretSha256 = Sha256Hex("secret-b") },
        };
        File.WriteAllText(Path.Combine(dataDir, "breakglass-holders.json"), JsonSerializer.Serialize(holders));
        return LoadWorld(dataDir);
    }

    private static EnterpriseService LoadWorld(string dataDir) =>
        new(dataDir, new RosterService(new EnrollmentService()), () => T0);

    [Fact]
    public void F1_RotationPending_SurvivesRestartBetweenUseAndRotate()
    {
        var dir = TestUtil.TempDir();
        var svc = BreakGlassWorld(dir);
        var used = svc.UseBreakGlass("co1", "holder-a", "secret-a", "holder-b", "secret-b", "drill", true);
        Assert.True(used.Ok, used.Detail);
        Assert.True(svc.BreakGlass.RotationRequired);

        // A Core restart (a fresh service over the same data dir)
        // must NOT clear the pending rotation — that was the
        // BAD-32 defeat: restart, and the exposed pair worked again.
        var fresh = LoadWorld(dir);
        Assert.True(fresh.BreakGlass.RotationRequired);
        Assert.Equal(new[] { "holder-a", "holder-b" }, fresh.BreakGlass.RotationPendingHolders);
        Assert.Null(fresh.BreakGlass.Use("co1", "holder-a", "secret-a", "holder-b", "secret-b", "again", true, T0));

        // One holder rotates; another restart: still pending for
        // the other, and the rotated holder's new secret is durable.
        Assert.True(fresh.RotateBreakGlassHolders("holder-a",
            new[] { ("holder-a", "secret-a", "secret-a2") }).Ok);
        var fresher = LoadWorld(dir);
        Assert.True(fresher.BreakGlass.RotationRequired);
        Assert.Equal(new[] { "holder-b" }, fresher.BreakGlass.RotationPendingHolders);
        Assert.True(fresher.RotateBreakGlassHolders("holder-b",
            new[] { ("holder-b", "secret-b", "secret-b2") }).Ok);
        var done = LoadWorld(dir);
        Assert.False(done.BreakGlass.RotationRequired);
        Assert.NotNull(done.BreakGlass.Use("co1", "holder-a", "secret-a2", "holder-b", "secret-b2", "rotated", true, T0));
    }

    [Fact]
    public void F2_Rotate_RequiresTheHolderThemself_WithCurrentSecretProof()
    {
        var dir = TestUtil.TempDir();
        var svc = BreakGlassWorld(dir);
        Assert.True(svc.UseBreakGlass("co1", "holder-a", "secret-a", "holder-b", "secret-b", "drill", true).Ok);

        // An operator (not the holder) cannot rotate.
        Assert.False(svc.RotateBreakGlassHolders("operator",
            new[] { ("holder-a", "secret-a", "secret-a2") }).Ok);
        // The OTHER holder cannot rotate this holder.
        Assert.False(svc.RotateBreakGlassHolders("holder-b",
            new[] { ("holder-a", "secret-a", "secret-a2") }).Ok);
        // The holder with a WRONG current secret cannot rotate.
        Assert.False(svc.RotateBreakGlassHolders("holder-a",
            new[] { ("holder-a", "not-the-secret", "secret-a2") }).Ok);
        // The new secret may not be the current (exposed) secret.
        Assert.False(svc.RotateBreakGlassHolders("holder-a",
            new[] { ("holder-a", "secret-a", "secret-a") }).Ok);
        // Nothing moved through any of that.
        Assert.Equal(new[] { "holder-a", "holder-b" }, svc.BreakGlass.RotationPendingHolders);
        // The holder, in person, with proof: accepted.
        Assert.True(svc.RotateBreakGlassHolders("holder-a",
            new[] { ("holder-a", "secret-a", "secret-a2") }).Ok);
    }

    [Fact]
    public void F2_Rotate_BothHoldersInOneCall_Refused_NothingApplied()
    {
        var dir = TestUtil.TempDir();
        var svc = BreakGlassWorld(dir);
        Assert.True(svc.UseBreakGlass("co1", "holder-a", "secret-a", "holder-b", "secret-b", "drill", true).Ok);
        // One caller rotating both holders would hold both new
        // secrets — dual control collapsed. Refused whole.
        var r = svc.RotateBreakGlassHolders("holder-a",
            new[] { ("holder-a", "secret-a", "x1"), ("holder-b", "secret-b", "x2") });
        Assert.False(r.Ok);
        Assert.Equal(new[] { "holder-a", "holder-b" }, svc.BreakGlass.RotationPendingHolders);
    }

    [Fact]
    public void F2_Rotate_WhenNothingPending_Refused()
    {
        var dir = TestUtil.TempDir();
        var svc = BreakGlassWorld(dir);
        // No use/drill has happened: rotation is accepted only in
        // the mandatory post-use window.
        Assert.False(svc.RotateBreakGlassHolders("holder-a",
            new[] { ("holder-a", "secret-a", "secret-a2") }).Ok);
        Assert.NotNull(svc.BreakGlass.Use("co1", "holder-a", "secret-a", "holder-b", "secret-b", "drill", true, T0));
    }

    // ================= F6: policy fail-closed =================

    private static void WriteBundle(string dir, PolicyBundle bundle, string? orgKeyBase64)
    {
        File.WriteAllText(Path.Combine(dir, "policy-bundle.json"), JsonSerializer.Serialize(bundle));
        if (orgKeyBase64 is not null)
            File.WriteAllText(Path.Combine(dir, "policy-orgkey.txt"), orgKeyBase64);
    }

    private static PolicyBundle Bundle(DeviceIdentity org)
    {
        var issued = DateTimeOffset.UtcNow.AddHours(-1);
        var unsigned = new PolicyBundle(2, "company-1", new[] { "lan", "hub" }, "auto",
            null, null, false, false, "business_hours", issued, issued.AddDays(30), "",
            new[] { PolicyFeatures.WakeOnLan }, null);
        return PolicyBundleService.Sign(unsigned, org);
    }

    [Fact]
    public void F6_BundlePresent_OrgKeyMissing_EveryGateDenies()
    {
        var w = Setup();
        var dir = TestUtil.TempDir();
        var org = new DeviceIdentity(new DevOnlyPassThroughProtector());
        WriteBundle(dir, Bundle(org), orgKeyBase64: null); // key file absent
        var svc = new EnterpriseService(dir, w.Roster);
        Assert.True(svc.PolicyRefused);
        Assert.False(svc.CheckFeature(PolicyFeatures.TcpTunnel).Allowed);
        Assert.False(svc.CheckFeature("company-1", PolicyFeatures.TcpTunnel).Allowed);
        Assert.False(svc.CheckFeature("personal-1", PolicyFeatures.TcpTunnel).Allowed);
        Assert.False(svc.CheckUpdate("9.9.9").Allowed);
        Assert.False(svc.CheckTransport("lan").Allowed);
        Assert.Equal("disabled", svc.FeatureState(PolicyFeatures.TcpTunnel));
    }

    [Fact]
    public void F6_BundlePresent_BadSignature_EveryGateDenies()
    {
        var w = Setup();
        var dir = TestUtil.TempDir();
        var org = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var other = new DeviceIdentity(new DevOnlyPassThroughProtector());
        // Signed by org, but the published org key is someone else's.
        WriteBundle(dir, Bundle(org), Convert.ToBase64String(other.PublicKey));
        var svc = new EnterpriseService(dir, w.Roster);
        Assert.True(svc.PolicyRefused);
        Assert.False(svc.CheckFeature("company-1", PolicyFeatures.WakeOnLan).Allowed);
        Assert.False(svc.CheckFeature("company-1", PolicyFeatures.TcpTunnel).Allowed);
    }

    [Fact]
    public void F6_BundleCorrupt_EveryGateDenies_AndNoBundle_StillOwnersDevice()
    {
        var w = Setup();
        var dir = TestUtil.TempDir();
        File.WriteAllText(Path.Combine(dir, "policy-bundle.json"), "{ not a bundle");
        var org = new DeviceIdentity(new DevOnlyPassThroughProtector());
        File.WriteAllText(Path.Combine(dir, "policy-orgkey.txt"), Convert.ToBase64String(org.PublicKey));
        var svc = new EnterpriseService(dir, w.Roster);
        Assert.True(svc.PolicyRefused);
        Assert.False(svc.CheckFeature(PolicyFeatures.TcpTunnel).Allowed);

        // Control: NO bundle at all remains the owner's own,
        // ungated device — F6 must not turn absence into refusal.
        var dir2 = TestUtil.TempDir();
        var svc2 = new EnterpriseService(dir2, w.Roster);
        Assert.False(svc2.PolicyRefused);
        Assert.True(svc2.CheckFeature(PolicyFeatures.TcpTunnel).Allowed);
        Assert.Equal("allowed", svc2.FeatureState(PolicyFeatures.TcpTunnel));
    }

    [Fact]
    public void F6_ValidBundle_StillGatesOnlyWhatItDisables()
    {
        var w = Setup();
        var dir = TestUtil.TempDir();
        var org = new DeviceIdentity(new DevOnlyPassThroughProtector());
        WriteBundle(dir, Bundle(org), Convert.ToBase64String(org.PublicKey));
        var svc = new EnterpriseService(dir, w.Roster);
        Assert.False(svc.PolicyRefused);
        Assert.False(svc.CheckFeature("company-1", PolicyFeatures.WakeOnLan).Allowed); // disabled by the bundle
        Assert.True(svc.CheckFeature("company-1", PolicyFeatures.TcpTunnel).Allowed);  // not disabled
    }

    // ================= F3: MCP actor binding =================

    [Fact]
    public void F3_PairingIdentity_IsTheHostIntendedName_NotTheClientClaim()
    {
        var svc = new PairingService(new DevOnlyPassThroughProtector());
        var code = svc.CreatePairingCode("Agent One", TimeSpan.FromMinutes(5), Scopes.All);
        // The exchanging client claims to be someone else entirely.
        var exchange = svc.ExchangeCode(code, "Mallory The Admin");
        Assert.NotNull(exchange);
        var pairing = svc.List().Single();
        Assert.Equal("Agent One", pairing.AgentName);
    }

    [Fact]
    public async Task F3_TunnelList_RequiresRosterMembershipInScope()
    {
        var w = Setup();
        var id = ActiveSession(w);
        var tunnels = new SessionTunnelService(w.Sessions, w.Roster);
        Assert.NotNull(tunnels.Open(id, "host", "192.168.1.10", 8080, 18080));
        var module = new TunnelListModule(tunnels, w.Sessions, w.Roster);
        // A pairing whose (host-bound) name matches no roster AI
        // user of the scope learns nothing — not even that a
        // tunnel exists.
        var stranger = await module.ExecuteAsync(Args("""{"scopeId":"company-1"}"""), Ctx("No Such Agent"), default);
        Assert.False(stranger.Ok);
        Assert.DoesNotContain("192.168.1.10", stranger.Text);
        // The enrolled AI member of the scope can list.
        var member = await module.ExecuteAsync(Args("""{"scopeId":"company-1"}"""), Ctx("Agent One"), default);
        Assert.True(member.Ok, member.Text);
        Assert.Contains("192.168.1.10:8080", member.Text);
    }

    [Fact]
    public async Task F3_DuplicateAiDisplayNames_ResolveToNobody()
    {
        var w = Setup();
        // A second live AI user with the SAME display name.
        Assert.NotNull(w.Roster.CreateUser("ai-2", "company-1", "Agent One", "ai", pairedByUserId: "admin"));
        var module = new TunnelListModule(new SessionTunnelService(w.Sessions, w.Roster), w.Sessions, w.Roster);
        var r = await module.ExecuteAsync(Args("""{"scopeId":"company-1"}"""), Ctx("Agent One"), default);
        Assert.False(r.Ok); // ambiguous identity = no identity
        Assert.Contains("no live AI roster user", r.Text);
    }

    // ================= F4 + F11: service control / arming =================

    private sealed class FakeSvc : IServiceProvider
    {
        public bool Available => true;
        public Dictionary<string, string> States { get; } = new(StringComparer.OrdinalIgnoreCase);
        public List<string> Calls { get; } = new();
        public IReadOnlyList<ServiceInfo> List() =>
            States.Select(kv => new ServiceInfo(kv.Key, kv.Key, kv.Value, "Automatic")).ToList();
        public ServiceInfo? Status(string name) =>
            States.TryGetValue(name, out var s) ? new ServiceInfo(name, name, s, "Automatic") : null;
        public void Start(string name) { Calls.Add("start:" + name); States[name] = "Running"; }
        public void Stop(string name) { Calls.Add("stop:" + name); States[name] = "Stopped"; }
        public void Restart(string name) { Calls.Add("restart:" + name); }
    }

    private sealed class FakeArmer : ISelfRestartArmer
    {
        public List<string> Armed { get; } = new();
        public void Arm(string serviceName, string dataDir, string exePath) => Armed.Add(serviceName);
    }

    [Fact]
    public async Task F4_Restart_OtherDeskGuestNamedService_NeverArmsTheCoreWatchdog()
    {
        // F7-staleness repair (BLOCKH F7 REPAIR lane): BD-WIN-CORE-1
        // F7 closed a gate bypass — a restart stops the service
        // first, so service_restart on a NON-DeskGuest service now
        // requires the service_stop_non_deskguest gate approval, exactly
        // as service_stop always did. Per F4's own exact-name rule
        // DeskGuestSessionHelper is a non-DeskGuest service (it is not the
        // Core), so this test's previously approval-less context
        // was correctly gated by F7 before the F4 path could run.
        // The PRODUCT behaviour is correct; only this setup was
        // stale. Repair: the context now legitimately carries the
        // approval — supplied the same way the BdWinCore1FixTests
        // F5/F7 controls supply gate approvals to direct module
        // calls (Ctx(gates: …)), mirroring production, where the
        // MCP choke point assembles ToolExecutionContext with the
        // owner's approved gate classes (CoreRuntime's gate-
        // approval path). The gate is not weakened and no product
        // code is special-cased; the test's purpose (an
        // other-DeskGuest-named restart never arms the CORE watchdog)
        // and its assertions below are unchanged.
        var svc = new FakeSvc(); svc.States["DeskGuestSessionHelper"] = "Running";
        var armer = new FakeArmer();
        var module = new ServiceControlModule(svc, "restart", armer, "DeskGuestCore");
        var r = await module.ExecuteAsync(Args("""{"name":"DeskGuestSessionHelper"}"""),
            Ctx(gates: new HashSet<string> { "service_stop_non_deskguest" }), default);
        Assert.True(r.Ok, r.Text);
        // The generic inline path ran; the watchdog — armed with
        // the CORE's exe — was never pointed at another service.
        Assert.Equal(new[] { "restart:DeskGuestSessionHelper" }, svc.Calls);
        Assert.Empty(armer.Armed);
    }

    [Fact]
    public async Task F4_Stop_OtherDeskGuestNamedService_IsNotRefusedAsOwnService()
    {
        var svc = new FakeSvc(); svc.States["DeskGuestSessionHelper"] = "Running";
        var module = new ServiceControlModule(svc, "stop", new FakeArmer(), "DeskGuestCore");
        var r = await module.ExecuteAsync(Args("""{"name":"DeskGuestSessionHelper"}"""), Ctx(), default);
        Assert.True(r.Ok, r.Text);
        Assert.Equal(new[] { "stop:DeskGuestSessionHelper" }, svc.Calls);
    }

    [Fact]
    public async Task F11_RestartOwnService_EmptyDataDir_RefusesBeforeArming()
    {
        var svc = new FakeSvc(); svc.States["DeskGuestCore"] = "Running";
        var armer = new FakeArmer();
        var module = new ServiceControlModule(svc, "restart", armer, "DeskGuestCore");
        var r = await module.ExecuteAsync(Args("""{"name":"DeskGuestCore"}"""), Ctx(dataDir: ""), default);
        Assert.False(r.Ok);
        Assert.Contains("data directory", r.Text);
        Assert.Empty(armer.Armed);
        Assert.Empty(svc.Calls);
    }

    // ================= F5 + F11: watchdog / outcome channel =================

    private sealed class ScriptSvc : IServiceProvider
    {
        public bool Available => true;
        public string State = "Running";
        public Queue<bool> StartResults { get; } = new();
        public IReadOnlyList<ServiceInfo> List() => new[] { new ServiceInfo("DeskGuestCore", "DeskGuestCore", State, "Automatic") };
        public ServiceInfo? Status(string name) => new(name, name, State, "Automatic");
        public void Start(string name) { if ((StartResults.Count > 0 ? StartResults.Dequeue() : true)) State = "Running"; }
        public void Stop(string name) { State = "Stopped"; }
        public void Restart(string name) { }
    }

    private sealed class FakeSink : IRestartOutcomeSink
    {
        public List<RestartOutcome> Outcomes { get; } = new();
        public void WriteOutcome(RestartOutcome outcome) => Outcomes.Add(outcome);
        public void Loud(string detail) { }
    }

    private static RestartWatchdog Watchdog(ScriptSvc svc, IRestartOutcomeSink sink)
    {
        var t = T0;
        return new RestartWatchdog(svc, sink, delay: (d, ct) => Task.CompletedTask,
            now: () => t += TimeSpan.FromSeconds(1))
        { GracePeriod = TimeSpan.Zero, PollInterval = TimeSpan.Zero };
    }

    [Fact]
    public async Task F5_RollbackAppliedButBinaryWontStart_OutcomeSaysSo()
    {
        var dir = TestUtil.TempDir();
        var exe = Path.Combine(dir, "DeskGuestCore.exe");
        await File.WriteAllTextAsync(exe, "new-binary");
        await File.WriteAllTextAsync(exe + ".prev1", "old-binary");
        await File.WriteAllTextAsync(exe + ".prev1.sha256", "88a7a16419fe6663dd2eb62912b2eb4c5a5d58fb7f024d0d94bf0548e3c35836");
        var svc = new ScriptSvc(); // every start fails, rollback included
        svc.StartResults.Enqueue(false); svc.StartResults.Enqueue(false);
        svc.StartResults.Enqueue(false); svc.StartResults.Enqueue(false);
        var outcome = await Watchdog(svc, new FakeSink()).RunAsync("DeskGuestCore", exe);
        Assert.Equal("failed", outcome.State);
        Assert.True(outcome.RollbackUsed);
        Assert.Contains("rollback was applied", outcome.Detail);
        Assert.DoesNotContain("no rollback binary was available", outcome.Detail);
        // The swap really happened: old binary at the installed
        // path, failed binary kept beside it.
        Assert.Equal("old-binary", await File.ReadAllTextAsync(exe));
        Assert.Single(Directory.EnumerateFiles(dir, "DeskGuestCore.exe.failed-*"));
    }

    [Fact]
    public async Task F5_SwapFailure_NeverClaimsNoRollbackBinary()
    {
        var dir = TestUtil.TempDir();
        // The "installed exe" is a DIRECTORY: the first swap move
        // cannot succeed, so the rollback fails midway — while a
        // rollback binary demonstrably exists beside it.
        var exe = Path.Combine(dir, "DeskGuestCore.exe");
        Directory.CreateDirectory(exe);
        await File.WriteAllTextAsync(exe + ".prev1", "old-binary");
        await File.WriteAllTextAsync(exe + ".prev1.sha256", "88a7a16419fe6663dd2eb62912b2eb4c5a5d58fb7f024d0d94bf0548e3c35836");
        var svc = new ScriptSvc();
        svc.StartResults.Enqueue(false); svc.StartResults.Enqueue(false); svc.StartResults.Enqueue(false);
        var outcome = await Watchdog(svc, new FakeSink()).RunAsync("DeskGuestCore", exe);
        Assert.Equal("failed", outcome.State);
        Assert.False(outcome.RollbackUsed);
        Assert.Contains("swap failed", outcome.Detail);
        Assert.DoesNotContain("no rollback binary was available", outcome.Detail);
    }

    [Fact]
    public void F11_EveryOutcomeGetsItsOwnFile_NothingOverwritten()
    {
        var dir = TestUtil.TempDir();
        var sink = new FileRestartOutcomeSink(dir);
        sink.WriteOutcome(new RestartOutcome("DeskGuestCore", "restarted", 1, false, "first", T0));
        sink.WriteOutcome(new RestartOutcome("DeskGuestOther", "failed", 3, true, "second", T0.AddMinutes(1)));
        var files = Directory.EnumerateFiles(FileRestartOutcomeSink.OutcomesDir(dir), "*.json").ToList();
        Assert.Equal(2, files.Count); // the second outcome did NOT erase the first
        var texts = files.Select(File.ReadAllText).ToList();
        Assert.Contains(texts, t => t.Contains("first"));
        Assert.Contains(texts, t => t.Contains("second"));
    }

    [Fact]
    public void F11_OutcomeSink_EmptyDataDir_RefusedAtConstruction()
    {
        Assert.Throws<ArgumentException>(() => new FileRestartOutcomeSink(""));
        Assert.Throws<ArgumentException>(() => new FileRestartOutcomeSink("   "));
    }

    [Fact]
    public void F11_SecondArmWhileWatchdogArmed_Refused_OutcomeClearsTheMarker()
    {
        var dir = TestUtil.TempDir();
        var armer = new ProcessSelfRestartArmer();
        // /bin/true stands in for the Core exe: arming spawns it
        // detached with watchdog arguments, which it ignores.
        armer.Arm("DeskGuestCore", dir, "/bin/true");
        Assert.True(File.Exists(ProcessSelfRestartArmer.ArmMarkerPath(dir, "DeskGuestCore")));
        // A competing arm for the same service refuses while the
        // first watchdog has not reported.
        Assert.Throws<InvalidOperationException>(() => armer.Arm("DeskGuestCore", dir, "/bin/true"));
        // The watchdog's outcome write clears the marker.
        new FileRestartOutcomeSink(dir).WriteOutcome(
            new RestartOutcome("DeskGuestCore", "restarted", 1, false, "done", T0));
        Assert.False(File.Exists(ProcessSelfRestartArmer.ArmMarkerPath(dir, "DeskGuestCore")));
        // Empty data dir refuses at the armer too (no silent
        // cwd-relative outcome).
        Assert.Throws<InvalidOperationException>(() => armer.Arm("DeskGuestCore", "", "/bin/true"));
    }

    // ================= F7 + F9: tunnels =================

    [Fact]
    public void F9_TunnelOpen_FloorHolderWithoutUseGrant_Refused_GrantHolderOpens()
    {
        var w = Setup();
        var id = ActiveSession(w); // initiator ctrl holds the grant
        // The floor is never implicit: the host grants it to ctrl
        // (the BlockHTests GrantFloor pattern) before ctrl can drive.
        Assert.True(w.Sessions.GrantFloor(id, "ctrl", "host"));
        var tunnels = new SessionTunnelService(w.Sessions, w.Roster);
        Assert.NotNull(tunnels.Open(id, "ctrl", "192.168.1.10", 8080, 18080));
        // Revoke the grant mid-session: the SAME floor holder can
        // no longer open a tunnel (the AF3 re-read reaches Open).
        Assert.True(w.Roster.RemoveGrant("company-1", "ug-1", "dg-1", "admin"));
        Assert.Null(tunnels.Open(id, "ctrl", "192.168.1.11", 8080, 18081));
        // And the already-open tunnel dies at the next read: its
        // opener's authority is gone.
        Assert.Empty(tunnels.ListOpen());
    }

    [Fact]
    public void F9_HoldsUseGrant_RevokedDevice_ConfersNothing()
    {
        var w = Setup();
        var id = ActiveSession(w);
        Assert.True(w.Sessions.HoldsUseGrant(id, "ctrl"));
        Assert.True(w.Enrollments.Revoke(w.DeviceId));
        Assert.False(w.Sessions.HoldsUseGrant(id, "ctrl"));
    }

    [Fact]
    public void F7_PolicyDisableLandsWhileDown_OpenTunnelDiesAtNextRead()
    {
        var w = Setup();
        var id = ActiveSession(w);
        var tunnels = new SessionTunnelService(w.Sessions, w.Roster,
            (scopeId, key) => w.Disabled.Contains(key)
                ? new PolicyVerdict(false, "disabled by test policy")
                : new PolicyVerdict(true, "permitted"));
        var tunnel = tunnels.Open(id, "host", "192.168.1.10", 8080, 18080);
        Assert.NotNull(tunnel);
        Assert.Single(tunnels.ListOpen());
        // The disable lands with no reload sweep (Core was down /
        // sweep unwired): the per-act liveness re-read still ends
        // the tunnel instead of it staying open forever.
        w.Disabled.Add(PolicyFeatures.TcpTunnel);
        Assert.Empty(tunnels.ListOpen());
        Assert.Equal("closed", tunnels.GetTunnel(tunnel!.Id)!.State);
        Assert.Contains(tunnels.Events, e => e.Kind == "tunnel_closed_policy");
    }

    [Fact]
    public void F7_Import_TcpTunnelDisabled_RestoresClosed_NotOpen()
    {
        var w = Setup();
        var id = ActiveSession(w);
        var source = new SessionTunnelService(w.Sessions, w.Roster);
        Assert.NotNull(source.Open(id, "host", "192.168.1.10", 8080, 18080));
        var json = source.ExportJson();

        var guarded = new SessionTunnelService(w.Sessions, w.Roster,
            (scopeId, key) => new PolicyVerdict(false, "tcp_tunnel disabled by policy"));
        Assert.Equal(1, guarded.ImportJson(json));
        Assert.Empty(guarded.ListOpen()); // restored, but closed
    }

    [Fact]
    public void F7_Import_AiOpener_RestoresClosed_NotOpen()
    {
        var w = Setup();
        var id = ActiveSession(w);
        // A store written as if an AI had opened a tunnel (Open
        // itself refuses AI actors; import must repeat the refusal).
        var json = $$"""
            {"Tunnels":[{"Id":"tun-ai","SessionId":"{{id}}","TargetHost":"192.168.1.10","TargetPort":8080,
            "ListenPort":18080,"State":"open","OpenedByUserId":"ai-1","OpenedUtc":"2026-11-21T12:00:00+00:00","ClosedUtc":null}],
            "Events":[]}
            """;
        var tunnels = new SessionTunnelService(w.Sessions, w.Roster);
        Assert.Equal(1, tunnels.ImportJson(json));
        Assert.Empty(tunnels.ListOpen());
        Assert.Equal("closed", tunnels.GetTunnel("tun-ai")!.State);
    }

    // ================= F10: device-presence stops =================

    [Fact]
    public void F10_DeviceConsole_StopsAnyTransfer_RecordedAsConsoleNotAClaimedName()
    {
        var w = Setup();
        var transfers = new StandaloneTransferService(w.Roster, w.Enrollments);
        var job = transfers.CreateJob("company-1", w.DeviceId, "ctrl", "to_host", "f.bin", 100);
        Assert.NotNull(job);
        // The person at the machine is neither initiator nor
        // admin — the device-presence stop still works, and the
        // record names the console, not a typed roster id.
        Assert.True(transfers.CancelJobFromDevice(job!.Id));
        Assert.Equal("cancelled", transfers.GetJob(job.Id)!.State);
        var ev = transfers.Events.Last(e => e.Kind == "job_cancelled");
        Assert.Equal("device-console", ev.ActorUserId);
        Assert.False(transfers.CancelJobFromDevice(job.Id)); // terminal: refuses
    }

    [Fact]
    public void F10_DeviceConsole_ClosesAnyTunnel()
    {
        var w = Setup();
        var id = ActiveSession(w);
        var tunnels = new SessionTunnelService(w.Sessions, w.Roster);
        var tunnel = tunnels.Open(id, "host", "192.168.1.10", 8080, 18080);
        Assert.NotNull(tunnel);
        Assert.True(tunnels.CloseFromDevice(tunnel!.Id));
        Assert.Equal("closed", tunnels.GetTunnel(tunnel.Id)!.State);
        var ev = tunnels.Events.Last(e => e.Kind == "tunnel_closed");
        Assert.Equal("device-console", ev.ActorUserId);
    }

    // ================= F12: second-factor throttle =================

    private sealed class PasskeyFixture
    {
        public required SecondFactorService Svc { get; init; }
        public required ECDsa Key { get; init; }
        public required string CredId { get; init; }

        public (byte[] AuthData, string ClientJson, byte[] Sig) Make(uint counter, string challenge, bool corruptSig = false)
        {
            const string rpId = "deskguest.local";
            var clientJson = "{\"type\":\"webauthn.get\",\"challenge\":\"" + challenge +
                "\",\"origin\":\"https://deskguest.local\",\"crossOrigin\":false}";
            var authData = new byte[37];
            SHA256.HashData(Encoding.UTF8.GetBytes(rpId)).CopyTo(authData, 0);
            authData[32] = 0x01;
            BinaryPrimitives.WriteUInt32BigEndian(authData.AsSpan(33, 4), counter);
            var signed = authData.Concat(SHA256.HashData(Encoding.UTF8.GetBytes(clientJson))).ToArray();
            var sig = Key.SignData(signed, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
            if (corruptSig) sig[^1] ^= 0xFF;
            return (authData, clientJson, sig);
        }
    }

    private static PasskeyFixture Passkeys(World w, SecondFactorService svc, params string[] users)
    {
        var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var p = ecdsa.ExportParameters(false);
        var credId = Convert.ToBase64String(new byte[] { 4, 2, 0 });
        foreach (var user in users)
            Assert.True(svc.RegisterPasskey("company-1", user, credId,
                Convert.ToBase64String(p.Q.X!), Convert.ToBase64String(p.Q.Y!)));
        return new PasskeyFixture { Svc = svc, Key = ecdsa, CredId = credId };
    }

    [Fact]
    public void F12_GarbageChallengeSpray_NeitherBurnsNorLocks()
    {
        var w = Setup();
        var svc = new SecondFactorService(w.Roster, new DevOnlyPassThroughProtector());
        var f = Passkeys(w, svc, "ctrl");
        var challenge = svc.IssuePasskeyChallenge("company-1", "ctrl", T0)!;
        // A stranger who knows the (public) credential id sprays
        // assertions carrying a challenge that was never issued.
        for (var i = 0; i < 8; i++)
        {
            var junk = f.Make(1, "attacker-invented-" + i);
            Assert.False(svc.VerifyPasskeyAssertion("company-1", "ctrl", f.CredId,
                junk.AuthData, junk.ClientJson, junk.Sig, "attacker-invented-" + i, "deskguest.local", T0));
        }
        // The victim's in-flight ceremony is intact: the issued
        // challenge was not burned by the spray, and no lockout
        // was accumulated — the genuine assertion verifies.
        var good = f.Make(1, challenge);
        Assert.True(svc.VerifyPasskeyAssertion("company-1", "ctrl", f.CredId,
            good.AuthData, good.ClientJson, good.Sig, challenge, "deskguest.local", T0));
    }

    [Fact]
    public void F12_MaterialPasskeyFailures_LockPasskeyOnly_TotpStillVerifies()
    {
        var w = Setup();
        var svc = new SecondFactorService(w.Roster, new DevOnlyPassThroughProtector());
        // Enroll TOTP for the same user.
        var begin = svc.BeginTotpEnrollment("company-1", "ctrl");
        Assert.NotNull(begin);
        var secret = Base32.Decode(begin!.Value.Base32Secret)!;
        Assert.True(svc.ConfirmTotpEnrollment("company-1", "ctrl", Totp.At(secret, T0), T0));
        var f = Passkeys(w, svc, "ctrl");

        // Five MATERIAL failures: the attacker holds each issued
        // challenge (they began the ceremonies) but cannot sign.
        for (var i = 0; i < SecondFactorService.MaxConsecutiveFailures; i++)
        {
            var c = svc.IssuePasskeyChallenge("company-1", "ctrl", T0)!;
            var bad = f.Make(1, c, corruptSig: true);
            Assert.False(svc.VerifyPasskeyAssertion("company-1", "ctrl", f.CredId,
                bad.AuthData, bad.ClientJson, bad.Sig, c, "deskguest.local", T0));
        }
        // The passkey path IS locked now — even a genuine assertion.
        var cLocked = svc.IssuePasskeyChallenge("company-1", "ctrl", T0)!;
        var genuine = f.Make(1, cLocked);
        Assert.False(svc.VerifyPasskeyAssertion("company-1", "ctrl", f.CredId,
            genuine.AuthData, genuine.ClientJson, genuine.Sig, cLocked, "deskguest.local", T0));
        // But the lockout is confined to the passkey path: the
        // victim's TOTP still verifies. Before F12 the shared key
        // locked every factor at once.
        var t = T0.AddSeconds(60);
        Assert.True(svc.VerifyTotp("company-1", "ctrl", Totp.At(secret, t), t));
    }
}
