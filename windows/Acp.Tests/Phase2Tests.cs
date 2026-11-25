using System.Net;
using System.Text.Json;
using Acp.Core;
using Acp.Core.Phase2;
using Acp.Core.Platform;
using Acp.Core.Services;
using Acp.Shared.State;
using Acp.Shared.Tools;

namespace Acp.Tests;

public class Phase2Tests
{
    private static JsonElement Args(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.Clone();
    }

    // ---- Unlock brakes ----

    private static readonly Acp.Shared.Security.Pairing UnlockPairing =
        TestUtil.BarePairing(new HashSet<string> { Acp.Shared.Security.Scopes.Unlock });

    private static UnlockService MakeUnlock(FakeFactChecks facts, bool channelResult, Func<bool>? stop = null,
        Acp.Core.Modules.SessionManager? sessions = null, Func<bool>? desktopUnlocked = null)
    {
        var vault = new InMemoryCredentialVault();
        vault.Vault("the-password");
        var channel = new DelegateChannel(channelResult);
        return new UnlockService(vault, channel, facts, stop ?? (() => false), sessions, desktopUnlocked) { ModuleEnabled = true };
    }

    private sealed class DelegateChannel : ICredentialProviderChannel
    {
        private readonly bool _result;
        public DelegateChannel(bool result) => _result = result;
        public bool SignalUnlock(string credentialPayload, string nonce) => _result;
    }

    [Fact]
    public async Task Unlock_HelloOnly_IsUnavailableWithReason()
    {
        var facts = new FakeFactChecks
        {
            Report = new FactCheckReport(
                new SubsystemHealth("edition", HealthLevel.Green, "Windows 11 Pro"),
                new SubsystemHealth("bitlocker", HealthLevel.Green, "on"),
                new SubsystemHealth("hello", HealthLevel.Red, "Hello-only sign-in mode is ON (DevicePasswordLessBuildVersion=2)"))
        };
        var unlock = MakeUnlock(facts, channelResult: true);
        var result = await unlock.RequestUnlockAsync(UnlockPairing, default);
        Assert.False(result.Ok);
        Assert.Contains("Hello-only", result.UnavailableReason ?? result.Text);
    }

    [Fact]
    public async Task Unlock_OneFailure_DegradesAndRefusesRetry()
    {
        var unlock = MakeUnlock(new FakeFactChecks(), channelResult: false);
        var first = await unlock.RequestUnlockAsync(UnlockPairing, default);
        Assert.False(first.Ok);
        Assert.Equal(UnlockModuleState.VaultDegraded, unlock.State);
        var second = await unlock.RequestUnlockAsync(UnlockPairing, default);
        Assert.False(second.Ok);
        Assert.Contains("degraded", (second.UnavailableReason ?? second.Text ?? "").ToLowerInvariant());
        Assert.Equal(1, unlock.Attempts); // the brake: no second attempt was made
    }

    [Fact]
    public async Task Unlock_StopInForce_Blocks()
    {
        var unlock = MakeUnlock(new FakeFactChecks(), channelResult: true, stop: () => true);
        var result = await unlock.RequestUnlockAsync(UnlockPairing, default);
        Assert.False(result.Ok);
        Assert.Contains("STOP", result.UnavailableReason ?? result.Text);
    }

    [Fact]
    public async Task Unlock_HappyPath_ConfirmedUnlock_StartsAgentUnlockedSession()
    {
        var sessions = new Acp.Core.Modules.SessionManager();
        var unlock = MakeUnlock(new FakeFactChecks(), channelResult: true, sessions: sessions, desktopUnlocked: () => true);
        var result = await unlock.RequestUnlockAsync(UnlockPairing, default);
        Assert.True(result.Ok, result.Text);
        Assert.Equal(1, unlock.Attempts);
        // H4: the session exists and is marked agent-unlocked, so the
        // relock rule has something true to act on.
        Assert.NotNull(sessions.Current);
        Assert.True(sessions.Current!.AgentUnlockedThisSession);
    }

    [Fact]
    public async Task Unlock_DeliveredButDesktopStaysLocked_DegradesLikeAFailedAuth()
    {
        // H3 regression: delivery is not authentication. The pipe says
        // "delivered", the desktop never unlocks → failed auth, brake on.
        var unlock = MakeUnlock(new FakeFactChecks(), channelResult: true, desktopUnlocked: () => false);
        var first = await unlock.RequestUnlockAsync(UnlockPairing, default);
        Assert.False(first.Ok);
        Assert.Equal("authentication_failed", first.ErrorClass);
        Assert.Equal(UnlockModuleState.VaultDegraded, unlock.State);
        var second = await unlock.RequestUnlockAsync(UnlockPairing, default);
        Assert.False(second.Ok);
        Assert.Equal(1, unlock.Attempts); // still exactly one attempt
    }

    // ---- Child sessions ----

    [Fact]
    public async Task ChildSession_HomeEdition_Refused()
    {
        var facts = new FakeFactChecks
        {
            Report = new FactCheckReport(
                new SubsystemHealth("edition", HealthLevel.Red, "Windows 11 Home — child seats need Pro+"),
                new SubsystemHealth("bitlocker", HealthLevel.Green, "on"),
                new SubsystemHealth("hello", HealthLevel.Green, "off"))
        };
        var manager = new ChildSessionManager(new FakeChildSessionDriver(), facts);
        var result = await manager.StartAsync("user-1", default);
        Assert.False(result.Ok);
        Assert.Contains("Pro", result.UnavailableReason ?? result.Text);
    }

    [Fact]
    public async Task ChildSession_ProEdition_FakeDriver_StartsAndStops()
    {
        var driver = new FakeChildSessionDriver();
        var manager = new ChildSessionManager(driver, new FakeFactChecks());
        var started = await manager.StartAsync("user-1", default);
        Assert.True(started.Ok, started.Text);
        Assert.True(manager.SeatActive);
        var stopped = await manager.StopAsync();
        Assert.True(stopped.Ok);
        Assert.False(manager.SeatActive);
    }

    // ---- Safe Mode ride ----

    [Fact]
    public async Task SafeMode_Ride_SetsSafeboot_ThenClearsItFirstOnReturnBoot()
    {
        var dir = TestUtil.TempDir();
        var runner = new FakeRunner();
        var orch = new SafeModeOrchestrator(runner, dir, isWindows: () => true, isSafeModeNow: () => false);
        var begin = await orch.BeginRideAsync("test", default);
        Assert.True(begin.Ok, begin.Text);
        Assert.Contains(runner.Calls, c => c.File == "bcdedit.exe" && c.Args.Contains("safeboot network"));
        Assert.Equal(SafeModePhase.RebootingToSafeMode, orch.Phase);

        // The return boot: a fresh orchestrator over the same state,
        // now reporting "we are in Safe Mode".
        var runner2 = new FakeRunner();
        var orch2 = new SafeModeOrchestrator(runner2, dir, isWindows: () => true, isSafeModeNow: () => true);
        await orch2.OnBootAsync(default);
        Assert.Contains(runner2.Calls, c => c.Args.Contains("/deletevalue"));
        Assert.Equal(SafeModePhase.Returning, orch2.Phase);

        // The boot after that completes the ride.
        await orch2.OnBootAsync(default);
        Assert.Equal(SafeModePhase.Normal, orch2.Phase);
    }

    [Fact]
    public async Task SafeMode_BeginRide_OffWindows_Unavailable()
    {
        var orch = new SafeModeOrchestrator(new FakeRunner(), TestUtil.TempDir(), isWindows: () => false, isSafeModeNow: () => false);
        var result = await orch.BeginRideAsync("test", default);
        Assert.False(result.Ok);
    }

    // ---- Takeover arbitration ----

    [Fact]
    public void Takeover_SeizeAndHandBack_FlipsState()
    {
        var state = new CoreState();
        var arbiter = new TakeoverArbiter(state);
        Assert.False(arbiter.OwnerHoldsDesktop);
        Assert.True(arbiter.Seize("user-1").Ok);
        Assert.True(state.Session.TakeoverActive);
        Assert.True(arbiter.OwnerHoldsDesktop);
        Assert.True(arbiter.HandBack().Ok);
        Assert.False(state.Session.TakeoverActive);
    }

    // ---- Missions ----

    [Fact]
    public async Task Mission_RunsSteps_Checkpoints_Completes_AndPersists()
    {
        var dir = TestUtil.TempDir();
        var engine = new MissionEngine(dir);
        var calls = new List<string>();
        engine.StepRunner = (pairingId, tool, args, ct) =>
        {
            calls.Add(tool);
            return Task.FromResult(ToolResult.Success("ok"));
        };
        var mission = engine.Create("p1", "two steps", new List<MissionEngine.MissionStep>
        {
            new() { Tool = "endpoint_state" },
            new() { Tool = "device_info" }
        });
        var done = await engine.RunAsync(mission.Id, default);
        Assert.Equal("complete", done.State);
        Assert.Equal(2, done.CompletedSteps);
        Assert.Equal(new[] { "endpoint_state", "device_info" }, calls);
        var reloaded = new MissionEngine(dir).Load(mission.Id);
        Assert.Equal(2, reloaded!.CompletedSteps);
    }

    [Fact]
    public async Task Mission_FailingStep_HaltsAtCheckpoint()
    {
        var dir = TestUtil.TempDir();
        var engine = new MissionEngine(dir);
        var n = 0;
        engine.StepRunner = (pairingId, tool, args, ct) =>
        {
            n++;
            return Task.FromResult(n == 1 ? ToolResult.Success("ok") : ToolResult.Error("boom", "step exploded"));
        };
        var mission = engine.Create("p1", "will fail", new List<MissionEngine.MissionStep>
        {
            new() { Tool = "a" }, new() { Tool = "b" }, new() { Tool = "c" }
        });
        var done = await engine.RunAsync(mission.Id, default);
        Assert.Equal("failed", done.State);
        Assert.Equal(1, done.CompletedSteps); // checkpoint kept: a resume starts at step 2
        Assert.Contains("step exploded", done.LastError);
    }

    // ---- Health rules / WoL / tunnel / scrape guard ----

    [Fact]
    public void HealthRules_TripAboveAndBelow()
    {
        var rules = new HealthAlertRules();
        rules.AddRule(new HealthAlertRules.Rule("disk hot", "disk_pct", 90, "above"));
        rules.AddRule(new HealthAlertRules.Rule("battery low", "battery_pct", 15, "below"));
        var fired = rules.Evaluate(new Dictionary<string, double> { ["disk_pct"] = 95, ["battery_pct"] = 50 }, DateTimeOffset.UtcNow);
        Assert.Single(fired);
        Assert.Equal("disk hot", fired[0].Rule);
        var fired2 = rules.Evaluate(new Dictionary<string, double> { ["disk_pct"] = 10, ["battery_pct"] = 5 }, DateTimeOffset.UtcNow);
        Assert.Single(fired2);
        Assert.Equal("battery low", fired2[0].Rule);
    }

    [Fact]
    public void WakeOnLan_MagicPacket_HasCorrectShape()
    {
        var packet = WakeOnLanModule.BuildMagicPacket("00:11:22:33:44:55");
        Assert.Equal(102, packet.Length);
        Assert.All(packet.Take(6), b => Assert.Equal(0xFF, b));
        Assert.Equal(0x00, packet[6]);
        Assert.Equal(0x55, packet[101]);
    }

    [Fact]
    public void TcpTunnel_NonAllowlistedTarget_Refused()
    {
        var tunnels = new TcpTunnelService(new HashSet<string> { "panel.local:80" });
        Assert.True(tunnels.IsAllowed("panel.local", 80));
        Assert.False(tunnels.IsAllowed("evil.example", 22));
    }

    [Theory]
    [InlineData("127.0.0.1", true)]
    [InlineData("10.1.2.3", true)]
    [InlineData("192.168.1.20", true)]
    [InlineData("169.254.169.254", true)]
    [InlineData("100.64.0.5", true)]
    [InlineData("8.8.8.8", false)]
    [InlineData("1.1.1.1", false)]
    public void ScrapeGuard_ClassifiesAddresses(string ip, bool blocked)
    {
        Assert.Equal(blocked, Acp.Core.Modules.ScrapeModule.IsPrivateOrSpecial(IPAddress.Parse(ip)));
    }

    // ---- Watchdog ----

    [Fact]
    public void Watchdog_StaleAgent_Relaunches()
    {
        var state = new CoreState();
        state.UpdateSession(s => s with { SessionExists = true });
        var liveness = new FakeLiveness { AgentConnected = false, LastAgentHeartbeatUtc = DateTimeOffset.MinValue };
        var launcher = new RecordingLauncher();
        var audit = TestUtil.AuditLog(TestUtil.TempDir());
        var watchdog = new AgentWatchdog(state, liveness, launcher, audit, "agent.exe");
        var acted = watchdog.Tick(DateTimeOffset.UtcNow);
        Assert.Equal("agent_relaunch_attempted", acted);
        Assert.Equal(1, launcher.Launches);
    }

    [Fact]
    public void Watchdog_Exhaustion_StopsLaunching_AndReports()
    {
        var state = new CoreState();
        state.UpdateSession(s => s with { SessionExists = true });
        var liveness = new FakeLiveness { AgentConnected = false, LastAgentHeartbeatUtc = DateTimeOffset.MinValue };
        var launcher = new RecordingLauncher { Result = false };
        var audit = TestUtil.AuditLog(TestUtil.TempDir());
        var watchdog = new AgentWatchdog(state, liveness, launcher, audit, "agent.exe") { MaxConsecutiveFailures = 3, BaseBackoff = TimeSpan.Zero };
        var now = DateTimeOffset.UtcNow;
        for (var i = 0; i < 10; i++) { watchdog.Tick(now); now += TimeSpan.FromSeconds(1); }
        Assert.True(watchdog.Exhausted);
        Assert.Equal(3, launcher.Launches);
    }

    [Fact]
    public void Watchdog_NoSession_StillLaunches_W20DeadlockFix()
    {
        // W20 REVISES this pin: the SessionExists gate was one half
        // of the AgentConnected deadlock (W19 diagnosis) — the
        // watchdog is the token-delivering relaunch path and must be
        // able to act before any session exists.
        var state = new CoreState(); // nobody logged on yet
        var liveness = new FakeLiveness { AgentConnected = false };
        var launcher = new RecordingLauncher();
        var watchdog = new AgentWatchdog(state, liveness, launcher, TestUtil.AuditLog(TestUtil.TempDir()), "agent.exe");
        Assert.Equal("agent_relaunch_attempted", watchdog.Tick(DateTimeOffset.UtcNow));
        Assert.Equal(1, launcher.Launches);
    }

    [Fact]
    public void Watchdog_PreSessionFailures_DoNotExhaust_AndSessionResetsBooks()
    {
        var state = new CoreState(); // no session
        var liveness = new FakeLiveness { AgentConnected = false, LastAgentHeartbeatUtc = DateTimeOffset.MinValue };
        var launcher = new RecordingLauncher { Result = false };
        var watchdog = new AgentWatchdog(state, liveness, launcher, TestUtil.AuditLog(TestUtil.TempDir()), "agent.exe")
            { MaxConsecutiveFailures = 3, BaseBackoff = TimeSpan.Zero };
        var now = DateTimeOffset.UtcNow;
        for (var i = 0; i < 10; i++) { watchdog.Tick(now); now += TimeSpan.FromSeconds(1); }
        Assert.False(watchdog.Exhausted);
        Assert.Equal(0, watchdog.ConsecutiveFailures);
        // A session appears: the books reset and the watchdog keeps
        // working for it (and CAN now exhaust on real failures).
        state.UpdateSession(s => s with { SessionExists = true });
        for (var i = 0; i < 10; i++) { watchdog.Tick(now); now += TimeSpan.FromSeconds(1); }
        Assert.True(watchdog.Exhausted);
    }
}
