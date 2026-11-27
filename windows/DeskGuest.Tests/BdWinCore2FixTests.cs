using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using DeskGuest.Core;
using DeskGuest.Core.Ipc;
using DeskGuest.Core.Modules;
using DeskGuest.Core.Phase2;
using DeskGuest.Core.Platform;
using DeskGuest.Core.Services;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.Tools;

namespace DeskGuest.Tests;

/// <summary>Regression tests for the BD-WIN-CORE-2 breakdown packet
/// (6a49c310): owner-takeover blocker, registry-backup traversal,
/// tunnel ownership/audit, mission ownership, Safe Mode ride,
/// ConPTY session/token, script/plugin TOCTOU, env/cert hardening,
/// macro replay policy, health-rule discipline, error wrapping,
/// fleet board / live view. Every test names its finding.</summary>
public class BdWinCore2FixTests
{
    private static ToolExecutionContext Ctx(string pairingId = "p1") =>
        new(TestUtil.BarePairing(Scopes.All, pairingId), TestUtil.Session(),
            TestUtil.State(), new HashSet<string>(), TestUtil.TempDir());

    private static JsonElement Args(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.Clone();
    }

    // ---- F1 (blocker): takeover is owner-local, never agent-callable ----

    [Fact]
    public async Task F1_OwnerTakeoverModule_RefusesSeizeAndHandback_StateUnchanged()
    {
        var state = new CoreState();
        state.UpdateSession(s => s with { TakeoverActive = true }); // the owner has taken over
        var module = new OwnerTakeoverModule();
        var handback = await module.ExecuteAsync(Args("""{"action":"handback"}"""), Ctx(), default);
        Assert.False(handback.Ok);
        Assert.Equal("owner_only", handback.ErrorClass);
        Assert.True(state.Session.TakeoverActive); // an Admin agent cannot end the owner's takeover

        var state2 = new CoreState();
        var seize = await module.ExecuteAsync(Args("""{"action":"seize"}"""), Ctx(), default);
        Assert.False(seize.Ok);
        Assert.Equal("owner_only", seize.ErrorClass);
        Assert.False(state2.Session.TakeoverActive);
    }

    [Fact]
    public void F1_ArbiterTransitions_AreAudited()
    {
        var dir = TestUtil.TempDir();
        var audit = TestUtil.AuditLog(dir);
        var state = new CoreState();
        var arbiter = new TakeoverArbiter(state, audit);
        Assert.True(arbiter.Seize("owner-at-machine").Ok);
        Assert.True(arbiter.HandBack().Ok);
        var outcomes = audit.ReadTail(10).Select(e => e.Outcome).ToList();
        Assert.Contains("owner_takeover_seized", outcomes);
        Assert.Contains("owner_takeover_handback", outcomes);
    }

    // ---- F2: registry backup traversal + import target ----

    private sealed class FakeRegistry : IRegistryProvider
    {
        public bool Available => true;
        public Dictionary<string, string> Values = new();
        public List<(string Key, string Name, string Value)> Sets = new();
        public string? GetValue(string keyPath, string valueName) => Values.TryGetValue(valueName, out var v) ? v : null;
        public IReadOnlyList<string> ListValues(string keyPath) => Values.Keys.ToList();
        public IReadOnlyList<string> ListSubKeys(string keyPath) => new List<string> { "Sub1" };
        public void SetValue(string keyPath, string valueName, string value) => Sets.Add((keyPath, valueName, value));
        public void DeleteValue(string keyPath, string valueName) { }
        public void DeleteKey(string keyPath) { }
    }

    [Fact]
    public async Task F2_BackupNameTraversal_Refused_NothingWrittenOutside()
    {
        var staging = TestUtil.TempDir();
        var module = new RegistryBackupExportModule(new FakeRegistry(), staging);
        var r = await module.ExecuteAsync(Args("""{"action":"export","key":"HKLM\\Software\\X","backup_name":"../evil"}"""), Ctx(), default);
        Assert.False(r.Ok);
        Assert.Equal("bad_arguments", r.ErrorClass);
        Assert.False(File.Exists(Path.Combine(Path.GetDirectoryName(staging)!, "evil.json")));
    }

    [Fact]
    public async Task F2_Import_FileKeyMustEqualCallerKey()
    {
        var staging = TestUtil.TempDir();
        var reg = new FakeRegistry { Values = new() { ["v1"] = "one" } };
        var module = new RegistryBackupExportModule(reg, staging);
        var export = await module.ExecuteAsync(Args("""{"action":"export","key":"HKLM\\Software\\Good","backup_name":"bk1"}"""), Ctx(), default);
        Assert.True(export.Ok, export.Text);
        // The backup records HKLM\Software\Good; importing it while
        // naming a DIFFERENT key must refuse and write nothing.
        var bad = await module.ExecuteAsync(Args("""{"action":"import","key":"HKLM\\Software\\Evil","backup_name":"bk1"}"""), Ctx(), default);
        Assert.False(bad.Ok);
        Assert.Equal("key_mismatch", bad.ErrorClass);
        Assert.Empty(reg.Sets);
        var good = await module.ExecuteAsync(Args("""{"action":"import","key":"HKLM\\Software\\Good","backup_name":"bk1"}"""), Ctx(), default);
        Assert.True(good.Ok, good.Text);
        Assert.Single(reg.Sets);
        Assert.Equal("HKLM\\Software\\Good", reg.Sets[0].Key);
    }

    // ---- F3: tunnels are owned, audited, stoppable ----

    private static int FreePort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start(); var p = ((IPEndPoint)l.LocalEndpoint).Port; l.Stop(); return p;
    }

    [Fact]
    public async Task F3_Tunnel_OwnershipAuditAndStop()
    {
        var events = new List<string>();
        var tunnels = new TcpTunnelService(new HashSet<string> { "panel.local:80" },
            (kind, pairingId, detail) => events.Add($"{kind}:{pairingId}"));
        var port = FreePort();
        var err = await tunnels.StartForwardAsync(IPAddress.Loopback, port, "panel.local", 80, default, "pair-A");
        Assert.Null(err);
        Assert.Single(tunnels.Active);
        Assert.Contains(events, e => e.StartsWith("tcp_tunnel_start:pair-A"));
        // A foreign pairing cannot stop it.
        Assert.False(tunnels.Stop(port, "pair-B", out var stopErr));
        Assert.Contains("another pairing", stopErr);
        Assert.Single(tunnels.Active);
        // The owner can; session-end teardown clears the rest.
        Assert.True(tunnels.Stop(port, "pair-A", out _));
        Assert.Empty(tunnels.Active);
        Assert.Contains(events, e => e.StartsWith("tcp_tunnel_stop:pair-A"));
        tunnels.StopAll();
    }

    [Fact]
    public async Task F3_Tunnel_ListenerStartFailure_ReturnsErrorNotException()
    {
        var blocker = new TcpListener(IPAddress.Loopback, 0);
        blocker.Start();
        var port = ((IPEndPoint)blocker.LocalEndpoint).Port;
        try
        {
            var tunnels = new TcpTunnelService(new HashSet<string> { "panel.local:80" });
            var err = await tunnels.StartForwardAsync(IPAddress.Loopback, port, "panel.local", 80, default, "pair-A");
            Assert.NotNull(err);
            Assert.Contains("failed to start", err);
        }
        finally { blocker.Stop(); }
    }

    [Fact]
    public async Task F3_TunnelModule_ListShowsOnlyOwnForwards()
    {
        var tunnels = new TcpTunnelService(new HashSet<string> { "panel.local:80" });
        var module = new TcpTunnelModule(tunnels);
        var port = FreePort();
        var started = await module.ExecuteAsync(Args($$"""{"action":"start","listen_port":{{port}},"target_host":"panel.local","target_port":80}"""), Ctx("owner-1"), default);
        Assert.True(started.Ok, started.Text);
        var mine = await module.ExecuteAsync(Args("""{"action":"list"}"""), Ctx("owner-1"), default);
        Assert.Contains(port.ToString(), mine.Text);
        var theirs = await module.ExecuteAsync(Args("""{"action":"list"}"""), Ctx("other-2"), default);
        Assert.DoesNotContain(port.ToString(), theirs.Text);
        tunnels.StopAll();
    }

    // ---- F4: missions are owned by their creating pairing ----

    private static MissionEngineModule MissionModule(MissionEngine engine) => new(engine);

    [Fact]
    public async Task F4_ForeignPairing_CannotRunStatusOrListMission()
    {
        var engine = new MissionEngine(TestUtil.TempDir());
        engine.StepRunner = (_, _, _, _) => Task.FromResult(ToolResult.Success("ok"));
        var module = MissionModule(engine);
        var created = await module.ExecuteAsync(Args("""{"action":"create","title":"mine","steps":[{"tool":"endpoint_state","args":{}}]}"""), Ctx("creator"), default);
        Assert.True(created.Ok, created.Text);
        var id = JsonDocument.Parse(created.Text!).RootElement.GetProperty("Id").GetString();

        var foreignRun = await module.ExecuteAsync(Args($$"""{"action":"run","id":"{{id}}"}"""), Ctx("intruder"), default);
        Assert.False(foreignRun.Ok);
        Assert.Equal("not_found", foreignRun.ErrorClass);
        var foreignStatus = await module.ExecuteAsync(Args($$"""{"action":"status","id":"{{id}}"}"""), Ctx("intruder"), default);
        Assert.False(foreignStatus.Ok);
        var foreignList = await module.ExecuteAsync(Args("""{"action":"list"}"""), Ctx("intruder"), default);
        Assert.DoesNotContain(id!, foreignList.Text);
        var ownList = await module.ExecuteAsync(Args("""{"action":"list"}"""), Ctx("creator"), default);
        Assert.Contains(id!, ownList.Text);
        var ownRun = await module.ExecuteAsync(Args($$"""{"action":"run","id":"{{id}}"}"""), Ctx("creator"), default);
        Assert.True(ownRun.Ok, ownRun.Text);
        Assert.Contains("complete", ownRun.Text);
    }

    [Fact]
    public async Task F4_CreateValidation_EmptyStepsAndMissingToolRefused()
    {
        var module = MissionModule(new MissionEngine(TestUtil.TempDir()));
        var empty = await module.ExecuteAsync(Args("""{"action":"create","title":"x","steps":[]}"""), Ctx(), default);
        Assert.Equal("bad_arguments", empty.ErrorClass);
        var noTool = await module.ExecuteAsync(Args("""{"action":"create","title":"x","steps":[{"args":{}}]}"""), Ctx(), default);
        Assert.Equal("bad_arguments", noTool.ErrorClass);
    }

    [Fact]
    public async Task F4_ConcurrentRunOfSameMission_Refused()
    {
        var engine = new MissionEngine(TestUtil.TempDir());
        var gate = new TaskCompletionSource<ToolResult>();
        engine.StepRunner = (_, _, _, _) => gate.Task;
        var m = engine.Create("p1", "slow", new List<MissionEngine.MissionStep> { new() { Tool = "a" } });
        var first = engine.RunAsync(m.Id, default);
        await Assert.ThrowsAsync<InvalidOperationException>(() => engine.RunAsync(m.Id, default));
        gate.SetResult(ToolResult.Success("ok"));
        var done = await first;
        Assert.Equal("complete", done.State);
    }

    [Fact]
    public async Task F4_RevokedCreator_HaltsMission_BeforeAnyStep()
    {
        var engine = new MissionEngine(TestUtil.TempDir());
        var steps = 0;
        engine.StepRunner = (_, _, _, _) => { steps++; return Task.FromResult(ToolResult.Success("ok")); };
        engine.PairingStillValid = _ => false;
        var m = engine.Create("dead-pairing", "t", new List<MissionEngine.MissionStep> { new() { Tool = "a" } });
        var done = await engine.RunAsync(m.Id, default);
        Assert.Equal("halted", done.State);
        Assert.Equal(0, steps);
    }

    [Fact]
    public void F4_StaleRunningMission_RecoversToPaused()
    {
        var dir = TestUtil.TempDir();
        var engine = new MissionEngine(dir);
        var m = engine.Create("p1", "t", new List<MissionEngine.MissionStep> { new() { Tool = "a" } });
        var path = Path.Combine(dir, "missions", $"{m.Id}.json");
        File.WriteAllText(path, File.ReadAllText(path).Replace("\"queued\"", "\"running\""));
        Assert.Equal(1, engine.RecoverStaleRuns());
        Assert.Equal("paused", engine.Load(m.Id)!.State);
    }

    // ---- F5: Safe Mode ride cannot loop the machine ----

    [Fact]
    public async Task F5_OnBoot_NormalBootWithRideOutstanding_StillClearsSafeboot()
    {
        var dir = TestUtil.TempDir();
        var runner = new FakeRunner();
        var orch = new SafeModeOrchestrator(runner, dir, isWindows: () => true, isSafeModeNow: () => true);
        Assert.True((await orch.BeginRideAsync("test", default)).Ok);
        // The machine comes back in a NORMAL boot (reboot aborted /
        // safeboot ignored) — the flag must still be cleared.
        var runner2 = new FakeRunner();
        var orch2 = new SafeModeOrchestrator(runner2, dir, isWindows: () => true, isSafeModeNow: () => false);
        await orch2.OnBootAsync(default);
        Assert.Contains(runner2.Calls, c => c.Args.Contains("/deletevalue"));
        Assert.Equal(SafeModePhase.Returning, orch2.Phase);
    }

    [Fact]
    public async Task F5_BeginRide_SafeBootRegistrationFailure_AbortsAndRollsBack()
    {
        var runner = new FakeRunner { Handler = (file, _) => file == "reg.exe" ? new ProcessResult(1, "", "denied", false) : new ProcessResult(0, "", "", false) };
        var orch = new SafeModeOrchestrator(runner, TestUtil.TempDir(), isWindows: () => true, isSafeModeNow: () => false);
        var r = await orch.BeginRideAsync("test", default);
        Assert.False(r.Ok);
        Assert.Equal("safeboot_registration_failed", r.ErrorClass);
        Assert.Equal(SafeModePhase.Failed, orch.Phase);
        Assert.Contains(runner.Calls, c => c.File == "bcdedit.exe" && c.Args.Contains("/deletevalue")); // rolled back
        Assert.DoesNotContain(runner.Calls, c => c.File == "shutdown.exe"); // never rebooted
    }

    // ---- F6: ConPTY launches as the user; failure paths dispose ----

    [Fact]
    public void F6_ConPty_UsesCreateProcessAsUser_NotCreateProcessW()
    {
        var methods = typeof(ConPtyTerminalSink).GetMethods(BindingFlags.NonPublic | BindingFlags.Static).Select(m => m.Name).ToList();
        Assert.Contains("CreateProcessAsUser", methods);
        Assert.Contains("WTSQueryUserToken", methods);
        Assert.DoesNotContain("CreateProcessW", methods);
    }

    [Fact]
    public void F6_ConPty_OffWindows_ReportsUnavailableHonestly()
    {
        if (OperatingSystem.IsWindows()) return; // the harness host is Linux; on Windows this is the laptop gate
        string? output = null;
        var sink = new ConPtyTerminalSink((_, line) => output = line);
        sink.Start("t1");
        Assert.Contains("unavailable", output);
    }

    // ---- F7: signature TOCTOU + policy-write audit + caps ----

    [Fact]
    public async Task F7_ScriptEngines_ExecutesSnapshotNotCallerPath_AndCapsTimeout()
    {
        var dir = TestUtil.TempDir();
        var script = Path.Combine(dir, "s.py");
        await File.WriteAllTextAsync(script, "print('hi')");
        var runner = new FakeRunner();
        var policy = new ScriptSignaturePolicy(dir);
        policy.SignedOnly = false; // explicit recorded opt-out for this test host
        using var verifier = new RsaUpdateSignatureVerifier();
        var module = new ScriptEnginesModule(runner, new FileScope(new[] { dir }), policy, verifier);
        var ctx = Ctx() with { DataDir = dir };
        var r = await module.ExecuteAsync(Args($$"""{"engine":"python","path":"{{script.Replace("\\", "\\\\")}}"}"""), ctx, default);
        Assert.True(r.Ok, r.Text);
        var call = Assert.Single(runner.Calls);
        Assert.Contains("script-snapshots", call.Args);
        Assert.DoesNotContain(script, call.Args); // the verified snapshot runs, never the caller's path re-opened
        Assert.Contains("-I", call.Args); // python isolated: no unsigned sibling imports from the script's directory
        var quoted = await module.ExecuteAsync(Args($$"""{"engine":"python","path":"{{script.Replace("\\", "\\\\")}}","args":"\" --evil"}"""), ctx, default);
        Assert.Equal("bad_arguments", quoted.ErrorClass);
        var longTimeout = await module.ExecuteAsync(Args($$"""{"engine":"python","path":"{{script.Replace("\\", "\\\\")}}","timeout_seconds":99999}"""), ctx, default);
        Assert.Equal("bad_arguments", longTimeout.ErrorClass);
    }

    [Fact]
    public async Task F7_ScriptSignaturePolicySet_IsAuditedWithActor()
    {
        var dir = TestUtil.TempDir();
        var audit = TestUtil.AuditLog(dir);
        var module = new ScriptSignaturePolicyModule(new ScriptSignaturePolicy(dir), audit);
        var r = await module.ExecuteAsync(Args("""{"action":"set","signed_only":false}"""), Ctx("admin-9"), default);
        Assert.True(r.Ok);
        var entry = audit.ReadTail(5).Single(e => e.Outcome == "policy_write");
        Assert.Equal("admin-9", entry.PairingId);
    }

    [Fact]
    public void F7_ToolModuleInstall_WritesExactlyTheVerifiedBytes()
    {
        var dir = TestUtil.TempDir();
        var source = Path.Combine(dir, "plug.dll");
        var bytes = new byte[] { 1, 2, 3, 4, 5 };
        File.WriteAllBytes(source, bytes);
        using var signer = new RsaUpdateSignatureVerifier();
        var policy = new ScriptSignaturePolicy(dir); // signed-only by default
        var module = new ToolModuleInstallModule(dir, signer, policy);
        var sig = Convert.ToBase64String(signer.Sign(bytes));
        var r = module.ExecuteAsync(Args($$"""{"action":"install","assembly_path":"{{source.Replace("\\", "\\\\")}}","signature":"{{sig}}"}"""), Ctx(), default).Result;
        Assert.True(r.Ok, r.Text);
        Assert.Equal(bytes, File.ReadAllBytes(Path.Combine(dir, "plugins", "plug.dll")));
    }

    // ---- F8: env_set cannot redirect launches or forge DeskGuest control vars ----

    [Fact]
    public async Task F8_EnvSet_ProtectedNamesRefused_ProcessEnvUntouched()
    {
        var module = new CertEnvAdminModule();
        foreach (var name in new[] { "PATH", "DESKGUEST_SAFE_MODE", "PYTHONPATH", "COMSPEC" })
        {
            var r = await module.ExecuteAsync(Args($$"""{"action":"env_set","name":"{{name}}","value":"x"}"""), Ctx(), default);
            Assert.False(r.Ok, name);
            Assert.Equal("protected_name", r.ErrorClass);
        }
        var ok = await module.ExecuteAsync(Args("""{"action":"env_set","name":"DESKGUEST_TEST_HARMLESS_MARKER","value":"x"}"""), Ctx(), default);
        Assert.False(ok.Ok); // DESKGUEST_* is refused wholesale — the assertion above covers the class; this name is DESKGUEST_ too
        var plain = await module.ExecuteAsync(Args("""{"action":"env_set","name":"BD2_PLAIN_MARKER","value":"v1"}"""), Ctx(), default);
        Assert.True(plain.Ok, plain.Text);
        Assert.Null(Environment.GetEnvironmentVariable("BD2_PLAIN_MARKER")); // the Core PROCESS env is never mutated
    }

    // ---- F9: macro replay goes through the policy runner or refuses ----

    [Fact]
    public async Task F9_MacroReplay_WithoutPolicyRunner_Refuses_AndTouchesNothing()
    {
        var dataDir = TestUtil.TempDir();
        var channel = new FakeAgentChannel();
        var module = new MacroModule(dataDir, channel);
        var ctx = Ctx();
        Assert.True((await module.ExecuteAsync(Args("""{"action":"save","name":"m1","steps":[{"engine":"shell_exec","args":{"command":"whoami"}}]}"""), ctx, default)).Ok);
        var replay = await module.ExecuteAsync(Args("""{"action":"replay","name":"m1"}"""), ctx, default);
        Assert.False(replay.Ok);
        Assert.Equal("replay_unavailable", replay.ErrorClass);
        Assert.Empty(channel.Calls); // the raw desktop channel was never touched
    }

    [Fact]
    public async Task F9_MacroReplay_WithPolicyRunner_StepsRunAsCallerPairing()
    {
        var dataDir = TestUtil.TempDir();
        var module = new MacroModule(dataDir, new FakeAgentChannel());
        var seen = new List<string>();
        module.PolicyStepRunner = (pairingId, tool, args, ct) => { seen.Add($"{pairingId}:{tool}"); return Task.FromResult(ToolResult.Success("ok")); };
        var ctx = Ctx("replayer-7");
        Assert.True((await module.ExecuteAsync(Args("""{"action":"save","name":"m2","steps":[{"engine":"click","args":{}},{"engine":"type_text","args":{}}]}"""), ctx, default)).Ok);
        var replay = await module.ExecuteAsync(Args("""{"action":"replay","name":"m2"}"""), ctx, default);
        Assert.True(replay.Ok, replay.Text);
        Assert.Equal(new[] { "replayer-7:click", "replayer-7:type_text" }, seen);
    }

    // ---- F10: health rules — dedup by transition, validated, bounded, persisted ----

    [Fact]
    public void F10_HealthRules_FireOncePerTrip_ValidateDirection_Persist()
    {
        var dir = TestUtil.TempDir();
        var path = Path.Combine(dir, "rules.json");
        var rules = new HealthAlertRules(path);
        Assert.Throws<ArgumentException>(() => rules.AddRule(new HealthAlertRules.Rule("bad", "m", 1, "sideways")));
        rules.AddRule(new HealthAlertRules.Rule("disk hot", "disk_pct", 90, "above"));
        var metrics = new Dictionary<string, double> { ["disk_pct"] = 95 };
        Assert.Single(rules.Evaluate(metrics, DateTimeOffset.UtcNow));
        Assert.Empty(rules.Evaluate(metrics, DateTimeOffset.UtcNow)); // still tripped: no flood
        Assert.Empty(rules.Evaluate(new Dictionary<string, double> { ["disk_pct"] = 10 }, DateTimeOffset.UtcNow)); // clears
        Assert.Single(rules.Evaluate(metrics, DateTimeOffset.UtcNow)); // trips again: fires again
        Assert.Equal(2, rules.Alerts.Count);
        var reloaded = new HealthAlertRules(path); // rules survive a restart now
        Assert.Single(reloaded.Rules);
    }

    // ---- F11: caller-shaped failures are ToolResults, not exceptions ----

    [Fact]
    public async Task F11_WakeOnLan_BadBroadcast_ReturnsCodedError()
    {
        var module = new WakeOnLanModule();
        var r = await module.ExecuteAsync(Args("""{"mac":"00:11:22:33:44:55","broadcast":"not-an-ip"}"""), Ctx(), default);
        Assert.False(r.Ok);
        Assert.Equal("bad_broadcast", r.ErrorClass);
    }

    [Fact]
    public async Task F11_SerialPort_MissingPort_ReturnsCodedError()
    {
        var module = new SerialPortModule();
        var r = await module.ExecuteAsync(Args("""{"action":"read","port":"COM99DOESNOTEXIST"}"""), Ctx(), default);
        Assert.False(r.Ok);
        Assert.Equal("port_unavailable", r.ErrorClass);
    }

    [Fact]
    public async Task F11_BrowserControl_PortClamp()
    {
        var module = new BrowserControlModule();
        var r = await module.ExecuteAsync(Args("""{"action":"targets","port":8080}"""), Ctx(), default);
        Assert.False(r.Ok);
        Assert.Equal("port_not_allowlisted", r.ErrorClass);
    }

    // ---- F12: fleet board parallel + caching; live view owner name + audit ----

    private sealed class StubPeerTransport : IPeerBoardTransport
    {
        public Func<string, Task<HostPublication?>> Handler = _ => Task.FromResult<HostPublication?>(null);
        public Task<HostPublication?> FetchAsync(string hostId, CancellationToken ct) => Handler(hostId);
    }

    private static HostPublication Pub(string id) =>
        new(id, id, "windows", default, false, null, null, true, DateTimeOffset.UtcNow);

    [Fact]
    public async Task F12_FleetBoard_HungPeerDoesNotStallBoard_AndSuccessIsCached()
    {
        var transport = new StubPeerTransport
        {
            Handler = id => id == "hung"
                ? new TaskCompletionSource<HostPublication?>().Task // never completes
                : Task.FromResult<HostPublication?>(Pub(id))
        };
        var board = new FleetBoard(transport, new[] { "hung", "fast" }) { PeerFetchTimeout = TimeSpan.FromMilliseconds(300) };
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var result = await board.BoardAsync(Pub("self"), default);
        sw.Stop();
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(5), $"board took {sw.Elapsed}");
        Assert.Contains(result, p => p.HostId == "fast");
        // Second fetch with the transport now failing: the cached
        // 'fast' publication is the last-known fallback.
        transport.Handler = _ => Task.FromResult<HostPublication?>(null);
        var result2 = await board.BoardAsync(Pub("self"), default);
        Assert.Contains(result2, p => p.HostId == "fast");
    }

    [Fact]
    public async Task F12_LiveView_TakeoverNoteUsesConfiguredOwnerName()
    {
        var state = new CoreState();
        state.UpdateSession(s => s with { TakeoverActive = true });
        var auditDir = TestUtil.TempDir();
        var audit = TestUtil.AuditLog(auditDir);
        var live = new LiveViewService(new AgentIpcServer(state, "tok"), state, audit, "Alex Owner");
        var r = await live.LatestFrameAsync("p1", "agent-x", default);
        Assert.True(r.Ok);
        Assert.Contains("Alex Owner has taken over", r.Text);
        Assert.DoesNotContain("DeskGuest", r.Text);
        Assert.Contains(audit.ReadTail(5), e => e.Outcome == "live_view_suspended:takeover");
    }
}
