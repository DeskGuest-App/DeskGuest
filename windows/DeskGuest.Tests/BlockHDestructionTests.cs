using System.Text.Json;
using DeskGuest.Core;
using DeskGuest.Core.Mcp;
using DeskGuest.Core.Modules;
using DeskGuest.Core.Services;
using DeskGuest.Shared.Policy;
using DeskGuest.Shared.Presence;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.Tools;
using IServiceProvider = DeskGuest.Core.Modules.IServiceProvider;

namespace DeskGuest.Tests;

/// <summary>Block H destruction pass ABOVE the model layer:
/// the MCP choke point, the presence state machine, and the wire
/// paths the new Block H surfaces ride. Every break found here
/// has a fix and a regression test in this file; outcomes are
/// recorded in DESTRUCTION-LEDGER.md (DG-H-* entries).</summary>
public class BlockHDestructionTests
{
    // ---- DG-H-01: the wire path dropped the Core's data dir ------
    // FOUND BY ATTACK: McpHandler built every execution context
    // with DataDir "". The only consumer is the self-restart
    // watchdog arm — so a service_restart issued over MCP (the
    // path an agent actually uses) armed a watchdog whose outcome
    // file landed in its working directory, and the next Core
    // start never consumed it: no chained-audit outcome entry, no
    // failure alert. The restart worked; its RECORD silently
    // vanished. Fixed: McpHandler carries the Core's data dir
    // (CoreRuntime passes options.DataDir) into every context.

    private sealed class DataDirProbeModule : IToolModule
    {
        public string? SeenDataDir;
        public ToolDescriptor Descriptor { get; } = new(
            "datadir_probe", "probe", Scopes.Observe, SessionRequirement.Core, RiskTier.Low, ExecutionContext: "SYSTEM");
        public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
        {
            SeenDataDir = ctx.DataDir;
            return Task.FromResult(ToolResult.Success("probe ran"));
        }
    }

    private sealed class SvcStub : IServiceProvider
    {
        public bool Available => true;
        public IReadOnlyList<ServiceInfo> List() => new[] { new ServiceInfo("DeskGuestCore", "DeskGuestCore", "Running", "Automatic") };
        public ServiceInfo? Status(string name) => new(name, name, "Running", "Automatic");
        public void Start(string name) { }
        public void Stop(string name) { }
        public void Restart(string name) { }
    }

    private sealed class ArmCapture : ISelfRestartArmer
    {
        public string? ServiceName, DataDir, ExePath;
        public void Arm(string serviceName, string dataDir, string exePath)
        {
            ServiceName = serviceName; DataDir = dataDir; ExePath = exePath;
        }
    }

    private static CoreState LiveState()
    {
        var state = new CoreState();
        state.UpdateSession(s => s with { SessionExists = true, AgentConnected = true, DesktopUnlocked = true });
        return state;
    }

    [Fact]
    public async Task Attack_WireRestart_ArmsWatchdogWithTheRealDataDir()
    {
        // CONV-style fixture correction (BLOCKH-DESTRUCTION TEST
        // REPAIR): BD-WIN-CORE-1 F6 closed the MCP choke point —
        // any non-Observe tool (except session_start, which creates
        // the session) is now denied when the calling pairing has
        // no live session of its own (no_session /
        // session_owned_by_other_pairing). This test previously
        // called service_restart over MCP with no presence session,
        // so F6 correctly denied it before the module ever ran and
        // the DG-H-01 assertion below never executed. The PRODUCT
        // behaviour is correct and gated; only this test's setup
        // was stale. Repair: the pairing first establishes its own
        // live session through the legitimate wire path —
        // session_start over MCP, registered exactly as
        // BdWinCore1FixTests' McpSetup registers it (no signed-
        // command gate configured in this rig, so the module's
        // pre-RMM-03 posture stands, as in that control) — and the
        // restart is then issued in that session. The test's
        // purpose is unchanged: a wire-issued restart must arm the
        // watchdog with the handler's real data dir. No product
        // code is special-cased and the F6 gate is not weakened.
        var (pairings, _, token) = TestUtil.MakePairing(Scopes.All);
        var registry = new ToolRegistry();
        var armer = new ArmCapture();
        var state = LiveState();
        var sessions = new SessionManager();
        registry.Register(new SessionStartModule(sessions, state));
        registry.Register(new ServiceControlModule(new SvcStub(), "restart", armer, "DeskGuestCore"));
        var dataDir = TestUtil.TempDir();
        var handler = new McpHandler(pairings, new PolicyEngine(), registry,
            TestUtil.AuditLog(TestUtil.TempDir()), state, sessions, dataDir);
        const string startBody = """{"jsonrpc":"2.0","id":0,"method":"tools/call","params":{"name":"session_start","arguments":{}}}""";
        var startResponse = await handler.HandleAsync(startBody, $"Bearer {token}", new HashSet<string>(), default);
        Assert.Contains("session_id", startResponse.Json);
        Assert.NotNull(sessions.Current);
        Assert.Equal(pairings.List().Single().Id, sessions.Current!.PairingId);
        const string body = """{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"service_restart","arguments":{"name":"DeskGuestCore"}}}""";
        var response = await handler.HandleAsync(body, $"Bearer {token}", new HashSet<string>(), default);
        Assert.Contains("ARMED", response.Json);
        Assert.Equal("DeskGuestCore", armer.ServiceName);
        // THE break: this used to be "" — the outcome file would
        // have landed in the watchdog's working directory.
        Assert.Equal(dataDir, armer.DataDir);
    }

    [Fact]
    public async Task Attack_ExecutionContext_CarriesTheHandlerDataDir()
    {
        var (pairings, _, token) = TestUtil.MakePairing(Scopes.All);
        var registry = new ToolRegistry();
        var probe = new DataDirProbeModule();
        registry.Register(probe);
        var dataDir = TestUtil.TempDir();
        var handler = new McpHandler(pairings, new PolicyEngine(), registry,
            TestUtil.AuditLog(TestUtil.TempDir()), LiveState(), new SessionManager(), dataDir);
        const string body = """{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"datadir_probe","arguments":{}}}""";
        var response = await handler.HandleAsync(body, $"Bearer {token}", new HashSet<string>(), default);
        Assert.Contains("probe ran", response.Json);
        Assert.Equal(dataDir, probe.SeenDataDir);
    }

    // ---- DG-H-02: presence can never be hidden by forgery --------
    // Barrage over the agent-side state machine: 2,000 seeded
    // operations in random order. Invariants after EVERY op:
    // presence is Off only when no session is active; Active only
    // with a live session and no STOP; the blocked modes only
    // while STOP is in force; and neither Dismiss nor SessionEnded
    // can ever clear the STOP flag itself — the notice is
    // dismissible, the block is not.

    [Fact]
    public void Attack_PresenceBarrage_InvariantsHoldUnderEverySequence()
    {
        var rng = new Random(42);
        var machine = new PresenceStateMachine();
        for (var i = 0; i < 2000; i++)
        {
            var stopBefore = machine.StopInForce;
            switch (rng.Next(6))
            {
                case 0: machine.SessionStarted("agent"); break;
                case 1:
                    machine.SessionEnded();
                    Assert.Equal(stopBefore, machine.StopInForce); // session end never clears STOP
                    break;
                case 2: machine.StopEngaged(); break;
                case 3: machine.StopCleared(); break;
                case 4:
                    machine.Dismiss();
                    Assert.Equal(stopBefore, machine.StopInForce); // dismiss touches the notice only
                    break;
                case 5: machine.ApplyDirective(rng.Next(2) == 0, "agent", rng.Next(2) == 0); break;
            }
            if (machine.Mode == PresenceMode.Off)
                Assert.False(machine.SessionActive, $"step {i}: presence Off during a live session");
            if (machine.Mode == PresenceMode.Active)
                Assert.True(machine.SessionActive && !machine.StopInForce, $"step {i}: Active without session or under STOP");
            if (machine.Mode is PresenceMode.Blocked or PresenceMode.BlockedDismissed)
                Assert.True(machine.StopInForce, $"step {i}: blocked mode without STOP in force");
            if (machine.StopInForce && machine.SessionActive)
                Assert.NotEqual(PresenceMode.Active, machine.Mode); // a stopped session never renders as merely active
        }
    }

    // ---- DG-H-03: the MCP choke point under attack ---------------

    private sealed class GuardedProbeModule : IToolModule
    {
        public int Executions;
        public ToolDescriptor Descriptor { get; } = new(
            "guarded_probe", "probe", Scopes.Drive, SessionRequirement.Core, RiskTier.Low, ExecutionContext: "SYSTEM");
        public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
        {
            Executions++;
            return Task.FromResult(ToolResult.Success("guarded ran"));
        }
    }

    [Fact]
    public async Task Attack_ScopeEscape_PairingWithoutTheScope_NeverExecutes()
    {
        var (pairings, _, token) = TestUtil.MakePairing(new HashSet<string> { Scopes.Observe });
        var registry = new ToolRegistry();
        var probe = new GuardedProbeModule();
        registry.Register(probe);
        var handler = new McpHandler(pairings, new PolicyEngine(), registry,
            TestUtil.AuditLog(TestUtil.TempDir()), LiveState(), new SessionManager(), TestUtil.TempDir());
        const string body = """{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"guarded_probe","arguments":{}}}""";
        var response = await handler.HandleAsync(body, $"Bearer {token}", new HashSet<string>(), default);
        Assert.Equal(0, probe.Executions);
        Assert.DoesNotContain("guarded ran", response.Json);
    }

    [Fact]
    public async Task Attack_RevokedPairing_Gets401_NothingExecutes()
    {
        var (pairings, pairing, token) = TestUtil.MakePairing(Scopes.All);
        var registry = new ToolRegistry();
        var probe = new GuardedProbeModule();
        registry.Register(probe);
        var handler = new McpHandler(pairings, new PolicyEngine(), registry,
            TestUtil.AuditLog(TestUtil.TempDir()), LiveState(), new SessionManager(), TestUtil.TempDir());
        Assert.True(pairings.Revoke(pairing.Id));
        const string body = """{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"guarded_probe","arguments":{}}}""";
        var response = await handler.HandleAsync(body, $"Bearer {token}", new HashSet<string>(), default);
        Assert.Equal(401, response.HttpStatus);
        Assert.Equal(0, probe.Executions);
    }

    [Fact]
    public async Task Attack_UnknownTool_AndMalformedBodies_ErrorCleanly()
    {
        var (pairings, _, token) = TestUtil.MakePairing(Scopes.All);
        var handler = new McpHandler(pairings, new PolicyEngine(), new ToolRegistry(),
            TestUtil.AuditLog(TestUtil.TempDir()), LiveState(), new SessionManager(), TestUtil.TempDir());
        var unknown = await handler.HandleAsync(
            """{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"no_such_tool","arguments":{}}}""",
            $"Bearer {token}", new HashSet<string>(), default);
        Assert.Contains("unknown tool", unknown.Json);
        // Malformed JSON, a JSON array, and an empty body: error
        // responses, never an exception escaping the handler.
        foreach (var body in new[] { "not json at all", "[1,2,3]", "", "   " })
        {
            var r = await handler.HandleAsync(body, $"Bearer {token}", new HashSet<string>(), default);
            Assert.True(r.HttpStatus >= 400 || r.Json is not null);
        }
        // No bearer at all: 401 before anything else happens.
        var anon = await handler.HandleAsync(
            """{"jsonrpc":"2.0","id":1,"method":"tools/list"}""", null, new HashSet<string>(), default);
        Assert.Equal(401, anon.HttpStatus);
    }
}
