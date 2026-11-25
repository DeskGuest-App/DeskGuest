using System.Text.Json;
using Acp.Core;
using Acp.Core.Ipc;
using Acp.Core.Mcp;
using Acp.Core.Modules;
using Acp.Shared.Audit;
using Acp.Shared.Policy;
using Acp.Shared.Security;
using Acp.Shared.Tools;

namespace Acp.Tests;

/// <summary>U3 — batch_actions dryRun + per-step policy evaluation.
/// Spec: log-union-verify.md item U3. The dry run must validate and
/// report while executing NOTHING: zero channel calls, zero
/// rate-budget consumption, no state moved; the dry run itself is
/// audited. Live batches stop BEFORE a step policy refuses.</summary>
public class BatchActionsDryRunTests
{
    private sealed class StubCoreModule : IToolModule
    {
        public ToolDescriptor Descriptor { get; } = new(
            "session_status", "stub non-desktop tool", Scopes.Observe, SessionRequirement.Core, RiskTier.Low, ExecutionContext: "SYSTEM");
        public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct) =>
            Task.FromResult(ToolResult.Success("stub"));
    }

    private sealed record Rig(BatchActionsModule Module, FakeAgentChannel Channel, PolicyEngine Policy, ToolRegistry Tools);

    private static Rig MakeRig(PolicyEngine? policy = null, IAuditLog? audit = null)
    {
        var channel = new FakeAgentChannel();
        var engine = policy ?? new PolicyEngine();
        var tools = new ToolRegistry();
        var module = new BatchActionsModule(channel, engine, tools, audit);
        tools.Register(module);
        foreach (var d in DesktopToolDescriptors.All())
            tools.Register(new ProxiedModule(channel, d));
        tools.Register(new StubCoreModule());
        return new Rig(module, channel, engine, tools);
    }

    private static ToolExecutionContext Ctx(Pairing pairing, IReadOnlySet<string>? approvedGates = null) =>
        new(pairing, TestUtil.Session(), TestUtil.State(), approvedGates ?? new HashSet<string>(), TestUtil.TempDir());

    private static JsonElement Args(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.Clone();
    }

    private static JsonElement Parse(string? text)
    {
        using var doc = JsonDocument.Parse(text!);
        return doc.RootElement.Clone();
    }

    private const string TwoGoodSteps = """{"dryRun":true,"steps":[{"tool":"mouse_move","arguments":{"x":1,"y":2}},{"tool":"scroll","arguments":{"delta":-3}}]}""";

    [Fact]
    public async Task DryRun_ExecutesNothing_AllStepsWouldPass()
    {
        var rig = MakeRig();
        var pairing = TestUtil.BarePairing(Scopes.All);
        var result = await rig.Module.ExecuteAsync(Args(TwoGoodSteps), Ctx(pairing), default);
        Assert.True(result.Ok, result.Text ?? result.UnavailableReason);
        Assert.Empty(rig.Channel.Calls); // the core U3 proof: nothing executed
        var root = Parse(result.Text);
        Assert.True(root.GetProperty("dry_run").GetBoolean());
        Assert.Equal(0, root.GetProperty("executed").GetInt32());
        Assert.Equal(2, root.GetProperty("steps_checked").GetInt32());
        Assert.True(root.GetProperty("all_steps_would_pass").GetBoolean());
        var verdicts = root.GetProperty("verdicts");
        Assert.Equal(2, verdicts.GetArrayLength());
        Assert.All(verdicts.EnumerateArray(), v => Assert.Equal("would_execute", v.GetProperty("verdict").GetString()));
        // Honesty: the result names what validation cannot know.
        Assert.NotEmpty(root.GetProperty("not_validated").EnumerateArray());
        Assert.All(verdicts.EnumerateArray(), v => Assert.False(v.GetProperty("effect_validated").GetBoolean()));
    }

    [Fact]
    public async Task DryRun_FlagsOutOfScopeStep()
    {
        var rig = MakeRig();
        var pairing = TestUtil.BarePairing(new HashSet<string> { Scopes.Observe, Scopes.Drive }); // no Shell
        var args = Args("""{"dryRun":true,"steps":[{"tool":"mouse_move","arguments":{"x":1,"y":2}},{"tool":"shell_exec","arguments":{"command":"echo hi"}}]}""");
        var result = await rig.Module.ExecuteAsync(args, Ctx(pairing), default);
        Assert.True(result.Ok, result.Text ?? result.UnavailableReason); // the dry run itself succeeded
        Assert.Empty(rig.Channel.Calls);
        var root = Parse(result.Text);
        Assert.False(root.GetProperty("all_steps_would_pass").GetBoolean());
        var verdicts = root.GetProperty("verdicts");
        Assert.Equal("would_execute", verdicts[0].GetProperty("verdict").GetString());
        Assert.Equal("blocked", verdicts[1].GetProperty("verdict").GetString());
        Assert.Contains("scope", verdicts[1].GetProperty("reason").GetString());
        Assert.Contains("'shell'", verdicts[1].GetProperty("reason").GetString());
    }

    [Fact]
    public async Task DryRun_FlagsGatedStep_AndPassesItWhenGateApproved()
    {
        var rig = MakeRig();
        var pairing = TestUtil.BarePairing(Scopes.All);
        var args = Args("""{"dryRun":true,"steps":[{"tool":"clipboard_get","arguments":{}}]}""");

        var denied = await rig.Module.ExecuteAsync(args, Ctx(pairing), default);
        var v = Parse(denied.Text).GetProperty("verdicts")[0];
        Assert.Equal("blocked", v.GetProperty("verdict").GetString());
        Assert.Contains("gated:clipboard_read", v.GetProperty("reason").GetString());
        Assert.Equal("clipboard_read", v.GetProperty("gate_class").GetString());

        var approved = await rig.Module.ExecuteAsync(args,
            Ctx(pairing, new HashSet<string> { "clipboard_read" }), default);
        var v2 = Parse(approved.Text).GetProperty("verdicts")[0];
        Assert.Equal("would_execute", v2.GetProperty("verdict").GetString());
        Assert.Empty(rig.Channel.Calls);
    }

    [Fact]
    public async Task DryRun_UnknownTool_NonDesktopTool_AndNestedBatch_AreBlocked()
    {
        var rig = MakeRig();
        var pairing = TestUtil.BarePairing(Scopes.All);
        var args = Args("""{"dryRun":true,"steps":[{"tool":"nope_tool","arguments":{}},{"tool":"session_status","arguments":{}},{"tool":"batch_actions","arguments":{"steps":[]}}]}""");
        var result = await rig.Module.ExecuteAsync(args, Ctx(pairing), default);
        Assert.Empty(rig.Channel.Calls);
        var verdicts = Parse(result.Text).GetProperty("verdicts");
        Assert.Contains("unknown_tool", verdicts[0].GetProperty("reason").GetString());
        Assert.Contains("not_a_desktop_step", verdicts[1].GetProperty("reason").GetString());
        Assert.Contains("not_a_desktop_step", verdicts[2].GetProperty("reason").GetString());
    }

    [Fact]
    public async Task DryRun_MissingRequiredArgument_IsBlocked()
    {
        var rig = MakeRig();
        var pairing = TestUtil.BarePairing(Scopes.All);
        var args = Args("""{"dryRun":true,"steps":[{"tool":"mouse_move","arguments":{"x":1}}]}""");
        var result = await rig.Module.ExecuteAsync(args, Ctx(pairing), default);
        var v = Parse(result.Text).GetProperty("verdicts")[0];
        Assert.Equal("blocked", v.GetProperty("verdict").GetString());
        Assert.Contains("invalid_arguments", v.GetProperty("reason").GetString());
        Assert.Contains("y", v.GetProperty("reason").GetString()!);
        Assert.Empty(rig.Channel.Calls);
    }

    [Fact]
    public async Task DryRun_DoesNotConsumeRateBudget()
    {
        // Cap of 2 recorded calls/minute: if dry-run step evaluation
        // recorded rate calls, the third dry run would start failing
        // with rate_limited and the live allowance would be gone.
        var rig = MakeRig(policy: new PolicyEngine(maxCallsPerMinute: 2));
        var pairing = TestUtil.BarePairing(Scopes.All);
        for (var n = 0; n < 5; n++)
        {
            var r = await rig.Module.ExecuteAsync(Args(TwoGoodSteps), Ctx(pairing), default);
            Assert.True(Parse(r.Text).GetProperty("all_steps_would_pass").GetBoolean(),
                $"dry run {n + 1} should still pass: {r.Text}");
        }
        Assert.Empty(rig.Channel.Calls);
        // The live allowance is untouched: two real evaluations pass,
        // the third is the one that hits the cap.
        var tool = rig.Tools.Find("mouse_move")!.Descriptor;
        var a1 = rig.Policy.Evaluate(pairing, tool, Args("{}"), TestUtil.Session(), TestUtil.State(), new HashSet<string>());
        var a2 = rig.Policy.Evaluate(pairing, tool, Args("{}"), TestUtil.Session(), TestUtil.State(), new HashSet<string>());
        var a3 = rig.Policy.Evaluate(pairing, tool, Args("{}"), TestUtil.Session(), TestUtil.State(), new HashSet<string>());
        Assert.True(a1.Allowed);
        Assert.True(a2.Allowed);
        Assert.False(a3.Allowed);
        Assert.Contains("rate_limited", a3.DenyReason);
    }

    [Fact]
    public async Task DryRun_IsAudited()
    {
        var dir = TestUtil.TempDir();
        var audit = TestUtil.AuditLog(dir);
        var rig = MakeRig(audit: audit);
        var pairing = TestUtil.BarePairing(Scopes.All);
        var result = await rig.Module.ExecuteAsync(Args(TwoGoodSteps), Ctx(pairing), default);
        Assert.True(result.Ok);
        var entries = audit.ReadTail(10);
        var entry = Assert.Single(entries, e => e.Kind == "batch_dry_run");
        Assert.Equal("batch_actions", entry.Tool);
        Assert.StartsWith("dry_run:", entry.Outcome);
        Assert.Contains("all_2_steps_would_execute", entry.Outcome);
        Assert.Equal(pairing.Id, entry.PairingId);
    }

    [Fact]
    public async Task DryRun_UnwiredModule_RefusesHonestly_AndExecutesNothing()
    {
        var channel = new FakeAgentChannel();
        var module = new BatchActionsModule(channel); // no policy / registry wired
        var pairing = TestUtil.BarePairing(Scopes.All);
        var result = await module.ExecuteAsync(Args(TwoGoodSteps), Ctx(pairing), default);
        Assert.False(result.Ok);
        Assert.Equal("dry_run_unavailable", result.ErrorClass);
        Assert.Empty(channel.Calls);
    }

    [Fact]
    public async Task NonBooleanDryRun_Refuses_ExecutesNothing()
    {
        // Destruction: dryRun:"true" / dryRun:1 must not fall through
        // to a live execution of the steps.
        var rig = MakeRig();
        var pairing = TestUtil.BarePairing(Scopes.All);
        foreach (var bad in new[] { "\"true\"", "1", "null" })
        {
            var args = Args("{\"dryRun\":" + bad + ",\"steps\":[{\"tool\":\"mouse_move\",\"arguments\":{\"x\":1,\"y\":2}}]}");
            var result = await rig.Module.ExecuteAsync(args, Ctx(pairing), default);
            Assert.False(result.Ok);
            Assert.Equal("bad_arguments", result.ErrorClass);
        }
        Assert.Empty(rig.Channel.Calls);
    }

    [Fact]
    public async Task Live_StopsBeforeOutOfScopeStep_RatherThanAfterIt()
    {
        var rig = MakeRig();
        var pairing = TestUtil.BarePairing(new HashSet<string> { Scopes.Observe, Scopes.Drive }); // no Shell
        var args = Args("""{"steps":[{"tool":"mouse_move","arguments":{"x":1,"y":2}},{"tool":"shell_exec","arguments":{"command":"echo hi"}},{"tool":"mouse_move","arguments":{"x":3,"y":4}}]}""");
        var result = await rig.Module.ExecuteAsync(args, Ctx(pairing), default);
        Assert.False(result.Ok);
        Assert.Equal("step_failed", result.ErrorClass);
        // Exactly ONE channel call: step 1 ran; step 2 was refused
        // before execution; step 3 never reached.
        var call = Assert.Single(rig.Channel.Calls);
        Assert.Equal("mouse_move", call.Tool);
        var root = Parse(result.Text);
        Assert.Equal(2, root.GetProperty("failed_step").GetInt32());
        Assert.Contains("scope", root.GetProperty("reason").GetString());
    }

    [Fact]
    public async Task Live_AllStepsPass_ExecutesInOrder()
    {
        var rig = MakeRig();
        var pairing = TestUtil.BarePairing(Scopes.All);
        var args = Args("""{"steps":[{"tool":"mouse_move","arguments":{"x":1,"y":2}},{"tool":"scroll","arguments":{"delta":5}}]}""");
        var result = await rig.Module.ExecuteAsync(args, Ctx(pairing), default);
        Assert.True(result.Ok, result.Text ?? result.UnavailableReason);
        Assert.Equal(2, Parse(result.Text).GetProperty("completed").GetInt32());
        Assert.Equal(new[] { "mouse_move", "scroll" }, rig.Channel.Calls.Select(c => c.Tool).ToArray());
    }

    [Fact]
    public async Task Live_StepFailure_StillStopsAndNamesIt()
    {
        var rig = MakeRig();
        rig.Channel.Handler = (tool, _) => tool == "scroll"
            ? ToolResult.Unavailable("engine refused scroll")
            : ToolResult.Success("ok");
        var pairing = TestUtil.BarePairing(Scopes.All);
        var args = Args("""{"steps":[{"tool":"mouse_move","arguments":{"x":1,"y":2}},{"tool":"scroll","arguments":{"delta":5}},{"tool":"mouse_move","arguments":{"x":9,"y":9}}]}""");
        var result = await rig.Module.ExecuteAsync(args, Ctx(pairing), default);
        Assert.False(result.Ok);
        Assert.Equal(2, Parse(result.Text).GetProperty("failed_step").GetInt32());
        Assert.Equal(2, rig.Channel.Calls.Count); // third step never ran
    }
}

/// <summary>U3 at the wire choke point: a dry-run batch call through
/// the real McpHandler must move NO state — no SessionBudget session
/// begun or counted, no session action counted, and the SCAM
/// tripwire must NOT pause the session — while still being audited
/// (outer tool_call entry + the module's batch_dry_run entry). The
/// fixture is armed: the foreground is a password manager, so the
/// same call WITHOUT dryRun tripwire-pauses the session (asserted
/// at the end, proving the fixture could actually fire).</summary>
public class BatchActionsDryRunWireTests
{
    [Fact]
    public async Task Wire_DryRun_MovesNoState_TripsNothing_AndIsAudited()
    {
        var (pairings, pairing, token) = TestUtil.MakePairing(Scopes.All);
        var dir = TestUtil.TempDir();
        var audit = TestUtil.AuditLog(dir);
        var channel = new FakeAgentChannel();
        var policy = new PolicyEngine();
        var registry = new ToolRegistry();
        var module = new BatchActionsModule(channel, policy, registry, audit);
        registry.Register(module);
        foreach (var d in DesktopToolDescriptors.All())
            registry.Register(new ProxiedModule(channel, d));
        var state = new CoreState();
        state.UpdateSession(s => s with { SessionExists = true, AgentConnected = true, DesktopUnlocked = true });
        state.ApplyAgentSessionReport(null, null, "vault.kdbx — KeePass", "KeePass"); // SCAM-sensitive foreground
        var sessions = new SessionManager();
        var session = sessions.Start(pairing);
        var handler = new McpHandler(pairings, policy, registry, audit, state, sessions, dir);

        const string dryBody = """{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"batch_actions","arguments":{"dryRun":true,"steps":[{"tool":"mouse_move","arguments":{"x":1,"y":2}}]}}}""";
        var dry = await handler.HandleAsync(dryBody, $"Bearer {token}", new HashSet<string>(), default);
        Assert.Contains("would_execute", dry.Json);
        Assert.Empty(channel.Calls);                                   // nothing executed
        Assert.False(sessions.IsPaused);                               // SCAM tripwire did NOT fire
        Assert.Equal(0, sessions.ActionCount);                         // no action counted
        Assert.False(handler.Budgets.HasSession(session.Id));          // no budget session begun/counted
        var kinds = audit.ReadTail(20).Select(e => e.Kind).ToList();
        Assert.Contains("tool_call", kinds);                           // outer call audited by the choke point
        Assert.Contains("batch_dry_run", kinds);                       // the dry run itself audited by the module

        // The fixture was armed: the same batch WITHOUT dryRun is a
        // Drive call in a sensitive foreground — it tripwire-pauses.
        const string liveBody = """{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"batch_actions","arguments":{"steps":[{"tool":"mouse_move","arguments":{"x":1,"y":2}}]}}}""";
        var live = await handler.HandleAsync(liveBody, $"Bearer {token}", new HashSet<string>(), default);
        Assert.Contains("scam_sensitive_context", live.Json);
        Assert.True(sessions.IsPaused);
        Assert.Empty(channel.Calls); // the tripped call never executed either
    }
}

/// <summary>U3 support: PolicyEngine.EvaluateDryRun must be a pure
/// peek — same verdicts, no recorded rate call, no pruned state.</summary>
public class PolicyDryRunTests
{
    private static ToolDescriptor Tool() =>
        new("mouse_move", "test", Scopes.Drive, SessionRequirement.Agent, RiskTier.Low, null, "Agent");

    private static JsonElement Args(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.Clone();
    }

    [Fact]
    public void EvaluateDryRun_SameVerdicts_ZeroRecordedCalls()
    {
        var engine = new PolicyEngine(maxCallsPerMinute: 1);
        var pairing = TestUtil.BarePairing(Scopes.All);
        // Three dry evaluations: all allowed, none recorded.
        for (var n = 0; n < 3; n++)
        {
            var d = engine.EvaluateDryRun(pairing, Tool(), Args("{}"), TestUtil.Session(), TestUtil.State(), new HashSet<string>());
            Assert.True(d.Allowed, d.DenyReason);
        }
        // The single live slot is still there — and is consumed by
        // exactly one live evaluation.
        var live1 = engine.Evaluate(pairing, Tool(), Args("{}"), TestUtil.Session(), TestUtil.State(), new HashSet<string>());
        Assert.True(live1.Allowed);
        var live2 = engine.Evaluate(pairing, Tool(), Args("{}"), TestUtil.Session(), TestUtil.State(), new HashSet<string>());
        Assert.False(live2.Allowed);
        Assert.Contains("rate_limited", live2.DenyReason);
        // And a dry run now honestly reports the exhausted window.
        var dryAfter = engine.EvaluateDryRun(pairing, Tool(), Args("{}"), TestUtil.Session(), TestUtil.State(), new HashSet<string>());
        Assert.False(dryAfter.Allowed);
        Assert.Contains("rate_limited", dryAfter.DenyReason);
    }

    [Fact]
    public void EvaluateDryRun_StillDeniesScopeGateAndStop()
    {
        var engine = new PolicyEngine();
        var gated = new ToolDescriptor("clipboard_get", "test", Scopes.Drive, SessionRequirement.Agent, RiskTier.Medium, "clipboard_read", "Agent");
        var noDrive = TestUtil.BarePairing(new HashSet<string> { Scopes.Observe });
        var d1 = engine.EvaluateDryRun(noDrive, Tool(), Args("{}"), TestUtil.Session(), TestUtil.State(), new HashSet<string>());
        Assert.False(d1.Allowed);
        Assert.Contains("scope", d1.DenyReason);
        var all = TestUtil.BarePairing(Scopes.All);
        var d2 = engine.EvaluateDryRun(all, gated, Args("{}"), TestUtil.Session(), TestUtil.State(), new HashSet<string>());
        Assert.False(d2.Allowed);
        Assert.Contains("gated:clipboard_read", d2.DenyReason);
        var d3 = engine.EvaluateDryRun(all, Tool(), Args("{}"), TestUtil.Session(stop: true), TestUtil.State(), new HashSet<string>());
        Assert.False(d3.Allowed);
        Assert.Contains("stopped_by_user", d3.DenyReason);
    }
}
