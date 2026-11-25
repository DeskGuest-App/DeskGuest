using System.Text.Json;
using Acp.Core;
using Acp.Core.Mcp;
using Acp.Core.Modules;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Policy;
using Acp.Shared.Security;
using Acp.Shared.Sessions;
using Acp.Shared.Tools;

namespace Acp.Tests;

/// <summary>U1 — clipboard direction policy, sensitive-item skip,
/// per-read indicator. Pure policy/gate cases, the descriptor
/// gate-class split, the RMM-07 policy plumbing, and choke-point
/// integration through the real McpHandler.</summary>
public class ClipboardPolicyTests
{
    private static ClipboardPolicy Policy(ClipboardDirection d, bool skip = true) => new(d, skip);

    // ---------- direction matrix (the gate the engine applies) ----------

    [Theory]
    [InlineData(ClipboardDirection.Both, true, true)]
    [InlineData(ClipboardDirection.HostToAgent, true, false)]
    [InlineData(ClipboardDirection.AgentToHost, false, true)]
    [InlineData(ClipboardDirection.Off, false, false)]
    public void DirectionMatrix_ReadWrite(ClipboardDirection direction, bool read, bool write)
    {
        var policy = Policy(direction);
        Assert.Equal(read, policy.AllowsRead);
        Assert.Equal(write, policy.AllowsWrite);
        Assert.Equal(read, ClipboardGate.CheckRead(policy, "benign text").Ok);
        Assert.Equal(write, ClipboardGate.CheckWrite(policy).Ok);
        if (!read) Assert.Contains("clipboard_direction", ClipboardGate.CheckRead(policy, "benign text").Refusal);
        if (!write) Assert.Contains("clipboard_direction", ClipboardGate.CheckWrite(policy).Refusal);
        // Non-clipboard tools are never this layer's business.
        Assert.Null(policy.DenyReasonFor("screenshot"));
        Assert.Null(policy.DenyReasonFor("file_read"));
    }

    [Fact]
    public void DenyReason_NamesTheDirectionAndTheKey()
    {
        var reason = Policy(ClipboardDirection.AgentToHost).DenyReasonFor("clipboard_get");
        Assert.Contains("agent_to_host", reason);
        Assert.Contains("clipboard.direction", reason);
        Assert.Contains("host → agent", reason);
        var setReason = Policy(ClipboardDirection.HostToAgent).DenyReasonFor("clipboard_set");
        Assert.Contains("host_to_agent", setReason);
        Assert.Contains("agent → host", setReason);
    }

    // ---------- sensitive-item skip (seeded strings) ----------

    [Fact]
    public void SensitiveSkip_SeededSensitiveClips_AreRefusedByClass_NeverReturned()
    {
        Assert.Equal("credential_secret", ClipboardSensitivity.SensitiveClassifierFor("password = hunter2hunter2"));
        Assert.Equal("credential_secret", ClipboardSensitivity.SensitiveClassifierFor("AKIAIOSFODNN7EXAMPLE"));
        Assert.Equal("payment_card", ClipboardSensitivity.SensitiveClassifierFor("card 4111 1111 1111 1111 exp 12/29"));
        Assert.Equal("national_id", ClipboardSensitivity.SensitiveClassifierFor("ssn 219-09-9998"));
        foreach (var clip in new[]
                 {
                     "password = hunter2hunter2",
                     "the card is 4111 1111 1111 1111",
                     "219-09-9998",
                 })
        {
            var (ok, refusal) = ClipboardGate.CheckRead(ClipboardPolicy.Default, clip);
            Assert.False(ok);
            Assert.Contains("clipboard_sensitive", refusal);
            Assert.DoesNotContain(clip, refusal); // the refusal never echoes content
        }
    }

    [Fact]
    public void SensitiveSkip_BenignClip_PassesUntouched()
    {
        Assert.Null(ClipboardSensitivity.SensitiveClassifierFor("meeting notes for Tuesday — bring the Q3 figures"));
        Assert.Null(ClipboardSensitivity.SensitiveClassifierFor(""));
        Assert.Null(ClipboardSensitivity.SensitiveClassifierFor(null));
        var (ok, refusal) = ClipboardGate.CheckRead(ClipboardPolicy.Default, "meeting notes for Tuesday");
        Assert.True(ok);
        Assert.Null(refusal);
    }

    [Fact]
    public void SensitiveSkip_DisabledByPolicy_LetsSensitiveTextThrough()
    {
        var (ok, _) = ClipboardGate.CheckRead(Policy(ClipboardDirection.Both, skip: false), "password = hunter2hunter2");
        Assert.True(ok);
    }

    [Fact]
    public void SensitiveSkip_DirectionDenialOutranksTheClassifier()
    {
        // Direction off + sensitive content: the refusal is the
        // direction refusal — the content is never even classified
        // for return, and the reason never hints at the class.
        var (ok, refusal) = ClipboardGate.CheckRead(Policy(ClipboardDirection.Off), "password = hunter2hunter2");
        Assert.False(ok);
        Assert.Contains("clipboard_direction", refusal);
        Assert.DoesNotContain("credential_secret", refusal);
    }

    // ---------- policy plumbing (RMM-07 pattern) ----------

    [Fact]
    public void PolicyKeys_ResolveFromEffectivePolicy()
    {
        var engine = new ManagementPolicyEngine();
        var facts = StaticDeviceFacts.Of("dev1", "scope1");
        var doc = new ManagementPolicyDocument("d1", PolicyLevels.Device, "dev1",
            new Dictionary<string, string>
            {
                ["clipboard.direction"] = "agent_to_host",
                ["clipboard.sensitive_skip"] = "false",
            }, 1);
        Assert.True(engine.AddDocument(doc).Allowed);
        var policy = ClipboardPolicy.FromEffective(engine.ComputeEffective(facts));
        Assert.Equal(ClipboardDirection.AgentToHost, policy.Direction);
        Assert.False(policy.SensitiveSkip);
    }

    [Fact]
    public void PolicyKeys_MalformedValues_AreIgnored_DefaultsStand()
    {
        var engine = new ManagementPolicyEngine();
        var facts = StaticDeviceFacts.Of("dev1", "scope1");
        var doc = new ManagementPolicyDocument("d1", PolicyLevels.Device, "dev1",
            new Dictionary<string, string>
            {
                ["clipboard.direction"] = "sideways",       // not a direction
                ["clipboard.sensitive_skip"] = "sometimes", // not a boolean
            }, 1);
        Assert.True(engine.AddDocument(doc).Allowed);
        var policy = ClipboardPolicy.FromEffective(engine.ComputeEffective(facts));
        Assert.Equal(ClipboardPolicy.Default, policy);
        Assert.Equal(ClipboardPolicy.Default, ClipboardPolicy.FromEffective(null));
    }

    [Fact]
    public void Registry_CarriesTheClipboardToggle_DefaultOn()
    {
        var registry = FeatureToggleRegistry.Seeded();
        Assert.True(registry.TryGet("rmm.clipboard_policy.enabled", out var toggle));
        Assert.True(toggle!.DefaultEnabled);
        var engine = new ManagementPolicyEngine(registry);
        Assert.True(engine.IsEnabled(StaticDeviceFacts.Of("dev1", ""), "rmm.clipboard_policy.enabled"));
    }

    [Fact]
    public void IpcRoundTrip_PreservesPolicy_MalformedPushIgnored()
    {
        var policy = new ClipboardPolicy(ClipboardDirection.HostToAgent, false);
        Assert.Equal(policy, ClipboardPolicy.FromIpcJson(policy.ToIpcJson()));
        Assert.Equal(ClipboardPolicy.Default, ClipboardPolicy.FromIpcJson(ClipboardPolicy.Default.ToIpcJson()));
        Assert.Null(ClipboardPolicy.FromIpcJson(null));
        Assert.Null(ClipboardPolicy.FromIpcJson("not json"));
        Assert.Null(ClipboardPolicy.FromIpcJson("""{"direction":"sideways","sensitiveSkip":true}"""));
    }

    // ---------- descriptor gate-class split ----------

    [Fact]
    public void Descriptors_SplitGateClasses_BothGatedInEveryMode()
    {
        var all = DesktopToolDescriptors.All().ToList();
        Assert.Equal("clipboard_read", all.Single(d => d.Name == "clipboard_get").GateClass);
        Assert.Equal("clipboard_write", all.Single(d => d.Name == "clipboard_set").GateClass);
        Assert.Contains("clipboard_read", PolicyEngine.GatedClasses);
        Assert.Contains("clipboard_write", PolicyEngine.GatedClasses);
    }

    [Fact]
    public void GateClasses_WriteNeedsItsOwnApproval()
    {
        var engine = new PolicyEngine();
        var pairing = TestUtil.BarePairing(Scopes.All);
        var setTool = DesktopToolDescriptors.All().Single(d => d.Name == "clipboard_set");
        // Approving READS does not approve WRITES (the split is real).
        var denied = engine.Evaluate(pairing, setTool, Args("{}"), TestUtil.Session(), TestUtil.State(),
            new HashSet<string> { "clipboard_read" });
        Assert.False(denied.Allowed);
        Assert.Contains("gated:clipboard_write", denied.DenyReason);
        var allowed = engine.Evaluate(pairing, setTool, Args("{}"), TestUtil.Session(), TestUtil.State(),
            new HashSet<string> { "clipboard_write" });
        Assert.True(allowed.Allowed);
    }

    private static JsonElement Args(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.Clone();
    }

    // ---------- choke-point integration ----------

    private sealed class StubModule(string name, string? gate, string text) : IToolModule
    {
        public ToolDescriptor Descriptor { get; } = new(name, "stub", Scopes.Drive, SessionRequirement.Agent, RiskTier.Medium, gate, "Agent");
        public int Calls;
        public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
        {
            Calls++;
            return Task.FromResult(ToolResult.Success(text));
        }
    }

    private sealed class Rig
    {
        public required McpHandler Handler;
        public required SessionManager Sessions;
        public required CoreState State;
        public required string Token;
        public required string PairingId;
        public required StubModule Get;
        public required StubModule Set;
        public ClipboardPolicy? Policy;
        public bool PolicyLayerOff;

        public async Task<string> Call(string tool, params string[] approvedGates)
        {
            var body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"" + tool + "\",\"arguments\":{}}}";
            var resp = await Handler.HandleAsync(body, $"Bearer {Token}", new HashSet<string>(approvedGates), default);
            return resp.Json!;
        }
    }

    private static Rig BuildRig()
    {
        var (pairings, pairing, token) = TestUtil.MakePairing(Scopes.All);
        var registry = new ToolRegistry();
        var state = new CoreState();
        var sessions = new SessionManager();
        registry.Register(new SessionStartModule(sessions, state));
        registry.Register(new SessionStopModule(sessions, state));
        var get = new StubModule("clipboard_get", "clipboard_read", "benign clip text");
        var set = new StubModule("clipboard_set", "clipboard_write", "clipboard set");
        registry.Register(get);
        registry.Register(set);
        var auditDir = TestUtil.TempDir();
        var handler = new McpHandler(pairings, new PolicyEngine(), registry,
            TestUtil.AuditLog(auditDir), state, sessions, auditDir);
        var rig = new Rig
        {
            Handler = handler, Sessions = sessions, State = state, Token = token,
            PairingId = pairing.Id, Get = get, Set = set,
        };
        sessions.ClipboardPolicyProvider = () => rig.PolicyLayerOff ? null : rig.Policy ?? ClipboardPolicy.Default;
        state.UpdateSession(s => s with { SessionExists = true, AgentConnected = true, DesktopUnlocked = true });
        return rig;
    }

    [Fact]
    public async Task ChokePoint_WriteOnly_GetDeniedBeforeExecution_SetExecutes()
    {
        var rig = BuildRig();
        rig.Policy = new ClipboardPolicy(ClipboardDirection.AgentToHost, true);
        await rig.Call("session_start");
        var getResp = await rig.Call("clipboard_get", "clipboard_read", "clipboard_write");
        Assert.Contains("clipboard_direction", getResp);
        Assert.Equal(0, rig.Get.Calls); // denied BEFORE execution
        var setResp = await rig.Call("clipboard_set", "clipboard_read", "clipboard_write");
        Assert.Contains("clipboard set", setResp);
        Assert.Equal(1, rig.Set.Calls);
    }

    [Fact]
    public async Task ChokePoint_ReadOnly_SetDenied_GetExecutes()
    {
        var rig = BuildRig();
        rig.Policy = new ClipboardPolicy(ClipboardDirection.HostToAgent, true);
        await rig.Call("session_start");
        var setResp = await rig.Call("clipboard_set", "clipboard_read", "clipboard_write");
        Assert.Contains("clipboard_direction", setResp);
        Assert.Equal(0, rig.Set.Calls);
        var getResp = await rig.Call("clipboard_get", "clipboard_read", "clipboard_write");
        Assert.Contains("benign clip text", getResp);
        Assert.Equal(1, rig.Get.Calls);
    }

    [Fact]
    public async Task ChokePoint_Off_BothDirectionsDenied_NothingExecutes()
    {
        var rig = BuildRig();
        rig.Policy = new ClipboardPolicy(ClipboardDirection.Off, true);
        await rig.Call("session_start");
        Assert.Contains("clipboard_direction", await rig.Call("clipboard_get", "clipboard_read", "clipboard_write"));
        Assert.Contains("clipboard_direction", await rig.Call("clipboard_set", "clipboard_read", "clipboard_write"));
        Assert.Equal(0, rig.Get.Calls);
        Assert.Equal(0, rig.Set.Calls);
    }

    [Fact]
    public async Task ChokePoint_LayerToggledOff_BehavesExactlyAsBeforeU1()
    {
        var rig = BuildRig();
        rig.PolicyLayerOff = true;
        await rig.Call("session_start");
        Assert.Contains("benign clip text", await rig.Call("clipboard_get", "clipboard_read", "clipboard_write"));
        Assert.Contains("clipboard set", await rig.Call("clipboard_set", "clipboard_read", "clipboard_write"));
        Assert.Equal(1, rig.Get.Calls);
        Assert.Equal(1, rig.Set.Calls);
    }

    [Fact]
    public async Task ChokePoint_GateOutranksDirection_UnapprovedReadDeniedAsGated()
    {
        // Consent floor order: with the direction OPEN but no gate
        // approval, the denial is the gate's, not the direction's.
        var rig = BuildRig();
        rig.Policy = ClipboardPolicy.Default;
        await rig.Call("session_start");
        var resp = await rig.Call("clipboard_get");
        Assert.Contains("gated:clipboard_read", resp);
        Assert.Equal(0, rig.Get.Calls);
    }

    [Fact]
    public async Task PerReadIndicator_EventPublishedToOwningPairing_NarrationSet()
    {
        var rig = BuildRig();
        rig.Policy = ClipboardPolicy.Default;
        var store = new EventSubscriptionStore();
        var bus = new AgentEventBus(store, _ => true);
        rig.Handler.Events = bus;
        store.Subscribe(rig.PairingId, new[] { AgentEventKinds.ClipboardRead });
        var received = new List<AgentEvent>();
        bus.Attach(rig.PairingId, received.Add);
        // A second pairing subscribed to the same kind must NOT see
        // this pairing's read (origin scoping).
        store.Subscribe("other-pairing", new[] { AgentEventKinds.ClipboardRead });
        var other = new List<AgentEvent>();
        bus.Attach("other-pairing", other.Add);

        await rig.Call("session_start");
        await rig.Call("clipboard_get", "clipboard_read", "clipboard_write");

        // F3: delivery is pumped asynchronously off the producer.
        var deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(5);
        while (received.Count == 0 && DateTimeOffset.UtcNow < deadline) await Task.Delay(10);
        var evt = Assert.Single(received);
        Assert.Equal(AgentEventKinds.ClipboardRead, evt.Kind);
        Assert.Contains("chars", evt.Detail);
        Assert.DoesNotContain("benign clip text", evt.Detail); // count only, never content
        Assert.Empty(other);
        Assert.Equal($"Clipboard read by test-agent", rig.State.LastNarration);
    }
}
