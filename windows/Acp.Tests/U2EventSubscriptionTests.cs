using System.Text.Json;
using Acp.Core;
using Acp.Core.Mcp;
using Acp.Core.Modules;
using Acp.Shared.Policy;
using Acp.Shared.Security;
using Acp.Shared.Sessions;
using Acp.Shared.Tools;

namespace Acp.Tests;

/// <summary>U2 regression + destruction tests: agent event
/// subscriptions. The registry, the per-pairing filter, the bus
/// delivery rule (kind filter + D9 origin rule), the choke-point
/// producers, the SSE stream (subscribed kinds only; STOP kills
/// it), and the destruction legs: subscribe beyond own scope,
/// cross-pairing event leakage, subscription as audit evasion.</summary>
public class U2EventSubscriptionTests
{
    // ---------- registry + store ----------

    [Fact]
    public void Registry_NamesTheCensusKinds()
    {
        // The six U2 census kinds, plus U1's clipboard_read
        // extension (added by the U1 lane to this shared registry).
        foreach (var k in new[] { "session", "approval", "screen_change", "foreground_app", "app_crash", "notification_posted", "clipboard_read" })
            Assert.True(AgentEventKinds.IsValid(k), k);
        Assert.False(AgentEventKinds.IsValid("tool_call"));
        Assert.False(AgentEventKinds.IsValid(""));
    }

    [Fact]
    public void Subscribe_UnknownKind_RefusesAtomically()
    {
        var store = new EventSubscriptionStore();
        var (ok, error) = store.Subscribe("p1", new[] { "session", "bogus_kind" });
        Assert.False(ok);
        Assert.Contains("unknown_event_kind", error);
        Assert.Empty(store.FilterFor("p1")); // no partial subscription
    }

    [Fact]
    public void Subscribe_Empty_Refuses()
    {
        var store = new EventSubscriptionStore();
        Assert.False(store.Subscribe("p1", Array.Empty<string>()).Ok);
    }

    [Fact]
    public void Unsubscribe_Partial_ThenWhole_AndClearPairing()
    {
        var store = new EventSubscriptionStore();
        Assert.True(store.Subscribe("p1", new[] { "session", "approval" }).Ok);
        Assert.True(store.Unsubscribe("p1", new[] { "session" }).Ok);
        Assert.Equal(new HashSet<string> { "approval" }, store.FilterFor("p1"));
        Assert.True(store.Unsubscribe("p1", null).Ok);
        Assert.Empty(store.FilterFor("p1"));
        Assert.True(store.Subscribe("p1", new[] { "session" }).Ok);
        store.ClearPairing("p1");
        Assert.Empty(store.FilterFor("p1"));
    }

    // ---------- bus delivery rule ----------

    // BD-SUPP-EVENTSUB F3: delivery runs on each attachment's own
    // pump (Publish never invokes a handler), so tests wait for the
    // pump instead of asserting on the producer's thread.
    internal static void WaitFor(Func<bool> condition, int timeoutMs = 5000)
    {
        var deadline = DateTimeOffset.UtcNow + TimeSpan.FromMilliseconds(timeoutMs);
        while (DateTimeOffset.UtcNow < deadline)
        {
            if (condition()) return;
            Thread.Sleep(10);
        }
        Assert.True(condition(), "condition not met within timeout");
    }


    private static (EventSubscriptionStore Store, AgentEventBus Bus, List<AgentEvent> Got) AttachFor(string pairing)
    {
        var store = new EventSubscriptionStore();
        var bus = new AgentEventBus(store, _ => true);
        var got = new List<AgentEvent>();
        bus.Attach(pairing, got.Add);
        return (store, bus, got);
    }

    [Fact]
    public void Stream_ReceivesOnlySubscribedKinds()
    {
        var (store, bus, got) = AttachFor("p1");
        store.Subscribe("p1", new[] { "session" });
        bus.Publish("session", "session_started: s1", "p1");
        bus.Publish("approval", "approval_required: x", "p1");
        bus.Publish("app_crash", "app_crash: x", null);
        WaitFor(() => got.Count == 1);
        Assert.Single(got);
        Assert.Equal("session", got[0].Kind);
    }

    [Fact]
    public void UnsubscribedPairing_ReceivesNothing()
    {
        var (_, bus, got) = AttachFor("p1");
        bus.Publish("session", "session_started: s1", null);
        bus.Publish("foreground_app", "foreground_app: x", null);
        Assert.Empty(got);
    }

    [Fact]
    public void Destruction_CrossPairing_OriginScopedEvent_NeverLeaks()
    {
        var store = new EventSubscriptionStore();
        var bus = new AgentEventBus(store, _ => true);
        var gotA = new List<AgentEvent>();
        var gotB = new List<AgentEvent>();
        bus.Attach("pairing-a", gotA.Add);
        bus.Attach("pairing-b", gotB.Add);
        store.Subscribe("pairing-a", AgentEventKinds.All);
        store.Subscribe("pairing-b", AgentEventKinds.All);
        // A's session event, both fully subscribed: only A receives.
        bus.Publish("session", "session_started: sA", "pairing-a");
        bus.Publish("approval", "approval_required: gated:shell for pairing-a", "pairing-a");
        WaitFor(() => gotA.Count == 2);
        Assert.Equal(2, gotA.Count);
        Assert.Empty(gotB);
        // A host fact belonging to no pairing reaches both.
        bus.Publish("app_crash", "app_crash: host fact", null);
        WaitFor(() => gotA.Count == 3 && gotB.Count == 1);
        Assert.Equal(3, gotA.Count);
        Assert.Single(gotB);
    }

    [Fact]
    public void Bus_UnknownKind_IsDropped()
    {
        var (store, bus, got) = AttachFor("p1");
        store.Subscribe("p1", AgentEventKinds.All);
        bus.Publish("invented_kind", "nope", null);
        Assert.Empty(got);
    }

    // ---------- destruction: scope ----------

    [Fact]
    public void Destruction_SubscribeTool_IsObserveScoped_ScopeLessPairingDeniedByPolicy()
    {
        var store = new EventSubscriptionStore();
        var module = new EventsSubscribeModule(store);
        Assert.Equal(Scopes.Observe, module.Descriptor.RequiredScope);
        var noObserve = TestUtil.BarePairing(new HashSet<string> { Scopes.Drive }, "p-no-observe");
        var decision = new PolicyEngine().Evaluate(noObserve, module.Descriptor,
            JsonDocument.Parse("{}").RootElement, TestUtil.Session(), TestUtil.State(), new HashSet<string>());
        Assert.False(decision.Allowed);
        Assert.Contains("scope", decision.DenyReason);
    }

    // ---------- choke-point integration ----------

    private sealed class Rig
    {
        public required McpHandler Handler;
        public required EventSubscriptionStore Store;
        public required AgentEventBus Bus;
        public required string TokenA;
        public required string TokenB;
        public required string PairingAId;
        public required string PairingBId;
        public required string AuditDir;
        public required CoreState State;

        public async Task<string> Call(string token, string tool, string args = "{}")
        {
            var body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"" + tool + "\",\"arguments\":" + args + "}}";
            var resp = await Handler.HandleAsync(body, $"Bearer {token}", new HashSet<string>(), default);
            return resp.Json!;
        }
    }

    private static Rig BuildRig()
    {
        var (pairings, pairingA, tokenA) = TestUtil.MakePairing(Scopes.Preset("full_control"));
        var codeB = pairings.CreatePairingCode("agent-b", TimeSpan.FromMinutes(5), Scopes.Preset("look_only"));
        var exchangeB = pairings.ExchangeCode(codeB, "agent-b")!;
        var pairingB = pairings.List().Single(p => p.Id == exchangeB.PairingId);
        var store = new EventSubscriptionStore();
        var bus = new AgentEventBus(store, _ => true);
        var registry = new ToolRegistry();
        var state = new CoreState();
        var sessions = new SessionManager();
        registry.Register(new SessionStartModule(sessions, state));
        registry.Register(new SessionStopModule(sessions, state));
        registry.Register(new EventsSubscribeModule(store));
        registry.Register(new EventsUnsubscribeModule(store));
        var auditDir = TestUtil.TempDir();
        var handler = new McpHandler(pairings, new PolicyEngine(), registry,
            TestUtil.AuditLog(auditDir), state, sessions, auditDir)
        { Events = bus };
        state.UpdateSession(s => s with { SessionExists = true, AgentConnected = true, DesktopUnlocked = true });
        return new Rig
        {
            Handler = handler, Store = store, Bus = bus, TokenA = tokenA, TokenB = exchangeB.BearerToken,
            PairingAId = pairingA.Id, PairingBId = pairingB.Id, AuditDir = auditDir, State = state
        };
    }

    [Fact]
    public async Task ChokePoint_SessionLifecycle_EventsFlowToOwnSubscriberOnly()
    {
        var rig = BuildRig();
        var gotA = new List<AgentEvent>();
        var gotB = new List<AgentEvent>();
        rig.Bus.Attach(rig.PairingAId, gotA.Add);
        rig.Bus.Attach(rig.PairingBId, gotB.Add);
        await rig.Call(rig.TokenA, "events_subscribe", """{"kinds":["session"]}""");
        await rig.Call(rig.TokenB, "events_subscribe", """{"kinds":["session"]}""");
        await rig.Call(rig.TokenA, "session_start");
        await rig.Call(rig.TokenA, "session_stop");
        WaitFor(() => gotA.Count == 2);
        Assert.Equal(2, gotA.Count);
        Assert.All(gotA, e => Assert.Equal("session", e.Kind));
        Assert.Empty(gotB); // B subscribed to the same kind and still gets none of A's events
    }

    [Fact]
    public async Task Destruction_SubscriptionIsNotAuditEvasion_SubscribeAndToolCallsAudited()
    {
        var rig = BuildRig();
        await rig.Call(rig.TokenA, "events_subscribe", """{"kinds":["session","approval"]}""");
        await rig.Call(rig.TokenA, "session_start");
        await rig.Call(rig.TokenA, "session_stop");
        var auditText = string.Join("\n", Directory.GetFiles(rig.AuditDir).Select(File.ReadAllText));
        Assert.Contains("events_subscribe", auditText);
        Assert.Contains("session_start", auditText);
        Assert.Contains(rig.PairingAId, auditText); // audited under its own identity (D9)
    }

    [Fact]
    public async Task Subscribe_ThroughChokePoint_UnknownKindRefused_NothingStored()
    {
        var rig = BuildRig();
        var resp = await rig.Call(rig.TokenA, "events_subscribe", """{"kinds":["session","wiretap"]}""");
        Assert.Contains("unknown_event_kind", resp);
        Assert.Empty(rig.Store.FilterFor(rig.PairingAId));
    }

    [Fact]
    public async Task Stream_SseHandler_DeliversSubscribedKind_AndStopKillsStream()
    {
        var rig = BuildRig();
        await rig.Call(rig.TokenA, "events_subscribe", """{"kinds":["session"]}""");
        var written = new List<string>();
        var writeGate = new object();
        using var cts = new CancellationTokenSource();
        var streamTask = rig.Handler.HandleEventStreamAsync($"Bearer {rig.TokenA}",
            (chunk, ct) => { lock (writeGate) written.Add(chunk); return Task.CompletedTask; }, cts.Token);
        await Task.Delay(150);
        rig.Bus.Publish("session", "session_started: sx", rig.PairingAId);
        rig.Bus.Publish("approval", "approval_required: not subscribed", rig.PairingAId);
        await Task.Delay(150);
        lock (writeGate)
        {
            var text = string.Join("", written);
            Assert.Contains("session_started: sx", text);
            Assert.DoesNotContain("not subscribed", text);
        }
        // STOP comes into force: the stream must end, not idle.
        rig.State.SetUserStop(true);
        var finished = await Task.WhenAny(streamTask, Task.Delay(7000));
        Assert.Same(streamTask, finished);
        Assert.True(streamTask.Result);
        cts.Cancel();
    }

    [Fact]
    public async Task Stream_Unauthenticated_Refused()
    {
        var rig = BuildRig();
        var ok = await rig.Handler.HandleEventStreamAsync("Bearer not-a-token",
            (chunk, ct) => Task.CompletedTask, default);
        Assert.False(ok);
    }
}
