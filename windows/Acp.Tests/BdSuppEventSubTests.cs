using System.Diagnostics;
using System.Text.Json;
using Acp.Core;
using Acp.Core.Modules;
using Acp.Shared.Security;
using Acp.Shared.Sessions;
using Acp.Shared.Tools;

namespace Acp.Tests;

/// <summary>BD-SUPP-EVENTSUB (packet 10acfc28) — WINDOWS half.
/// Permanent regression tests for the supplementary breakdown of the
/// U2 event-subscription surface. (The Android half is dispositioned
/// in log-laneW5-andfix4.md; the two halves share the registry
/// strings and the same fail-closed delivery law.) F1 fail-closed,
/// F2 per-kind scope map + device provenance, F3 backpressure, F4
/// revocation detach, F5 tombstone race, F6 expiry + ListAll, F7
/// sequence + replay, F8 no-copy check (behavioural), F9 descriptor
/// built from the registry, F10 scope-loss, F11 input caps, F12 the
/// wiring legs the packet could not see.</summary>
public class BdSuppEventSubTests
{
    private static void WaitFor(Func<bool> condition, int timeoutMs = 5000) =>
        U2EventSubscriptionTests.WaitFor(condition, timeoutMs);

    private static (EventSubscriptionStore Store, AgentEventBus Bus) WiredBus(
        Func<string, string, bool>? scope = null, string? deviceId = null)
    {
        var store = new EventSubscriptionStore();
        return (store, new AgentEventBus(store, scope ?? ((_, _) => true), deviceId));
    }

    // ---- F1: fail-closed ------------------------------------------

    [Fact]
    public void NoScopeSource_BusDeliversNothing()
    {
        var store = new EventSubscriptionStore();
        var bus = new AgentEventBus(store); // the pre-fix production posture
        store.Subscribe("p1", new[] { AgentEventKinds.Session });
        var got = new List<AgentEvent>();
        bus.Attach("p1", got.Add);
        bus.Publish(AgentEventKinds.Session, "session_started: s1", "p1");
        Thread.Sleep(300);
        Assert.Empty(got);
        // And the static rule itself: null delegate = deny, never allow.
        var evt = new AgentEvent(DateTimeOffset.UtcNow, AgentEventKinds.Session, "x", "p1");
        Assert.False(AgentEventBus.ShouldDeliver(store, "p1", evt, (Func<string, bool>?)null));
        Assert.False(AgentEventBus.ShouldDeliver(store, "p1", evt, (Func<string, string, bool>?)null));
    }

    [Fact]
    public void ObserveRevokedAfterSubscribe_NextEventNotDelivered()
    {
        var store = new EventSubscriptionStore();
        var holds = true;
        var bus = new AgentEventBus(store, _ => holds);
        store.Subscribe("p1", new[] { AgentEventKinds.ForegroundApp });
        var got = new List<AgentEvent>();
        bus.Attach("p1", got.Add);
        bus.Publish(AgentEventKinds.ForegroundApp, "fg: a", null);
        WaitFor(() => got.Count == 1);
        holds = false; // Observe removed after subscribing (F10's scenario too)
        bus.Publish(AgentEventKinds.ForegroundApp, "fg: b", null);
        Thread.Sleep(300);
        Assert.Single(got);
    }

    // ---- F2: scope map + provenance --------------------------------

    [Fact]
    public void KindScopeMap_EveryKindRequiresObserve_NoKindMapsToNothing()
    {
        foreach (var kind in AgentEventKinds.All)
            Assert.Equal(Scopes.Observe, AgentEventKinds.RequiredScope(kind));
        Assert.Null(AgentEventKinds.RequiredScope("invented_kind"));
        // The map's premise, pinned: the product has no finer event
        // scope for a kind to map to.
        Assert.DoesNotContain("notification", Scopes.All);
    }

    [Fact]
    public void Publish_StampsDeviceIdAndSequence()
    {
        var (store, bus) = WiredBus(deviceId: "device-abc");
        store.Subscribe("p1", new[] { AgentEventKinds.Session });
        var got = new List<AgentEvent>();
        bus.Attach("p1", got.Add);
        bus.Publish(AgentEventKinds.Session, "s1", "p1");
        bus.Publish(AgentEventKinds.Session, "s2", "p1");
        WaitFor(() => got.Count == 2);
        Assert.All(got, e => Assert.Equal("device-abc", e.DeviceId));
        Assert.True(got[1].Sequence > got[0].Sequence && got[0].Sequence >= 1);
    }

    // ---- F3: backpressure -------------------------------------------

    [Fact]
    public void StalledHandler_NeverBlocksPublish_OrOtherStreams()
    {
        var (store, bus) = WiredBus();
        store.Subscribe("slow", new[] { AgentEventKinds.Session });
        store.Subscribe("fast", new[] { AgentEventKinds.Session });
        using var gate = new ManualResetEventSlim(false);
        bus.Attach("slow", _ => gate.Wait()); // a handler that never returns
        var fastGot = new List<AgentEvent>();
        bus.Attach("fast", fastGot.Add);

        var sw = Stopwatch.StartNew();
        for (var i = 0; i < 50; i++) bus.Publish(AgentEventKinds.Session, $"s{i}", null);
        sw.Stop();
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(5), $"Publish blocked for {sw.Elapsed}");
        WaitFor(() => fastGot.Count == 50); // the healthy stream got everything
        gate.Set(); // release the stalled pump for teardown
    }

    // ---- F4/F5: revocation ------------------------------------------

    [Fact]
    public void RevokePairing_ClearsStore_DetachesStreams_Tombstones()
    {
        var (store, bus) = WiredBus();
        store.Subscribe("p1", new[] { AgentEventKinds.Session });
        var got = new List<AgentEvent>();
        bus.Attach("p1", got.Add);
        bus.RevokePairing("p1");
        Assert.Empty(store.FilterFor("p1"));
        Assert.True(store.IsTombstoned("p1"));
        bus.Publish(AgentEventKinds.Session, "s1", "p1");
        Thread.Sleep(300);
        Assert.Empty(got); // detached: nothing arrives even filtered-in
        // F5: a subscribe racing in after revocation cannot resurrect.
        var (ok, error) = store.Subscribe("p1", new[] { AgentEventKinds.Session });
        Assert.False(ok);
        Assert.Contains("pairing_revoked", error);
        // Only a fresh exchange (AllowPairing) clears the tombstone.
        store.AllowPairing("p1");
        Assert.True(store.Subscribe("p1", new[] { AgentEventKinds.Session }).Ok);
    }

    [Fact]
    public void PairingAdmin_RevokeWithoutLiveSession_StillClearsSubscriptions()
    {
        // F4's found gap: the admin-tool revoke path only cleared
        // subscriptions via the session-ended callback, which never
        // fires for an idle pairing. The pairingRevoked callback now
        // fires on every successful revoke.
        var (svc, pairing, _) = TestUtil.MakePairing(new HashSet<string> { Scopes.Admin });
        var store = new EventSubscriptionStore();
        var bus = new AgentEventBus(store, (_, _) => true, null);
        store.Subscribe(pairing.Id, new[] { AgentEventKinds.Session });
        var module = new PairingAdminModule(svc, sessions: null, sessionEnded: null,
            pairingRevoked: id => bus.RevokePairing(id));
        var ctx = new ToolExecutionContext(pairing, TestUtil.Session(), TestUtil.State(), new HashSet<string>(), "unused");
        var result = module.ExecuteAsync(
            JsonDocument.Parse(JsonSerializer.Serialize(new { action = "revoke", pairing_id = pairing.Id })).RootElement,
            ctx, default).Result;
        Assert.True(result.Ok);
        Assert.Empty(store.FilterFor(pairing.Id));
        Assert.True(store.IsTombstoned(pairing.Id));
    }

    // ---- F6: expiry + enumeration ------------------------------------

    [Fact]
    public void Subscriptions_Expire_AndListAllShowsLiveWatches()
    {
        var now = DateTimeOffset.UtcNow;
        var store = new EventSubscriptionStore(() => now, TimeSpan.FromMinutes(10));
        store.Subscribe("p1", new[] { AgentEventKinds.Session, AgentEventKinds.Approval });
        store.Subscribe("p2", new[] { AgentEventKinds.AppCrash });
        var all = store.ListAll();
        Assert.Equal(2, all.Count);
        Assert.Contains(all, w => w.PairingId == "p1" && w.Kinds.Count == 2);
        now = now.AddMinutes(11); // past the TTL with no renewal
        Assert.Empty(store.ListAll());
        Assert.Empty(store.FilterFor("p1"));
        Assert.False(store.IsSubscribed("p2", AgentEventKinds.AppCrash));
        // Renewal: subscribing again extends the watch.
        store.Subscribe("p1", new[] { AgentEventKinds.Session });
        now = now.AddMinutes(9);
        Assert.True(store.IsSubscribed("p1", AgentEventKinds.Session));
    }

    // ---- F7: sequence + replay ----------------------------------------

    [Fact]
    public void ReplaySince_ReturnsMissedEvents_FilteredForThisPairing()
    {
        var (store, bus) = WiredBus();
        store.Subscribe("p1", AgentEventKinds.All);
        store.Subscribe("p2", AgentEventKinds.All);
        bus.Publish(AgentEventKinds.Session, "for-p1", "p1");
        bus.Publish(AgentEventKinds.AppCrash, "host-fact", null);
        bus.Publish(AgentEventKinds.Session, "for-p2", "p2");
        var replay = bus.ReplaySince("p1", 0);
        Assert.Equal(2, replay.Count); // its own + the host fact, never p2's
        Assert.All(replay, e => Assert.True(e.Sequence >= 1));
        Assert.Empty(bus.ReplaySince("p1", bus.CurrentSequence));
    }

    [Fact]
    public void DeliveryOrder_MatchesPublishOrder_PerStream()
    {
        var (store, bus) = WiredBus();
        store.Subscribe("p1", new[] { AgentEventKinds.Session });
        var got = new List<AgentEvent>();
        bus.Attach("p1", got.Add);
        for (var i = 0; i < 20; i++) bus.Publish(AgentEventKinds.Session, $"s{i}", "p1");
        WaitFor(() => got.Count == 20);
        Assert.Equal(Enumerable.Range(0, 20).Select(i => $"s{i}"), got.Select(e => e.Detail));
        Assert.Equal(got.Select(e => e.Sequence).OrderBy(s => s), got.Select(e => e.Sequence));
    }

    // ---- F9: descriptor cannot drift ----------------------------------

    [Fact]
    public void SubscribeDescriptor_ListsEveryRegistryKind_InTextAndSchema()
    {
        var module = new EventsSubscribeModule(new EventSubscriptionStore());
        foreach (var kind in AgentEventKinds.All)
        {
            Assert.Contains(kind, module.Descriptor.Description);
            Assert.Contains($"\"{kind}\"", module.Descriptor.InputSchemaJson);
        }
    }

    // ---- F11: input handling -------------------------------------------

    [Fact]
    public void UnknownKindEcho_IsTruncatedAndSanitised_ArrayCapped()
    {
        var store = new EventSubscriptionStore();
        var hostile = new string('x', 500) + "\nINJECTED";
        var (ok, error) = store.Subscribe("p1", new[] { hostile });
        Assert.False(ok);
        Assert.DoesNotContain("\n", error);
        Assert.True(error!.Length < 300, $"error too long: {error.Length}");
        var many = Enumerable.Repeat(AgentEventKinds.Session, AgentEventKinds.All.Count * 2 + 1).ToArray();
        Assert.False(store.Subscribe("p1", many).Ok);
        Assert.Contains("too_many_kinds", store.Subscribe("p1", many).Error);
    }

    // ---- F12: the wiring the packet could not see -----------------------

    [Fact]
    public async Task CoreRuntime_BusIsWiredFailClosed_WithLiveScopeLookup()
    {
        // Production composition, exercised end to end: a pairing
        // that holds Observe receives its events through the
        // runtime's own bus; after revocation through the runtime,
        // its subscription is gone AND tombstoned.
        var rt = new CoreRuntime(new CoreOptions
        {
            DataDir = TestUtil.TempDir(), Port = HeldInputTests.FreePort(),
            Protector = new DevOnlyPassThroughProtector(),
            Probe = new FakeProbe(), FactChecks = new FakeFactChecks(), Runner = new FakeRunner(),
            SupervisorPeriod = TimeSpan.FromHours(1)
        });
        var code = rt.Pairings.CreatePairingCode("w7-agent", TimeSpan.FromMinutes(5), Scopes.Preset("look_only"));
        var exchange = rt.Pairings.ExchangeCode(code, "w7-agent");
        Assert.NotNull(exchange);
        var live = rt.Pairings.List().Single(p => p.Id == exchange!.PairingId);
        Assert.True(rt.EventSubscriptions.Subscribe(live.Id, new[] { AgentEventKinds.Session }).Ok);
        var got = new List<AgentEvent>();
        rt.AgentEvents.Attach(live.Id, got.Add);
        rt.AgentEvents.Publish(AgentEventKinds.Session, "session_started: sx", live.Id);
        WaitFor(() => got.Count == 1);
        Assert.Equal(rt.Identity.DeviceId, got[0].DeviceId);

        Assert.True(rt.TryRevokePairingFromLaptop(JsonSerializer.Serialize(new { id = live.Id })));
        Assert.Empty(rt.EventSubscriptions.FilterFor(live.Id));
        Assert.True(rt.EventSubscriptions.IsTombstoned(live.Id));
        rt.AgentEvents.Publish(AgentEventKinds.Session, "session_started: sy", live.Id);
        Thread.Sleep(300);
        Assert.Single(got); // nothing after revocation
        try { await rt.StopAsync(default); } catch { }
        try { await rt.DisposeAsync(); } catch { }
    }
}
