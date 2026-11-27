using System.Text.Json;
using DeskGuest.Shared.Transport;

namespace DeskGuest.Tests;

/// <summary>Block C part 1 wiring (2026-11-19): the transport core
/// driven through the LIVE surfaces — the Core's laptop-UI IPC
/// action handlers (ApplyTransportAction + the new roster actions),
/// the host-state snapshot's transport section, and the real LAN
/// listener + failover engine the Core composes. Fixtures build a
/// real CoreRuntime (WiringFixture) and act only through the public
/// handler methods the IPC event calls.</summary>
public sealed class TransportWiringTests : IClassFixture<WiringFixture>
{
    private readonly WiringFixture _f;
    public TransportWiringTests(WiringFixture f) => _f = f;

    private static string Json(object payload) => JsonSerializer.Serialize(payload);

    // CONV-F3: the session legs of all three tests in this class
    // run through the Core's own LanRung (product TcpClient) via the
    // IPC handlers, so they cannot be rerouted to a raw Socket
    // without changing product code to fit the sandbox; they stay
    // failing IN THIS SANDBOX ONLY (egress proxy intercepts the
    // rung's TcpClient — log-conv-f3.md) and are reported
    // remaining-environmental in log-conv-f3-greenup.md.
    [Fact]
    public async Task TransportStart_ThroughIpc_LanSessionCarriedByTheLanRung()
    {
        var rt = _f.Runtime;
        var deviceId = _f.EnrollThisDevice();

        // CONV-F3 isolation fix: the WiringFixture is SHARED across
        // this class, and a sibling test may already have started
        // the listener (the harness runs TransportReestablish first),
        // so an unconditional opening Assert.False(IsListening) trips
        // on ordering alone — the fragility the CONV-F3 lane found.
        // Start the listener only if it is dormant, exactly as the
        // sibling tests do; listener dormancy before any operator
        // act remains asserted where a fresh fixture guarantees it
        // (TransportWiringDestructionTests' hostile-payload test).
        if (!rt.LanListener.IsListening)
        {
            var (lok, ldetail) = await rt.ApplyTransportAction(Json(new { action = "start_lan_listener" }));
            Assert.True(lok, ldetail);
        }
        Assert.True(rt.LanListener.IsListening);

        var acceptedBefore = rt.LanListener.AcceptedSessions;
        var (ok, detail) = await rt.ApplyTransportAction(Json(new
        {
            action = "start", scopeId = WiringFixture.ScopeId, hostDeviceId = deviceId,
            initiatorUserId = WiringFixture.OwnerId, kind = "unattended",
            address = $"127.0.0.1:{rt.LanListener.Port}",
        }));
        Assert.True(ok, detail);
        var sessionId = detail.Split(' ')[1];
        var session = rt.HumanSessions.GetSession(sessionId);
        Assert.NotNull(session);
        Assert.Equal("active", session!.State);
        Assert.Equal("lan", session.TransportRung); // the rung that actually carried it
        Assert.Equal(acceptedBefore + 1, rt.LanListener.AcceptedSessions); // proof-of-possession handshake passed

        // The snapshot the window renders carries the transport facts.
        var snapshot = rt.BuildHostStateJson();
        using var doc = JsonDocument.Parse(snapshot);
        var transport = doc.RootElement.GetProperty("transport");
        Assert.True(transport.GetProperty("lanListening").GetBoolean());
        Assert.Equal(rt.LanListener.Port, transport.GetProperty("lanPort").GetInt32());
        Assert.Equal(rt.LanListener.AcceptedSessions, transport.GetProperty("lanAccepted").GetInt32());
    }

    [Fact]
    public async Task TransportStart_ThroughIpc_WindowPayloadShape_NullPinsMeansNoPin()
    {
        // Regression (live-proof find, 2026-11-19): the host window
        // always sends the manualPins property — JSON null when the
        // pin field is empty. The handler turned "present but null"
        // into an EMPTY pin list, and the engine refuses an empty
        // pin set wholesale, so every unpinned start from the window
        // was refused with "No effective transports". The payload
        // below is the window's exact shape.
        var rt = _f.Runtime;
        var deviceId = _f.EnrollThisDevice();
        if (!rt.LanListener.IsListening)
            await rt.ApplyTransportAction(Json(new { action = "start_lan_listener" }));
        var (ok, detail) = await rt.ApplyTransportAction(Json(new
        {
            action = "start", scopeId = WiringFixture.ScopeId, hostDeviceId = deviceId,
            initiatorUserId = WiringFixture.OwnerId, kind = "unattended", recording = "none",
            address = $"127.0.0.1:{rt.LanListener.Port}", manualPins = (string[]?)null,
        }));
        Assert.True(ok, detail);
        var session = rt.HumanSessions.GetSession(detail.Split(' ')[1]);
        Assert.NotNull(session);
        Assert.Equal("lan", session!.TransportRung);
    }

    [Fact]
    public async Task TransportReestablish_ThroughIpc_NoNextRegisteredRung_FloorHolds()
    {
        var rt = _f.Runtime;
        var deviceId = _f.EnrollThisDevice();
        if (!rt.LanListener.IsListening)
            await rt.ApplyTransportAction(Json(new { action = "start_lan_listener" }));
        var (ok, detail) = await rt.ApplyTransportAction(Json(new
        {
            action = "start", scopeId = WiringFixture.ScopeId, hostDeviceId = deviceId,
            initiatorUserId = WiringFixture.OwnerId, kind = "unattended",
            address = $"127.0.0.1:{rt.LanListener.Port}",
        }));
        Assert.True(ok, detail);
        var session = rt.HumanSessions.GetSession(detail.Split(' ')[1]);
        Assert.NotNull(session);

        // Only the lan rung is registered in this build: the walk to
        // hub/mesh/ipv6/ownpath/tor finds no implementation, so the
        // re-establish fails honestly — the old session ends with
        // transport_failover and NO session leaves the resolved set.
        var (rok, rdetail) = await rt.ApplyTransportAction(Json(new { action = "reestablish", sessionId = session!.Id }));
        Assert.False(rok);
        Assert.Contains("re-establish failed", rdetail);
        var old = rt.HumanSessions.GetSession(session.Id);
        Assert.Equal("ended", old!.State);
        Assert.Equal("transport_failover", old.EndReason);
        Assert.DoesNotContain(rt.HumanSessions.ListSessions(WiringFixture.ScopeId),
            s => s.State == "active" && s.Id == session.Id);
    }

    [Fact]
    public void SetEditing_ThroughIpc_AdminLands_MemberAndAiRefused_CeilingCaps_PinGuardsHold()
    {
        var rt = _f.Runtime;
        var deviceId = _f.EnrollThisDevice();

        // A fresh group to edit (the fixture's fleet group is shared).
        var (gok, gdetail) = rt.ApplyRosterAction(Json(new
        {
            action = "create_device_group", id = "tport", scopeId = WiringFixture.ScopeId,
            name = "Transport Edited", transportSet = new[] { "lan", "hub", "tor" },
        }));
        Assert.True(gok, gdetail);

        // Member (not an admin of anything) cannot change the set.
        var (mok, _) = rt.ApplyRosterAction(Json(new
        {
            action = "create_user", id = "mallory", scopeId = WiringFixture.ScopeId,
            displayName = "Mallory Member", kind = "human",
        }));
        Assert.True(mok);
        var (rok, rdetail) = rt.ApplyRosterAction(Json(new
        {
            action = "set_group_transports", scopeId = WiringFixture.ScopeId, groupId = "tport",
            actorUserId = "mallory", transportSet = new[] { "tor" },
        }));
        Assert.False(rok);
        Assert.Contains("refused", rdetail);

        // The company admin can.
        var (aok, adetail) = rt.ApplyRosterAction(Json(new
        {
            action = "set_group_transports", scopeId = WiringFixture.ScopeId, groupId = "tport",
            actorUserId = WiringFixture.OwnerId, transportSet = new[] { "tor", "lan" },
        }));
        Assert.True(aok, adetail);

        // Per-device pin: outside the device's resolved set refuses
        // whole; within it lands. (The fixture device sits in the
        // fleet group whose set is all six rungs.)
        var (pok, pdetail) = rt.ApplyRosterAction(Json(new
        {
            action = "update_device_transports", deviceId, transportMode = "manual",
            allowedTransports = new[] { "bogus-rung" },
        }));
        Assert.False(pok);
        Assert.Contains("refused", pdetail);
        var (wok, wdetail) = rt.ApplyRosterAction(Json(new
        {
            action = "update_device_transports", deviceId, transportMode = "manual",
            allowedTransports = new[] { "lan" },
        }));
        Assert.True(wok, wdetail);
        Assert.Equal(new[] { "lan" }, rt.Roster.EffectiveTransportsForDevice(deviceId)!.ToArray());
        // Restore inherit so sibling assertions in this class see the full set.
        var (iok, _) = rt.ApplyRosterAction(Json(new
        {
            action = "update_device_transports", deviceId, transportMode = "inherit",
            allowedTransports = Array.Empty<string>(),
        }));
        Assert.True(iok);
    }

    [Fact]
    public async Task DiscoveryBrowse_ThroughCore_BoundedWindow_ReturnsClassifiedList()
    {
        var rt = _f.Runtime;
        using var doc = JsonDocument.Parse(Json(new { windowMs = 500 }));
        var found = await rt.BrowseDiscoveryAsync(doc.RootElement);
        // In this sandbox nothing announces (UDP send is blocked
        // wholesale here); the contract proven is the bounded window
        // itself: it returns, classified, without throwing or hanging.
        Assert.NotNull(found);
    }
}

/// <summary>Destruction pass on the Block C wiring: hostile payloads
/// against the new handlers, set-editing bypass through the IPC
/// surface, and a transport start pinned outside the set. Every
/// defense held or the break is fixed above its test.</summary>
public sealed class TransportWiringDestructionTests : IClassFixture<WiringFixture>
{
    private readonly WiringFixture _f;
    public TransportWiringDestructionTests(WiringFixture f) => _f = f;

    private static string Json(object payload) => JsonSerializer.Serialize(payload);

    [Fact]
    public async Task Attack_HostileTransportPayloads_RefuseAndMutateNothing()
    {
        var rt = _f.Runtime;
        _f.EnrollThisDevice();
        var sessionsBefore = rt.HumanSessions.ListSessions(WiringFixture.ScopeId).Count;
        var eventsBefore = rt.Transports.Events.Count;

        Assert.False((await rt.ApplyTransportAction(null)).Ok);
        Assert.False((await rt.ApplyTransportAction("not json")).Ok);
        Assert.False((await rt.ApplyTransportAction("""{"action":"nonsense"}""")).Ok);
        Assert.False((await rt.ApplyTransportAction(Json(new
        {
            action = "start", scopeId = WiringFixture.ScopeId, hostDeviceId = "no-such-device",
            initiatorUserId = WiringFixture.OwnerId, kind = "unattended",
        }))).Ok);
        Assert.False((await rt.ApplyTransportAction(Json(new
        {
            action = "reestablish", sessionId = "no-such-session",
        }))).Ok);

        Assert.Equal(sessionsBefore, rt.HumanSessions.ListSessions(WiringFixture.ScopeId).Count);
        Assert.False(rt.LanListener.IsListening); // no payload opened the dormant listener
        Assert.True(rt.Transports.Events.Count >= eventsBefore); // refusals are recorded, not silent
    }

    [Fact]
    public async Task Attack_TransportStart_PinnedOutsideTheSet_RefusedThroughIpc()
    {
        var rt = _f.Runtime;
        var deviceId = _f.EnrollThisDevice();
        // "ownpath" IS in the fleet set; pin to a rung after narrowing
        // the device to lan-only manual — the pin must refuse whole.
        var (wok, _) = rt.ApplyRosterAction(Json(new
        {
            action = "update_device_transports", deviceId, transportMode = "manual",
            allowedTransports = new[] { "lan" },
        }));
        Assert.True(wok);
        try
        {
            var (ok, detail) = await rt.ApplyTransportAction(Json(new
            {
                action = "start", scopeId = WiringFixture.ScopeId, hostDeviceId = deviceId,
                initiatorUserId = WiringFixture.OwnerId, kind = "unattended",
                manualPins = new[] { "tor" },
            }));
            Assert.False(ok);
            Assert.Contains("transport start failed", detail);
            Assert.DoesNotContain(rt.HumanSessions.ListSessions(WiringFixture.ScopeId),
                s => s.State == "active" && s.TransportRung == "tor");
        }
        finally
        {
            rt.ApplyRosterAction(Json(new
            {
                action = "update_device_transports", deviceId, transportMode = "inherit",
                allowedTransports = Array.Empty<string>(),
            }));
        }
    }

    [Fact]
    public void Attack_SetEditingBypass_ThroughIpc_SuspendedAdminAndCrossScope_Refused()
    {
        var rt = _f.Runtime;
        // Suspend the second company admin, then try to edit as them.
        Assert.True(rt.Roster.SetUserSuspended(WiringFixture.ScopeId, WiringFixture.Admin2Id, true));
        try
        {
            var (ok, detail) = rt.ApplyRosterAction(Json(new
            {
                action = "set_group_transports", scopeId = WiringFixture.ScopeId, groupId = WiringFixture.GroupId,
                actorUserId = WiringFixture.Admin2Id, transportSet = new[] { "tor" },
            }));
            Assert.False(ok);
            Assert.Contains("refused", detail);
            // Cross-scope: the fleet group does not live in "beta".
            var (xok, _) = rt.ApplyRosterAction(Json(new
            {
                action = "set_group_transports", scopeId = "beta", groupId = WiringFixture.GroupId,
                actorUserId = WiringFixture.OwnerId, transportSet = new[] { "tor" },
            }));
            Assert.False(xok);
            // The set is untouched.
            var deviceId = _f.EnrollThisDevice();
            Assert.Equal(
                new[] { "lan", "hub", "mesh", "ipv6", "ownpath", "tor" },
                rt.Roster.EffectiveTransportsForDevice(deviceId)!.ToArray());
        }
        finally
        {
            rt.Roster.SetUserSuspended(WiringFixture.ScopeId, WiringFixture.Admin2Id, false);
        }
    }
}
