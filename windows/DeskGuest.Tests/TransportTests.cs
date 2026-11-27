using System.Net;
using System.Net.Sockets;
using System.Text;
using DeskGuest.Shared.Enrollment;
using DeskGuest.Shared.Roster;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.Sessions;
using DeskGuest.Shared.Transport;

namespace DeskGuest.Tests;

/// <summary>Block C transport core (D19/D20/D29/D31/D32): the LAN
/// rung's authenticated session protocol, connect-by-address, the
/// rung-agnostic failover engine, group transport-set editing
/// guards, and local discovery. Destruction cases live in
/// TransportDestructionTests.</summary>
public class TransportTests
{
    internal sealed class World
    {
        public required EnrollmentService Enrollments { get; init; }
        public required RosterService Roster { get; init; }
        public required SessionService Sessions { get; init; }
        public required string DeviceId { get; init; }
        public required DeviceIdentity OperatorIdentity { get; init; }
        // BD-SHARED-TRANSPORT F1 test repair: the v2 handshake is
        // mutual — the host listener now needs the host's own
        // identity to sign its challenge, and the rungs need the
        // enrollment store to verify hosts. Setup previously
        // discarded the host identity; the World now carries it
        // and every listener/rung construction below passes the
        // real stores. No assertion was weakened: the gates these
        // tests exercise are the v2 gates.
        public required DeviceIdentity HostIdentity { get; init; }
    }

    internal static World Setup(string[]? groupSet = null)
    {
        var enrollments = new EnrollmentService();
        var roster = new RosterService(enrollments);
        Assert.NotNull(roster.CreateScope("company-1", "company", "Company A"));
        Assert.NotNull(roster.CreateUser("admin", "company-1", "Admin", "human"));
        Assert.True(roster.AddCompanyAdmin("company-1", "admin"));
        Assert.NotNull(roster.CreateUser("ctrl", "company-1", "Controller", "human"));
        Assert.NotNull(roster.CreateUserGroup("ug-1", "company-1", "Techs", new[] { "ctrl" }));
        Assert.NotNull(roster.CreateDeviceGroup("dg-1", "company-1", "Fleet", groupSet ?? new[] { "lan", "hub", "tor" }));
        Assert.NotNull(roster.AddGrant("company-1", "ug-1", "dg-1", new[] { "use" }));

        var hostIdentity = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var code = enrollments.CreateEnrollmentCode("company", "dg-1", "Fleet");
        var device = enrollments.Redeem(code, new EnrollingDevice(hostIdentity.DeviceId, hostIdentity.PublicKeyBase64, "Site PC"));
        Assert.NotNull(device);

        // The operator device is enrolled too — the LAN handshake
        // proves possession of an enrolled key, nobody else's.
        var opIdentity = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var opCode = enrollments.CreateEnrollmentCode("company", "dg-1", "Fleet");
        var op = enrollments.Redeem(opCode, new EnrollingDevice(opIdentity.DeviceId, opIdentity.PublicKeyBase64, "Operator PC"));
        Assert.NotNull(op);

        return new World
        {
            Enrollments = enrollments,
            Roster = roster,
            Sessions = new SessionService(roster, enrollments),
            DeviceId = device!.DeviceId,
            OperatorIdentity = opIdentity,
            HostIdentity = hostIdentity,
        };
    }

    private static Dictionary<string, TransportTarget> NoTargets() => new();

    // ---- failover engine: order, dormancy, rung-agnosticism (D29/D32) -----------

    [Fact]
    public async Task Engine_WalksGroupSetInOrder_FirstSuccessCarriesSession_D32()
    {
        var w = Setup();
        var lan = StubRung.Failing("lan");
        var hub = StubRung.Succeeding("hub");
        var tor = StubRung.Succeeding("tor");
        var mgr = new TransportSessionManager(w.Roster, w.Sessions, new ITransportRung[] { lan, hub, tor });
        var s = await mgr.StartSessionAsync("company-1", w.DeviceId, "ctrl", "unattended", NoTargets());
        Assert.NotNull(s);
        Assert.Equal("hub", s!.TransportRung);
        Assert.Equal("active", s.State);
        Assert.Equal(1, lan.ConnectAttempts);
        Assert.Equal(1, hub.ConnectAttempts);
        Assert.Equal(0, tor.ConnectAttempts); // never reached: earlier rung carried it
    }

    [Fact]
    public async Task Engine_NonPrimaryRungsStayDormant_WhenPrimaryCarries_D29()
    {
        var w = Setup();
        var lan = StubRung.Succeeding("lan");
        var hub = StubRung.Succeeding("hub");
        var tor = StubRung.Succeeding("tor");
        var mgr = new TransportSessionManager(w.Roster, w.Sessions, new ITransportRung[] { lan, hub, tor });
        var s = await mgr.StartSessionAsync("company-1", w.DeviceId, "ctrl", "unattended", NoTargets());
        Assert.NotNull(s);
        Assert.Equal("lan", s!.TransportRung);
        Assert.True(hub.IsDormant);
        Assert.True(tor.IsDormant);
        Assert.Equal(0, hub.ConnectAttempts);
        Assert.Equal(0, tor.ConnectAttempts);
    }

    [Fact]
    public async Task Engine_ManualPin_AttemptsOnlyThePin_D29_D32()
    {
        var w = Setup();
        var lan = StubRung.Succeeding("lan");
        var hub = StubRung.Succeeding("hub");
        var tor = StubRung.Succeeding("tor");
        var mgr = new TransportSessionManager(w.Roster, w.Sessions, new ITransportRung[] { lan, hub, tor });
        var s = await mgr.StartSessionAsync("company-1", w.DeviceId, "ctrl", "unattended", NoTargets(),
            manualPins: new[] { "tor" });
        Assert.NotNull(s);
        Assert.Equal("tor", s!.TransportRung);
        Assert.Equal(0, lan.ConnectAttempts);
        Assert.Equal(0, hub.ConnectAttempts);
    }

    [Fact]
    public async Task Engine_ManualPinOutsideTheSet_RefusedWholesale_D32()
    {
        var w = Setup();
        var lan = StubRung.Succeeding("lan");
        var mgr = new TransportSessionManager(w.Roster, w.Sessions, new ITransportRung[] { lan });
        // "ownpath" is a real rung but NOT in this group's set.
        var s = await mgr.StartSessionAsync("company-1", w.DeviceId, "ctrl", "unattended", NoTargets(),
            manualPins: new[] { "ownpath" });
        Assert.Null(s);
        Assert.Equal(0, lan.ConnectAttempts);
        Assert.Contains(mgr.Events, e => e.Kind == "start_refused");
    }

    [Fact]
    public async Task Engine_Reestablish_EndsOldAndStartsNew_LinkedByEvents_D29()
    {
        var w = Setup();
        var lan = StubRung.Succeeding("lan");
        var hub = StubRung.Succeeding("hub");
        var mgr = new TransportSessionManager(w.Roster, w.Sessions, new ITransportRung[] { lan, hub, StubRung.Succeeding("tor") });
        var first = await mgr.StartSessionAsync("company-1", w.DeviceId, "ctrl", "unattended", NoTargets());
        Assert.NotNull(first);
        var next = await mgr.ReestablishAsync(first!.Id, NoTargets());
        Assert.NotNull(next);
        Assert.NotEqual(first.Id, next!.Id);
        Assert.Equal("hub", next.TransportRung);
        Assert.Equal("active", next.State);
        var old = w.Sessions.GetSession(first.Id);
        Assert.Equal("ended", old!.State);
        Assert.Equal(SessionService.EndReasonTransportFailover, old.EndReason);
        Assert.Contains(w.Sessions.ListEvents(next.Id), e => e.Kind == "transport_failover" && e.SubjectId == first.Id);
        Assert.Contains(mgr.Events, e => e.Kind == "session_reestablished" && e.FromSessionId == first.Id && e.ToSessionId == next.Id);
    }

    [Fact]
    public async Task Engine_Reestablish_NoNextRung_SessionStaysLive_FloorHolds_D32()
    {
        var w = Setup(new[] { "lan" });
        var lan = StubRung.Succeeding("lan");
        var mgr = new TransportSessionManager(w.Roster, w.Sessions, new ITransportRung[] { lan });
        var first = await mgr.StartSessionAsync("company-1", w.DeviceId, "ctrl", "unattended", NoTargets());
        Assert.NotNull(first);
        var next = await mgr.ReestablishAsync(first!.Id, NoTargets());
        Assert.Null(next); // failover never leaves the group's set
        Assert.Equal("active", w.Sessions.GetSession(first.Id)!.State);
        Assert.Contains(mgr.Events, e => e.Kind == "failover_exhausted");
    }

    [Fact]
    public async Task Engine_AllRungsFail_NoSession_AttemptsBoundedBySetSize_D29()
    {
        var w = Setup();
        var mgr = new TransportSessionManager(w.Roster, w.Sessions,
            new ITransportRung[] { StubRung.Failing("lan"), StubRung.Failing("hub"), StubRung.Failing("tor") });
        var s = await mgr.StartSessionAsync("company-1", w.DeviceId, "ctrl", "unattended", NoTargets());
        Assert.Null(s);
        Assert.Empty(w.Sessions.ListSessions("company-1").Where(x => x.State != "ended"));
        Assert.Contains(mgr.Events, e => e.Kind == "start_failed");
    }

    // ---- LAN rung: real socket, real handshake ---------------------------------

    // CONV-F3: this test's client leg lives inside product code
    // (LanRung's own TcpClient, driven through TransportSessionManager),
    // so it cannot be rerouted to a raw Socket without changing product
    // code to fit the sandbox. It stays failing IN THIS SANDBOX ONLY
    // (egress proxy intercepts the rung's TcpClient; the handshake
    // itself is proven sound over a raw Socket — log-conv-f3.md) and
    // is reported remaining-environmental in log-conv-f3-greenup.md.
    [Fact]
    public async Task Lan_LiveSocketSession_AuthenticatedByDeviceKey()
    {
        var w = Setup();
        using var listener = new LanHostListener(w.Enrollments, w.HostIdentity);
        listener.Start(IPAddress.Loopback, 0);
        Assert.True(listener.IsListening);
        var lan = new LanRung(w.Enrollments);
        var mgr = new TransportSessionManager(w.Roster, w.Sessions, new ITransportRung[] { lan }, w.OperatorIdentity);
        var targets = new Dictionary<string, TransportTarget>
        { ["lan"] = new(w.DeviceId, $"127.0.0.1:{listener.Port}") };
        var s = await mgr.StartSessionAsync("company-1", w.DeviceId, "ctrl", "unattended", targets);
        Assert.NotNull(s);
        Assert.Equal("lan", s!.TransportRung);
        Assert.Equal("active", s.State);
        // The channel actually speaks the session protocol.
        Assert.Equal(1, listener.AcceptedSessions);
        mgr.ForgetLink(s.Id);
    }

    [Fact]
    public async Task Lan_ConnectByAddress_SameRungSameProtocol_D19()
    {
        var w = Setup();
        using var listener = new LanHostListener(w.Enrollments, w.HostIdentity);
        listener.Start(IPAddress.Loopback, 0);
        // CONV-F3 test transport (RawSocketTestLeg / log-conv-f3.md):
        // the rung's own client leg is a TcpClient this sandbox's
        // egress proxy intercepts, so the connect-by-address leg is
        // driven at the level the CONV-F3 probe proved — the rung's
        // own address parsing (LanRung.ParseAddress, the exact parse
        // ConnectByAddressAsync performs) plus the SAME LanProtocol
        // proof-of-possession handshake the rung runs, over a raw
        // Socket. D19's claim — a hand-entered address rides the same
        // rung semantics and the same authenticated protocol — is
        // what is asserted; only the client transport differs.
        var address = $"127.0.0.1:{listener.Port}";
        var (host, port) = LanRung.ParseAddress(address);
        Assert.Equal("127.0.0.1", host);
        Assert.Equal(listener.Port, port);
        using var stream = await RawSocketTestLeg.ConnectLoopbackAsync(port);
        Assert.True(await LanProtocol.ClientHandshakeAsync(stream, w.OperatorIdentity, w.Enrollments, w.DeviceId, default));
    }

    [Fact]
    public async Task Lan_SessionChannel_PingPong()
    {
        var w = Setup();
        using var listener = new LanHostListener(w.Enrollments, w.HostIdentity);
        listener.Start(IPAddress.Loopback, 0);
        // CONV-F3 test transport (RawSocketTestLeg / log-conv-f3.md):
        // same adaptation as Lan_ConnectByAddress above — the real
        // LanProtocol client handshake (the exact half
        // LanRung.ConnectSessionAsync runs) over a raw Socket, then
        // the session channel itself: PING → PONG, verbatim.
        using var stream = await RawSocketTestLeg.ConnectLoopbackAsync(listener.Port);
        // BD-SHARED-TRANSPORT F1: session traffic rides the AEAD
        // channel the handshake derives — PING/PONG now go over
        // the detailed result's Channel, not the raw socket.
        var hs = await LanProtocol.ClientHandshakeDetailedAsync(stream, w.OperatorIdentity, w.Enrollments, w.DeviceId, default);
        Assert.Equal(LanProtocol.ClientHandshakeOutcome.Connected, hs.Outcome);
        using var channel = hs.Channel!;
        await LanProtocol.WriteLineAsync(channel, "PING", default);
        var reply = await LanProtocol.ReadLineAsync(channel, default);
        Assert.Equal("PONG", reply);
    }

    // ---- group transport-set editing guards (D31/D32) ----------------------------

    [Fact]
    public void SetEditing_AdminChangesSet_ResolutionFollows_D31_D32()
    {
        var w = Setup();
        Assert.True(w.Roster.SetGroupTransports("company-1", "dg-1", new[] { "tor", "lan" }, "admin"));
        var eff = w.Roster.EffectiveTransportsForDevice(w.DeviceId);
        Assert.Equal(new[] { "tor", "lan" }, eff!.ToArray());
    }

    [Fact]
    public void SetEditing_NonAdminAndAiAndUnknownRung_Refused_D31_D32_D9()
    {
        var w = Setup();
        Assert.NotNull(w.Roster.CreateUser("ai-1", "company-1", "Agent", "ai", pairedByUserId: "admin"));
        Assert.False(w.Roster.SetGroupTransports("company-1", "dg-1", new[] { "lan" }, "ctrl")); // member, no admin right
        Assert.False(w.Roster.SetGroupTransports("company-1", "dg-1", new[] { "lan" }, "ai-1")); // AI never admin
        Assert.False(w.Roster.SetGroupTransports("company-1", "dg-1", new[] { "lan", "bogus" }, "admin")); // unknown rung
        Assert.False(w.Roster.SetGroupTransports("company-1", "dg-1", new[] { "lan" }, "ghost")); // unknown actor
        // The set is unchanged after every refusal.
        Assert.Equal(new[] { "lan", "hub", "tor" }, w.Roster.EffectiveTransportsForDevice(w.DeviceId)!.ToArray());
    }

    [Fact]
    public void SetEditing_CompanyCeilingCapsTheSet_D31()
    {
        var w = Setup();
        Assert.True(w.Roster.SetScopeTransportCeiling("company-1", new[] { "lan" }));
        Assert.Equal(new[] { "lan" }, w.Roster.EffectiveTransportsForDevice(w.DeviceId)!.ToArray());
    }

    // ---- discovery codec + classification (D19/D20) ------------------------------

    [Fact]
    public void Discovery_Roundtrip_CarriesOnlyHashNameState_D19_D20()
    {
        var a = DiscoveryAnnouncement.ForDevice("device-abc", "Site PC", enrolled: true);
        Assert.NotNull(a);
        var wire = a!.Encode();
        Assert.DoesNotContain("device-abc", wire); // the id itself never broadcasts
        var back = DiscoveryAnnouncement.Decode(wire);
        Assert.NotNull(back);
        Assert.Equal(a.DeviceIdHash, back!.DeviceIdHash);
        Assert.Equal("Site PC", back.DisplayName);
        Assert.Equal("enrolled", back.EnrollmentState);
    }

    [Fact]
    public void Discovery_HostileDatagrams_RefusedWholesale_D20()
    {
        Assert.Null(DiscoveryAnnouncement.Decode("DESKGUEST1|zzzz|enrolled|U2l0ZSBQQw=="));
        Assert.Null(DiscoveryAnnouncement.Decode("XXXX|" + new string('a', 64) + "|enrolled|U2l0ZSBQQw=="));
        Assert.Null(DiscoveryAnnouncement.Decode("DESKGUEST1|" + new string('a', 64) + "|controllable|U2l0ZSBQQw=="));
        Assert.Null(DiscoveryAnnouncement.Decode("DESKGUEST1|" + new string('a', 64) + "|enrolled|!!!not-base64!!!"));
        Assert.Null(DiscoveryAnnouncement.Decode(""));
        Assert.Null(DiscoveryAnnouncement.Decode(null));
    }

    [Fact]
    public void Discovery_Classification_KnownPeerVsAvailable_NeverControllable_D20()
    {
        var w = Setup();
        var svc = new DiscoveryService(new[] { w.DeviceId });
        var known = svc.Classify(DiscoveryAnnouncement.ForDevice(w.DeviceId, "Site PC", true)!);
        Assert.True(known.IsKnownPeer);
        Assert.False(known.AvailableToEnroll);
        Assert.False(known.IsControllable);
        var stranger = svc.Classify(DiscoveryAnnouncement.ForDevice("some-other-device", "Other", false)!);
        Assert.False(stranger.IsKnownPeer);
        Assert.True(stranger.AvailableToEnroll); // operator surfaces only: "available to enroll"
        Assert.False(stranger.IsControllable);    // discovery grants no trust
    }

    [Fact]
    public async Task Discovery_UdpBrowse_HeardOnLoopback_Classified_D19()
    {
        var w = Setup();
        var svc = new DiscoveryService(new[] { w.DeviceId });
        int port;
        using (var tmp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0)))
            port = ((IPEndPoint)tmp.Client.LocalEndPoint!).Port;
        var browse = svc.BrowseAsync(TimeSpan.FromSeconds(3), port);
        await Task.Delay(250);
        var known = DiscoveryAnnouncement.ForDevice(w.DeviceId, "Site PC", true)!;
        var spare = DiscoveryAnnouncement.ForDevice("unpaired-device", "Spare", false)!;
        try
        {
            await svc.AnnounceAsync(known, "127.0.0.1", port);
            await svc.AnnounceAsync(spare, "127.0.0.1", port);
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.AccessDenied)
        {
            // Environment fact (verified 2026-11-19, this sandbox):
            // UDP send is blocked wholesale — native Python gets the
            // same EPERM on loopback sendto. The live-browse leg
            // cannot run here; it runs wherever UDP is permitted
            // (the laptop proof exercises it for real). What CAN be
            // proven here is the exact receive path BrowseAsync runs:
            // the announced bytes, parsed and classified.
            var heard = new[]
            {
                DiscoveryService.ParseDatagram(System.Text.Encoding.UTF8.GetBytes(known.Encode()), svc),
                DiscoveryService.ParseDatagram(System.Text.Encoding.UTF8.GetBytes(spare.Encode()), svc),
            };
            Assert.All(heard, d => Assert.NotNull(d));
            Assert.Contains(heard, d => d!.IsKnownPeer);
            Assert.Contains(heard, d => d!.AvailableToEnroll && !d.IsControllable);
            return;
        }
        var found = await browse;
        Assert.Equal(2, found.Count);
        Assert.Contains(found, d => d.IsKnownPeer);
        Assert.Contains(found, d => d.AvailableToEnroll && !d.IsControllable);
    }
}

/// <summary>Destruction pass on the Block C transport core: every
/// attack is a genuine attempt to break the feature; breaks found
/// during the pass were fixed and these are their permanent
/// regressions (programme law, 2026-11-18).</summary>
public class TransportDestructionTests
{
    private static TransportTests.World Setup(string[]? set = null) => TransportTests.Setup(set);

    [Fact]
    public async Task Attack_UnauthenticatedLanClient_RefusedAndDropped()
    {
        var w = Setup();
        using var listener = new LanHostListener(w.Enrollments, w.HostIdentity);
        listener.Start(IPAddress.Loopback, 0);
        // Raw socket, no key at all: garbage instead of a proof.
        // CONV-F3 test transport (RawSocketTestLeg / log-conv-f3.md):
        // a literal raw Socket — a TcpClient leg is intercepted by
        // this sandbox's egress proxy and never reaches the listener.
        using var stream = await RawSocketTestLeg.ConnectLoopbackAsync(listener.Port);
        var chal = await LanProtocol.ReadLineAsync(stream, default);
        Assert.StartsWith("CHAL2 ", chal);
        await LanProtocol.WriteLineAsync(stream, "HELLO2 nobody AAAA AAAA AAAA", default);
        var verdict = await LanProtocol.ReadLineAsync(stream, default);
        Assert.Equal("REFUSE", verdict);
        await Task.Delay(150);
        Assert.Equal(0, listener.AcceptedSessions);
        Assert.True(listener.RefusedHandshakes >= 1);
    }

    [Fact]
    public async Task Attack_SpoofedDiscoveryClaim_CannotPassHandshake_D20()
    {
        var w = Setup();
        using var listener = new LanHostListener(w.Enrollments, w.HostIdentity);
        listener.Start(IPAddress.Loopback, 0);
        // A hostile announcer claims the victim device's hash…
        var spoof = DiscoveryAnnouncement.ForDevice(w.DeviceId, "Site PC", true)!;
        var svc = new DiscoveryService(Array.Empty<string>());
        Assert.True(svc.Classify(spoof).AvailableToEnroll); // …which buys it nothing but a listing
        // …and then tries to BE the victim: it signs the challenge
        // with the ATTACKER's key while claiming the victim's id.
        var attacker = new DeviceIdentity(new DevOnlyPassThroughProtector());
        // CONV-F3 test transport (RawSocketTestLeg / log-conv-f3.md):
        // raw Socket leg, as in Attack_UnauthenticatedLanClient above.
        using var stream = await RawSocketTestLeg.ConnectLoopbackAsync(listener.Port);
        var chal = await LanProtocol.ReadLineAsync(stream, default);
        // BD-SHARED-TRANSPORT F1: the v2 wire — CHAL2 carries the
        // host nonce, host id, host ephemeral and host signature.
        // The attacker claims the victim's id in HELLO2 and signs
        // the full client transcript with the ATTACKER's key; the
        // host verifies against the victim's ENROLLED key and
        // refuses. (Filler ephemeral: the signature check runs
        // before any DH, so the refusal does not depend on it.)
        var parts = chal!.Split(' ');
        Assert.Equal("CHAL2", parts[0]);
        var clientNonce = Convert.ToBase64String(new byte[16]);
        var forged = attacker.Sign(LanProtocol.ClientProofMessage(
            w.DeviceId, w.DeviceId, parts[1], clientNonce, parts[3], parts[3]));
        await LanProtocol.WriteLineAsync(stream,
            $"HELLO2 {w.DeviceId} {clientNonce} {parts[3]} {Convert.ToBase64String(forged)}", default);
        var verdict = await LanProtocol.ReadLineAsync(stream, default);
        Assert.Equal("REFUSE", verdict);
        Assert.Equal(0, listener.AcceptedSessions);
    }

    [Fact]
    public async Task Attack_UnenrolledIdentity_HandshakeRefused()
    {
        var w = Setup();
        using var listener = new LanHostListener(w.Enrollments, w.HostIdentity);
        listener.Start(IPAddress.Loopback, 0);
        var stranger = new DeviceIdentity(new DevOnlyPassThroughProtector()); // never enrolled
        var lan = new LanRung(w.Enrollments);
        var result = await lan.ConnectSessionAsync(
            new TransportTarget(stranger.DeviceId, $"127.0.0.1:{listener.Port}"), stranger);
        Assert.False(result.Ok);
        Assert.Equal(0, listener.AcceptedSessions);
    }

    [Fact]
    public async Task Attack_RevokedIdentity_HandshakeRefused()
    {
        var w = Setup();
        using var listener = new LanHostListener(w.Enrollments, w.HostIdentity);
        listener.Start(IPAddress.Loopback, 0);
        Assert.True(w.Enrollments.Revoke(w.OperatorIdentity.DeviceId));
        var lan = new LanRung(w.Enrollments);
        var result = await lan.ConnectSessionAsync(
            new TransportTarget(w.OperatorIdentity.DeviceId, $"127.0.0.1:{listener.Port}"), w.OperatorIdentity);
        Assert.False(result.Ok);
        Assert.Equal(0, listener.AcceptedSessions);
    }

    [Fact]
    public async Task Attack_FailoverDowngrade_KillingRungsNeverLeavesTheSet_D32()
    {
        var w = Setup(new[] { "lan", "hub" });
        // Both in-set rungs die; an out-of-set "tor" rung is
        // registered and WOULD succeed — the engine must not use it.
        var mgr = new TransportSessionManager(w.Roster, w.Sessions, new ITransportRung[]
        {
            StubRung.Failing("lan"), StubRung.Failing("hub"), StubRung.Succeeding("tor"),
        });
        var s = await mgr.StartSessionAsync("company-1", w.DeviceId, "ctrl", "unattended",
            new Dictionary<string, TransportTarget>());
        Assert.Null(s);
        Assert.Equal(0, ((StubRung)mgr.GetRung("tor")!).ConnectAttempts);
    }

    [Fact]
    public async Task Attack_DormantRungProbe_NoListenerNoTraffic_D29()
    {
        var w = Setup();
        using var listener = new LanHostListener(w.Enrollments, w.HostIdentity);
        // Never started: there is no listener to probe.
        Assert.False(listener.IsListening);
        int closedPort;
        using (var tmp = new TcpListener(IPAddress.Loopback, 0))
        { tmp.Start(); closedPort = ((IPEndPoint)tmp.LocalEndpoint).Port; tmp.Stop(); }
        var lan = new LanRung(w.Enrollments);
        var probe = await lan.ConnectSessionAsync(
            new TransportTarget(w.OperatorIdentity.DeviceId, $"127.0.0.1:{closedPort}"), w.OperatorIdentity);
        Assert.False(probe.Ok); // nothing answers on a dormant rung
        // And a stub rung the engine never walks stays untouched.
        var tor = StubRung.Succeeding("tor");
        var mgr = new TransportSessionManager(w.Roster, w.Sessions,
            new ITransportRung[] { StubRung.Succeeding("lan"), tor });
        await mgr.StartSessionAsync("company-1", w.DeviceId, "ctrl", "unattended",
            new Dictionary<string, TransportTarget>(), manualPins: new[] { "lan" });
        Assert.True(tor.IsDormant);
        Assert.Equal(0, tor.ConnectAttempts);
    }

    [Fact]
    public async Task Attack_ReconnectLoop_RepeatedReestablishTerminates()
    {
        var w = Setup();
        var mgr = new TransportSessionManager(w.Roster, w.Sessions, new ITransportRung[]
        {
            StubRung.Succeeding("lan"), StubRung.Succeeding("hub"), StubRung.Succeeding("tor"),
        });
        var s = await mgr.StartSessionAsync("company-1", w.DeviceId, "ctrl", "unattended",
            new Dictionary<string, TransportTarget>());
        Assert.NotNull(s);
        // Walk the whole chain, then keep asking: it must stop, not loop.
        var cur = s!;
        for (var i = 0; i < 2; i++)
        {
            var next = await mgr.ReestablishAsync(cur.Id, new Dictionary<string, TransportTarget>());
            Assert.NotNull(next);
            cur = next!;
        }
        var exhausted = await mgr.ReestablishAsync(cur.Id, new Dictionary<string, TransportTarget>());
        Assert.Null(exhausted);
        var again = await mgr.ReestablishAsync(cur.Id, new Dictionary<string, TransportTarget>());
        Assert.Null(again); // a dead-end stays a dead-end; no resurrection loop
        Assert.Equal("active", w.Sessions.GetSession(cur.Id)!.State);
    }

    [Fact]
    public void Attack_SetEditingBypass_SuspendedAdminAndCrossScope_Refused_D31_D8()
    {
        var w = Setup();
        Assert.NotNull(w.Roster.CreateUser("admin2", "company-1", "Admin Two", "human"));
        Assert.True(w.Roster.AddCompanyAdmin("company-1", "admin2"));
        Assert.True(w.Roster.SetUserSuspended("company-1", "admin2", true));
        Assert.False(w.Roster.SetGroupTransports("company-1", "dg-1", new[] { "tor" }, "admin2")); // suspended: no power
        Assert.False(w.Roster.SetGroupTransports("personal-x", "dg-1", new[] { "tor" }, "admin")); // wrong scope key
        Assert.Equal(new[] { "lan", "hub", "tor" }, w.Roster.EffectiveTransportsForDevice(w.DeviceId)!.ToArray());
    }
}
