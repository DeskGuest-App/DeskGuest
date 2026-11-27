using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using DeskGuest.Core;
using DeskGuest.Shared.AiPack;
using DeskGuest.Shared.Enrollment;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.OwnPath;
using DeskGuest.Shared.QuickAssist;
using DeskGuest.Shared.Roster;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.Sessions;
using DeskGuest.Shared.Terminal;
using DeskGuest.Shared.Transport;
using DeskGuest.Shared.WebRtc;

namespace DeskGuest.Tests;

/// <summary>Block F — surfacing + enterprise wiring + remaining
/// rungs. Floor surfacing (D35), the terminal channel, quick assist
/// (D24), the AI pack machinery (D25), ipv6/ownpath/tor + manual
/// WebRTC, and the Block E enterprise services wired live into the
/// Core. Destruction cases are named as such inline.</summary>
public class BlockFTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 20, 12, 0, 0, TimeSpan.Zero);

    internal sealed class World
    {
        public required EnrollmentService Enrollments { get; init; }
        public required RosterService Roster { get; init; }
        public required SessionService Sessions { get; init; }
        public required string DeviceId { get; init; }
        public required DeviceIdentity OperatorIdentity { get; init; }
        // BD-SHARED-TRANSPORT F1 test repair: the v2 host listener
        // signs its challenge with the host's own identity — the
        // World carries it (Setup previously discarded it).
        public required DeviceIdentity HostIdentity { get; init; }
    }

    internal static World Setup()
    {
        var enrollments = new EnrollmentService();
        var roster = new RosterService(enrollments);
        Assert.NotNull(roster.CreateScope("company-1", "company", "Company A"));
        Assert.NotNull(roster.CreateUser("admin", "company-1", "Admin", "human"));
        Assert.True(roster.AddCompanyAdmin("company-1", "admin"));
        Assert.NotNull(roster.CreateUser("host", "company-1", "Host User", "human"));
        Assert.NotNull(roster.CreateUser("ctrl", "company-1", "Controller", "human"));
        Assert.NotNull(roster.CreateUser("peer", "company-1", "Peer", "human"));
        Assert.NotNull(roster.CreateUser("watch", "company-1", "Watcher", "human"));
        Assert.NotNull(roster.CreateUser("ai-1", "company-1", "Agent One", "ai", pairedByUserId: "admin"));
        Assert.NotNull(roster.CreateUserGroup("ug-1", "company-1", "Techs",
            new[] { "ctrl", "host", "peer", "watch", "ai-1" }));
        Assert.NotNull(roster.CreateDeviceGroup("dg-1", "company-1", "Fleet",
            new[] { "lan", "hub", "ipv6", "ownpath", "tor" }));
        Assert.NotNull(roster.AddGrant("company-1", "ug-1", "dg-1", new[] { "use" }));

        var hostIdentity = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var code = enrollments.CreateEnrollmentCode("company", "dg-1", "Fleet");
        var device = enrollments.Redeem(code, new EnrollingDevice(hostIdentity.DeviceId, hostIdentity.PublicKeyBase64, "Site PC"));
        Assert.NotNull(device);
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

    private static string ActiveSession(World w, string rung = "lan", string initiator = "ctrl")
    {
        var s = w.Sessions.CreateSession("company-1", w.DeviceId, initiator, "attended", rung);
        Assert.NotNull(s);
        Assert.True(w.Sessions.AcceptSession(s!.Id, "host", SessionAcceptOrigin.EndpointLocal));
        Assert.True(w.Sessions.StartSession(s.Id));
        Assert.Equal("active", w.Sessions.GetSession(s.Id)!.State);
        return s.Id;
    }

    // ---- OwnPath: T5 serializer + validators + X25519 (RFC 7748) ----

    [Fact]
    public void OwnPath_X25519_MatchesRfc7748Vector()
    {
        // RFC 7748 §6.1 (Alice), cross-checked against an independent
        // implementation (Python cryptography) before being pinned here.
        var alicePriv = Convert.FromHexString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        var basePoint = new byte[32]; basePoint[0] = 9;
        var pub = WireGuardConfigGenerator.X25519(alicePriv, basePoint);
        Assert.Equal("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
            Convert.ToHexString(pub).ToLowerInvariant());
        // DH agreement between two generated pairs.
        var (aPriv, aPub) = WireGuardConfigGenerator.GenerateKeyPair();
        var (bPriv, bPub) = WireGuardConfigGenerator.GenerateKeyPair();
        var s1 = WireGuardConfigGenerator.X25519(Convert.FromBase64String(aPriv), Convert.FromBase64String(bPub));
        var s2 = WireGuardConfigGenerator.X25519(Convert.FromBase64String(bPriv), Convert.FromBase64String(aPub));
        Assert.Equal(s1, s2);
    }

    [Fact]
    public void OwnPath_GeneratedConfig_IsClean_PerPeer32_NoHooks()
    {
        var (_, pub) = WireGuardConfigGenerator.GenerateKeyPair();
        var peer = new OwnPathPeer("dev-1", "Site PC", pub, "10.9.0.2", "203.0.113.9:51820");
        var config = WireGuardConfigGenerator.GeneratePeerConfig(peer);
        Assert.Contains("AllowedIPs = 10.9.0.2/32", config);
        Assert.DoesNotContain("PostUp", config);
        Assert.DoesNotContain("SaveConfig", config);
        Assert.DoesNotContain("DNS", config);
        Assert.True(WireGuardConfigGenerator.ValidateConfigText(config).Ok);
    }

    [Fact]
    public void OwnPath_HostileNames_FuzzSuite_AllRefused()
    {
        var (_, pub) = WireGuardConfigGenerator.GenerateKeyPair();
        string[] hostile =
        {
            "evil\n[Peer]\nPublicKey = AAAA", "a/b", "name; rm -rf /", "na\"me", "[Interface]",
            "", "   ", new string('x', 49), "tab\tname", "emoji😀", "name#comment", "a\\b",
            "peer\nPostUp = curl evil", "..", "name=", " lead", "trail ",
        };
        foreach (var name in hostile)
        {
            Assert.False(OwnPathValidation.IsSafeName(name), $"name should be refused: {name}");
            var peer = new OwnPathPeer("dev-1", name, pub, "10.9.0.2", "203.0.113.9:51820");
            Assert.Throws<InvalidOperationException>(() => WireGuardConfigGenerator.GeneratePeerConfig(peer));
        }
    }

    [Fact]
    public void OwnPath_ValidateConfigText_RefusesHooksSaveConfigDns()
    {
        const string clean = "[Peer]\nPublicKey = AAAA\nAllowedIPs = 10.0.0.2/32\n";
        Assert.True(WireGuardConfigGenerator.ValidateConfigText(clean).Ok);
        Assert.False(WireGuardConfigGenerator.ValidateConfigText(clean + "PostUp = x\n").Ok);
        Assert.False(WireGuardConfigGenerator.ValidateConfigText(clean + "PreDown = x\n").Ok);
        Assert.False(WireGuardConfigGenerator.ValidateConfigText(clean + "SaveConfig = true\n").Ok);
        Assert.False(WireGuardConfigGenerator.ValidateConfigText(clean + "DNS = 1.1.1.1\n").Ok);
        Assert.False(WireGuardConfigGenerator.ValidateConfigText(clean + "Table = off\n").Ok);
    }

    [Fact]
    public void OwnPath_SshChannelConfig_AssertsDenyList()
    {
        var (_, pub) = WireGuardConfigGenerator.GenerateKeyPair();
        var peer = new OwnPathPeer("dev-1", "Site PC", pub, "10.9.0.2", "203.0.113.9:2222");
        var config = SshChannelConfigGenerator.GenerateHostStanza("sitepc", peer, "deskguest-tunnel", "deskguest_channel_key");
        Assert.Contains("PasswordAuthentication no", config);
        Assert.Contains("KbdInteractiveAuthentication no", config);
        Assert.Contains("MaxAuthTries 3", config);
        Assert.Contains("StrictHostKeyChecking yes", config);
        Assert.Contains("ForwardAgent no", config);
        Assert.Contains("ClearAllForwardings yes", config);
        // The authorized_keys side is restrict-class, Ed25519 only.
        var identity = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var keyLine = SshChannelConfigGenerator.GenerateAuthorizedKeyLine(
            $"ssh-ed25519 {identity.PublicKeyBase64}", "Site PC");
        Assert.StartsWith("restrict", keyLine);
        Assert.Throws<InvalidOperationException>(() =>
            SshChannelConfigGenerator.GenerateAuthorizedKeyLine($"ssh-rsa {identity.PublicKeyBase64}", "Site PC"));
    }

    // ---- ipv6 rung: honest reachability ------------------------------

    [Fact]
    public void Ipv6_Classify_OnlyGlobalUnicastPasses()
    {
        Assert.True(Ipv6Reachability.Classify("2606:4700:4700::1111").Ok);
        Assert.False(Ipv6Reachability.Classify("2001:db8::1").Ok);   // documentation range lies about reachability
        Assert.False(Ipv6Reachability.Classify("fe80::1").Ok);       // link-local
        Assert.False(Ipv6Reachability.Classify("fd00::1").Ok);       // unique-local
        Assert.False(Ipv6Reachability.Classify("::1").Ok);           // loopback
        Assert.False(Ipv6Reachability.Classify("10.0.0.5").Ok);      // not IPv6 at all
        Assert.False(Ipv6Reachability.Classify("example.com").Ok);   // names are not probed addresses
        Assert.False(Ipv6Reachability.Classify(null).Ok);
    }

    [Fact]
    public async Task Ipv6Rung_RefusesWhenLocalHasNoGlobalIpv6()
    {
        var w = Setup();
        var rung = new Ipv6Rung(localHasGlobal: () => false, enrollments: w.Enrollments);
        var result = await rung.ConnectSessionAsync(
            new TransportTarget(w.DeviceId, "[2606:4700:4700::1111]:47621"), w.OperatorIdentity);
        Assert.False(result.Ok);
        Assert.Contains("no global IPv6", result.Detail);
    }

    [Fact]
    public async Task Ipv6Rung_RefusesNonGlobalTarget_EvenWithLocalGlobal()
    {
        var w = Setup();
        var rung = new Ipv6Rung(localHasGlobal: () => true, enrollments: w.Enrollments);
        var result = await rung.ConnectSessionAsync(
            new TransportTarget(w.DeviceId, "[2001:db8::1]:47621"), w.OperatorIdentity);
        Assert.False(result.Ok);
        Assert.Contains("documentation", result.Detail);
    }

    // ---- ownpath rung: session-layer integration ----------------------

    [Fact]
    public async Task OwnPathRung_NoPeerConfig_Refuses()
    {
        var w = Setup();
        var rung = new OwnPathRung(() => OwnPathPeerSet.Empty, w.Enrollments);
        var result = await rung.ConnectSessionAsync(new TransportTarget(w.DeviceId, ""), w.OperatorIdentity);
        Assert.False(result.Ok);
        Assert.Contains("no generated WireGuard config", result.Detail);
    }

    [Fact]
    public async Task OwnPathRung_SwappedInvalidPeer_RefusesAtUseTime()
    {
        var w = Setup();
        var (_, pub) = WireGuardConfigGenerator.GenerateKeyPair();
        // A peer record whose endpoint is not a host:port can never
        // serialize — the rung re-validates at use time and refuses.
        var bad = new OwnPathPeer(w.DeviceId, "Site PC", pub, "127.0.0.1", "not a host");
        var rung = new OwnPathRung(() => new OwnPathPeerSet(
            new Dictionary<string, OwnPathPeer> { [w.DeviceId] = bad }), w.Enrollments);
        var result = await rung.ConnectSessionAsync(new TransportTarget(w.DeviceId, ""), w.OperatorIdentity);
        Assert.False(result.Ok);
        Assert.Contains("validation", result.Detail);
    }

    [Fact]
    public async Task OwnPathRung_CarriesSession_AndFailoverHopsToIt()
    {
        var w = Setup();
        using var listener = new LanHostListener(w.Enrollments, w.HostIdentity);
        listener.Start(IPAddress.Loopback, 0);
        var (_, pub) = WireGuardConfigGenerator.GenerateKeyPair();
        var peer = new OwnPathPeer(w.DeviceId, "Site PC", pub, "127.0.0.1", "127.0.0.1:51820");
        var rung = new OwnPathRung(() => new OwnPathPeerSet(
            new Dictionary<string, OwnPathPeer> { [w.DeviceId] = peer }), w.Enrollments);
        var mgr = new TransportSessionManager(w.Roster, w.Sessions,
            new ITransportRung[] { StubRung.Failing("lan"), rung }, w.OperatorIdentity);
        var targets = new Dictionary<string, TransportTarget>
        { ["ownpath"] = new(w.DeviceId, $"127.0.0.1:{listener.Port}") };
        var s = await mgr.StartSessionAsync("company-1", w.DeviceId, "ctrl", "unattended", targets);
        Assert.NotNull(s);
        Assert.Equal("ownpath", s!.TransportRung);
        Assert.Equal("active", s.State);
        mgr.ForgetLink(s.Id);
    }

    // ---- tor rung ------------------------------------------------------

    [Fact]
    public async Task TorRung_Unconfigured_RefusesHonestly()
    {
        var w = Setup();
        var rung = new TorRung(() => null, w.Enrollments);
        var result = await rung.ConnectSessionAsync(
            new TransportTarget(w.DeviceId, "203.0.113.7:47621"), w.OperatorIdentity);
        Assert.False(result.Ok);
        Assert.Contains("not configured", result.Detail);
        Assert.Contains("latency", TorConfig.LatencyLabel, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task TorRung_Socks5Handshake_CarriesSession()
    {
        var w = Setup();
        using var listener = new LanHostListener(w.Enrollments, w.HostIdentity);
        listener.Start(IPAddress.Loopback, 0);
        // A minimal fake Tor SOCKS5 proxy: no-auth CONNECT, then a
        // byte relay to the real host listener (the "exit").
        var socks = new TcpListener(IPAddress.Loopback, 0);
        socks.Start();
        var socksPort = ((IPEndPoint)socks.LocalEndpoint).Port;
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var serverTask = Task.Run(async () =>
        {
            using var clientSide = await socks.AcceptTcpClientAsync(cts.Token);
            var cs = clientSide.GetStream();
            var head = new byte[2];
            await cs.ReadExactlyAsync(head, cts.Token);
            var methods = new byte[head[1]];
            await cs.ReadExactlyAsync(methods, cts.Token);
            await cs.WriteAsync(new byte[] { 5, 0 }, cts.Token);
            var req = new byte[4];
            await cs.ReadExactlyAsync(req, cts.Token);
            if (req[3] == 1) { var a = new byte[4]; await cs.ReadExactlyAsync(a, cts.Token); }
            else if (req[3] == 3) { var l = new byte[1]; await cs.ReadExactlyAsync(l, cts.Token); var d = new byte[l[0]]; await cs.ReadExactlyAsync(d, cts.Token); }
            var p = new byte[2]; await cs.ReadExactlyAsync(p, cts.Token);
            await cs.WriteAsync(new byte[] { 5, 0, 0, 1, 0, 0, 0, 0, 0, 0 }, cts.Token);
            using var exit = new TcpClient();
            await exit.ConnectAsync(IPAddress.Loopback, listener.Port, cts.Token);
            var es = exit.GetStream();
            await Task.WhenAny(cs.CopyToAsync(es, cts.Token), es.CopyToAsync(cs, cts.Token));
        }, cts.Token);
        try
        {
            var rung = new TorRung(() => new TorConfig("127.0.0.1", socksPort), w.Enrollments);
            var result = await rung.ConnectSessionAsync(
                new TransportTarget(w.DeviceId, "203.0.113.7:47621"), w.OperatorIdentity);
            Assert.True(result.Ok, result.Detail);
            result.Stream!.Dispose();
        }
        finally { socks.Stop(); }
    }

    // ---- terminal channel ----------------------------------------------

    private sealed class FakeSink : ITerminalSink
    {
        public List<string> Written { get; } = new();
        public List<string> Started { get; } = new();
        public List<string> Closed { get; } = new();
        public void Start(string terminalId) => Started.Add(terminalId);
        public void Write(string terminalId, string text) => Written.Add(text);
        public void Close(string terminalId) => Closed.Add(terminalId);
    }

    [Fact]
    public void Terminal_FloorHolderWrites_WatcherAndAiWithoutCapabilityRefused()
    {
        var w = Setup();
        var sink = new FakeSink();
        var terminals = new TerminalService(w.Sessions, w.Roster, sink: sink);
        var id = ActiveSession(w);
        Assert.True(w.Sessions.AddParticipant(id, "watch", "watcher", "host"));
        Assert.True(w.Sessions.AddParticipant(id, "ai-1", "watcher", "host"));
        Assert.True(w.Sessions.GrantFloor(id, "ai-1", "host")); // the AI even holds the floor…

        var (ok, _, term) = terminals.Open(id, "host", T0);
        Assert.True(ok);
        // …but without the pairing scope's named terminal capability
        // its keystrokes never reach the shell (D9, default OFF).
        Assert.False(terminals.Write(term!.Id, "ai-1", "dir\r\n").Ok);
        // A watcher is refused identically.
        Assert.False(terminals.Write(term.Id, "watch", "dir\r\n").Ok);
        // A non-participant is refused.
        Assert.False(terminals.Write(term.Id, "outsider", "dir\r\n").Ok);
        // Even the host is refused while the floor is given away —
        // keystrokes reach the terminal from the floor holder only;
        // the host takes the floor back first (a host act).
        Assert.False(terminals.Write(term.Id, "host", "dir\r\n").Ok);
        Assert.True(w.Sessions.TakeFloorBack(id, "host"));
        Assert.True(terminals.Write(term.Id, "host", "dir\r\n").Ok);
        Assert.Equal(new[] { "dir\r\n" }, sink.Written);
        // The open terminal is a roster fact, and output is recorded.
        Assert.NotNull(terminals.OpenTerminalFor(id));
        Assert.True(terminals.AppendOutput(term.Id, "C:\\>"));
        Assert.Contains("C:\\>", terminals.Output(term.Id));
        Assert.Contains(w.Sessions.ListEvents(id), e => e.Kind == "terminal_opened");
    }

    [Fact]
    public void Terminal_AiWithPairingCapability_MayWrite()
    {
        var w = Setup();
        var sink = new FakeSink();
        var terminals = new TerminalService(w.Sessions, w.Roster,
            aiTerminalCapability: (_, user) => user == "ai-1", sink: sink);
        var id = ActiveSession(w);
        Assert.True(w.Sessions.AddParticipant(id, "ai-1", "watcher", "host"));
        Assert.True(w.Sessions.GrantFloor(id, "ai-1", "host"));
        var (ok, _, term) = terminals.Open(id, "host", T0);
        Assert.True(ok);
        Assert.True(terminals.Write(term!.Id, "ai-1", "whoami\r\n").Ok);
    }

    [Fact]
    public void Terminal_FloorChangeCutsFormerHolder_AndSessionEndKillsTerminal()
    {
        var w = Setup();
        var sink = new FakeSink();
        var terminals = new TerminalService(w.Sessions, w.Roster, sink: sink);
        var id = ActiveSession(w);
        Assert.True(w.Sessions.GrantFloor(id, "ctrl", "host"));
        var (ok, _, term) = terminals.Open(id, "ctrl", T0);
        Assert.True(ok);
        Assert.True(terminals.Write(term!.Id, "ctrl", "echo hi\r\n").Ok);
        // Floor taken back: the former holder's keystrokes stop NOW.
        Assert.True(w.Sessions.TakeFloorBack(id, "host"));
        Assert.False(terminals.Write(term.Id, "ctrl", "echo pwned\r\n").Ok);
        // Session end reaps the terminal; the shell is torn down.
        Assert.True(w.Sessions.EndSession(id, "host"));
        Assert.Equal(1, terminals.ReapEnded());
        Assert.Contains(term.Id, sink.Closed);
        Assert.Null(terminals.OpenTerminalFor(id));
        Assert.False(terminals.Write(term.Id, "host", "echo ghost\r\n").Ok);
    }

    [Fact]
    public void Terminal_NeverOutsideASession()
    {
        var w = Setup();
        var terminals = new TerminalService(w.Sessions, w.Roster, sink: new FakeSink());
        var s = w.Sessions.CreateSession("company-1", w.DeviceId, "ctrl", "attended", "lan");
        Assert.NotNull(s);
        // Requested (not accepted/started): no terminal.
        Assert.False(terminals.Open(s!.Id, "host", T0).Ok);
        // Unknown session: no terminal.
        Assert.False(terminals.Open("nope", "host", T0).Ok);
    }

    // ---- quick assist ---------------------------------------------------

    [Fact]
    public void QuickAssist_HappyPath_ViewOnlyGrant_BoundToClient()
    {
        var qa = new QuickAssistService();
        var code = qa.Mint("co1", "dev-1", "tech", T0);
        Assert.True(QuickAssistService.IsWellFormed(code));
        var (ok, _, grant, token) = qa.Redeem(code, "browser-binding", T0);
        Assert.True(ok);
        Assert.True(grant!.ViewOnly);
        Assert.True(QuickAssistService.GrantViewOnly);
        // The same grant answers only to its own binding + token.
        Assert.True(qa.Validate(grant.GrantId, token, "browser-binding", T0).Ok);
        var impersonation = qa.Validate(grant.GrantId, token, "attacker-binding", T0);
        Assert.False(impersonation.Ok); // helper impersonation refused
        Assert.False(qa.Validate(grant.GrantId, "wrong-token", "browser-binding", T0).Ok);
    }

    [Fact]
    public void QuickAssist_CodeReuseAfterClose_AndSingleUseEnforced()
    {
        var qa = new QuickAssistService();
        var code = qa.Mint("co1", "dev-1", "tech", T0);
        var (ok, _, grant, _) = qa.Redeem(code, "b1", T0);
        Assert.True(ok);
        Assert.False(qa.Redeem(code, "b1", T0).Ok); // single-use
        Assert.True(qa.Close(grant!.GrantId));
        Assert.False(qa.Validate(grant.GrantId, "anything", "b1", T0).Ok); // dead with the close
    }

    [Fact]
    public void QuickAssist_Guessing_BurnsAttempts_ThenLocksEvenTheRealCode()
    {
        // AMENDED by bd-shared-plat-2/F7: the lockout is PER CLIENT
        // BINDING. The old global lockout let five junk redeems
        // from anyone lock quick assist for every user — a DoS,
        // not a burn. Now the guessing binding burns itself; the
        // genuine binding is untouched.
        var qa = new QuickAssistService();
        var code = qa.Mint("co1", "dev-1", "tech", T0);
        for (var i = 0; i < QuickAssistService.MaxFailedAttempts; i++)
            Assert.False(qa.Redeem("ZZZZ-ZZZZ", "guess", T0).Ok);
        Assert.True(qa.IsLocked(T0, "guess"));
        // Attempt burn: during ITS lockout even the genuine code
        // refuses FROM THE GUESSING BINDING.
        Assert.False(qa.Redeem(code, "guess", T0).Ok);
        // But the real helper's binding was never burned.
        Assert.True(qa.Redeem(code, "b1", T0).Ok);
    }

    [Fact]
    public void QuickAssist_ExpiredCode_Refused()
    {
        var qa = new QuickAssistService();
        var code = qa.Mint("co1", "dev-1", "tech", T0, TimeSpan.FromMinutes(1));
        Assert.False(qa.Redeem(code, "b1", T0.AddMinutes(2)).Ok);
    }

    // ---- AI pack machinery (fixture-proven; production pins open) -------

    private static string Sha256Hex(byte[] bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    [Fact]
    public void AiPack_ProductionManifest_PinsCaptured_A3()
    {
        // A3 (2026-11-22): pins captured from the author's own
        // listing — the production manifest no longer refuses for
        // missing pins. Pin-state proof lives in AiPackPinTests.
        Assert.True(AiPackManifest.UiTars15_7B.PinsCaptured);
        Assert.NotEmpty(AiPackManifest.UiTars15_7B.Files);
        Assert.Equal("unaudited", AiPackManifest.UiTars15_7B.AuditStatus);
        Assert.True(AiPackManifest.UiTars15_7B.ValidateIntegrity().Ok);
    }

    [Fact]
    public async Task AiPack_LicenceGate_ThenFixtureDownload_Verifies()
    {
        var bytes = Encoding.UTF8.GetBytes("fixture-weights");
        var files = new[] { new PackFile("model.bin", Sha256Hex(bytes), bytes.Length) };
        var svc = new AiPackService(AiPackManifest.ForFixture("fixture://local", files));
        var dir = TestUtil.TempDir();
        Task Fetch(string url, string dest, CancellationToken ct) => File.WriteAllBytesAsync(dest, bytes, ct);
        // Licence not yet accepted: refused before any fetch.
        Assert.False((await svc.DownloadAsync(dir, Fetch, fixtureMode: true)).Ok);
        svc.AcceptLicence("operator");
        var (ok, detail) = await svc.DownloadAsync(dir, Fetch, fixtureMode: true);
        Assert.True(ok, detail);
        Assert.True(File.Exists(Path.Combine(dir, "model.bin")));
        Assert.True((await svc.VerifyInstalledAsync(dir)).Ok);
        Assert.Contains("Apache-2.0", svc.LicenceToShow());
    }

    [Fact]
    public async Task AiPack_HashMismatch_RefusesAndDeletesPartial_NoOverride()
    {
        var good = Encoding.UTF8.GetBytes("real-weights-123");
        var files = new[] { new PackFile("model.bin", Sha256Hex(good), good.Length) };
        var svc = new AiPackService(AiPackManifest.ForFixture("fixture://local", files));
        svc.AcceptLicence("operator");
        var dir = TestUtil.TempDir();
        Task Fetch(string url, string dest, CancellationToken ct) =>
            File.WriteAllBytesAsync(dest, Encoding.UTF8.GetBytes("tampered-weights"), ct);
        var (ok, detail) = await svc.DownloadAsync(dir, Fetch, fixtureMode: true);
        Assert.False(ok);
        Assert.Contains("hash mismatch", detail, StringComparison.OrdinalIgnoreCase);
        Assert.False(File.Exists(Path.Combine(dir, "model.bin")));
        Assert.False(File.Exists(Path.Combine(dir, "model.bin.partial")));
    }

    [Fact]
    public async Task AiPack_WrongSource_Refused()
    {
        var bytes = Encoding.UTF8.GetBytes("fixture-weights");
        var files = new[] { new PackFile("model.bin", Sha256Hex(bytes), bytes.Length) };
        var svc = new AiPackService(AiPackManifest.ForFixture("fixture://local", files));
        svc.AcceptLicence("operator");
        var dir = TestUtil.TempDir();
        Task Fetch(string url, string dest, CancellationToken ct) => File.WriteAllBytesAsync(dest, bytes, ct);
        var (ok, detail) = await svc.DownloadAsync(dir, Fetch,
            sourceBaseOverride: "https://evil.example/models", fixtureMode: false);
        Assert.False(ok);
        Assert.Contains("wrong source", detail, StringComparison.OrdinalIgnoreCase);
    }

    // ---- manual WebRTC: signaling + session binding ----------------------

    [Fact]
    public void WebRtc_CodeExchange_BindsSession_AndRefusesReplayTamperMismatch()
    {
        var w = Setup();
        var id = ActiveSession(w);
        var sig = new WebRtcSignaling(w.Enrollments, w.Sessions,
            // BD-SHARED-TRANSPORT F5 test repair: AcceptCode now
            // requires the code's device to be a PARTY to the
            // session. In this world the operator device is the
            // session's controlling participant, so the resolver
            // names it a party alongside the host — the production
            // default (host-only) plus CoreRuntime's own-device
            // rule cover the real wirings.
            (session, deviceId) => deviceId == session.HostDeviceId || deviceId == w.OperatorIdentity.DeviceId);
        const string sdp = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\n";
        var code = sig.CreateCode("offer", id, sdp, w.OperatorIdentity, T0);
        Assert.StartsWith("DGWR1.", code);
        var (ok, _, parsed) = sig.AcceptCode(code, sdp, T0);
        Assert.True(ok);
        Assert.Equal(id, parsed!.SessionId);
        // Replay: a code sets up exactly once.
        Assert.False(sig.AcceptCode(code, sdp, T0).Ok);
        // SDP swap: the code binds the SDP hash, not whatever arrives.
        var code2 = sig.CreateCode("offer", id, sdp, w.OperatorIdentity, T0);
        Assert.False(sig.AcceptCode(code2, "v=0\r\nattacker-sdp", T0).Ok);
        // Tamper: flip a signature character (guaranteed different).
        var code3 = sig.CreateCode("offer", id, sdp, w.OperatorIdentity, T0);
        var flip = code3[^2] == 'A' ? 'B' : 'A';
        var tampered = code3[..^2] + flip + code3[^1..];
        Assert.False(sig.AcceptCode(tampered, sdp, T0).Ok);
        // Expiry.
        var code4 = sig.CreateCode("offer", id, sdp, w.OperatorIdentity, T0);
        Assert.False(sig.AcceptCode(code4, sdp, T0.AddMinutes(11)).Ok);
        // The media leg is labeled, never silently adopted (T7).
        Assert.Equal("media_unavailable_t7_unaudited", WebRtcMediaStatus.Label);
    }

    [Fact]
    public void WebRtc_UnenrolledDeviceCode_Refused()
    {
        var w = Setup();
        var id = ActiveSession(w);
        var sig = new WebRtcSignaling(w.Enrollments, w.Sessions,
            // BD-SHARED-TRANSPORT F5 test repair: AcceptCode now
            // requires the code's device to be a PARTY to the
            // session. In this world the operator device is the
            // session's controlling participant, so the resolver
            // names it a party alongside the host — the production
            // default (host-only) plus CoreRuntime's own-device
            // rule cover the real wirings.
            (session, deviceId) => deviceId == session.HostDeviceId || deviceId == w.OperatorIdentity.DeviceId);
        var stranger = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var code = sig.CreateCode("offer", id, "sdp", stranger, T0);
        Assert.False(sig.AcceptCode(code, "sdp", T0).Ok);
    }

    // ---- floor surfacing (D35) -------------------------------------------

    [Fact]
    public void FloorSurfacing_PictureCarriesTransportPerParticipant()
    {
        var w = Setup();
        var id = ActiveSession(w, rung: "ownpath");
        Assert.True(w.Sessions.AddParticipant(id, "watch", "watcher", "host"));
        Assert.True(w.Sessions.GrantFloor(id, "ctrl", "host"));
        var facts = DeskGuest.Core.Services.SessionPicture.All(w.Sessions, w.Roster, DateTimeOffset.UtcNow);
        var fact = Assert.Single(facts, f => f.Id == id);
        Assert.All(fact.Participants, p => Assert.Equal("ownpath", p.Transport));
        Assert.Contains(fact.Participants, p => p.Role == "host");
        Assert.Contains(fact.Participants, p => p.Floor == "holds");
    }

    // ---- enterprise wiring through the live Core ---------------------------

    private static CoreRuntime NewRuntime(string dir, int port) => new(new CoreOptions
    {
        DataDir = dir, Port = port, Protector = new DevOnlyPassThroughProtector(),
        Probe = new FakeProbe(), FactChecks = new FakeFactChecks(),
    });

    private static (string BundleJson, string OrgKeyB64) SignedPolicy(string? pin = null, DateTimeOffset? deferUntil = null)
    {
        var org = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var issued = DateTimeOffset.UtcNow.AddHours(-1);
        var unsigned = new PolicyBundle(1, "co1", new[] { "lan", "hub" }, "auto",
            pin, deferUntil, false, false, "business_hours", issued, issued.AddDays(30), "");
        var signed = PolicyBundleService.Sign(unsigned, org);
        return (System.Text.Json.JsonSerializer.Serialize(signed),
            Convert.ToBase64String(org.PublicKey));
    }

    private static void WritePolicy(string dir, string bundleJson, string orgKeyB64)
    {
        File.WriteAllText(Path.Combine(dir, "policy-bundle.json"), bundleJson);
        File.WriteAllText(Path.Combine(dir, "policy-orgkey.txt"), orgKeyB64);
    }

    [Fact]
    public void EnterpriseWiring_PinnedUpdate_RefusedThroughLiveUpdateSurface()
    {
        var dir = TestUtil.TempDir();
        var (bundle, key) = SignedPolicy(pin: "1.2.3");
        WritePolicy(dir, bundle, key);
        var runtime = NewRuntime(dir, 18811);
        Assert.Contains("loaded", runtime.Enterprise.PolicyState);
        var check = runtime.ApplyEnterpriseAction("{\"action\":\"update_check\",\"version\":\"9.9.9\"}");
        Assert.False(check.Ok);
        Assert.Contains("policy pins", check.Detail, StringComparison.OrdinalIgnoreCase);
        // The refusal lives in the update surface itself, not just
        // the enterprise page: staging a non-pinned version dies at
        // the policy gate, before signature verification.
        var staged = runtime.Updates.StagePackage(new byte[] { 1, 2, 3 }, new byte[] { 4 }, "9.9.9");
        Assert.False(staged.Ok);
        Assert.Contains("policy pins", staged.Message, StringComparison.OrdinalIgnoreCase);
        // The pinned version passes the policy gate (and then fails
        // signature verification on its own merits — a different refusal).
        var stagedPinned = runtime.Updates.StagePackage(new byte[] { 1, 2, 3 }, new byte[] { 4 }, "1.2.3");
        Assert.False(stagedPinned.Ok);
        Assert.DoesNotContain("policy pins", stagedPinned.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void EnterpriseWiring_DeferredUpdate_Refused()
    {
        var dir = TestUtil.TempDir();
        var (bundle, key) = SignedPolicy(deferUntil: DateTimeOffset.UtcNow.AddDays(7));
        WritePolicy(dir, bundle, key);
        var runtime = NewRuntime(dir, 18812);
        var check = runtime.ApplyEnterpriseAction("{\"action\":\"update_check\",\"version\":\"2.0.0\"}");
        Assert.False(check.Ok);
        Assert.Contains("deferred", check.Detail, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task EnterpriseWiring_PolicySwapBetweenRestarts_DropsStalePolicy()
    {
        var dir = TestUtil.TempDir();
        var (bundle, key) = SignedPolicy(pin: "1.2.3");
        WritePolicy(dir, bundle, key);
        var first = NewRuntime(dir, 18813);
        Assert.Contains("loaded", first.Enterprise.PolicyState);
        // Attack: swap in a bundle signed by a DIFFERENT org key.
        var (forged, _) = SignedPolicy(pin: "9.9.9");
        File.WriteAllText(Path.Combine(dir, "policy-bundle.json"), forged);
        // W95 / FR-124 amendment: "between restarts" is now literal —
        // the first runtime stops before the second constructs (the
        // single-instance guard refuses a second LIVE Core on the
        // same data dir; defect D-W93-1's fix).
        await first.StopAsync(default);
        await first.DisposeAsync();
        var second = NewRuntime(dir, 18813);
        Assert.DoesNotContain("loaded and verified", second.Enterprise.PolicyState);
        Assert.Null(second.Enterprise.Enforcer); // the stale policy is GONE, not merely doubted
        // Block H D38 fix F6 (TOTAL POLICY CONTROL): a bundle that is
        // PRESENT but refused (here: signed by a different org key) is
        // NOT "no policy" — every gate DENIES until a valid bundle
        // loads. The old assertion here (update_check Ok) encoded the
        // fail-open defect F6 condemned; amended with disclosure in
        // the lane log/ledger.
        Assert.True(second.Enterprise.PolicyRefused);
        var check = second.ApplyEnterpriseAction("{\"action\":\"update_check\",\"version\":\"9.9.9\"}");
        Assert.False(check.Ok); // present-but-refused bundle = fail CLOSED, never fail open
        await second.StopAsync(default);
        await second.DisposeAsync();
    }

    [Fact]
    public async Task EnterpriseWiring_AuditExport_AndBrokenChainExportCarriesVerdict()
    {
        var dir = TestUtil.TempDir();
        var runtime = NewRuntime(dir, 18814);
        var export = runtime.ApplyEnterpriseAction("{\"action\":\"audit_export\",\"format\":\"json\",\"actorUserId\":\"admin\"}");
        Assert.True(export.Ok, export.Detail);
        Assert.Single(Directory.GetFiles(Path.Combine(dir, "exports"), "audit-export-*.json"));
        Assert.Contains("chain OK", export.Detail);
        // Tamper with the persisted chain, restart: restore verdict
        // is BROKEN and the next export says so in its own header.
        // W95 / FR-124 amendment: the tamper + restart happen after
        // the first runtime STOPS (single-instance guard — a second
        // live Core on this dir is refused by design, D-W93-1).
        await runtime.StopAsync(default);
        await runtime.DisposeAsync();
        var chainPath = Path.Combine(dir, "enterprise-audit.json");
        var text = File.ReadAllText(chainPath);
        var mid = text.Length / 2;
        File.WriteAllText(chainPath, text[..mid] + (text[mid] == 'A' ? 'B' : 'A') + text[(mid + 1)..]);
        var runtime2 = NewRuntime(dir, 18814);
        Assert.False(runtime2.Enterprise.RestoreVerdict.Ok);
        var export2 = runtime2.ApplyEnterpriseAction("{\"action\":\"audit_export\",\"format\":\"csv\",\"actorUserId\":\"admin\"}");
        Assert.True(export2.Ok, export2.Detail);
        Assert.Contains("BROKEN", export2.Detail);
        var csvPath = Directory.GetFiles(Path.Combine(dir, "exports"), "audit-export-*.csv").Single();
        Assert.Contains("BROKEN", File.ReadAllText(csvPath));
        await runtime2.StopAsync(default);
        await runtime2.DisposeAsync();
    }

    [Fact]
    public void EnterpriseWiring_DirectorySync_RemovesUserThroughLiveCore_AndReplayCannotResurrect()
    {
        var dir = TestUtil.TempDir();
        var runtime = NewRuntime(dir, 18815);
        Assert.NotNull(runtime.Roster.CreateScope("co1", "company", "Company A"));
        Assert.NotNull(runtime.Roster.CreateUser("admin1", "co1", "Admin One", "human"));
        Assert.True(runtime.Roster.AddCompanyAdmin("co1", "admin1"));
        Assert.NotNull(runtime.Roster.CreateUser("victim", "co1", "Victim User", "human"));
        var payload = "{\"action\":\"sync_event\",\"actorUserId\":\"admin1\",\"event\":{" +
            "\"externalScopeBinding\":\"co1\",\"scopeId\":\"co1\",\"userId\":\"victim\"," +
            "\"displayName\":\"Victim User\",\"action\":\"remove\",\"externalId\":\"ext-v\"}}";
        var applied = runtime.ApplyEnterpriseAction(payload);
        Assert.True(applied.Ok, applied.Detail);
        Assert.Null(runtime.Roster.GetUser("co1", "victim"));
        // Replay of the same event: the user stays gone; nothing resurrects.
        var replay = runtime.ApplyEnterpriseAction(payload);
        Assert.False(replay.Ok);
        Assert.Null(runtime.Roster.GetUser("co1", "victim"));
        // Cross-scope injection: a binding that does not match the scope refuses.
        Assert.NotNull(runtime.Roster.CreateUser("victim2", "co1", "Second", "human"));
        var cross = runtime.ApplyEnterpriseAction("{\"action\":\"sync_event\",\"actorUserId\":\"admin1\",\"event\":{" +
            "\"externalScopeBinding\":\"other-org\",\"scopeId\":\"co1\",\"userId\":\"victim2\"," +
            "\"displayName\":\"Second\",\"action\":\"remove\",\"externalId\":\"ext-x\"}}");
        Assert.False(cross.Ok);
        Assert.NotNull(runtime.Roster.GetUser("co1", "victim2"));
    }

    [Fact]
    public void EnterpriseWiring_BreakGlass_DualControl_LoudInAuditAndAlerts()
    {
        var dir = TestUtil.TempDir();
        string Hash(string s) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(s))).ToLowerInvariant();
        File.WriteAllText(Path.Combine(dir, "breakglass-holders.json"),
            $"[{{\"holderId\":\"h1\",\"secretSha256\":\"{Hash("s1")}\"}},{{\"holderId\":\"h2\",\"secretSha256\":\"{Hash("s2")}\"}}]");
        var runtime = NewRuntime(dir, 18816);
        Assert.NotNull(runtime.Roster.CreateScope("co1", "company", "Company A"));
        // One holder alone — even twice — is not dual control.
        var solo = runtime.ApplyEnterpriseAction("{\"action\":\"break_glass_use\",\"scopeId\":\"co1\"," +
            "\"holder1\":\"h1\",\"secret1\":\"s1\",\"holder2\":\"h1\",\"secret2\":\"s1\",\"reason\":\"test\"}");
        Assert.False(solo.Ok);
        var use = runtime.ApplyEnterpriseAction("{\"action\":\"break_glass_use\",\"scopeId\":\"co1\"," +
            "\"holder1\":\"h1\",\"secret1\":\"s1\",\"holder2\":\"h2\",\"secret2\":\"s2\",\"reason\":\"drill\",\"drill\":true}");
        Assert.True(use.Ok, use.Detail);
        Assert.Contains("BREAK-GLASS GRANTED", use.Detail);
        // Loud: the chained audit AND the alert center both carry it,
        // and the snapshot says rotation is now required.
        Assert.Contains(runtime.Enterprise.AuditLog.Entries, e => e.Kind == "break_glass_use");
        Assert.Contains(runtime.Enterprise.Alerts.Alerts, a => a.EventClass == "break_glass_use");
        Assert.Contains("breakGlassRotationRequired\":true", runtime.BuildHostStateJson());
    }

    [Fact]
    public void EnterpriseWiring_MockIdp_SignInFlow_AndUnverifiedEmailRefused()
    {
        var dir = TestUtil.TempDir();
        var runtime = NewRuntime(dir, 18817);
        var begin = runtime.ApplyEnterpriseAction(
            "{\"action\":\"idp_begin\",\"subject\":\"user-1\",\"email\":\"tech@example.com\",\"emailVerified\":true}");
        Assert.True(begin.Ok, begin.Detail);
        var complete = runtime.ApplyEnterpriseAction("{\"action\":\"idp_complete\"}");
        Assert.True(complete.Ok, complete.Detail);
        Assert.Contains("user-1", complete.Detail);
        // The mock leg enforces the same claim rules as the real one:
        // an unverified email never completes a sign-in.
        var begin2 = runtime.ApplyEnterpriseAction(
            "{\"action\":\"idp_begin\",\"subject\":\"user-2\",\"email\":\"bad@example.com\",\"emailVerified\":false}");
        Assert.True(begin2.Ok, begin2.Detail);
        Assert.False(runtime.ApplyEnterpriseAction("{\"action\":\"idp_complete\"}").Ok);
        Assert.Contains("mock", global::DeskGuest.Core.Services.EnterpriseService.RealIdpBoundary, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void FloorSurfacing_NonHostFloorGrantForgery_RefusedThroughSurface()
    {
        var dir = TestUtil.TempDir();
        var runtime = NewRuntime(dir, 18818);
        var w = Setup();
        // Build the same world inside the live Core's stores.
        Assert.NotNull(runtime.Roster.CreateScope("company-1", "company", "Company A"));
        Assert.NotNull(runtime.Roster.CreateUser("host", "company-1", "Host User", "human"));
        Assert.NotNull(runtime.Roster.CreateUser("ctrl", "company-1", "Controller", "human"));
        Assert.NotNull(runtime.Roster.CreateUser("peer", "company-1", "Peer", "human"));
        Assert.NotNull(runtime.Roster.CreateUserGroup("ug-1", "company-1", "Techs", new[] { "ctrl", "host", "peer" }));
        Assert.NotNull(runtime.Roster.CreateDeviceGroup("dg-1", "company-1", "Fleet", new[] { "lan" }));
        Assert.NotNull(runtime.Roster.AddGrant("company-1", "ug-1", "dg-1", new[] { "use" }));
        var code = runtime.Enrollments.CreateEnrollmentCode("company", "dg-1", "Fleet");
        var device = runtime.Enrollments.Redeem(code,
            new EnrollingDevice(runtime.Identity.DeviceId, runtime.Identity.PublicKeyBase64, "Site PC"));
        Assert.NotNull(device);
        var s = runtime.HumanSessions.CreateSession("company-1", device!.DeviceId, "ctrl", "attended", "lan");
        Assert.NotNull(s);
        Assert.True(runtime.HumanSessions.AcceptSession(s!.Id, "host", SessionAcceptOrigin.EndpointLocal));
        Assert.True(runtime.HumanSessions.StartSession(s.Id));
        // Forgery: a non-host participant grants THEMSELVES the floor
        // through the host-window surface — refused by the model.
        var forged = runtime.ApplySessionAction(
            $"{{\"action\":\"grant_floor\",\"sessionId\":\"{s.Id}\",\"actorUserId\":\"peer\",\"userId\":\"peer\"}}");
        Assert.False(forged.Ok);
        // The host's grant works, and the snapshot carries the roster
        // with transport per participant (D35).
        var granted = runtime.ApplySessionAction(
            $"{{\"action\":\"grant_floor\",\"sessionId\":\"{s.Id}\",\"actorUserId\":\"host\",\"userId\":\"ctrl\"}}");
        Assert.True(granted.Ok, granted.Detail);
        var snapshot = runtime.BuildHostStateJson();
        Assert.Contains("\"transport\":\"lan\"", snapshot);
        Assert.Contains("\"floor\":\"holds\"", snapshot);
        Assert.Contains("\"enterprise\":{", snapshot);
    }
}
