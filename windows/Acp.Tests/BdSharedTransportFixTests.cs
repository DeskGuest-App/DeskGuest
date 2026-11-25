using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Acp.Shared.Enrollment;
using Acp.Shared.Hub;
using Acp.Shared.NetworkDiscovery;
using Acp.Shared.OwnPath;
using Acp.Shared.Tailscale;
using Acp.Shared.Security;
using Acp.Shared.Transport;
using Acp.Shared.Wake;

namespace Acp.Tests;

/// <summary>BD-SHARED-TRANSPORT (packet f324c675) — permanent
/// regressions for the confirmed findings F1–F12. Every test here
/// fails against the pre-fix code for the reason named in its
/// comment.</summary>
public class BdSharedTransportFixTests
{
    private static TransportTests.World W() => TransportTests.Setup();

    // ---- F1: the LAN channel is mutually authenticated + AEAD -------------

    [Fact]
    public async Task F1_RelayedHandshake_CompletesButRelaySeesOnlyCiphertext()
    {
        var w = W();
        using var listener = new LanHostListener(w.Enrollments, w.HostIdentity);
        listener.Start(IPAddress.Loopback, 0);

        // A byte-relay MITM between client and host (raw Socket
        // listener — CONV-F3, as below).
        var relay = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        relay.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        relay.Listen(4);
        var relayPort = ((IPEndPoint)relay.LocalEndPoint!).Port;
        var seen = new List<byte>();
        var relayTask = Task.Run(async () =>
        {
            // Raw sockets on both legs (CONV-F3: this sandbox's
            // egress proxy intercepts TcpClient legs; raw Socket
            // legs reach loopback — the same reason every other
            // socket leg in this suite is a raw Socket).
            using var clientSide = await relay.AcceptAsync();
            using var hostSide = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            await hostSide.ConnectAsync(IPAddress.Loopback, listener.Port);
            var cs = new NetworkStream(clientSide, ownsSocket: false);
            var hs = new NetworkStream(hostSide, ownsSocket: false);
            async Task Pump(Stream from, Stream to)
            {
                var buf = new byte[4096];
                int n;
                while ((n = await from.ReadAsync(buf, 0, buf.Length)) > 0)
                {
                    lock (seen) seen.AddRange(buf.Take(n));
                    await to.WriteAsync(buf, 0, n);
                    await to.FlushAsync();
                }
            }
            await Task.WhenAny(Pump(cs, hs), Pump(hs, cs));
        });

        using var stream = await RawSocketTestLeg.ConnectLoopbackAsync(relayPort);
        var hsResult = await LanProtocol.ClientHandshakeDetailedAsync(
            stream, w.OperatorIdentity, w.Enrollments, w.DeviceId, default);
        // The relay CAN forward the handshake (it is a transport),
        // but the channel keys are DH-derived between the two
        // endpoints — the relay never holds them.
        Assert.Equal(LanProtocol.ClientHandshakeOutcome.Connected, hsResult.Outcome);
        using var channel = hsResult.Channel!;
        await LanProtocol.WriteLineAsync(channel, "PING", default);
        Assert.Equal("PONG", await LanProtocol.ReadLineAsync(channel, default));
        await Task.Delay(100);
        lock (seen)
        {
            var text = Encoding.ASCII.GetString(seen.ToArray());
            Assert.DoesNotContain("PING", text);
            Assert.DoesNotContain("PONG", text);
        }
        relay.Dispose();
    }

    [Fact]
    public async Task F1_SpoofedHost_RefusedBeforeClientSignsAnything()
    {
        var w = W();
        var attacker = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var fake = new TcpListener(IPAddress.Loopback, 0);
        fake.Start();
        var port = ((IPEndPoint)fake.LocalEndpoint).Port;
        var hostTask = Task.Run(async () =>
        {
            using var side = await fake.AcceptTcpClientAsync();
            var s = side.GetStream();
            var nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
            var eph = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
            // Claims the REAL host's DeviceId; signs with the
            // ATTACKER's key — the enrolled host key will not match.
            var sig = attacker.Sign(LanProtocol.HostProofMessage(w.DeviceId, nonce, eph));
            await LanProtocol.WriteLineAsync(s,
                $"CHAL2 {nonce} {w.DeviceId} {eph} {Convert.ToBase64String(sig)}", default);
            await Task.Delay(400);
            return side.Available;
        });
        using var stream = await RawSocketTestLeg.ConnectLoopbackAsync(port);
        var result = await LanProtocol.ClientHandshakeDetailedAsync(
            stream, w.OperatorIdentity, w.Enrollments, w.DeviceId, default);
        Assert.Equal(LanProtocol.ClientHandshakeOutcome.HostAuthenticationFailed, result.Outcome);
        Assert.Null(result.Channel);
        // The client sent NOTHING for the spoofed host to relay.
        Assert.Equal(0, await hostTask);
        fake.Stop();
    }

    [Fact]
    public async Task F1_AeadChannel_TamperedFrameKillsTheChannel()
    {
        var w = W();
        var server = new TcpListener(IPAddress.Loopback, 0);
        server.Start();
        var port = ((IPEndPoint)server.LocalEndpoint).Port;
        var hostTask = Task.Run(async () =>
        {
            using var side = await server.AcceptTcpClientAsync();
            var s = side.GetStream();
            var (deviceId, channel) = await LanProtocol.HostHandshakeAsync(s, w.Enrollments, w.HostIdentity, default);
            Assert.Equal(w.OperatorIdentity.DeviceId, deviceId);
            var line = await LanProtocol.ReadLineAsync(channel!, default);
            Assert.Equal("hello", line);
            // The next frame is tampered garbage: the channel must
            // fail, never deliver it.
            await Assert.ThrowsAnyAsync<Exception>(async () =>
                await LanProtocol.ReadLineAsync(channel!, default));
            return true;
        });
        using var stream = await RawSocketTestLeg.ConnectLoopbackAsync(port);
        var hs = await LanProtocol.ClientHandshakeDetailedAsync(
            stream, w.OperatorIdentity, w.Enrollments, w.DeviceId, default);
        Assert.Equal(LanProtocol.ClientHandshakeOutcome.Connected, hs.Outcome);
        using var channel = hs.Channel!;
        await LanProtocol.WriteLineAsync(channel, "hello", default);
        // Tamper: write raw junk straight onto the wire, bypassing
        // the channel's framing/encryption.
        var junk = RandomNumberGenerator.GetBytes(64);
        await stream.WriteAsync(junk, 0, junk.Length, default);
        await stream.FlushAsync(default);
        Assert.True(await hostTask);
        server.Stop();
    }

    [Fact]
    public async Task F1_RungWithoutEnrollments_FailsClosed()
    {
        var w = W();
        var rung = new LanRung(); // no enrollments wired
        var result = await rung.ConnectSessionAsync(
            new TransportTarget(w.DeviceId, "127.0.0.1:9"), w.OperatorIdentity);
        Assert.False(result.Ok);
        Assert.Contains("enrollment", result.Detail, StringComparison.OrdinalIgnoreCase);
    }

    // ---- F10: address handling ---------------------------------------------

    [Theory]
    [InlineData("[2001:db8::5]:47621", "2001:db8::5", 47621)]
    [InlineData("2001:db8::5", "2001:db8::5", LanProtocol.DefaultPort)]
    [InlineData("host.example:1234", "host.example", 1234)]
    [InlineData("127.0.0.1", "127.0.0.1", LanProtocol.DefaultPort)]
    public void F10_ParseAddress_Ipv6Forms(string input, string host, int port)
    {
        var (h, p) = LanRung.ParseAddress(input);
        Assert.Equal(host, h);
        Assert.Equal(port, p);
    }

    [Fact]
    public async Task F10_TorRung_NonLoopbackSocksHost_Refused()
    {
        var w = W();
        var rung = new TorRung(() => new TorConfig("192.168.1.5", 9050), w.Enrollments);
        var result = await rung.ConnectSessionAsync(
            new TransportTarget(w.DeviceId, "203.0.113.7:47621"), w.OperatorIdentity);
        Assert.False(result.Ok);
        Assert.Contains("loopback", result.Detail, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void F10_TailnetAddress_IsNotPeerProof()
    {
        Assert.True(MeshAddress.IsTailnetAddress("100.64.0.9"));
        // Prefix alone never proves a peer — the known-peer check
        // additionally requires membership of the actual peer list.
        Assert.False(MeshAddress.IsKnownTailnetPeer("100.64.0.9", new[] { "100.64.0.10" }));
        Assert.True(MeshAddress.IsKnownTailnetPeer("100.64.0.9", new[] { "100.64.0.9" }));
        Assert.False(MeshAddress.IsKnownTailnetPeer("192.168.1.9", new[] { "192.168.1.9" }));
    }

    [Fact]
    public async Task F9_MeshRung_ReadinessRecheckRefusesOnDrift()
    {
        var w = W();
        var rung = new MeshRung(
            () => new Acp.Shared.Tailscale.MeshSetupState(Acp.Shared.Tailscale.MeshSetupStage.Ready, "ready"),
            enrollments: w.Enrollments, readinessRecheck: () => false);
        var result = await rung.ConnectSessionAsync(
            new TransportTarget(w.DeviceId, "100.64.0.9"), w.OperatorIdentity);
        Assert.False(result.Ok);
        Assert.Contains("readiness", result.Detail, StringComparison.OrdinalIgnoreCase);
    }

    // ---- F2: hub credentials are issued, never invented ---------------------

    private sealed class FakeAuthority : IHeadscaleKeyAuthority
    {
        public string? CreatePreAuthKey(string hubUser, TimeSpan lifetime) => "hskey-auth-issued-0123456789abcdef0123456789";
        public string? CreateApiKey(TimeSpan lifetime) => "hskey-api-issued-0123456789abcdef0123456789";
    }

    [Fact]
    public void F2_NoAuthority_MintingRefuses_NothingIsInvented()
    {
        var vault = new HubApiKeyVault(new DevOnlyPassThroughProtector());
        Assert.Throws<InvalidOperationException>(() =>
            vault.Mint(TimeSpan.FromDays(30), DateTimeOffset.UtcNow));
        var reg = new HubNodeRegistry(new ClientVersionGate());
        var join = new HubJoinService(new DevOnlyPassThroughProtector(), reg);
        Assert.Throws<InvalidOperationException>(() =>
            join.MintJoinTicket("dev-1", "g", "https://hub.example.test:8085", DateTimeOffset.UtcNow));
    }

    [Fact]
    public void F2_AuthorityIssuedKeys_AreWhatGetsVaultedAndConsumed()
    {
        var vault = new HubApiKeyVault(new DevOnlyPassThroughProtector(), new FakeAuthority());
        var minted = vault.Mint(TimeSpan.FromDays(30), DateTimeOffset.UtcNow);
        Assert.Equal("hskey-api-issued-0123456789abcdef0123456789", minted.PlaintextOnce);

        var reg = new HubNodeRegistry(new ClientVersionGate());
        var join = new HubJoinService(new DevOnlyPassThroughProtector(), reg, new FakeAuthority());
        var now = DateTimeOffset.UtcNow;
        var ticket = join.MintJoinTicket("dev-1", "g", "https://hub.example.test:8085", now);
        Assert.Contains("hskey-auth-issued-", ticket.CommandLine);
        var key = ticket.CommandLine.Split("--authkey ")[1].Split(' ')[0];
        Assert.NotNull(join.ConsumeJoin(key, "dev-1", "1.104.7", now));
    }

    [Fact]
    public void F2_HeadscaleCli_ArgShapesAndParsers()
    {
        var args = HeadscaleCli.PreAuthKeyCreateArgs("acp", TimeSpan.FromHours(1));
        Assert.Contains("preauthkeys", args);
        Assert.Contains("--reusable=false", args);
        Assert.Equal("hskey-auth-x", HeadscaleCli.ParseCreatedKey("{\"key\":\"hskey-auth-x\"}", "key"));
        Assert.Null(HeadscaleCli.ParseCreatedKey("not json", "key"));
        var map = HeadscaleCli.ParseNodeIds(
            "[{\"id\":\"7\",\"name\":\"dev-1\"},{\"id\":\"8\",\"name\":\"other\"}]",
            new HashSet<string> { "dev-1" });
        Assert.Equal("7", map["dev-1"]);
        Assert.False(map.ContainsKey("other"));
    }

    [Fact]
    public void F2F12_DecommissionNeedsRealNodeId_AndReenrollReopensJoin()
    {
        var reg = new HubNodeRegistry(new ClientVersionGate());
        var now = DateTimeOffset.UtcNow;
        Assert.NotNull(reg.Join("dev-1", "1.104.7", now));
        // The ACP id is not a Headscale id — decommission refuses
        // until the real numeric id is recorded.
        Assert.Throws<InvalidOperationException>(() => reg.Decommission("dev-1", now));
        reg.RecordHeadscaleNodeId("dev-1", "42");
        var cmd = reg.Decommission("dev-1", now);
        Assert.Contains("--identifier 42", cmd);
        // Deleted is no longer a life sentence: re-enrolment goes
        // through the same floor gate and reopens the node.
        Assert.Null(reg.Join("dev-1", "1.104.7", now));
        Assert.NotNull(reg.Reenroll("dev-1", "1.104.7", now));
        Assert.False(reg.Get("dev-1")!.Deleted);
    }

    // ---- F3: hub self-check actually reads policy + config ------------------

    [Theory]
    [InlineData("{\"acls\":[{\"src\":[\"*\"],\"dst\":[\"*:*\"]}]}", true)]
    [InlineData("{\"acls\":[{\"dst\":[\"*:*\"],\"src\":[\"*\"]}]}", true)] // key order swapped
    [InlineData("{\"grants\":[{\"src\":[\"autogroup:member\"],\"dst\":[\"*:*\"]}]}", true)]
    [InlineData("{\"acls\":[{\"src\":[\"group:admins\"],\"dst\":[\"tag:db:5432\"]}]}", false)]
    [InlineData("{\"acls\":[]}", false)]
    public void F3_PolicyCompile_KeyOrderAndAutogroup(string policy, bool allowAll) =>
        Assert.Equal(allowAll, HubPolicy.Compile(policy).IsAllowAll);

    [Fact]
    public void F3_ConfigValidate_PolicyBindingAndSocketPermission()
    {
        var home = Path.Combine(Path.GetTempPath(), "acp-f3-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(home);
        var opts = new HubOptions
        {
            ComponentHome = home, ServerUrl = "https://hub.example.test:8085",
            TlsCertPath = "/acp/hub/tls.crt", TlsKeyPath = "/acp/hub/tls.key",
        };
        var good = HubConfig.Generate(opts);
        Assert.Empty(HubConfig.Validate(good, opts));
        // Policy section removed → the binding violation is named.
        var noPolicy = string.Join("\n", good.Split('\n').Where(l => !l.StartsWith("policy:") && !l.Contains("mode: file") && !l.Contains("path:")));
        Assert.Contains(HubConfig.Validate(noPolicy, opts), v => v.Detail.Contains("policy"));
        // Socket permission removed → named.
        var noPerm = good.Replace("unix_socket_permission: \"0770\"", "");
        Assert.Contains(HubConfig.Validate(noPerm, opts), v => v.Detail.Contains("unix_socket_permission"));
    }

    // ---- F11: hub lifecycle --------------------------------------------------

    private sealed class FakeHubProcess : IHubProcess
    {
        public bool Healthy;
        public bool IsRunning { get; private set; }
        public void Start(string binaryPath, string configPath, string workingDir) => IsRunning = true;
        public void Stop() => IsRunning = false;
        public bool HealthOk(string healthUrl) => Healthy && IsRunning;
    }

    private static (string Home, HubOptions Opts) LifecycleHome(string? pin = null)
    {
        var home = Path.Combine(Path.GetTempPath(), "acp-f11-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(home);
        var opts = new HubOptions
        {
            ComponentHome = home,
            ServerUrl = "https://hub.example.test:8085",
            TlsCertPath = "/acp/hub/tls.crt", TlsKeyPath = "/acp/hub/tls.key",
            BinarySha256 = pin,
        };
        File.WriteAllText(opts.BinaryPath, "hub-binary-v1");
        return (home, opts);
    }

    [Fact]
    public void F11_Start_RequiresHealth_BeforeClaimingRunning()
    {
        var (_, opts) = LifecycleHome();
        var proc = new FakeHubProcess { Healthy = false };
        var life = new HubLifecycle(opts, proc, hubRungSelected: true);
        life.Install();
        Assert.Throws<InvalidOperationException>(() => life.Start());
        Assert.Equal(HubState.Refused, life.State);
        Assert.False(proc.IsRunning); // stopped again, not left running dead
        proc.Healthy = true;
        life.Start();
        Assert.Equal(HubState.Running, life.State);
    }

    [Fact]
    public void F11_BinaryPin_EnforcedAtInstall()
    {
        var goodPin = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("hub-binary-v1"))).ToLowerInvariant();
        var (_, optsGood) = LifecycleHome(goodPin);
        new HubLifecycle(optsGood, new FakeHubProcess(), hubRungSelected: true).Install();
        var (_, optsBad) = LifecycleHome(new string('0', 64));
        var life = new HubLifecycle(optsBad, new FakeHubProcess(), hubRungSelected: true);
        Assert.Throws<InvalidOperationException>(() => life.Install());
    }

    [Fact]
    public void F11_Update_PerformsTheSwap_AndRefusesBadCandidate()
    {
        var pin = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("hub-binary-v2"))).ToLowerInvariant();
        var (_, opts) = LifecycleHome(pin);
        var life = new HubLifecycle(opts, new FakeHubProcess(), hubRungSelected: true);
        var candidate = Path.Combine(Path.GetTempPath(), "acp-cand-" + Guid.NewGuid().ToString("N"));
        File.WriteAllText(candidate, "hub-binary-v2");
        var result = life.Update(HubPins.HeadscaleVersion, null, candidate);
        Assert.Contains("replaced", result);
        Assert.Equal("hub-binary-v2", File.ReadAllText(opts.BinaryPath));
        Assert.Equal("hub-binary-v1", File.ReadAllText(opts.BinaryPath + ".prev"));
        // A candidate that does not match the pin never lands.
        File.WriteAllText(candidate, "evil-binary");
        Assert.Throws<InvalidOperationException>(() =>
            life.Update(HubPins.HeadscaleVersion, null, candidate));
        Assert.Equal("hub-binary-v2", File.ReadAllText(opts.BinaryPath));
        // Gate-only call says plainly that nothing was swapped.
        Assert.Contains("nothing was swapped", life.Update(HubPins.HeadscaleVersion, null));
    }

    // ---- F12: bounded growth ---------------------------------------------------

    [Fact]
    public void F12_GateRefusalsAndRegistryEvents_AreCapped()
    {
        var gate = new ClientVersionGate();
        var now = DateTimeOffset.UtcNow;
        for (var i = 0; i < 700; i++) gate.Admit("0.0.1", now);
        Assert.True(gate.Refusals.Count <= 512, $"refusals grew to {gate.Refusals.Count}");

        var reg = new HubNodeRegistry(new ClientVersionGate());
        for (var i = 0; i < 700; i++) reg.Join($"dev-{i}", "1.104.7", now);
        Assert.True(reg.Events.Count <= 512, $"registry events grew to {reg.Events.Count}");
    }

    private sealed class NullWakeSender : IWakeSender
    {
        public void Send(byte[] packet, string broadcastAddress, int port) { }
    }

    [Fact]
    public void F12_WakeImport_TwiceDoesNotDoubleHistory()
    {
        var w = W();
        var wake = new WakeService(w.Roster, w.Enrollments, new NullWakeSender());
        Assert.True(wake.RegisterTarget(w.DeviceId, "AA:BB:CC:DD:EE:FF", "192.168.1.255", "admin"));
        var export = wake.ExportJson();
        var before = wake.Events.Count;
        wake.ImportJson(export);
        wake.ImportJson(export);
        Assert.Equal(before, wake.Events.Count);
    }

    // ---- F4/F5: own-path ------------------------------------------------------

    [Theory]
    [InlineData("PostUp = iptables -A FORWARD -j ACCEPT")]
    [InlineData("postup = iptables -A FORWARD -j ACCEPT")] // wg-quick lowercases keys
    [InlineData("DNS = 1.1.1.1")]
    [InlineData("[Peer]\nAllowedIPs = 0.0.0.0/0")]
    [InlineData("[Peer]\nAllowedIPs = 10.0.0.0/24")]
    public void F4_ValidateConfigText_Refuses(string text) =>
        Assert.False(WireGuardConfigGenerator.ValidateConfigText(text).Ok);

    [Fact]
    public void F4_ValidateConfigText_AcceptsSingleHostAllowedIPs() =>
        Assert.True(WireGuardConfigGenerator.ValidateConfigText("[Peer]\nAllowedIPs = 10.9.0.2/32").Ok);

    [Fact]
    public void F4_PeerConfig_InjectedDeviceId_Refused()
    {
        var (_, pub) = WireGuardConfigGenerator.GenerateKeyPair();
        var peer = new OwnPathPeer("dev\n[Interface]\nAllowedIPs = 0.0.0.0/0", "Site PC", pub, "10.9.0.2", "127.0.0.1:51820");
        Assert.Throws<InvalidOperationException>(() => WireGuardConfigGenerator.GeneratePeerConfig(peer));
    }

    [Fact]
    public void F4_AuthorizedKeyLine_IsRestrictWithoutForwarding()
    {
        var identity = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var line = SshChannelConfigGenerator.GenerateAuthorizedKeyLine(
            $"ssh-ed25519 {identity.PublicKeyBase64}", "Site PC");
        Assert.StartsWith("restrict ", line);
        Assert.DoesNotContain("port-forwarding", line);
    }

    [Fact]
    public void F5_TunnelConfig_HasInterfaceAndPeer()
    {
        var (priv, pub) = WireGuardConfigGenerator.GenerateKeyPair();
        var peer = new OwnPathPeer("dev-1", "Site PC", pub, "10.9.0.2", "127.0.0.1:51820");
        var config = WireGuardConfigGenerator.GenerateTunnelConfig(priv, "10.9.0.1", 51820, peer);
        Assert.Contains("[Interface]", config);
        Assert.Contains("PrivateKey =", config);
        Assert.Contains("ListenPort = 51820", config);
        Assert.Contains("[Peer]", config);
        Assert.Equal("WireGuardTunnel$site", WireGuardTunnelLifecycle.ServiceNameFor("site.conf"));
    }

    // ---- F6/F7: collectors + probe ----------------------------------------------

    [Fact]
    public void F6_FlowCollector_ParsesRealNetFlowV5Layout()
    {
        // One v5 record: src 10.0.0.1 dst 10.0.0.2, packets at 16,
        // octets at 20, ports at 32/34, protocol at 38.
        var data = new byte[24 + 48];
        data[0] = 0; data[1] = 5;   // version 5
        data[2] = 0; data[3] = 1;   // count 1
        var r = data.AsSpan(24);
        new IPAddress(new byte[] { 10, 0, 0, 1 }).GetAddressBytes().CopyTo(r);
        new IPAddress(new byte[] { 10, 0, 0, 2 }).GetAddressBytes().CopyTo(r.Slice(4));
        r[19] = 7;                  // packets = 7 (bytes 16..19)
        r[23] = 42;                 // octets = 42 (bytes 20..23)
        r[33] = 80;                 // srcPort = 80 (bytes 32..33)
        r[34] = 0x01; r[35] = 0xBB; // dstPort = 443 (bytes 34..35)
        r[38] = 6;                  // protocol TCP
        var flows = FlowCollector.ParseDatagram(data);
        var f = Assert.Single(flows);
        Assert.Equal("10.0.0.1", f.SrcAddr);
        Assert.Equal("10.0.0.2", f.DstAddr);
        Assert.Equal(7, f.Packets);
        Assert.Equal(42, f.Octets);
        Assert.Equal(80, f.SrcPort);
        Assert.Equal(443, f.DstPort);
        Assert.Equal(6, f.Protocol);
        // A lying count is refused whole, not clamped.
        data[3] = 2;
        Assert.Empty(FlowCollector.ParseDatagram(data));
    }

    [Fact]
    public void F6_SyslogCollector_HostComesFromTheShapeNotAnOffset()
    {
        var withHost = SyslogCollector.Parse(
            Encoding.UTF8.GetBytes("<13>Oct 11 22:14:15 myhost myapp: hello world"),
            IPAddress.Parse("10.0.0.9"));
        Assert.Equal("myhost", withHost.Hostname);
        Assert.Equal(13 % 8, withHost.Severity);
        // Host-less short datagram: no garbage attribution.
        var bare = SyslogCollector.Parse(
            Encoding.UTF8.GetBytes("<13>hi"), IPAddress.Parse("10.0.0.9"));
        Assert.Null(bare.Hostname);
    }

    [Fact]
    public void F7_ArpParsers_ReadRealCacheShapes()
    {
        var proc = "IP address       HW type     Flags       HW address            Mask     Device\n" +
                   "192.168.1.5      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0\n";
        Assert.Equal("aa:bb:cc:dd:ee:ff", ArpNeighbourCache.ParseProcNetArp(proc, "192.168.1.5"));
        Assert.Null(ArpNeighbourCache.ParseProcNetArp(proc, "192.168.1.6"));
        var arpA = "Interface: 192.168.1.1 --- 0x2\n  192.168.1.5   aa-bb-cc-dd-ee-ff   dynamic\n";
        Assert.Equal("aa:bb:cc:dd:ee:ff", ArpNeighbourCache.ParseArpA(arpA, "192.168.1.5"));
    }

    [Fact]
    public void F7_ProbeObservation_RtspAndOnvifAreSeparateClaims()
    {
        var obs = new Acp.Shared.NetworkDiscovery.ProbeObservation(
            "10.0.0.5", null, null, new[] { 554 }, null, null, null,
            OnvifCapable: false, DateTimeOffset.UtcNow, RtspCapable: true);
        Assert.True(obs.RtspCapable);
        Assert.False(obs.OnvifCapable);
    }
}

public sealed class BdSharedTransportReconcileTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void F2_Reconcile_UnknownNodeId_PendsInsteadOfFabricating()
    {
        var registry = new HubNodeRegistry(new ClientVersionGate());
        registry.Join("dev-stay", "1.104.7", T0);
        registry.Join("dev-gone", "1.104.7", T0);

        var commands = registry.ReconcileDeletions(new HashSet<string> { "dev-stay" }, T0);

        // No command is fabricated against an invented id; the
        // local decommission still lands and the hub delete pends.
        Assert.Empty(commands);
        Assert.True(registry.Get("dev-gone")!.Deleted);
        Assert.False(registry.Get("dev-stay")!.Deleted);
        Assert.Equal(new[] { "dev-gone" }, registry.PendingHubDeletions());

        // When the id sync learns the id, the owed delete command
        // is produced for the caller to execute.
        var owed = registry.RecordHeadscaleNodeId("dev-gone", "9");
        Assert.Equal("headscale nodes delete --identifier 9", owed);
        Assert.Empty(registry.PendingHubDeletions());
    }
}
