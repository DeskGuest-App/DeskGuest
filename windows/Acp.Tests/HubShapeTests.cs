using System.Net;
using System.Text.Json;
using Acp.Core;
using Acp.Core.Services;
using Acp.Shared.Enterprise;
using Acp.Shared.Enrollment;
using Acp.Shared.HealthScoring;
using Acp.Shared.Hub;
using Acp.Shared.Security;
using Acp.Shared.Transport;

namespace Acp.Tests;

/// <summary>C15 — hub-SHAPE deployment proof (union verify log, C15).
/// The prior hub proof (proofs/hub-rung-v2, 2026-11-20) proved the hub
/// RUNG in laptop shape: every node co-located with the laptop. This
/// class proves the deployment SHAPE at the strongest level this
/// sandbox allows: THREE separate CoreRuntime instances with separate
/// data dirs — one Core in the hub ROLE (its own HubLifecycle standing
/// up the packaged-hub process stand-in, its own HubNodeRegistry /
/// HubJoinService / HubApiKeyVault / HubSigningKeyProvisioning) and
/// two peer Cores that enroll THROUGH that hub and route sessions
/// whose only rung is the hub.
///
/// Named environmental limits (never papered over):
///  * The hub binary here is a stand-in executable placed where the
///    packaging step places the pinned Headscale binary; HubLifecycle
///    runs it through the REAL HubProcess (a real child process,
///    really killed on Stop). The real Headscale binary's own mesh
///    data plane (Tailscale clients, DERP relay across a network
///    boundary, an Android endpoint) cannot run in this sandbox —
///    that leg stays a remainder (see log-c15-build.md).
///  * The session channel leg uses the CONV-F3 raw-Socket transport:
///    HubRung's own TcpClient is steered into this sandbox's egress
///    proxy (established fact, log-conv-f3.md). The rung's membership
///    + address gates are asserted at their PRODUCTION shape against
///    the hub Core's real registry; the channel after the gates is
///    the SAME LanProtocol proof-of-possession handshake + PING/PONG
///    the rung runs, over a raw Socket, against the peer Core's REAL
///    HubListener (its hub host listener, loopback-bound here).
///  * LAN rung is never used: peers enroll and route hub-only.</summary>
public class HubShapeTests
{
    private const string HubUrl = "https://127.0.0.1:8085";

    private sealed class Shape : IAsyncDisposable
    {
        public required CoreRuntime Hub { get; init; }
        public required CoreRuntime PeerA { get; init; }
        public required CoreRuntime PeerB { get; init; }
        public required string HubDir { get; init; }

        public async ValueTask DisposeAsync()
        {
            foreach (var rt in new[] { PeerA, PeerB, Hub })
            {
                try { await rt.DisposeAsync(); } catch { /* teardown only */ }
            }
        }
    }

    private static CoreRuntime Runtime(string dataDir, bool hubRole) => new(new CoreOptions
    {
        DataDir = dataDir,
        HubRungSelected = hubRole,
        HubServerUrl = HubUrl,
        Protector = new DevOnlyPassThroughProtector(),
        FactChecks = new FakeFactChecks(),
    });

    /// <summary>Place the hub-process stand-in where packaging places
    /// the pinned binary (HubLifecycle.Install verifies it exists and
    /// HubProcess really executes it).</summary>
    private static void PlaceHubBinary(string hubDataDir)
    {
        var home = Path.Combine(hubDataDir, "hub");
        Directory.CreateDirectory(home);
        var bin = Path.Combine(home, OperatingSystem.IsWindows() ? "headscale.exe" : "headscale");
        // BD-SHARED-TRANSPORT F2/F11 test repair: the stand-in is
        // now a REAL minimal hub double, because the product
        // stopped taking the stand-in's word for anything:
        //  * HubLifecycle.Start requires a live /health answer
        //    before it will say Running (F11) — a `sleep` process
        //    is not a hub and no longer passes.
        //  * Hub keys are issued by the binary itself through the
        //    production CLI authority (F2): `preauthkeys create`
        //    and `apikeys create` must answer with issued keys,
        //    unique per call (single-use PAK prefixes collide
        //    otherwise).
        // The double is python3 (the previous sh stand-in already
        // limited this class to sh-capable hosts); `serve` runs an
        // HTTPS /health endpoint on the config's server_url port
        // with a self-signed cert (HubProcess.HealthOk accepts any
        // cert for the loopback host it probes, by design).
        // TrimStart: the raw-string literal opens with a newline;
        // the shebang must be at byte 0 or the kernel will not
        // exec the script as python3 (it falls back to sh).
        File.WriteAllText(bin, StandinScript.TrimStart());
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(bin, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    }

    private const string StandinScript = """
        #!/usr/bin/env python3
        import json, re, secrets, ssl, subprocess, sys
        from http.server import BaseHTTPRequestHandler, HTTPServer

        args = sys.argv[1:]
        def config_path():
            if "--config" in args:
                return args[args.index("--config") + 1]
            return "config.yaml"

        if "preauthkeys" in args:
            print(json.dumps({"key": "hskey-auth-standin-" + secrets.token_hex(24)}))
        elif "apikeys" in args:
            print(json.dumps({"apiKey": "hskey-api-standin-" + secrets.token_hex(24)}))
        elif "nodes" in args:
            print("[]")
        elif "serve" in args:
            port = 8085
            try:
                cfg = open(config_path()).read()
                m = re.search(r"server_url:\s*https?://[^:/\s]+:(\d+)", cfg)
                if m: port = int(m.group(1))
            except Exception:
                pass
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
                            "-keyout", "standin-key.pem", "-out", "standin-cert.pem",
                            "-days", "1", "-nodes", "-subj", "/CN=localhost"],
                           check=True, capture_output=True)
            class H(BaseHTTPRequestHandler):
                def do_GET(self):
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"status":"pass"}')
                def log_message(self, *a):
                    pass
            srv = HTTPServer(("127.0.0.1", port), H)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain("standin-cert.pem", "standin-key.pem")
            srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
            srv.serve_forever()
        else:
            print("[]")
        """;

    private static string KeyFromTicket(HubJoinTicket ticket) =>
        ticket.CommandLine.Split("--authkey ")[1].Split(' ')[0];

    /// <summary>Build the shape: hub Core stood up (install + start
    /// through its real IPC hub-action handler), both peer Cores
    /// enrolled through the hub's join service (single-use PAK →
    /// registry), and each peer ACP-enrolled with the other peer's
    /// Core (the admission layer — mesh membership alone admits
    /// nobody, so the operator identity must ALSO be enrolled at the
    /// host peer).</summary>
    private static async Task<Shape> BuildShapeAsync()
    {
        var hubDir = TestUtil.TempDir();
        PlaceHubBinary(hubDir);
        var hub = Runtime(hubDir, hubRole: true);
        var peerA = Runtime(TestUtil.TempDir(), hubRole: false);
        var peerB = Runtime(TestUtil.TempDir(), hubRole: false);
        var shape = new Shape { Hub = hub, PeerA = peerA, PeerB = peerB, HubDir = hubDir };

        var (installOk, installDetail) = hub.ApplyHubAction("""{"action":"install"}""");
        Assert.True(installOk, installDetail);
        var (startOk, startDetail) = hub.ApplyHubAction("""{"action":"start"}""");
        Assert.True(startOk, startDetail);
        Assert.Equal(HubState.Running, hub.Hub.State);

        // Both peers enroll THROUGH the hub (D28 join flow).
        var now = DateTimeOffset.UtcNow;
        foreach (var peer in new[] { peerA, peerB })
        {
            var ticket = hub.HubJoins.MintJoinTicket(peer.Identity.DeviceId, "fleet", HubUrl, now);
            var node = hub.HubJoins.ConsumeJoin(KeyFromTicket(ticket), peer.Identity.DeviceId, "1.104.7", now);
            Assert.NotNull(node);
            // Single-use: replaying the same PAK is refused.
            Assert.Null(hub.HubJoins.ConsumeJoin(KeyFromTicket(ticket), peer.Identity.DeviceId, "1.104.7", now));
        }

        // ACP admission layer: each peer enrolls the OTHER peer's
        // identity (the operator in each direction).
        EnrollInto(peerB, peerA.Identity);
        EnrollInto(peerA, peerB.Identity);
        return shape;
    }

    private static void EnrollInto(CoreRuntime host, DeviceIdentity guest)
    {
        var code = host.Enrollments.CreateEnrollmentCode("company", "fleet", "Fleet");
        var rec = host.Enrollments.Redeem(code,
            new EnrollingDevice(guest.DeviceId, guest.PublicKeyBase64, "peer"));
        Assert.NotNull(rec);
    }

    /// <summary>One routed session channel through the hub shape:
    /// production HubRung gates (membership from the HUB Core's
    /// registry + production tailnet address gate), then the
    /// CONV-F3 raw-Socket channel: LanProtocol handshake + PING/PONG
    /// against the host peer's real HubListener.</summary>
    private static async Task RouteThroughHubAsync(
        Shape s, CoreRuntime from, CoreRuntime hostPeer)
    {
        // Gate 1+2 at production shape: the target IS a live hub node
        // (no "not a live hub node" refusal) and a LAN address is
        // refused by the address gate — the hub rung never falls back.
        var rung = new HubRung(s.Hub.HubNodes);
        var lanRefusal = await rung.ConnectSessionAsync(
            new TransportTarget(hostPeer.Identity.DeviceId, "192.168.1.20"), from.Identity);
        Assert.False(lanRefusal.Ok);
        Assert.Contains("not a tailnet", lanRefusal.Detail);

        // The channel itself (CONV-F3 leg, see class header).
        hostPeer.HubListener.Start(IPAddress.Loopback, 0);
        using var stream = await RawSocketTestLeg.ConnectLoopbackAsync(hostPeer.HubListener.Port);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        // BD-SHARED-TRANSPORT F1: the client verifies the host
        // peer's enrolled key + expected DeviceId before signing,
        // and PING/PONG ride the AEAD channel.
        var hs = await LanProtocol.ClientHandshakeDetailedAsync(stream, from.Identity, from.Enrollments, hostPeer.Identity.DeviceId, cts.Token);
        Assert.Equal(LanProtocol.ClientHandshakeOutcome.Connected, hs.Outcome);
        using var channel = hs.Channel!;
        await LanProtocol.WriteLineAsync(channel, "PING", cts.Token);
        Assert.Equal("PONG", await LanProtocol.ReadLineAsync(channel, cts.Token));
        await RawSocketTestLeg.WaitUntilAsync(() => hostPeer.HubListener.AcceptedSessions >= 1);
        Assert.True(hostPeer.HubListener.AcceptedSessions >= 1);
        hostPeer.HubListener.Stop();
    }

    // ---- the shape: enroll + route both ways, hub-only -------------

    [Fact]
    public async Task HubShape_TwoPeersEnrollThroughHub_AndRouteSessionsBothWays()
    {
        await using var s = await BuildShapeAsync();

        // Enrollment state lives on the HUB Core, not the peers.
        Assert.NotNull(s.Hub.HubNodes.Get(s.PeerA.Identity.DeviceId));
        Assert.NotNull(s.Hub.HubNodes.Get(s.PeerB.Identity.DeviceId));
        Assert.False(s.Hub.HubNodes.Get(s.PeerA.Identity.DeviceId)!.Deleted);
        Assert.False(s.Hub.HubNodes.Get(s.PeerB.Identity.DeviceId)!.Deleted);
        // The peers' own registries hold nobody: they are endpoints,
        // not hubs — membership is the hub's state.
        Assert.Null(s.PeerA.HubNodes.Get(s.PeerB.Identity.DeviceId));
        Assert.Null(s.PeerB.HubNodes.Get(s.PeerA.Identity.DeviceId));

        // One session each way, hub rung only.
        await RouteThroughHubAsync(s, s.PeerA, s.PeerB);
        await RouteThroughHubAsync(s, s.PeerB, s.PeerA);
    }

    // ---- persistence + signing across a hub restart ----------------

    [Fact]
    public async Task HubShape_PersistenceAndSigning_SurviveHubCoreRestart()
    {
        var hubDir = TestUtil.TempDir();
        PlaceHubBinary(hubDir);
        byte[] keyBefore;
        string apiId, apiPlaintext;
        await using (var hub1 = Runtime(hubDir, hubRole: true))
        {
            Assert.True(hub1.HubSigningKeys.IsProvisioned);
            keyBefore = hub1.HubSigningKeys.CurrentKey!.ToArray();
            var minted = hub1.HubApiKeys.Mint(TimeSpan.FromDays(30), DateTimeOffset.UtcNow);
            apiId = minted.Record.Id;
            apiPlaintext = minted.PlaintextOnce;
            // The production write-through (CoreRuntime Changed →
            // hub-apikeys.json) must have persisted the vault with NO
            // plaintext key in the file (HS-02).
            var keysFile = Path.Combine(hubDir, "hub-apikeys.json");
            Assert.True(File.Exists(keysFile));
            Assert.DoesNotContain(apiPlaintext, File.ReadAllText(keysFile));
        } // hub1 disposed here (await using) before hub2 opens the same data dir

        await using var hub2 = Runtime(hubDir, hubRole: true);
        // Signing: the restarted hub LOADS the same sealed key — it
        // does not mint a new one (snapshots signed before the
        // restart must still verify after it).
        Assert.True(hub2.HubSigningKeys.IsProvisioned);
        Assert.Equal(keyBefore, hub2.HubSigningKeys.CurrentKey!);
        // Vault: the API key minted before the restart is still
        // usable and reveals identically.
        Assert.True(hub2.HubApiKeys.IsUsable(apiId, DateTimeOffset.UtcNow));
        Assert.Equal(apiPlaintext, hub2.HubApiKeys.RevealForUse(apiId, DateTimeOffset.UtcNow));

        // FL-28a signing with the hub's provisioned key: a snapshot
        // signed under it verifies at a peer store keyed with the
        // same hub key, and ONLY under that key.
        var hubKey = hub2.HubSigningKeys.CurrentKey!;
        var exporter = new HealthScoreStore(hubKey);
        Assert.True(exporter.Add(Rmm28Kit.Score(Rmm28Kit.AllGood())).Ok);
        var signedJson = exporter.Export(exporter.Latest(Rmm28Kit.Dev)!);
        var receiver = new HealthScoreStore(hubKey);
        var (ok, _, imported) = receiver.Import(signedJson, Rmm28Kit.T0);
        Assert.True(ok);
        Assert.True(HealthScoreSigning.Verify(imported!, hubKey));
        var wrongKey = new HealthScoreStore(new byte[32]);
        var (okWrong, reasonWrong, _) = wrongKey.Import(signedJson, Rmm28Kit.T0);
        Assert.False(okWrong);
        Assert.Contains("signature", reasonWrong);
        // Unsigned (unkeyed-exporter) snapshots are refused by a
        // keyed receiver: the public hash is not provenance.
        var unsignedJson = new HealthScoreStore().Export(Rmm28Kit.Score(Rmm28Kit.AllGood()));
        var (okUnsigned, reasonUnsigned, _) = new HealthScoreStore(hubKey).Import(unsignedJson, Rmm28Kit.T0);
        Assert.False(okUnsigned);
        Assert.Contains("signature", reasonUnsigned);

        // Hub store persistence envelope (HubPersistence, the shape
        // CoreRuntime's RestoreHubStore loads): round-trip clean,
        // tamper and wrong-kind both unwrap to null.
        var payload = hub2.HubInventory.ExportJson();
        var wrapped = HubPersistence.Wrap("acp-inventory-v1", payload);
        Assert.Equal(payload, HubPersistence.Unwrap(wrapped, "acp-inventory-v1"));
        Assert.Null(HubPersistence.Unwrap(wrapped, "acp-exposures-v1"));
        // Tamper leg on a payload whose bytes are known (the empty
        // inventory export above is "[]" — nothing to flip in it):
        // one flipped payload character breaks the envelope hash.
        const string knownPayload = """{"devices":["dev-1"]}""";
        var knownWrapped = HubPersistence.Wrap("acp-inventory-v1", knownPayload);
        Assert.Equal(knownPayload, HubPersistence.Unwrap(knownWrapped, "acp-inventory-v1"));
        var tampered = knownWrapped.Replace("dev-1", "dev-2");
        Assert.NotEqual(knownWrapped, tampered);
        Assert.Null(HubPersistence.Unwrap(tampered, "acp-inventory-v1"));
    }

    // ---- destruction ----------------------------------------------

    [Fact]
    public async Task Destruction_NonMemberPeer_CannotRouteThroughHub()
    {
        await using var s = await BuildShapeAsync();
        // The attacker Core never consumed a hub join ticket: it is
        // not a hub node, so the production HubRung refuses it
        // BEFORE any socket — even addressed at a real peer.
        var attacker = Runtime(TestUtil.TempDir(), hubRole: false);
        try
        {
            Assert.Null(s.Hub.HubNodes.Get(attacker.Identity.DeviceId));
            var rung = new HubRung(s.Hub.HubNodes);
            // The membership gate guards the TARGET: a session TO a
            // device that never joined the hub is refused before any
            // socket, whoever asks.
            var result = await rung.ConnectSessionAsync(
                new TransportTarget(attacker.Identity.DeviceId, "100.64.0.9"), s.PeerA.Identity);
            Assert.False(result.Ok);
            Assert.Contains("not a live hub node", result.Detail);

            // Second wall: even a peer that IS a hub member but holds
            // no ACP enrollment at the host is refused at the host's
            // handshake (membership ≠ admission). Enroll the attacker
            // into the hub ONLY, then drive the channel leg.
            var now = DateTimeOffset.UtcNow;
            var ticket = s.Hub.HubJoins.MintJoinTicket(attacker.Identity.DeviceId, "fleet", HubUrl, now);
            Assert.NotNull(s.Hub.HubJoins.ConsumeJoin(
                KeyFromTicket(ticket), attacker.Identity.DeviceId, "1.104.7", now));
            s.PeerB.HubListener.Start(IPAddress.Loopback, 0);
            using var stream = await RawSocketTestLeg.ConnectLoopbackAsync(s.PeerB.HubListener.Port);
            Assert.False(await LanProtocol.ClientHandshakeAsync(stream, attacker.Identity, attacker.Enrollments, s.PeerB.Identity.DeviceId, default));
            // v2 note: the client refuses the host FIRST here (the
            // host is not in the attacker's enrollment store), so
            // no HELLO2 is ever sent; closing the stream is what
            // lets the host count its refused handshake promptly.
            stream.Dispose();
            await RawSocketTestLeg.WaitUntilAsync(() => s.PeerB.HubListener.RefusedHandshakes >= 1);
            Assert.Equal(0, s.PeerB.HubListener.AcceptedSessions);
            s.PeerB.HubListener.Stop();
        }
        finally { try { await attacker.DisposeAsync(); } catch { } }
    }

    [Fact]
    public async Task Destruction_HubRestartMidRoute_RecoversAndReRoutes()
    {
        await using var s = await BuildShapeAsync();
        // Route a session, then kill the hub mid-route.
        await RouteThroughHubAsync(s, s.PeerA, s.PeerB);
        var (stopOk, stopDetail) = s.Hub.ApplyHubAction("""{"action":"stop"}""");
        Assert.True(stopOk, stopDetail);
        Assert.Equal(HubState.Stopped, s.Hub.Hub.State);

        // Restart: the on-disk self-check passes and the hub serves
        // again; membership (the hub Core's registry) and the signing
        // key survive the process restart, and a NEW session routes.
        var keyBefore = s.Hub.HubSigningKeys.CurrentKey!.ToArray();
        var (startOk, startDetail) = s.Hub.ApplyHubAction("""{"action":"start"}""");
        Assert.True(startOk, startDetail);
        Assert.Equal(HubState.Running, s.Hub.Hub.State);
        Assert.Equal(keyBefore, s.Hub.HubSigningKeys.CurrentKey!);
        Assert.NotNull(s.Hub.HubNodes.Get(s.PeerB.Identity.DeviceId));
        await RouteThroughHubAsync(s, s.PeerB, s.PeerA);
        var (stop2Ok, _) = s.Hub.ApplyHubAction("""{"action":"stop"}""");
        Assert.True(stop2Ok);
    }

    [Fact]
    public async Task Destruction_TamperedHubState_RefusedAndPreserved()
    {
        await using var s = await BuildShapeAsync();
        var (stopOk, _) = s.Hub.ApplyHubAction("""{"action":"stop"}""");
        Assert.True(stopOk);

        // (a) Hand-edit the hub policy to the HS-01 fail-open shape:
        // the next start is REFUSED and ACP re-asserts deny-by-default
        // (the tamper cannot persist into a running hub).
        var policyPath = Path.Combine(s.HubDir, "hub", "policy.json");
        File.WriteAllText(policyPath, "{ \"groups\": {} }");
        var (ok, detail) = s.Hub.ApplyHubAction("""{"action":"start"}""");
        Assert.False(ok);
        Assert.Contains("refused", detail);
        Assert.False(HubPolicy.Compile(File.ReadAllText(policyPath)).IsAllowAll);
        // And the following start is clean.
        var (ok2, detail2) = s.Hub.ApplyHubAction("""{"action":"start"}""");
        Assert.True(ok2, detail2);
        var (stop2Ok, _) = s.Hub.ApplyHubAction("""{"action":"stop"}""");
        Assert.True(stop2Ok);

        // (b) Tamper the sealed signing-key file: provisioning
        // preserves the corrupt file as evidence and generates a
        // FRESH key — it never silently reuses or accepts the tamper.
        var dir = TestUtil.TempDir();
        var audit = new ChainedAuditLog();
        var prov1 = new HubSigningKeyProvisioning(dir, new DevOnlyPassThroughProtector(), audit);
        prov1.ProvisionOrLoad();
        var original = prov1.CurrentKey!.ToArray();
        var keyPath = Path.Combine(dir, HubSigningKeyProvisioning.CurrentFileName);
        File.WriteAllText(keyPath, "tampered-not-a-sealed-key");
        var prov2 = new HubSigningKeyProvisioning(dir, new DevOnlyPassThroughProtector(), audit);
        prov2.ProvisionOrLoad();
        Assert.True(prov2.IsProvisioned);
        Assert.NotEqual(original, prov2.CurrentKey!);
        Assert.True(Directory.EnumerateFiles(dir, HubSigningKeyProvisioning.CurrentFileName + ".corrupt-*").Any());
    }
}
