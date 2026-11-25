using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Acp.Core;
using Acp.Core.Mcp;
using Acp.Core.Modules;
using Acp.Core.Services;
using Acp.Shared.Connection;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Policy;
using Acp.Shared.Security;
using Acp.Shared.State;
using Acp.Shared.Tools;

namespace Acp.Tests;

/// <summary>
/// FR-143 (GitHub issue #44) — "Require HTTPS for agent connections".
/// The registry entry + the pure decision are pinned directly; the
/// lane behaviour is pinned on the wire over raw sockets (the
/// CONV-F3 transport: this sandbox steers HttpClient loopback into
/// its egress proxy, so the client leg speaks raw Socket/SslStream
/// while the protocol, handshakes and refusals are exercised
/// verbatim); the Core wiring is pinned by source, in the W73
/// pattern. The live behaviour — refusal on the real mesh listener,
/// the pinned-HTTPS Axle channel, the off-flip restoring HTTP — is
/// proven on the laptop (BUILD-LOG, FR-143 entry).
/// </summary>
public class Fr143HttpsOnlyTests
{
    private const string Key = HttpsOnlyPolicyKeys.FeatureToggle;

    // ---- Registry + policy engine --------------------------------

    [Fact]
    public void Registry_HttpsOnlyToggle_SeededOn_WithPerRungHonestDescription()
    {
        var registry = FeatureToggleRegistry.Seeded();
        Assert.True(registry.TryGet(Key, out var toggle));
        Assert.Equal("FR-143", toggle!.Directive);
        Assert.True(toggle.DefaultEnabled);
        // The explanation must tell the truth per rung, not sell
        // the toggle as changing what it does not change:
        Assert.Contains("HTTPS-only by construction", toggle.Description);   // the LAN lane
        Assert.Contains("sealed end to end", toggle.Description);            // device-to-device rungs
        Assert.Contains("loopback", toggle.Description);                     // the named exemption
        Assert.Contains("pin", toggle.Description);                          // the pairing pin story
    }

    [Fact]
    public void ConsentFloorGuard_AdmitsTheHttpsOnlyKey()
    {
        // The key names none of presence / STOP / audit / consent,
        // so the registry accepts it and policy documents may set it.
        Assert.False(ConsentFloorGuard.IsDenied(Key));
        Assert.Null(ConsentFloorGuard.CheckDocument(new ManagementPolicyDocument(
            "doc-1", PolicyLevels.Device, "dev-1",
            new Dictionary<string, string> { [Key] = "false" }, 1)));
    }

    [Fact]
    public void Engine_HttpsOnly_DefaultsOn_AndPolicyCanTurnItOffAndBackOn()
    {
        var facts = StaticDeviceFacts.Of("dev-1", "scope-1");
        var engine = new ManagementPolicyEngine();
        Assert.True(engine.IsEnabled(facts, Key)); // registry default ON
        var off = engine.AddDocument(new ManagementPolicyDocument(
            "owner-https", PolicyLevels.Device, "dev-1",
            new Dictionary<string, string> { [Key] = "false" }, 1));
        Assert.True(off.Allowed, off.Reason);
        Assert.False(engine.IsEnabled(facts, Key));
        var on = engine.AddDocument(new ManagementPolicyDocument(
            "owner-https", PolicyLevels.Device, "dev-1",
            new Dictionary<string, string> { [Key] = "true" }, 2));
        Assert.True(on.Allowed, on.Reason);
        Assert.True(engine.IsEnabled(facts, Key));
        // And it shows in Effective Policy with its provenance.
        var effective = engine.ComputeEffective(facts).Get(Key);
        Assert.NotNull(effective);
        Assert.Equal("true", effective!.Value);
        Assert.Equal(PolicyLevels.Device, effective.SourceLevel);
    }

    [Fact]
    public void Engine_HttpsOnly_UnparsableDocumentValue_FailsClosed()
    {
        var facts = StaticDeviceFacts.Of("dev-1", "scope-1");
        var engine = new ManagementPolicyEngine();
        var verdict = engine.AddDocument(new ManagementPolicyDocument(
            "owner-https", PolicyLevels.Device, "dev-1",
            new Dictionary<string, string> { [Key] = "banana" }, 1));
        Assert.True(verdict.Allowed, verdict.Reason);
        Assert.False(engine.IsEnabled(facts, Key)); // unparsable never enables
    }

    // ---- The pure decision ----------------------------------------

    [Fact]
    public void Decision_TransportMatrix()
    {
        // LAN: HTTPS always, policy-independent.
        Assert.Equal(LaneTransport.Https, HttpsOnlyDecision.TransportFor("Lan", httpsOnlyEnabled: true, certificateAvailable: true));
        Assert.Equal(LaneTransport.Https, HttpsOnlyDecision.TransportFor("Lan", httpsOnlyEnabled: false, certificateAvailable: true));
        // Loopback: HTTP always — the named exemption.
        Assert.Equal(LaneTransport.Http, HttpsOnlyDecision.TransportFor("loopback", httpsOnlyEnabled: true, certificateAvailable: true));
        Assert.Equal(LaneTransport.Http, HttpsOnlyDecision.TransportFor("loopback", httpsOnlyEnabled: false, certificateAvailable: false));
        // Mesh lane: the governed surface.
        Assert.Equal(LaneTransport.Https, HttpsOnlyDecision.TransportFor("Tailscale", httpsOnlyEnabled: true, certificateAvailable: true));
        Assert.Equal(LaneTransport.RefuseStart, HttpsOnlyDecision.TransportFor("Tailscale", httpsOnlyEnabled: true, certificateAvailable: false));
        Assert.Equal(LaneTransport.Http, HttpsOnlyDecision.TransportFor("Tailscale", httpsOnlyEnabled: false, certificateAvailable: true));
        Assert.Equal(LaneTransport.Http, HttpsOnlyDecision.TransportFor("Tailscale", httpsOnlyEnabled: false, certificateAvailable: false));
    }

    [Fact]
    public void Decision_RefusalMatrix()
    {
        Assert.True(HttpsOnlyDecision.RefusePlainHttp("Tailscale", requestIsHttps: false, httpsOnlyEnabled: true));
        Assert.False(HttpsOnlyDecision.RefusePlainHttp("Tailscale", requestIsHttps: true, httpsOnlyEnabled: true));
        Assert.False(HttpsOnlyDecision.RefusePlainHttp("Tailscale", requestIsHttps: false, httpsOnlyEnabled: false));
        Assert.False(HttpsOnlyDecision.RefusePlainHttp("loopback", requestIsHttps: false, httpsOnlyEnabled: true));
    }

    // ---- Supervisor rebind ----------------------------------------

    [Fact]
    public void ForceRebind_BoundLane_RebindsOnNextTick_UnboundLane_NoForce()
    {
        var clock = new FakeClock();
        var probe = new FakeProbe { Handler = _ => "100.119.105.54" };
        var sup = new LaneSupervisor(probe, clock);
        Assert.False(sup.ForceRebind(LaneKind.Tailscale)); // not bound yet
        var bind = sup.Tick(LaneKind.Tailscale);
        Assert.Contains(bind, a => a.Action == "bind");
        sup.ReportBindResult(LaneKind.Tailscale, true);
        Assert.Equal(LanePhase.Bound, sup.Status(LaneKind.Tailscale).Phase);
        Assert.True(sup.ForceRebind(LaneKind.Tailscale));
        Assert.Equal(LanePhase.NoAddress, sup.Status(LaneKind.Tailscale).Phase);
        var rebind = sup.Tick(LaneKind.Tailscale);
        Assert.Contains(rebind, a => a.Action == "bind" && a.Address == "100.119.105.54");
    }

    // ---- Wire behaviour -------------------------------------------

    private static int FreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    private static LaneHostManager Lanes(int port, X509Certificate2? cert, Func<bool>? httpsOnly,
        Action<string, string?, string?>? onRefusal = null)
    {
        var pairings = new PairingService(new DevOnlyPassThroughProtector());
        var audit = TestUtil.AuditLog(TestUtil.TempDir());
        return new LaneHostManager(
            new McpHandler(pairings, new PolicyEngine(), new ToolRegistry(), audit, new CoreState(), new SessionManager()),
            new PairingHandler(pairings, audit), () => new HashSet<string>(), port,
            lanCertificate: cert, meshCertificate: cert, httpsOnly: httpsOnly, onHttpsRefusal: onRefusal);
    }

    private static async Task<string> RawRequestAsync(int port, string request, int readTimeoutMs = 4000)
    {
        using var stream = await RawSocketTestLeg.ConnectLoopbackAsync(port);
        var bytes = Encoding.ASCII.GetBytes(request);
        await stream.WriteAsync(bytes, 0, bytes.Length);
        using var ms = new MemoryStream();
        var buf = new byte[8192];
        using var cts = new CancellationTokenSource(readTimeoutMs);
        try
        {
            int n;
            while ((n = await stream.ReadAsync(buf, 0, buf.Length, cts.Token)) > 0)
                ms.Write(buf, 0, n);
        }
        catch (OperationCanceledException) { }
        catch (IOException) { } // a reset is a legitimate wire outcome on the refusal legs
        return Encoding.UTF8.GetString(ms.ToArray());
    }

    [Fact]
    public async Task MeshLane_HttpsOnlyOn_ServesTlsWithPin_PlainHttpGetsNoHttpAnswer()
    {
        var store = new LanCertificateStore(TestUtil.TempDir());
        var cert = store.EnsureCertificate();
        var pin = store.Fingerprint;
        var port = FreePort();
        var lanes = Lanes(port, cert, () => true);
        try
        {
            Assert.True(await lanes.StartLaneAsync("Tailscale", "127.0.0.1", default));

            // Pinned TLS leg: handshake with the production pin
            // check, then /healthz answers.
            using (var socket = await RawSocketTestLeg.ConnectSocketLoopbackAsync(port))
            using (var tls = new SslStream(new NetworkStream(socket, ownsSocket: false), leaveInnerStreamOpen: false,
                (_, presented, _, _) => CertificatePinning.MatchesPin(presented as X509Certificate2, pin)))
            {
                await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = "127.0.0.1",
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                });
                var req = Encoding.ASCII.GetBytes($"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
                await tls.WriteAsync(req, 0, req.Length);
                using var ms = new MemoryStream();
                var buf = new byte[8192];
                int n;
                while ((n = await tls.ReadAsync(buf, 0, buf.Length)) > 0) ms.Write(buf, 0, n);
                var response = Encoding.UTF8.GetString(ms.ToArray());
                Assert.Contains("200", response);
                Assert.Contains("status", response);
                Assert.Contains("up", response);
            }

            // Plain-HTTP leg: the TLS endpoint gives no HTTP answer
            // (the read resets or closes with nothing HTTP-shaped).
            var plain = await RawRequestAsync(port, $"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
            Assert.DoesNotContain("HTTP/1.1 200", plain);
            Assert.DoesNotContain("ACP-Windows Core", plain);
        }
        finally { await lanes.DisposeAsync(); }
    }

    [Fact]
    public async Task MeshLane_HttpsOnlyOn_WithoutCertificate_RefusesToStart()
    {
        var port = FreePort();
        var lanes = Lanes(port, cert: null, () => true);
        try
        {
            Assert.False(await lanes.StartLaneAsync("Tailscale", "127.0.0.1", default));
            Assert.Empty(lanes.RunningLanes);
        }
        finally { await lanes.DisposeAsync(); }
    }

    [Fact]
    public async Task MeshLane_PolicyFlipWindow_PlainHttpRefusedByName_AndReported()
    {
        var port = FreePort();
        var enforcement = false;
        var refusals = new List<(string Lane, string? Remote, string? Path)>();
        var lanes = Lanes(port, cert: null, () => enforcement,
            onRefusal: (lane, remote, path) => { lock (refusals) refusals.Add((lane, remote, path)); });
        try
        {
            // Bound under policy OFF: plain HTTP serves (prior behaviour).
            Assert.True(await lanes.StartLaneAsync("Tailscale", "127.0.0.1", default));
            var before = await RawRequestAsync(port, $"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
            Assert.Contains("HTTP/1.1 200", before);

            // The flip lands before the rebind: the same plain-HTTP
            // surface now refuses BY NAME and reports the refusal.
            enforcement = true;
            var body = "{\"jsonrpc\":\"2.0\",\"id\":\"1\",\"method\":\"initialize\",\"params\":{}}";
            var after = await RawRequestAsync(port,
                $"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nContent-Length: {body.Length}\r\nConnection: close\r\n\r\n{body}");
            Assert.Contains("HTTP/1.1 403", after);
            Assert.Contains("https_required", after);
            lock (refusals)
            {
                Assert.Single(refusals);
                Assert.Equal("Tailscale", refusals[0].Lane);
                Assert.Equal("/mcp", refusals[0].Path);
            }
        }
        finally { await lanes.DisposeAsync(); }
    }

    [Fact]
    public async Task LoopbackLane_Exempt_PlainHttpServes_WhileEnforcementOn()
    {
        var port = FreePort();
        var lanes = Lanes(port, cert: null, () => true);
        try
        {
            Assert.True(await lanes.StartLaneAsync("loopback", "127.0.0.1", default));
            var response = await RawRequestAsync(port, $"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
            Assert.Contains("HTTP/1.1 200", response);
        }
        finally { await lanes.DisposeAsync(); }
    }

    // ---- Source pins (W73 pattern) --------------------------------

    private static string SrcFile(params string[] parts)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            foreach (var root in new[] { "src", Path.Combine("windows-agent", "src") })
            {
                var c = Path.Combine(new[] { dir.FullName, root }.Concat(parts).ToArray());
                if (File.Exists(c)) return File.ReadAllText(c);
            }
            dir = dir.Parent;
        }
        throw new DirectoryNotFoundException(string.Join("/", parts) + " not found above " + AppContext.BaseDirectory);
    }

    [Fact]
    public void Source_CoreRuntime_WiresPolicyIntoLaneHosts_AndRebindsOnFlip()
    {
        var core = SrcFile("Acp.Core", "CoreRuntime.cs");
        Assert.Contains("HttpsOnlyPolicyKeys.FeatureToggle", core);
        Assert.Contains("meshCertificate: lanCert", core);
        Assert.Contains("https_only_refused", core);
        Assert.Contains("ForceRebind(LaneKind.Tailscale)", core);
        Assert.Contains("https_only_policy_applied", core);
        var lanes = SrcFile("Acp.Core", "Services", "LaneHostManager.cs");
        Assert.Contains("HttpsOnlyDecision.TransportFor", lanes);
        Assert.Contains("HttpsOnlyDecision.RefusePlainHttp", lanes);
        Assert.Contains("https_required", lanes);
    }
}
