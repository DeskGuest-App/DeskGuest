using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Acp.Core;
using Acp.Core.Ipc;
using Acp.Core.Mcp;
using Acp.Core.Modules;
using Acp.Core.Services;
using Acp.Shared.Policy;
using Acp.Shared.QuickAssist;
using Acp.Shared.Security;
using Acp.Shared.Tools;

namespace Acp.Tests;

/// <summary>
/// C18 — the quick-assist front door, served by the endpoint.
/// QuickAssistWeb.TryServe is the whole routing decision behind the
/// LaneHostManager GET /quickassist routes, so these tests prove the
/// serving contract at the handler level: the served bytes are the
/// repo files (hash-equal), the redeem flow the served page drives
/// works against the same QuickAssistService the route uses, and no
/// other path — static or otherwise — is exposed by the door.
/// Destruction cases (traversal, method abuse, fingerprint leakage)
/// are named as such inline.
/// </summary>
public class QuickAssistWebTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 22, 12, 0, 0, TimeSpan.Zero);

    private static string RepoFile(string name)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            var candidate = Path.Combine(dir.FullName, "agent-control-app", "quick-assist-web", name);
            if (File.Exists(candidate)) return candidate;
            dir = dir.Parent;
        }
        throw new InvalidOperationException("quick-assist-web repo files not found above " + AppContext.BaseDirectory);
    }

    private static string Sha256Hex(byte[] bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    // ---- the served bytes ARE the repo files ----------------------------

    [Fact]
    public void ServedIndex_HashEqualsRepoFile()
    {
        var repoBytes = File.ReadAllBytes(RepoFile("index.html"));
        foreach (var path in new[] { "/quickassist", "/quickassist/", "/quickassist/index.html" })
        {
            Assert.True(QuickAssistWeb.TryServe("GET", path, out var status, out var asset), path);
            Assert.Equal(200, status);
            Assert.Equal(Sha256Hex(repoBytes), asset!.Sha256Hex);
            Assert.Equal(repoBytes, asset.Body);
            Assert.StartsWith("text/html", asset.ContentType);
        }
    }

    [Fact]
    public void ServedAppJs_HashEqualsRepoFile()
    {
        var repoBytes = File.ReadAllBytes(RepoFile("app.js"));
        Assert.True(QuickAssistWeb.TryServe("GET", "/quickassist/app.js", out var status, out var asset));
        Assert.Equal(200, status);
        Assert.Equal(Sha256Hex(repoBytes), asset!.Sha256Hex);
        Assert.Equal(repoBytes, asset.Body);
        Assert.Contains("javascript", asset.ContentType);
    }

    [Fact]
    public void ServedPaths_AreExactlyTheDoorPaths()
    {
        Assert.Equal(
            new[] { "/quickassist", "/quickassist/", "/quickassist/index.html", "/quickassist/app.js" }
                .OrderBy(p => p).ToArray(),
            QuickAssistWeb.ServedPaths.OrderBy(p => p).ToArray());
    }

    // ---- redeem works against the served page's origin ------------------

    [Fact]
    public void RedeemFlow_AgainstServedPage_UsesTheRouteThePageCalls()
    {
        // The served app.js must call exactly the redeem/close routes
        // LaneHostManager maps, relative to the Core origin the user
        // enters — i.e. the served page's own origin serves them.
        Assert.True(QuickAssistWeb.TryServe("GET", "/quickassist/app.js", out _, out var asset));
        var js = Encoding.UTF8.GetString(asset!.Body);
        Assert.Contains("/mesh/quickassist/redeem", js);
        Assert.Contains("/mesh/quickassist/close", js);

        // The handshake behind those routes, run against the same
        // service the endpoint route delegates to: mint → redeem →
        // view-only, browser-bound grant; reuse refused.
        var qa = new QuickAssistService();
        var code = qa.Mint("co1", "dev-1", "tech", T0);
        var (ok, _, grant, _) = qa.Redeem(code, "browser-binding-hash", T0);
        Assert.True(ok);
        Assert.True(grant!.ViewOnly);
        Assert.False(qa.Redeem(code, "browser-binding-hash", T0).Ok);
    }

    [Fact]
    public void ServedPage_GrantsNothingByItself_NoSecretsInBytes()
    {
        // An unauthenticated visitor gets the door page and nothing
        // else: the bytes are the public repo files, which carry no
        // token, roster, or session material.
        foreach (var path in QuickAssistWeb.ServedPaths)
        {
            Assert.True(QuickAssistWeb.TryServe("GET", path, out _, out var asset), path);
            var text = Encoding.UTF8.GetString(asset!.Body);
            Assert.DoesNotContain("Bearer ", text);
            // BD-ENTERPRISE-DOCS F2 reconciliation: the page now
            // names the grantToken FIELD (it must present the token
            // redeem issued in order to close) — the invariant here
            // is that no token VALUE or credential material is baked
            // into the static bytes, so assert on value shapes, not
            // the field name.
            Assert.DoesNotMatch("[0-9a-f]{64}", text);
            Assert.DoesNotContain("PRIVATE KEY", text);
        }
    }

    // ---- no other static paths are exposed -------------------------------

    [Theory]
    [InlineData("/quickassist/README.md")]   // repo file, deliberately NOT served
    [InlineData("/quickassist/style.css")]
    [InlineData("/quickassist/index.html.bak")]
    [InlineData("/quickassist/app.js.map")]
    [InlineData("/quickassist/nested/app.js")]
    [InlineData("/index.html")]
    [InlineData("/app.js")]
    [InlineData("/")]
    [InlineData("")]
    [InlineData("/mesh/state")]              // mesh routes are not the door's to serve
    [InlineData("/healthz")]
    public void NonDoorPaths_Refused404(string path)
    {
        Assert.False(QuickAssistWeb.TryServe("GET", path, out var status, out var asset));
        Assert.Equal(404, status);
        Assert.Null(asset);
    }

    // ---- destruction: traversal off the served page ----------------------

    [Theory]
    [InlineData("/quickassist/../app.js")]
    [InlineData("/quickassist/../../src/Acp.Core/Services/LaneHostManager.cs")]
    [InlineData("/quickassist/%2e%2e/app.js")]
    [InlineData("/quickassist/%2E%2E%2Fapp.js")]
    [InlineData("/quickassist/..%2fapp.js")]
    [InlineData("/quickassist/%252e%252e/app.js")] // double-encoded
    [InlineData("/quickassist/..\\app.js")]
    [InlineData("/quickassist\\app.js")]
    [InlineData("/quickassist//app.js")]
    [InlineData("/quickassist/app.js/..")]
    [InlineData("/quickassist/app.js%00")]
    [InlineData("/quickassist/%00")]
    [InlineData("/QUICKASSIST/app.js")]            // paths are case-sensitive
    [InlineData("/QuickAssist/App.Js")]
    [InlineData("/quickassist/app.js?x=1")]        // query strings are not paths
    public void TraversalAndTricks_Refused404(string path)
    {
        Assert.False(QuickAssistWeb.TryServe("GET", path, out var status, out var asset), path);
        Assert.Equal(404, status);
        Assert.Null(asset);
    }

    // ---- destruction: auth bypass via the new route ----------------------

    [Theory]
    [InlineData("POST")]
    [InlineData("PUT")]
    [InlineData("DELETE")]
    [InlineData("PATCH")]
    public void NonGetMethods_Refused405_NoAssetServed(string method)
    {
        // The door never accepts writes: redemption stays on its own
        // POST route with its own one-time-code gate.
        Assert.False(QuickAssistWeb.TryServe(method, "/quickassist/app.js", out var status, out var asset));
        Assert.Equal(405, status);
        Assert.Null(asset);
    }

    [Fact]
    public void Head_IsServedLikeGet()
    {
        Assert.True(QuickAssistWeb.TryServe("HEAD", "/quickassist/", out var status, out var asset));
        Assert.Equal(200, status);
        Assert.NotNull(asset);
    }

    // ---- live wire: a real loopback lane serves the door -----------------
    // Raw Socket client per the CONV-F3 precedent (RawSocketTestLeg):
    // HttpClient loopback is proxied away in this sandbox; the wire
    // request/response below are exercised verbatim.

    private sealed class FakeChannel : IAgentChannel
    {
        public bool AgentConnected => true;
        public Task<ToolResult> CallDesktopToolAsync(string tool, string argumentsJson, CancellationToken ct) =>
            Task.FromResult(ToolResult.Success("ok"));
    }

    private static int FreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    private static async Task<(int Status, string Headers, byte[] Body)> RawHttp(int port, string request)
    {
        using var stream = await RawSocketTestLeg.ConnectLoopbackAsync(port);
        await stream.WriteAsync(Encoding.ASCII.GetBytes(request));
        using var ms = new MemoryStream();
        var buf = new byte[8192];
        int n;
        while ((n = await stream.ReadAsync(buf)) > 0) ms.Write(buf, 0, n);
        var raw = ms.ToArray();
        var split = -1;
        for (var i = 0; i + 3 < raw.Length; i++)
            if (raw[i] == '\r' && raw[i + 1] == '\n' && raw[i + 2] == '\r' && raw[i + 3] == '\n') { split = i; break; }
        Assert.True(split > 0, "malformed HTTP response");
        var head = Encoding.ASCII.GetString(raw, 0, split);
        var status = int.Parse(head.Split(' ')[1]);
        var body = raw.AsSpan(split + 4).ToArray();
        if (head.Contains("Transfer-Encoding: chunked", StringComparison.OrdinalIgnoreCase))
        {
            using var outMs = new MemoryStream();
            var pos = 0;
            while (true)
            {
                var lineEnd = -1;
                for (var i = pos; i + 1 < body.Length; i++)
                    if (body[i] == '\r' && body[i + 1] == '\n') { lineEnd = i; break; }
                Assert.True(lineEnd > pos, "bad chunk");
                var size = int.Parse(Encoding.ASCII.GetString(body, pos, lineEnd - pos).Trim(),
                    System.Globalization.NumberStyles.HexNumber);
                if (size == 0) break;
                outMs.Write(body, lineEnd + 2, size);
                pos = lineEnd + 2 + size + 2;
            }
            body = outMs.ToArray();
        }
        return (status, head, body);
    }

    [Fact]
    public async Task LiveWire_LoopbackLane_ServesDoor_RedeemWorks_TricksRefused()
    {
        var pairings = new PairingService(new DevOnlyPassThroughProtector());
        var audit = TestUtil.AuditLog(TestUtil.TempDir());
        var mesh = new MeshService(new FakeChannel(), () => null, () => 0, () => true, () => null);
        var qa = new QuickAssistService();
        var port = FreePort();
        var lanes = new LaneHostManager(
            new McpHandler(pairings, new PolicyEngine(), new ToolRegistry(), audit, new CoreState(), new SessionManager()),
            new PairingHandler(pairings, audit), () => new HashSet<string>(), port,
            lanCertificate: null, mesh: mesh, quickAssist: qa);
        try
        {
            Assert.True(await lanes.StartLaneAsync("loopback", "127.0.0.1", default));

            // The door, on the wire, unauthenticated: the page itself.
            var (status, headers, body) = await RawHttp(port,
                "GET /quickassist/ HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
            Assert.Equal(200, status);
            Assert.Equal(Sha256Hex(File.ReadAllBytes(RepoFile("index.html"))), Sha256Hex(body));
            Assert.Contains("X-Content-Type-Options: nosniff", headers);
            Assert.DoesNotContain("Server:", headers);

            var (jsStatus, _, jsBody) = await RawHttp(port,
                "GET /quickassist/app.js HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
            Assert.Equal(200, jsStatus);
            Assert.Equal(Sha256Hex(File.ReadAllBytes(RepoFile("app.js"))), Sha256Hex(jsBody));

            // Nothing else static rides along — not even the README
            // that sits beside the page in the repo.
            var (readmeStatus, _, readmeBody) = await RawHttp(port,
                "GET /quickassist/README.md HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
            Assert.Equal(404, readmeStatus);
            Assert.Empty(readmeBody);

            // Traversal on the wire stays a bare 404 with no bytes.
            var (travStatus, _, travBody) = await RawHttp(port,
                "GET /quickassist/%2e%2e/app.js HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
            Assert.Equal(404, travStatus);
            Assert.Empty(travBody);

            // Redeem against the served page's own origin: mint →
            // redeem over the wire → view-only grant; reuse refused.
            var code = qa.Mint("co1", "dev-1", "tech", DateTimeOffset.UtcNow);
            var payload = Encoding.UTF8.GetBytes($"{{\"code\":\"{code}\",\"clientBinding\":\"wire-binding\"}}");
            var (redeemStatus, _, redeemBody) = await RawHttp(port,
                $"POST /mesh/quickassist/redeem HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {payload.Length}\r\nConnection: close\r\n\r\n" +
                Encoding.UTF8.GetString(payload));
            Assert.Equal(200, redeemStatus);
            var redeemJson = Encoding.UTF8.GetString(redeemBody);
            Assert.Contains("\"ok\":true", redeemJson);
            Assert.Contains("\"viewOnly\":true", redeemJson);
            var (reuseStatus, _, _) = await RawHttp(port,
                $"POST /mesh/quickassist/redeem HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {payload.Length}\r\nConnection: close\r\n\r\n" +
                Encoding.UTF8.GetString(payload));
            Assert.Equal(403, reuseStatus);
        }
        finally { await lanes.DisposeAsync(); }
    }

    // ---- destruction: information leakage in headers ---------------------

    [Fact]
    public void ResponseHeaders_CarryNoFingerprint_AndNoStore()
    {
        var headers = QuickAssistWeb.ResponseHeaders;
        Assert.Equal("nosniff", headers["X-Content-Type-Options"]);
        Assert.Equal("no-store", headers["Cache-Control"]);
        Assert.False(headers.ContainsKey("Server"));
        Assert.False(headers.ContainsKey("X-Powered-By"));
        Assert.False(headers.ContainsKey("X-AspNet-Version"));
        foreach (var value in headers.Values)
        {
            Assert.DoesNotContain("Kestrel", value);
            Assert.DoesNotContain("ASP.NET", value);
        }
    }
}
