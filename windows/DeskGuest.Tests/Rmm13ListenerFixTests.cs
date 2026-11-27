using System.Net;
using System.Net.Sockets;
using DeskGuest.Core.Services;
using DeskGuest.Shared.Reporting;

namespace DeskGuest.Tests;

// RMM-13 LISTENER WIRING FIX — regression tests for the defect found
// by the RMM-13 D38 fix lane: ReportingHttpListener called
// ReportingService.Api.Dispatch directly, bypassing
// ReportingService.DispatchApi, so over HTTP (1) the
// rmm.reporting.api.enabled policy gate was NOT applied and (2) no
// chained api_call audit entry was appended. The listener now routes
// through DispatchApi; these tests prove HTTP and in-process calls
// get identical gate + audit treatment, over REAL HTTP requests.
public class Rmm13ListenerFixTests
{
    private static int FreePort()
    {
        var probe = new TcpListener(IPAddress.Loopback, 0);
        probe.Start();
        var port = ((IPEndPoint)probe.LocalEndpoint).Port;
        probe.Stop();
        return port;
    }

    // A REAL HTTP request over a raw loopback socket. (HttpClient /
    // TcpClient are deliberately NOT used: in this sandbox their
    // connect paths are steered into the egress proxy, which refuses
    // the call before it reaches the listener — probed and proven
    // during this fix; a raw Socket connected by IPAddress reaches
    // the listener directly, and the wire request/response are
    // exercised verbatim either way.)
    private static async Task<(HttpStatusCode Status, string Body)> HttpGet(
        ReportingHttpListener listener, int port, string path, string? secret)
    {
        listener.Start();
        Assert.True(listener.IsListening);
        // The listener loop is live once Start returns; retry briefly
        // only against connection-level races, never against a status.
        for (var attempt = 0; ; attempt++)
        {
            try
            {
                using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                await socket.ConnectAsync(IPAddress.Loopback, port);
                using var stream = new NetworkStream(socket, ownsSocket: false);
                var request =
                    $"GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n" +
                    (secret is null ? "" : $"Authorization: Bearer {secret}\r\n") +
                    "Connection: close\r\n\r\n";
                var reqBytes = System.Text.Encoding.ASCII.GetBytes(request);
                await stream.WriteAsync(reqBytes, 0, reqBytes.Length);
                using var ms = new MemoryStream();
                await stream.CopyToAsync(ms);
                var raw = System.Text.Encoding.UTF8.GetString(ms.ToArray());
                var split = raw.IndexOf("\r\n\r\n", StringComparison.Ordinal);
                Assert.True(split > 0, $"malformed HTTP response: {raw}");
                var statusLine = raw[..raw.IndexOf("\r\n", StringComparison.Ordinal)];
                var status = (HttpStatusCode)int.Parse(statusLine.Split(' ')[1]);
                return (status, raw[(split + 4)..]);
            }
            catch (SocketException) when (attempt < 10)
            {
                await Task.Delay(100);
            }
        }
    }

    [Fact]
    public async Task Http_ApiDisabledByPolicy_RefusedExactlyAsInProcess()
    {
        var rig = Rmm13Tests.NewRig();
        // Issue the key while the API is still enabled (issuance is
        // itself gated), then turn the API OFF by policy.
        var (ok, _, secret) = rig.Service.IssueApiKey(Rmm13Tests.Facts(), "admin",
            new HashSet<string> { HubApiScopes.ReportsRead });
        Assert.True(ok);
        Rmm13Tests.SetPolicy(rig, "scope1", ReportingPolicyKeys.ApiEnabled, "false", 901);

        // In-process reference behaviour: 403, named policy refusal.
        var inProcess = rig.Service.DispatchApi(Rmm13Tests.Facts(), "GET",
            "/api/v1/reports/fleet_health", secret);
        Assert.Equal(403, inProcess.Status);
        Assert.Contains("disabled by policy", inProcess.BodyJson);

        // Over HTTP the SAME call must be refused identically — before
        // the fix the listener answered 200 here (gate bypassed).
        var port = FreePort();
        using var listener = new ReportingHttpListener(rig.Service,
            $"http://127.0.0.1:{port}/", Rmm13Tests.Facts());
        var (status, body) = await HttpGet(listener, port, "/api/v1/reports/fleet_health", secret);
        Assert.Equal(HttpStatusCode.Forbidden, status);
        Assert.Equal(inProcess.BodyJson, body);
    }

    [Fact]
    public async Task Http_ApiEnabled_AppendsChainedApiCallAuditEntry()
    {
        var rig = Rmm13Tests.NewRig();
        var (ok, _, secret) = rig.Service.IssueApiKey(Rmm13Tests.Facts(), "admin",
            new HashSet<string> { HubApiScopes.ReportsRead });
        Assert.True(ok);
        var before = rig.Audit.Entries.Count;

        var port = FreePort();
        using var listener = new ReportingHttpListener(rig.Service,
            $"http://127.0.0.1:{port}/", Rmm13Tests.Facts());
        var (status, body) = await HttpGet(listener, port, "/api/v1/reports/fleet_health", secret);
        Assert.Equal(HttpStatusCode.OK, status);
        Assert.Contains("fleet_health", body);

        // Exactly one new chained entry, and it is the api_call record
        // for this HTTP call — before the fix the count did not move.
        Assert.Equal(before + 1, rig.Audit.Entries.Count);
        var entry = rig.Audit.Entries[^1];
        Assert.Equal("api_call", entry.Kind);
        Assert.Contains("status=200", entry.Detail);
        Assert.Contains("/api/v1/reports/fleet_health", entry.Detail);
        Assert.True(rig.Audit.Verify().Ok);
    }

    [Fact]
    public void Listener_StillDefaultOffAndFailClosed()
    {
        // (c) Lane A posture is unchanged by the wiring fix: the
        // listener policy key is the http toggle, a constructed
        // listener answers nothing until started, and a null service
        // is refused at construction.
        Assert.Equal("rmm.reporting.http.enabled", ReportingHttpListener.PolicyKey);
        Assert.Throws<ArgumentNullException>(() => new ReportingHttpListener(null!));
        var rig = Rmm13Tests.NewRig();
        using var listener = new ReportingHttpListener(rig.Service,
            $"http://127.0.0.1:{FreePort()}/", Rmm13Tests.Facts());
        Assert.False(listener.IsListening);
    }
}
