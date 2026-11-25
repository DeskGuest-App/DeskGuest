using System.Net;
using System.Text;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Reporting;

namespace Acp.Core.Services;

// =====================================================================
// Lane A (item 6) — RMM-13 reporting HTTP listener.
//
// Wired ONLY through the hub's existing authenticated surface:
// every request is dispatched through ReportingService.DispatchApi
// — the SAME gated + audited entry point in-process callers use —
// so an HTTP call gets identical treatment to an in-process one:
// the rmm.reporting.api.enabled policy gate is applied BEFORE the
// HubApiDispatcher authenticates the presented API secret against
// the HubApiKeyStore, and every call appends its chained api_call
// audit entry. (Previously this listener called Api.Dispatch
// directly, bypassing both the gate and the audit append — the
// RMM-13 listener-wiring defect, fixed here.) The dispatcher's
// catalogue is the only route set. This listener adds:
//   * NO new authentication of its own (and no unauthenticated
//     route of any kind — there is no health/status bypass);
//   * NO routes beyond the dispatcher's catalogue;
//   * a loopback-only default bind (the hub operator exposes it
//     further only by an explicit prefix choice at construction);
//   * a TOTAL POLICY CONTROL gate: the listener starts only when
//     policy enables rmm.reporting.http.enabled for this device —
//     default OFF, so a stock hub grows no new network surface.
// Responses are the dispatcher's own (status + body); the API
// secret is read from the Authorization header and never logged.
// =====================================================================

public sealed class ReportingHttpListener : IDisposable
{
    public const string PolicyKey = "rmm.reporting.http.enabled";

    private readonly ReportingService _reporting;
    private readonly IDeviceFacts _facts;
    private readonly string _prefix;
    private readonly Func<bool>? _httpEnabled;
    private HttpListener? _listener;
    private CancellationTokenSource? _cts;

    public bool IsListening => _listener?.IsListening == true;
    public string Prefix => _prefix;
    /// <summary>True when the last Start() was refused by the
    /// rmm.reporting.http.enabled policy gate (BD-WIN-CORE-3/F6).</summary>
    public bool StartRefusedByPolicy { get; private set; }

    /// <param name="facts">The hub facts DispatchApi gates on —
    /// the same facts an in-process caller would present. Defaults
    /// to the hub's own facts (device "hub", no scope), matching
    /// ReportingService's internal hub-facts shape.</param>
    /// <param name="httpEnabled">BD-WIN-CORE-3/F6: the TOTAL POLICY
    /// CONTROL gate for <see cref="PolicyKey"/>. When wired, Start()
    /// refuses unless it returns true, and every request re-checks
    /// it (a policy flip closes the surface). CoreRuntime wires it
    /// to the policy engine; unwired construction is the in-process
    /// test posture only.</param>
    public ReportingHttpListener(ReportingService reporting, string prefix = "http://127.0.0.1:8731/",
        IDeviceFacts? facts = null, Func<bool>? httpEnabled = null)
    {
        _reporting = reporting ?? throw new ArgumentNullException(nameof(reporting));
        if (string.IsNullOrWhiteSpace(prefix) || !prefix.EndsWith('/'))
            throw new ArgumentException("listener prefix must be a non-empty HttpListener prefix ending in '/'", nameof(prefix));
        // BD-WIN-CORE-3/F6: cleartext http is LOOPBACK-ONLY. The old
        // constructor accepted any http:// prefix, so the API bearer
        // secret could travel in cleartext across a network.
        if (!Uri.TryCreate(prefix, UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
            throw new ArgumentException("listener prefix must be an http:// or https:// prefix", nameof(prefix));
        if (uri.Scheme == Uri.UriSchemeHttp && !IsLoopbackHost(uri.Host))
            throw new ArgumentException(
                "cleartext http listener prefixes are loopback-only — a non-loopback prefix must be https (the API bearer secret never travels in cleartext)", nameof(prefix));
        _prefix = prefix;
        _facts = facts ?? StaticDeviceFacts.Of("hub", "");
        _httpEnabled = httpEnabled;
    }

    internal static bool IsLoopbackHost(string host) =>
        string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase) ||
        (System.Net.IPAddress.TryParse(host, out var ip) && System.Net.IPAddress.IsLoopback(ip));

    public void Start()
    {
        if (_listener is not null) return;
        // BD-WIN-CORE-3/F6: Start() itself checks the policy key —
        // the header always claimed it did; now it does.
        if (_httpEnabled is not null && !_httpEnabled())
        {
            StartRefusedByPolicy = true;
            return;
        }
        StartRefusedByPolicy = false;
        _listener = new HttpListener();
        _listener.Prefixes.Add(_prefix);
        _listener.Start();
        _cts = new CancellationTokenSource();
        _ = Task.Run(() => Loop(_cts.Token));
    }

    private async Task Loop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested && _listener is not null)
        {
            HttpListenerContext ctx;
            try { ctx = await _listener.GetContextAsync(); }
            catch { break; }
            _ = Task.Run(() => Handle(ctx));
        }
    }

    private void Handle(HttpListenerContext ctx)
    {
        try
        {
            // BD-WIN-CORE-3/F6: re-check the http gate per request —
            // a policy flip after Start must close the surface.
            if (_httpEnabled is not null && !_httpEnabled())
            {
                ctx.Response.StatusCode = 403;
                ctx.Response.Close();
                return;
            }
            var secret = ctx.Request.Headers["Authorization"];
            if (secret is not null && secret.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                secret = secret[7..].Trim();
            var path = ctx.Request.Url?.AbsolutePath ?? "/";
            // Through DispatchApi — NEVER Api.Dispatch directly:
            // DispatchApi applies the rmm.reporting.api.enabled
            // policy gate and appends the chained api_call audit
            // entry, exactly as for an in-process call.
            var response = _reporting.DispatchApi(
                _facts, ctx.Request.HttpMethod, path, secret);
            var bytes = Encoding.UTF8.GetBytes(response.BodyJson ?? "");
            ctx.Response.StatusCode = response.Status;
            ctx.Response.ContentType = "application/json";
            ctx.Response.ContentLength64 = bytes.Length;
            ctx.Response.OutputStream.Write(bytes, 0, bytes.Length);
            ctx.Response.Close();
        }
        catch
        {
            try { ctx.Response.StatusCode = 500; ctx.Response.Close(); } catch { }
        }
    }

    public void Dispose()
    {
        _cts?.Cancel();
        try { _listener?.Stop(); } catch { }
        _listener?.Close();
        _listener = null;
        _cts?.Dispose();
    }
}
