using System.Security.Cryptography.X509Certificates;
using DeskGuest.Core.Mcp;
using DeskGuest.Shared.Connection;
using DeskGuest.Shared.Policy;
using DeskGuest.Shared.Security;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace DeskGuest.Core.Services;

/// <summary>
/// Owns one WebApplication per bound lane (DESIGN §4.2). Lane lifecycle
/// is driven by the LaneSupervisor's transitions: an address appearing
/// starts a listener; an address vanishing stops it; a bind failure is
/// reported back to the supervisor for backoff. The Core process itself
/// NEVER exits over a lane — lanes are states, not preconditions.
/// Loopback can be added as a dev/test lane; production binds only the
/// supervisor's lanes (tailnet + LAN), never 0.0.0.0.
/// </summary>
public sealed class LaneHostManager : IAsyncDisposable
{
    private readonly McpHandler _mcp;
    private readonly PairingHandler _pairing;
    private readonly Func<IReadOnlySet<string>> _approvedGates;
    private readonly int _port;
    private readonly X509Certificate2? _lanCertificate;
    private readonly MeshService? _mesh;
    private readonly StreamService? _stream;
    private readonly DeskGuest.Shared.QuickAssist.QuickAssistService? _quickAssist;
    // BD-WIN-CORE-3/F1: mesh identity resolver. The host wires the
    // pairing-channel identity (MeshIdentityResolver: the request's
    // pairing bearer token → the host-bound pairing name → the
    // unique live roster user). Null (no resolver wired) means
    // every sensitive mesh verb FAILS CLOSED with 401.
    private readonly Func<HttpContext, string?>? _meshIdentity;
    // FR-143: the mesh lane's TLS host certificate (the same device
    // certificate the LAN lane serves), the signed-policy HTTPS-only
    // callback, and the refusal sink (audit + narration, wired by
    // the host). All optional: an unwired host serves exactly as
    // before — CoreRuntime always wires them, with the registry
    // default making enforcement ON.
    private readonly X509Certificate2? _meshCertificate;
    private readonly Func<bool>? _httpsOnly;
    private readonly Action<string, string?, string?>? _onHttpsRefusal;
    private readonly Dictionary<string, WebApplication> _hosts = new(); // key: lane name or "loopback"
    private readonly SemaphoreSlim _gate = new(1, 1);

    /// <param name="lanCertificate">The LAN lane's TLS host
    /// certificate. The LAN lane is served ONLY over TLS with this
    /// certificate (clients pin it at pairing); without one the LAN
    /// lane refuses to start — cleartext LAN service is not a
    /// fallback (H1 remainder closure). FR-143: the mesh lane's
    /// scheme is policy-decided (see HttpsOnlyDecision) — HTTPS
    /// with the device certificate while connections.https_only is
    /// on (the default), plain HTTP inside the mesh tunnel while
    /// off; loopback stays plain HTTP, exempt by name.</param>
    public LaneHostManager(McpHandler mcp, PairingHandler pairing, Func<IReadOnlySet<string>> approvedGates, int port,
        X509Certificate2? lanCertificate = null, MeshService? mesh = null, StreamService? stream = null,
        DeskGuest.Shared.QuickAssist.QuickAssistService? quickAssist = null,
        Func<HttpContext, string?>? meshIdentity = null,
        X509Certificate2? meshCertificate = null, Func<bool>? httpsOnly = null,
        Action<string, string?, string?>? onHttpsRefusal = null)
    {
        _mcp = mcp;
        _pairing = pairing;
        _approvedGates = approvedGates;
        _port = port;
        _lanCertificate = lanCertificate;
        _mesh = mesh;
        _stream = stream;
        _quickAssist = quickAssist;
        _meshIdentity = meshIdentity;
        _meshCertificate = meshCertificate;
        _httpsOnly = httpsOnly;
        _onHttpsRefusal = onHttpsRefusal;
    }

    /// <summary>FR-143: the current HTTPS-only policy state. An
    /// unwired host (unit rigs) reports OFF — CoreRuntime always
    /// wires the signed-policy callback, whose registry default
    /// is ON, so production enforcement is default-on.</summary>
    private bool HttpsOnly() => _httpsOnly?.Invoke() ?? false;

    /// <summary>BD-WIN-CORE-3/F1: the authenticated roster user id
    /// behind this mesh request, resolved ONCE per request through
    /// the host-wired pairing-channel identity. Null ⇒ the request
    /// is unauthenticated and every mesh verb fails closed.</summary>
    private string? AuthenticatedMeshUser(HttpContext http)
    {
        if (http.Items.TryGetValue("deskguest-mesh-user", out var cached)) return cached as string;
        var user = _meshIdentity?.Invoke(http);
        http.Items["deskguest-mesh-user"] = user;
        return user;
    }

    /// <summary>A mesh request is authorized ONLY when it carries
    /// an authenticated mesh identity (fail closed).</summary>
    private bool MeshAuthorized(HttpContext http) => AuthenticatedMeshUser(http) is not null;

    private static async Task MeshUnauthorized(HttpContext http)
    {
        http.Response.StatusCode = 401;
        http.Response.ContentType = "application/json";
        await http.Response.WriteAsync("{\"error\":\"mesh authentication required — the mesh lanes fail closed until the client presents a paired mesh credential\"}", http.RequestAborted);
    }

    public IReadOnlyCollection<string> RunningLanes => _hosts.Keys.ToList();

    public async Task<bool> StartLaneAsync(string laneName, string address, CancellationToken ct)
    {
        await _gate.WaitAsync(ct);
        try
        {
            if (_hosts.ContainsKey(laneName)) return true;
            var isLan = laneName == nameof(LaneKind.Lan);
            if (isLan && _lanCertificate is null)
                return false; // no certificate, no LAN lane — never cleartext
            // FR-143: the scheme decision is pure and pinned
            // (HttpsOnlyDecision). The mesh lane's certificate is
            // the dedicated mesh cert when wired, else the LAN
            // cert — CoreRuntime passes the one device certificate
            // for both. Enforcement ON with no certificate at all
            // REFUSES the lane (fail closed), never cleartext.
            var meshCert = _meshCertificate ?? _lanCertificate;
            var transport = HttpsOnlyDecision.TransportFor(laneName, HttpsOnly(), meshCert is not null);
            if (transport == LaneTransport.RefuseStart)
                return false; // policy demands HTTPS; no certificate — no lane
            var useTls = transport == LaneTransport.Https;
            var tlsCert = isLan ? _lanCertificate! : meshCert!;
            var builder = WebApplication.CreateSlimBuilder();
            builder.Logging.ClearProviders();
            // C18 destruction pass (header leakage): no Server
            // fingerprint header on any lane response — the front
            // door must not advertise the stack, and neither should
            // the rest of the surface.
            builder.WebHost.ConfigureKestrel(kestrel => kestrel.AddServerHeader = false);
            if (useTls)
            {
                builder.WebHost.UseUrls($"https://{address}:{_port}");
                builder.WebHost.ConfigureKestrel(kestrel =>
                    kestrel.ConfigureEndpointDefaults(listen =>
                        listen.UseHttps(tlsCert)));
            }
            else
            {
                builder.WebHost.UseUrls($"http://{address}:{_port}");
            }
            var app = builder.Build();
            // /pair is mapped only on the tailnet + loopback lanes: the
            // LAN lane serves paired traffic but never mints pairings —
            // a pairing code is exchanged inside the tunnel or not at
            // all (second-inspector H1).
            MapEndpoints(app, allowPairing: laneName != "Lan", laneName: laneName);
            await app.StartAsync(ct);
            _hosts[laneName] = app;
            return true;
        }
        catch
        {
            return false; // bind failure is a supervisor input, not a crash
        }
        finally { _gate.Release(); }
    }

    public async Task StopLaneAsync(string laneName)
    {
        await _gate.WaitAsync();
        try
        {
            if (_hosts.Remove(laneName, out var app))
            {
                try { await app.StopAsync(); } catch { }
                await app.DisposeAsync();
            }
        }
        finally { _gate.Release(); }
    }

    private void MapEndpoints(WebApplication app, bool allowPairing, string laneName = "")
    {
        // FR-143 defence in depth: the bind-time scheme decision
        // (StartLaneAsync) is the authority, but a policy flip can
        // land while a plain-HTTP lane is still bound (the rebind
        // follows on the Core's next lane tick). In that window —
        // and only there — a plain-HTTP request on a non-loopback
        // lane meets this guard: a NAMED refusal, reported through
        // the host's refusal sink (hash-chained audit + narration),
        // never a silent drop. Loopback is exempt by name.
        app.Use(async (http, next) =>
        {
            if (HttpsOnlyDecision.RefusePlainHttp(laneName, http.Request.IsHttps, HttpsOnly()))
            {
                _onHttpsRefusal?.Invoke(laneName, http.Connection.RemoteIpAddress?.ToString(), http.Request.Path.Value);
                http.Response.StatusCode = 403;
                http.Response.ContentType = "application/json";
                await http.Response.WriteAsync(
                    "{\"error\":\"https_required: this device requires HTTPS for agent connections (policy connections.https_only.enabled) — plain HTTP is refused; connect over HTTPS and check the certificate against the pin from your pairing\"}",
                    http.RequestAborted);
                return;
            }
            await next();
        });
        // W97 / S09(b): this lane's rung id, handed to every
        // handler below — the connection-path policy can only be
        // enforced where the arrival path is KNOWN, and this is
        // the one place it is known by construction (one
        // WebApplication per lane).
        var arrivalRung = ConnectionPathPolicy.RungForLane(laneName);
        // U2: the agent event stream — GET /mcp with an SSE Accept
        // header and the pairing's bearer token. Auth, STOP and the
        // per-pairing filter/origin rules are enforced inside
        // McpHandler.HandleEventStreamAsync; a refusal happens
        // before any byte is written, so it can still answer 401.
        app.MapGet("/mcp", async (HttpContext http) =>
        {
            if (!http.Request.Headers.Accept.ToString().Contains("text/event-stream", StringComparison.OrdinalIgnoreCase))
            {
                http.Response.StatusCode = 404;
                return;
            }
            http.Response.ContentType = "text/event-stream";
            http.Response.Headers.CacheControl = "no-cache";
            var lastEventId = long.TryParse(http.Request.Headers["Last-Event-ID"].ToString(), out var lei) ? lei : 0;
            var ok = await _mcp.HandleEventStreamAsync(
                http.Request.Headers.Authorization.ToString(),
                async (chunk, ct) =>
                {
                    await http.Response.WriteAsync(chunk, ct);
                    await http.Response.Body.FlushAsync(ct);
                },
                http.RequestAborted, lastEventId, arrivalRung);
            if (!ok && !http.Response.HasStarted) http.Response.StatusCode = 401;
        });
        app.MapPost("/mcp", async (HttpContext http) =>
        {
            using var reader = new StreamReader(http.Request.Body);
            var body = await reader.ReadToEndAsync(http.RequestAborted);
            var response = await _mcp.HandleAsync(body, http.Request.Headers.Authorization.ToString(), _approvedGates(), http.RequestAborted, arrivalRung);
            http.Response.StatusCode = response.HttpStatus;
            if (response.Json is not null)
            {
                http.Response.ContentType = "application/json";
                await http.Response.WriteAsync(response.Json, http.RequestAborted);
            }
        });
        if (allowPairing) app.MapPost("/pair", async (HttpContext http) =>
        {
            using var reader = new StreamReader(http.Request.Body);
            var body = await reader.ReadToEndAsync(http.RequestAborted);
            var (status, json) = _pairing.Handle(body, http.Connection.RemoteIpAddress?.ToString(), arrivalRung);
            http.Response.StatusCode = status;
            http.Response.ContentType = "application/json";
            await http.Response.WriteAsync(json, http.RequestAborted);
        });
        app.MapGet("/healthz", () => Results.Json(new { service = "DeskGuest-Windows Core", status = "up" }));
        // Mesh companion routes (M2): tailnet + loopback lanes only —
        // the same lanes that may mint pairings. The LAN lane never
        // serves them. BD-WIN-CORE-3/F1: lane placement is NOT
        // authentication — every mesh verb additionally fails
        // closed (401) until a paired mesh credential validator is
        // wired and accepts the request (see MapMesh).
        if (allowPairing && _mesh is not null) MapMesh(app);
    }

    private void MapMesh(WebApplication app)
    {
        var mesh = _mesh!;
        // BD-WIN-CORE-3/F1: EVERY v1 mesh verb is gated — state
        // leaks session facts, preview captures the screen, input
        // drives it, and heartbeat/handoff/disconnect mutate the
        // manual-control claim. Unauthenticated ⇒ 401, fail closed.
        app.MapGet("/mesh/state", async (HttpContext http) => { if (!MeshAuthorized(http)) { await MeshUnauthorized(http); return; } await WriteAsync(http, mesh.GetState()); });
        app.MapGet("/mesh/preview", async (HttpContext http) => { if (!MeshAuthorized(http)) { await MeshUnauthorized(http); return; } await WriteAsync(http, await mesh.GetPreviewAsync(http.RequestAborted)); });
        app.MapPost("/mesh/input", async (HttpContext http) =>
        {
            if (!MeshAuthorized(http)) { await MeshUnauthorized(http); return; }
            using var reader = new StreamReader(http.Request.Body);
            var body = await reader.ReadToEndAsync(http.RequestAborted);
            await WriteAsync(http, await mesh.PostInputAsync(body, http.RequestAborted));
        });
        app.MapPost("/mesh/handoff", async (HttpContext http) => { if (!MeshAuthorized(http)) { await MeshUnauthorized(http); return; } await WriteAsync(http, mesh.PostHandoff()); });
        app.MapPost("/mesh/disconnect", async (HttpContext http) => { if (!MeshAuthorized(http)) { await MeshUnauthorized(http); return; } await WriteAsync(http, mesh.PostDisconnect()); });
        app.MapPost("/mesh/heartbeat", async (HttpContext http) =>
        {
            if (!MeshAuthorized(http)) { await MeshUnauthorized(http); return; }
            using var reader = new StreamReader(http.Request.Body);
            var body = await reader.ReadToEndAsync(http.RequestAborted);
            await WriteAsync(http, mesh.PostHeartbeat(body));
        });
        // Session stream (Block D, mesh contract v2 — additive; the
        // v1 verbs above are unchanged). Same lanes as the rest of
        // the mesh: tailnet + loopback only, never the LAN lane.
        if (_stream is not null)
        {
            var stream = _stream;
            // BD-WIN-CORE-3/F1: the stream routes carry the SAME
            // route gate as the v1 verbs (info included — it leaks
            // session facts), and the authenticated identity (never
            // a body-typed userId) is handed to StreamService, whose
            // participant + floor checks remain the second wall.
            app.MapPost("/mesh/stream/start", async (HttpContext http) =>
            {
                if (!MeshAuthorized(http)) { await MeshUnauthorized(http); return; }
                using var reader = new StreamReader(http.Request.Body);
                var body = await reader.ReadToEndAsync(http.RequestAborted);
                await WriteAsync(http, await stream.StartAsync(body, AuthenticatedMeshUser(http), http.RequestAborted));
            });
            app.MapPost("/mesh/stream/stop", async (HttpContext http) =>
            {
                if (!MeshAuthorized(http)) { await MeshUnauthorized(http); return; }
                using var reader = new StreamReader(http.Request.Body);
                var body = await reader.ReadToEndAsync(http.RequestAborted);
                await WriteAsync(http, await stream.StopAsync(body, AuthenticatedMeshUser(http), http.RequestAborted));
            });
            app.MapGet("/mesh/stream/info", async (HttpContext http) =>
            {
                if (!MeshAuthorized(http)) { await MeshUnauthorized(http); return; }
                await WriteAsync(http, await stream.GetInfoAsync(http.Request.Query["sessionId"].ToString() is { Length: > 0 } sid ? sid : null, http.RequestAborted));
            });
            app.MapGet("/mesh/stream/frame", async (HttpContext http) =>
            {
                if (!MeshAuthorized(http)) { await MeshUnauthorized(http); return; }
                long.TryParse(http.Request.Query["after"].ToString(), out var after);
                await WriteAsync(http, await stream.GetFrameAsync(http.Request.Query["sessionId"].ToString(), after, AuthenticatedMeshUser(http), http.RequestAborted));
            });
            app.MapPost("/mesh/stream/input", async (HttpContext http) =>
            {
                if (!MeshAuthorized(http)) { await MeshUnauthorized(http); return; }
                using var reader = new StreamReader(http.Request.Body);
                var body = await reader.ReadToEndAsync(http.RequestAborted);
                await WriteAsync(http, await stream.PostInputAsync(body, AuthenticatedMeshUser(http), http.RequestAborted));
            });
        }
        // Quick assist (Block F, D24): the web front door's
        // handshake. Same lanes as the rest of the mesh (tailnet +
        // loopback, never the LAN lane). Redeem consumes a session
        // code and issues a VIEW-ONLY grant bound to the redeeming
        // side's client binding — the browser side is view-only by
        // platform law, and the grant itself can never carry
        // control (QuickAssistService.GrantViewOnly).
        if (_quickAssist is not null)
        {
            var qa = _quickAssist;
            // C18: the front door itself, served by the endpoint on
            // these same lanes (tailnet + loopback, never LAN). No
            // auth — the page holds no secrets and grants nothing;
            // the redeem POST below remains the only gate. Serving is
            // QuickAssistWeb's exact-path allowlist over the two
            // embedded repo files: no static-file middleware, no
            // directory surface, and a refusal is a bare status with
            // an empty body (no state, no hints about what exists).
            var webHandler = async (HttpContext http) =>
            {
                if (QuickAssistWeb.TryServe(http.Request.Method, http.Request.Path.Value, out var status, out var asset))
                {
                    http.Response.StatusCode = status;
                    http.Response.ContentType = asset!.ContentType;
                    foreach (var (name, value) in QuickAssistWeb.ResponseHeaders)
                        http.Response.Headers[name] = value;
                    await http.Response.Body.WriteAsync(asset.Body, http.RequestAborted);
                }
                else
                {
                    http.Response.StatusCode = status;
                }
            };
            app.MapGet("/quickassist", webHandler);
            app.MapGet("/quickassist/{**path}", webHandler);
            app.MapPost("/mesh/quickassist/redeem", async (HttpContext http) =>
            {
                using var reader = new StreamReader(http.Request.Body);
                var body = await reader.ReadToEndAsync(http.RequestAborted);
                string? code = null, binding = null;
                try
                {
                    using var doc = System.Text.Json.JsonDocument.Parse(body);
                    if (doc.RootElement.TryGetProperty("code", out var c)) code = c.GetString();
                    if (doc.RootElement.TryGetProperty("clientBinding", out var b)) binding = b.GetString();
                }
                catch { /* malformed JSON refuses below */ }
                var (ok, detail, grant, token) = qa.Redeem(code, binding ?? "", DateTimeOffset.UtcNow);
                http.Response.StatusCode = ok ? 200 : 403;
                http.Response.ContentType = "application/json";
                await http.Response.WriteAsync(System.Text.Json.JsonSerializer.Serialize(new
                {
                    ok, detail,
                    grantId = grant?.GrantId, grantToken = token, viewOnly = grant?.ViewOnly,
                    scopeId = grant?.ScopeId, hostDeviceId = grant?.HostDeviceId,
                    expiresUtc = grant?.ExpiresUtc,
                }), http.RequestAborted);
            });
            app.MapPost("/mesh/quickassist/close", async (HttpContext http) =>
            {
                // BD-WIN-CORE-3/F1: closing a session is a control
                // act — an id alone is not authority. Two authorities
                // are accepted: (a) the mesh credential, as for the
                // other mesh verbs; or (b) BD-ENTERPRISE-DOCS F2 —
                // the redeeming web client itself, proving possession
                // of the one-time grant token + its client binding
                // (the browser holds no mesh bearer; a copied grant
                // id alone still closes nothing).
                using var reader = new StreamReader(http.Request.Body);
                var body = await reader.ReadToEndAsync(http.RequestAborted);
                string? id = null, token = null, binding = null;
                try
                {
                    using var doc = System.Text.Json.JsonDocument.Parse(body);
                    if (doc.RootElement.TryGetProperty("id", out var v)) id = v.GetString();
                    if (doc.RootElement.TryGetProperty("token", out var t)) token = t.GetString();
                    if (doc.RootElement.TryGetProperty("clientBinding", out var b)) binding = b.GetString();
                }
                catch { }
                bool closed;
                if (MeshAuthorized(http))
                {
                    closed = id is not null && qa.Close(id);
                }
                else if (id is not null && token is not null && binding is not null)
                {
                    var (okClose, _) = qa.CloseWithBinding(id, token, binding, DateTimeOffset.UtcNow);
                    closed = okClose;
                }
                else
                {
                    await MeshUnauthorized(http); return;
                }
                http.Response.StatusCode = closed ? 200 : 404;
                http.Response.ContentType = "application/json";
                await http.Response.WriteAsync(System.Text.Json.JsonSerializer.Serialize(new { ok = closed }), http.RequestAborted);
            });
        }

        static async Task WriteAsync(HttpContext http, MeshReply reply)
        {
            http.Response.StatusCode = reply.Status;
            http.Response.ContentType = reply.ContentType;
            await http.Response.Body.WriteAsync(reply.Body, http.RequestAborted);
        }
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var lane in _hosts.Keys.ToList()) await StopLaneAsync(lane);
        _gate.Dispose();
    }
}
