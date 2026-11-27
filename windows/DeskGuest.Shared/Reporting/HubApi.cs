using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DeskGuest.Shared.Enterprise;

namespace DeskGuest.Shared.Reporting;

// =====================================================================
// RMM-13 — The hub's documented local API, formalised.
//
// The hub's existing authenticated surface (pairing-bearer MCP +
// mesh state) is the pattern; this is its fleet-facts form:
//   * VERSIONED: every path lives under /api/v1/. An unknown
//     version or path refuses by name (404), never guesses.
//   * READ-MOSTLY BY SHAPE: the catalogue contains NO mutating
//     endpoint. A non-GET request to any catalogue path is refused
//     405 — state changes on the hub go through the existing
//     governed surfaces (signed commands, approvals), never the
//     reporting API. Key management is a hub-admin act performed
//     through the service, NOT an API endpoint.
//   * KEYS ARE HUB-ISSUED, SCOPED, REVOCABLE, AUDITED PER CALL:
//     the store keeps only the SHA-256 hash of each secret (the
//     plaintext is shown once, at issuance, by the service);
//     scopes are a closed set and every endpoint names the scope
//     it requires; revocation is immediate; expiry is honoured.
//     Every dispatch — accepted or refused — yields an ApiCallRecord
//     the service writes to the chained audit BEFORE the caller
//     sees a result (the McpHandler discipline).
// =====================================================================

/// <summary>The closed set of API scopes. A key holding a scope may
/// read exactly the endpoints that name it — nothing is implied:
/// `reports.read` does not grant `audit.read`.</summary>
public static class HubApiScopes
{
    public const string ReportsRead = "reports.read";
    public const string FleetRead = "fleet.read";
    public const string AuditRead = "audit.read";

    public static readonly IReadOnlySet<string> All = new HashSet<string> { ReportsRead, FleetRead, AuditRead };
}

/// <summary>One hub-issued API key. Only the secret's hash is ever
/// stored; the record names its scopes, its issuer, and its life
/// (expiry + revocation) on its face.</summary>
public sealed record HubApiKey(
    string KeyId,
    string SecretHash,
    IReadOnlySet<string> Scopes,
    string IssuedBy,
    DateTimeOffset IssuedUtc,
    DateTimeOffset? ExpiresUtc,
    bool Revoked,
    DateTimeOffset? RevokedUtc,
    string ScopeId = "")
{
    public IReadOnlySet<string> Scopes { get; init; } = Scopes ?? new HashSet<string>();

    public bool IsLive(DateTimeOffset now) =>
        !Revoked && (ExpiresUtc is null || ExpiresUtc.Value > now);
}

/// <summary>The key store. Issuance takes the plaintext secret ONCE
/// (the service generates it and shows it to the admin once) and
/// keeps only its hash. Authentication hashes the presented secret
/// and compares in fixed time against every live key — an unknown,
/// revoked, or expired secret authenticates as NOTHING.</summary>
public sealed class HubApiKeyStore
{
    private readonly Dictionary<string, HubApiKey> _keys = new(StringComparer.Ordinal);
    private readonly object _gate = new();

    public static string HashSecret(string secret) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(secret ?? ""))).ToLowerInvariant();

    public static string NewKeyId() =>
        "key-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant();

    public static string NewSecret() =>
        "deskguest_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(24)).ToLowerInvariant();

    public IReadOnlyList<HubApiKey> Keys
    {
        get { lock (_gate) return _keys.Values.OrderBy(k => k.KeyId, StringComparer.Ordinal).ToList(); }
    }

    /// <summary>Issue a key. Refusals (returned, never thrown):
    /// empty identity/issuer, no scopes, a scope outside the closed
    /// set, a past expiry, a duplicate key id.</summary>
    public (bool Ok, string Reason, HubApiKey? Key) Issue(string keyId, string secret,
        IReadOnlySet<string> scopes, string issuedBy, DateTimeOffset now, DateTimeOffset? expiresUtc = null,
        string scopeId = "")
    {
        if (string.IsNullOrWhiteSpace(keyId)) return (false, "api key needs an id — refused", null);
        if (string.IsNullOrWhiteSpace(secret) || secret.Length < 16)
            return (false, "api key secret must be at least 16 characters — refused", null);
        // D38-F12: Issue used to hash the secret as given while
        // Authenticate trimmed first — a secret issued with
        // surrounding whitespace could never authenticate. Refuse
        // it by name instead of minting a dead key.
        if (!string.Equals(secret, secret.Trim(), StringComparison.Ordinal))
            return (false, "api key secret carries surrounding whitespace — refused (it would never authenticate as issued)", null);
        if (string.IsNullOrWhiteSpace(issuedBy)) return (false, "api key needs an issuing admin — refused", null);
        if (scopes is null || scopes.Count == 0) return (false, "api key needs at least one scope — refused (a scopeless key reads nothing, so it is never issued)", null);
        var bad = scopes.FirstOrDefault(s => !HubApiScopes.All.Contains(s));
        if (bad is not null) return (false, $"api key names unknown scope '{bad}' — refused", null);
        if (expiresUtc is { } exp && exp <= now) return (false, "api key expiry is not in the future — refused", null);
        lock (_gate)
        {
            if (_keys.ContainsKey(keyId)) return (false, $"api key id '{keyId}' already exists — refused", null);
            var key = new HubApiKey(keyId, HashSecret(secret),
                new HashSet<string>(scopes, StringComparer.Ordinal), issuedBy.Trim(), now, expiresUtc, false, null,
                (scopeId ?? "").Trim());
            _keys[keyId] = key;
            return (true, $"api key '{keyId}' issued to scopes [{string.Join(",", key.Scopes.OrderBy(s => s, StringComparer.Ordinal))}]", key);
        }
    }

    /// <summary>Revoke a key: immediate and permanent (a revoked key
    /// is never un-revoked; a replacement is a new issuance).</summary>
    public (bool Ok, string Reason) Revoke(string keyId, DateTimeOffset now)
    {
        lock (_gate)
        {
            if (!_keys.TryGetValue(keyId ?? "", out var key)) return (false, $"unknown api key '{keyId}' — nothing to revoke");
            if (key.Revoked) return (false, $"api key '{keyId}' is already revoked");
            _keys[keyId] = key with { Revoked = true, RevokedUtc = now };
            return (true, $"api key '{keyId}' revoked — it authenticates nothing from this instant");
        }
    }

    /// <summary>Authenticate a presented secret. Returns the live
    /// key or null. Comparison is fixed-time over the hash.</summary>
    public HubApiKey? Authenticate(string? presentedSecret, DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(presentedSecret)) return null;
        var presented = HashSecret(presentedSecret.Trim());
        lock (_gate)
        {
            // D38-F12: compare against EVERY live key with no early
            // return — the matched key's position in the store must
            // not leak through timing.
            HubApiKey? matched = null;
            foreach (var key in _keys.Values)
            {
                if (!key.IsLive(now)) continue;
                if (CryptographicOperations.FixedTimeEquals(
                        Encoding.ASCII.GetBytes(presented), Encoding.ASCII.GetBytes(key.SecretHash)))
                    matched = key;
            }
            return matched;
        }
    }

    public HubApiKey? Get(string keyId)
    {
        lock (_gate) return _keys.TryGetValue(keyId ?? "", out var k) ? k : null;
    }
}

/// <summary>One documented endpoint. RequiredScope is named on the
/// descriptor itself — the catalogue IS the documentation: method,
/// path, version, the auth it demands, and the fact that it does
/// not mutate state.</summary>
public sealed record HubApiEndpoint(
    string Id, string Method, string PathTemplate, string Version,
    string RequiredScope, bool MutatesState, string Description);

/// <summary>The v1 catalogue. Every endpoint is a GET; MutatesState
/// is false for all of them, and the dispatcher's catalogue check
/// refuses to serve any descriptor that claims otherwise.</summary>
public static class HubApiCatalogue
{
    public const string Version = "v1";
    public const string BasePath = "/api/v1";

    public static readonly IReadOnlyList<HubApiEndpoint> Endpoints = new[]
    {
        new HubApiEndpoint("reports.get", "GET", "/api/v1/reports/{kind}", Version, HubApiScopes.ReportsRead, false,
            "One report (fleet_health | patch_compliance | inventory_lifecycle | backup_status | audit_summary | vulnerability_posture) as JSON, with provenance + staleness on its face. Query: ?format=json|csv|text (default json)."),
        new HubApiEndpoint("reports.list", "GET", "/api/v1/reports", Version, HubApiScopes.ReportsRead, false,
            "The report kinds this hub serves, with each kind's data sources named."),
        new HubApiEndpoint("fleet.health", "GET", "/api/v1/fleet/health", Version, HubApiScopes.FleetRead, false,
            "Current per-device health views from the RMM-01 hub ingest (state, last report, firing conditions)."),
        new HubApiEndpoint("fleet.devices", "GET", "/api/v1/fleet/devices", Version, HubApiScopes.FleetRead, false,
            "The hub's inventory records (RMM-04) as last reported — no live probing is performed by this endpoint."),
        new HubApiEndpoint("audit.summary", "GET", "/api/v1/audit/summary", Version, HubApiScopes.AuditRead, false,
            "Audit-ledger summary: entry counts by kind + the chain verification verdict. A broken chain reports BROKEN here, never OK."),
        new HubApiEndpoint("api.catalogue", "GET", "/api/v1/catalogue", Version, HubApiScopes.ReportsRead, false,
            "This catalogue: every endpoint, its required scope, and its read-only nature."),
    };

    public static HubApiEndpoint? Find(string id) =>
        Endpoints.FirstOrDefault(e => e.Id == id);
}

/// <summary>The per-call audit record. EVERY dispatch produces one
/// — including 401s (key id "(unauthenticated)") — and the service
/// appends it to the chained ledger.</summary>
public sealed record ApiCallRecord(
    string KeyId, string Method, string Path, string EndpointId, int Status, string Detail, DateTimeOffset AtUtc);

public sealed record ApiResponse(int Status, string BodyJson, ApiCallRecord Record);

/// <summary>The data surface the dispatcher serves. Implementations
/// return report/export payloads; they hold no key material and no
/// mutation path — the interface itself is the read-only proof.</summary>
public interface IHubApiData
{
    /// <summary>A rendered report export (format already applied),
    /// or null when the kind is unknown. <paramref name="scopeId"/>
    /// is the scope the CALLER'S KEY was issued under (D38-F8):
    /// the data served is built for that scope, never hub-global
    /// data gated only by the caller's own facts.</summary>
    string? ReportExport(string kind, string format, string scopeId, DateTimeOffset now);
    string FleetHealthJson(string scopeId, DateTimeOffset now);
    string FleetDevicesJson(string scopeId, DateTimeOffset now);
    string AuditSummaryJson(string scopeId, DateTimeOffset now);
}

/// <summary>The dispatcher: auth → catalogue → scope → data. Pure
/// request-in/response-out (the HTTP adapter is hub wiring); every
/// outcome is a named status + an audit record.</summary>
public sealed class HubApiDispatcher
{
    private readonly HubApiKeyStore _keys;
    private readonly IHubApiData _data;

    public HubApiDispatcher(HubApiKeyStore keys, IHubApiData data)
    {
        _keys = keys ?? throw new ArgumentNullException(nameof(keys));
        _data = data ?? throw new ArgumentNullException(nameof(data));
    }

    public ApiResponse Dispatch(string? method, string? rawPath, string? presentedSecret, DateTimeOffset now)
    {
        var m = (method ?? "").Trim().ToUpperInvariant();
        var path = (rawPath ?? "").Trim();
        var query = "";
        var q = path.IndexOf('?');
        if (q >= 0) { query = path[(q + 1)..]; path = path[..q]; }
        if (path.Length > 1) path = path.TrimEnd('/');

        ApiResponse Done(int status, string body, HubApiKey? key, string endpointId, string detail) =>
            new(status, body, new ApiCallRecord(key?.KeyId ?? "(unauthenticated)", m, path, endpointId, status, detail, now));

        string Err(int code, string message) => JsonSerializer.Serialize(new { error = message });

        // Version gate: anything outside /api/v1/ is not this API.
        if (!path.StartsWith(HubApiCatalogue.BasePath + "/", StringComparison.Ordinal) &&
            path != HubApiCatalogue.BasePath)
            return Done(404, Err(404, $"path '{path}' is not part of the hub API (this hub serves {HubApiCatalogue.BasePath})"),
                null, "(none)", "unknown path/version");

        // Authenticate BEFORE route semantics leak: an unauthenticated
        // caller learns only that it is unauthenticated.
        var key = _keys.Authenticate(presentedSecret, now);
        if (key is null)
            return Done(401, Err(401, "unauthorized: a valid, unrevoked hub API key is required"),
                null, "(none)", "authentication failed (unknown, revoked, or expired key)");

        // Route.
        string? endpointId = null;
        string? reportKind = null;
        if (path == "/api/v1/reports") endpointId = "reports.list";
        else if (path == "/api/v1/catalogue") endpointId = "api.catalogue";
        else if (path == "/api/v1/fleet/health") endpointId = "fleet.health";
        else if (path == "/api/v1/fleet/devices") endpointId = "fleet.devices";
        else if (path == "/api/v1/audit/summary") endpointId = "audit.summary";
        else if (path.StartsWith("/api/v1/reports/", StringComparison.Ordinal))
        {
            endpointId = "reports.get";
            reportKind = path["/api/v1/reports/".Length..];
        }
        if (endpointId is null)
            return Done(404, Err(404, $"no such endpoint: {m} {path}"), key, "(none)", "unknown endpoint");

        var endpoint = HubApiCatalogue.Find(endpointId)!;
        // Read-mostly by shape: the catalogue holds no mutating
        // endpoint, and a non-GET verb is refused even on a real path.
        if (endpoint.MutatesState)
            return Done(500, Err(500, "catalogue defect: a mutating endpoint was served by the reporting API"), key, endpointId, "catalogue defect");
        if (m != endpoint.Method)
            return Done(405, Err(405, $"method {m} refused: {endpoint.PathTemplate} is {endpoint.Method} only — the reporting API does not change hub state"),
                key, endpointId, "method refused (read-only API)");

        if (!key.Scopes.Contains(endpoint.RequiredScope))
            return Done(403, Err(403, $"forbidden: endpoint requires scope '{endpoint.RequiredScope}', which this key does not hold"),
                key, endpointId, $"scope refused (requires {endpoint.RequiredScope})");

        var format = QueryValue(query, "format") ?? ReportExportFormats.Json;
        if (!ReportExportFormats.All.Contains(format))
            return Done(400, Err(400, $"unknown format '{format}' — formats are json, csv, text"), key, endpointId, "bad format");

        string body;
        switch (endpointId)
        {
            case "reports.list":
                body = JsonSerializer.Serialize(new
                {
                    version = HubApiCatalogue.Version,
                    kinds = ReportKinds.All.OrderBy(k => k, StringComparer.Ordinal).ToArray(),
                });
                break;
            case "api.catalogue":
                body = JsonSerializer.Serialize(HubApiCatalogue.Endpoints.Select(e => new
                {
                    id = e.Id, method = e.Method, path = e.PathTemplate, version = e.Version,
                    requiredScope = e.RequiredScope, mutatesState = e.MutatesState, description = e.Description,
                }).ToArray());
                break;
            case "reports.get":
                if (!ReportKinds.All.Contains(reportKind ?? ""))
                    return Done(404, Err(404, $"unknown report kind '{reportKind}'"), key, endpointId, "unknown report kind");
                body = _data.ReportExport(reportKind!, format, key.ScopeId ?? "", now) ??
                    Err(500, "report unavailable");
                break;
            case "fleet.health": body = _data.FleetHealthJson(key.ScopeId ?? "", now); break;
            case "fleet.devices": body = _data.FleetDevicesJson(key.ScopeId ?? "", now); break;
            case "audit.summary": body = _data.AuditSummaryJson(key.ScopeId ?? "", now); break;
            default:
                return Done(404, Err(404, "unknown endpoint"), key, endpointId, "unknown endpoint");
        }
        return Done(200, body, key, endpointId, "ok");
    }

    private static string? QueryValue(string query, string name)
    {
        foreach (var pair in (query ?? "").Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = pair.IndexOf('=');
            if (eq > 0 && string.Equals(pair[..eq], name, StringComparison.OrdinalIgnoreCase))
                return Uri.UnescapeDataString(pair[(eq + 1)..]).Trim().ToLowerInvariant();
        }
        return null;
    }
}
