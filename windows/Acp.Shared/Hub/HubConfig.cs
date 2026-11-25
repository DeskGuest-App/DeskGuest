using System.Text;
using System.Text.RegularExpressions;

namespace Acp.Shared.Hub;

/// <summary>
/// ACP hub packaging — Headscale as an ACP-managed component (D27).
/// Pins, ACP-owned configuration, deny-by-default policy and the startup
/// self-check that together implement the binding conditions of the
/// Headscale security audit §8 (research/headscale-security-audit/REPORT.md)
/// for the packaged build. Nothing in this file shells out or touches the
/// network: it produces and verifies the artefacts the lifecycle runs.
/// </summary>
public static class HubPins
{
    /// <summary>Audit §8.1 — pin v0.29.7, never float.</summary>
    public const string HeadscaleVersion = "0.29.7";
    public const string HeadscaleCommit = "c9cf210b8bc84d13177e18b91f555788a44b47b6";
    /// <summary>HS-10 — official 0.29.7 binaries predate the Go 1.27.4 fix
    /// (CVE-2026-97054); ACP rebuilds from the pinned source with this
    /// toolchain floor instead of shipping the official binary.</summary>
    public const string MinGoToolchain = "1.27.4";
    public const string BuildGoToolchain = "1.27.4";
    /// <summary>FR-133 — SHA-256 of the rebuilt Windows amd64
    /// headscale.exe the deploy package stages (hub-component/
    /// PACKAGE-MANIFEST.md). HubLifecycle refuses to install or
    /// run a binary whose bytes differ from this pin: packaging
    /// places the pinned binary, the lifecycle proves it.</summary>
    public const string WindowsBinarySha256 =
        "0a64ea4cf96569cb69a12f589d47d057a2ac90aee3ffa6ae3bef0c1508b32dc8";
    /// <summary>Official release artefact, hash-verified at packaging time
    /// against the release checksums.txt (used for the Linux leak-observation
    /// run and as the provenance cross-check for the source tree).</summary>
    public const string OfficialLinuxAmd64Sha256 =
        "e827fc9b12d958bc95b081c4401dd63f8e0471d025b45b508535a920532150a8";
    /// <summary>HS-03 — the client floor Headscale itself cannot enforce.</summary>
    public const string MinTailscaleClient = "1.104.4";
    /// <summary>HS-02 — API keys are root; ACP caps their lifetime.</summary>
    public static readonly TimeSpan MaxApiKeyLifetime = TimeSpan.FromDays(90);
    /// <summary>Audit §8.6 — pre-auth keys are single-use, ≤1 h by default.</summary>
    public static readonly TimeSpan MaxPreAuthKeyLifetime = TimeSpan.FromHours(1);
}

/// <summary>Everything the hub needs to stand up, in ACP terms. All paths
/// live under the ACP-managed component home (D41: everything in its home).</summary>
public sealed record HubOptions
{
    /// <summary>Component home: binary, config, policy, data all live here.</summary>
    public required string ComponentHome { get; init; }
    /// <summary>Public URL clients use. Must be https (audit §8.2) unless
    /// <see cref="AllowLoopbackHttpDev"/> is set for a loopback-only dev hub.</summary>
    public required string ServerUrl { get; init; }
    public string ListenAddr { get; init; } = "127.0.0.1:8085";
    public string GrpcListenAddr { get; init; } = "127.0.0.1:50443";
    /// <summary>Empty = metrics/debug listener OFF (audit §8.2, HS-08).
    /// A non-empty value must be loopback; the validator refuses otherwise.</summary>
    public string MetricsListenAddr { get; init; } = "";
    public string StunListenAddr { get; init; } = "0.0.0.0:3478";
    public string BaseDomain { get; init; } = "acp.internal";
    public string TlsCertPath { get; init; } = "";
    public string TlsKeyPath { get; init; } = "";
    /// <summary>Dev escape hatch: permits an http:// server_url ONLY when it
    /// is loopback. Never set in a shipped scope.</summary>
    public bool AllowLoopbackHttpDev { get; init; } = false;
    /// <summary>The HS-01 escape hatch: an admin may explicitly opt into an
    /// allow-all compiled policy. Default false; the self-check refuses to
    /// serve an allow-all policy without it.</summary>
    public bool AllowAllPolicyOptIn { get; init; } = false;
    public HubOidcOptions? Oidc { get; init; }
    /// <summary>BD-SHARED-TRANSPORT F11: the SHA-256 the packaged
    /// hub binary must carry (per-platform pin, recorded by the
    /// packaging step from the rebuilt-from-pinned-source binary).
    /// When set, Install/Start/Update verify the binary against
    /// it and refuse on mismatch. When null the lifecycle cannot
    /// verify — HubLifecycle surfaces that as an explicit
    /// UnverifiedBinary state note, never as a silent pass.</summary>
    public string? BinarySha256 { get; init; }

    public string ConfigPath => Path.Combine(ComponentHome, "config.yaml");
    public string PolicyPath => Path.Combine(ComponentHome, "policy.json");
    public string DataDir => Path.Combine(ComponentHome, "data");
    public string DbPath => Path.Combine(DataDir, "db.sqlite");
    public string NoiseKeyPath => Path.Combine(DataDir, "noise_private.key");
    public string DerpKeyPath => Path.Combine(DataDir, "derp_server_private.key");
    public string SocketPath => Path.Combine(DataDir, "headscale.sock");
    public string BinaryPath => Path.Combine(ComponentHome,
        OperatingSystem.IsWindows() ? "headscale.exe" : "headscale");
}

public sealed record HubOidcOptions
{
    public required string Issuer { get; init; }
    public required string ClientId { get; init; }
    /// <summary>Path to a file holding the client secret — the secret itself
    /// never appears in ACP-generated config text.</summary>
    public required string ClientSecretPath { get; init; }
    public IReadOnlyList<string> AllowedDomains { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> AllowedGroups { get; init; } = Array.Empty<string>();
}

/// <summary>A single §8 condition violation found in a config/policy pair.</summary>
public sealed record HubViolation(string Condition, string Detail);

public sealed class HubRefusalException : Exception
{
    public IReadOnlyList<HubViolation> Violations { get; }
    public HubRefusalException(IReadOnlyList<HubViolation> violations)
        : base("Hub refused: " + string.Join("; ", violations.Select(v => v.Condition + " — " + v.Detail)))
        => Violations = violations;
}

/// <summary>Generates ACP's own Headscale config (never the example) and
/// validates any config text against every §8.2/§8.8 condition.</summary>
public static class HubConfig
{
    /// <summary>Paths inside the component home are emitted RELATIVE to
    /// the config file's directory: Headscale resolves relative paths
    /// against the config location (its documented behavior), while an
    /// absolute Windows path is misjudged as relative by its resolver and
    /// joined onto the config dir — proven live on the reference laptop
    /// 2026-11-19 (hub refused to start: "…\data-home\C:\…\noise_private.key").
    /// Forward slashes are used for the relative form (Go accepts them on
    /// Windows).</summary>
    private static string ConfigPath(HubOptions o, string absolute)
    {
        var home = o.ComponentHome.Replace('\\', '/').TrimEnd('/');
        var path = absolute.Replace('\\', '/');
        return path.StartsWith(home + "/", StringComparison.OrdinalIgnoreCase)
            ? path[(home.Length + 1)..]
            : absolute;
    }

    public static string Generate(HubOptions o)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# ACP-managed Headscale config — generated by ACP hub packaging.");
        sb.AppendLine("# Audit: research/headscale-security-audit/REPORT.md §8 conditions.");
        sb.AppendLine($"# Headscale pinned v{HubPins.HeadscaleVersion} commit {HubPins.HeadscaleCommit}.");
        sb.AppendLine($"server_url: {o.ServerUrl}");
        sb.AppendLine($"listen_addr: {o.ListenAddr}");
        // HS-08: metrics/debug off unless explicitly loopback.
        sb.AppendLine(string.IsNullOrEmpty(o.MetricsListenAddr)
            ? "metrics_listen_addr: \"\""
            : $"metrics_listen_addr: {o.MetricsListenAddr}");
        sb.AppendLine($"grpc_listen_addr: {o.GrpcListenAddr}");
        sb.AppendLine("grpc_allow_insecure: false");
        sb.AppendLine("noise:");
        sb.AppendLine($"  private_key_path: {ConfigPath(o, o.NoiseKeyPath)}");
        sb.AppendLine("prefixes:");
        sb.AppendLine("  v4: 100.64.0.0/10");
        sb.AppendLine("  v6: fd7a:115c:a1e0::/48");
        sb.AppendLine("  allocation: sequential");
        sb.AppendLine("derp:");
        sb.AppendLine("  server:");
        sb.AppendLine("    enabled: true");
        sb.AppendLine("    region_id: 999");
        sb.AppendLine("    region_code: acp");
        sb.AppendLine("    region_name: ACP Embedded DERP");
        // HS-04 fix: embedded DERP admission is fail-closed.
        sb.AppendLine("    verify_clients: true");
        sb.AppendLine($"    stun_listen_addr: \"{o.StunListenAddr}\"");
        sb.AppendLine($"    private_key_path: {ConfigPath(o, o.DerpKeyPath)}");
        sb.AppendLine("    automatically_add_embedded_derp_region: true");
        // HS-04/HS-05 fix: NO external DERP map — never Tailscale Inc.'s fleet.
        sb.AppendLine("  urls: []");
        sb.AppendLine("  paths: []");
        sb.AppendLine("  auto_update_enabled: false");
        sb.AppendLine("  update_frequency: 24h");
        // HS-28 fix: no GitHub update-check phone-home.
        sb.AppendLine("disable_check_updates: true");
        sb.AppendLine("database:");
        sb.AppendLine("  type: sqlite");
        sb.AppendLine("  sqlite:");
        sb.AppendLine($"    path: {ConfigPath(o, o.DbPath)}");
        sb.AppendLine("    write_ahead_log: true");
        if (!string.IsNullOrEmpty(o.TlsCertPath))
            sb.AppendLine($"tls_cert_path: {ConfigPath(o, o.TlsCertPath)}");
        if (!string.IsNullOrEmpty(o.TlsKeyPath))
            sb.AppendLine($"tls_key_path: {ConfigPath(o, o.TlsKeyPath)}");
        sb.AppendLine("log:");
        sb.AppendLine("  level: info");
        sb.AppendLine("  format: text");
        // Telemetry: asserted off (audit §4 — with this false, Headscale also
        // instructs clients not to upload logs to Tailscale Inc.).
        sb.AppendLine("logtail:");
        sb.AppendLine("  enabled: false");
        sb.AppendLine("policy:");
        sb.AppendLine("  mode: file");
        sb.AppendLine($"  path: {ConfigPath(o, o.PolicyPath)}");
        sb.AppendLine("dns:");
        sb.AppendLine("  magic_dns: true");
        sb.AppendLine($"  base_domain: {o.BaseDomain}");
        sb.AppendLine("  override_local_dns: false");
        sb.AppendLine("  nameservers:");
        sb.AppendLine("    global: []");
        sb.AppendLine($"unix_socket: {ConfigPath(o, o.SocketPath)}");
        sb.AppendLine("unix_socket_permission: \"0770\"");
        if (o.Oidc is { } oidc)
        {
            sb.AppendLine("oidc:");
            sb.AppendLine($"  issuer: \"{oidc.Issuer}\"");
            sb.AppendLine($"  client_id: \"{oidc.ClientId}\"");
            sb.AppendLine($"  client_secret_path: \"{oidc.ClientSecretPath}\"");
            // HS-17/HS-18/HS-22 fixes.
            sb.AppendLine("  pkce:");
            sb.AppendLine("    enabled: true");
            sb.AppendLine("    method: S256");
            sb.AppendLine("  email_verified_required: true");
            if (oidc.AllowedDomains.Count > 0)
                sb.AppendLine($"  allowed_domains: [{string.Join(", ", oidc.AllowedDomains.Select(d => $"\"{d}\""))}]");
            if (oidc.AllowedGroups.Count > 0)
                sb.AppendLine($"  allowed_groups: [{string.Join(", ", oidc.AllowedGroups.Select(g => $"\"{g}\""))}]");
        }
        return sb.ToString();
    }

    private static bool IsLoopbackHost(string host) =>
        host is "127.0.0.1" or "localhost" or "::1" or "[::1]";

    private static bool IsLoopbackAddr(string addr)
    {
        if (string.IsNullOrWhiteSpace(addr)) return false;
        var host = addr.Trim().Trim('"');
        var idx = host.LastIndexOf(':');
        if (idx > 0) host = host[..idx];
        return IsLoopbackHost(host);
    }

    /// <summary>Validates config text against the §8 conditions. Returns every
    /// violation found (empty = clean). This is the check the lifecycle runs
    /// on the files AS THEY EXIST ON DISK before every start, so a hand-edit
    /// cannot smuggle a weakened config past the generator.</summary>
    public static IReadOnlyList<HubViolation> Validate(string configText, HubOptions o)
    {
        var v = new List<HubViolation>();
        var y = new MiniYaml(configText);

        // server_url: HTTPS mandatory (HS-07b); http only as loopback dev.
        var serverUrl = y.GetScalar("server_url")?.Trim().Trim('"') ?? "";
        if (!Uri.TryCreate(serverUrl, UriKind.Absolute, out var su))
            v.Add(new("§8.2 server_url", "server_url missing or not an absolute URL"));
        else if (su.Scheme == "https") { /* required shape */ }
        else if (su.Scheme == "http" && o.AllowLoopbackHttpDev && IsLoopbackHost(su.Host)) { /* dev only */ }
        else
            v.Add(new("§8.2 server_url HTTPS mandatory",
                $"server_url '{serverUrl}' is not https (http is refused outside loopback dev)"));

        // derp.urls EMPTY (HS-04) and no local map paths either.
        var urls = y.GetList("derp", "urls");
        if (urls is null)
            v.Add(new("§8.2 derp.urls", "derp.urls key absent — cannot prove the DERP map is ACP-only"));
        else if (urls.Count > 0)
            v.Add(new("§8.2 derp.urls EMPTY (HS-04)",
                "derp.urls is non-empty: " + string.Join(", ", urls)));
        var paths = y.GetList("derp", "paths");
        if (paths is { Count: > 0 })
            v.Add(new("§8.2 derp.paths", "derp.paths non-empty — external DERP maps are not ACP's"));

        // Embedded DERP on + verify_clients on (HS-04).
        if (y.GetScalar("derp", "server", "enabled") != "true")
            v.Add(new("§8.2 embedded DERP", "derp.server.enabled is not true"));
        if (y.GetScalar("derp", "server", "verify_clients") != "true")
            v.Add(new("§8.2 DERP verify_clients (fail-closed)", "derp.server.verify_clients is not true"));
        if (y.GetScalar("derp", "auto_update_enabled") == "true")
            v.Add(new("§8.2 derp.auto_update_enabled", "DERP map auto-update must be off with an ACP-only map"));

        // Phone-homes off (HS-28 + logtail assertion).
        if (y.GetScalar("disable_check_updates") != "true")
            v.Add(new("§8.2 disable_check_updates (HS-28)", "disable_check_updates is not true — GitHub update check would phone home"));
        if (y.GetScalar("logtail", "enabled") != "false")
            v.Add(new("§8.2 logtail.enabled asserted false", "logtail.enabled is not explicitly false"));

        // Metrics/debug: off or loopback only (HS-08).
        var metrics = y.GetScalar("metrics_listen_addr")?.Trim().Trim('"');
        if (!string.IsNullOrEmpty(metrics) && !IsLoopbackAddr(metrics))
            v.Add(new("§8.2 metrics loopback-only or OFF (HS-08)",
                $"metrics_listen_addr '{metrics}' is not loopback — /metrics and /debug/* would be exposed"));

        // gRPC: loopback + TLS-required posture (HS-13).
        var grpc = y.GetScalar("grpc_listen_addr");
        if (grpc is null || !IsLoopbackAddr(grpc))
            v.Add(new("§8.2 gRPC loopback", $"grpc_listen_addr '{grpc}' is not loopback"));
        if (y.GetScalar("grpc_allow_insecure") != "false")
            v.Add(new("§8.2 grpc_allow_insecure: false (HS-13)", "grpc_allow_insecure is not false"));

        // Socket permissions stay at 0770 or tighter (HS-13).
        // BD-SHARED-TRANSPORT F3: the permission must be PRESENT —
        // absent previously passed silently, leaving Headscale's
        // own default in force instead of ACP's asserted one.
        var perm = y.GetScalar("unix_socket_permission")?.Trim().Trim('"');
        var tightPerms = new HashSet<string> { "0770", "0700", "077", "77" };
        if (perm is null)
            v.Add(new("§8.9 socket permissions", "unix_socket_permission is absent — ACP asserts it explicitly; an absent value leaves Headscale's default in force"));
        else if (!tightPerms.Contains(perm))
            v.Add(new("§8.9 socket permissions", $"unix_socket_permission '{perm}' loosens the local gRPC gate"));

        // Policy binding (BD-SHARED-TRANSPORT F3): Validate never
        // read the policy section, so a hand-edited config could
        // point Headscale at a DIFFERENT policy file (or database
        // mode) while the self-check compiled ACP's own policy.json
        // and passed. The config must bind policy mode=file and
        // policy.path resolving to THIS options' PolicyPath.
        var policyMode = y.GetScalar("policy", "mode")?.Trim().Trim('"');
        if (policyMode is null)
            v.Add(new("§8.3 policy binding", "policy.mode is absent — the config does not bind Headscale to ACP's policy file"));
        else if (policyMode != "file")
            v.Add(new("§8.3 policy binding", $"policy.mode is '{policyMode}', not 'file' — Headscale would not load ACP's policy file at all"));
        var policyPath = y.GetScalar("policy", "path")?.Trim().Trim('"');
        var expectedPolicyPath = ConfigPath(o, o.PolicyPath).Replace('\\', '/');
        if (policyPath is null)
            v.Add(new("§8.3 policy binding", "policy.path is absent — the config does not name ACP's policy file"));
        else if (!string.Equals(policyPath.Replace('\\', '/'), expectedPolicyPath, StringComparison.OrdinalIgnoreCase))
            v.Add(new("§8.3 policy binding",
                $"policy.path '{policyPath}' does not resolve to ACP's policy file '{expectedPolicyPath}' — a hand-edited config must not be able to point Headscale at another policy while the self-check compiles ACP's own"));

        // OIDC, if configured (§8.8: HS-17/18/22).
        if (y.HasSection("oidc"))
        {
            var issuer = y.GetScalar("oidc", "issuer")?.Trim().Trim('"') ?? "";
            if (!issuer.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                v.Add(new("§8.8 OIDC https issuer only (HS-18)", $"oidc.issuer '{issuer}' is not https"));
            if (y.GetScalar("oidc", "pkce", "enabled") != "true")
                v.Add(new("§8.8 OIDC PKCE enabled (HS-17)", "oidc.pkce.enabled is not true"));
            var method = y.GetScalar("oidc", "pkce", "method");
            if (method is not null && method != "S256")
                v.Add(new("§8.8 OIDC PKCE S256 only (HS-17)", $"oidc.pkce.method '{method}' — 'plain' adds nothing"));
            if (y.GetScalar("oidc", "email_verified_required") != "true")
                v.Add(new("§8.8 email_verified_required: true (HS-22)", "oidc.email_verified_required is not true"));
            var domains = y.GetList("oidc", "allowed_domains");
            var groups = y.GetList("oidc", "allowed_groups");
            var users = y.GetList("oidc", "allowed_users");
            if ((domains is null or { Count: 0 }) && (groups is null or { Count: 0 }) && (users is null or { Count: 0 }))
                v.Add(new("§8.8 OIDC authorization always set (HS-22)",
                    "no allowed_domains / allowed_groups / allowed_users — any verified IdP identity could register"));
        }
        return v;
    }
}

/// <summary>The deny-by-default policy ACP always installs, plus a model of
/// Headscale's policy compiler sufficient for the HS-01 self-check: it
/// reproduces the audited semantics (policy/v2: absent acls AND grants ⇒
/// FilterAllowAll; explicit empty acls ⇒ deny-all) and additionally treats a
/// wildcard-to-wildcard rule as effectively allow-all.</summary>
public static class HubPolicy
{
    /// <summary>ACP's installed policy: explicit empty acls = deny-all.
    /// ACP's admin layer narrows from here; nothing is reachable by default.</summary>
    public const string DenyByDefault = """
        {
          // ACP hub policy — deny-by-default (audit §8.3, HS-01).
          // An explicit empty "acls" compiles to deny-all in Headscale;
          // an ABSENT acls/grants pair compiles to allow-all, which is
          // why this file must always carry the key.
          "groups": {},
          "tagOwners": {},
          "acls": [],
          "ssh": []
        }
        """;

    public sealed record CompiledFilter(bool IsAllowAll, int RuleCount, string Reason);

    public static CompiledFilter Compile(string policyText)
    {
        if (string.IsNullOrWhiteSpace(policyText))
            return new(true, 0, "empty policy compiles to FilterAllowAll (HS-01)");
        var text = StripComments(policyText);
        // BD-SHARED-TRANSPORT F3: the allow-all detector was a
        // regex over raw text that only matched rules whose "src"
        // key came directly before "dst" — a rule written
        // {"dst":["*:*"],"src":["*"]} sailed past it, and
        // autogroup:member sources were never counted. The policy
        // is now parsed with a real JSON parser and every rule's
        // src/dst SETS are tested regardless of key order.
        System.Text.Json.JsonDocument doc;
        try { doc = System.Text.Json.JsonDocument.Parse(text); }
        catch
        {
            // Unparseable policy: Headscale would refuse it too,
            // but the self-check's job is the allow-all question —
            // fall back to the structural key check, fail-closed on
            // absence of both rule sections.
            var hasKeys = Regex.IsMatch(text, "\"acls\"\\s*:") || Regex.IsMatch(text, "\"grants\"\\s*:");
            return hasKeys
                ? new(false, 0, "policy text is not parseable JSON; acls/grants keys are present (Headscale makes the final parse call)")
                : new(true, 0, "policy omits both acls and grants — compiles to FilterAllowAll (HS-01)");
        }
        using (doc)
        {
            var root = doc.RootElement;
            var hasAcls = root.TryGetProperty("acls", out var acls);
            var hasGrants = root.TryGetProperty("grants", out var grants);
            if (!hasAcls && !hasGrants)
                return new(true, 0, "policy omits both acls and grants — compiles to FilterAllowAll (HS-01)");
            var rules = 0;
            var wildcardAll = false;
            void Scan(System.Text.Json.JsonElement section)
            {
                if (section.ValueKind != System.Text.Json.JsonValueKind.Array) return;
                foreach (var rule in section.EnumerateArray())
                {
                    if (rule.ValueKind != System.Text.Json.JsonValueKind.Object) continue;
                    rules++;
                    var srcs = StringSet(rule, "src");
                    var dsts = StringSet(rule, "dst");
                    var broadSource = srcs.Contains("*") || srcs.Contains("autogroup:member");
                    if (broadSource && (dsts.Contains("*") || dsts.Contains("*:*")))
                        wildcardAll = true;
                }
            }
            static HashSet<string> StringSet(System.Text.Json.JsonElement rule, string key)
            {
                var set = new HashSet<string>(StringComparer.Ordinal);
                if (rule.TryGetProperty(key, out var arr) && arr.ValueKind == System.Text.Json.JsonValueKind.Array)
                    foreach (var e in arr.EnumerateArray())
                        if (e.ValueKind == System.Text.Json.JsonValueKind.String) set.Add(e.GetString()!);
                return set;
            }
            if (hasAcls) Scan(acls);
            if (hasGrants) Scan(grants);
            if (wildcardAll)
                return new(true, rules, "a wildcard/autogroup-source to wildcard-destination rule is allow-all in effect");
            return new(false, rules, rules == 0 ? "explicit empty acls/grants — deny-all" : $"{rules} rule(s), none wildcard-total");
        }
    }

    private static string StripComments(string text)
    {
        text = Regex.Replace(text, "/\\*.*?\\*/", "", RegexOptions.Singleline);
        text = Regex.Replace(text, "(?m)//.*$", "");
        return text;
    }
}

/// <summary>The §8.3 startup self-check: compiles the effective policy and
/// refuses to serve if it is allow-all (without the explicit admin opt-in),
/// and refuses on any §8 config violation. Run by the lifecycle against the
/// on-disk files before EVERY start — never against in-memory intentions.</summary>
public static class HubStartupSelfCheck
{
    public static IReadOnlyList<HubViolation> Check(string configText, string policyText, HubOptions o)
    {
        var v = new List<HubViolation>(HubConfig.Validate(configText, o));
        var compiled = HubPolicy.Compile(policyText);
        if (compiled.IsAllowAll && !o.AllowAllPolicyOptIn)
            v.Add(new("§8.3 startup self-check (HS-01)",
                "effective policy compiles to allow-all: " + compiled.Reason));
        return v;
    }

    public static void AssertSafeToServe(string configText, string policyText, HubOptions o)
    {
        var v = Check(configText, policyText, o);
        if (v.Count > 0) throw new HubRefusalException(v);
    }
}

/// <summary>A deliberately small YAML reader for the subset ACP generates
/// and must police: nested maps by indentation, scalar leaves, inline and
/// block lists. It exists so validation needs no third-party parser; it
/// fails closed (absent key = null = violation where a condition requires
/// an explicit value).</summary>
internal sealed class MiniYaml
{
    private sealed class Node
    {
        public string? Scalar;
        public List<string>? List;
        public Dictionary<string, Node> Map = new();
        public bool HasValue;
    }

    private readonly Node _root = new();

    public MiniYaml(string text)
    {
        // Stack of (indent, node) for map nodes currently open.
        var stack = new List<(int Indent, Node Map)> { (-1, _root) };
        Node? pendingListKey = null;
        var pendingListIndent = -1;

        foreach (var rawLine in text.Replace("\r\n", "\n").Split('\n'))
        {
            var line = rawLine;
            var hash = line.IndexOf(" #", StringComparison.Ordinal);
            if (hash >= 0) line = line[..hash];
            if (string.IsNullOrWhiteSpace(line)) continue;
            var indent = line.Length - line.TrimStart().Length;
            var body = line.Trim();

            while (stack.Count > 1 && indent <= stack[^1].Indent) stack.RemoveAt(stack.Count - 1);
            var parent = stack[^1].Map;

            if (body.StartsWith("- ", StringComparison.Ordinal) || body == "-")
            {
                if (pendingListKey is not null && indent >= pendingListIndent)
                {
                    pendingListKey.List ??= new List<string>();
                    pendingListKey.List.Add(body.Length > 1 ? body[2..].Trim().Trim('"') : "");
                    pendingListKey.HasValue = true;
                }
                continue;
            }

            var colon = body.IndexOf(':');
            if (colon < 0) continue;
            var key = body[..colon].Trim();
            var value = body[(colon + 1)..].Trim();
            var node = new Node();
            parent.Map[key] = node;
            pendingListKey = null;

            if (value.Length == 0)
            {
                // Either a nested map or a block list; decide on next lines.
                stack.Add((indent, node));
                pendingListKey = node;
                pendingListIndent = indent;
                node.List = null; // becomes a list only if "- " items follow
            }
            else if (value == "[]")
            {
                node.List = new List<string>();
                node.HasValue = true;
            }
            else if (value.StartsWith('[') && value.EndsWith(']'))
            {
                node.List = value[1..^1]
                    .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                    .Select(s => s.Trim().Trim('"')).ToList();
                node.HasValue = true;
            }
            else
            {
                node.Scalar = value;
                node.HasValue = true;
            }
        }
    }

    private Node? Walk(params string[] path)
    {
        var cur = _root;
        foreach (var seg in path)
        {
            if (!cur.Map.TryGetValue(seg, out var next)) return null;
            cur = next;
        }
        return cur;
    }

    public bool HasSection(string key) => _root.Map.ContainsKey(key);

    public string? GetScalar(params string[] path) => Walk(path)?.Scalar;

    /// <summary>Returns list items for a key, [] for an explicit empty list,
    /// or null when the key is absent or holds no list.</summary>
    public IReadOnlyList<string>? GetList(params string[] path)
    {
        var n = Walk(path);
        if (n is null) return null;
        if (n.List is not null) return n.List;
        if (n.Scalar is not null) return new List<string> { n.Scalar.Trim().Trim('"') };
        // Key present with an (empty) map/section body and no items: the
        // generator never emits this for list keys; treat as empty list
        // only when the node carries no children either.
        return n.Map.Count == 0 && !n.HasValue ? null : Array.Empty<string>();
    }
}
