using System.IO.Compression;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Acp.Core.Modules;
using Acp.Core.Platform;
using Acp.Shared.Security;
using Acp.Shared.Tools;

namespace Acp.Core.Phase2;

/// <summary>Census row 80: Wake-on-LAN — the laptop as the always-on
/// waker of OTHER machines. Real UDP magic packet, broadcast + directed.</summary>
public sealed class WakeOnLanModule : IToolModule
{
    public ToolDescriptor Descriptor { get; } = new(
        "wake_on_lan_send", "Send a Wake-on-LAN magic packet to wake another machine on the LAN.",
        Scopes.Shell, SessionRequirement.Core, RiskTier.Low, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"mac":{"type":"string"},"broadcast":{"type":"string","default":"255.255.255.255"}},"required":["mac"]}""");

    /// <summary>Delegates to the canonical builder (G-01): one
    /// packet shape for the whole product, so the agent tool and
    /// the session feature can never diverge. Parsing is strict
    /// (exactly 6 two-hex-digit octets) — the same refusal the
    /// wake registry applies.</summary>
    public static byte[] BuildMagicPacket(string mac) => Acp.Shared.Wake.MagicPacket.Build(mac);

    public async Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var mac = FileArgs.Str(arguments, "mac") ?? "";
        var broadcast = FileArgs.Str(arguments, "broadcast") ?? "255.255.255.255";
        byte[] packet;
        try { packet = BuildMagicPacket(mac); }
        catch (Exception ex) { return ToolResult.Error("bad_mac", ex.Message); }
        // BD-WIN-CORE-2/F11: a bad broadcast string escaped as a raw
        // FormatException; every caller-shaped failure is a ToolResult.
        if (!IPAddress.TryParse(broadcast, out var broadcastAddr))
            return ToolResult.Error("bad_broadcast", $"'{broadcast}' is not an IP address");
        try
        {
            using var udp = new UdpClient { EnableBroadcast = true };
            await udp.SendAsync(packet, new IPEndPoint(broadcastAddr, 9), ct);
        }
        catch (Exception ex) { return ToolResult.Error("send_failed", ex.Message); }
        return ToolResult.Success($"magic packet sent for {mac} via {broadcast}:9");
    }
}

/// <summary>Census row 126: scoped TCP tunnelling. Destinations are
/// allowlisted per host config. HONEST POSTURE (BD-WIN-CORE-2/F3):
/// the listener is a raw LOOPBACK port — any local process can
/// connect to it while it lives, so a forward is a bounded, owned,
/// audited loan of loopback reachability, not a ride "through the
/// agent's authenticated channel" (the previous docstring claimed
/// that; it was false). Bounds: every forward is owned by the
/// pairing that started it, is audit-logged at start / stop / every
/// accepted connection, can be listed and stopped (by its owner),
/// and is torn down when its pairing's session ends, on STOP, on
/// revocation, and at Core shutdown (host wires StopForPairing /
/// StopAll to those events).</summary>
public sealed class TcpTunnelService
{
    private readonly IReadOnlySet<string> _allowedTargets; // "host:port"
    private readonly Action<string, string?, string>? _audit; // (kind, pairingId, detail)
    private readonly object _gate = new();
    private readonly List<Forward> _active = new();

    private sealed class Forward
    {
        public required TcpListener Listener;
        public required CancellationTokenSource Cts;
        public required int ListenPort;
        public required string TargetHost;
        public required int TargetPort;
        public required string PairingId;
    }

    public TcpTunnelService(IReadOnlySet<string> allowedTargets, Action<string, string?, string>? audit = null)
    { _allowedTargets = allowedTargets; _audit = audit; }

    public bool IsAllowed(string host, int port) => _allowedTargets.Contains($"{host}:{port}");

    public IReadOnlyList<(int ListenPort, string TargetHost, int TargetPort, string PairingId)> Active
    {
        get { lock (_gate) return _active.Select(f => (f.ListenPort, f.TargetHost, f.TargetPort, f.PairingId)).ToList(); }
    }

    public async Task<string?> StartForwardAsync(IPAddress bindAddress, int listenPort, string targetHost, int targetPort, CancellationToken ct, string pairingId = "")
    {
        if (!IsAllowed(targetHost, targetPort))
            return $"target {targetHost}:{targetPort} is not on this host's tunnel allowlist; refused";
        var listener = new TcpListener(bindAddress, listenPort);
        try { listener.Start(); }
        catch (Exception ex) { return $"listener on {bindAddress}:{listenPort} failed to start: {ex.GetType().Name}: {ex.Message}"; }
        var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var forward = new Forward { Listener = listener, Cts = cts, ListenPort = listenPort, TargetHost = targetHost, TargetPort = targetPort, PairingId = pairingId };
        lock (_gate) _active.Add(forward);
        _audit?.Invoke("tcp_tunnel_start", pairingId, $"{bindAddress}:{listenPort} -> {targetHost}:{targetPort}");
        _ = Task.Run(async () =>
        {
            try
            {
                while (!cts.Token.IsCancellationRequested)
                {
                    var client = await listener.AcceptTcpClientAsync(cts.Token);
                    _audit?.Invoke("tcp_tunnel_connection", pairingId, $"{bindAddress}:{listenPort} -> {targetHost}:{targetPort} from {client.Client.RemoteEndPoint}");
                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            using var remote = new TcpClient();
                            await remote.ConnectAsync(targetHost, targetPort, cts.Token);
                            var a = client.GetStream();
                            var b = remote.GetStream();
                            await Task.WhenAny(a.CopyToAsync(b, cts.Token), b.CopyToAsync(a, cts.Token));
                        }
                        catch { }
                        finally { client.Dispose(); }
                    }, cts.Token);
                }
            }
            catch { }
        }, cts.Token);
        return null;
    }

    private void StopForward(Forward f, string reason)
    {
        try { f.Cts.Cancel(); f.Listener.Stop(); } catch { }
        _audit?.Invoke("tcp_tunnel_stop", f.PairingId, $"{f.ListenPort} -> {f.TargetHost}:{f.TargetPort} ({reason})");
    }

    /// <summary>Stop one forward by listen port; only its owning
    /// pairing may stop it (a foreign pairing gets 'not yours').</summary>
    public bool Stop(int listenPort, string pairingId, out string? error)
    {
        Forward? f;
        lock (_gate) f = _active.FirstOrDefault(x => x.ListenPort == listenPort);
        if (f is null) { error = $"no active forward on port {listenPort}"; return false; }
        if (f.PairingId != pairingId) { error = $"forward on port {listenPort} belongs to another pairing; only its owner can stop it"; return false; }
        lock (_gate) _active.Remove(f);
        StopForward(f, "stopped by owning pairing");
        error = null; return true;
    }

    /// <summary>Teardown for session end / revocation of one pairing.</summary>
    public void StopForPairing(string pairingId, string reason = "pairing session ended or was revoked")
    {
        List<Forward> mine;
        lock (_gate) { mine = _active.Where(f => f.PairingId == pairingId).ToList(); _active.RemoveAll(f => f.PairingId == pairingId); }
        foreach (var f in mine) StopForward(f, reason);
    }

    public void StopAll()
    {
        List<Forward> all;
        lock (_gate) { all = _active.ToList(); _active.Clear(); }
        foreach (var f in all) StopForward(f, "stop all");
    }
}

public sealed class TcpTunnelModule : IToolModule
{
    private readonly TcpTunnelService _tunnels;
    public TcpTunnelModule(TcpTunnelService tunnels) => _tunnels = tunnels;
    public ToolDescriptor Descriptor { get; } = new(
        "tcp_tunnel", "Scoped TCP forwards through this host: action=start|list|stop. Allowlisted destinations only; forwards are owned by the starting pairing, audited (start/stop/each connection), and torn down at session end, STOP and revocation. The listener is loopback-only.",
        Scopes.Shell, SessionRequirement.Core, RiskTier.High, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"action":{"type":"string","enum":["start","list","stop"],"default":"start"},"listen_port":{"type":"integer"},"target_host":{"type":"string"},"target_port":{"type":"integer"}}}""");

    public async Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var action = FileArgs.Str(arguments, "action") ?? "start";
        switch (action)
        {
            case "list":
                return ToolResult.Success(JsonSerializer.Serialize(_tunnels.Active
                    .Where(f => f.PairingId == ctx.Pairing.Id)
                    .Select(f => new { f.ListenPort, f.TargetHost, f.TargetPort })));
            case "stop":
            {
                var listen = arguments.TryGetProperty("listen_port", out var lp) ? lp.GetInt32() : 0;
                return _tunnels.Stop(listen, ctx.Pairing.Id, out var error)
                    ? ToolResult.Success($"forward on 127.0.0.1:{listen} stopped")
                    : ToolResult.Error("stop_refused", error ?? "stop refused");
            }
            default:
            {
                var listen = arguments.TryGetProperty("listen_port", out var lp) ? lp.GetInt32() : 0;
                var host = FileArgs.Str(arguments, "target_host") ?? "";
                var port = arguments.TryGetProperty("target_port", out var tp) ? tp.GetInt32() : 0;
                var error = await _tunnels.StartForwardAsync(IPAddress.Loopback, listen, host, port, ct, ctx.Pairing.Id);
                return error is null ? ToolResult.Success($"forwarding 127.0.0.1:{listen} → {host}:{port} (owned by your pairing; stops at session end, STOP or revocation)") : ToolResult.Error("not_allowlisted", error);
            }
        }
    }
}

/// <summary>Census row 121: certificate store listing + environment
/// variables. Private keys are NEVER read back (X4) — export is of
/// public certificates only.</summary>
public sealed class CertEnvAdminModule : IToolModule
{
    public ToolDescriptor Descriptor { get; } = new(
        "certificate_env_admin", "List certificates (public material only; store_location=LocalMachine|CurrentUser — under the SYSTEM Core, CurrentUser is the service account's store, NOT the signed-in owner's), read environment variables, set USER-scope variables. Process-scope env_set no longer exists: it mutated the Core's own environment for its lifetime (BD-WIN-CORE-2/F8).",
        Scopes.Shell, SessionRequirement.Core, RiskTier.High, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"action":{"type":"string","enum":["cert_list","env_get","env_set"]},"name":{"type":"string"},"value":{"type":"string"},"store":{"type":"string","default":"My"},"store_location":{"type":"string","enum":["LocalMachine","CurrentUser"],"default":"LocalMachine"}}}""");

    /// <summary>Names an env_set may never touch (BD-WIN-CORE-2/F8):
    /// anything that redirects later launches (PATH & friends), the
    /// Core's own control variables (ACP_* — ACP_SAFE_MODE among
    /// them, which SafeModeOrchestrator reads), or process identity.</summary>
    public static bool IsProtectedEnvName(string name) =>
        string.IsNullOrWhiteSpace(name)
        || name.StartsWith("ACP_", StringComparison.OrdinalIgnoreCase)
        || new[] { "PATH", "PATHEXT", "COMSPEC", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "PSMODULEPATH", "NODE_PATH", "PYTHONPATH", "USERNAME", "USERPROFILE", "HOME" }
            .Contains(name, StringComparer.OrdinalIgnoreCase);

    public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var action = FileArgs.Str(arguments, "action") ?? "cert_list";
        switch (action)
        {
            case "cert_list":
            {
                var storeName = FileArgs.Str(arguments, "store") ?? "My";
                // Default LocalMachine: this module runs as SYSTEM, so
                // CurrentUser was the machine account's store while the
                // caller believed it was the owner's (F8). The owner's
                // store remains available, but only when named — and
                // the result says whose store it was.
                var location = string.Equals(FileArgs.Str(arguments, "store_location"), "CurrentUser", StringComparison.OrdinalIgnoreCase)
                    ? StoreLocation.CurrentUser : StoreLocation.LocalMachine;
                try
                {
                    using var store = new X509Store(storeName, location);
                    store.Open(OpenFlags.ReadOnly);
                    var certs = store.Certificates.Cast<X509Certificate2>().Select(c => new
                    {
                        subject = c.Subject, issuer = c.Issuer, thumbprint = c.Thumbprint,
                        not_after = c.NotAfter, has_private_key = c.HasPrivateKey // presence only; key material never leaves (X4)
                    }).ToList();
                    return Task.FromResult(ToolResult.Success(JsonSerializer.Serialize(new
                    {
                        store = storeName,
                        location = location.ToString(),
                        note = location == StoreLocation.CurrentUser
                            ? "CurrentUser under the SYSTEM Core is the service account's store, not the signed-in owner's"
                            : "machine store",
                        certs
                    }, new JsonSerializerOptions { WriteIndented = true })));
                }
                catch (Exception ex) { return Task.FromResult(ToolResult.Error("store_failed", ex.Message)); }
            }
            case "env_get":
            {
                var name = FileArgs.Str(arguments, "name") ?? "";
                var value = Environment.GetEnvironmentVariable(name)
                    ?? Environment.GetEnvironmentVariable(name, EnvironmentVariableTarget.User)
                    ?? Environment.GetEnvironmentVariable(name, EnvironmentVariableTarget.Machine);
                return Task.FromResult(ToolResult.Success(value ?? "(unset)"));
            }
            case "env_set":
            {
                var name = FileArgs.Str(arguments, "name") ?? "";
                if (IsProtectedEnvName(name))
                    return Task.FromResult(ToolResult.Error("protected_name",
                        $"'{name}' cannot be set: launch-redirecting variables (PATH, PATHEXT, COMSPEC, PYTHONPATH, NODE_PATH, …) and every ACP_* control variable are refused, and process-scope env mutation no longer exists — it silently redirected every later bare-name launch the Core made"));
                // User scope of the SERVICE account, persisted — never
                // the running Core process's own environment.
                Environment.SetEnvironmentVariable(name, FileArgs.Str(arguments, "value"), EnvironmentVariableTarget.User);
                return Task.FromResult(ToolResult.Success($"user-scope environment variable '{name}' set (service account; the running Core process's environment is unchanged)"));
            }
            default:
                return Task.FromResult(ToolResult.Error("bad_arguments", action));
        }
    }
}

/// <summary>Census row 109 (archive half): create/extract zip archives
/// inside the file scope. (NTFS ACLs ride the Windows provider at the
/// laptop gate.)</summary>
public sealed class FileExtendedOpsModule : IToolModule
{
    private readonly FileScope _scope;
    public FileExtendedOpsModule(FileScope scope) => _scope = scope;
    public ToolDescriptor Descriptor { get; } = new(
        "file_extended_ops", "Archive create/extract within scope (action=zip|unzip).",
        Scopes.Shell, SessionRequirement.Core, RiskTier.High, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"action":{"type":"string","enum":["zip","unzip"]},"source":{"type":"string"},"destination":{"type":"string"}}}""");

    public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var src = FileArgs.Path(arguments, "source");
        var dst = FileArgs.Path(arguments, "destination");
        var s = src is null ? null : _scope.ResolveInScope(src);
        var d = dst is null ? null : _scope.ResolveInScope(dst);
        if (s is null || d is null) return Task.FromResult(ToolResult.Error("out_of_scope", "both paths must be inside the configured roots"));
        var action = FileArgs.Str(arguments, "action") ?? "zip";
        // BD-WIN-CORE-2/F11: zip/unzip I/O failures escaped as raw
        // exceptions; they are caller-shaped outcomes, returned coded.
        try
        {
            if (action == "zip")
            {
                if (File.Exists(d)) File.Delete(d);
                ZipFile.CreateFromDirectory(s, d);
                return Task.FromResult(ToolResult.Success($"archived {s} → {d}"));
            }
            Directory.CreateDirectory(d);
            ZipFile.ExtractToDirectory(s, d, overwriteFiles: true);
            return Task.FromResult(ToolResult.Success($"extracted {s} → {d}"));
        }
        catch (Exception ex) { return Task.FromResult(ToolResult.Error("archive_failed", ex.Message)); }
    }
}

/// <summary>Census row 110: export a registry key to a JSON backup in
/// the staging store before writes; import restores it. HONEST SHAPE:
/// export records the key's string values plus its subkey NAMES;
/// import restores the string values only — subkeys are recorded
/// for the record, not recreated (the previous header promised
/// 'values + subkeys' backup; the code never did that).
/// BD-WIN-CORE-2/F2 fixes: backup_name is validated with
/// SafeStoreName (the 2026-11-15 discipline) — it previously went
/// straight into Path.Combine, so '..\x' wrote JSON anywhere the
/// SYSTEM Core could reach; import now requires the file's recorded
/// key to EQUAL the caller's key argument (the file previously
/// chose the restore target itself — an arbitrary-registry-write
/// path); import is gated as a registry write and rated High.</summary>
public sealed class RegistryBackupExportModule : IToolModule
{
    private readonly IRegistryProvider _reg;
    private readonly string _stagingRoot;
    public RegistryBackupExportModule(IRegistryProvider reg, string stagingRoot) { _reg = reg; _stagingRoot = stagingRoot; }
    public ToolDescriptor Descriptor { get; } = new(
        "registry_backup_export", "Export a registry key's string values (plus subkey names, for the record) to a staging-store JSON backup, or restore string values from one. Import restores ONLY into the key named by the caller's key argument and refuses a backup recorded for any other key.",
        Scopes.Shell, SessionRequirement.Core, RiskTier.High, GateClass: "registry_write", ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"action":{"type":"string","enum":["export","import"]},"key":{"type":"string"},"backup_name":{"type":"string"}}}""");

    public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        if (!_reg.Available) return Task.FromResult(ToolResult.Unavailable("registry is a Windows surface; this host is not running Windows"));
        var action = FileArgs.Str(arguments, "action") ?? "export";
        var key = FileArgs.Str(arguments, "key") ?? "";
        var name = FileArgs.Str(arguments, "backup_name") ?? "registry-backup";
        if (!SafeStoreName.IsValid(name))
            return Task.FromResult(ToolResult.Error("bad_arguments", "backup_name must be 1-64 characters of letters, digits, '-' or '_' (no path separators or dots)"));
        var path = Path.Combine(_stagingRoot, $"{name}.json");
        try
        {
            if (action == "export")
            {
                Directory.CreateDirectory(_stagingRoot);
                var values = _reg.ListValues(key).ToDictionary(v => v, v => _reg.GetValue(key, v));
                File.WriteAllText(path, JsonSerializer.Serialize(new { key, values, subkeys = _reg.ListSubKeys(key) }, new JsonSerializerOptions { WriteIndented = true }));
                return Task.FromResult(ToolResult.Success($"exported {key} → {path} (string values + subkey names; import restores string values only)"));
            }
            if (!File.Exists(path)) return Task.FromResult(ToolResult.Error("not_found", $"no backup '{name}' in the staging store"));
            using var doc = JsonDocument.Parse(File.ReadAllText(path));
            var root = doc.RootElement;
            var recordedKey = root.TryGetProperty("key", out var k) ? k.GetString() : null;
            if (!string.Equals(recordedKey, key, StringComparison.OrdinalIgnoreCase))
                return Task.FromResult(ToolResult.Error("key_mismatch",
                    $"backup '{name}' was recorded for key '{recordedKey ?? "(none)"}', not '{key}': import restores only into the key the caller names AND the backup was taken from — a backup file never chooses its own restore target"));
            var restored = 0;
            if (root.TryGetProperty("values", out var valuesEl) && valuesEl.ValueKind == JsonValueKind.Object)
                foreach (var prop in valuesEl.EnumerateObject())
                    if (prop.Value.ValueKind == JsonValueKind.String)
                    { _reg.SetValue(key, prop.Name, prop.Value.GetString() ?? ""); restored++; }
            return Task.FromResult(ToolResult.Success($"restored {restored} string values into {key} from {path}"));
        }
        catch (Exception ex) { return Task.FromResult(ToolResult.Error("backup_failed", ex.Message)); }
    }
}

/// <summary>Census row 113: threshold rules over host metrics, evaluated
/// by the supervisor; a tripped rule surfaces in heartbeat + audit.
/// The engine is pure and VM-tested; metric feeds are delegates.</summary>
public sealed class HealthAlertRules
{
    public sealed record Rule(string Name, string Metric, double Threshold, string Direction); // "above" | "below"
    public sealed record Alert(string Rule, string Metric, double Value, DateTimeOffset AtUtc);

    /// <summary>BD-WIN-CORE-2/F10: this engine previously appended a
    /// fresh alert on EVERY Evaluate while a condition held (unbounded
    /// growth, no dedup, no locks, rules lost on restart, any direction
    /// other than "above" silently meaning "below"). It now: validates
    /// direction ∈ {above, below} at AddRule; dedups by transition (a
    /// rule fires once when its condition becomes true and not again
    /// until the condition clears); caps retained alerts (oldest drop,
    /// counted in DroppedAlerts — never silent); is thread-safe; and
    /// persists rules when constructed with a path. NOTE: RMM-01's
    /// HealthAlertCentre remains the product's primary alerting engine
    /// (dedup/cooldown/flood discipline + chained audit); this census
    /// engine is retained for the threshold-rule tool surface and now
    /// follows the same transition discipline, but migrating its rules
    /// INTO the centre is the recorded end-state, not done here.</summary>
    public const int MaxRetainedAlerts = 500;

    private readonly List<Rule> _rules = new();
    private readonly List<Alert> _alerts = new();
    private readonly HashSet<string> _tripped = new(StringComparer.Ordinal); // rule names currently in tripped state
    private readonly object _gate = new();
    private readonly string? _persistPath;

    public HealthAlertRules(string? persistPath = null)
    {
        _persistPath = persistPath;
        if (persistPath is not null && File.Exists(persistPath))
        {
            try
            {
                var loaded = JsonSerializer.Deserialize<List<Rule>>(File.ReadAllText(persistPath));
                if (loaded is not null) _rules.AddRange(loaded.Where(r => r.Direction is "above" or "below"));
            }
            catch { /* a corrupt rules file starts empty rather than crashing the Core; rules are re-addable */ }
        }
    }

    public IReadOnlyList<Alert> Alerts { get { lock (_gate) return _alerts.ToList(); } }
    public IReadOnlyList<Rule> Rules { get { lock (_gate) return _rules.ToList(); } }
    public int DroppedAlerts { get; private set; }

    public void AddRule(Rule rule)
    {
        if (rule.Direction is not ("above" or "below"))
            throw new ArgumentException($"direction must be 'above' or 'below', not '{rule.Direction}' — an unknown direction is refused, never silently treated as 'below'", nameof(rule));
        lock (_gate)
        {
            _rules.Add(rule);
            if (_persistPath is not null)
            {
                Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(_persistPath))!);
                File.WriteAllText(_persistPath, JsonSerializer.Serialize(_rules));
            }
        }
    }

    public IReadOnlyList<Alert> Evaluate(IReadOnlyDictionary<string, double> metrics, DateTimeOffset now)
    {
        var fired = new List<Alert>();
        lock (_gate)
        {
            foreach (var rule in _rules)
            {
                if (!metrics.TryGetValue(rule.Metric, out var value)) continue;
                var trip = rule.Direction == "above" ? value > rule.Threshold : value < rule.Threshold;
                if (trip && _tripped.Add(rule.Name))
                {
                    var alert = new Alert(rule.Name, rule.Metric, value, now);
                    _alerts.Add(alert);
                    fired.Add(alert);
                    while (_alerts.Count > MaxRetainedAlerts) { _alerts.RemoveAt(0); DroppedAlerts++; }
                }
                else if (!trip)
                {
                    _tripped.Remove(rule.Name); // condition cleared: the rule may fire again on the next trip
                }
            }
        }
        return fired;
    }
}

public sealed class HealthAlertRulesModule : IToolModule
{
    private readonly HealthAlertRules _rules;
    public HealthAlertRulesModule(HealthAlertRules rules) => _rules = rules;
    public ToolDescriptor Descriptor { get; } = new(
        "health_alert_rules", "Add a threshold rule over host metrics, or list fired alerts.",
        Scopes.Shell, SessionRequirement.Core, RiskTier.Medium, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"action":{"type":"string","enum":["add","alerts"]},"name":{"type":"string"},"metric":{"type":"string"},"threshold":{"type":"number"},"direction":{"type":"string"}}}""");

    public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var action = FileArgs.Str(arguments, "action") ?? "alerts";
        if (action == "add")
        {
            try
            {
                _rules.AddRule(new HealthAlertRules.Rule(
                    FileArgs.Str(arguments, "name") ?? "rule",
                    FileArgs.Str(arguments, "metric") ?? "",
                    arguments.TryGetProperty("threshold", out var t) ? t.GetDouble() : 0,
                    FileArgs.Str(arguments, "direction") ?? "above"));
            }
            catch (ArgumentException ex) { return Task.FromResult(ToolResult.Error("bad_arguments", ex.Message)); }
            return Task.FromResult(ToolResult.Success("rule added"));
        }
        return Task.FromResult(ToolResult.Success(JsonSerializer.Serialize(_rules.Alerts, new JsonSerializerOptions { WriteIndented = true })));
    }
}

/// <summary>Census row 129: serial/COM port inventory + basic I/O.
/// The owner's bench case: panels and controllers on a bench lead.</summary>
public sealed class SerialPortModule : IToolModule
{
    public ToolDescriptor Descriptor { get; } = new(
        "serial_port_io", "List serial ports; open/read/write a port with explicit parameters.",
        Scopes.Shell, SessionRequirement.Core, RiskTier.Medium, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"action":{"type":"string","enum":["list","read","write"]},"port":{"type":"string"},"baud":{"type":"integer","default":9600},"data":{"type":"string"},"read_seconds":{"type":"integer","default":2}}}""");

    public async Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var action = FileArgs.Str(arguments, "action") ?? "list";
        if (action == "list")
            return ToolResult.Success(JsonSerializer.Serialize(System.IO.Ports.SerialPort.GetPortNames()));
        var portName = FileArgs.Str(arguments, "port") ?? "";
        var baud = arguments.TryGetProperty("baud", out var b) ? b.GetInt32() : 9600;
        using var port = new System.IO.Ports.SerialPort(portName, baud);
        port.ReadTimeout = 500;
        // BD-WIN-CORE-2/F11: a missing/busy port escaped as a raw
        // exception; port-open failure is a coded ToolResult.
        try { port.Open(); }
        catch (Exception ex) { return ToolResult.Error("port_unavailable", $"cannot open '{portName}': {ex.Message}"); }
        try
        {
            if (action == "write")
            {
                port.Write(FileArgs.Str(arguments, "data") ?? "");
                return ToolResult.Success($"wrote to {portName} at {baud}");
            }
            var seconds = arguments.TryGetProperty("read_seconds", out var rs) ? rs.GetInt32() : 2;
            var buffer = new char[4096];
            var read = 0;
            var deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(seconds);
            while (DateTimeOffset.UtcNow < deadline && read < buffer.Length)
            {
                try { read += port.Read(buffer, read, buffer.Length - read); }
                catch (TimeoutException) { break; }
            }
            return ToolResult.Success(new string(buffer, 0, read));
        }
        finally { port.Close(); }
    }
}

/// <summary>Census row 131: device location. Windows location is a
/// WinRT surface; until the CsWinRT engine lands at the laptop gate,
/// this reports unavailable — a real position is never invented (X13's
/// mirror rule: read real location only, and only when we truly can).</summary>
public sealed class DeviceLocationModule : IToolModule
{
    public ToolDescriptor Descriptor { get; } = new(
        "device_location", "Read the device's real location where location services expose it. Never spoofed, never invented.",
        Scopes.Observe, SessionRequirement.Core, RiskTier.Low, ExecutionContext: "SYSTEM");

    public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct) =>
        Task.FromResult(ToolResult.Unavailable("the Windows location engine (WinRT Geolocator) lands at the laptop gate; no position is reported rather than a fabricated one"));
}
