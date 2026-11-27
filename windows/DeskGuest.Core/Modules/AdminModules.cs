using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.ServiceProcess;
using System.Text.Json;
using DeskGuest.Core.Platform;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.Tools;
using Microsoft.Win32;

namespace DeskGuest.Core.Modules;

// ---------- Provider interfaces: Windows engines behind seams, fakes in tests ----------

public interface IRegistryProvider
{
    bool Available { get; }
    string? GetValue(string keyPath, string valueName);
    IReadOnlyList<string> ListValues(string keyPath);
    IReadOnlyList<string> ListSubKeys(string keyPath);
    void SetValue(string keyPath, string valueName, string value);
    void DeleteValue(string keyPath, string valueName);
    void DeleteKey(string keyPath);
}

/// <summary>Registry engine over Microsoft.Win32.Registry. Key paths use
/// HKLM\ / HKCU\ / HKCR\ prefixes. Compiles anywhere; Available=false
/// off-Windows, where the tools report unavailable honestly.</summary>
public sealed class WindowsRegistryProvider : IRegistryProvider
{
    public bool Available => OperatingSystem.IsWindows();

    private static (RegistryHive Hive, string Sub) Split(string keyPath)
    {
        var idx = keyPath.IndexOf('\\');
        var hiveName = idx < 0 ? keyPath : keyPath[..idx];
        var sub = idx < 0 ? "" : keyPath[(idx + 1)..];
        var hive = hiveName.ToUpperInvariant() switch
        {
            "HKLM" or "HKEY_LOCAL_MACHINE" => RegistryHive.LocalMachine,
            "HKCU" or "HKEY_CURRENT_USER" => RegistryHive.CurrentUser,
            "HKCR" or "HKEY_CLASSES_ROOT" => RegistryHive.ClassesRoot,
            "HKU" or "HKEY_USERS" => RegistryHive.Users,
            _ => throw new ArgumentException($"unknown hive '{hiveName}'")
        };
        return (hive, sub);
    }

    public string? GetValue(string keyPath, string valueName)
    {
        var (hive, sub) = Split(keyPath);
        using var key = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64).OpenSubKey(sub);
        return key?.GetValue(valueName)?.ToString();
    }

    public IReadOnlyList<string> ListValues(string keyPath)
    {
        var (hive, sub) = Split(keyPath);
        using var key = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64).OpenSubKey(sub);
        return key?.GetValueNames().ToList() ?? new List<string>();
    }

    public IReadOnlyList<string> ListSubKeys(string keyPath)
    {
        var (hive, sub) = Split(keyPath);
        using var key = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64).OpenSubKey(sub);
        return key?.GetSubKeyNames().ToList() ?? new List<string>();
    }

    public void SetValue(string keyPath, string valueName, string value)
    {
        var (hive, sub) = Split(keyPath);
        using var key = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64).CreateSubKey(sub);
        key.SetValue(valueName, value);
    }

    public void DeleteValue(string keyPath, string valueName)
    {
        var (hive, sub) = Split(keyPath);
        using var key = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64).OpenSubKey(sub, writable: true);
        key?.DeleteValue(valueName, throwOnMissingValue: false);
    }

    public void DeleteKey(string keyPath)
    {
        var (hive, sub) = Split(keyPath);
        var parentPath = Path.GetDirectoryName(sub) ?? "";
        var leaf = Path.GetFileName(sub);
        using var parent = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64).OpenSubKey(parentPath, writable: true);
        parent?.DeleteSubKeyTree(leaf, throwOnMissingSubKey: false);
    }
}

public sealed class RegistryGetModule : IToolModule
{
    private readonly IRegistryProvider _reg;
    public RegistryGetModule(IRegistryProvider reg) => _reg = reg;
    public ToolDescriptor Descriptor { get; } = new(
        "registry_get", "Read a registry value, or list a key's values/subkeys (action=list).",
        Scopes.Shell, SessionRequirement.Core, RiskTier.Low, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"key":{"type":"string"},"value":{"type":"string"},"action":{"type":"string","enum":["get","list"]}},"required":["key"]}""");

    public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        if (!_reg.Available) return Task.FromResult(ToolResult.Unavailable("registry is a Windows surface; this host is not running Windows"));
        var key = FileArgs.Str(arguments, "key") ?? "";
        if (DeskGuestProtectedRegistryKeys.IsProtected(key))
            return Task.FromResult(ToolResult.Error("protected_key", "DeskGuest's own service/policy registry keys refuse deletes through the generic registry tools"));
        if ((FileArgs.Str(arguments, "action") ?? "get") == "list")
            return Task.FromResult(ToolResult.Success(JsonSerializer.Serialize(new { values = _reg.ListValues(key), subkeys = _reg.ListSubKeys(key) }, new JsonSerializerOptions { WriteIndented = true })));
        var valueName = FileArgs.Str(arguments, "value") ?? "";
        var value = _reg.GetValue(key, valueName);
        return Task.FromResult(value is null
            ? ToolResult.Error("not_found", $"{key} :: {valueName}")
            : ToolResult.Success(value));
    }
}

/// <summary>BD-WIN-CORE-1 F7: DeskGuest's own registry surface is a
/// denylist for the generic registry tools — rewriting the Core's
/// service registration (or DeskGuest's policy keys) through registry_set
/// would be an ungated persistence/privilege path. The background
/// registry tool already promised this; the session tools now keep
/// the same promise.</summary>
public static class DeskGuestProtectedRegistryKeys
{
    public static bool IsProtected(string? key)
    {
        if (string.IsNullOrWhiteSpace(key)) return false;
        var k = key.Replace('/', '\\').Trim().ToLowerInvariant();
        if (k.Contains("\\services\\deskguest")) return true;                       // DeskGuestCore / DeskGuestSessionAgent service registrations
        if (k.Contains("\\software\\deskguest")) return true;                        // DeskGuest product/policy keys
        if (k.Contains("\\software\\deskguest")) return true;
        if (k.Contains("\\controlset") && k.Contains("deskguestcore")) return true;
        return false;
    }
}

public sealed class RegistrySetModule : IToolModule
{
    private readonly IRegistryProvider _reg;
    public RegistrySetModule(IRegistryProvider reg) => _reg = reg;
    public ToolDescriptor Descriptor { get; } = new(
        "registry_set", "Create/set a registry value (string). Critical tier.",
        // FR-115 (W65): Critical-tier registry writes gate like the
        // other sensitive classes — GateClass "registry_write" (the
        // class the registry backup tool already declares). Before
        // this, registry_set declared NO gate class and ran ungated
        // while the Guardrails page claimed "Gated by policy".
        Scopes.Shell, SessionRequirement.Core, RiskTier.Critical, GateClass: "registry_write", ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"key":{"type":"string"},"value":{"type":"string"},"data":{"type":"string"}},"required":["key","value","data"]}""");

    public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        if (!_reg.Available) return Task.FromResult(ToolResult.Unavailable("registry is a Windows surface; this host is not running Windows"));
        var key = FileArgs.Str(arguments, "key") ?? "";
        if (DeskGuestProtectedRegistryKeys.IsProtected(key))
            return Task.FromResult(ToolResult.Error("protected_key", "DeskGuest's own service/policy registry keys refuse deletes through the generic registry tools"));
        if (DeskGuestProtectedRegistryKeys.IsProtected(key))
            return Task.FromResult(ToolResult.Error("protected_key", "DeskGuest's own service/policy registry keys refuse writes through the generic registry tools"));
        _reg.SetValue(key, FileArgs.Str(arguments, "value") ?? "", FileArgs.Str(arguments, "data") ?? "");
        return Task.FromResult(ToolResult.Success("registry value set"));
    }
}

public sealed class RegistryDeleteModule : IToolModule
{
    private readonly IRegistryProvider _reg;
    public RegistryDeleteModule(IRegistryProvider reg) => _reg = reg;
    public ToolDescriptor Descriptor { get; } = new(
        "registry_delete", "Delete a registry value, or a whole key (whole_key=true). Critical tier.",
        // FR-115 (W65): deletes gate under the existing "deletions"
        // class, exactly like file deletions — previously ungated.
        Scopes.Shell, SessionRequirement.Core, RiskTier.Critical, GateClass: "deletions", ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"key":{"type":"string"},"value":{"type":"string"},"whole_key":{"type":"boolean"}}}""");

    public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        if (!_reg.Available) return Task.FromResult(ToolResult.Unavailable("registry is a Windows surface; this host is not running Windows"));
        var key = FileArgs.Str(arguments, "key") ?? "";
        if (DeskGuestProtectedRegistryKeys.IsProtected(key))
            return Task.FromResult(ToolResult.Error("protected_key", "DeskGuest's own service/policy registry keys refuse deletes through the generic registry tools"));
        if (arguments.TryGetProperty("whole_key", out var w) && w.ValueKind == JsonValueKind.True)
            _reg.DeleteKey(key);
        else
            _reg.DeleteValue(key, FileArgs.Str(arguments, "value") ?? "");
        return Task.FromResult(ToolResult.Success("registry delete applied"));
    }
}

// ---------- Services ----------

public sealed record ServiceInfo(string Name, string DisplayName, string Status, string StartType);

public interface IServiceProvider
{
    bool Available { get; }
    IReadOnlyList<ServiceInfo> List();
    ServiceInfo? Status(string name);
    void Start(string name);
    void Stop(string name);
    void Restart(string name);
}

public sealed class WindowsServiceProvider : IServiceProvider
{
    public bool Available => OperatingSystem.IsWindows();

    public IReadOnlyList<ServiceInfo> List()
    {
        if (!Available) return Array.Empty<ServiceInfo>();
        return ServiceController.GetServices().Select(ToInfo).ToList();
    }

    public ServiceInfo? Status(string name)
    {
        if (!Available) return null;
        try { using var sc = new ServiceController(name); return ToInfo(sc); }
        catch { return null; }
    }

    public void Start(string name) { using var sc = new ServiceController(name); sc.Start(); }
    public void Stop(string name) { using var sc = new ServiceController(name); if (sc.CanStop) sc.Stop(); }
    public void Restart(string name) { Stop(name); Start(name); }

    private static ServiceInfo ToInfo(ServiceController sc) =>
        new(sc.ServiceName, sc.DisplayName, sc.Status.ToString(), sc.StartType.ToString());
}

public sealed class ServiceListModule : IToolModule
{
    private readonly IServiceProvider _svc;
    public ServiceListModule(IServiceProvider svc) => _svc = svc;
    public ToolDescriptor Descriptor { get; } = new(
        "service_list", "List Windows services with status (optionally one service's status via {name}).",
        Scopes.Observe, SessionRequirement.Core, RiskTier.Low, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"name":{"type":"string"}}}""");

    public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        if (!_svc.Available) return Task.FromResult(ToolResult.Unavailable("services are a Windows surface; this host is not running Windows"));
        var name = FileArgs.Str(arguments, "name");
        if (name is not null)
        {
            var one = _svc.Status(name);
            return Task.FromResult(one is null ? ToolResult.Error("not_found", name) : ToolResult.Success(JsonSerializer.Serialize(one, new JsonSerializerOptions { WriteIndented = true })));
        }
        return Task.FromResult(ToolResult.Success(JsonSerializer.Serialize(_svc.List(), new JsonSerializerOptions { WriteIndented = true })));
    }
}

public sealed class ServiceControlModule : IToolModule
{
    private readonly IServiceProvider _svc;
    private readonly string _action;
    private readonly Services.ISelfRestartArmer? _armer;
    private readonly string _ownServiceName;
    private readonly Action<string, string?, string>? _auditSink;

    /// <param name="armer">The self-restart watchdog armer (Block
    /// H). REQUIRED for an DeskGuest-service restart to be possible at
    /// all: without it the restart refuses rather than risking the
    /// inline stop that stranded the Core in the 2026-11-20 drill.</param>
    /// <param name="auditSink">Chained-audit sink (kind, actor,
    /// detail): the restart intent is written BEFORE anything
    /// stops, and the refusal when arming fails.</param>
    public ServiceControlModule(IServiceProvider svc, string action,
        Services.ISelfRestartArmer? armer = null, string ownServiceName = "DeskGuestCore",
        Action<string, string?, string>? auditSink = null)
    {
        _svc = svc; _action = action; _armer = armer;
        _ownServiceName = ownServiceName; _auditSink = auditSink;
    }

    public ToolDescriptor Descriptor => new(
        $"service_{_action}", $"{_action} a Windows service. Stopping a non-DeskGuest service is a gated class.",
        Scopes.Shell, SessionRequirement.Core, RiskTier.High,
        GateClass: _action == "stop" ? "service_stop_non_deskguest" : null, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}""");

    public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        if (!_svc.Available) return Task.FromResult(ToolResult.Unavailable("services are a Windows surface; this host is not running Windows"));
        var name = (FileArgs.Str(arguments, "name") ?? "").Trim();
        if (name.Length == 0) return Task.FromResult(ToolResult.Error("bad_request", "a service name is required"));
        // DeskGuest's own service means THIS Core's service, by exact
        // name (Block H D38 fix F4). The old prefix test treated
        // ANY service starting with "DeskGuest" as the Core: restarting
        // a different DeskGuest service armed the watchdog with the
        // CORE's executable, and the rollback path would have
        // renamed the running Core's binary and swapped in the
        // Core's .prev — rolling back the wrong binary and
        // silently downgrading the Core. There is exactly one DeskGuest
        // service (the installer registers only it); anything else
        // takes the ordinary service path below.
        var isDeskGuest = string.Equals(name, _ownServiceName, StringComparison.OrdinalIgnoreCase);
        // DeskGuest's own components refuse unmanaged control (census row 45's rule, applied to services).
        if (isDeskGuest && _action == "stop")
            return Task.FromResult(ToolResult.Error("refused", "DeskGuest's own services are managed through the supervisor (agent_restart_component), never stopped via this tool"));
        // An DeskGuest service is never restarted inline (Block H): the
        // old Stop()+Start() killed the caller when the target was
        // the Core itself and stranded it stopped (2026-11-20
        // drill). The watchdog path below is the only restart an
        // DeskGuest service gets from this tool.
        if (isDeskGuest && _action == "restart")
            return Task.FromResult(RestartDeskGuestService(name, ctx));
        // BD-WIN-CORE-1 F7: a restart STOPS the service first — the
        // service_stop_non_deskguest gate that covers "stop" covers
        // "restart" too (it previously bypassed the gate entirely).
        if (_action == "restart" && !isDeskGuest && !ctx.ApprovedGateClasses.Contains("service_stop_non_deskguest"))
            return Task.FromResult(ToolResult.Error("gated:service_stop_non_deskguest", "restarting a non-DeskGuest service stops it first; the service_stop_non_deskguest gate class must be approved"));
        switch (_action)
        {
            case "start": _svc.Start(name); break;
            case "stop": _svc.Stop(name); break;
            case "restart": _svc.Restart(name); break;
        }
        // Report the OBSERVED status, not just the request: the
        // drill defect was a "requested" success over a dead
        // service. StartPending/StopPending are truthful states
        // and are reported as such.
        var observed = _svc.Status(name)?.Status ?? "Unknown";
        return Task.FromResult(ToolResult.Success($"service {name} {_action} requested — status now {observed}"));
    }

    /// <summary>Restart an DeskGuest service without ever stranding it:
    /// a STOPPED service is simply started (the caller survives —
    /// that is the recovery act, not the hazard). A RUNNING one is
    /// handed to the external watchdog: intent is chained-audited
    /// first, the watchdog owns stop/start/verify, retries the
    /// start, and rolls back to the previous binary before it ever
    /// reports failure. No armer = refusal, service untouched.</summary>
    private ToolResult RestartDeskGuestService(string name, ToolExecutionContext ctx)
    {
        var info = _svc.Status(name);
        if (info is null) return ToolResult.Error("not_found", name);
        if (string.Equals(info.Status, "Stopped", StringComparison.OrdinalIgnoreCase))
        {
            _svc.Start(name);
            _auditSink?.Invoke("service_restart", ctx.Pairing.AgentName,
                $"service {name} was Stopped; start requested via service_restart (recovery act — no stop was needed or issued)");
            var observed = _svc.Status(name)?.Status ?? "Unknown";
            return ToolResult.Success($"service {name} was stopped; start requested — status now {observed}");
        }
        if (_armer is null)
            return ToolResult.Error("unavailable",
                $"restart of DeskGuest service {name} requires the self-restart watchdog, which this host cannot arm; the service was NOT touched");
        // The watchdog's outcome file lives in the data dir; an
        // empty data dir would silently write it cwd-relative and
        // the outcome would never reach the chained audit (Block
        // H D38 fix F11). Refuse here, loudly, before arming.
        if (string.IsNullOrWhiteSpace(ctx.DataDir))
            return ToolResult.Error("unavailable",
                $"restart of DeskGuest service {name} refused: no data directory is configured on this host, so the watchdog's outcome could not be recorded; the service was NOT touched");
        _auditSink?.Invoke("service_restart_armed", ctx.Pairing.AgentName,
            $"restart of {name} ARMED by {ctx.Pairing.AgentName}: an external watchdog owns stop/start/verify; " +
            "on start failure it retries, then rolls back to the previous binary; the outcome lands in this chain at next start");
        try
        {
            _armer.Arm(name, ctx.DataDir, Environment.ProcessPath ?? "");
        }
        catch (Exception ex)
        {
            _auditSink?.Invoke("service_restart_refused", ctx.Pairing.AgentName,
                $"restart of {name} REFUSED: the watchdog could not be armed ({ex.Message}); the service was NOT touched");
            return ToolResult.Error("arm_failed",
                $"the restart watchdog could not be armed ({ex.Message}); service {name} was NOT touched");
        }
        return ToolResult.Success(
            $"service {name} restart ARMED — the external watchdog will stop and restart it, roll back to the previous binary if the start fails, " +
            "and record the outcome in the chained audit at next start. This process never stops itself.");
    }
}

// ---------- Scheduled tasks / event log / apps / battery / updates ----------

public sealed class TaskListModule : IToolModule
{
    private readonly IProcessRunner _runner;
    public TaskListModule(IProcessRunner runner) => _runner = runner;
    public ToolDescriptor Descriptor { get; } = new(
        "task_list", "List scheduled tasks with state and last result (Windows Task Scheduler).",
        Scopes.Observe, SessionRequirement.Core, RiskTier.Low, ExecutionContext: "SYSTEM");

    public async Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows()) return ToolResult.Unavailable("scheduled tasks are a Windows surface; this host is not running Windows");
        var r = await _runner.RunAsync("schtasks.exe", "/query /fo CSV /v", TimeSpan.FromSeconds(60), ct);
        return r.ExitCode == 0 ? ToolResult.Success(r.StdOut) : ToolResult.Error("schtasks_failed", r.StdErr);
    }
}

public sealed class EventLogReadModule : IToolModule
{
    public ToolDescriptor Descriptor { get; } = new(
        "event_log_read", "Read Windows event log entries, newest first (incl. the endpoint's own post-mortem evidence).",
        Scopes.Observe, SessionRequirement.Core, RiskTier.Low, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"log":{"type":"string","default":"System"},"max_entries":{"type":"integer","default":50},"level":{"type":"string"}}}""");

    public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows()) return Task.FromResult(ToolResult.Unavailable("event logs are a Windows surface; this host is not running Windows"));
        // UNPROVEN-ON-WINDOWS: System.Diagnostics.EventLog read path.
        var logName = FileArgs.Str(arguments, "log") ?? "System";
        var max = arguments.TryGetProperty("max_entries", out var m) ? Math.Clamp(m.GetInt32(), 1, 500) : 50;
        var level = FileArgs.Str(arguments, "level");
        using var log = new EventLog(logName);
        var entries = new List<object>();
        for (var i = log.Entries.Count - 1; i >= 0 && entries.Count < max; i--)
        {
            var e = log.Entries[i];
            if (level is not null && !e.EntryType.ToString().Equals(level, StringComparison.OrdinalIgnoreCase)) continue;
            entries.Add(new { time = e.TimeGenerated, type = e.EntryType.ToString(), source = e.Source, id = e.InstanceId, message = e.Message.Length > 500 ? e.Message[..500] : e.Message });
        }
        return Task.FromResult(ToolResult.Success(JsonSerializer.Serialize(entries, new JsonSerializerOptions { WriteIndented = true })));
    }
}

public sealed class AppInventoryModule : IToolModule
{
    private readonly IRegistryProvider _reg;
    public AppInventoryModule(IRegistryProvider reg) => _reg = reg;
    public ToolDescriptor Descriptor { get; } = new(
        "app_inventory", "Installed applications (from the uninstall registry keys).",
        Scopes.Observe, SessionRequirement.Core, RiskTier.Low, ExecutionContext: "SYSTEM");

    public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        if (!_reg.Available) return Task.FromResult(ToolResult.Unavailable("the app inventory reads Windows registry keys; this host is not running Windows"));
        var apps = new List<object>();
        foreach (var root in new[]
        {
            @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            @"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            @"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
        })
        {
            foreach (var sub in _reg.ListSubKeys(root))
            {
                var name = _reg.GetValue($@"{root}\{sub}", "DisplayName");
                if (name is null) continue;
                apps.Add(new { name, version = _reg.GetValue($@"{root}\{sub}", "DisplayVersion"), publisher = _reg.GetValue($@"{root}\{sub}", "Publisher") });
            }
        }
        return Task.FromResult(ToolResult.Success(JsonSerializer.Serialize(apps, new JsonSerializerOptions { WriteIndented = true })));
    }
}

public sealed class BatteryStatusModule : IToolModule
{
    private readonly IProcessRunner _runner;
    public BatteryStatusModule(IProcessRunner runner) => _runner = runner;
    public ToolDescriptor Descriptor { get; } = new(
        "battery_status", "Charge, health, and AC state. A closet laptop's battery is its mini-UPS; this is availability data.",
        Scopes.Observe, SessionRequirement.Core, RiskTier.Low, ExecutionContext: "SYSTEM");

    public async Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows()) return ToolResult.Unavailable("battery telemetry here uses WMI on Windows; this host is not running Windows");
        var r = await _runner.RunAsync("powershell.exe",
            "-NoProfile -NonInteractive -Command \"Get-CimInstance Win32_Battery | Select-Object EstimatedChargeRemaining,BatteryStatus,DesignCapacity,FullChargeCapacity | ConvertTo-Json -Compress\"",
            TimeSpan.FromSeconds(30), ct);
        if (r.ExitCode != 0 || string.IsNullOrWhiteSpace(r.StdOut))
            return ToolResult.Unavailable("no battery readable on this machine (a desktop reports this honestly)");
        return ToolResult.Success(r.StdOut.Trim());
    }
}

public sealed class ProcessKillModule : IToolModule
{
    public ToolDescriptor Descriptor { get; } = new(
        "process_kill", "End a process by PID. DeskGuest's own components refuse self-kill via this tool (supervisor paths only).",
        Scopes.Shell, SessionRequirement.Core, RiskTier.High, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"pid":{"type":"integer"}},"required":["pid"]}""");

    public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var pid = arguments.TryGetProperty("pid", out var p) ? p.GetInt32() : 0;
        try
        {
            using var proc = System.Diagnostics.Process.GetProcessById(pid);
            if (proc.ProcessName.StartsWith("DeskGuest", StringComparison.OrdinalIgnoreCase))
                return Task.FromResult(ToolResult.Error("refused", "DeskGuest components are managed through the supervisor (agent_restart_component), never killed via this tool"));
            proc.Kill();
            return Task.FromResult(ToolResult.Success($"killed {proc.ProcessName} ({pid})"));
        }
        catch (Exception ex) { return Task.FromResult(ToolResult.Error(ex.GetType().Name, ex.Message)); }
    }
}
