using System.Diagnostics;
using System.IO.Compression;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.Json;
using DeskGuest.Core.Platform;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.Tools;

namespace DeskGuest.Core.Modules;

public sealed class DeviceInfoModule : IToolModule
{
    public ToolDescriptor Descriptor { get; } = new(
        "device_info", "Model/host, OS build, CPU, RAM, architecture.",
        Scopes.Observe, SessionRequirement.Core, RiskTier.Low, ExecutionContext: "SYSTEM");

    public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var gc = GC.GetGCMemoryInfo();
        return Task.FromResult(ToolResult.Success(JsonSerializer.Serialize(new
        {
            host_name = Environment.MachineName,
            os = Environment.OSVersion.VersionString,
            os_architecture = System.Runtime.InteropServices.RuntimeInformation.OSArchitecture.ToString(),
            process_architecture = System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture.ToString(),
            cpu_count = Environment.ProcessorCount,
            total_memory_gb = Math.Round(gc.TotalAvailableMemoryBytes / 1073741824.0, 1),
            running_as = Environment.UserName,
            dotnet = Environment.Version.ToString()
        }, new JsonSerializerOptions { WriteIndented = true })));
    }
}

public sealed class DiskStatusModule : IToolModule
{
    public ToolDescriptor Descriptor { get; } = new(
        "disk_status", "Volumes, free space, format, readiness.",
        Scopes.Observe, SessionRequirement.Core, RiskTier.Low, ExecutionContext: "SYSTEM");

    public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var drives = DriveInfo.GetDrives().Where(d => d.IsReady).Select(d => new
        {
            name = d.Name, format = d.DriveFormat,
            total_gb = Math.Round(d.TotalSize / 1073741824.0, 1),
            free_gb = Math.Round(d.AvailableFreeSpace / 1073741824.0, 1),
            free_percent = Math.Round(100.0 * d.AvailableFreeSpace / d.TotalSize, 1)
        });
        return Task.FromResult(ToolResult.Success(JsonSerializer.Serialize(drives, new JsonSerializerOptions { WriteIndented = true })));
    }
}

public sealed class BootStateModule : IToolModule
{
    private readonly CoreState _state;
    private readonly string _dataDir;
    public BootStateModule(CoreState state, string dataDir) { _state = state; _dataDir = dataDir; }
    public ToolDescriptor Descriptor { get; } = new(
        "boot_state", "Boot count, uptime, and whether the previous shutdown was clean (post-mortem input, DESIGN §4.4).",
        Scopes.Observe, SessionRequirement.Core, RiskTier.Low, ExecutionContext: "SYSTEM");

    public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var countPath = Path.Combine(_dataDir, "boot-count.txt");
        var boots = File.Exists(countPath) && int.TryParse(File.ReadAllText(countPath), out var n) ? n : 0;
        var prev = _state.BuildReport(Array.Empty<Shared.State.SubsystemHealth>()).PreviousRun;
        return Task.FromResult(ToolResult.Success(JsonSerializer.Serialize(new
        {
            boot_count_observed_by_deskguest = boots,
            uptime = TimeSpan.FromMilliseconds(Environment.TickCount64).ToString(),
            previous_run = prev is null ? null : new { prev.EndedCleanly, last_state = prev.LastState?.ToString(), prev.LastSeenUtc, prev.Characterization }
        }, new JsonSerializerOptions { WriteIndented = true })));
    }
}

public sealed class PerformanceCountersModule : IToolModule
{
    public ToolDescriptor Descriptor { get; } = new(
        "performance_counters", "A short performance snapshot: total CPU %, memory pressure, process count.",
        Scopes.Observe, SessionRequirement.Core, RiskTier.Low, ExecutionContext: "SYSTEM");

    public async Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var procs = Process.GetProcesses();
        var t0 = procs.ToDictionary(p => p.Id, p => SafeCpu(p));
        var wall0 = DateTimeOffset.UtcNow;
        await Task.Delay(300, ct);
        var cpuTotal = 0.0;
        var count = 0;
        foreach (var p in Process.GetProcesses())
        {
            try
            {
                if (t0.TryGetValue(p.Id, out var before))
                {
                    cpuTotal += (SafeCpu(p) - before).TotalMilliseconds;
                    count++;
                }
            }
            catch { }
            finally { p.Dispose(); }
        }
        foreach (var p in procs) p.Dispose();
        var elapsed = (DateTimeOffset.UtcNow - wall0).TotalMilliseconds;
        var cpuPercent = elapsed > 0 ? Math.Round(100.0 * cpuTotal / elapsed / Environment.ProcessorCount, 1) : 0;
        var gc = GC.GetGCMemoryInfo();
        return ToolResult.Success(JsonSerializer.Serialize(new
        {
            cpu_percent_total = cpuPercent,
            processes_sampled = count,
            memory_available_gb = Math.Round(gc.TotalAvailableMemoryBytes / 1073741824.0, 1),
            note = "snapshot sampled over 300 ms from the process table"
        }, new JsonSerializerOptions { WriteIndented = true }));
    }

    private static TimeSpan SafeCpu(Process p) { try { return p.TotalProcessorTime; } catch { return TimeSpan.Zero; } }
}

public sealed class DiagnosticsBundleModule : IToolModule
{
    private readonly CoreState _state;
    private readonly Func<CancellationToken, Task<IReadOnlyList<Shared.State.SubsystemHealth>>> _selfCheck;
    private readonly Shared.Audit.IAuditLog _audit;
    private readonly string _stagingRoot;

    public DiagnosticsBundleModule(CoreState state, Func<CancellationToken, Task<IReadOnlyList<Shared.State.SubsystemHealth>>> selfCheck, Shared.Audit.IAuditLog audit, string stagingRoot)
    {
        _state = state; _selfCheck = selfCheck; _audit = audit; _stagingRoot = stagingRoot;
    }

    public ToolDescriptor Descriptor { get; } = new(
        "diagnostics_bundle", "Collect state, health, heartbeat, and audit tail into one evidence zip in the staging store.",
        Scopes.Observe, SessionRequirement.Core, RiskTier.Low, ExecutionContext: "SYSTEM");

    public async Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var name = $"diagnostics-{DateTimeOffset.UtcNow:yyyyMMdd-HHmmss}.zip";
        var path = Path.Combine(_stagingRoot, name);
        var subsystems = await _selfCheck(ct);
        using (var zip = ZipFile.Open(path, ZipArchiveMode.Create))
        {
            void Add(string entry, string content)
            {
                var e = zip.CreateEntry(entry);
                using var w = new StreamWriter(e.Open());
                w.Write(content);
            }
            Add("endpoint-state.json", JsonSerializer.Serialize(_state.BuildReport(subsystems), new JsonSerializerOptions { WriteIndented = true }));
            Add("heartbeat.json", JsonSerializer.Serialize(_state.BuildHeartbeat(), new JsonSerializerOptions { WriteIndented = true }));
            Add("audit-tail.json", JsonSerializer.Serialize(_audit.ReadTail(200), new JsonSerializerOptions { WriteIndented = true }));
        }
        return ToolResult.Success($"diagnostics bundle written: {path}");
    }
}

public sealed class UpdateStatusModule : IToolModule
{
    private readonly IRegistryProvider _reg;
    private readonly CoreState _state;
    public UpdateStatusModule(IRegistryProvider reg, CoreState state) { _reg = reg; _state = state; }
    public ToolDescriptor Descriptor { get; } = new(
        "update_status", "Pending-reboot state and update posture. (Full Windows Update enumeration rides the Phase 2 patch module.)",
        Scopes.Observe, SessionRequirement.Core, RiskTier.Low, ExecutionContext: "SYSTEM");

    public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var pending = false;
        string? evidence = null;
        if (_reg.Available)
        {
            // The standard pending-reboot witnesses.
            if (_reg.ListSubKeys(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing").Contains("RebootPending"))
            { pending = true; evidence = "CBS RebootPending key present"; }
            else if (_reg.GetValue(@"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager", "PendingFileRenameOperations") is not null)
            { pending = true; evidence = "PendingFileRenameOperations present"; }
        }
        _state.SetPendingReboot(pending);
        return Task.FromResult(ToolResult.Success(JsonSerializer.Serialize(new
        {
            pending_reboot = pending,
            evidence = evidence ?? (_reg.Available ? "no pending-reboot witness found" : "registry witnesses unavailable off-Windows")
        })));
    }
}

public sealed class BitLockerStatusModule : IToolModule
{
    private readonly IFactChecks _facts;
    public BitLockerStatusModule(IFactChecks facts) => _facts = facts;
    public ToolDescriptor Descriptor { get; } = new(
        "bitlocker_status", "Volume encryption state + protector types. Recovery-key material is NEVER read (X14).",
        Scopes.Observe, SessionRequirement.Core, RiskTier.Low, ExecutionContext: "SYSTEM");

    public async Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var facts = await _facts.RunAsync(ct);
        return ToolResult.Success(JsonSerializer.Serialize(new { level = facts.BitLocker.Level.ToString(), facts.BitLocker.Reason }));
    }
}

public sealed class SessionInventoryModule : IToolModule
{
    private readonly CoreState _state;
    public SessionInventoryModule(CoreState state) => _state = state;
    public ToolDescriptor Descriptor { get; } = new(
        "session_inventory", "Logon sessions on the machine, derived from the process table plus the agent's own session report.",
        Scopes.Observe, SessionRequirement.Core, RiskTier.Low, ExecutionContext: "SYSTEM");

    public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var bySession = new Dictionary<int, int>();
        foreach (var p in Process.GetProcesses())
        {
            try { bySession[p.SessionId] = bySession.GetValueOrDefault(p.SessionId) + 1; }
            catch { }
            finally { p.Dispose(); }
        }
        var session = _state.Session;
        var rows = bySession.Select(kv => new
        {
            session_id = kv.Key,
            process_count = kv.Value,
            is_agent_session = kv.Key != 0 && session.SessionExists,
            note = kv.Key == 0 ? "Session 0 (services — the Core lives here)" : "interactive session"
        });
        return Task.FromResult(ToolResult.Success(JsonSerializer.Serialize(rows, new JsonSerializerOptions { WriteIndented = true })));
    }
}

// ---------- Network ----------

public sealed class NetPingModule : IToolModule
{
    public ToolDescriptor Descriptor { get; } = new(
        "net_ping", "Ping / DNS-resolve a host from the laptop's seat (action=ping|dns).",
        Scopes.Observe, SessionRequirement.Core, RiskTier.Low, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"host":{"type":"string"},"action":{"type":"string","enum":["ping","dns"]}},"required":["host"]}""");

    public async Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var host = FileArgs.Str(arguments, "host") ?? "";
        if ((FileArgs.Str(arguments, "action") ?? "ping") == "dns")
        {
            var entry = await Dns.GetHostEntryAsync(host, ct);
            return ToolResult.Success(JsonSerializer.Serialize(new { host = entry.HostName, addresses = entry.AddressList.Select(a => a.ToString()) }));
        }
        using var ping = new Ping();
        var reply = await ping.SendPingAsync(host, 4000);
        return ToolResult.Success(JsonSerializer.Serialize(new { status = reply.Status.ToString(), roundtrip_ms = reply.RoundtripTime, address = reply.Address?.ToString() }));
    }
}

public sealed class NetPortCheckModule : IToolModule
{
    public ToolDescriptor Descriptor { get; } = new(
        "net_port_check", "TCP connect test to host:port from the laptop's seat.",
        Scopes.Observe, SessionRequirement.Core, RiskTier.Low, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"host":{"type":"string"},"port":{"type":"integer"}},"required":["host","port"]}""");

    public async Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var host = FileArgs.Str(arguments, "host") ?? "";
        var port = arguments.TryGetProperty("port", out var p) ? p.GetInt32() : 0;
        using var client = new TcpClient();
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(5));
        try
        {
            await client.ConnectAsync(host, port, timeout.Token);
            return ToolResult.Success($"{host}:{port} is reachable (TCP connect succeeded)");
        }
        catch (Exception ex)
        {
            return ToolResult.Success($"{host}:{port} is NOT reachable ({ex.GetType().Name})");
        }
    }
}

public sealed class NetAdaptersModule : IToolModule
{
    public ToolDescriptor Descriptor { get; } = new(
        "net_adapters", "Network adapters: type, status, addresses, link speed. Proves the closet box is hardwired.",
        Scopes.Observe, SessionRequirement.Core, RiskTier.Low, ExecutionContext: "SYSTEM");

    public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var rows = NetworkInterface.GetAllNetworkInterfaces().Select(ni => new
        {
            name = ni.Name,
            type = ni.NetworkInterfaceType.ToString(),
            status = ni.OperationalStatus.ToString(),
            speed_mbps = ni.Speed > 0 ? ni.Speed / 1_000_000 : 0,
            addresses = ni.GetIPProperties().UnicastAddresses.Select(a => a.Address.ToString()).ToArray()
        });
        return Task.FromResult(ToolResult.Success(JsonSerializer.Serialize(rows, new JsonSerializerOptions { WriteIndented = true })));
    }
}

public sealed class NetTailscaleStateModule : IToolModule
{
    private readonly CoreState _state;
    public NetTailscaleStateModule(CoreState state) => _state = state;
    public ToolDescriptor Descriptor { get; } = new(
        "net_tailscale_state", "The connection supervisor's own report: lane phases and bound addresses.",
        Scopes.Observe, SessionRequirement.Core, RiskTier.Low, ExecutionContext: "SYSTEM");

    public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        if (_state.Lanes is null) return Task.FromResult(ToolResult.Unavailable("lane supervisor not initialised"));
        var ts = _state.Lanes.Status(Shared.Connection.LaneKind.Tailscale);
        var lan = _state.Lanes.Status(Shared.Connection.LaneKind.Lan);
        return Task.FromResult(ToolResult.Success(JsonSerializer.Serialize(new { tailscale = ts, lan }, new JsonSerializerOptions { WriteIndented = true })));
    }
}

public sealed class NetConnectionsModule : IToolModule
{
    public ToolDescriptor Descriptor { get; } = new(
        "net_connections", "Live TCP connections with local/remote endpoints and state.",
        Scopes.Observe, SessionRequirement.Core, RiskTier.Low, ExecutionContext: "SYSTEM");

    public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var conns = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections()
            .Select(c => new { local = c.LocalEndPoint.ToString(), remote = c.RemoteEndPoint.ToString(), state = c.State.ToString() });
        return Task.FromResult(ToolResult.Success(JsonSerializer.Serialize(conns, new JsonSerializerOptions { WriteIndented = true })));
    }
}

// ---------- Power / panic / restart / elevate ----------

/// <summary>Census row 75 (D-POWER): reboot is a gated class. The Core
/// announces its departure first (last-word protocol), then reboots.
/// Shutdown and sleep are excluded from remote call entirely (rows
/// 76/77) — there is deliberately no module for them.</summary>
public sealed class PowerRebootModule : IToolModule
{
    private readonly IProcessRunner _runner;
    private readonly Action<string> _announceDeparture;
    private readonly Func<bool> _isWindows;
    public PowerRebootModule(IProcessRunner runner, Action<string> announceDeparture, Func<bool>? isWindows = null)
    {
        _runner = runner;
        _announceDeparture = announceDeparture;
        _isWindows = isWindows ?? (() => OperatingSystem.IsWindows());
    }

    public ToolDescriptor Descriptor { get; } = new(
        "power_reboot", "Reboot the machine (gated class: power). The endpoint announces its departure first and reports the whole ride.",
        Scopes.Admin, SessionRequirement.Core, RiskTier.High, GateClass: "power", ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"delay_seconds":{"type":"integer","default":5}}}""");

    public async Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        if (!_isWindows()) return ToolResult.Unavailable("power actions execute only on the Windows host");
        var delay = arguments.TryGetProperty("delay_seconds", out var d) ? Math.Clamp(d.GetInt32(), 0, 600) : 5;
        _announceDeparture($"reboot requested by {ctx.Pairing.AgentName}; rebooting in {delay}s");
        var r = await _runner.RunAsync("shutdown.exe", $"/r /t {delay} /c \"DeskGuest: reboot requested by an agent\"", TimeSpan.FromSeconds(15), ct);
        return r.ExitCode == 0 ? ToolResult.Success($"reboot scheduled in {delay}s") : ToolResult.Error("shutdown_failed", r.StdErr);
    }
}

/// <summary>Census row 140 (Core half): panic stop — any authenticated
/// pairing can slam the brake; it engages the same host-side STOP the
/// tray and STOP file engage.</summary>
public sealed class PanicStopModule : IToolModule
{
    private readonly CoreState _state;
    public PanicStopModule(CoreState state) => _state = state;
    public ToolDescriptor Descriptor { get; } = new(
        "panic_stop", "Halt everything now: engages STOP host-side; sessions end and new ones are blocked until the owner clears it.",
        Scopes.Observe, SessionRequirement.Core, RiskTier.Low, ExecutionContext: "SYSTEM");

    public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        _state.SetUserStop(true);
        return Task.FromResult(ToolResult.Success("STOP engaged by panic_stop; only the owner can clear it"));
    }
}

public interface IAgentRestarter
{
    void RestartAgent();
    void RequestElevation();
}

/// <summary>Census row 86: restart a component through the supervisor —
/// the managed path. (Row 45 refuses the unmanaged one.)</summary>
public sealed class AgentRestartComponentModule : IToolModule
{
    private readonly IAgentRestarter _restarter;
    public AgentRestartComponentModule(IAgentRestarter restarter) => _restarter = restarter;
    public ToolDescriptor Descriptor { get; } = new(
        "agent_restart_component", "Restart the Session Agent through the supervisor (drop + watchdog relaunch). Core restarts are SCM's job and are reported, not self-inflicted.",
        Scopes.Admin, SessionRequirement.Core, RiskTier.High, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"component":{"type":"string","enum":["agent"]}}}""");

    public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        _restarter.RestartAgent();
        return Task.FromResult(ToolResult.Success("agent restart requested through the supervisor; the watchdog relaunches it and the audit log shows it"));
    }
}

/// <summary>Census row 89: elevation is a session state the Core grants
/// per pairing scope (admin) — the Core relaunches the Agent at high
/// integrity so elevated app windows become automatable. Visible in
/// the banner, audit-logged, ends with the session (DESIGN §1A.2).
/// UNPROVEN-ON-WINDOWS: the token surgery is laptop-gate work.</summary>
public sealed class AgentElevateModule : IToolModule
{
    private readonly IAgentRestarter _restarter;
    private readonly CoreState _state;
    public AgentElevateModule(IAgentRestarter restarter, CoreState state) { _restarter = restarter; _state = state; }
    public ToolDescriptor Descriptor { get; } = new(
        "agent_elevate", "Relaunch the Session Agent at high integrity for this session (admin scope), making elevated windows automatable. Reports unavailable if the signed-in account is not a local admin.",
        Scopes.Admin, SessionRequirement.Core, RiskTier.High, ExecutionContext: "SYSTEM");

    public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        _restarter.RequestElevation();
        _state.UpdateSession(s => s with { AgentElevated = true });
        return Task.FromResult(ToolResult.Success("elevation relaunch requested; the banner shows the elevated state while it lasts"));
    }
}

// ---------- U6: connection doctor ----------

/// <summary>U6 connection doctor: answers "why can't I connect" from
/// facts DeskGuest already has (lane state, engine attempt events, local
/// interface addresses). DIAGNOSTIC ONLY: it takes no target to probe
/// — an optional peer_address is CLASSIFIED (parsed) and never
/// contacted, and peer_nat lets a caller state what the peer already
/// reported about itself. It changes no setting, binds nothing, and
/// sends no traffic (the shared doctor contains no network I/O).
/// Every failure line is {what, why in plain language, fix}; the D18
/// both-ends-hostile-NAT corner is named as D18, never generic.</summary>
public sealed class ConnectionDoctorModule : IToolModule
{
    private readonly Func<Shared.Connection.DoctorFacts> _facts;
    public ConnectionDoctorModule(Func<Shared.Connection.DoctorFacts> facts) => _facts = facts;

    public ToolDescriptor Descriptor { get; } = new(
        "connection_doctor", "Diagnose why a pairing/transport cannot connect: per-rung state with plain-language reasons and fixes, NAT classification from local facts, and the D18 corner named when it applies. Diagnostic only — probes nothing and changes nothing.",
        Scopes.Observe, SessionRequirement.Core, RiskTier.Low, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"peer_address":{"type":"string","description":"an already-known peer address to classify (parsed only, never contacted)"},"peer_nat":{"type":"string","enum":["Unknown","PublicDirect","BehindNat","CarrierGradeNat","DoubleNat","Hostile"],"description":"what the peer already reported about its own NAT"}}}""");

    public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var facts = _facts();
        var peerAddress = FileArgs.Str(arguments, "peer_address") ?? facts.PeerAddress;
        var peerNat = facts.PeerNat;
        if (FileArgs.Str(arguments, "peer_nat") is { } pn &&
            Enum.TryParse<Shared.Connection.NatClass>(pn, ignoreCase: true, out var parsed))
            peerNat = parsed;
        var report = Shared.Connection.ConnectionDoctor.Diagnose(
            facts with { PeerAddress = peerAddress, PeerNat = peerNat });
        return Task.FromResult(ToolResult.Success(JsonSerializer.Serialize(new
        {
            summary = report.Summary,
            diagnostic_only = "this report changed no setting, opened no listener, and sent no traffic; peer addresses are classified, never contacted; NAT depth beyond the local interface is not observable without an owner-configured external endpoint, and the report says so rather than guessing",
            local_nat = report.LocalNat.ToString(),
            local_address_class = report.LocalAddressClass.ToString(),
            peer_nat = report.PeerNat.ToString(),
            is_d18_corner = report.IsD18Corner,
            d18 = report.IsD18Corner ? Shared.Connection.ConnectionDoctor.D18Explanation : null,
            nat_note = report.NatNote,
            rungs = report.Rungs.Select(r => new
            {
                rung = r.Rung, state = r.State.ToString(), evidence = r.Evidence,
                is_d18_corner = r.IsD18Corner,
                finding = r.Finding is null ? null : new { what = r.Finding.What, why = r.Finding.Why, fix = r.Finding.Fix }
            }),
            findings = report.Findings.Select(f => new { what = f.What, why = f.Why, fix = f.Fix })
        }, new JsonSerializerOptions { WriteIndented = true })));
    }
}
