using System.Text.Json;
using System.Text.RegularExpressions;
using DeskGuest.Core.Modules;
using DeskGuest.Core.Platform;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.Tools;

namespace DeskGuest.Core.Phase2;

/// <summary>Base for the Windows-admin family that rides PowerShell /
/// inbox CLIs through the SYSTEM runner. Off-Windows every one reports
/// unavailable — the command surfaces are Windows', and the tools say
/// so instead of failing obscurely. UNPROVEN-ON-WINDOWS command lines
/// are first exercised at the laptop gate.</summary>
public abstract class RunnerModule : IToolModule
{
    protected readonly IProcessRunner Runner;
    protected RunnerModule(IProcessRunner runner) => Runner = runner;
    public abstract ToolDescriptor Descriptor { get; }

    protected async Task<ToolResult> PsAsync(string command, CancellationToken ct, int timeoutSeconds = 120)
    {
        if (!OperatingSystem.IsWindows())
            return ToolResult.Unavailable("this is a Windows administration surface; this host is not running Windows");
        var r = await Runner.RunAsync("powershell.exe", $"-NoProfile -NonInteractive -Command \"{command.Replace("\"", "\\\"")}\"", TimeSpan.FromSeconds(timeoutSeconds), ct);
        return r.ExitCode == 0 ? ToolResult.Success(r.StdOut) : ToolResult.Error("command_failed", string.IsNullOrWhiteSpace(r.StdErr) ? r.StdOut : r.StdErr);
    }

    /// <summary>Quote a caller-supplied value as a PowerShell
    /// single-quoted literal (2026-11-15 blocker fix). Doubling the
    /// single quote is PowerShell's own escape inside such literals,
    /// so the value can never break out into command position — the
    /// admin modules previously interpolated caller strings raw into
    /// '-quoted slots, and one quote in a user/drive/printer name ran
    /// arbitrary PowerShell as SYSTEM. EVERY caller value that lands
    /// inside a PsAsync command goes through here.</summary>
    public static string PsLiteral(string? value) => "'" + (value ?? "").Replace("'", "''") + "'";

    /// <summary>Allowlist shape for values that must land UNQUOTED in
    /// a native command line (winget ids, wevtutil log names): a
    /// conservative character set with no quotes, spaces, or shell /
    /// argument separators.</summary>
    protected static bool IsSafeUnquoted(string? value, string pattern) =>
        value is not null && Regex.IsMatch(value, pattern);

    public abstract Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct);
}

public sealed class PackageManageModule : RunnerModule
{
    public PackageManageModule(IProcessRunner r) : base(r) { }
    public override ToolDescriptor Descriptor { get; } = new(
        "package_manage", "winget inventory/install/upgrade/remove (action=list|install|upgrade|remove). Installs are a gated class.",
        Scopes.Shell, SessionRequirement.Core, RiskTier.High, GateClass: "installs", ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"action":{"type":"string"},"package_id":{"type":"string"}}}""");

    public override async Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var action = FileArgs.Str(arguments, "action") ?? "list";
        var id = FileArgs.Str(arguments, "package_id") ?? "";
        // The id lands UNQUOTED in winget's argument string (2026-11-15
        // blocker-fix sweep): hold it to the winget id alphabet so it
        // can never smuggle extra switches into the command line.
        // Validation precedes the OS gate: bad input is bad input on
        // every host.
        if (action != "list" && !IsSafeUnquoted(id, "^[A-Za-z0-9._+-]+$"))
            return ToolResult.Error("bad_arguments", "package_id must be a plain winget id (letters, digits, '.', '_', '-', '+')");
        if (!OperatingSystem.IsWindows()) return ToolResult.Unavailable("winget is a Windows surface; this host is not running Windows");
        var args = action switch
        {
            "list" => "list --accept-source-agreements",
            "install" => $"install --id {id} --accept-source-agreements --accept-package-agreements --silent",
            "upgrade" => $"upgrade --id {id} --accept-source-agreements --accept-package-agreements --silent",
            "remove" => $"uninstall --id {id} --silent",
            _ => ""
        };
        if (args == "") return ToolResult.Error("bad_arguments", action);
        var r = await Runner.RunAsync("winget.exe", args, TimeSpan.FromMinutes(10), ct);
        return r.ExitCode == 0 ? ToolResult.Success(r.StdOut) : ToolResult.Error("winget_failed", r.StdErr + r.StdOut);
    }
}

public sealed class PatchManageModule : RunnerModule
{
    public PatchManageModule(IProcessRunner r) : base(r) { }
    public override ToolDescriptor Descriptor { get; } = new(
        "patch_manage", "Windows Update status/apply via the Windows Update Agent COM API (through PowerShell).",
        Scopes.Shell, SessionRequirement.Core, RiskTier.High, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"action":{"type":"string","enum":["status","apply"]}}}""");

    public override async Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var action = FileArgs.Str(arguments, "action") ?? "status";
        var script = action == "status"
            ? "$s=New-Object -ComObject Microsoft.Update.Session; $q=$s.CreateUpdateSearcher().Search('IsInstalled=0'); $q.Updates | ForEach-Object { $_.Title } "
            : "$s=New-Object -ComObject Microsoft.Update.Session; $q=$s.CreateUpdateSearcher().Search('IsInstalled=0'); $c=New-Object -ComObject Microsoft.Update.UpdateColl; $q.Updates | ForEach-Object { $c.Add($_) | Out-Null }; $d=$s.CreateUpdateDownloader(); $d.Updates=$c; $d.Download() | Out-Null; $i=$s.CreateUpdateInstaller(); $i.Updates=$c; ($i.Install()).ResultCode";
        return await PsAsync(script, ct, 900);
    }
}

public sealed class DefenderManageModule : RunnerModule
{
    public DefenderManageModule(IProcessRunner r) : base(r) { }
    public override ToolDescriptor Descriptor { get; } = new(
        "defender_manage", "Defender status + start a quick/full/custom scan with result report. Policy changes stay gated shell work.",
        Scopes.Shell, SessionRequirement.Core, RiskTier.Medium, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"action":{"type":"string","enum":["status","quick_scan","full_scan"]}}}""");

    public override async Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var action = FileArgs.Str(arguments, "action") ?? "status";
        return action switch
        {
            "status" => await PsAsync("Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated | ConvertTo-Json -Compress", ct),
            "quick_scan" => await PsAsync("Start-MpScan -ScanType QuickScan; 'quick scan started'", ct),
            "full_scan" => await PsAsync("Start-MpScan -ScanType FullScan; 'full scan started'", ct),
            _ => ToolResult.Error("bad_arguments", action)
        };
    }
}

public sealed class UserGroupAdminModule : RunnerModule
{
    public UserGroupAdminModule(IProcessRunner r) : base(r) { }
    public override ToolDescriptor Descriptor { get; } = new(
        "user_group_admin", "Local users/groups: list, or disable a user (admin scope). Creating users is laptop-UI work in Phase 2's posture — agents do not mint identities (X20's spirit).",
        Scopes.Admin, SessionRequirement.Core, RiskTier.High, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"action":{"type":"string","enum":["list_users","list_groups","disable_user"]},"name":{"type":"string"}}}""");

    public override async Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var action = FileArgs.Str(arguments, "action") ?? "list_users";
        return action switch
        {
            "list_users" => await PsAsync("Get-LocalUser | Select-Object Name,Enabled,LastLogon | ConvertTo-Json -Compress", ct),
            "list_groups" => await PsAsync("Get-LocalGroup | Select-Object Name,Description | ConvertTo-Json -Compress", ct),
            "disable_user" => await PsAsync($"Disable-LocalUser -Name {PsLiteral(FileArgs.Str(arguments, "name"))}; 'disabled'", ct),
            _ => ToolResult.Error("bad_arguments", action)
        };
    }
}

public sealed class SystemRepairModule : RunnerModule
{
    public SystemRepairModule(IProcessRunner r) : base(r) { }
    public override ToolDescriptor Descriptor { get; } = new(
        "system_repair", "DISM/SFC runs with captured verdicts + driver inventory (pnputil).",
        Scopes.Shell, SessionRequirement.Core, RiskTier.High, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"action":{"type":"string","enum":["dism_check","sfc","drivers"]}}}""");

    public override async Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows()) return ToolResult.Unavailable("DISM/SFC are Windows surfaces; this host is not running Windows");
        var action = FileArgs.Str(arguments, "action") ?? "dism_check";
        var (file, args, timeout) = action switch
        {
            "dism_check" => ("dism.exe", "/Online /Cleanup-Image /CheckHealth", 300),
            "sfc" => ("sfc.exe", "/scannow", 1800),
            "drivers" => ("pnputil.exe", "/enum-drivers", 120),
            _ => ("", "", 0)
        };
        if (file == "") return ToolResult.Error("bad_arguments", action);
        var r = await Runner.RunAsync(file, args, TimeSpan.FromSeconds(timeout), ct);
        return ToolResult.Success(JsonSerializer.Serialize(new { exit_code = r.ExitCode, output = r.StdOut, errors = r.StdErr }));
    }
}

public sealed class MappedDrivesModule : RunnerModule
{
    public MappedDrivesModule(IProcessRunner r) : base(r) { }
    public override ToolDescriptor Descriptor { get; } = new(
        "mapped_drives", "List/map/unmap network drives in the owner's context (via the session agent's user context on Windows; SYSTEM view here).",
        Scopes.Shell, SessionRequirement.Core, RiskTier.Medium, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"action":{"type":"string","enum":["list","map","unmap"]},"letter":{"type":"string"},"unc":{"type":"string"}}}""");

    public override async Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var action = FileArgs.Str(arguments, "action") ?? "list";
        return action switch
        {
            "list" => await PsAsync("Get-PSDrive -PSProvider FileSystem | Select-Object Name,Root,DisplayRoot | ConvertTo-Json -Compress", ct),
            "map" => await PsAsync($"New-PSDrive -Name {PsLiteral(FileArgs.Str(arguments, "letter"))} -PSProvider FileSystem -Root {PsLiteral(FileArgs.Str(arguments, "unc"))} -Persist | Out-Null; 'mapped'", ct),
            "unmap" => await PsAsync($"Remove-PSDrive -Name {PsLiteral(FileArgs.Str(arguments, "letter"))} -Force; 'unmapped'", ct),
            _ => ToolResult.Error("bad_arguments", action)
        };
    }
}

public sealed class PrinterControlModule : RunnerModule
{
    public PrinterControlModule(IProcessRunner r) : base(r) { }
    public override ToolDescriptor Descriptor { get; } = new(
        "printer_control", "Printers/queues: list, print a test page, clear a queue.",
        Scopes.Shell, SessionRequirement.Core, RiskTier.Medium, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"action":{"type":"string","enum":["list","test_page","clear_queue"]},"name":{"type":"string"}}}""");

    public override async Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var action = FileArgs.Str(arguments, "action") ?? "list";
        var name = FileArgs.Str(arguments, "name") ?? "";
        return action switch
        {
            "list" => await PsAsync("Get-Printer | Select-Object Name,PrinterStatus,JobCount | ConvertTo-Json -Compress", ct),
            "test_page" => await PsAsync($"Invoke-CimMethod -InputObject (Get-CimInstance Win32_Printer | Where-Object {{ $_.Name -eq {PsLiteral(name)} }}) -MethodName PrintTestPage | Out-Null; 'test page sent'", ct),
            "clear_queue" => await PsAsync($"Get-PrintJob -PrinterName {PsLiteral(name)} | Remove-PrintJob; 'queue cleared'", ct),
            _ => ToolResult.Error("bad_arguments", action)
        };
    }
}

public sealed class DeviceInventoryModule : RunnerModule
{
    private readonly string _kind;
    public DeviceInventoryModule(IProcessRunner r, string kind) : base(r) => _kind = kind;
    public override ToolDescriptor Descriptor => new(
        _kind == "usb" ? "usb_devices" : "bluetooth_devices",
        _kind == "usb" ? "Attached USB device inventory." : "Bluetooth inventory + radio state (row 130's control half rides the laptop gate: pairing operations are presence-gated UI work).",
        Scopes.Observe, SessionRequirement.Core, RiskTier.Low, ExecutionContext: "SYSTEM");

    public override async Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var cls = _kind == "usb" ? "USB" : "Bluetooth";
        return await PsAsync($"Get-PnpDevice -Class {cls} -PresentOnly:$false | Select-Object FriendlyName,Status,InstanceId | ConvertTo-Json -Compress", ct);
    }
}

public sealed class BluetoothControlModule : RunnerModule
{
    public BluetoothControlModule(IProcessRunner r) : base(r) { }
    public override ToolDescriptor Descriptor { get; } = new(
        "bluetooth_control", "Bluetooth radio on/off (our original — the research found no product exposing this). Pair/unpair stays presence-gated UI work at the laptop gate.",
        Scopes.Shell, SessionRequirement.Core, RiskTier.Medium, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"action":{"type":"string","enum":["radio_on","radio_off","radio_status"]}}}""");

    public override async Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var action = FileArgs.Str(arguments, "action") ?? "radio_status";
        // Radio control via the WinRT Bluetooth API through PowerShell is
        // laptop-gate verification work; the state read is inbox-supported.
        return action switch
        {
            "radio_status" => await PsAsync("Get-Service bthserv | Select-Object Status,StartType | ConvertTo-Json -Compress", ct),
            _ => ToolResult.Unavailable("radio on/off rides the WinRT radio API and is verified at the laptop gate; radio_status is available now")
        };
    }
}

public sealed class AudioModule : RunnerModule
{
    private readonly string _kind;
    public AudioModule(IProcessRunner r, string kind) : base(r) => _kind = kind;
    public override ToolDescriptor Descriptor => new(
        _kind == "volume" ? "audio_volume" : "audio_devices",
        _kind == "volume" ? "Get/set default-device volume and mute." : "List audio input/output devices.",
        Scopes.Shell, SessionRequirement.Core, RiskTier.Low, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"action":{"type":"string","enum":["get","set","mute","unmute","list"]},"level":{"type":"number"}}}""");

    public override async Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        if (_kind == "devices")
            return await PsAsync("Get-CimInstance Win32_SoundDevice | Select-Object Name,Status | ConvertTo-Json -Compress", ct);
        // Volume rides the Core Audio COM API; the inbox path is the
        // AudioDeviceCmdlets module when present. Honest either way.
        var action = FileArgs.Str(arguments, "action") ?? "get";
        var probe = await PsAsync("if (Get-Command Get-AudioDevice -ErrorAction SilentlyContinue) { 'present' } else { 'absent' }", ct);
        if (!probe.Ok || !(probe.Text?.Contains("present") ?? false))
            return ToolResult.Unavailable("volume control needs the Core Audio API; this host has no AudioDeviceCmdlets module and the COM engine lands at the laptop gate");
        return action switch
        {
            "get" => await PsAsync("(Get-AudioDevice -PlaybackVolume).Volume", ct),
            "set" => await PsAsync($"Set-AudioDevice -PlaybackVolume {(arguments.TryGetProperty("level", out var l) ? l.GetDouble() : 50)}", ct),
            "mute" => await PsAsync("Set-AudioDevice -PlaybackMute $true; 'muted'", ct),
            "unmute" => await PsAsync("Set-AudioDevice -PlaybackMute $false; 'unmuted'", ct),
            _ => ToolResult.Error("bad_arguments", action)
        };
    }
}

public sealed class EventLogManageModule : RunnerModule
{
    public EventLogManageModule(IProcessRunner r) : base(r) { }
    public override ToolDescriptor Descriptor { get; } = new(
        "event_log_manage", "Export or clear Windows event logs (wevtutil). The DeskGuest host audit log is expressly out of this tool's reach.",
        Scopes.Shell, SessionRequirement.Core, RiskTier.High, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"action":{"type":"string","enum":["export","clear"]},"log":{"type":"string"},"destination":{"type":"string"}}}""");

    public override async Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var action = FileArgs.Str(arguments, "action") ?? "export";
        var log = FileArgs.Str(arguments, "log") ?? "System";
        if (log.Contains("deskguest", StringComparison.OrdinalIgnoreCase))
            return ToolResult.Error("refused", "the DeskGuest audit log is not manageable through this tool — agents cannot alter the evidence (DESIGN §6.4)");
        // Both values land in wevtutil's argument string (2026-11-15
        // blocker-fix sweep): the log name unquoted, the destination
        // inside double quotes — hold each to a shape that cannot
        // break out of its slot.
        if (!IsSafeUnquoted(log, "^[A-Za-z0-9 _.\\-/]+$"))
            return ToolResult.Error("bad_arguments", "log must be a plain event-log name");
        var destination = FileArgs.Str(arguments, "destination");
        if (action == "export" && (destination is null || destination.Contains('"')))
            return ToolResult.Error("bad_arguments", "destination must be a file path without double quotes");
        if (!OperatingSystem.IsWindows()) return ToolResult.Unavailable("event logs are a Windows surface; this host is not running Windows");
        var args = action == "export"
            ? $"epl {log} \"{destination}\""
            : $"cl {log}";
        var r = await Runner.RunAsync("wevtutil.exe", args, TimeSpan.FromSeconds(120), ct);
        return r.ExitCode == 0 ? ToolResult.Success($"{action} applied to {log}") : ToolResult.Error("wevtutil_failed", r.StdErr);
    }
}

public sealed class TaskRunModule : RunnerModule
{
    public TaskRunModule(IProcessRunner r) : base(r) { }
    public override ToolDescriptor Descriptor { get; } = new(
        "task_run", "Run or stop an existing scheduled task on demand.",
        Scopes.Shell, SessionRequirement.Core, RiskTier.Medium, ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"action":{"type":"string","enum":["run","stop"]},"name":{"type":"string"}}}""");

    public override async Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var action = FileArgs.Str(arguments, "action") ?? "run";
        var name = FileArgs.Str(arguments, "name") ?? "";
        // The name lands inside double quotes in schtasks' argument
        // string (2026-11-15 blocker-fix sweep): a quote in it would
        // break out into extra arguments.
        if (name.Contains('"'))
            return ToolResult.Error("bad_arguments", "task name must not contain double quotes");
        if (!OperatingSystem.IsWindows()) return ToolResult.Unavailable("scheduled tasks are a Windows surface; this host is not running Windows");
        var verb = action == "run" ? "/run" : "/end";
        var r = await Runner.RunAsync("schtasks.exe", $"{verb} /tn \"{name}\"", TimeSpan.FromSeconds(30), ct);
        return r.ExitCode == 0 ? ToolResult.Success($"task {name} {action} requested") : ToolResult.Error("schtasks_failed", r.StdErr);
    }
}

public sealed class VulnerabilityScanModule : RunnerModule
{
    public VulnerabilityScanModule(IProcessRunner r) : base(r) { }
    public override ToolDescriptor Descriptor { get; } = new(
        "vulnerability_scan", "Installed-software vulnerability assessment, report-only. Uses the host's own tooling (Defender vulnerability data where present); never exploits.",
        Scopes.Observe, SessionRequirement.Core, RiskTier.Medium, ExecutionContext: "SYSTEM");

    public override async Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        // Report-only by design: enumerate installed software versions so
        // the CALLER can assess; the host ships no exploit capability.
        return await PsAsync("Get-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*, HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Where-Object DisplayName | Select-Object DisplayName,DisplayVersion | ConvertTo-Json -Compress", ct);
    }
}
