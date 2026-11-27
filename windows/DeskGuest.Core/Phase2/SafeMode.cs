using System.Text.Json;
using DeskGuest.Core.Platform;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.Tools;

namespace DeskGuest.Core.Phase2;

public enum SafeModePhase { Normal, Requested, RebootingToSafeMode, InSafeMode, Returning, Failed }

/// <summary>
/// Safe Mode reboot orchestration (census row 133): the ride is a
/// state machine persisted to disk, because the process does not
/// survive the reboot it schedules. bcdedit safeboot network is set
/// before the reboot and REMOVED as the first act on the next boot —
/// a machine that comes back still flagged safeboot is the failure
/// this design exists to prevent. State is reported through the
/// whole ride via the heartbeat marker.
/// BD-WIN-CORE-2/F5 fixes: Safe Mode is now detected from the OS
/// (GetSystemMetrics(SM_CLEANBOOT)), not from the DESKGUEST_SAFE_MODE
/// environment variable that NOTHING set (and that env_set could
/// forge — see F8); safeboot is cleared on the next boot whenever a
/// ride is outstanding, whether the machine actually booted into
/// Safe Mode, booted normally, or the reboot was aborted — the old
/// code only cleared when it believed it was in Safe Mode, so one
/// unset variable looped the machine into Safe Mode forever; and
/// BeginRide registers the Core service under SafeBoot\Network, so
/// the Core actually starts in Safe Mode to do the clearing.
/// </summary>
public sealed class SafeModeOrchestrator
{
    private readonly IProcessRunner _runner;
    private readonly string _statePath;
    private readonly Func<bool> _isWindows;
    private readonly Func<bool> _isSafeModeNow;
    private readonly string _serviceName;

    public SafeModeOrchestrator(IProcessRunner runner, string dataDir, Func<bool>? isWindows = null, Func<bool>? isSafeModeNow = null, string serviceName = "DeskGuestCore")
    {
        _runner = runner;
        _statePath = Path.Combine(dataDir, "safe-mode-ride.json");
        _isWindows = isWindows ?? (() => OperatingSystem.IsWindows());
        _isSafeModeNow = isSafeModeNow ?? DefaultIsSafeModeNow;
        _serviceName = serviceName;
    }

    /// <summary>OS truth, not an environment variable: SM_CLEANBOOT
    /// (67) is 1 for Safe Mode, 2 for Safe Mode with Networking, 0
    /// for a normal boot. The DESKGUEST_SAFE_MODE variable is still honoured
    /// as a test seam on non-Windows hosts only.</summary>
    private static bool DefaultIsSafeModeNow()
    {
        if (OperatingSystem.IsWindows())
        {
            try { return GetSystemMetrics(67) != 0; } catch { /* fall through to the seam */ }
        }
        return Environment.GetEnvironmentVariable("DESKGUEST_SAFE_MODE") == "1";
    }

    [System.Runtime.InteropServices.DllImport("user32.dll")]
    private static extern int GetSystemMetrics(int nIndex);

    private sealed record RideState(SafeModePhase Phase, DateTimeOffset ChangedUtc, string? Note);
    public SafeModePhase Phase => Read().Phase;

    private RideState Read()
    {
        if (!File.Exists(_statePath)) return new RideState(SafeModePhase.Normal, DateTimeOffset.UtcNow, null);
        try { return JsonSerializer.Deserialize<RideState>(File.ReadAllText(_statePath)) ?? new RideState(SafeModePhase.Normal, DateTimeOffset.UtcNow, null); }
        catch (JsonException) { return new RideState(SafeModePhase.Failed, DateTimeOffset.UtcNow, "ride state file unreadable"); }
    }

    private void Write(SafeModePhase phase, string? note) =>
        File.WriteAllText(_statePath, JsonSerializer.Serialize(new RideState(phase, DateTimeOffset.UtcNow, note)));

    /// <summary>Begin the ride: set safeboot, announce, reboot.</summary>
    public async Task<ToolResult> BeginRideAsync(string requestedBy, CancellationToken ct)
    {
        if (!_isWindows()) return ToolResult.Unavailable("Safe Mode orchestration executes only on the Windows host");
        if (Phase != SafeModePhase.Normal) return ToolResult.Error("ride_in_progress", $"a Safe Mode ride is already in phase {Phase}");
        Write(SafeModePhase.Requested, $"requested by {requestedBy}");
        var set = await _runner.RunAsync("bcdedit.exe", "/set {current} safeboot network", TimeSpan.FromSeconds(30), ct);
        if (set.ExitCode != 0)
        {
            Write(SafeModePhase.Failed, "bcdedit set failed");
            return ToolResult.Error("bcdedit_failed", set.StdErr);
        }
        // The Core must be able to START in Safe Mode, or nothing
        // clears the flag: register the service under SafeBoot\Network
        // (value "Service"). Failure aborts the ride BEFORE the reboot
        // and rolls safeboot back — never strand the machine.
        var reg = await _runner.RunAsync("reg.exe",
            $"add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\{_serviceName}\" /ve /d Service /f",
            TimeSpan.FromSeconds(30), ct);
        if (reg.ExitCode != 0)
        {
            await _runner.RunAsync("bcdedit.exe", "/deletevalue {current} safeboot", TimeSpan.FromSeconds(30), ct);
            Write(SafeModePhase.Failed, "SafeBoot\\Network registration failed; ride aborted and safeboot rolled back");
            return ToolResult.Error("safeboot_registration_failed", reg.StdErr);
        }
        Write(SafeModePhase.RebootingToSafeMode, "safeboot set; rebooting");
        var reboot = await _runner.RunAsync("shutdown.exe", "/r /t 5 /c \"DeskGuest: Safe Mode ride\"", TimeSpan.FromSeconds(15), ct);
        if (reboot.ExitCode != 0)
        {
            // No reboot is coming: roll safeboot back NOW instead of
            // leaving the ride (and the flag) stranded (F5).
            await _runner.RunAsync("bcdedit.exe", "/deletevalue {current} safeboot", TimeSpan.FromSeconds(30), ct);
            Write(SafeModePhase.Failed, "reboot command failed; safeboot rolled back");
            return ToolResult.Error("reboot_failed", reboot.StdErr);
        }
        return ToolResult.Success("Safe Mode ride begun: safeboot set, rebooting. The endpoint reports its state through the ride and clears safeboot on return.");
    }

    /// <summary>Called by the Core at every start. If a ride is
    /// outstanding (Requested / RebootingToSafeMode), clear safeboot
    /// FIRST — regardless of which mode this boot is in. The previous
    /// condition also had an operator-precedence trap ('A or B && C'
    /// bound as A or (B && C)) and depended on the env-var detection:
    /// a normal boot after an aborted ride never cleared the flag,
    /// and the NEXT boot went back into Safe Mode, forever.</summary>
    public async Task OnBootAsync(CancellationToken ct)
    {
        var ride = Read();
        if (ride.Phase is SafeModePhase.RebootingToSafeMode or SafeModePhase.Requested)
        {
            var inSafeMode = _isSafeModeNow();
            var clear = await _runner.RunAsync("bcdedit.exe", "/deletevalue {current} safeboot", TimeSpan.FromSeconds(30), ct);
            Write(clear.ExitCode == 0 ? SafeModePhase.Returning : SafeModePhase.Failed,
                clear.ExitCode == 0
                    ? (inSafeMode
                        ? "in Safe Mode; safeboot cleared — the next boot is normal"
                        : "booted NORMALLY with a ride outstanding (reboot aborted or safeboot ignored); safeboot cleared — the ride cannot loop this machine into Safe Mode")
                    : "CRITICAL: safeboot clear failed; a human must run bcdedit /deletevalue {current} safeboot");
        }
        else if (ride.Phase == SafeModePhase.Returning)
        {
            Write(SafeModePhase.Normal, "ride complete: returned to a normal boot");
        }
    }

    public ToolResult Status() => ToolResult.Success(JsonSerializer.Serialize(Read(), new JsonSerializerOptions { WriteIndented = true }));
}

public sealed class SafeModeRebootModule : IToolModule
{
    private readonly SafeModeOrchestrator _orchestrator;
    public SafeModeRebootModule(SafeModeOrchestrator orchestrator) => _orchestrator = orchestrator;
    public ToolDescriptor Descriptor { get; } = new(
        "power_reboot_safe_mode", "Reboot into Safe Mode (networking), with state reported through the whole ride and a defined return path. Gated: power.",
        Scopes.Admin, SessionRequirement.Core, RiskTier.Critical, GateClass: "power", ExecutionContext: "SYSTEM",
        InputSchemaJson: """{"type":"object","properties":{"action":{"type":"string","enum":["begin","status"]}}}""");

    public async Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct)
    {
        var action = arguments.TryGetProperty("action", out var a) ? a.GetString() : "status";
        return action == "begin" ? await _orchestrator.BeginRideAsync(ctx.Pairing.AgentName, ct) : _orchestrator.Status();
    }
}
