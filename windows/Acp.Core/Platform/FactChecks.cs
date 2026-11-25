using Acp.Shared.State;
using Microsoft.Win32;

namespace Acp.Core.Platform;

/// <summary>
/// The Phase 0 fact-checks (DESIGN §11 D-BITLOCKER, §5.4 setup facts,
/// §3.6 edition gate), encoded as runtime checks the installer and the
/// self-check run. They READ and report; they never change a setting
/// (X8: posture changes happen through the owner's hands or his gates).
/// </summary>
public sealed record FactCheckReport(
    SubsystemHealth WindowsEdition,   // child-seat needs Pro/Enterprise/Education
    SubsystemHealth BitLocker,        // C: protection state + protector types; NO key material (X14)
    SubsystemHealth HelloOnlyMode);   // DevicePasswordLessBuildVersion: 2 = password sign-in suppressed

public interface IFactChecks
{
    Task<FactCheckReport> RunAsync(CancellationToken ct);
}

public sealed class WindowsFactChecks : IFactChecks
{
    private readonly IProcessRunner _runner;
    public WindowsFactChecks(IProcessRunner runner) => _runner = runner;

    public async Task<FactCheckReport> RunAsync(CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows())
        {
            var na = new SubsystemHealth("fact_checks", HealthLevel.Amber, "not running on Windows; fact checks report at install time on the laptop");
            return new FactCheckReport(na, na, na);
        }
        return new FactCheckReport(CheckEdition(), await CheckBitLockerAsync(ct), CheckHelloOnly());
    }

    private static SubsystemHealth CheckEdition()
    {
        // UNPROVEN-ON-WINDOWS: registry read path compiled here, first run is the laptop gate.
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            var product = key?.GetValue("ProductName")?.ToString() ?? "unknown";
            var capable = product.Contains("Pro") || product.Contains("Enterprise") || product.Contains("Education");
            return new SubsystemHealth("windows_edition",
                capable ? HealthLevel.Green : HealthLevel.Amber,
                capable ? $"{product}: child-session seat (Phase 2) is edition-capable"
                        : $"{product}: child-session seat reports unavailable on Home editions (DESIGN §3.6)");
        }
        catch (Exception ex)
        {
            return new SubsystemHealth("windows_edition", HealthLevel.Red, $"edition check failed: {ex.GetType().Name}");
        }
    }

    private async Task<SubsystemHealth> CheckBitLockerAsync(CancellationToken ct)
    {
        // Status + protector types only. Recovery-key material is NEVER read (X14).
        try
        {
            var result = await _runner.RunAsync("powershell.exe",
                "-NoProfile -NonInteractive -Command \"(Get-BitLockerVolume -MountPoint 'C:') | ForEach-Object { $_.ProtectionStatus.ToString() + '|' + (($_.KeyProtector | ForEach-Object { $_.KeyProtectorType.ToString() }) -join ',') }\"",
                TimeSpan.FromSeconds(30), ct);
            if (result.ExitCode != 0)
                return new SubsystemHealth("bitlocker", HealthLevel.Amber, "BitLocker status could not be read (module may be absent); posture unverified");
            var parts = result.StdOut.Trim().Split('|');
            var protection = parts.ElementAtOrDefault(0) ?? "Unknown";
            var protectors = parts.ElementAtOrDefault(1) ?? "";
            if (protection == "On")
            {
                var hasPin = protectors.Contains("Pin", StringComparison.OrdinalIgnoreCase);
                return new SubsystemHealth("bitlocker", HealthLevel.Green,
                    hasPin ? "C: encrypted, protectors include a PIN — a PRE-BOOT PIN strands unattended reboots (DESIGN §5.5); TPM-only recommended"
                           : $"C: encrypted (TPM-class protectors: {protectors}); the vault's recommended companion posture (DESIGN §5.5)");
            }
            return new SubsystemHealth("bitlocker", HealthLevel.Amber,
                "C: BitLocker protection is OFF — the unlock vault (Phase 2) would sit on an unencrypted disk; enabling TPM-only BitLocker is recommended (D-BITLOCKER)");
        }
        catch (Exception ex)
        {
            return new SubsystemHealth("bitlocker", HealthLevel.Amber, $"BitLocker check failed: {ex.GetType().Name}; posture unverified");
        }
    }

    private static SubsystemHealth CheckHelloOnly()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\PasswordLess\Device");
            var value = key?.GetValue("DevicePasswordLessBuildVersion");
            return value switch
            {
                2 => new SubsystemHealth("hello_only_mode", HealthLevel.Amber,
                    "Hello-only sign-in mode is ON (DevicePasswordLessBuildVersion=2): password sign-in is suppressed; the unlock module's setup includes the owner's one toggle to re-offer it (DESIGN §5.4)"),
                0 => new SubsystemHealth("hello_only_mode", HealthLevel.Green,
                    "password sign-in is offered alongside Hello (DevicePasswordLessBuildVersion=0)"),
                _ => new SubsystemHealth("hello_only_mode", HealthLevel.Amber,
                    $"DevicePasswordLessBuildVersion reads '{value ?? "absent"}'; unlock setup will verify at install")
            };
        }
        catch (Exception ex)
        {
            return new SubsystemHealth("hello_only_mode", HealthLevel.Red, $"Hello-only check failed: {ex.GetType().Name}");
        }
    }
}
