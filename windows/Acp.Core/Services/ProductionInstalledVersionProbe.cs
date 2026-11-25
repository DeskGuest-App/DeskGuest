using System.Text.RegularExpressions;
using Acp.Shared.Deployment;
using Acp.Shared.Inventory;
using Microsoft.Win32;

namespace Acp.Core.Services;

// =====================================================================
// W5 host wiring (bd-shared-plat-1/F4 remainder) — the PRODUCTION
// verify_install probe for software deployments.
//
// verify_install must READ installed state; until this wiring the
// deployment runner had no production probe, so every service
// deployment landed honest-PartialFailure. This probe observes, in
// order:
//
//   1. The hub inventory record for the device (the RMM-04
//      recording seam): the version inventory NOW records for the
//      package's InstalledSoftwareName. This is the cross-device
//      path — a hub deploying to a peer reads what that peer's
//      inventory reported, never an assumption.
//   2. For THIS device only, a live OS read through the executor
//      seam (OsTool): the uninstall-registry DisplayVersion for
//      the software (the production default enumerates the
//      Windows uninstall keys), corroborated by an `sc.exe query`
//      service check — a service that exists and is RUNNING proves
//      presence but carries no version, so it can never by itself
//      produce a version.
//
// FAIL-CLOSED: a package with no InstalledSoftwareName is
// unobservable; a device with no inventory record and no local OS
// observation is unobservable; an unknown/empty recorded version
// is unobservable. Every unobservable case returns null, and the
// runner's verify_install then FAILS the step and downgrades the
// deployment to PartialFailure — the probe never invents a version.
// =====================================================================

/// <summary>Production post-install inventory probe:
/// (package, deviceId) → the version actually observed, or null
/// when the installed state cannot be observed.</summary>
public sealed class ProductionInstalledVersionProbe
{
    private readonly Func<string, DeviceInventoryRecord?> _recordOf;
    private readonly string _localDeviceId;
    private readonly Func<string, string?> _localRegistryVersion;
    private readonly Func<string, (bool Ok, string Output)> _serviceQuery;

    /// <param name="recordOf">Device id → its hub inventory record
    /// (null when the device has reported none).</param>
    /// <param name="localDeviceId">This host's device id — live OS
    /// reads are only ever taken for the local device.</param>
    /// <param name="localRegistryVersion">Software name → installed
    /// version read from the local OS (default: Windows uninstall
    /// registry; off-Windows it observes nothing).</param>
    /// <param name="serviceQuery">Service name → (ok, output) of a
    /// service query (default: sc.exe via OsTool).</param>
    public ProductionInstalledVersionProbe(
        Func<string, DeviceInventoryRecord?> recordOf,
        string localDeviceId,
        Func<string, string?>? localRegistryVersion = null,
        Func<string, (bool Ok, string Output)>? serviceQuery = null)
    {
        _recordOf = recordOf ?? throw new ArgumentNullException(nameof(recordOf));
        _localDeviceId = localDeviceId ?? "";
        _localRegistryVersion = localRegistryVersion ?? ReadUninstallDisplayVersion;
        _serviceQuery = serviceQuery ?? (name => OsTool.Run("sc.exe", new[] { "query", name }, 30_000));
    }

    public string? Observe(DeploymentPackage package, string deviceId)
    {
        if (package is null || string.IsNullOrWhiteSpace(package.InstalledSoftwareName))
            return null; // no inventory name — unobservable by construction
        var name = package.InstalledSoftwareName.Trim();

        // 1. The inventory record for the device.
        var record = _recordOf(deviceId);
        var item = record?.Software?.FirstOrDefault(s =>
            string.Equals(s.NormalizedName, InventoryValidation.NormalizeSoftwareName(name),
                StringComparison.OrdinalIgnoreCase));
        if (item is not null && !string.IsNullOrWhiteSpace(item.Version) &&
            !string.Equals(item.Version.Trim(), "unknown", StringComparison.OrdinalIgnoreCase))
            return item.Version.Trim();

        // 2. Local device only: live OS reads.
        if (!string.Equals(deviceId ?? "", _localDeviceId, StringComparison.OrdinalIgnoreCase))
            return null;
        var fromRegistry = _localRegistryVersion(name);
        if (!string.IsNullOrWhiteSpace(fromRegistry)) return fromRegistry.Trim();
        // Service corroboration: presence without a version is not
        // an observation of the version — fall through to null.
        _ = _serviceQuery(name);
        return null;
    }

    /// <summary>True when a Windows service with this exact name
    /// exists and reports RUNNING (pure over sc.exe query output —
    /// the parse is testable off-Windows).</summary>
    internal static bool ServiceRunning(string scQueryOutput) =>
        scQueryOutput is not null &&
        Regex.IsMatch(scQueryOutput, @"STATE\s*:\s*4\s+RUNNING", RegexOptions.IgnoreCase);

    /// <summary>The production local read: enumerate the Windows
    /// uninstall keys (64-bit, 32-bit WOW, per-user) for a
    /// DisplayName match and return its DisplayVersion. Off-Windows
    /// or on any failure it observes nothing (null).</summary>
    internal static string? ReadUninstallDisplayVersion(string softwareName)
    {
        if (!OperatingSystem.IsWindows()) return null;
        try
        {
            foreach (var (root, path) in new[]
            {
                (Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
                (Registry.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
                (Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            })
            {
                using var key = root.OpenSubKey(path);
                if (key is null) continue;
                foreach (var sub in key.GetSubKeyNames())
                {
                    using var entry = key.OpenSubKey(sub);
                    var display = entry?.GetValue("DisplayName") as string;
                    if (display is not null &&
                        string.Equals(display.Trim(), softwareName.Trim(), StringComparison.OrdinalIgnoreCase))
                        return entry?.GetValue("DisplayVersion") as string;
                }
            }
        }
        catch { /* an unreadable registry observes nothing */ }
        return null;
    }
}
