using System.Diagnostics;
using System.Security.Cryptography;
using System.ServiceProcess;
using System.Text;
using System.Xml;
using Acp.Shared.ApplicationControl;
using Acp.Shared.Encryption;
using Acp.Shared.Inventory;
using Acp.Shared.PeripheralControl;
using Acp.Shared.Provisioning;
using Acp.Shared.Remediation;
using Microsoft.Win32;

namespace Acp.Core.Services;

// =====================================================================
// Lane A (items 2b/2c/2e/2f) — PRODUCTION OS bindings for Block R's
// honest Unavailable/Fake seams. Every binding here is fail-closed:
//   * off-Windows (this build VM) each writer/driver refuses BY
//     NAME — the same honesty shape as the Unavailable bindings,
//     but on a Windows host the real OS machinery runs;
//   * OS tools are invoked as processes with ARGUMENT LISTS (never
//     a shell, never string-interpolated commands), bounded by a
//     timeout, with output captured for the audit detail;
//   * a tool that exits non-zero, is missing, or produces
//     unparseable output yields a refusal/UNKNOWN — never a
//     fabricated success.
// =====================================================================

internal static class OsTool
{
    public static (bool Ok, string Output) Run(string exe, IReadOnlyList<string> args, int timeoutMs = 120_000)
    {
        try
        {
            var psi = new ProcessStartInfo(exe)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            foreach (var a in args) psi.ArgumentList.Add(a);
            using var proc = Process.Start(psi);
            if (proc is null) return (false, $"failed to start {exe}");
            var stdout = proc.StandardOutput.ReadToEndAsync();
            var stderr = proc.StandardError.ReadToEndAsync();
            if (!proc.WaitForExit(timeoutMs))
            {
                try { proc.Kill(entireProcessTree: true); } catch { }
                return (false, $"{exe} timed out after {timeoutMs} ms — killed");
            }
            var output = (stdout.GetAwaiter().GetResult() + stderr.GetAwaiter().GetResult()).Trim();
            return (proc.ExitCode == 0, output.Length == 0 ? $"(exit {proc.ExitCode})" : output);
        }
        catch (Exception ex)
        {
            return (false, $"{exe} could not run: {ex.Message}");
        }
    }
}

// ---- 2b: registry/CIM-class collectors (RMM-01/RMM-04) ------------------

public sealed record ServicePostureFact(string Name, string DisplayName, string Status, string StartType);

/// <summary>Production inventory collectors over the Windows
/// registry + service control manager. Hardware identity comes
/// from the BIOS/CPU registry keys the OS itself maintains (the
/// same facts CIM Win32_BIOS/Win32_Processor expose); software is
/// the uninstall-key enumeration (64-bit, 32-bit WOW and per-user);
/// services are the live SCM list. Off-Windows every collector
/// returns the honest empty/blank shape — never invented data.</summary>
public static class WindowsProductionCollectors
{
    public static HardwareSnapshot CollectHardware()
    {
        var fallback = InventoryService.DefaultHardwareCollector();
        if (!OperatingSystem.IsWindows()) return fallback;
        string manufacturer = "", model = "", serial = "", bios = "", cpu = "";
        try
        {
            using var biosKey = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\BIOS");
            manufacturer = biosKey?.GetValue("SystemManufacturer") as string ?? "";
            model = biosKey?.GetValue("SystemProductName") as string ?? "";
            bios = biosKey?.GetValue("BIOSVersion") as string ?? "";
            using var cpuKey = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\CentralProcessor\0");
            cpu = cpuKey?.GetValue("ProcessorNameString") as string ?? "";
            using var winKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            var product = winKey?.GetValue("ProductName") as string ?? fallback.OsName;
            var build = winKey?.GetValue("CurrentBuildNumber") as string ?? fallback.OsBuild;
            var display = winKey?.GetValue("DisplayVersion") as string;
            // Serial: the BIOS key carries it on most OEM firmware;
            // absent means null (unknown), never a guess.
            using var sysKey = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System");
            serial = sysKey?.GetValue("SystemSerialNumber") as string ?? "";
            return fallback with
            {
                Manufacturer = manufacturer,
                Model = model.Length > 0 ? model : fallback.Model,
                SerialNumber = string.IsNullOrWhiteSpace(serial) ? null : serial.Trim(),
                CpuModel = cpu.Trim(),
                BiosVersion = string.IsNullOrWhiteSpace(bios) ? null : bios,
                OsName = product,
                OsBuild = build,
                OsVersion = string.IsNullOrWhiteSpace(display) ? build : $"{build} ({display})",
                CollectedUtc = DateTimeOffset.UtcNow,
            };
        }
        catch
        {
            return fallback; // registry read failure = runtime-truth facts only
        }
    }

    public static IReadOnlyList<SoftwareItem> CollectSoftware()
    {
        var items = new List<SoftwareItem>();
        if (!OperatingSystem.IsWindows()) return items;
        var roots = new[]
        {
            (RegistryHive.LocalMachine, RegistryView.Registry64),
            (RegistryHive.LocalMachine, RegistryView.Registry32),
            (RegistryHive.CurrentUser, RegistryView.Default),
        };
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (hive, view) in roots)
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                using var uninstall = baseKey.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall");
                if (uninstall is null) continue;
                foreach (var subName in uninstall.GetSubKeyNames())
                {
                    using var sub = uninstall.OpenSubKey(subName);
                    var name = sub?.GetValue("DisplayName") as string;
                    if (string.IsNullOrWhiteSpace(name)) continue;
                    var version = sub?.GetValue("DisplayVersion") as string ?? "";
                    var publisher = sub?.GetValue("Publisher") as string;
                    if (!seen.Add(name + "|" + version)) continue;
                    items.Add(new SoftwareItem(name.Trim(), version.Trim(), publisher,
                        null, "registry-uninstall"));
                }
            }
            catch { /* one unreadable hive must not lose the others */ }
        }
        return items;
    }

    public static IReadOnlyList<ServicePostureFact> CollectServices()
    {
        var facts = new List<ServicePostureFact>();
        if (!OperatingSystem.IsWindows()) return facts;
        try
        {
            foreach (var svc in ServiceController.GetServices())
            {
                string startType;
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{svc.ServiceName}");
                    startType = (key?.GetValue("Start") as int?) switch
                    {
                        0 => "boot", 1 => "system", 2 => "automatic",
                        3 => "manual", 4 => "disabled", _ => "unknown",
                    };
                }
                catch { startType = "unknown"; }
                facts.Add(new ServicePostureFact(svc.ServiceName, svc.DisplayName,
                    svc.Status.ToString(), startType));
            }
        }
        catch { /* SCM unavailable = empty posture, named by callers as unknown */ }
        return facts;
    }

    /// <summary>The production InventoryService: registry collectors
    /// in place of the empty defaults.</summary>
    public static InventoryService CreateInventoryService(string deviceId, string scopeId) =>
        new(deviceId, scopeId, CollectHardware, CollectSoftware);
}

// ---- 2c: AppLocker writer (RMM-25) ---------------------------------------

/// <summary>Production AppLocker writer: renders the enforcement
/// plan as an AppLocker policy document (EXE collection; hash →
/// FileHashRule, publisher → FilePublisherRule, path → FilePathRule),
/// then applies it with Set-AppLockerPolicy -Merge through a FIXED
/// PowerShell script file invoked with -File (BD-WIN-CORE-3/F2):
/// the old shape passed the XML path as a trailing argument to
/// -Command, where PowerShell joins trailing arguments INTO the
/// script text — $args[0] was empty and the device-id-bearing path
/// was parsed as CODE (injection via a crafted device id). Now:
/// the script is a constant with a param() block, the XML path
/// travels as a bound parameter, the file name is a SHA-256 hash
/// of the device id (never the raw id), -Merge preserves the
/// machine's existing policy instead of replacing it wholesale,
/// ENFORCE renders the AppLocker default allow rules for Windows
/// + Program Files alongside the plan (an Enabled policy with no
/// default allows can lock users out), and the default policy dir
/// is the machine-wide ACP data dir under CommonApplicationData,
/// NOT %TEMP%. Audit mode renders EnforcementMode=AuditOnly;
/// enforce renders Enabled. Any failure — non-Windows host,
/// PowerShell/AppLocker missing, non-zero exit — reports
/// Applied=false with the reason.</summary>
public sealed class AppLockerPolicyWriter : IAppControlApplier
{
    private readonly string _policyDir;

    public AppLockerPolicyWriter(string? policyDir = null) =>
        _policyDir = policyDir ?? DefaultPolicyDir();

    internal static string DefaultPolicyDir()
    {
        var common = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        return string.IsNullOrWhiteSpace(common)
            ? Path.Combine(Path.GetTempPath(), "acp-applocker")
            : Path.Combine(common, "ACP", "applocker");
    }

    /// <summary>The on-disk policy file name for a device: a hash,
    /// never the raw device id (a crafted id must never become a
    /// path — or, historically, script text).</summary>
    internal static string PolicyFileName(string deviceId) =>
        "applocker-" + Convert.ToHexString(SHA256.HashData(
            Encoding.UTF8.GetBytes(deviceId ?? ""))).ToLowerInvariant() + ".xml";

    /// <summary>The FIXED apply script: a param block and one
    /// cmdlet. It contains no plan content, ever.</summary>
    internal const string ApplyScript =
        "param([Parameter(Mandatory=$true)][string]$XmlPath)\n" +
        "Set-AppLockerPolicy -XmlPolicy $XmlPath -Merge\n";

    /// <summary>The exact powershell.exe argument list for an
    /// apply (BD-WIN-CORE-3/F2 regression surface): -File with the
    /// fixed script, the XML path as its bound parameter. No
    /// -Command, no $args, no interpolation.</summary>
    internal static IReadOnlyList<string> ApplyArguments(string scriptPath, string xmlPath) =>
        new[] { "-NoProfile", "-NonInteractive", "-File", scriptPath, xmlPath };

    public AppApplyResult Apply(AppEnforcementPlan plan)
    {
        if (!OperatingSystem.IsWindows())
            return new AppApplyResult(false,
                $"AppLocker writer runs on Windows only — plan for device '{plan.DeviceId}' ({plan.Rules.Count} rules, mode {plan.EffectiveModeLabel}) was computed but NOT applied on this host");
        var xml = BuildPolicyXml(plan);
        try
        {
            Directory.CreateDirectory(_policyDir);
            var file = Path.Combine(_policyDir, PolicyFileName(plan.DeviceId));
            File.WriteAllText(file, xml);
            var script = Path.Combine(_policyDir, "apply-applocker.ps1");
            File.WriteAllText(script, ApplyScript);
            var (ok, output) = OsTool.Run("powershell.exe", ApplyArguments(script, file), 60_000);
            return ok
                ? new AppApplyResult(true, $"AppLocker policy applied (merged) for device '{plan.DeviceId}': {plan.Rules.Count} rules, mode {plan.EffectiveModeLabel} (Set-AppLockerPolicy -Merge exit 0)")
                : new AppApplyResult(false, $"Set-AppLockerPolicy failed for device '{plan.DeviceId}': {output}");
        }
        catch (Exception ex)
        {
            return new AppApplyResult(false, $"AppLocker policy write failed for device '{plan.DeviceId}': {ex.Message}");
        }
    }

    internal static string BuildPolicyXml(AppEnforcementPlan plan)
    {
        var settings = new XmlWriterSettings { Indent = true, Encoding = Encoding.UTF8 };
        using var sw = new StringWriter();
        using var w = XmlWriter.Create(sw, settings);
        w.WriteStartDocument();
        w.WriteStartElement("AppLockerPolicy");
        w.WriteAttributeString("Version", "1");
        w.WriteStartElement("RuleCollection");
        w.WriteAttributeString("Type", "Exe");
        w.WriteAttributeString("EnforcementMode",
            plan.EffectiveMode == AppControlModes.Enforce ? "Enabled" : "AuditOnly");
        // BD-WIN-CORE-3/F2: ENFORCE carries the AppLocker DEFAULT
        // allow rules (Everyone may run Windows + Program Files) —
        // an Enabled collection without them can lock users out of
        // the machine. (The apply also uses -Merge, so a machine's
        // own existing rules survive alongside these.)
        if (plan.EffectiveMode == AppControlModes.Enforce)
        {
            foreach (var (name, path) in new[]
            {
                ("ACP default allow: Windows directory", "%WINDIR%\\*"),
                ("ACP default allow: Program Files directory", "%PROGRAMFILES%\\*"),
            })
            {
                w.WriteStartElement("FilePathRule");
                w.WriteAttributeString("Id", Guid.NewGuid().ToString());
                w.WriteAttributeString("Name", name);
                w.WriteAttributeString("Description", "AppLocker default rule rendered by ACP (BD-WIN-CORE-3/F2) so enforcement cannot lock users out of Windows itself");
                w.WriteAttributeString("UserOrGroupSid", "S-1-1-0");
                w.WriteAttributeString("Action", "Allow");
                w.WriteStartElement("Conditions");
                w.WriteStartElement("FilePathCondition");
                w.WriteAttributeString("Path", path);
                w.WriteEndElement();
                w.WriteEndElement();
                w.WriteEndElement();
            }
        }
        foreach (var rule in plan.Rules)
        {
            var action = rule.Effect == RuleEffects.Deny ? "Deny" : "Allow";
            var (element, conditionElement) = rule.Kind switch
            {
                "hash" => ("FileHashRule", "FileHashCondition"),
                "publisher" => ("FilePublisherRule", "FilePublisherCondition"),
                _ => ("FilePathRule", "FilePathCondition"),
            };
            w.WriteStartElement(element);
            w.WriteAttributeString("Id", Guid.NewGuid().ToString());
            w.WriteAttributeString("Name", $"ACP {rule.Id}");
            w.WriteAttributeString("Description", $"ACP RMM-25 rule {rule.Id} (scope {rule.ScopeKind}:{rule.ScopeId})");
            w.WriteAttributeString("UserOrGroupSid", "S-1-1-0");
            w.WriteAttributeString("Action", action);
            w.WriteStartElement("Conditions");
            w.WriteStartElement(conditionElement);
            if (element == "FileHashRule")
            {
                w.WriteStartElement("FileHash");
                w.WriteAttributeString("Type", "SHA256");
                w.WriteAttributeString("SourceFileName", rule.Product ?? "");
                w.WriteAttributeString("SourceFileLength", "0");
                w.WriteAttributeString("Data", rule.Hash ?? "");
                w.WriteEndElement();
            }
            else if (element == "FilePublisherRule")
            {
                // BD-WIN-CORE-3/F2: PublisherName is the PUBLISHER,
                // ProductName is the product — the old code wrote
                // the product into BOTH, so the rule bound a
                // publisher named after a product (matching nothing
                // real, or the wrong signer). The ACP rule model
                // binds publisher rules by signer certificate
                // thumbprint, which AppLocker publisher conditions
                // cannot express; the honest rendering is any
                // publisher ("*") narrowed by the product name —
                // never the product masquerading as the publisher.
                w.WriteAttributeString("PublisherName", "*");
                w.WriteAttributeString("ProductName", rule.Product ?? "*");
                w.WriteAttributeString("BinaryName", "*");
                w.WriteStartElement("BinaryVersionRange");
                w.WriteAttributeString("LowSection", "*");
                w.WriteAttributeString("HighSection", "*");
                w.WriteEndElement();
            }
            else
            {
                w.WriteAttributeString("Path", rule.Path ?? "*");
            }
            w.WriteEndElement(); // condition
            w.WriteEndElement(); // Conditions
            w.WriteEndElement(); // rule
        }
        w.WriteEndElement(); // RuleCollection
        w.WriteEndElement(); // AppLockerPolicy
        w.WriteEndDocument();
        w.Flush();
        return sw.ToString();
    }
}

// ---- 2c: device-control writer (RMM-30) ----------------------------------

/// <summary>Production device-control writer: applies the plan to
/// the Windows device-installation-restriction + removable-storage
/// Group Policy registry keys (the same keys the GPO editor writes).
/// Enforce mode writes deny/allow lists by device class; audit mode
/// writes NOTHING and reports so (audit means observe — a writer
/// that changes the machine while claiming to audit would be lying).
/// Non-Windows or a registry failure reports Applied=false.</summary>
public sealed class DeviceControlPolicyWriter : IPeripheralControlApplier
{
    /// <summary>BD-WIN-CORE-3/F3: model class NAME → Windows device
    /// SETUP CLASS GUID. The DenyDeviceClasses/AllowDeviceClasses
    /// policy lists carry GUIDs in braces; the old writer copied
    /// the model's class names ("hid", "storage", …) straight in,
    /// which Windows matches against nothing. A class with no GUID
    /// mapping refuses the whole apply by name — never a silent
    /// no-op reported as enforcement.</summary>
    internal static readonly IReadOnlyDictionary<string, string> SetupClassGuids =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            [DeviceClasses.Storage] = "{4d36e967-e325-11ce-bfc1-08002be10318}",   // DiskDrive
            [DeviceClasses.Hid] = "{745a17a0-74d3-11d0-b6fe-00a0c90f57da}",       // HIDClass
            [DeviceClasses.Network] = "{4d36e972-e325-11ce-bfc1-08002be10318}",   // Net
            [DeviceClasses.Bluetooth] = "{e0cbf06c-cd8b-4647-bb8a-263b43f0f974}", // Bluetooth
            [DeviceClasses.Camera] = "{6bdd1fc6-810f-11d0-bec7-08002be2092f}",    // Image
            [DeviceClasses.Printer] = "{4d36e979-e325-11ce-bfc1-08002be10318}",   // Printer
            [DeviceClasses.Serial] = "{4d36e978-e325-11ce-bfc1-08002be10318}",    // Ports
        };

    /// <summary>The full registry write-set for a plan (pure;
    /// testable off-Windows): denied/allowed setup-class GUIDs.
    /// Null + reason when any class rule cannot be mapped.</summary>
    internal static (IReadOnlyList<string> Denied, IReadOnlyList<string> Allowed, string? Refusal)
        BuildClassLists(PeripheralEnforcementPlan plan)
    {
        var denied = new List<string>(); var allowed = new List<string>();
        foreach (var rule in plan.Rules.Where(r => r.Class is not null))
        {
            if (!SetupClassGuids.TryGetValue(rule.Class!.Trim(), out var guid))
                return (denied, allowed,
                    $"device class '{rule.Class}' has no Windows setup-class GUID mapping — the apply refuses rather than writing a list Windows would match against nothing");
            var list = rule.Effect == PeripheralEffects.Block ? denied
                : rule.Effect == PeripheralEffects.Allow ? allowed : null;
            if (list is not null && !list.Contains(guid, StringComparer.OrdinalIgnoreCase))
                list.Add(guid);
        }
        return (denied, allowed, null);
    }

    public PeripheralApplyResult Apply(PeripheralEnforcementPlan plan)
    {
        if (!OperatingSystem.IsWindows())
            return new PeripheralApplyResult(false,
                $"device-control writer runs on Windows only — plan for machine '{plan.MachineId}' ({plan.Rules.Count} rules, mode {plan.EffectiveModeLabel}) was computed but NOT applied on this host");
        if (plan.EffectiveMode != PeripheralModes.Enforce)
            return new PeripheralApplyResult(false,
                $"device-control plan for machine '{plan.MachineId}' is AUDIT-ONLY — the writer changed nothing by design (audit mode observes; it does not enforce)");
        var (denied, allowed, refusal) = BuildClassLists(plan);
        if (refusal is not null)
            return new PeripheralApplyResult(false, $"device-control policy NOT applied for machine '{plan.MachineId}': {refusal}");
        try
        {
            using var restrictions = Registry.LocalMachine.CreateSubKey(
                @"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions");
            // BD-WIN-CORE-3/F3: rewrite the keys IN FULL on every
            // apply — delete every stale list value and reset the
            // DWORD flags, so removing a block rule actually
            // unblocks (the old writer only ever added entries).
            RewriteClassList(restrictions, "DenyDeviceClasses", denied);
            RewriteClassList(restrictions, "AllowDeviceClasses", allowed);
            // An allow list alone does nothing unless unspecified
            // devices are denied: with allowed classes present and
            // no explicit denies, DenyUnspecified makes the allow
            // list the effective boundary, as the model intends.
            restrictions.SetValue("DenyUnspecified", allowed.Count > 0 ? 1 : 0, RegistryValueKind.DWord);
            // Read back before claiming enforcement.
            var denyBack = ReadClassList(restrictions, "DenyDeviceClasses");
            var allowBack = ReadClassList(restrictions, "AllowDeviceClasses");
            if (!denyBack.SequenceEqual(denied, StringComparer.OrdinalIgnoreCase) ||
                !allowBack.SequenceEqual(allowed, StringComparer.OrdinalIgnoreCase))
                return new PeripheralApplyResult(false,
                    $"device-control policy write for machine '{plan.MachineId}' did not read back as written — enforcement NOT claimed");
            return new PeripheralApplyResult(true,
                $"device-installation restrictions written + verified for machine '{plan.MachineId}': {denied.Count} denied class GUID(s), {allowed.Count} allowed class GUID(s) (Group Policy registry keys, rewritten in full)");
        }
        catch (Exception ex)
        {
            return new PeripheralApplyResult(false,
                $"device-control policy write failed for machine '{plan.MachineId}': {ex.Message}");
        }
    }

    private static void RewriteClassList(RegistryKey restrictions, string name, IReadOnlyList<string> guids)
    {
        restrictions.SetValue(name, guids.Count > 0 ? 1 : 0, RegistryValueKind.DWord);
        using var key = restrictions.CreateSubKey(name);
        foreach (var valueName in key.GetValueNames()) key.DeleteValue(valueName, throwOnMissingValue: false);
        var i = 1;
        foreach (var guid in guids) key.SetValue((i++).ToString(), guid, RegistryValueKind.String);
    }

    private static IReadOnlyList<string> ReadClassList(RegistryKey restrictions, string name)
    {
        using var key = restrictions.OpenSubKey(name);
        if (key is null) return Array.Empty<string>();
        return key.GetValueNames()
            .OrderBy(n => int.TryParse(n, out var i) ? i : int.MaxValue)
            .Select(n => key.GetValue(n) as string)
            .Where(v => v is not null).Cast<string>().ToList();
    }
}

// ---- 2c/2f: BitLocker driver (RMM-18) ------------------------------------

/// <summary>Production BitLocker driver over manage-bde.exe (the OS
/// tool; argument lists only). State is PARSED from `manage-bde
/// -status` output — a volume whose status cannot be parsed reports
/// UNKNOWN, never encrypted. BeginEnable runs `manage-bde -on` with
/// a recovery-password protector; ReadRecoveryKey reads the
/// recovery-password protector value. The escrow layer seals what
/// this returns with the runtime ISecretProtector — DPAPI on
/// Windows (item 2f: CoreRuntime already selects
/// DpapiSecretProtector on Windows; the dev pass-through exists
/// only off-Windows and the self-check reports it).</summary>
public sealed class BitLockerDriver : IEncryptionDriver
{
    public string Name => "bitlocker-manage-bde";

    public IReadOnlyList<VolumeEncryptionState> ReadVolumes(string deviceId, DateTimeOffset now)
    {
        if (!OperatingSystem.IsWindows())
            return new[] { new VolumeEncryptionState("OS", VolumeEncryptionStates.Unknown, null, null, null) };
        var (ok, output) = OsTool.Run("manage-bde.exe", new[] { "-status" }, 60_000);
        if (!ok) return new[] { new VolumeEncryptionState("OS", VolumeEncryptionStates.Unknown, null, null, null) };
        return ParseStatus(output);
    }

    internal static IReadOnlyList<VolumeEncryptionState> ParseStatus(string output)
    {
        var volumes = new List<VolumeEncryptionState>();
        string? volume = null, conversion = null, protection = null;
        double? percent = null;
        void Flush()
        {
            if (volume is null) return;
            var state = (conversion, protection) switch
            {
                ("Fully Encrypted", "Protection On") => VolumeEncryptionStates.Encrypted,
                ("Fully Encrypted", _) => VolumeEncryptionStates.Suspended,
                ("Encryption in Progress", _) => VolumeEncryptionStates.Encrypting,
                ("Decryption in Progress", _) => VolumeEncryptionStates.Decrypting,
                ("Fully Decrypted", _) => VolumeEncryptionStates.NotEncrypted,
                _ => VolumeEncryptionStates.Unknown,
            };
            volumes.Add(new VolumeEncryptionState(volume, state,
                protection == "Protection On", percent, null));
        }
        foreach (var rawLine in output.Split('\n'))
        {
            var line = rawLine.Trim();
            if (line.StartsWith("Volume ", StringComparison.OrdinalIgnoreCase) && line.Contains(':'))
            {
                Flush();
                volume = line.Split(' ')[1].TrimEnd(':');
                conversion = null; protection = null; percent = null;
            }
            else if (line.StartsWith("Conversion Status:", StringComparison.OrdinalIgnoreCase))
                conversion = line["Conversion Status:".Length..].Trim();
            else if (line.StartsWith("Protection Status:", StringComparison.OrdinalIgnoreCase))
                protection = line["Protection Status:".Length..].Trim();
            else if (line.StartsWith("Percentage Encrypted:", StringComparison.OrdinalIgnoreCase) &&
                     double.TryParse(line["Percentage Encrypted:".Length..].Trim().TrimEnd('%'),
                         System.Globalization.NumberStyles.Float,
                         System.Globalization.CultureInfo.InvariantCulture, out var pct))
                percent = pct;
        }
        Flush();
        return volumes.Count > 0 ? volumes
            : new[] { new VolumeEncryptionState("OS", VolumeEncryptionStates.Unknown, null, null, null) };
    }

    public (bool Ok, string Reason) BeginEnable(string deviceId, string volumeId, DateTimeOffset now)
    {
        if (!OperatingSystem.IsWindows())
            return (false, "BitLocker driver runs on Windows only — enable refuses on this host");
        var volume = string.IsNullOrWhiteSpace(volumeId) ? "C:" : volumeId;
        var (ok, output) = OsTool.Run("manage-bde.exe",
            new[] { "-on", volume, "-RecoveryPassword", "-EncryptionMethod", "XtsAes256" }, 300_000);
        return ok
            ? (true, $"BitLocker enable started on {volume} (manage-bde exit 0)")
            : (false, $"manage-bde -on {volume} failed: {output}");
    }

    public string? ReadRecoveryKey(string deviceId, string volumeId, DateTimeOffset now)
    {
        if (!OperatingSystem.IsWindows()) return null;
        var volume = string.IsNullOrWhiteSpace(volumeId) ? "C:" : volumeId;
        var (ok, output) = OsTool.Run("manage-bde.exe",
            new[] { "-protectors", volume, "-get", "-Type", "RecoveryPassword" }, 60_000);
        if (!ok) return null;
        var match = System.Text.RegularExpressions.Regex.Match(output,
            @"\b\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}\b");
        return match.Success ? match.Value : null;
    }
}

// ---- 2e: DISM imaging executor (RMM-29) ----------------------------------

/// <summary>Production imaging executor over DISM. Fail-closed
/// order: (1) the base image file must exist at the definition's
/// ref (a local path or UNC — no URL is ever fetched); (2) its
/// SHA-256 must EQUAL the definition's pinned BaseImageHash — a
/// substituted image refuses before DISM is invoked; (3) DISM
/// /Apply-Image runs with the target as an argument. The applied
/// hash reported is the verified file hash. Capture is not part of
/// the IImagingExecutor contract (apply only); the WIM capture
/// driver below covers the capture half for the provisioning
/// runner's host tooling.</summary>
public sealed class DismImagingExecutor : IImagingExecutor
{
    public ImagingApplyResult ApplyImage(ImagingApplyRequest request)
    {
        if (!OperatingSystem.IsWindows())
            return new ImagingApplyResult(false, null,
                "DISM imaging executor runs on Windows only — apply refuses on this host");
        var image = request.Image;
        var path = image.BaseImageRef;
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return new ImagingApplyResult(false, null,
                $"base image '{path}' does not exist on this host — apply refused (nothing was written)");
        string actualHash;
        try
        {
            using var stream = File.OpenRead(path);
            actualHash = Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
        }
        catch (Exception ex)
        {
            return new ImagingApplyResult(false, null, $"base image '{path}' could not be hashed: {ex.Message} — apply refused");
        }
        if (!string.Equals(actualHash, (image.BaseImageHash ?? "").Trim(), StringComparison.OrdinalIgnoreCase))
            return new ImagingApplyResult(false, null,
                $"base image hash mismatch — definition pins {image.BaseImageHash}, the file hashes {actualHash}; a substituted image is refused before DISM runs");
        var target = Environment.GetEnvironmentVariable("ACP_IMAGING_TARGET");
        if (string.IsNullOrWhiteSpace(target) || !Directory.Exists(target))
            return new ImagingApplyResult(false, null,
                "no imaging target directory is configured (ACP_IMAGING_TARGET) — apply refused rather than guessing a destination");
        var (ok, output) = OsTool.Run("dism.exe",
            new[] { "/Apply-Image", $"/ImageFile:{path}", "/Index:1", $"/ApplyDir:{target}" }, 3_600_000);
        return ok
            ? new ImagingApplyResult(true, actualHash, $"DISM applied image '{image.Id}' v{image.Version} to {target} (hash verified before apply)")
            : new ImagingApplyResult(false, null, $"DISM /Apply-Image failed: {output}");
    }

    /// <summary>WIM capture half: DISM /Capture-Image from a source
    /// directory to a new WIM, returning the captured file's hash.
    /// Refuses to overwrite an existing WIM.</summary>
    public (bool Ok, string Reason, string? WimHash) CaptureImage(string sourceDir, string wimPath, string name)
    {
        if (!OperatingSystem.IsWindows())
            return (false, "DISM capture runs on Windows only — capture refuses on this host", null);
        if (!Directory.Exists(sourceDir))
            return (false, $"capture source '{sourceDir}' does not exist — capture refused", null);
        if (File.Exists(wimPath))
            return (false, $"capture target '{wimPath}' already exists — capture never overwrites a WIM", null);
        var (ok, output) = OsTool.Run("dism.exe",
            new[] { "/Capture-Image", $"/ImageFile:{wimPath}", $"/CaptureDir:{sourceDir}", $"/Name:{name}" }, 3_600_000);
        if (!ok) return (false, $"DISM /Capture-Image failed: {output}", null);
        using var stream = File.OpenRead(wimPath);
        var hash = Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
        return (true, $"captured '{sourceDir}' to {wimPath}", hash);
    }
}

// ---- 2g: remediation step executor (RMM-08, BD-WIN-CORE-3/F7) -----------

/// <summary>Production remediation executor (BD-WIN-CORE-3/F7 —
/// replaces the always-fail HostWiringRemediationStepExecutor in
/// Core composition): service start/stop/restart through the
/// ServiceController, process kill by name, and clear_path with an
/// optional minimum-age-hours argument are REAL here (service acts
/// are Windows-only and refuse by name off-Windows). run_script
/// still refuses by name — script bodies execute only through the
/// RMM-03 signed shell gate, which is a different surface — and
/// uninstall_app / rerun_patch refuse by name until their own
/// host surfaces are wired; no kind ever reports a success it did
/// not perform and verify.</summary>
public sealed class WindowsRemediationStepExecutor : IRemediationStepExecutor, IPatchRerunTarget
{
    public StepRunResult Execute(RemediationStep step, RemediationExecutionContext context)
    {
        try
        {
            return step.Kind switch
            {
                RemediationStepKinds.RestartService => ServiceAct(step.Target, restart: true),
                RemediationStepKinds.StartService => ServiceAct(step.Target, restart: false, start: true),
                RemediationStepKinds.StopService => ServiceAct(step.Target, restart: false),
                RemediationStepKinds.KillProcess => KillProcess(step.Target),
                RemediationStepKinds.ClearPath => ClearPath(step.Target, step.Argument),
                RemediationStepKinds.RunScript => StepRunResult.Failure(
                    "run_script executes only through the RMM-03 signed shell gate — this executor never runs a script body directly; no action was taken"),
                RemediationStepKinds.UninstallApp => StepRunResult.Failure(
                    $"uninstall_app for '{step.Target}' is host wiring (vendor uninstaller) — not wired in this build; no action was taken"),
                _ => StepRunResult.Failure($"unknown remediation step kind '{step.Kind}' — no action was taken"),
            };
        }
        catch (Exception ex)
        {
            return StepRunResult.Failure($"remediation step '{step.Kind}' failed: {ex.GetType().Name}: {ex.Message}");
        }
    }

    private static StepRunResult ServiceAct(string? name, bool restart, bool start = false)
    {
        if (!OperatingSystem.IsWindows())
            return StepRunResult.Failure("service control runs on Windows only — refused on this host; no action was taken");
        if (string.IsNullOrWhiteSpace(name))
            return StepRunResult.Failure("service step needs a service name target — refused");
        using var svc = new ServiceController(name);
        svc.Refresh();
        if (restart || !start)
        {
            if (svc.Status != ServiceControllerStatus.Stopped)
            {
                svc.Stop();
                svc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
            }
        }
        if (restart || start)
        {
            svc.Refresh();
            if (svc.Status == ServiceControllerStatus.Stopped)
            {
                svc.Start();
                svc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
            }
        }
        svc.Refresh();
        return StepRunResult.Success($"service '{name}' now {svc.Status}");
    }

    private static StepRunResult KillProcess(string? name)
    {
        if (string.IsNullOrWhiteSpace(name))
            return StepRunResult.Failure("kill_process needs a process name target — refused");
        var procs = Process.GetProcessesByName(name);
        if (procs.Length == 0)
            return StepRunResult.Failure($"no process named '{name}' is running — nothing was killed");
        foreach (var p in procs) { try { p.Kill(); } finally { p.Dispose(); } }
        return StepRunResult.Success($"killed {procs.Length} process(es) named '{name}'");
    }

    private static StepRunResult ClearPath(string? target, string? argument)
    {
        if (string.IsNullOrWhiteSpace(target))
            return StepRunResult.Failure("clear_path needs a path target — refused");
        var path = Environment.ExpandEnvironmentVariables(target);
        if (!Directory.Exists(path))
            return StepRunResult.Failure($"clear_path target '{path}' does not exist — nothing was cleared");
        var minAge = TimeSpan.Zero;
        if (!string.IsNullOrWhiteSpace(argument) && double.TryParse(argument,
                System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var hours))
            minAge = TimeSpan.FromHours(hours);
        var cutoff = DateTime.UtcNow - minAge;
        var cleared = 0;
        foreach (var file in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
        {
            try
            {
                if (File.GetLastWriteTimeUtc(file) <= cutoff) { File.Delete(file); cleared++; }
            }
            catch { /* one locked file must not fail the whole clear */ }
        }
        return StepRunResult.Success($"cleared {cleared} file(s) at '{path}'");
    }

    public StepRunResult RerunPatch(string patchEntryId, RemediationExecutionContext context) =>
        StepRunResult.Failure(
            $"host wiring pending: patch re-run for '{patchEntryId}' targets the RMM-02 patch service through IPatchRerunTarget — not wired in this build; no action was taken");
}
