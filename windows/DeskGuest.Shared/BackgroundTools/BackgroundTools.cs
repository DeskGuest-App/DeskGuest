using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace DeskGuest.Shared.BackgroundTools;

// =====================================================================
// RMM-10 — Background tools: fix without taking the screen (model).
//
// A background toolset that works WITHOUT opening a visible session:
// process manager (kill process / tree), service manager, file
// browser, remote registry editor (Windows) — running as SYSTEM /
// root, every action a hash-chained audit event. A governed
// mid-session toolbox (the tech's standard utilities; personal +
// shared kits) rides the same machinery: a kit is a named, versioned,
// HASH-PINNED tool bundle definition, and a kit tool runs only if
// the bytes presented at run time hash to its pin.
//
// POLICY (TOTAL POLICY CONTROL): the toolset is governed by the
// management-policy SETTING key `rmm.background_tools.enabled`,
// resolved through the RMM-07 ManagementPolicyEngine's effective
// values. It is deliberately a setting key, not a seeded registry
// toggle: the registry is code-seeded in ManagementPolicy.cs and
// this lane does not edit that file; the engine resolves an
// unregistered key from effective policy alone and fails closed
// (unknown + unset ⇒ false), so the toolset is DEFAULT OFF until
// policy enables it. The coordinator's registry integration should
// seed `rmm.background_tools.enabled` (RMM-10, default OFF) beside
// the existing `rmm.backstage.enabled` toggle. The Backstage half
// rides the SEEDED toggle `rmm.backstage.enabled` (default OFF).
//
// THE BACKSTAGE TENSION, recorded not hidden: a full hidden desktop
// session sits in real tension with DeskGuest's §7.10 presence law
// (presence cannot be hidden; STOP cannot be disabled). This lane
// builds the CAPABILITY GATE only — policy + separate permission +
// audited session record — plus a streaming-sink INTERFACE. It does
// NOT build a hidden-desktop streaming path. The gate's own law:
// a Backstage session is hidden from the DESKTOP, never from the
// AUDIT and never from the device's own session history; the
// endpoint's presence surface still shows that a background session
// occurred. See BackgroundToolsService.cs (BackstageService).
//
// THE CONSENT-SURFACE PROTECTION: the toolset can never blind the
// endpoint's own consent surface. ProtectedTargets refuses — by
// name, by resolved identity, case-insensitively, with or without
// an .exe suffix — kills/stops/writes against DeskGuest's own agent,
// presence, watchdog and audit components and DeskGuest's own protected
// registry keys. This check runs inside the service on EVERY action
// path, including tree kills (a tree containing a protected process
// refuses whole) and kit tools (a kit tool whose target resolves
// protected refuses).
// =====================================================================

public static class BackgroundPolicyKeys
{
    /// <summary>The toolset master toggle — a management-policy
    /// SETTING key (see file header for why it is not a seeded
    /// registry toggle in this lane). Default OFF: the engine fails
    /// closed on an unset key.</summary>
    public const string ToolsEnabled = "rmm.background_tools.enabled";

    /// <summary>The Backstage master toggle — the SEEDED RMM-07
    /// registry toggle for RMM-10, default OFF per the directive.</summary>
    public const string BackstageEnabled = "rmm.backstage.enabled";

    /// <summary>Per-tool policy disable: `rmm.background_tools.<tool>.enabled`
    /// — policy can disable one tool (e.g. the registry editor)
    /// while the rest of the toolset stays enabled. Absence means
    /// "follow the master toggle"; an explicit false refuses.</summary>
    public static string ToolEnabled(string tool) => $"rmm.background_tools.{tool}.enabled";
}

public static class BackgroundTools
{
    public const string ProcessKill = "process_kill";
    public const string ProcessKillTree = "process_kill_tree";
    public const string ServiceStart = "service_start";
    public const string ServiceStop = "service_stop";
    public const string ServiceRestart = "service_restart";
    public const string FileList = "file_list";
    public const string FileRead = "file_read";
    public const string FileDelete = "file_delete";
    public const string RegistryGet = "registry_get";
    public const string RegistrySet = "registry_set";
    public const string RegistryDelete = "registry_delete";
    public const string KitRun = "kit_run";
    /// <summary>BD-SHARED-RMM-1 F6: kit ADMISSION is a registered
    /// tool of its own — AdmitKit previously gated under the
    /// unregistered name "kit_admit", which no policy key could
    /// disable and no surface enumerated.</summary>
    public const string KitAdmit = "kit_admit";

    public static readonly IReadOnlyList<string> All = new[]
    {
        ProcessKill, ProcessKillTree, ServiceStart, ServiceStop, ServiceRestart,
        FileList, FileRead, FileDelete, RegistryGet, RegistrySet, RegistryDelete, KitRun, KitAdmit,
    };
}

/// <summary>The call context every background action carries: WHO is
/// asking (the pairing — its scopes are the RBAC check), for WHICH
/// device, and the RMM-03 signed-command envelope when the action
/// was initiated from the hub. Local (endpoint-initiated) calls pass
/// a null envelope and are named as local in the audit.</summary>
public sealed record BackgroundCallContext(
    string PairingId,
    string ActorName,
    IReadOnlySet<string> PairingScopes,
    string DeviceId,
    string? SignedCommandJson = null,
    // D38 F2: 'local' is a POSITIVE fact about the call's origin
    // (endpoint-initiated, established by the local transport), never
    // the mere absence of a signed envelope. A hub-relayed call
    // leaves this false; when a signed-command gate is wired, a
    // false-LocalOrigin call with no envelope refuses.
    bool LocalOrigin = false);

public sealed record BackgroundActionResult(bool Ok, string Detail, string? Output = null);

// ---- protected targets (the consent surface defends itself) -----------------

public static class ProtectedTargets
{
    /// <summary>Process image names (no extension, lowercase) that
    /// ARE DeskGuest's consent surface: the core, the session agent that
    /// renders presence + STOP, the launcher, the watchdog. Killing
    /// any of them through the toolset would blind the endpoint
    /// user — refused unconditionally, whatever policy says.</summary>
    public static readonly IReadOnlySet<string> ProcessNames = new HashSet<string>(StringComparer.Ordinal)
    {
        "deskguestcore", "deskguest.sessionagent", "deskguestsessionagent", "deskguest.launcher", "deskguestlauncher",
        "deskguest.agent", "deskguestagent", "deskguest.credentialprovider",
        "deskguest.watchdog", "deskguestwatchdog", "deskguestwatchdogservice",
    };

    /// <summary>Service names of DeskGuest's own services (the core
    /// service and its watchdog). Stopping them through the toolset
    /// is the same blind-the-endpoint move via the service manager.</summary>
    public static readonly IReadOnlySet<string> ServiceNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "DeskGuestCore", "DeskGuest", "DeskGuestWatchdog",
    };

    /// <summary>Registry key prefixes (normalised: no hive prefix,
    /// '/' or '\' separators, case-insensitive) holding DeskGuest's own
    /// protected state — pairing store, policy, audit config,
    /// command keys. The registry editor refuses writes AND deletes
    /// at or under any of them; reads are refused too (the editor
    /// is a fix tool, not a window into DeskGuest's own key material).</summary>
    public static readonly IReadOnlyList<string> RegistryKeyPrefixes = new[]
    {
        "software\\deskguest",
        "software\\wow6432node\\deskguest",
        "software\\policies\\deskguest", "system\\currentcontrolset\\services\\deskguestcore",
        "system\\currentcontrolset\\services\\deskguest",
        "system\\currentcontrolset\\services\\deskguestwatchdog",
    };

    public static string NormaliseProcessName(string? name)
    {
        var n = (name ?? "").Trim().Replace('/', '\\').ToLowerInvariant();
        // An executor may return a full image path — only the file
        // name carries the identity (D38 F7c).
        var slash = n.LastIndexOf('\\');
        if (slash >= 0) n = n[(slash + 1)..];
        if (n.EndsWith(".exe", StringComparison.Ordinal)) n = n[..^4];
        return n.Trim().Trim('*');
    }

    public static bool IsProtectedProcess(string? name) =>
        ProcessNames.Contains(NormaliseProcessName(name));

    /// <summary>Instance-level process protection (D38 F8): when the
    /// executor supplies an image path, a same-named binary OUTSIDE
    /// DeskGuest's own install roots is not DeskGuest — name alone over-blocks.
    /// With no path supplied, the name decides (fail safe).</summary>
    public static bool IsProtectedProcessInstance(BackgroundProcessInfo? proc)
    {
        if (proc is null) return false;
        if (!IsProtectedProcess(proc.Name) && !IsProtectedProcess(proc.ImagePath)) return false;
        if (string.IsNullOrWhiteSpace(proc.ImagePath)) return IsProtectedProcess(proc.Name);
        var p = proc.ImagePath.Replace('/', '\\').ToLowerInvariant();
        return p.Contains("\\deskguest\\") || p.Contains("\\deskguest ") ||
               IsProtectedProcess(proc.Name) && p.Contains("\\program files\\");
    }

    public static bool IsProtectedService(string? name) =>
        name is not null && ServiceNames.Contains(name.Trim());

    /// <summary>Resolved-identity service protection (D38 F7): the
    /// check runs on the RESOLVED service (name AND display name),
    /// never only on the caller's string.</summary>
    public static bool IsProtectedServiceInfo(BackgroundServiceInfo? svc) =>
        svc is not null && (IsProtectedService(svc.Name) || IsProtectedService(svc.DisplayName));

    public static string NormaliseRegistryKey(string? key)
    {
        var k = (key ?? "").Trim().Replace('/', '\\').ToLowerInvariant();
        foreach (var hive in new[] { "hkey_local_machine\\", "hklm\\", "hkey_current_user\\", "hkcu\\",
                                     "hkey_classes_root\\", "hkcr\\", "hkey_users\\", "hku\\" })
            if (k.StartsWith(hive, StringComparison.Ordinal)) { k = k[hive.Length..]; break; }
        // Collapse repeated separators (D38 F3f).
        while (k.Contains("\\\\")) k = k.Replace("\\\\", "\\");
        k = k.Trim('\\');
        // Canonicalise the control-set alias: CurrentControlSet and
        // ControlSet00x name the SAME key (D38 F3a).
        var segs = k.Split('\\');
        for (var i = 0; i < segs.Length; i++)
            if (segs[i] == "currentcontrolset" ||
                (segs[i].StartsWith("controlset", StringComparison.Ordinal) && segs[i].Length > 10 && segs[i][10..].All(char.IsDigit)))
                segs[i] = "currentcontrolset";
        return string.Join("\\", segs);
    }

    public static bool IsProtectedRegistryKey(string? key)
    {
        var k = NormaliseRegistryKey(key);
        if (k.Length == 0) return false;
        if (RegistryKeyPrefixes.Any(p => k == p || k.StartsWith(p + "\\", StringComparison.Ordinal))) return true;
        var segs = k.Split('\\');
        // HKU\<SID>\Software\DeskGuest…: after the hive strip the SID is the
        // first segment and the DeskGuest path follows it (D38 F3d).
        if (segs.Length >= 3 && segs[0].StartsWith("s-1-", StringComparison.Ordinal) &&
            RegistryKeyPrefixes.Any(p => string.Join("\\", segs.Skip(1)) == p ||
                                         string.Join("\\", segs.Skip(1)).StartsWith(p + "\\", StringComparison.Ordinal)))
            return true;
        // Image File Execution Options for an DeskGuest binary: a Debugger
        // value there hijacks the consent surface's launch (D38 F3e).
        const string ifeo = "software\\microsoft\\windows nt\\currentversion\\image file execution options\\";
        if (k.StartsWith(ifeo, StringComparison.Ordinal) && IsProtectedProcess(k[ifeo.Length..].Split('\\')[0]))
            return true;
        return false;
    }

    /// <summary>Write-level registry protection: the key alone plus
    /// the value name/data. Run/RunOnce launch entries pointing at
    /// an DeskGuest binary are protected writes even though the Run key
    /// itself is shared with legitimate software (D38 F3e).</summary>
    public static bool IsProtectedRegistryWrite(string? key, string? valueName, string? value)
    {
        if (IsProtectedRegistryKey(key)) return true;
        var k = NormaliseRegistryKey(key);
        if (k.EndsWith("\\currentversion\\run", StringComparison.Ordinal) ||
            k.EndsWith("\\currentversion\\runonce", StringComparison.Ordinal) ||
            k.EndsWith("\\currentversion\\runonceex", StringComparison.Ordinal))
            return IsProtectedProcess(valueName) || IsProtectedProcess(value) ||
                   (value is not null && IsProtectedFilePath(value));
        return false;
    }

    /// <summary>File-tool protection (D38 F4): DeskGuest's own install /
    /// data roots (any path segment naming DeskGuest), DeskGuest binary file
    /// names, and DeskGuest state files (pairing store, audit, config)
    /// refuse on the file tools just as they do on the registry
    /// editor — the consent surface defends itself on EVERY path.</summary>
    public static bool IsProtectedFilePath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        var segs = CanonicalSegments(path);
        if (segs.Any(s => s is "deskguest"))
            return true;
        // BD-SHARED-RMM-1 F12: the same names with separators
        // removed (a directory literally named
        // "DeskGuestPlatform" or "deskguest" is the
        // same target to a human reader and to the OS).
        if (segs.Any(s => s.Replace(" ", "").Replace("-", "").Replace("_", "") is
                "deskguest" or "deskguestplatform" or "deskguestapp"))
            return true;
        // 8.3 stems of the family names (DESKGU~1 → "deskgu").
        if (segs.Any(IsDeskGuestFamilySegment) && segs.Any(s => s.Length >= 6 &&
                ("deskguestplatform".StartsWith(s) || "deskguest".StartsWith(s))))
            return true;
        var leaf = segs.Length == 0 ? "" : segs[^1];
        if (IsProtectedProcess(leaf)) return true;
        if (leaf is "pairings.json" or "pairing.json" or "audit.log" or "audit.json" or
                    "deskguest-config.json" or "deskguest.config" or "command-keys.json")
            return segs.Any(IsDeskGuestFamilySegment);
        return false;
    }

    /// <summary>Is this (canonicalized) segment part of the DeskGuest
    /// install/data family? Covers the plain names, substrings,
    /// and the 8.3 stem of the long names (F12): the stem of
    /// "DeskGuest" is DESKGU~1 — its canonical
    /// segment "deskgu" is a ≥6-char prefix of the family name,
    /// which no ordinary directory shares.</summary>
    internal static bool IsDeskGuestFamilySegment(string seg) =>
        seg.Contains("deskguest") ||
        (seg.Length >= 6 && ("deskguestplatform".StartsWith(seg) || "deskguest".StartsWith(seg)));

    /// <summary>BD-SHARED-RMM-1 F12: canonical path segments for
    /// the protection match. The raw-string match was bypassed by
    /// every alternate form Windows itself accepts: the \?\ and
    /// \.\ device prefixes, GLOBALROOT\Device\HarddiskVolumeN
    /// device paths, trailing dots/spaces in a segment (stripped
    /// by the Win32 layer), and 8.3 short names (DESKGU~1 for
    /// "DeskGuest"). Canonicalization strips the
    /// device prefixes, drops the HarddiskVolumeN device segment,
    /// trims trailing dots/spaces per segment, and ALSO yields
    /// the 8.3 stem (the part before ~&lt;digits&gt;) as the
    /// segment when the long name is unrecoverable — the stem of
    /// a protected name still names the protected root's family,
    /// and the file tools additionally re-check the RESOLVED
    /// final path (see IBackgroundExecutor.ResolveFinalPath),
    /// which is where a junction or 8.3 alias meets its real
    /// name.</summary>
    internal static string[] CanonicalSegments(string path)
    {
        var p = path.Trim().Replace('/', '\\').ToLowerInvariant();
        while (p.Contains("\\\\")) p = p.Replace("\\\\", "\\");
        if (p.StartsWith("\\?\\")) p = p[4..];
        if (p.StartsWith("\\.\\")) p = p[4..];
        var segs = p.Split('\\', StringSplitOptions.RemoveEmptyEntries).ToList();
        // GLOBALROOT\Device\HarddiskVolumeN\… — drop the device
        // plumbing; what follows is the real path.
        var dev = segs.FindIndex(x => x.StartsWith("harddiskvolume"));
        if (dev > 0 && segs[dev - 1] == "device") segs.RemoveRange(0, dev + 1);
        else if (segs.Count > 0 && segs[0] == "globalroot") segs.RemoveAt(0);
        return segs.Select(seg =>
        {
            var t = seg.TrimEnd('.', ' ');
            // 8.3 short name: STEM~<digits>[.ext] — the stem is
            // the first 6 chars of the long name; matching uses
            // the stem as an additional candidate below.
            var tilde = t.IndexOf('~');
            if (tilde > 0 && t[(tilde + 1)..].All(c => char.IsDigit(c) || c == '.'))
            {
                var dot = t.IndexOf('.');
                var stem = dot >= 0 ? t[..tilde] + t[dot..] : t[..tilde];
                return stem;
            }
            return t;
        }).ToArray();
    }

    /// <summary>Kit-argument screening (D38 F5): true when the
    /// argument text references a protected process/service (incl.
    /// wildcard prefixes like `deskguest*`), a protected registry key, or
    /// a protected file path. PID-shaped references are resolved by
    /// the caller against the live process table.</summary>
    public static bool ArgumentsReferenceProtectedTarget(string? arguments)
    {
        if (string.IsNullOrWhiteSpace(arguments)) return false;
        var lower = arguments.ToLowerInvariant();
        foreach (var stem in ProcessNames)
            if (lower.Contains(stem)) return true;
        foreach (var svc in ServiceNames)
            if (lower.Contains(svc.ToLowerInvariant())) return true;
        if (IsProtectedRegistryKey(arguments) || IsProtectedFilePath(arguments)) return true;
        foreach (var tok in lower.Split(new[] { ' ', '\t', '"', '\'', '=', ':', ';', ',', '(', ')' },
                                        StringSplitOptions.RemoveEmptyEntries))
        {
            if (IsProtectedProcess(tok) || IsProtectedService(tok) ||
                IsProtectedRegistryKey(tok) || IsProtectedFilePath(tok)) return true;
            // Wildcard image patterns: deskguest* / deskguestcore* …
            var lit = tok.TrimEnd('*');
            if (tok.EndsWith("*", StringComparison.Ordinal) && lit.Length >= 3 &&
                ProcessNames.Any(s => s.StartsWith(lit, StringComparison.Ordinal))) return true;
        }
        return false;
    }
}

// ---- executor contracts (the agent's primitives; tests drive fakes) ---------

public sealed record BackgroundProcessInfo(int Pid, int ParentPid, string Name, long WorkingSetBytes, string? ImagePath = null);

public sealed record BackgroundServiceInfo(string Name, string DisplayName, string State);

public sealed record BackgroundFileEntry(string Name, bool IsDirectory, long? SizeBytes);

/// <summary>The primitive contract the background service drives:
/// process control, service control, file browsing, registry
/// editing, and kit-tool execution. Production wiring binds these
/// to the host's SYSTEM-context primitives (the same ones the
/// existing ProcessModule / service / registry modules use); tests
/// drive <see cref="RecordingBackgroundExecutor"/>. An executor
/// NEVER decides policy — the service gates before it is touched,
/// and the executor is only ever called after the audit start entry
/// is chained.</summary>
public interface IBackgroundExecutor
{
    IReadOnlyList<BackgroundProcessInfo> ListProcesses();
    BackgroundProcessInfo? GetProcess(int pid);
    (bool Ok, string Detail) KillProcess(int pid);
    IReadOnlyList<BackgroundServiceInfo> ListServices();
    BackgroundServiceInfo? GetService(string name);
    (bool Ok, string Detail) ControlService(string name, string action); // start|stop|restart
    (bool Ok, string Detail, IReadOnlyList<BackgroundFileEntry> Entries) ListDirectory(string path);
    (bool Ok, string Detail, string? Content) ReadFile(string path);
    (bool Ok, string Detail) DeleteFile(string path);
    (bool Ok, string Detail, string? Value) RegistryGet(string key, string valueName);
    /// <summary>BD-SHARED-RMM-1 F12: resolve a caller path to
    /// its FINAL path (junctions/symlinks/8.3 aliases resolved —
    /// production: GetFinalPathNameByHandle). The file tools
    /// re-check the resolved path against ProtectedTargets inside
    /// the audited body: the pre-gate check sees only the caller's
    /// string, and a junction under an innocent name pointing
    /// into DeskGuest's roots previously sailed through it. Null ⇒ the
    /// path cannot be resolved ⇒ the file tools refuse.</summary>
    string? ResolveFinalPath(string path);
    (bool Ok, string Detail) RegistrySet(string key, string valueName, string value);
    (bool Ok, string Detail) RegistryDelete(string key, string valueName);
    (bool Ok, string Detail, string Output) RunKitToolBinary(string kitId, string toolName, byte[] toolBytes, string arguments);
}

/// <summary>Recording + scripted fake for IBackgroundExecutor (house
/// pattern: fakes live beside the model). Holds an in-memory process
/// table (pid → name/parent), service table, file table, registry
/// table and kit-byte store. Every call is recorded; KillProcess /
/// ControlService / etc. mutate the tables so tree kills and state
/// assertions read honestly. <see cref="ThrowOn"/> makes a named
/// operation throw — the audit-evasion probe: even a throwing
/// primitive must leave a chained error event.</summary>
public sealed class RecordingBackgroundExecutor : IBackgroundExecutor
{
    public List<string> Calls { get; } = new();
    public Dictionary<int, BackgroundProcessInfo> Processes { get; } = new();
    public Dictionary<string, BackgroundServiceInfo> Services { get; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, List<BackgroundFileEntry>> Directories { get; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, string> Files { get; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, string> Registry { get; } = new(StringComparer.OrdinalIgnoreCase); // "key|value" -> data
    public Dictionary<string, byte[]> KitBytes { get; } = new(StringComparer.OrdinalIgnoreCase);   // "kitId/tool" -> bytes
    public HashSet<string> ThrowOn { get; } = new(StringComparer.OrdinalIgnoreCase);
    public List<(string KitId, string Tool, string Args)> KitRuns { get; } = new();

    private void MaybeThrow(string op)
    {
        if (ThrowOn.Contains(op)) throw new InvalidOperationException($"scripted failure in {op}");
    }

    private static string RegKey(string key, string valueName) =>
        ProtectedTargets.NormaliseRegistryKey(key) + "|" + (valueName ?? "").ToLowerInvariant();

    public IReadOnlyList<BackgroundProcessInfo> ListProcesses()
    {
        Calls.Add("list_processes"); MaybeThrow("list_processes");
        return Processes.Values.OrderBy(p => p.Pid).ToList();
    }

    public BackgroundProcessInfo? GetProcess(int pid)
    {
        Calls.Add($"get_process:{pid}"); MaybeThrow("get_process");
        return Processes.GetValueOrDefault(pid);
    }

    public (bool Ok, string Detail) KillProcess(int pid)
    {
        Calls.Add($"kill:{pid}"); MaybeThrow("kill");
        if (!Processes.Remove(pid)) return (false, $"no process with pid {pid}");
        return (true, $"killed pid {pid}");
    }

    public IReadOnlyList<BackgroundServiceInfo> ListServices()
    {
        Calls.Add("list_services"); MaybeThrow("list_services");
        return Services.Values.OrderBy(s => s.Name, StringComparer.OrdinalIgnoreCase).ToList();
    }

    public BackgroundServiceInfo? GetService(string name)
    {
        Calls.Add($"get_service:{name}"); MaybeThrow("get_service");
        if (Services.TryGetValue(name ?? "", out var byName)) return byName;
        // Mirror ServiceController semantics (D38 F7): a DISPLAY name
        // resolves to the same service — resolution is how the
        // service's identity is established, not the caller's string.
        return Services.Values.FirstOrDefault(s =>
            string.Equals(s.DisplayName, name, StringComparison.OrdinalIgnoreCase));
    }

    public (bool Ok, string Detail) ControlService(string name, string action)
    {
        Calls.Add($"service_{action}:{name}"); MaybeThrow("service_control");
        if (!Services.TryGetValue(name ?? "", out var svc)) return (false, $"no service named '{name}'");
        var state = action switch { "start" => "Running", "stop" => "Stopped", "restart" => "Running", _ => svc.State };
        Services[svc.Name] = svc with { State = state };
        return (true, $"service '{svc.Name}' {action} → {state}");
    }

    public (bool Ok, string Detail, IReadOnlyList<BackgroundFileEntry> Entries) ListDirectory(string path)
    {
        Calls.Add($"file_list:{path}"); MaybeThrow("file_list");
        return Directories.TryGetValue(path ?? "", out var entries)
            ? (true, "ok", entries)
            : (false, $"no directory at '{path}'", Array.Empty<BackgroundFileEntry>());
    }

    public (bool Ok, string Detail, string? Content) ReadFile(string path)
    {
        Calls.Add($"file_read:{path}"); MaybeThrow("file_read");
        return Files.TryGetValue(path ?? "", out var content)
            ? (true, "ok", content)
            : (false, $"no file at '{path}'", null);
    }

    public (bool Ok, string Detail) DeleteFile(string path)
    {
        Calls.Add($"file_delete:{path}"); MaybeThrow("file_delete");
        return Files.Remove(path ?? "") ? (true, $"deleted '{path}'") : (false, $"no file at '{path}'");
    }

    public (bool Ok, string Detail, string? Value) RegistryGet(string key, string valueName)
    {
        Calls.Add($"registry_get:{key}"); MaybeThrow("registry_get");
        return Registry.TryGetValue(RegKey(key, valueName), out var v)
            ? (true, "ok", v)
            : (false, $"no value '{valueName}' under '{key}'", null);
    }

    public (bool Ok, string Detail) RegistrySet(string key, string valueName, string value)
    {
        Calls.Add($"registry_set:{key}"); MaybeThrow("registry_set");
        Registry[RegKey(key, valueName)] = value;
        return (true, $"set '{key}' value '{valueName}'");
    }

    public (bool Ok, string Detail) RegistryDelete(string key, string valueName)
    {
        Calls.Add($"registry_delete:{key}"); MaybeThrow("registry_delete");
        return Registry.Remove(RegKey(key, valueName))
            ? (true, $"deleted '{key}' value '{valueName}'")
            : (false, $"no value '{valueName}' under '{key}'");
    }

    /// <summary>Scripted final paths (F12): caller path → the
    /// final path it resolves to. Unscripted paths resolve to
    /// themselves; a scripted null refuses resolution.</summary>
    public Dictionary<string, string?> FinalPaths { get; } = new(StringComparer.OrdinalIgnoreCase);

    public string? ResolveFinalPath(string path)
    {
        Calls.Add($"resolve_path:{path}"); MaybeThrow("resolve_path");
        return FinalPaths.TryGetValue(path ?? "", out var final) ? final : path;
    }

    public (bool Ok, string Detail, string Output) RunKitToolBinary(string kitId, string toolName, byte[] toolBytes, string arguments)
    {
        Calls.Add($"kit_run:{kitId}/{toolName}"); MaybeThrow("kit_run");
        KitRuns.Add((kitId, toolName, arguments));
        return (true, "kit tool ran (recording double)", $"ran {toolName} {arguments}".Trim());
    }

    /// <summary>Seed the kit-byte store from text (test convenience).</summary>
    public void SeedKitBytes(string kitId, string toolName, string content) =>
        KitBytes[$"{kitId}/{toolName}"] = Encoding.UTF8.GetBytes(content);

    public byte[]? GetKitBytes(string kitId, string toolName) =>
        KitBytes.GetValueOrDefault($"{kitId}/{toolName}");
}

// ---- the governed toolbox: kits ----------------------------------------------

public static class KitOwnerKinds
{
    public const string Personal = "personal";
    public const string Shared = "shared";
    public static readonly IReadOnlySet<string> All = new HashSet<string> { Personal, Shared };
}

/// <summary>One tool in a kit: a name, the bundle-relative path its
/// bytes live at, and the SHA-256 PIN those bytes must hash to.
/// The pin is the governance: bytes that do not match do not run,
/// whatever the caller claims they are.</summary>
public sealed record KitToolDefinition(string Name, string BundlePath, string Sha256Pin)
{
    public static string HashBytes(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    public bool PinMatches(ReadOnlySpan<byte> bytes) =>
        CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(HashBytes(bytes)),
            Encoding.ASCII.GetBytes((Sha256Pin ?? "").Trim().ToLowerInvariant()));
}

/// <summary>A named, versioned, hash-pinned tool bundle definition.
/// Personal kits belong to one tech; shared kits are the team's
/// governed standard utilities. Canonical JSON + content hash follow
/// the house library pattern (RMM-08): admission validates the whole
/// definition, the admitted copy is frozen by defensive copy, and a
/// kit's ContentHash binds (id, version, owner, tools+pins) — swap
/// any pin and the hash moves.</summary>
public sealed record ToolboxKit(
    string Id, string Name, long Version, string OwnerKind, string OwnerId,
    IReadOnlyList<KitToolDefinition> Tools)
{
    public KitToolDefinition? GetTool(string name) =>
        Tools.FirstOrDefault(t => string.Equals(t.Name, name, StringComparison.OrdinalIgnoreCase));

    public string ContentHash => EntHash.Of(ToCanonicalJson());

    public string ToCanonicalJson()
    {
        var tools = Tools.OrderBy(t => t.Name, StringComparer.Ordinal)
            .Select(t => new { name = t.Name, path = t.BundlePath, pin = (t.Sha256Pin ?? "").Trim().ToLowerInvariant() });
        return JsonSerializer.Serialize(new
        {
            id = Id, name = Name, version = Version, ownerKind = OwnerKind, ownerId = OwnerId, tools,
        });
    }

    /// <summary>Whole-definition admission validation. Null = valid;
    /// otherwise the refusal reason. A kit that fails ANY check is
    /// refused whole — a partially-governed kit is not governed.</summary>
    public string? Validate()
    {
        if (string.IsNullOrWhiteSpace(Id)) return "kit has no id — refused";
        if (string.IsNullOrWhiteSpace(Name)) return $"kit '{Id}' has no name — refused";
        if (Version < 1) return $"kit '{Id}' version must be ≥ 1 — refused";
        if (!KitOwnerKinds.All.Contains(OwnerKind ?? "")) return $"kit '{Id}' owner kind '{OwnerKind}' is not personal|shared — refused";
        if (string.IsNullOrWhiteSpace(OwnerId)) return $"kit '{Id}' has no owner id — refused";
        if (Tools is null || Tools.Count == 0) return $"kit '{Id}' carries no tools — refused";
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var t in Tools)
        {
            if (string.IsNullOrWhiteSpace(t.Name)) return $"kit '{Id}' carries a tool with no name — refused";
            if (!seen.Add(t.Name)) return $"kit '{Id}' carries duplicate tool '{t.Name}' — refused";
            if (t.Name.Any(c => !(char.IsLetterOrDigit(c) || c is '-' or '_' or '.')))
                return $"kit '{Id}' tool '{t.Name}' name carries unsafe characters — refused";
            var path = (t.BundlePath ?? "").Replace('\\', '/');
            if (path.Length == 0 || path.StartsWith("/", StringComparison.Ordinal) ||
                path.Split('/').Any(seg => seg is ".." or "") ||
                path.Contains(':'))
                return $"kit '{Id}' tool '{t.Name}' bundle path '{t.BundlePath}' is not a safe bundle-relative path — refused";
            var pin = (t.Sha256Pin ?? "").Trim();
            if (pin.Length != 64 || pin.Any(c => !Uri.IsHexDigit(c)))
                return $"kit '{Id}' tool '{t.Name}' sha256 pin is not 64 hex chars — refused";
        }
        return null;
    }

    public ToolboxKit FrozenCopy() => this with
    {
        Tools = Tools.Select(t => t with { }).ToList(),
    };
}

/// <summary>Where kit bytes come from at run time. The service asks
/// the store for the bytes of (kit, tool) and verifies them against
/// the ADMITTED definition's pin — the store is never trusted to
/// vouch for itself.</summary>
public interface IKitByteStore
{
    byte[]? GetToolBytes(string kitId, string toolName);
}

/// <summary>Kit-byte store over the recording executor's table
/// (tests); production wiring binds the on-device kit cache the
/// same way.</summary>
public sealed class ExecutorKitByteStore : IKitByteStore
{
    private readonly RecordingBackgroundExecutor _exec;
    public ExecutorKitByteStore(RecordingBackgroundExecutor exec) => _exec = exec;
    public byte[]? GetToolBytes(string kitId, string toolName) => _exec.GetKitBytes(kitId, toolName);
}

/// <summary>SHA-256 hex helper shared with the house pattern.</summary>
internal static class EntHash
{
    public static string Of(string s) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(s))).ToLowerInvariant();
}
