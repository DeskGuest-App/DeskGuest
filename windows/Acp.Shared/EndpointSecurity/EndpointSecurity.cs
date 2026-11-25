using System.Text;
using System.Text.Json;
using Acp.Shared.Audit;
using Acp.Shared.Enterprise;
using Acp.Shared.Hub;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Monitoring;
using Acp.Shared.Security;

namespace Acp.Shared.EndpointSecurity;

// =====================================================================
// RMM-17 — Endpoint security posture: ransomware auto-isolation +
// AV/EDR management (ADOPTED 2026-11-20).
//
// TWO HALVES, with the register's boundary kept sharp:
//   (1) Ransomware auto-isolation. A behaviour heuristic over a
//       file-activity seam watches for mass-encryption patterns.
//       On detection the endpoint ISOLATES from the LAN while
//       KEEPING THE ACP CHANNEL ALIVE and raises a CRITICAL alert.
//       The trigger bar is HIGH by construction (see
//       RansomwareThresholds): multiple INDEPENDENT signal families
//       are required — a single signal NEVER isolates — AND the
//       ransom-artifact family is REQUIRED (D38-F1 fix, 2026-11-21:
//       mass + rename + entropy alone is exactly what a photo
//       organiser or a compressing backup does, so behaviour alone
//       no longer isolates without an artifact) — because a
//       false-positive isolation is itself an incident. Isolation
//       is a first-class audited state, visible to the endpoint
//       user, and reversible ONLY by a hub-issued RMM-03 signed
//       command. There is no local un-isolate path.
//   (2) AV/EDR management. ACP deploys/configures/surfaces the
//       status of the ORG'S CHOSEN AV/EDR from a product registry
//       and flags machines where protection is missing, disabled
//       or stale, feeding RMM-01's security-state conditions.
//
// ACP manages security tools; it does NOT become one. There is no
// scanning engine, no signature database, no cloud SOC in this
// file — that is the excluded class-(c) form. AV status comes from
// the OS security-centre seam (the same source family the state
// report / RMM-01 SecurityStateSample already consume); the real
// WMI SecurityCenter2 reader is WINDOWS-HOST WIRING behind
// IAvStatusSource, named as a remainder, never fabricated here.
// The OS firewall/NIC actuation is likewise host wiring behind
// IEndpointNetworkControl; the DECISION, the exemption model, the
// state machine and the audit are here and fully tested.
// Recording FAKES for the seams live in Acp.Tests (D38-F12 fix:
// test doubles never ship in the production Shared assembly, so a
// DI mis-wiring can never substitute a fake for real actuation).
// =====================================================================

// ---- policy ------------------------------------------------------------

/// <summary>TOTAL POLICY CONTROL keys for RMM-17. The master toggle
/// (`rmm.endpoint_security.enabled`, seeded ON) lives in the RMM-07
/// registry; the keys below are policy CONTENT read through
/// Effective Policy by <see cref="EndpointSecurityPolicy"/>.</summary>
public static class EndpointSecurityPolicyKeys
{
    public const string Enabled = "rmm.endpoint_security.enabled";
    public const string AutoIsolation = "rmm.endpoint_security.auto_isolation";
    public const string MinSignalFamilies = "rmm.endpoint_security.min_signal_families";
    public const string MassFileThreshold = "rmm.endpoint_security.mass_file_threshold";
    public const string WindowSeconds = "rmm.endpoint_security.window_seconds";
    public const string RequiredAv = "rmm.endpoint_security.required_av";
    public const string DefinitionsMaxAgeDays = "rmm.endpoint_security.definitions_max_age_days";
    public const string StatusMaxAgeMinutes = "rmm.endpoint_security.status_max_age_minutes";
}

/// <summary>The numeric isolation bar and AV staleness bounds, with
/// their FLOORS. Policy may RAISE the bar (more conservative) but
/// may never lower it below the floors: a policy that tries is
/// clamped and the clamp is NAMED in <see cref="ClampNotes"/> (the
/// service audits it) — a weakened trigger bar arriving quietly via
/// policy is exactly the suppression game this directive refuses.</summary>
public sealed record RansomwareThresholds(
    int WindowSeconds,
    int MassFileThreshold,
    int RenameBurstThreshold,
    int EntropySurgeThreshold,
    double EntropyFloor,
    int RansomExtensionThreshold,
    int MinSignalFamilies)
{
    // THE BAR, stated numerically (also in the build log):
    //   window 60s; mass-modification >= 50 distinct files;
    //   rename burst >= 25 DISTINCT files; entropy surge >= 20
    //   DISTINCT files at >= 7.2/8.0 (inherently compressed formats
    //   never count — their entropy is naturally high);
    //   ransom artifact = >= 1 note file OR >= 10 DISTINCT
    //   ransom-extension files OR any canary touch. Isolation
    //   requires the mass signal AND the ransom-artifact signal
    //   AND >= 3 signal families in total (D38-F1).
    //   The window CEILING is the default itself (D38-F7): a longer
    //   window with the same count thresholds is a LOWER rate bar
    //   (50 files/300 s is 5x weaker than 50/60 s), so policy may
    //   only shorten the window, never lengthen it past 60 s.
    public const int FloorWindowSeconds = 30;
    public const int CeilWindowSeconds = 60;
    public const int FloorMassFiles = 50;
    public const int FloorRenameBurst = 25;
    public const int FloorEntropySurge = 20;
    public const double FloorEntropy = 7.2;
    public const int FloorMinFamilies = 3;
    public const int MaxFamilies = 4;

    public static readonly RansomwareThresholds Default = new(
        WindowSeconds: 60, MassFileThreshold: 50, RenameBurstThreshold: 25,
        EntropySurgeThreshold: 20, EntropyFloor: 7.2, RansomExtensionThreshold: 10,
        MinSignalFamilies: 3);
}

/// <summary>RMM-17's effective policy for one device: thresholds +
/// AV bounds, parsed from RMM-07 Effective Policy with floors
/// enforced. Unparsable values fall back to defaults (never to a
/// weaker reading) and are named in ClampNotes.</summary>
public sealed record EndpointSecurityPolicy(
    bool AutoIsolation,
    RansomwareThresholds Thresholds,
    string? RequiredAvProductId,
    int DefinitionsMaxAgeDays,
    int StatusMaxAgeMinutes,
    IReadOnlyList<string> ClampNotes)
{
    public const int FloorDefinitionsMaxAgeDays = 1;
    public const int DefaultDefinitionsMaxAgeDays = 7;
    public const int FloorStatusMaxAgeMinutes = 5;
    public const int DefaultStatusMaxAgeMinutes = 30;

    public static EndpointSecurityPolicy Default => new(
        true, RansomwareThresholds.Default, null,
        DefaultDefinitionsMaxAgeDays, DefaultStatusMaxAgeMinutes, Array.Empty<string>());

    public static EndpointSecurityPolicy FromEffective(EffectivePolicy effective)
    {
        var notes = new List<string>();
        string? Raw(string key) => effective.Get(key)?.Value;

        var auto = true;
        if (Raw(EndpointSecurityPolicyKeys.AutoIsolation) is { } a)
        {
            if (bool.TryParse(a, out var av)) auto = av;
            else notes.Add($"{EndpointSecurityPolicyKeys.AutoIsolation}='{a}' unparsable — default ON kept");
        }

        int Int(string key, int def, int floor, int ceil, string label)
        {
            if (Raw(key) is not { } raw) return def;
            if (!int.TryParse(raw, out var v)) { notes.Add($"{key}='{raw}' unparsable — default {def} kept"); return def; }
            if (v < floor) { notes.Add($"{key}={v} is below the {label} floor {floor} — CLAMPED to {floor} (policy may raise the bar, never lower it)"); return floor; }
            if (v > ceil) { notes.Add($"{key}={v} exceeds the ceiling {ceil} — clamped to {ceil}"); return ceil; }
            return v;
        }

        var t = RansomwareThresholds.Default with
        {
            WindowSeconds = Int(EndpointSecurityPolicyKeys.WindowSeconds,
                RansomwareThresholds.Default.WindowSeconds,
                RansomwareThresholds.FloorWindowSeconds, RansomwareThresholds.CeilWindowSeconds, "window"),
            MassFileThreshold = Int(EndpointSecurityPolicyKeys.MassFileThreshold,
                RansomwareThresholds.Default.MassFileThreshold,
                RansomwareThresholds.FloorMassFiles, 100_000, "mass-file"),
            MinSignalFamilies = Int(EndpointSecurityPolicyKeys.MinSignalFamilies,
                RansomwareThresholds.Default.MinSignalFamilies,
                RansomwareThresholds.FloorMinFamilies, RansomwareThresholds.MaxFamilies, "signal-family"),
        };

        var required = Raw(EndpointSecurityPolicyKeys.RequiredAv)?.Trim().ToLowerInvariant();
        if (required is not null && required.Length > 0 && !AvProducts.KnownIds.Contains(required))
        {
            notes.Add($"{EndpointSecurityPolicyKeys.RequiredAv}='{required}' names no registered AV product — treated as 'any registered product' and NAMED here, never silently trusted");
            required = null;
        }

        return new EndpointSecurityPolicy(
            auto, t, string.IsNullOrEmpty(required) ? null : required,
            Int(EndpointSecurityPolicyKeys.DefinitionsMaxAgeDays, DefaultDefinitionsMaxAgeDays,
                FloorDefinitionsMaxAgeDays, 365, "definitions-age"),
            Int(EndpointSecurityPolicyKeys.StatusMaxAgeMinutes, DefaultStatusMaxAgeMinutes,
                FloorStatusMaxAgeMinutes, 24 * 60, "status-age"),
            notes);
    }
}

// ---- file-activity seam + ransomware heuristic -------------------------

public static class FileActivityKinds
{
    public const string Created = "created";
    public const string Modified = "modified";
    public const string Renamed = "renamed";
    public const string Deleted = "deleted";
    public static readonly IReadOnlySet<string> All = new HashSet<string> { Created, Modified, Renamed, Deleted };
}

/// <summary>One observed file-activity event — the detector's only
/// input. EntropyAfter is the post-write Shannon entropy of the
/// file content (0..8) when the watcher measured it, null when it
/// did not: an unmeasured file NEVER counts toward the entropy
/// signal (no fabricated readings). ProcessName is attribution
/// only; it is never an allowlist — a "backup-shaped" process name
/// earns no exemption, because names are spoofable (named residual
/// in the destruction ledger).</summary>
public sealed record FileActivityEvent(
    string Path,
    string Kind,
    string? OldPath,
    double? EntropyAfter,
    string? ProcessName,
    DateTimeOffset AtUtc)
{
    public string Extension
    {
        get
        {
            var p = Path ?? "";
            var dot = p.LastIndexOf('.');
            var sep = Math.Max(p.LastIndexOf('/'), p.LastIndexOf('\\'));
            return dot > sep && dot >= 0 ? p[(dot + 1)..].ToLowerInvariant() : "";
        }
    }
}

/// <summary>The file-activity seam. The production watcher
/// (FileSystemWatcher + entropy sampling on the Windows host) is
/// host wiring; tests and this build drive the fake below. The
/// detector consumes ONLY this interface.</summary>
public interface IFileActivitySource
{
    IReadOnlyList<FileActivityEvent> Drain();
}

public static class SignalFamilies
{
    public const string MassModification = "mass_modification";
    public const string RenameBurst = "rename_burst";
    public const string EntropySurge = "entropy_surge";
    public const string RansomArtifact = "ransom_artifact";
    public static readonly IReadOnlyList<string> All = new[]
        { MassModification, RenameBurst, EntropySurge, RansomArtifact };
}

/// <summary>Ransom-note filenames and extensions the artifact signal
/// recognises. Deliberately a small, named, local list — content,
/// not a signature database: this is a behaviour heuristic input,
/// not an AV engine. D38-F10: the extension list carries ONLY
/// generic descriptive forms (locked / encrypted / crypto).
/// Ransomware FAMILY names (lockbit, conti, …) are signatures and
/// are out of scope by the directive's own law; everyday benign
/// extensions (enc, crypt, wallet) are out because real vault /
/// wallet software writes them routinely.</summary>
public static class RansomArtifacts
{
    public static readonly IReadOnlySet<string> NoteNameFragments = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "readme_decrypt", "decrypt_instruction", "how_to_decrypt", "recover_files",
        "ransom_note", "your_files_are_encrypted", "restore_my_files", "help_decrypt",
    };

    public static readonly IReadOnlySet<string> Extensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "locked", "encrypted", "crypto",
    };

    /// <summary>Extensions whose content is inherently compressed /
    /// encoded, so a high measured entropy says nothing about
    /// encryption (JPEG ≈ 7.9 bits/byte natively). Files with these
    /// extensions NEVER count toward the entropy-surge family
    /// (D38-F1: a photo import is not an entropy surge).</summary>
    public static readonly IReadOnlySet<string> InherentlyCompressedExtensions =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "jpg", "jpeg", "png", "gif", "webp", "heic", "heif", "avif",
            "zip", "gz", "bz2", "xz", "7z", "rar", "zst", "lz4",
            "mp3", "mp4", "mkv", "avi", "mov", "webm", "flac", "ogg",
            "pdf", "docx", "xlsx", "pptx", "epub",
        };

    public static bool IsNoteFile(string path)
    {
        var name = path ?? "";
        var sep = Math.Max(name.LastIndexOf('/'), name.LastIndexOf('\\'));
        if (sep >= 0) name = name[(sep + 1)..];
        return NoteNameFragments.Any(f => name.Contains(f, StringComparison.OrdinalIgnoreCase));
    }
}

/// <summary>One evaluation of the sliding window. FamiliesPresent
/// names exactly which independent signals fired and Counts carries
/// the raw numbers, so every verdict — isolate or not — is
/// explainable from the record, never a bare boolean.</summary>
public sealed record DetectionVerdict(
    bool ShouldIsolate,
    IReadOnlyList<string> FamiliesPresent,
    int DistinctFiles,
    int RenameCount,
    int HighEntropyFiles,
    int RansomExtensionFiles,
    bool NoteFileSeen,
    bool CanaryTouched,
    string Detail);

/// <summary>The conservative ransomware detector. Stateful sliding
/// window over ingested events; evaluation is a pure function of
/// the window contents + thresholds. THE BAR: isolation requires
/// the mass-modification family AND the ransom-artifact family AND
/// at least MinSignalFamilies (>= 3, floor-enforced) families in
/// total. All family counts are over DISTINCT files (D38-F10: one
/// file saved / renamed repeatedly is one file, not a burst).
/// Corollaries proven in tests: a bulk backup / photo import /
/// build fires at most mass + rename and never isolates; a rename
/// storm alone never isolates; an entropy surge alone never
/// isolates; mass + rename + entropy with NO artifact (the photo
/// organiser / compressing backup shape) never isolates.</summary>
public sealed class RansomwareDetector
{
    /// <summary>Hard cap on retained window events (D38-F12): a
    /// real burst can produce millions of events per minute; the
    /// window keeps the NEWEST events up to the cap and drops the
    /// oldest, so memory is bounded regardless of ingest rate.</summary>
    public const int MaxWindowEvents = 100_000;

    private readonly List<FileActivityEvent> _window = new();
    private readonly IReadOnlySet<string> _canaryPaths;
    private readonly object _gate = new();

    public RansomwareDetector(IEnumerable<string>? canaryPaths = null)
    {
        _canaryPaths = new HashSet<string>(
            canaryPaths ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
    }

    public IReadOnlySet<string> CanaryPaths => _canaryPaths;

    public int WindowEventCount { get { lock (_gate) return _window.Count; } }

    public void Ingest(IEnumerable<FileActivityEvent> events)
    {
        lock (_gate)
        {
            foreach (var e in events)
                if (e is not null && FileActivityKinds.All.Contains(e.Kind ?? ""))
                    _window.Add(e);
            if (_window.Count > MaxWindowEvents)
                _window.RemoveRange(0, _window.Count - MaxWindowEvents);
        }
    }

    /// <summary>bd-shared-sec-1/F11: the canary paths the service
    /// seeds by DEFAULT for each protected root — a hidden,
    /// never-legitimately-touched file per root. Previously the
    /// detector defaulted to NO canaries at all, so the strongest
    /// single artifact signal existed only where a host happened
    /// to wire paths by hand.</summary>
    public static IReadOnlyList<string> DefaultCanaryPathsFor(IEnumerable<string> protectedRoots) =>
        (protectedRoots ?? Array.Empty<string>())
            .Where(r => !string.IsNullOrWhiteSpace(r))
            .Select(r => Path.Combine(r.Trim(), ".acp-canary", "acp-canary-do-not-modify.txt"))
            .Distinct(StringComparer.OrdinalIgnoreCase).ToList();

    /// <summary>Seed the default canary files on disk (idempotent:
    /// an existing canary is left byte-for-byte alone) and return
    /// their paths for the detector. A root that cannot be seeded
    /// is skipped and NOT returned — an unseeded canary is never
    /// claimed as watched.</summary>
    public static IReadOnlyList<string> SeedDefaultCanaries(IEnumerable<string> protectedRoots)
    {
        var seeded = new List<string>();
        foreach (var path in DefaultCanaryPathsFor(protectedRoots))
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                if (!File.Exists(path))
                    File.WriteAllText(path, "ACP ransomware canary — this file is never legitimately modified. Its touch is an isolation signal.\n");
                seeded.Add(path);
            }
            catch { /* unseedable root: not claimed */ }
        }
        return seeded;
    }

    /// <summary>A detector whose canaries are the seeded defaults
    /// for the protected roots, plus any extra paths supplied.</summary>
    public static RansomwareDetector ForProtectedRoots(IEnumerable<string> protectedRoots, IEnumerable<string>? extraCanaryPaths = null) =>
        new(SeedDefaultCanaries(protectedRoots).Concat(extraCanaryPaths ?? Array.Empty<string>()));

    public DetectionVerdict Evaluate(RansomwareThresholds t, DateTimeOffset now)
    {
        List<FileActivityEvent> events;
        lock (_gate)
        {
            var cutoff = now.AddSeconds(-t.WindowSeconds);
            _window.RemoveAll(e => e.AtUtc < cutoff || e.AtUtc > now.AddMinutes(5));
            events = _window.ToList();
        }

        var touched = events.Where(e => e.Kind is FileActivityKinds.Created or FileActivityKinds.Modified or FileActivityKinds.Renamed).ToList();
        var distinctFiles = touched.Select(e => e.Path).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        // DISTINCT files per family (D38-F10).
        var renames = events.Where(e => e.Kind == FileActivityKinds.Renamed)
            .Select(e => e.Path).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        var highEntropy = touched
            .Where(e => e.EntropyAfter is { } en && en >= t.EntropyFloor
                        && !RansomArtifacts.InherentlyCompressedExtensions.Contains(e.Extension))
            .Select(e => e.Path).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        var ransomExt = touched.Where(e => RansomArtifacts.Extensions.Contains(e.Extension))
            .Select(e => e.Path).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        var noteSeen = events.Any(e => RansomArtifacts.IsNoteFile(e.Path));
        var canary = events.Any(e =>
            _canaryPaths.Contains(e.Path) || (e.OldPath is not null && _canaryPaths.Contains(e.OldPath)));
        // bd-shared-sec-1/F11: EXTENSION CHURN — modern ransomware
        // uses a random per-victim extension, so the fixed
        // three-extension list misses it entirely. The churn shape:
        // at least RansomExtensionThreshold DISTINCT files RENAMED
        // to the SAME new extension (not a known ransom extension,
        // not an inherently-compressed/benign format, and different
        // from each file's original extension). One new extension
        // arriving on many files at once is the artifact.
        var churn = events
            .Where(e => e.Kind == FileActivityKinds.Renamed && e.OldPath is not null
                        && e.Extension.Length > 0
                        && !RansomArtifacts.Extensions.Contains(e.Extension)
                        && !RansomArtifacts.InherentlyCompressedExtensions.Contains(e.Extension))
            .Where(e =>
            {
                var old = e.OldPath!;
                var dot = old.LastIndexOf('.');
                var sep = Math.Max(old.LastIndexOf('/'), old.LastIndexOf('\\'));
                var oldExt = dot > sep && dot >= 0 ? old[(dot + 1)..].ToLowerInvariant() : "";
                return !string.Equals(oldExt, e.Extension, StringComparison.OrdinalIgnoreCase);
            })
            .GroupBy(e => e.Extension, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.Select(e => e.Path).Distinct(StringComparer.OrdinalIgnoreCase).Count())
            .DefaultIfEmpty(0).Max();
        var churnArtifact = churn >= t.RansomExtensionThreshold;

        var families = new List<string>();
        if (distinctFiles >= t.MassFileThreshold) families.Add(SignalFamilies.MassModification);
        if (renames >= t.RenameBurstThreshold) families.Add(SignalFamilies.RenameBurst);
        if (highEntropy >= t.EntropySurgeThreshold) families.Add(SignalFamilies.EntropySurge);
        if (noteSeen || canary || ransomExt >= t.RansomExtensionThreshold || churnArtifact) families.Add(SignalFamilies.RansomArtifact);

        var isolate = families.Contains(SignalFamilies.MassModification)
                      && families.Contains(SignalFamilies.RansomArtifact)
                      && families.Count >= t.MinSignalFamilies;
        var detail =
            $"window={t.WindowSeconds}s files={distinctFiles}/{t.MassFileThreshold} renames={renames}/{t.RenameBurstThreshold} " +
            $"highEntropy={highEntropy}/{t.EntropySurgeThreshold} ransomExt={ransomExt}/{t.RansomExtensionThreshold} churnExt={churn}/{t.RansomExtensionThreshold} " +
            $"note={noteSeen} canary={canary} families=[{string.Join(",", families)}] required>={t.MinSignalFamilies}+mass+artifact";
        return new DetectionVerdict(isolate, families, distinctFiles, renames,
            highEntropy, ransomExt, noteSeen, canary, detail);
    }

    /// <summary>Drop all windowed events (after an isolation episode
    /// resolves, the next episode must earn the bar from fresh
    /// activity — yesterday's burst never re-isolates by itself).</summary>
    public void Reset() { lock (_gate) _window.Clear(); }
}

// ---- network isolation ---------------------------------------------------

public static class ExemptionKinds
{
    public const string Hub = "hub";               // the ACP hub endpoint (host+port)
    public const string LanRung = "lan_rung";      // ACP's own LAN transport rung (port)
    public const string Tailscale = "tailscale";   // ACP's tailnet endpoint (host+port)
    public static readonly IReadOnlySet<string> All = new HashSet<string> { Hub, LanRung, Tailscale };
}

/// <summary>Strict exact-host validation for exemptions (D38-F4).
/// A host is admissible ONLY as (a) an exact IP literal that is a
/// real host address — never unspecified (0.0.0.0), never a
/// multicast or broadcast address, never an IPv4 network/broadcast
/// form (last octet 0/255) — or (b) a strict multi-label DNS
/// hostname (LDH labels). EVERYTHING else refuses: wildcards, CIDR,
/// IP ranges ("10.0.0.1-10.0.0.254" and any digits/dots/hyphens
/// string that is not a valid IP), and the Windows Firewall scope
/// KEYWORDS (Any, LocalSubnet, Intranet, …) that RemoteAddress
/// would silently expand into broad holes.</summary>
public static class ExemptionHosts
{
    private static readonly IReadOnlySet<string> ScopeKeywords =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "any", "localsubnet", "local-subnet", "intranet", "internet",
            "dns", "dhcp", "wins", "defaultgateway", "default-gateway",
            "broadcast", "multicast", "localhost",
        };

    public static string? Validate(string? host)
    {
        if (string.IsNullOrWhiteSpace(host))
            return "exemption needs an exact host — refused";
        var h = host.Trim();
        if (ScopeKeywords.Contains(h))
            return $"exemption host '{h}' is a firewall scope keyword that expands to a range — refused (exemptions are exact hosts only)";
        if (System.Net.IPAddress.TryParse(h, out var ip))
        {
            if (ip.Equals(System.Net.IPAddress.Any) || ip.Equals(System.Net.IPAddress.IPv6Any))
                return $"exemption host '{h}' is the unspecified address — refused";
            var bytes = ip.GetAddressBytes();
            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                if (bytes[0] >= 224 && bytes[0] <= 239)
                    return $"exemption host '{h}' is a multicast address — refused";
                if (bytes[3] == 0 || bytes[3] == 255)
                    return $"exemption host '{h}' is a network/broadcast form, not a host address — refused";
            }
            if (ip.Equals(System.Net.IPAddress.Broadcast))
                return $"exemption host '{h}' is the broadcast address — refused";
            return null;
        }
        // Not an IP literal. A digits/dots/hyphens-only string is an
        // IP-range or partial-IP form — never a hostname.
        if (h.All(c => char.IsDigit(c) || c is '.' or '-'))
            return $"exemption host '{h}' is an IP range / partial address — refused (exemptions are exact hosts only, never ranges)";
        if (h.Contains('*') || h.Contains('/') || h.Contains(' ') || h.Contains('\\')
            || h.Contains('_') || h.EndsWith('.'))
            return $"exemption host '{h}' is not a strict exact host — refused";
        var labels = h.Split('.');
        if (labels.Length < 2)
            return $"exemption host '{h}' is a single label (scope keyword / bare name) — refused (an exact qualified host or IP is required)";
        foreach (var label in labels)
        {
            if (label.Length is < 1 or > 63 || ScopeKeywords.Contains(label))
                return $"exemption host '{h}' has an invalid or keyword label '{label}' — refused";
            if (!label.All(c => char.IsLetterOrDigit(c) || c == '-')
                || label.StartsWith('-') || label.EndsWith('-'))
                return $"exemption host '{h}' has a non-LDH label '{label}' — refused";
        }
        if (h.Length > 253)
            return $"exemption host '{h}' is too long — refused";
        return null;
    }
}

/// <summary>One ACP-channel exemption: the ONLY traffic allowed
/// while isolated. Narrow by construction: an exact host (never a
/// wildcard, never a CIDR, never a range, never a firewall scope
/// keyword — see <see cref="ExemptionHosts"/>) and an exact port,
/// for EVERY kind including the LAN rung (D38-F3: the rung
/// previously matched ANY host on its port, which is the
/// ransomware lateral-movement shape; the rung's peer is the hub's
/// exact LAN address, named like every other exemption). There is
/// no shape in this model that expresses "allow a subnet" or
/// "allow any host" — the exemption cannot be widened into a
/// general hole without changing this type, and validation refuses
/// the attempt. Hostname exemptions resolve through DNS at the
/// host seam; that residual is named in the ledger.</summary>
public sealed record AcpChannelExemption(string Kind, string? Host, int Port)
{
    public string? Validate()
    {
        if (!ExemptionKinds.All.Contains(Kind ?? ""))
            return $"unknown exemption kind '{Kind}' — refused (the ACP channel exemption is a closed set)";
        if (Port < 1 || Port > 65535)
            return $"exemption port {Port} out of range — refused";
        if (ExemptionHosts.Validate(Host) is { } err)
            return $"exemption kind '{Kind}': {err}";
        return null;
    }

    public bool Matches(string? host, int port)
    {
        if (port != Port) return false;
        return host is not null && string.Equals(host, Host, StringComparison.OrdinalIgnoreCase);
    }
}

/// <summary>The isolation plan handed to the network-control seam:
/// block ALL LAN traffic except the listed ACP exemptions. An
/// empty exemption list refuses — isolating WITH the ACP channel
/// cut is the one outcome this directive exists to prevent, so a
/// plan that would do it is invalid by construction.</summary>
public sealed record IsolationPlan(IReadOnlyList<AcpChannelExemption> Exemptions)
{
    public IReadOnlyList<AcpChannelExemption> Exemptions { get; init; } =
        Exemptions ?? Array.Empty<AcpChannelExemption>();

    public string? Validate()
    {
        if (Exemptions.Count == 0)
            return "isolation plan carries NO ACP channel exemption — refused (isolation must keep the ACP channel alive; a total network cut is not this feature)";
        foreach (var e in Exemptions)
            if (e.Validate() is { } err) return err;
        return null;
    }

    /// <summary>Pure traffic decision while isolated: allowed IFF
    /// some exemption matches exactly. Everything else — LAN peers,
    /// internet, other ports on the hub host — is blocked.</summary>
    public bool IsTrafficAllowed(string? host, int port) =>
        Exemptions.Any(e => e.Matches(host, port));
}

/// <summary>The network-control seam. The production implementation
/// (Windows Firewall rule set / NIC control on the host) is host
/// wiring; it receives only validated plans. Tests use the fake.</summary>
public interface IEndpointNetworkControl
{
    bool IsIsolationApplied { get; }
    IsolationPlan? AppliedPlan { get; }
    void ApplyIsolation(IsolationPlan plan);
    void RemoveIsolation();
}

public static class IsolationStates
{
    public const string Normal = "normal";
    public const string Isolated = "isolated";
    public const string IsolationFailed = "isolation_failed";
}

/// <summary>The endpoint user's plain view of isolation. When
/// isolated, BannerText is non-empty BY CONSTRUCTION — the state is
/// never a silent network cut: the person at the machine can read
/// that ACP isolated it, why, and that only the hub can release
/// it.</summary>
public sealed record IsolationStatus(
    string State,
    DateTimeOffset? SinceUtc,
    string? Reason,
    string? BannerText,
    IReadOnlyList<AcpChannelExemption> ActiveExemptions)
{
    public bool IsIsolated => State == IsolationStates.Isolated;

    public static IsolationStatus Normal() =>
        new(IsolationStates.Normal, null, null, null, Array.Empty<AcpChannelExemption>());
}

/// <summary>The isolation state machine + audit. Transitions:
/// normal → isolated (detector verdict, via the service),
/// normal → isolation_failed (actuation threw; alerted, retried on
/// the next verdict), isolated → normal (ONLY through
/// <see cref="HandleSignedUnisolate"/>: an RMM-03 signed envelope,
/// class automation, payload action rmm17.unisolate bound to THIS
/// device). Every other path — including any local call — refuses
/// and the refusal is chained.</summary>
public sealed class EndpointIsolationManager
{
    public const string UnisolateAction = "rmm17.unisolate";

    private readonly string _deviceId;
    private readonly IEndpointNetworkControl _control;
    private readonly ChainedAuditLog _audit;
    private readonly object _gate = new();
    private IsolationStatus _status = IsolationStatus.Normal();

    public EndpointIsolationManager(string deviceId, IEndpointNetworkControl control, ChainedAuditLog audit)
    {
        _deviceId = deviceId ?? throw new ArgumentNullException(nameof(deviceId));
        _control = control ?? throw new ArgumentNullException(nameof(control));
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        // bd-shared-sec-1/F3: reconcile against the OS-level control
        // at construction — firewall isolation survives a process
        // restart even though this in-memory state does not.
        ReconcileWithControl(DateTimeOffset.UtcNow);
    }

    public string DeviceId => _deviceId;
    public IsolationStatus Status { get { lock (_gate) return _status; } }

    // bd-shared-sec-1/F12: every free-text value spliced into audit
    // details goes through the shared escape (AuditText), exactly
    // as the encryption lane's E(...) does.
    private static string E(string? s) => AuditText.Escape(s);

    /// <summary>bd-shared-sec-1/F3: reconcile the manager's state
    /// with the network control's ACTUAL state. If isolation is
    /// applied at OS level but the manager thinks Normal (the
    /// restart shape), the manager ADOPTS the isolated state —
    /// banner, since-instant and the applied plan's exemptions —
    /// and chains the adoption, so the banner's promise ("only
    /// your IT team can end the isolation — restarting will not")
    /// is true. If the manager thinks Isolated but the control
    /// reports nothing applied, the state is honestly marked
    /// isolation_failed, never silently Normal. Returns true when
    /// a reconciliation changed the state.</summary>
    public bool ReconcileWithControl(DateTimeOffset now)
    {
        lock (_gate)
        {
            if (_control.IsIsolationApplied && !_status.IsIsolated)
            {
                var plan = _control.AppliedPlan;
                var reason = "isolation restored after restart: the network control reports isolation still applied (the firewall state survived; the manager's in-memory state did not)";
                _status = new IsolationStatus(IsolationStates.Isolated, now, reason,
                    BannerFor(reason), plan?.Exemptions ?? Array.Empty<AcpChannelExemption>());
                _audit.Append("endpoint_isolation_restored", "endpoint-security",
                    $"device={E(_deviceId)} reason={E(reason)} exemptions={plan?.Exemptions.Count ?? 0}", now);
                return true;
            }
            if (!_control.IsIsolationApplied && _status.IsIsolated)
            {
                _status = new IsolationStatus(IsolationStates.IsolationFailed, now,
                    "manager believed the endpoint isolated but the network control reports isolation NOT applied — state is honestly failed, not normal", null, Array.Empty<AcpChannelExemption>());
                _audit.Append("endpoint_isolation_state_mismatch", "endpoint-security",
                    $"device={E(_deviceId)} manager=isolated control=not-applied", now);
                return true;
            }
            return false;
        }
    }

    // ---- persistence (bd-shared-sec-1/F3) ------------------------
    // The isolation episode (state, since, reason, plan) exports
    // through the HubPersistence envelope so a host can restore it
    // across restarts; ReconcileWithControl remains the ground
    // truth check against the OS control after any restore.

    public string ExportStatusJson()
    {
        lock (_gate)
            return HubPersistence.Wrap("acp-endpoint-isolation-v1", JsonSerializer.Serialize(_status));
    }

    /// <summary>Restore a persisted isolation episode. A payload
    /// failing the envelope, or naming an unknown state, restores
    /// nothing. After a successful restore the caller should run
    /// ReconcileWithControl — the OS control is the ground truth.
    /// Returns true when a status was restored.</summary>
    public bool ImportStatusJson(string json)
    {
        var payload = HubPersistence.Unwrap(json, "acp-endpoint-isolation-v1");
        if (payload is null) return false;
        IsolationStatus? status;
        try { status = JsonSerializer.Deserialize<IsolationStatus>(payload); } catch { return false; }
        if (status is null) return false;
        if (status.State is not (IsolationStates.Normal or IsolationStates.Isolated or IsolationStates.IsolationFailed)) return false;
        lock (_gate) _status = status;
        return true;
    }

    public static string BannerFor(string reason) =>
        $"THIS COMPUTER HAS BEEN ISOLATED FROM THE NETWORK by ACP endpoint protection. " +
        $"Reason: {reason}. The ACP management channel remains connected so IT can investigate and release this computer. " +
        $"Only your IT team can end the isolation — restarting will not.";

    /// <summary>Isolate now under a validated plan. Idempotent while
    /// isolated (a second verdict refreshes nothing and does not
    /// re-apply). A plan that fails validation, or actuation that
    /// throws, leaves the state honest (normal / isolation_failed)
    /// and chained — never a pretend isolation.</summary>
    public (bool Applied, string Detail) Isolate(IsolationPlan plan, string reason, DateTimeOffset now)
    {
        lock (_gate)
        {
            if (_status.IsIsolated)
                return (true, "already isolated (idempotent)");
            var planError = plan is null ? "no plan" : plan.Validate();
            if (planError is not null)
            {
                _audit.Append("endpoint_isolation_refused", "endpoint-security",
                    $"device={E(_deviceId)} reason={E(planError)}", now);
                return (false, planError);
            }
            try { _control.ApplyIsolation(plan!); }
            catch (Exception ex)
            {
                _status = new IsolationStatus(IsolationStates.IsolationFailed, now,
                    $"actuation failed: {ex.Message}", null, Array.Empty<AcpChannelExemption>());
                _audit.Append("endpoint_isolation_failed", "endpoint-security",
                    $"device={E(_deviceId)} reason={E(reason)} error={E(ex.Message)}", now);
                return (false, $"isolation actuation failed: {ex.Message}");
            }
            _status = new IsolationStatus(IsolationStates.Isolated, now, reason,
                BannerFor(reason), plan.Exemptions);
            _audit.Append("endpoint_isolated", "endpoint-security",
                $"device={E(_deviceId)} reason={E(reason)} exemptions={plan.Exemptions.Count}", now);
            return (true, "endpoint isolated; ACP channel exemptions in force");
        }
    }

    /// <summary>THE local un-isolate path — which is to say, there
    /// isn't one. Any local attempt (a process on the endpoint, a
    /// console action, a script) refuses unconditionally and the
    /// attempt is chained. Release authority is the hub's signed
    /// command and nothing else.</summary>
    public (bool Applied, string Detail) TryLocalUnisolate(string actor, DateTimeOffset now)
    {
        _audit.Append("endpoint_unisolate_refused_local", actor ?? "unknown",
            $"device={_deviceId} — local un-isolation does not exist; release requires an RMM-03 signed hub command", now);
        return (false, "local un-isolation refused: release is a hub-signed command only (RMM-03)");
    }

    /// <summary>Release isolation under an RMM-03 signed command.
    /// The gate verifies class (automation), signature, expiry and
    /// nonce; this method additionally binds the payload: action
    /// must be rmm17.unisolate and deviceId must be THIS device —
    /// a validly signed command for another device, or for another
    /// action, releases nothing here.</summary>
    public (bool Applied, string Detail) HandleSignedUnisolate(
        SignedCommandEnvelope? envelope, SignedCommandGate gate, DateTimeOffset now)
    {
        if (gate is null) throw new ArgumentNullException(nameof(gate));
        var verdict = gate.Authorize(envelope, now, SignedCommandClasses.Automation);
        if (!verdict.Allowed)
            return (false, $"un-isolate refused: {verdict.Reason}");
        string action, device;
        try
        {
            using var doc = JsonDocument.Parse(verdict.Payload!);
            action = doc.RootElement.GetProperty("action").GetString() ?? "";
            device = doc.RootElement.GetProperty("deviceId").GetString() ?? "";
        }
        catch
        {
            _audit.Append("endpoint_unisolate_refused", "endpoint-security",
                $"device={_deviceId} — signed payload is not the expected JSON shape (refusal chained; D38-F11: gate-level nonce consumption is RMM-03's record, this is the manager's)", now);
            return (false, "un-isolate refused: payload is not the expected JSON shape");
        }
        // EPISODE BINDING (D38-F11): the envelope must have been
        // issued FOR THIS isolation episode — an envelope minted
        // before the current episode began (for an earlier episode,
        // or in anticipation of one) releases nothing, even inside
        // its expiry. (Replay of an envelope minted DURING this
        // episode is already refused by the RMM-03 nonce guard.)
        lock (_gate)
        {
            if ((_status.IsIsolated || _status.State == IsolationStates.IsolationFailed)
                && _status.SinceUtc is { } since && envelope!.IssuedUtc < since)
            {
                _audit.Append("endpoint_unisolate_refused", "endpoint-security",
                    $"device={_deviceId} envelope issued {envelope.IssuedUtc:O} predates the current isolation episode (since {since:O}) — not bound to this episode", now);
                return (false, "un-isolate refused: envelope predates the current isolation episode");
            }
        }
        if (action != UnisolateAction)
        {
            _audit.Append("endpoint_unisolate_refused", "endpoint-security",
                $"device={_deviceId} payload action '{action}' is not {UnisolateAction}", now);
            return (false, $"un-isolate refused: payload action '{action}' is not {UnisolateAction}");
        }
        if (!string.Equals(device, _deviceId, StringComparison.OrdinalIgnoreCase))
        {
            _audit.Append("endpoint_unisolate_refused", "endpoint-security",
                $"device={_deviceId} payload targets '{device}' — a signed command for another device releases nothing here", now);
            return (false, "un-isolate refused: payload targets a different device");
        }
        lock (_gate)
        {
            if (!_status.IsIsolated && _status.State != IsolationStates.IsolationFailed)
            {
                // bd-shared-sec-1/F3: "not isolated" in the manager
                // is NOT the ground truth — after a restart the
                // firewall rules can still be applied while this
                // state reads Normal. A signed unisolate must then
                // still call RemoveIsolation, or the device is
                // stuck isolated with no release path.
                if (!_control.IsIsolationApplied)
                    return (true, "not isolated (idempotent release)");
                try { _control.RemoveIsolation(); }
                catch (Exception ex)
                {
                    _audit.Append("endpoint_unisolate_failed", "endpoint-security",
                        $"device={E(_deviceId)} error={E(ex.Message)}", now);
                    return (false, $"un-isolate actuation failed: {ex.Message}");
                }
                _audit.Append("endpoint_unisolated", "signed-command",
                    $"device={E(_deviceId)} released by hub signed command (manager state was normal but the network control reported isolation applied — OS-level isolation removed; key={envelope!.KeyId} nonce={envelope.Nonce})", now);
                return (true, "isolation released by signed hub command (OS-level isolation was applied despite a normal manager state — removed)");
            }
            try { _control.RemoveIsolation(); }
            catch (Exception ex)
            {
                _audit.Append("endpoint_unisolate_failed", "endpoint-security",
                    $"device={E(_deviceId)} error={E(ex.Message)}", now);
                return (false, $"un-isolate actuation failed: {ex.Message}");
            }
            _status = IsolationStatus.Normal();
            _audit.Append("endpoint_unisolated", "signed-command",
                $"device={_deviceId} released by hub signed command (key={envelope!.KeyId} nonce={envelope.Nonce})", now);
            return (true, "isolation released by signed hub command");
        }
    }
}

// ---- AV/EDR registry + posture ------------------------------------------

/// <summary>One AV/EDR product ACP knows how to MANAGE (deploy /
/// configure / surface). Registry membership means "ACP has a
/// management mapping for this product" — it confers no trust: a
/// reading for an unregistered product is flagged unknown, never
/// read as protection.</summary>
public sealed record AvProduct(
    string Id, string DisplayName, string Vendor,
    bool SupportsDeploy, bool SupportsConfigure);

public static class AvProducts
{
    public static readonly IReadOnlyList<AvProduct> All = new[]
    {
        new AvProduct("defender", "Microsoft Defender Antivirus", "Microsoft", true, true),
        new AvProduct("bitdefender", "Bitdefender Endpoint Security", "Bitdefender", true, true),
        new AvProduct("crowdstrike", "CrowdStrike Falcon", "CrowdStrike", true, true),
        new AvProduct("sentinelone", "SentinelOne", "SentinelOne", true, true),
        new AvProduct("eset", "ESET Endpoint Security", "ESET", true, true),
        new AvProduct("sophos", "Sophos Intercept X", "Sophos", true, true),
        new AvProduct("trendmicro", "Trend Micro Apex One", "Trend Micro", true, true),
        new AvProduct("trellix", "Trellix Endpoint Security", "Trellix", true, false),
    };

    public static readonly IReadOnlySet<string> KnownIds =
        new HashSet<string>(All.Select(p => p.Id), StringComparer.Ordinal);

    public static AvProduct? Find(string? id) =>
        id is null ? null : All.FirstOrDefault(p => string.Equals(p.Id, id, StringComparison.OrdinalIgnoreCase));
}

/// <summary>One AV status reading from the OS security-centre seam.
/// StatusObservedUtc is when the SOURCE observed the state (not
/// when ACP read the cache); SourceAlive says the security-centre
/// source itself responded. Both exist so a product (or a stale
/// cache of it) claiming health through a dead/old source reads
/// STALE, not healthy — claimed state is never taken at face value
/// past the freshness bound.</summary>
public sealed record AvStatusReading(
    string ProductId,
    bool Installed,
    bool Enabled,
    bool RealTimeProtection,
    DateTimeOffset? DefinitionsUpdatedUtc,
    DateTimeOffset? LastScanUtc,
    DateTimeOffset StatusObservedUtc,
    bool SourceAlive,
    string? ClaimedState);

/// <summary>The AV status seam: the OS security-centre interfaces
/// (Windows SecurityCenter2 / the state report's security readers)
/// are host wiring behind this interface. Tests drive the fake.</summary>
public interface IAvStatusSource
{
    IReadOnlyList<AvStatusReading> Read(DateTimeOffset now);
}

public static class AvPostureStates
{
    public const string Protected = "protected";
    public const string Missing = "missing";
    public const string Disabled = "disabled";
    public const string Stale = "stale";
    public const string Unknown = "unknown";
}

/// <summary>One posture finding for one product (or for the org's
/// required product when absent). ConditionKind/ConditionId are the
/// RMM-01 feed: missing/disabled/stale all ride the never-
/// suppressible security_av_off kind under condition ids that are
/// distinct PER PRODUCT AND STATE (D38-F9: state-only ids collapsed
/// two products in the same state into one alert and lost the
/// second product's detail to dedup), so a maintenance window can
/// never mute an unprotected machine.</summary>
public sealed record AvFinding(
    string ProductId,
    string State,
    string Detail,
    string ConditionId,
    string ConditionKind);

public sealed record AvPostureReport(
    string DeviceId,
    DateTimeOffset EvaluatedUtc,
    IReadOnlyList<AvFinding> Findings,
    bool AnyProtected,
    string? RequiredProductId = null)
{
    /// <summary>A GAP means the endpoint lacks the protection it is
    /// supposed to have: nothing protected at all, or the org's
    /// REQUIRED product not protected (D38-F9). An unrelated
    /// unregistered tool reading "unknown" beside a healthy required
    /// product is a finding, not a gap — it must not pin HasGap (and
    /// downstream health scoring) forever.</summary>
    public bool HasGap => !AnyProtected
        || (RequiredProductId is not null
            && !Findings.Any(f => f.ProductId == RequiredProductId
                                  && f.State == AvPostureStates.Protected));
}

/// <summary>Pure posture evaluation. Order matters and is the
/// anti-lying discipline: (1) a dead or stale status SOURCE makes
/// every claimed state stale before any claim is read; (2) the
/// org's required product absent is missing; (3) installed-but-off
/// is disabled; (4) definitions past the age bound are stale;
/// (5) only then is a product protected.</summary>
public static class AvPostureEvaluator
{
    /// <summary>Tolerated clock skew for FUTURE timestamps (D38-F8):
    /// a reading stamped further than this ahead of now is
    /// future-dated and untrusted — without the bound, a negative
    /// age passed the freshness check forever and a stuck/lying
    /// cache stamped ahead of time read "protected" indefinitely.</summary>
    public const int MaxFutureSkewMinutes = 5;

    public static AvPostureReport Evaluate(
        string deviceId, IReadOnlyList<AvStatusReading> readings,
        EndpointSecurityPolicy policy, DateTimeOffset now)
    {
        var findings = new List<AvFinding>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        AvFinding F(string product, string state, string detail) => new(
            product, state, detail,
            $"rmm17-av-{product}-{state}", ConditionKinds.SecurityAvOff);

        foreach (var r in readings ?? Array.Empty<AvStatusReading>())
        {
            var id = (r.ProductId ?? "").Trim().ToLowerInvariant();
            seen.Add(id);
            var product = AvProducts.Find(id);
            if (product is null)
            {
                findings.Add(F(id.Length == 0 ? "(blank)" : id, AvPostureStates.Unknown,
                    $"status reading names unregistered product '{r.ProductId}' — not trusted as protection (registry membership is a management mapping, and unknown tools are flagged, not assumed)"));
                continue;
            }
            // (1) Source freshness BEFORE any claimed state is read.
            // Both directions (D38-F8): too old is stale, and too far
            // in the FUTURE is stale — a future stamp is a lying or
            // stuck clock, never freshness.
            var age = now - r.StatusObservedUtc;
            if (!r.SourceAlive || age > TimeSpan.FromMinutes(policy.StatusMaxAgeMinutes)
                || age < TimeSpan.FromMinutes(-MaxFutureSkewMinutes))
            {
                findings.Add(F(id, AvPostureStates.Stale,
                    !r.SourceAlive
                        ? $"{product.DisplayName} status source is not responding — claimed state '{r.ClaimedState ?? "?"}' is NOT trusted; protection reads STALE, not healthy"
                        : age < TimeSpan.FromMinutes(-MaxFutureSkewMinutes)
                            ? $"{product.DisplayName} status is stamped {-age.TotalMinutes:F0} min in the FUTURE (skew bound {MaxFutureSkewMinutes}) — a future-dated source is NOT trusted; protection reads STALE, not healthy"
                            : $"{product.DisplayName} status was observed {age.TotalMinutes:F0} min ago (bound {policy.StatusMaxAgeMinutes}) — claimed state '{r.ClaimedState ?? "?"}' is too old to trust; protection reads STALE, not healthy"));
                continue;
            }
            if (!r.Installed)
            {
                findings.Add(F(id, AvPostureStates.Missing,
                    $"{product.DisplayName} reports not installed"));
                continue;
            }
            // (3) Disabled.
            if (!r.Enabled || !r.RealTimeProtection)
            {
                findings.Add(F(id, AvPostureStates.Disabled,
                    $"{product.DisplayName} installed but {(r.Enabled ? "real-time protection OFF" : "DISABLED")}"));
                continue;
            }
            // (4) Definitions staleness — both directions (D38-F8):
            // past the age bound is stale, and future-dated past the
            // skew bound is stale (it would otherwise never age).
            var defsUtc = r.DefinitionsUpdatedUtc;
            var defsAge = defsUtc is null ? (TimeSpan?)null : now - defsUtc.Value;
            if (defsUtc is null
                || defsAge > TimeSpan.FromDays(policy.DefinitionsMaxAgeDays)
                || defsAge < TimeSpan.FromMinutes(-MaxFutureSkewMinutes))
            {
                findings.Add(F(id, AvPostureStates.Stale,
                    defsUtc is null
                        ? $"{product.DisplayName} enabled but its definitions age was never reported — reads STALE"
                        : defsAge < TimeSpan.FromMinutes(-MaxFutureSkewMinutes)
                            ? $"{product.DisplayName} definitions are stamped {-defsAge!.Value.TotalDays:F1} days in the FUTURE (skew bound {MaxFutureSkewMinutes} min) — reads STALE, never fresh-forever"
                            : $"{product.DisplayName} definitions are {defsAge!.Value.TotalDays:F1} days old (bound {policy.DefinitionsMaxAgeDays}) — reads STALE"));
                continue;
            }
            findings.Add(F(id, AvPostureStates.Protected,
                $"{product.DisplayName} enabled, real-time on, definitions {(now - defsUtc.Value).TotalHours:F0}h old"));
        }

        // (2) The org's chosen product must be present.
        if (policy.RequiredAvProductId is { } req && !seen.Contains(req))
        {
            findings.Add(F(req, AvPostureStates.Missing,
                $"the org-required AV/EDR '{req}' has NO status reading on this endpoint — protection is MISSING, not assumed"));
        }
        if (findings.Count == 0)
        {
            findings.Add(F(policy.RequiredAvProductId ?? "(none)", AvPostureStates.Missing,
                "no AV/EDR status readings at all on this endpoint — protection is MISSING, not assumed"));
        }

        return new AvPostureReport(deviceId, now, findings,
            findings.Any(f => f.State == AvPostureStates.Protected),
            policy.RequiredAvProductId);
    }
}

// ---- AV management intents ------------------------------------------------

public static class AvManagementActions
{
    public const string Deploy = "deploy";
    public const string Configure = "configure";
    public const string UpdateDefinitions = "update_definitions";
    public const string RunScan = "run_scan";
    public static readonly IReadOnlySet<string> All =
        new HashSet<string> { Deploy, Configure, UpdateDefinitions, RunScan };

    /// <summary>The RMM-03 class an action's command must travel
    /// as: installs are package deployments; the rest are
    /// automations. A command arriving under the wrong class
    /// refuses at the gate before this mapping is consulted.</summary>
    public static string CommandClassFor(string action) =>
        action == Deploy ? SignedCommandClasses.PackageDeploy : SignedCommandClasses.Automation;
}

/// <summary>A management intent against the org's chosen AV/EDR:
/// the signed-command payload ACP issues so the endpoint deploys /
/// configures / updates / scans with its EXISTING tool. Building
/// the intent validates product + action support; executing it on
/// the host (the vendor installer's actual run) is host wiring —
/// the intent, its signature binding and its audit are ACP's.</summary>
public sealed record AvManagementIntent(
    string ProductId, string Action, string DeviceId, string PayloadJson, string CommandClass)
{
    public static (AvManagementIntent? Intent, string? Refusal) Build(
        string productId, string action, string deviceId, IReadOnlyDictionary<string, string>? settings = null)
    {
        var product = AvProducts.Find(productId);
        if (product is null)
            return (null, $"AV product '{productId}' is not in the management registry — refused (ACP manages registered tools only)");
        var a = (action ?? "").Trim().ToLowerInvariant();
        if (!AvManagementActions.All.Contains(a))
            return (null, $"unknown AV management action '{action}' — refused");
        if (a == AvManagementActions.Deploy && !product.SupportsDeploy)
            return (null, $"{product.DisplayName} does not support ACP-driven deployment — refused");
        if (a == AvManagementActions.Configure && !product.SupportsConfigure)
            return (null, $"{product.DisplayName} does not support ACP-driven configuration — refused");
        if (string.IsNullOrWhiteSpace(deviceId))
            return (null, "AV management intent needs a target device — refused");
        var payload = JsonSerializer.Serialize(new
        {
            action = $"rmm17.av.{a}",
            productId = product.Id,
            deviceId,
            settings = settings ?? new Dictionary<string, string>(),
        });
        return (new AvManagementIntent(product.Id, a, deviceId, payload,
            AvManagementActions.CommandClassFor(a)), null);
    }
}

// ---- combined report --------------------------------------------------------

public static class Rmm17AlertKinds
{
    /// <summary>The isolation alert kind. RES-3 CLOSED (closing
    /// integration, 2026-11-21): RMM-01's NeverSuppressible set now
    /// INCLUDES this kind, so a maintenance window can suppress
    /// neither the alert nor (as ever) the isolation itself, the
    /// chained audit, or the user banner. The service additionally
    /// re-raises on every cycle while isolated or isolation_failed
    /// (D38-F2), so no alert can be lost to window timing.
    /// (D38-F6: earlier comments here and in the service claimed
    /// the kind was still suppressible — stale after RES-3;
    /// corrected.)</summary>
    public const string RansomwareIsolation = "ransomware_isolation";
    public const string IsolationConditionId = "rmm17-ransomware-isolation";
}

/// <summary>The endpoint→hub RMM-17 report: facts only (isolation
/// state, detector's last verdict, AV findings) in the same spirit
/// as RMM-01's DeviceHealthReport — evaluation already happened on
/// the endpoint.</summary>
public sealed record EndpointSecurityReport(
    string DeviceId,
    DateTimeOffset GeneratedUtc,
    bool FeatureEnabled,
    IsolationStatus Isolation,
    DetectionVerdict? LastVerdict,
    AvPostureReport? AvPosture);
