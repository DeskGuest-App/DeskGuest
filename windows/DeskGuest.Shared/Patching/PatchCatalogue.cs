using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace DeskGuest.Shared.Patching;

// =====================================================================
// RMM-02 — Patch management (catalogue half).
//
// The hub determines missing patches per endpoint from (a) RMM-04
// inventory — what's installed — and (b) THIS catalogue. The
// catalogue is USER-CURATED ON THE HUB: entries are admin-supplied
// local content. There is NO vendor cloud catalogue anywhere in
// this design (Block R class-(c) exclusion): the hub never silently
// trusts a third party's selection of what code the fleet runs. The
// one import shape is a WinGet-shaped manifest the ADMIN provides
// as a local file — a free source shape, mirrored, never fetched.
//
// Supply-chain discipline:
//   * every entry pins its payload by SHA-256; a payload whose hash
//     does not match its entry is refused BEFORE distribution
//     (PatchDeploymentPlanner / PatchService check it; the RMM-14
//     ContentManifest must name the same hash);
//   * every entry carries a content hash over its own fields. An
//     approval binds (entry id, content hash): swapping or editing
//     an entry after approval changes the hash and the approval
//     stops matching — approval can never be laundered onto
//     different content;
//   * CVE references are validated in shape (CVE-YYYY-NNNN+) and
//     CVSS is bounded 0.0–10.0. The correlation ENGINE that scores
//     fleet exposure is RMM-05's; RMM-02 carries the references.
// =====================================================================

public static class PatchKinds
{
    public const string Os = "os";
    public const string ThirdParty = "third_party";
    public static readonly IReadOnlySet<string> All = new HashSet<string> { Os, ThirdParty };
}

public static class PatchClassifications
{
    public const string Security = "security";
    public const string Critical = "critical";
    public const string Important = "important";
    public const string Moderate = "moderate";
    public const string Low = "low";
    public const string Update = "update";
    public static readonly IReadOnlySet<string> All =
        new HashSet<string> { Security, Critical, Important, Moderate, Low, Update };
}

public static class PatchSeverities
{
    public const string Critical = "critical";
    public const string High = "high";
    public const string Medium = "medium";
    public const string Low = "low";
    public const string None = "none";
    public static readonly IReadOnlySet<string> All =
        new HashSet<string> { Critical, High, Medium, Low, None };

    /// <summary>Rank for threshold/SLA comparisons (higher = worse).</summary>
    public static int Rank(string? severity) => (severity ?? "").Trim().ToLowerInvariant() switch
    {
        Critical => 4, High => 3, Medium => 2, Low => 1, _ => 0,
    };
}

public static class PatchOsKinds
{
    public const string Windows = "windows";
    public const string MacOs = "macos";
    public const string Linux = "linux";
    public static readonly IReadOnlySet<string> All = new HashSet<string> { Windows, MacOs, Linux };

    /// <summary>Map an inventory OsName ("Windows 11 Pro",
    /// "macOS 14.2", "Ubuntu Linux 24.04") to a patch OS kind.
    /// Unknown maps to null — an entry never applies to an OS the
    /// matcher cannot name (fail closed).</summary>
    public static string? OfOsName(string? osName)
    {
        var n = (osName ?? "").ToLowerInvariant();
        if (n.Contains("windows")) return Windows;
        if (n.Contains("macos") || n.Contains("mac os") || n.Contains("darwin")) return MacOs;
        if (n.Contains("linux") || n.Contains("ubuntu") || n.Contains("debian") || n.Contains("fedora")) return Linux;
        return null;
    }
}

/// <summary>One curated catalogue entry. For a third-party patch,
/// ProductName is the inventory software name and FixedInVersion is
/// the first version that contains the fix (installed &lt; fixed ⇒
/// missing). For an OS patch, KbId names the update and
/// FixedInOsBuild is the first OS build that contains it (device
/// build &lt; fixed ⇒ missing); an OS entry may ALSO name a
/// ProductName (an OS component) — then the software rule applies.
/// PayloadHash pins the distributable payload (null only for OS
/// patches the OS's own channel delivers, where there is no DeskGuest
/// payload to pin — the applier shape names that channel).</summary>
public sealed record PatchCatalogueEntry(
    string Id,
    string Title,
    string Kind,
    string TargetOs,
    string? ProductName,
    string? FixedInVersion,
    string? KbId,
    string? FixedInOsBuild,
    string Classification,
    string Severity,
    double? CvssScore,
    IReadOnlyList<string> CveIds,
    string? PayloadHash,
    string? PayloadLabel,
    bool RequiresReboot,
    long Revision)
{
    public IReadOnlyList<string> CveIds { get; init; } = CveIds ?? Array.Empty<string>();

    /// <summary>SHA-256 over the entry's canonical content. This is
    /// what approvals bind to: ANY field change — a swapped payload
    /// hash, a re-mapped CVE, a severity edit — produces a different
    /// content hash and invalidates approvals recorded against the
    /// old one.</summary>
    public string ContentHash => PatchCatalogue.ComputeContentHash(this);
}

public static class PatchCatalogueValidation
{
    private static readonly Regex CvePattern = new(@"^CVE-\d{4}-\d{4,}$", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex Sha256Pattern = new(@"^[0-9a-f]{64}$", RegexOptions.Compiled);

    public static bool IsValidCve(string? cve) => cve is not null && CvePattern.IsMatch(cve.Trim());
    public static bool IsSha256Hex(string? hash) =>
        hash is not null && Sha256Pattern.IsMatch(hash.Trim().ToLowerInvariant());

    /// <summary>Null when the entry is admissible; otherwise the
    /// refusal reason. Admission is structural: identity, closed-set
    /// kinds/classifications/severities, CVE shape, CVSS bounds,
    /// payload-hash shape, and a fix reference the scanner can
    /// actually evaluate (a patch that can never be determined
    /// missing-or-present is not catalogue content, it's noise).</summary>
    public static string? Check(PatchCatalogueEntry? e)
    {
        if (e is null) return "no catalogue entry — refused";
        if (string.IsNullOrWhiteSpace(e.Id)) return "catalogue entry carries no id — refused";
        if (string.IsNullOrWhiteSpace(e.Title)) return $"catalogue entry '{e.Id}' carries no title — refused";
        if (!PatchKinds.All.Contains((e.Kind ?? "").Trim().ToLowerInvariant()))
            return $"catalogue entry '{e.Id}' has unknown kind '{e.Kind}' — refused";
        if (!PatchOsKinds.All.Contains((e.TargetOs ?? "").Trim().ToLowerInvariant()))
            return $"catalogue entry '{e.Id}' targets unknown OS '{e.TargetOs}' — refused";
        if (!PatchClassifications.All.Contains((e.Classification ?? "").Trim().ToLowerInvariant()))
            return $"catalogue entry '{e.Id}' has unknown classification '{e.Classification}' — refused";
        if (!PatchSeverities.All.Contains((e.Severity ?? "").Trim().ToLowerInvariant()))
            return $"catalogue entry '{e.Id}' has unknown severity '{e.Severity}' — refused";
        if (e.CvssScore is { } cvss && (cvss < 0.0 || cvss > 10.0))
            return $"catalogue entry '{e.Id}' has CVSS {cvss} outside 0.0–10.0 — refused";
        foreach (var cve in e.CveIds)
            if (!IsValidCve(cve))
                return $"catalogue entry '{e.Id}' carries malformed CVE reference '{cve}' — refused (CVE references are CVE-YYYY-NNNN+)";
        if (e.PayloadHash is not null && !IsSha256Hex(e.PayloadHash))
            return $"catalogue entry '{e.Id}' payload hash is not a SHA-256 hex digest — refused (payload pinning is not optional decoration)";
        var kind = e.Kind.Trim().ToLowerInvariant();
        if (kind == PatchKinds.ThirdParty)
        {
            if (string.IsNullOrWhiteSpace(e.ProductName))
                return $"third-party entry '{e.Id}' names no product — refused (it could never be matched against inventory)";
            if (string.IsNullOrWhiteSpace(e.FixedInVersion))
                return $"third-party entry '{e.Id}' names no fixed-in version — refused (missing-ness would be undecidable)";
            if (e.PayloadHash is null)
                return $"third-party entry '{e.Id}' pins no payload hash — refused (DeskGuest distributes third-party payloads, so the pin is the supply-chain control)";
        }
        else // os
        {
            if (string.IsNullOrWhiteSpace(e.KbId) && string.IsNullOrWhiteSpace(e.ProductName))
                return $"OS entry '{e.Id}' names neither a KB id nor a component product — refused";
            if (string.IsNullOrWhiteSpace(e.FixedInOsBuild) && string.IsNullOrWhiteSpace(e.FixedInVersion))
                return $"OS entry '{e.Id}' names no fixed-in build or version — refused (missing-ness would be undecidable)";
        }
        return null;
    }
}

/// <summary>The hub's curated patch catalogue. Thread-safe.
/// Revision discipline mirrors the policy engine: an entry id's
/// revision is monotonic — a stale re-delivery refuses, and a
/// same-revision delivery whose content differs refuses (two
/// entries cannot share id+revision and disagree). Replacing an
/// entry therefore always takes a NEW revision, which changes the
/// content hash, which is what approvals bind to.</summary>
public sealed class PatchCatalogue
{
    private readonly Dictionary<string, PatchCatalogueEntry> _entries = new(StringComparer.OrdinalIgnoreCase);
    // D38 F10(a): retirement tombstones — the highest revision ever
    // admitted per id. Retiring an entry removes it from service
    // but NEVER erases its revision floor: re-admitting a retired
    // id at or below the floor refuses, so "remove the entry,
    // re-admit the old approved revision, and the old approval
    // matches again" rollback laundering has no path.
    private readonly Dictionary<string, long> _retiredFloor = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();

    public static string ComputeContentHash(PatchCatalogueEntry e)
    {
        // D38 F10(b): the v1 canonical string joined fields with '|'
        // unescaped and rendered CVSS at F1 — field-boundary
        // collisions (ProductName 'X|1' + FixedInVersion '' hashing
        // as ProductName 'X' + FixedInVersion '1|') and CVSS values
        // that straddle the critical ≥9.0 cutoff (8.96 vs 9.04 both
        // rendering "9.0") could share one content hash, and with
        // it one approval. The v2 form length-prefixes EVERY field
        // (boundaries are unambiguous by construction) and renders
        // CVSS at full round-trip precision, so two entries hash
        // alike only when every field is actually alike.
        var sb = new StringBuilder("deskguest-patch-entry-v2");
        void Field(string? v)
        {
            var s = v ?? "";
            sb.Append('|').Append(s.Length).Append(':').Append(s);
        }
        Field(e.Id); Field(e.Title); Field(e.Kind); Field(e.TargetOs);
        Field(e.ProductName); Field(e.FixedInVersion); Field(e.KbId); Field(e.FixedInOsBuild);
        Field(e.Classification); Field(e.Severity);
        Field(e.CvssScore?.ToString("R", System.Globalization.CultureInfo.InvariantCulture));
        Field(string.Join(",", e.CveIds.Select(c => c.Trim().ToUpperInvariant()).OrderBy(c => c, StringComparer.Ordinal)));
        Field((e.PayloadHash ?? "").Trim().ToLowerInvariant()); Field(e.PayloadLabel);
        Field(e.RequiresReboot.ToString());
        Field(e.Revision.ToString(System.Globalization.CultureInfo.InvariantCulture));
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(sb.ToString()))).ToLowerInvariant();
    }

    public (bool Accepted, string Reason) AddOrReplace(PatchCatalogueEntry entry)
    {
        if (PatchCatalogueValidation.Check(entry) is { } refusal)
            return (false, refusal);
        var normalized = entry with
        {
            Kind = entry.Kind.Trim().ToLowerInvariant(),
            TargetOs = entry.TargetOs.Trim().ToLowerInvariant(),
            Classification = entry.Classification.Trim().ToLowerInvariant(),
            Severity = entry.Severity.Trim().ToLowerInvariant(),
            PayloadHash = entry.PayloadHash?.Trim().ToLowerInvariant(),
            CveIds = entry.CveIds.Select(c => c.Trim().ToUpperInvariant()).ToList(),
        };
        lock (_gate)
        {
            if (!_entries.ContainsKey(normalized.Id) &&
                _retiredFloor.TryGetValue(normalized.Id, out var floor) && normalized.Revision <= floor)
                return (false, $"catalogue entry '{normalized.Id}' revision {normalized.Revision} is at or below the RETIRED revision floor {floor} for this id — refused (a retired entry's old revisions never come back; re-admission takes a higher revision and fresh approval)");
            if (_entries.TryGetValue(normalized.Id, out var existing))
            {
                if (normalized.Revision < existing.Revision)
                    return (false, $"catalogue entry '{normalized.Id}' revision {normalized.Revision} is stale (current {existing.Revision}) — refused");
                if (normalized.Revision == existing.Revision && normalized.ContentHash != existing.ContentHash)
                    return (false, $"catalogue entry '{normalized.Id}' revision {normalized.Revision} conflicts with the admitted entry of the same id+revision — refused (a same-revision swap is exactly the post-approval poisoning this discipline exists to stop)");
                if (normalized.Revision == existing.Revision)
                    return (true, $"catalogue entry '{normalized.Id}' r{normalized.Revision} already admitted (idempotent)");
            }
            _entries[normalized.Id] = normalized;
            return (true, $"catalogue entry '{normalized.Id}' r{normalized.Revision} admitted (content {normalized.ContentHash[..12]}…)");
        }
    }

    public PatchCatalogueEntry? Get(string? id)
    {
        lock (_gate) return id is not null && _entries.TryGetValue(id, out var e) ? e : null;
    }

    public IReadOnlyList<PatchCatalogueEntry> All
    {
        get { lock (_gate) return _entries.Values.OrderBy(e => e.Id, StringComparer.Ordinal).ToList(); }
    }

    /// <summary>Retire an entry: it leaves service (Get returns
    /// null, scans stop matching it) but its revision floor is
    /// tombstoned forever in this catalogue — see the floor check
    /// in AddOrReplace. There is deliberately no plain Remove:
    /// D38 F10(a) showed remove + re-admit resurrecting a
    /// superseded, previously-approved revision.</summary>
    public bool Retire(string id)
    {
        lock (_gate)
        {
            if (!_entries.Remove(id, out var e)) return false;
            _retiredFloor[id] = Math.Max(_retiredFloor.GetValueOrDefault(id), e.Revision);
            return true;
        }
    }

    /// <summary>The retirement tombstones (id → highest admitted
    /// revision at retirement). Exposed so the Core service can
    /// persist them beside the entries — a tombstone that dies
    /// with the process is no tombstone.</summary>
    public IReadOnlyDictionary<string, long> RetiredFloors
    {
        get { lock (_gate) return new Dictionary<string, long>(_retiredFloor, StringComparer.OrdinalIgnoreCase); }
    }

    /// <summary>Restore a persisted tombstone (service state load).
    /// Only ever RAISES a floor.</summary>
    public void RestoreRetiredFloor(string id, long revision)
    {
        lock (_gate)
            _retiredFloor[id] = Math.Max(_retiredFloor.GetValueOrDefault(id), revision);
    }
}

/// <summary>WinGet-shaped manifest import. The admin provides the
/// manifest as a LOCAL file's content (JSON form of the winget
/// manifest shape: PackageIdentifier / Version / InstallerSha256 /
/// …). Import NEVER fetches anything and never trusts the
/// manifest's own claims about severity or CVEs beyond carrying
/// admin-supplied fields through validation — every imported entry
/// passes the same admission checks as a hand-authored one, and the
/// admin's classification/severity/CVE curation rides in the
/// manifest's optional `deskguest` block (absent ⇒ conservative defaults:
/// classification "update", severity "medium", manual approval by
/// the default rule). A malformed manifest imports NOTHING (atomic:
/// parse and validate all, then admit all).</summary>
public static class WinGetManifestImport
{
    public sealed record Result(bool Ok, string Reason, IReadOnlyList<PatchCatalogueEntry> Entries);

    public static Result Parse(string? json, long revision)
    {
        if (string.IsNullOrWhiteSpace(json))
            return new Result(false, "manifest is empty — refused (nothing imports from nothing)", Array.Empty<PatchCatalogueEntry>());
        JsonDocument doc;
        try { doc = JsonDocument.Parse(json); }
        catch { return new Result(false, "manifest is not valid JSON — refused, nothing imported", Array.Empty<PatchCatalogueEntry>()); }
        using (doc)
        {
            var root = doc.RootElement;
            var items = new List<JsonElement>();
            if (root.ValueKind == JsonValueKind.Array) items.AddRange(root.EnumerateArray());
            else if (root.ValueKind == JsonValueKind.Object && root.TryGetProperty("packages", out var pkgs) && pkgs.ValueKind == JsonValueKind.Array)
                items.AddRange(pkgs.EnumerateArray());
            else if (root.ValueKind == JsonValueKind.Object) items.Add(root.Clone());
            else return new Result(false, "manifest root is neither an object nor an array — refused", Array.Empty<PatchCatalogueEntry>());

            var entries = new List<PatchCatalogueEntry>();
            foreach (var item in items)
            {
                var entry = MapOne(item, revision);
                if (entry is null)
                    return new Result(false, "a manifest package is missing PackageIdentifier, Version or InstallerSha256 — refused, nothing imported (atomic import)", Array.Empty<PatchCatalogueEntry>());
                if (PatchCatalogueValidation.Check(entry) is { } refusal)
                    return new Result(false, refusal + " — refused, nothing imported (atomic import)", Array.Empty<PatchCatalogueEntry>());
                entries.Add(entry);
            }
            if (entries.Count == 0)
                return new Result(false, "manifest carried no packages — refused", Array.Empty<PatchCatalogueEntry>());
            if (entries.Select(e => e.Id).Distinct(StringComparer.OrdinalIgnoreCase).Count() != entries.Count)
                return new Result(false, "manifest carries a duplicate package identifier — refused, nothing imported", Array.Empty<PatchCatalogueEntry>());
            return new Result(true, $"manifest parsed: {entries.Count} entr{(entries.Count == 1 ? "y" : "ies")} (validation passed; admission is the catalogue's act)", entries);
        }
    }

    private static PatchCatalogueEntry? MapOne(JsonElement item, long revision)
    {
        string? S(string name) =>
            item.ValueKind == JsonValueKind.Object && item.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String
                ? v.GetString() : null;
        var id = S("PackageIdentifier");
        var version = S("Version");
        var sha = S("InstallerSha256");
        if (string.IsNullOrWhiteSpace(id) || string.IsNullOrWhiteSpace(version) || string.IsNullOrWhiteSpace(sha))
            return null;
        string classification = "update", severity = "medium", os = "windows";
        string? kb = null; var cves = new List<string>(); double? cvss = null; var reboot = false;
        if (item.TryGetProperty("deskguest", out var deskguest) && deskguest.ValueKind == JsonValueKind.Object)
        {
            if (deskguest.TryGetProperty("classification", out var c) && c.ValueKind == JsonValueKind.String) classification = c.GetString() ?? classification;
            if (deskguest.TryGetProperty("severity", out var s) && s.ValueKind == JsonValueKind.String) severity = s.GetString() ?? severity;
            if (deskguest.TryGetProperty("targetOs", out var o) && o.ValueKind == JsonValueKind.String) os = o.GetString() ?? os;
            if (deskguest.TryGetProperty("kbId", out var k) && k.ValueKind == JsonValueKind.String) kb = k.GetString();
            if (deskguest.TryGetProperty("cvss", out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetDouble(out var d)) cvss = d;
            if (deskguest.TryGetProperty("requiresReboot", out var r) && r.ValueKind is JsonValueKind.True or JsonValueKind.False) reboot = r.GetBoolean();
            if (deskguest.TryGetProperty("cveIds", out var arr) && arr.ValueKind == JsonValueKind.Array)
                cves.AddRange(arr.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString()!));
        }
        return new PatchCatalogueEntry(
            Id: id!, Title: S("PackageName") ?? id!, Kind: PatchKinds.ThirdParty,
            TargetOs: os, ProductName: S("PackageName") ?? id, FixedInVersion: version,
            KbId: kb, FixedInOsBuild: null, Classification: classification, Severity: severity,
            CvssScore: cvss, CveIds: cves, PayloadHash: sha, PayloadLabel: id,
            RequiresReboot: reboot, Revision: revision);
    }
}
