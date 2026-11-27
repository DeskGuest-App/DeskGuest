using DeskGuest.Shared.Inventory;

namespace DeskGuest.Shared.Patching;

// =====================================================================
// RMM-02 — Missing-patch determination + fleet targeting.
//
// Missing = the catalogue says a fix exists AND inventory (RMM-04)
// says this device does not have it yet:
//   * third-party: the product is installed and its version
//     compares BELOW the entry's fixed-in version
//     (SoftwareVersion.Compare — version semantics, never raw
//     string order, so "9.0" is correctly older than "10.0");
//   * OS by build: the device's OS kind matches the entry's target
//     and its OS build compares below the fixed-in build;
//   * OS by component: an OS entry naming a product uses the
//     software rule (the component's version decides).
// A device whose OS kind cannot be determined, or whose relevant
// version is absent, is NOT declared missing — undecidable is
// reported as undecidable in scan tooling, never guessed into
// either state here (this engine simply does not list it).
// =====================================================================

/// <summary>One device's one missing patch, with the evidence:
/// what is installed and what would fix it.</summary>
public sealed record MissingPatch(
    string DeviceId,
    string EntryId,
    string EntryContentHash,
    string Title,
    string Kind,
    string? KbId,
    string Classification,
    string Severity,
    double? CvssScore,
    IReadOnlyList<string> CveIds,
    string InstalledVersion,
    string FixedInVersion,
    bool RequiresReboot);

public static class PatchScanner
{
    public static IReadOnlyList<MissingPatch> DetermineMissing(DeviceInventoryRecord record, PatchCatalogue catalogue)
    {
        ArgumentNullException.ThrowIfNull(record);
        ArgumentNullException.ThrowIfNull(catalogue);
        var missing = new List<MissingPatch>();
        var deviceOs = PatchOsKinds.OfOsName(record.Hardware?.OsName);
        foreach (var entry in catalogue.All)
        {
            if (!string.Equals(entry.TargetOs, deviceOs, StringComparison.OrdinalIgnoreCase)) continue;
            if (entry.ProductName is not null)
            {
                // BD-SHARED-RMM-2/F7: targeting semantics must never
                // drift from fleet-query semantics (the header's own
                // claim). The product name is NORMALIZED exactly as
                // InventoryQueryEngine normalizes its query, and EVERY
                // matching install is evaluated — side-by-side installs
                // (a patched 64-bit copy beside a vulnerable 32-bit
                // one) report the LOWEST installed version, never the
                // first match's.
                var wanted = InventoryValidation.NormalizeSoftwareName(entry.ProductName);
                var matches = record.Software
                    .Where(s => string.Equals(s.NormalizedName, wanted, StringComparison.OrdinalIgnoreCase))
                    .ToList();
                if (matches.Count == 0) continue; // not installed ⇒ this patch is not this device's gap
                var fixedIn = entry.Kind == PatchKinds.Os && entry.FixedInVersion is null
                    ? entry.FixedInOsBuild : entry.FixedInVersion;
                if (fixedIn is null) continue;
                var lowest = matches.OrderBy(s => s.Version, Comparer<string>.Create(
                    (a, b) => SoftwareVersion.Compare(a, b))).First();
                if (SoftwareVersion.Compare(lowest.Version, fixedIn) < 0)
                    missing.Add(ToMissing(record.DeviceId, entry, lowest.Version, fixedIn));
            }
            else if (entry.FixedInOsBuild is not null)
            {
                var build = record.Hardware?.OsBuild;
                if (string.IsNullOrWhiteSpace(build)) continue; // undecidable, not missing
                if (SoftwareVersion.Compare(build, entry.FixedInOsBuild) < 0)
                    missing.Add(ToMissing(record.DeviceId, entry, build, entry.FixedInOsBuild));
            }
        }
        return missing.OrderByDescending(m => PatchSeverities.Rank(m.Severity))
            .ThenBy(m => m.EntryId, StringComparer.Ordinal).ToList();
    }

    private static MissingPatch ToMissing(string deviceId, PatchCatalogueEntry e, string installed, string fixedIn) =>
        new(deviceId, e.Id, e.ContentHash, e.Title, e.Kind, e.KbId, e.Classification, e.Severity,
            e.CvssScore, e.CveIds, installed, fixedIn, e.RequiresReboot);
}

/// <summary>Fleet targeting over the hub inventory store: "every
/// device that needs this patch." Third-party targeting rides the
/// RMM-04 InventoryQueryEngine (software name + version-below), so
/// targeting semantics can never drift from fleet-query semantics;
/// OS-build targeting filters the store directly on OS kind +
/// build comparison (the query engine has no build-range operator
/// and this lane does not invent one).</summary>
public static class PatchTargeting
{
    public static IReadOnlyList<string> FindTargets(InventoryStore store, PatchCatalogueEntry entry, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(entry);
        if (entry.ProductName is not null && entry.FixedInVersion is not null)
        {
            var result = InventoryQueryEngine.Query(store, new InventoryQuery(
                SoftwareName: entry.ProductName,
                VersionOp: VersionComparison.LessThan,
                Version: entry.FixedInVersion), now);
            if (!result.Accepted) return Array.Empty<string>();
            return result.Matches
                .Where(r => string.Equals(PatchOsKinds.OfOsName(r.Hardware?.OsName), entry.TargetOs, StringComparison.OrdinalIgnoreCase))
                .Select(r => r.DeviceId).OrderBy(d => d, StringComparer.Ordinal).ToList();
        }
        return store.List()
            .Where(r => string.Equals(PatchOsKinds.OfOsName(r.Hardware?.OsName), entry.TargetOs, StringComparison.OrdinalIgnoreCase))
            .Where(r => entry.FixedInOsBuild is not null && !string.IsNullOrWhiteSpace(r.Hardware?.OsBuild)
                        && SoftwareVersion.Compare(r.Hardware.OsBuild, entry.FixedInOsBuild) < 0)
            .Select(r => r.DeviceId).OrderBy(d => d, StringComparer.Ordinal).ToList();
    }
}
