using System.Text.RegularExpressions;

namespace Acp.Shared.Inventory;

// =====================================================================
// RMM-04 — Continuous fleet inventory (ADOPTED 2026-11-20).
// The agent maintains a continuous inventory per device — hardware,
// installed software with versions, OS build — reported to the hub
// ON CHANGE (diff-based, never full dumps). This file is the model:
// snapshots, records, validation, version comparison, and the pure
// diff function. The hub store, query engine, warranty surface and
// unmanaged-asset register live in their own files beside this one.
//
// Fail-closed discipline (house pattern): hostile or malformed input
// is refused or dropped-and-counted, never silently widened, never
// fatal to the store. Every limit below is a named constant so a
// poisoned feed hits a wall with a name, not an unbounded list.
// =====================================================================

/// <summary>TOTAL POLICY CONTROL keys for RMM-04, registered as data.
/// A foundation lane (RMM-07) owns the policy engine; the coordinator
/// wires these keys into it at integration. Until then every RMM-04
/// surface consults an injectable policy-check delegate
/// (Func&lt;string,bool&gt;) that defaults to enabled, so tests can
/// flip any toggle without the engine existing yet.</summary>
public static class InventoryPolicyKeys
{
    public const string InventoryEnabled = "rmm.inventory.enabled";
    public const string WarrantyLookupEnabled = "rmm.inventory.warrantyLookup.enabled";
    public const string UnmanagedRegisterEnabled = "rmm.inventory.unmanagedRegister.enabled";

    public static readonly IReadOnlySet<string> All = new HashSet<string>
    {
        InventoryEnabled, WarrantyLookupEnabled, UnmanagedRegisterEnabled,
    };

    /// <summary>Every RMM-04 toggle defaults ON (the register's
    /// defaults). The consent floor is not a feature and has no key
    /// here — toggles govern features only.</summary>
    public static readonly IReadOnlyDictionary<string, bool> Defaults =
        new Dictionary<string, bool>
        {
            [InventoryEnabled] = true,
            [WarrantyLookupEnabled] = true,
            [UnmanagedRegisterEnabled] = true,
        };

    /// <summary>The default policy check (D38-F12): reads
    /// <see cref="Defaults"/> — a known key gets its registered
    /// default, an UNKNOWN key is refused (fail closed), never
    /// silently enabled.</summary>
    public static bool DefaultCheck(string key) =>
        key is not null && Defaults.TryGetValue(key, out var enabled) && enabled;
}

/// <summary>Named bounds for inventory data. A feed that exceeds one
/// is refused (whole snapshot) or trimmed-and-counted (single items),
/// per the rule stated on each constant — never silently accepted.</summary>
public static class InventoryLimits
{
    public const int MaxSoftwareItems = 5000;      // distinct apps per device; over → snapshot refused
    public const int MaxDisks = 64;
    public const int MaxPeripherals = 256;
    public const int MaxCustomFields = 64;
    public const int MaxCustomFieldValueLength = 1024;
    public const int MaxTags = 32;
    public const int MaxTagLength = 64;
    public const int MaxSoftwareNameLength = 256;
    public const int MaxSoftwareVersionLength = 64;
    public const int MinSerialLength = 4;
    public const int MaxSerialLength = 32;
    public const int MaxHostnameLength = 128;
    // D38-F6: hardware string bounds + fail-fast raw-count walls.
    public const int MaxHardwareStringLength = 256;
    public const int MaxDiskPeripheralStringLength = 256;
    public const int RawSoftwareFailFast = MaxSoftwareItems * 4; // raw list beyond this refuses before any processing
    public const int RawTagsFailFast = MaxTags * 32;
}

/// <summary>One physical/logical disk as the agent observed it.</summary>
public sealed record DiskInfo(
    string Name,
    string? Model,
    string? SerialNumber,
    long SizeBytes,
    string? InterfaceType,
    string? MediaType);

/// <summary>One attached peripheral (monitor, dock, printer, USB
/// device class…). Kind is a short slug ("monitor", "dock", …).</summary>
public sealed record PeripheralInfo(
    string Kind,
    string Name,
    string? Vendor,
    string? Model);

/// <summary>The hardware + OS half of a device's inventory at one
/// instant. SerialNumber is the machine serial the warranty lookup
/// keys on — normalized (trimmed, uppercased) at validation time.</summary>
public sealed record HardwareSnapshot(
    string Manufacturer,
    string Model,
    string? SerialNumber,
    string CpuModel,
    int CpuCores,
    long RamBytes,
    string OsName,
    string OsBuild,
    string OsVersion,
    string? BiosVersion,
    IReadOnlyList<DiskInfo> Disks,
    IReadOnlyList<PeripheralInfo> Peripherals,
    DateTimeOffset CollectedUtc);

/// <summary>One installed application. Name is matched across the
/// fleet by its normalized form (trimmed, case-insensitive); Version
/// is compared with <see cref="SoftwareVersion"/> semantics, never by
/// raw string order ("9.0" &lt; "10.0" as versions, not as text).</summary>
public sealed record SoftwareItem(
    string Name,
    string Version,
    string? Publisher,
    DateTimeOffset? InstallDateUtc,
    string? Source)
{
    /// <summary>The fleet-matching key for this application.</summary>
    public string NormalizedName => InventoryValidation.NormalizeSoftwareName(Name);
}

/// <summary>Version comparison for installed-software queries and
/// diffs. Dotted numeric segments compare numerically; a trailing
/// non-numeric suffix compares lexically AFTER the numeric prefix
/// ("1.2-beta" &lt; "1.2"); missing segments read as 0 ("1.2" ==
/// "1.2.0"). Unparseable versions fall back to ordinal string order
/// so comparison is always total and deterministic.</summary>
public static class SoftwareVersion
{
    public static int Compare(string? a, string? b)
    {
        a = (a ?? "").Trim();
        b = (b ?? "").Trim();
        if (a == b) return 0;
        var pa = Parse(a);
        var pb = Parse(b);
        if (pa is not null && pb is not null)
        {
            var n = Math.Max(pa.Value.Numbers.Count, pb.Value.Numbers.Count);
            for (var i = 0; i < n; i++)
            {
                var x = i < pa.Value.Numbers.Count ? pa.Value.Numbers[i] : 0;
                var y = i < pb.Value.Numbers.Count ? pb.Value.Numbers[i] : 0;
                if (x != y) return x.CompareTo(y);
            }
            // Suffix rule: a bare release outranks any suffixed
            // pre-release ("1.2" > "1.2-beta"); two suffixes compare
            // lexically.
            var sa = pa.Value.Suffix;
            var sb = pb.Value.Suffix;
            if (sa.Length == 0 && sb.Length == 0) return 0;
            if (sa.Length == 0) return 1;
            if (sb.Length == 0) return -1;
            return string.Compare(sa, sb, StringComparison.OrdinalIgnoreCase);
        }
        return string.Compare(a, b, StringComparison.OrdinalIgnoreCase);
    }

    private static (List<long> Numbers, string Suffix)? Parse(string v)
    {
        if (v.Length == 0) return null;
        var numbers = new List<long>();
        var i = 0;
        while (i < v.Length)
        {
            var start = i;
            while (i < v.Length && char.IsDigit(v[i])) i++;
            if (i == start) break; // no digits here: the rest is suffix
            if (!long.TryParse(v.AsSpan(start, i - start), out var num)) return null;
            numbers.Add(num);
            if (i < v.Length && v[i] == '.') { i++; continue; }
            break;
        }
        if (numbers.Count == 0) return null;
        return (numbers, v[i..]);
    }
}

/// <summary>Admin-defined custom-field definition. Fields are defined
/// BEFORE values are accepted: a value for an undefined key is
/// refused, so the field set on a record can never grow by injection
/// from a device feed. Type is "text" | "number" | "date" | "bool" |
/// "enum" (enum carries AllowedValues).</summary>
/// <summary>Custom fields are ADMIN-OWNED metadata (D38-F1/F4):
/// a device change report can never create, change or erase them —
/// InventoryStore.ApplyChangeReport pins them from the stored
/// record and the differ excludes them from the device diff. The
/// only write paths are ApplyBaseline provisioning and the admin
/// act SetCustomFieldsAndTags.</summary>
public sealed record CustomFieldDefinition(
    string Key,
    string Label,
    string Type,
    IReadOnlyList<string>? AllowedValues = null)
{
    public IReadOnlyList<string> AllowedValues { get; init; } =
        AllowedValues ?? Array.Empty<string>();
}

public static class CustomFieldTypes
{
    public static readonly IReadOnlySet<string> All =
        new HashSet<string> { "text", "number", "date", "bool", "enum" };
}

/// <summary>Validation + normalization shared by the store, the
/// register, and the query engine. One home so a rule cannot drift
/// between the write path and the query path.</summary>
public static partial class InventoryValidation
{
    [GeneratedRegex(@"^[a-z][a-z0-9_.\-]{0,63}$")]
    private static partial Regex CustomFieldKeyPattern();

    [GeneratedRegex(@"^[a-z0-9][a-z0-9\-_]{0,63}$")]
    private static partial Regex TagPattern();

    [GeneratedRegex(@"^[A-Z0-9][A-Z0-9\-]{3,31}$")]
    private static partial Regex SerialPattern();

    public static bool IsValidCustomFieldKey(string? key) =>
        key is not null && CustomFieldKeyPattern().IsMatch(key);

    public static bool IsValidTag(string? tag) =>
        tag is not null && TagPattern().IsMatch(tag);

    /// <summary>Tags normalize to trimmed lowercase slugs; an invalid
    /// tag normalizes to null (the caller drops it and counts it).</summary>
    public static string? NormalizeTag(string? tag)
    {
        var t = (tag ?? "").Trim().ToLowerInvariant();
        return IsValidTag(t) ? t : null;
    }

    /// <summary>Serials normalize to trimmed uppercase. Null when the
    /// shape is not a plausible OEM serial (length/charset) — a URL,
    /// a path, or prose is not a serial and never reaches a lookup.</summary>
    public static string? NormalizeSerial(string? serial)
    {
        var s = (serial ?? "").Trim().ToUpperInvariant();
        return s.Length is >= InventoryLimits.MinSerialLength and <= InventoryLimits.MaxSerialLength
               && SerialPattern().IsMatch(s)
            ? s
            : null;
    }

    public static string NormalizeSoftwareName(string? name) =>
        (name ?? "").Trim();

    public static bool HasControlChars(string? s) =>
        s is not null && s.Any(char.IsControl);

    /// <summary>Validate one custom-field value against its
    /// definition. Returns the normalized value, or null on refusal.</summary>
    public static string? ValidateCustomFieldValue(CustomFieldDefinition def, string? raw)
    {
        if (raw is null) return null;
        var v = raw.Trim();
        if (v.Length == 0 || v.Length > InventoryLimits.MaxCustomFieldValueLength) return null;
        if (HasControlChars(v)) return null;
        return def.Type switch
        {
            "text" => v,
            "number" => double.TryParse(v, System.Globalization.NumberStyles.Float,
                System.Globalization.CultureInfo.InvariantCulture, out _) ? v : null,
            "date" => DateTimeOffset.TryParse(v, System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.None, out _) ? v : null,
            "bool" => bool.TryParse(v, out _) ? v.ToLowerInvariant() : null,
            "enum" => def.AllowedValues.Contains(v, StringComparer.OrdinalIgnoreCase) ? v : null,
            _ => null,
        };
    }
}

/// <summary>The hub-stored continuous inventory record for ONE managed
/// device. Revision is a hub-side monotonic counter: every accepted
/// change bumps it by exactly one, and a change report must name the
/// revision it was computed against (optimistic concurrency — a
/// replayed or stale diff cannot apply twice). Warranty is hub-filled
/// (the lookup is hub-side); a device feed can never set it — see
/// InventoryStore.ApplyChangeReport, which takes warranty from the
/// stored record, never from the wire.</summary>
public sealed record DeviceInventoryRecord(
    string DeviceId,
    string ScopeId,
    string Hostname,
    HardwareSnapshot Hardware,
    IReadOnlyList<SoftwareItem> Software,
    IReadOnlyDictionary<string, string> CustomFields,
    IReadOnlySet<string> Tags,
    DateTimeOffset FirstSeenUtc,
    DateTimeOffset LastSeenUtc,
    DateTimeOffset LastChangedUtc,
    long Revision,
    DateTimeOffset? PurchaseDateUtc = null,
    WarrantyInfo? Warranty = null,
    // D38-F7: dropped-item accounting PERSISTED on the record (it
    // previously lived only in a transient Warnings list nothing
    // stored), so the query/report surface can show what a feed lost.
    int DroppedSoftwareCount = 0,
    int DroppedTagsCount = 0,
    int UnknownVersionSoftwareCount = 0,
    // BD-SHARED-RMM-1 F10: when the inventory path last actually
    // COLLECTED software for this device (a baseline snapshot or
    // a change report carrying a software-bearing snapshot).
    // Heartbeats (seen_unchanged) do NOT set it. The hub drift
    // cross-check reads this — and only this, plus a populated
    // software list — as "software was collected" evidence; it
    // previously inferred collection from Revision > 0 or
    // LastSeen > FirstSeen, which a heartbeat-only record
    // satisfies without any software ever being collected.
    DateTimeOffset? SoftwareCollectedUtc = null)
{
    public IReadOnlyDictionary<string, string> CustomFields { get; init; } =
        CustomFields ?? new Dictionary<string, string>();
    public IReadOnlySet<string> Tags { get; init; } =
        Tags ?? new HashSet<string>();
    public IReadOnlyList<SoftwareItem> Software { get; init; } =
        Software ?? Array.Empty<SoftwareItem>();
}

// ---- diff model ------------------------------------------------------

public sealed record SoftwareChange(string Name, string OldVersion, string NewVersion);

public sealed record CustomFieldChange(string Key, string? OldValue, string? NewValue);

/// <summary>One change-reported inventory diff: the ONLY thing an
/// agent sends after its first full snapshot. Hardware changes are
/// named field-level facts ("ram_bytes", "disk_added:…"), never a
/// re-dump of the snapshot. An empty diff is representable and means
/// "seen, unchanged" — the hub treats it as a heartbeat, not a
/// change (no revision bump).</summary>
public sealed record InventoryDiff(
    string DeviceId,
    long BaseRevision,
    DateTimeOffset AtUtc,
    IReadOnlyList<SoftwareItem> AddedSoftware,
    IReadOnlyList<string> RemovedSoftwareNames,
    IReadOnlyList<SoftwareChange> ChangedSoftware,
    IReadOnlyList<string> HardwareChanges,
    IReadOnlyList<CustomFieldChange> CustomFieldChanges,
    IReadOnlyList<string> TagsAdded,
    IReadOnlyList<string> TagsRemoved,
    bool HostnameChanged,
    // D38-F7: version-specific removals for a name that still has
    // other installs ("Name|Version") — RemovedSoftwareNames alone
    // cannot express losing one of several side-by-side installs.
    IReadOnlyList<string>? RemovedSoftwareVersionKeys = null)
{
    public IReadOnlyList<string> RemovedSoftwareVersionKeys { get; init; } =
        RemovedSoftwareVersionKeys ?? Array.Empty<string>();
    public bool IsEmpty =>
        AddedSoftware.Count == 0 && RemovedSoftwareNames.Count == 0 &&
        ChangedSoftware.Count == 0 && HardwareChanges.Count == 0 &&
        CustomFieldChanges.Count == 0 && TagsAdded.Count == 0 &&
        TagsRemoved.Count == 0 && RemovedSoftwareVersionKeys.Count == 0 && !HostnameChanged;
}

/// <summary>What travels from agent to hub after the baseline: the
/// diff PLUS the resulting snapshot. The snapshot is not trusted —
/// the hub recomputes the diff from (stored, snapshot) and refuses
/// the report when the claimed diff does not match the recomputed
/// one (diff spoofing), and refuses when BaseRevision is stale
/// (replay). The diff is the report of record; the snapshot is the
/// evidence it is checked against.
/// D38-F4 — what this check does and does NOT prove: recomputation
/// proves CONSISTENCY (claimed diff ↔ attached snapshot) and the
/// base-revision check proves freshness (no replay). Neither proves
/// PROVENANCE: any caller who can read the current revision can
/// forge a consistent pair. Device AUTHENTICATION is the transport/
/// pairing layer's job (hub integration binds each report to the
/// authenticated device id); no authenticity claim is made here and
/// the word "verified" must not be read as "authenticated".</summary>
public sealed record InventoryChangeReport(
    InventoryDiff Diff,
    DeviceInventoryRecord ResultingSnapshot);

/// <summary>Pure diff computation. Deterministic ordering everywhere
/// (ordinal by normalized name / key) so two computations over the
/// same pair always produce byte-identical diffs — the property the
/// hub's anti-spoof recompute relies on.</summary>
public static class InventoryDiffer
{
    public static InventoryDiff Compute(
        DeviceInventoryRecord? previous, DeviceInventoryRecord next, long baseRevision, DateTimeOffset atUtc)
    {
        var prevHw = previous?.Hardware;
        var hwChanges = new List<string>();
        if (prevHw is not null)
        {
            var n = next.Hardware;
            if (prevHw.Manufacturer != n.Manufacturer) hwChanges.Add($"manufacturer:{prevHw.Manufacturer}->{n.Manufacturer}");
            if (prevHw.Model != n.Model) hwChanges.Add($"model:{prevHw.Model}->{n.Model}");
            if (prevHw.SerialNumber != n.SerialNumber) hwChanges.Add($"serial:{prevHw.SerialNumber ?? "-"}->{n.SerialNumber ?? "-"}");
            if (prevHw.CpuModel != n.CpuModel) hwChanges.Add($"cpu:{prevHw.CpuModel}->{n.CpuModel}");
            if (prevHw.CpuCores != n.CpuCores) hwChanges.Add($"cpu_cores:{prevHw.CpuCores}->{n.CpuCores}");
            if (prevHw.RamBytes != n.RamBytes) hwChanges.Add($"ram_bytes:{prevHw.RamBytes}->{n.RamBytes}");
            if (prevHw.OsName != n.OsName) hwChanges.Add($"os_name:{prevHw.OsName}->{n.OsName}");
            if (prevHw.OsBuild != n.OsBuild) hwChanges.Add($"os_build:{prevHw.OsBuild}->{n.OsBuild}");
            if (prevHw.OsVersion != n.OsVersion) hwChanges.Add($"os_version:{prevHw.OsVersion}->{n.OsVersion}");
            if (prevHw.BiosVersion != n.BiosVersion) hwChanges.Add($"bios:{prevHw.BiosVersion ?? "-"}->{n.BiosVersion ?? "-"}");
            var prevDisks = prevHw.Disks.Select(DiskKey).ToHashSet(StringComparer.OrdinalIgnoreCase);
            var nextDisks = n.Disks.Select(DiskKey).ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach (var d in nextDisks.Except(prevDisks).OrderBy(x => x, StringComparer.Ordinal)) hwChanges.Add($"disk_added:{d}");
            foreach (var d in prevDisks.Except(nextDisks).OrderBy(x => x, StringComparer.Ordinal)) hwChanges.Add($"disk_removed:{d}");
            var prevPer = prevHw.Peripherals.Select(PerKey).ToHashSet(StringComparer.OrdinalIgnoreCase);
            var nextPer = n.Peripherals.Select(PerKey).ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach (var p in nextPer.Except(prevPer).OrderBy(x => x, StringComparer.Ordinal)) hwChanges.Add($"peripheral_added:{p}");
            foreach (var p in prevPer.Except(nextPer).OrderBy(x => x, StringComparer.Ordinal)) hwChanges.Add($"peripheral_removed:{p}");
        }

        // D38-F7/F3: software is MULTI-INSTALL aware. A name may hold
        // several distinct (version) installs side by side (32/64-bit);
        // grouping to g.First() hid the others. Versions present on
        // both sides are checked for Publisher/InstallDate/Source
        // changes (F3: the diff covers every field the store persists);
        // version-only-on-one-side pairs up as Changed (preserving the
        // classic 1.0->2.0 upgrade shape), leftovers become Added /
        // RemovedSoftwareVersionKeys.
        var prevByName = (previous?.Software ?? Array.Empty<SoftwareItem>())
            .GroupBy(s => s.NormalizedName, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.ToList(), StringComparer.OrdinalIgnoreCase);
        var nextByName = next.Software
            .GroupBy(s => s.NormalizedName, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.ToList(), StringComparer.OrdinalIgnoreCase);

        var added = new List<SoftwareItem>();
        var removed = new List<string>();
        var removedVersionKeys = new List<string>();
        var changed = new List<SoftwareChange>();
        foreach (var key in nextByName.Keys.Except(prevByName.Keys).OrderBy(k => k, StringComparer.Ordinal))
            added.AddRange(nextByName[key].OrderBy(s => s.Version, StringComparer.Ordinal));
        foreach (var key in prevByName.Keys.Except(nextByName.Keys).OrderBy(k => k, StringComparer.Ordinal))
            removed.Add(prevByName[key][0].NormalizedName);
        foreach (var key in nextByName.Keys.Intersect(prevByName.Keys).OrderBy(k => k, StringComparer.Ordinal))
        {
            var prevItems = prevByName[key];
            var nextItems = nextByName[key];
            var prevByVer = prevItems.GroupBy(s => (s.Version ?? "").Trim(), StringComparer.OrdinalIgnoreCase)
                .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);
            var nextByVer = nextItems.GroupBy(s => (s.Version ?? "").Trim(), StringComparer.OrdinalIgnoreCase)
                .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);
            foreach (var ver in nextByVer.Keys.Intersect(prevByVer.Keys).OrderBy(v => v, StringComparer.Ordinal))
            {
                var p = prevByVer[ver]; var q = nextByVer[ver];
                if (!string.Equals(p.Publisher ?? "", q.Publisher ?? "", StringComparison.Ordinal) ||
                    p.InstallDateUtc != q.InstallDateUtc ||
                    !string.Equals(p.Source ?? "", q.Source ?? "", StringComparison.Ordinal))
                    changed.Add(new SoftwareChange(q.Name, p.Version, q.Version));
            }
            var prevOnly = prevByVer.Keys.Except(nextByVer.Keys)
                .OrderBy(v => v, StringComparer.Ordinal).ToList();
            var nextOnly = nextByVer.Keys.Except(prevByVer.Keys)
                .OrderBy(v => v, StringComparer.Ordinal).ToList();
            var pairs = Math.Min(prevOnly.Count, nextOnly.Count);
            for (var i = 0; i < pairs; i++)
                changed.Add(new SoftwareChange(nextByVer[nextOnly[i]].Name, prevOnly[i], nextOnly[i]));
            for (var i = pairs; i < nextOnly.Count; i++) added.Add(nextByVer[nextOnly[i]]);
            for (var i = pairs; i < prevOnly.Count; i++)
                removedVersionKeys.Add($"{prevItems[0].NormalizedName}|{prevOnly[i]}");
        }
        added = added.OrderBy(s => s.NormalizedName, StringComparer.Ordinal).ThenBy(s => s.Version, StringComparer.Ordinal).ToList();
        removed = removed.OrderBy(k => k, StringComparer.Ordinal).ToList();
        removedVersionKeys = removedVersionKeys.OrderBy(k => k, StringComparer.Ordinal).ToList();
        changed = changed.OrderBy(c => c.Name, StringComparer.Ordinal).ThenBy(c => c.OldVersion, StringComparer.Ordinal).ToList();

        // D38-F1/F4: custom fields + tags are ADMIN-OWNED and are NOT
        // part of the device diff at all — a device report can neither
        // change nor erase them, and an admin edit cannot stale a
        // device diff. The lists stay in the record shape (always
        // empty from Compute) so a forged diff claiming field/tag
        // changes fails the recompute equality check.
        var cfChanges = new List<CustomFieldChange>();
        var tagsAdded = new List<string>();
        var tagsRemoved = new List<string>();

        return new InventoryDiff(
            next.DeviceId, baseRevision, atUtc,
            added, removed, changed, hwChanges, cfChanges, tagsAdded, tagsRemoved,
            previous is not null && previous.Hostname != next.Hostname,
            removedVersionKeys);
    }

    // D38-F3: DiskKey covers InterfaceType/MediaType — every field
    // ApplyChangeReport persists is either diff-covered or hub-pinned.
    private static string DiskKey(DiskInfo d) =>
        $"{d.Name}|{d.Model ?? ""}|{d.SerialNumber ?? ""}|{d.SizeBytes}|{d.InterfaceType ?? ""}|{d.MediaType ?? ""}";

    private static string PerKey(PeripheralInfo p) =>
        $"{p.Kind}|{p.Name}|{p.Vendor ?? ""}|{p.Model ?? ""}";

    /// <summary>Structural diff equality for the hub's anti-spoof
    /// recompute: every collection compared element-by-element in
    /// the differ's deterministic order.</summary>
    public static bool DiffsEqual(InventoryDiff a, InventoryDiff b) =>
        a.DeviceId == b.DeviceId && a.BaseRevision == b.BaseRevision &&
        a.HostnameChanged == b.HostnameChanged &&
        a.AddedSoftware.SequenceEqual(b.AddedSoftware) &&
        a.RemovedSoftwareNames.SequenceEqual(b.RemovedSoftwareNames) &&
        a.ChangedSoftware.SequenceEqual(b.ChangedSoftware) &&
        a.HardwareChanges.SequenceEqual(b.HardwareChanges) &&
        a.CustomFieldChanges.SequenceEqual(b.CustomFieldChanges) &&
        a.TagsAdded.SequenceEqual(b.TagsAdded) &&
        a.TagsRemoved.SequenceEqual(b.TagsRemoved) &&
        a.RemovedSoftwareVersionKeys.SequenceEqual(b.RemovedSoftwareVersionKeys);
}

/// <summary>D38-F2 — THE canonical normalization point. Agent and hub
/// BOTH run this exact function: the agent normalizes its collector
/// output before diffing/sending, the hub normalizes the received
/// snapshot before recomputing — so normalization can never read as
/// diff spoofing. Pure and idempotent (Normalize(Normalize(x)) ==
/// Normalize(x) on every field it touches). It handles identity,
/// hardware serial/hostname, software and tags; schema-governed
/// custom-field validation stays in the store (the agent has no
/// schema), and the store pins admin-owned fields after this runs.
/// Software rule (D38-F7): distinct installs are kept — dedupe is
/// exact-duplicate only; an item whose VERSION is oversize/control-
/// charred is kept with its version marked unknown ("") and counted
/// in UnknownVersionCount, never vanished; items with an invalid
/// NAME are dropped and counted.</summary>
public static class InventoryNormalizer
{
    public sealed record Result(
        DeviceInventoryRecord Record,
        int DroppedSoftwareCount,
        int DroppedTagsCount,
        int UnknownVersionSoftwareCount);

    public static Result Normalize(DeviceInventoryRecord candidate)
    {
        var hw = candidate.Hardware;
        HardwareSnapshot? normalizedHw = null;
        if (hw is not null)
        {
            var serial = hw.SerialNumber is null ? null : InventoryValidation.NormalizeSerial(hw.SerialNumber);
            // Keep the raw serial when it does not normalize: the
            // store refuses poisoned serial shapes itself; here we
            // only canonicalize shapes that DO normalize so agent
            // and hub agree byte-for-byte on valid data.
            normalizedHw = hw with
            {
                Manufacturer = hw.Manufacturer?.Trim() ?? null!,
                Model = hw.Model?.Trim() ?? null!,
                SerialNumber = serial ?? hw.SerialNumber,
                CpuModel = hw.CpuModel?.Trim() ?? null!,
                OsName = hw.OsName?.Trim() ?? null!,
                OsBuild = hw.OsBuild?.Trim() ?? null!,
                OsVersion = hw.OsVersion?.Trim() ?? null!,
                Disks = (hw.Disks ?? Array.Empty<DiskInfo>()).ToList(),
                Peripherals = (hw.Peripherals ?? Array.Empty<PeripheralInfo>()).ToList(),
            };
        }

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var software = new List<SoftwareItem>();
        var droppedSw = 0; var unknownVer = 0;
        foreach (var item in candidate.Software ?? Array.Empty<SoftwareItem>())
        {
            if (item is null || string.IsNullOrWhiteSpace(item.Name) ||
                item.Name.Trim().Length > InventoryLimits.MaxSoftwareNameLength ||
                InventoryValidation.HasControlChars(item.Name))
            { droppedSw++; continue; }
            var version = (item.Version ?? "").Trim();
            if (version.Length > InventoryLimits.MaxSoftwareVersionLength ||
                InventoryValidation.HasControlChars(item.Version))
            { version = ""; unknownVer++; }
            var clean = item with { Name = item.Name.Trim(), Version = version };
            var key = $"{clean.NormalizedName}|{clean.Version}|{clean.Publisher ?? ""}|{clean.Source ?? ""}|{clean.InstallDateUtc?.UtcTicks}";
            if (!seen.Add(key)) { droppedSw++; continue; } // exact duplicate only
            software.Add(clean);
        }
        software = software.OrderBy(s => s.NormalizedName, StringComparer.Ordinal)
            .ThenBy(s => s.Version, StringComparer.Ordinal).ToList();

        var tags = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var droppedTags = 0;
        foreach (var raw in candidate.Tags ?? new HashSet<string>())
        {
            var t = InventoryValidation.NormalizeTag(raw);
            if (t is null) droppedTags++; else tags.Add(t);
        }

        var record = candidate with
        {
            DeviceId = (candidate.DeviceId ?? "").Trim(),
            Hostname = (candidate.Hostname ?? "").Trim(),
            Hardware = normalizedHw!,
            Software = software,
            Tags = tags,
        };
        return new Result(record, droppedSw, droppedTags, unknownVer);
    }
}
