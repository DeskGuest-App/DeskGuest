using System.Text.Json;

namespace Acp.Shared.Inventory;

// =====================================================================
// RMM-04 hub-side inventory store + fleet query + lifecycle view.
// The store is the hub's maintained record: agents baseline once,
// then report diffs; the store consistency-checks every report
// before applying it (base-revision + recomputed-diff equality), so
// the stored record can only ever be the result of a checked change
// chain. D38-F4: "checked" means diff↔snapshot CONSISTENCY + replay
// freshness — NOT device authenticity. Authentication is the
// transport/pairing layer's job; hub integration must bind each
// report to the authenticated device id. No claim beyond that is
// made anywhere in this file.
//
// Queries are STRUCTURED — criteria are typed fields, never a query
// string — so there is no query language to inject into. A custom-
// field criterion carries a key + value as data; an invalid key
// refuses the query (named in the result), it does not become a
// wildcard.
// =====================================================================

/// <summary>BD-WIN-CORE-3/F12(c): typed outcome kinds for apply
/// results whose handling branches on WHY — callers switch on the
/// kind, never on the human-readable Outcome text (the old shape
/// string-matched "stale or replayed" in InventoryService, so a
/// wording edit would silently disable the re-baseline path).</summary>
public static class InventoryOutcomeKinds
{
    public const string Accepted = "accepted";
    public const string Refused = "refused";
    public const string StaleOrReplayed = "stale_or_replayed";
}

public sealed record InventoryApplyResult(
    bool Accepted,
    string Outcome,
    InventoryDiff? Diff,
    long NewRevision,
    IReadOnlyList<string> Warnings)
{
    /// <summary>The typed outcome kind (InventoryOutcomeKinds).
    /// Defaults from Accepted for results built positionally.</summary>
    public string OutcomeKind { get; init; } = Accepted ? InventoryOutcomeKinds.Accepted : InventoryOutcomeKinds.Refused;

    public static InventoryApplyResult Refused(string reason) =>
        new(false, reason, null, -1, Array.Empty<string>());

    public static InventoryApplyResult Refused(string reason, string outcomeKind) =>
        new(false, reason, null, -1, Array.Empty<string>()) { OutcomeKind = outcomeKind };
}

public sealed record SerialConflict(string SerialNumber, IReadOnlyList<string> DeviceIds);

/// <summary>D38-F5(d) — the serial-conflict alert event shape for the
/// RMM-01 alert centre (the seam their lane consumes, mirroring
/// WarrantyAlertEvent). Raised from stored data only via
/// InventoryStore.CollectSerialConflictAlerts; wiring this into
/// RMM-01's centre is hub/RMM-01 integration work — this lane
/// exposes the event, it does not edit RMM-01 files.</summary>
public sealed record SerialConflictAlertEvent(
    string SerialNumber,
    IReadOnlyList<string> DeviceIds,
    string Kind,
    DateTimeOffset RaisedUtc)
{
    public const string KindSerialConflict = "serial_conflict";
}

public sealed class InventoryStore
{
    private readonly Dictionary<string, DeviceInventoryRecord> _records = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, CustomFieldDefinition> _schema = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();
    private readonly Func<string, bool> _policyCheck;

    public InventoryStore(Func<string, bool>? policyCheck = null,
        IEnumerable<CustomFieldDefinition>? customFieldSchema = null)
    {
        _policyCheck = policyCheck ?? InventoryPolicyKeys.DefaultCheck;
        foreach (var def in customFieldSchema ?? Array.Empty<CustomFieldDefinition>())
            DefineCustomField(def);
    }

    public event Action? Changed;

    public bool InventoryEnabled => _policyCheck(InventoryPolicyKeys.InventoryEnabled);

    // ---- custom-field schema ----------------------------------------

    /// <summary>Define (or refuse) an admin custom field. A key that
    /// is not a clean slug, a type outside the closed set, an enum
    /// with no values, or a redefinition with a different type are
    /// all refused — the schema cannot be mutated by a feed.</summary>
    public bool DefineCustomField(CustomFieldDefinition? def)
    {
        if (def is null) return false;
        if (!InventoryValidation.IsValidCustomFieldKey(def.Key)) return false;
        if (!CustomFieldTypes.All.Contains(def.Type ?? "")) return false;
        if (def.Type == "enum" && def.AllowedValues.Count == 0) return false;
        if (string.IsNullOrWhiteSpace(def.Label)) return false;
        lock (_gate)
        {
            if (_schema.TryGetValue(def.Key, out var existing))
                return existing.Type == def.Type; // same-type re-define is a no-op; type change refuses
            if (_schema.Count >= InventoryLimits.MaxCustomFields) return false;
            _schema[def.Key] = def;
            Changed?.Invoke();
            return true;
        }
    }

    public IReadOnlyList<CustomFieldDefinition> CustomFieldSchema
    {
        get { lock (_gate) return _schema.Values.OrderBy(d => d.Key, StringComparer.Ordinal).ToList(); }
    }

    // ---- ingest -------------------------------------------------------

    /// <summary>Validate + normalize a candidate record against the
    /// schema and limits. Returns the normalized record plus dropped-
    /// item counts, or null when the record must be refused whole
    /// (oversized software list, bad identity, bad serial shape).</summary>
    private (DeviceInventoryRecord Record, List<string> Warnings)? Normalize(
        DeviceInventoryRecord candidate)
    {
        var warnings = new List<string>();
        if (candidate is null) return null;
        // D38-F6: fail-fast bounds BEFORE any processing — a raw list
        // beyond the fail-fast wall refuses without the hub doing
        // unbounded work first.
        if ((candidate.Software?.Count ?? 0) > InventoryLimits.RawSoftwareFailFast) return null;
        if ((candidate.Tags?.Count ?? 0) > InventoryLimits.RawTagsFailFast) return null;
        if (string.IsNullOrWhiteSpace(candidate.DeviceId) ||
            InventoryValidation.HasControlChars(candidate.DeviceId)) return null;
        if (string.IsNullOrWhiteSpace(candidate.Hostname) ||
            candidate.Hostname.Trim().Length > InventoryLimits.MaxHostnameLength ||
            InventoryValidation.HasControlChars(candidate.Hostname)) return null;
        var hw = candidate.Hardware;
        if (hw is null) return null;
        // D38-F6: hardware sub-fields validated — null, oversize or
        // control-charred strings refuse the record (one bad record
        // must never crash fleet Query/Lifecycle/Export later).
        if (!IsBoundedHwString(hw.Manufacturer, allowEmpty: true) ||
            !IsBoundedHwString(hw.Model, allowEmpty: true) ||
            !IsBoundedHwString(hw.CpuModel, allowEmpty: true) ||
            !IsBoundedHwString(hw.OsName, allowEmpty: true) ||
            !IsBoundedHwString(hw.OsBuild, allowEmpty: false) ||
            !IsBoundedHwString(hw.OsVersion, allowEmpty: true) ||
            (hw.BiosVersion is not null && !IsBoundedHwString(hw.BiosVersion, allowEmpty: true)))
            return null;
        var serial = hw.SerialNumber is null ? null : InventoryValidation.NormalizeSerial(hw.SerialNumber);
        if (hw.SerialNumber is not null && serial is null) return null; // poisoned serial shape refuses

        var disks = hw.Disks ?? Array.Empty<DiskInfo>();
        var peripherals = hw.Peripherals ?? Array.Empty<PeripheralInfo>();
        if (disks.Count > InventoryLimits.MaxDisks || peripherals.Count > InventoryLimits.MaxPeripherals)
            return null;
        foreach (var d in disks)
        {
            if (d is null) return null;
            if (!IsBoundedHwString(d.Name, allowEmpty: false) ||
                (d.Model is not null && !IsBoundedHwString(d.Model, allowEmpty: true)) ||
                (d.SerialNumber is not null && !IsBoundedHwString(d.SerialNumber, allowEmpty: true)) ||
                (d.InterfaceType is not null && !IsBoundedHwString(d.InterfaceType, allowEmpty: true)) ||
                (d.MediaType is not null && !IsBoundedHwString(d.MediaType, allowEmpty: true)))
                return null;
        }
        foreach (var p in peripherals)
        {
            if (p is null) return null;
            if (!IsBoundedHwString(p.Kind, allowEmpty: false) ||
                !IsBoundedHwString(p.Name, allowEmpty: false) ||
                (p.Vendor is not null && !IsBoundedHwString(p.Vendor, allowEmpty: true)) ||
                (p.Model is not null && !IsBoundedHwString(p.Model, allowEmpty: true)))
                return null;
        }

        // D38-F2: software + tags go through the ONE canonical
        // normalizer the agent also uses. D38-F7: distinct installs
        // kept; bad-version items kept with unknown version.
        var canon = InventoryNormalizer.Normalize(candidate);
        if (canon.Record.Software.Count > InventoryLimits.MaxSoftwareItems) return null;
        if (canon.DroppedSoftwareCount > 0) warnings.Add($"software_items_dropped:{canon.DroppedSoftwareCount}");
        if (canon.UnknownVersionSoftwareCount > 0) warnings.Add($"software_versions_unknown:{canon.UnknownVersionSoftwareCount}");
        if (canon.Record.Tags.Count > InventoryLimits.MaxTags) return null;
        if (canon.DroppedTagsCount > 0) warnings.Add($"tags_dropped:{canon.DroppedTagsCount}");

        // Custom fields: EVERY key must be defined and EVERY value
        // must validate. An undefined key refuses the record — a
        // device feed can never invent fields on the hub record.
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (key, value) in candidate.CustomFields)
        {
            if (!_schema.TryGetValue(key ?? "", out var def)) return null;
            var v = InventoryValidation.ValidateCustomFieldValue(def, value);
            if (v is null) return null;
            fields[def.Key] = v;
        }

        var record = canon.Record with
        {
            Hardware = canon.Record.Hardware with { SerialNumber = serial },
            CustomFields = fields,
            // Warranty is hub-owned: a candidate NEVER carries one in.
            Warranty = null,
            // D38-F7: dropped accounting persisted on the record.
            DroppedSoftwareCount = canon.DroppedSoftwareCount,
            DroppedTagsCount = canon.DroppedTagsCount,
            UnknownVersionSoftwareCount = canon.UnknownVersionSoftwareCount,
        };
        return (record, warnings);
    }

    private static bool IsBoundedHwString(string? s, bool allowEmpty) =>
        s is not null &&
        (allowEmpty || s.Trim().Length > 0) &&
        s.Length <= InventoryLimits.MaxHardwareStringLength &&
        !InventoryValidation.HasControlChars(s);

    /// <summary>D38-F5: the ONE warranty acceptance rule, used by
    /// SetWarranty AND import: the record must be a genuine outbound
    /// lookup, its serial must equal the device record's normalized
    /// serial, its vendor must be a known OEM (normalized), and its
    /// status must be in the closed set. Returns the normalized
    /// warranty to store, or null to refuse.</summary>
    private static WarrantyInfo? ValidateWarrantyForRecord(WarrantyInfo? w, DeviceInventoryRecord record)
    {
        if (w is null || !w.IsOutboundLookup) return null;
        var vendor = WarrantyVendors.Normalize(w.Vendor);
        if (vendor is null) return null;
        var status = (w.Status ?? "").Trim().ToLowerInvariant();
        if (status is not (WarrantyInfo.StatusActive or WarrantyInfo.StatusExpired or WarrantyInfo.StatusUnknown))
            return null;
        var recordSerial = record.Hardware?.SerialNumber is null
            ? null : InventoryValidation.NormalizeSerial(record.Hardware.SerialNumber);
        var warrantySerial = InventoryValidation.NormalizeSerial(w.SerialNumber);
        if (recordSerial is null || warrantySerial is null ||
            !string.Equals(recordSerial, warrantySerial, StringComparison.Ordinal))
            return null;
        return w with { Vendor = vendor, SerialNumber = warrantySerial, Status = status };
    }

    /// <summary>Accept a device's baseline (first) snapshot. Refused
    /// when inventory is disabled by policy, the record fails
    /// validation, or a baseline already exists (a second baseline
    /// must arrive as a change report, so history cannot be reset
    /// silently).</summary>
    public InventoryApplyResult ApplyBaseline(DeviceInventoryRecord candidate, DateTimeOffset now)
    {
        if (!InventoryEnabled)
            return InventoryApplyResult.Refused("refused: inventory disabled by policy (rmm.inventory.enabled)");
        var norm = Normalize(candidate);
        if (norm is null)
            return InventoryApplyResult.Refused("refused: inventory record failed validation (identity, serial, software cap, or custom-field schema)");
        lock (_gate)
        {
            if (_records.ContainsKey(norm.Value.Record.DeviceId))
                return InventoryApplyResult.Refused("refused: baseline already exists for this device — changes must arrive as change reports");
            var stored = norm.Value.Record with
            {
                FirstSeenUtc = now,
                LastSeenUtc = now,
                LastChangedUtc = now,
                Revision = 1,
                Warranty = null,
                // F10: a baseline snapshot IS a software
                // collection — stamp it hub-side.
                SoftwareCollectedUtc = now,
            };
            _records[stored.DeviceId] = stored;
            var diff = InventoryDiffer.Compute(null, stored, 0, now);
            Changed?.Invoke();
            return new InventoryApplyResult(true, "baseline_accepted", diff, 1, norm.Value.Warnings);
        }
    }

    /// <summary>Accept a change report — the heart of RMM-04's
    /// consistency-check discipline (D38-F4 wording: consistency,
    /// not authenticity). THREE checks, all must pass:
    /// (1) BaseRevision equals the stored revision (no replay, no
    /// stale diff); (2) the claimed diff EQUALS the diff recomputed
    /// from (stored, resulting snapshot) — a forged diff that does
    /// not match its own snapshot refuses; (3) the snapshot itself
    /// validates. Hub-owned state is PINNED from the stored record,
    /// never taken from the wire (D38-F1/F3): ScopeId, PurchaseDateUtc,
    /// CustomFields, Tags and Warranty — so a report cannot move its
    /// own scope, back-date its purchase, or erase admin metadata
    /// behind an unrelated checked diff. Every other persisted field
    /// is diff-covered (D38-F3).</summary>
    public InventoryApplyResult ApplyChangeReport(InventoryChangeReport report, DateTimeOffset now)
    {
        if (!InventoryEnabled)
            return InventoryApplyResult.Refused("refused: inventory disabled by policy (rmm.inventory.enabled)");
        if (report?.Diff is null || report.ResultingSnapshot is null)
            return InventoryApplyResult.Refused("refused: malformed change report");
        var norm = Normalize(report.ResultingSnapshot);
        if (norm is null)
            return InventoryApplyResult.Refused("refused: resulting snapshot failed validation");
        lock (_gate)
        {
            if (!_records.TryGetValue(norm.Value.Record.DeviceId, out var stored))
                return InventoryApplyResult.Refused("refused: no baseline for this device — a change report cannot create a record");
            if (report.Diff.DeviceId != stored.DeviceId)
                return InventoryApplyResult.Refused("refused: diff device id does not match the snapshot device id");
            if (report.Diff.BaseRevision != stored.Revision)
                return InventoryApplyResult.Refused(
                    $"refused: stale or replayed diff — base revision {report.Diff.BaseRevision} != stored revision {stored.Revision}",
                    InventoryOutcomeKinds.StaleOrReplayed);
            // Pin admin/hub-owned fields BEFORE the recompute so the
            // recomputed diff is over exactly what will be stored.
            var pinned = norm.Value.Record with
            {
                ScopeId = stored.ScopeId,
                PurchaseDateUtc = stored.PurchaseDateUtc,
                CustomFields = stored.CustomFields,
                Tags = stored.Tags,
            };
            var recomputed = InventoryDiffer.Compute(stored, pinned, stored.Revision, report.Diff.AtUtc);
            if (!InventoryDiffer.DiffsEqual(recomputed, report.Diff))
                return InventoryApplyResult.Refused("refused: claimed diff does not match the diff recomputed from the stored record and the resulting snapshot (diff spoofing)");

            if (report.Diff.IsEmpty)
            {
                _records[stored.DeviceId] = stored with { LastSeenUtc = now };
                return new InventoryApplyResult(true, "seen_unchanged", report.Diff, stored.Revision, norm.Value.Warnings);
            }
            // D38-F5(c): a serial change (board swap) detaches the old
            // warranty — it described a different serial.
            var serialChanged = !string.Equals(
                stored.Hardware.SerialNumber ?? "", pinned.Hardware.SerialNumber ?? "",
                StringComparison.OrdinalIgnoreCase);
            var updated = pinned with
            {
                FirstSeenUtc = stored.FirstSeenUtc,
                LastSeenUtc = now,
                LastChangedUtc = now,
                Revision = stored.Revision + 1,
                Warranty = serialChanged ? null : stored.Warranty,
                // F10: a change report carries a fresh software-
                // bearing snapshot — a collection act, stamped
                // hub-side. (seen_unchanged heartbeats above keep
                // the stored stamp untouched.)
                SoftwareCollectedUtc = now,
            };
            _records[stored.DeviceId] = updated;
            Changed?.Invoke();
            return new InventoryApplyResult(true, "change_applied", report.Diff, updated.Revision, norm.Value.Warnings);
        }
    }

    /// <summary>Admin act: set/replace custom fields + tags on a
    /// stored record (admin-owned metadata — purchase assignment,
    /// site codes, etc.). Validated against the same schema.
    /// D38-F1: this does NOT bump the device Revision — admin
    /// metadata lives in a separate revision domain from device-
    /// reported state, so an admin edit can neither stale an
    /// in-flight device diff nor be erased by one. (Warranty writes
    /// already followed this rule; fields/tags now do too.)</summary>
    public bool SetCustomFieldsAndTags(string deviceId,
        IReadOnlyDictionary<string, string>? customFields, IEnumerable<string>? tags, DateTimeOffset now)
    {
        lock (_gate)
        {
            if (!_records.TryGetValue(deviceId ?? "", out var stored)) return false;
            var fields = new Dictionary<string, string>(stored.CustomFields, StringComparer.OrdinalIgnoreCase);
            if (customFields is not null)
            {
                foreach (var (key, value) in customFields)
                {
                    if (!_schema.TryGetValue(key ?? "", out var def)) return false;
                    var v = InventoryValidation.ValidateCustomFieldValue(def, value);
                    if (v is null) return false;
                    fields[def.Key] = v;
                }
            }
            var tagSet = new HashSet<string>(stored.Tags, StringComparer.OrdinalIgnoreCase);
            if (tags is not null)
            {
                tagSet.Clear();
                foreach (var raw in tags)
                {
                    var t = InventoryValidation.NormalizeTag(raw);
                    if (t is null) return false;
                    tagSet.Add(t);
                }
                if (tagSet.Count > InventoryLimits.MaxTags) return false;
            }
            _records[stored.DeviceId] = stored with
            {
                CustomFields = fields,
                Tags = tagSet,
                LastChangedUtc = now,
                // D38-F1: Revision deliberately NOT bumped (see summary).
                Revision = stored.Revision,
            };
            Changed?.Invoke();
            return true;
        }
    }

    /// <summary>Hub-side warranty write: the ONLY path that sets a
    /// record's warranty. Bumps no revision (warranty is hub metadata,
    /// not device-reported state — a device diff in flight must not
    /// go stale because the hub refreshed a warranty).
    /// D38-F5(b): validates like import does — genuine outbound
    /// lookup, serial equal to the record's, known vendor, closed
    /// status set; anything else is refused, nothing stored.</summary>
    public bool SetWarranty(string deviceId, WarrantyInfo warranty)
    {
        lock (_gate)
        {
            if (!_records.TryGetValue(deviceId ?? "", out var stored)) return false;
            var validated = ValidateWarrantyForRecord(warranty, stored);
            if (validated is null) return false;
            _records[stored.DeviceId] = stored with { Warranty = validated };
            Changed?.Invoke();
            return true;
        }
    }

    public DeviceInventoryRecord? Get(string? deviceId)
    {
        lock (_gate) return deviceId is not null && _records.TryGetValue(deviceId, out var r) ? r : null;
    }

    public IReadOnlyList<DeviceInventoryRecord> List(string? scopeId = null)
    {
        lock (_gate)
            return _records.Values
                .Where(r => scopeId is null || string.Equals(r.ScopeId, scopeId, StringComparison.OrdinalIgnoreCase))
                .OrderBy(r => r.DeviceId, StringComparer.Ordinal)
                .ToList();
    }

    public bool Remove(string deviceId)
    {
        lock (_gate)
        {
            if (!_records.Remove(deviceId ?? "")) return false;
            Changed?.Invoke();
            return true;
        }
    }

    /// <summary>Duplicate/forged serial detection: serials claimed by
    /// MORE THAN ONE device id. Both records are kept (device identity
    /// is the device id, not the serial — refusing the second record
    /// would let an attacker DoS a legit device by pre-claiming its
    /// serial), and the conflict is surfaced here for the operator.</summary>
    public IReadOnlyList<SerialConflict> GetSerialConflicts()
    {
        lock (_gate)
            return _records.Values
                .Where(r => r.Hardware.SerialNumber is not null)
                .GroupBy(r => r.Hardware.SerialNumber!, StringComparer.OrdinalIgnoreCase)
                .Where(g => g.Count() > 1)
                .Select(g => new SerialConflict(g.Key,
                    g.Select(r => r.DeviceId).OrderBy(x => x, StringComparer.Ordinal).ToList()))
                .OrderBy(c => c.SerialNumber, StringComparer.Ordinal)
                .ToList();
    }

    /// <summary>D38-F5(d) SEAM for RMM-01: serial conflicts as alert
    /// events, evaluated from stored data only (mirrors
    /// CollectWarrantyAlerts). RMM-01's centre consumes this shape;
    /// wiring it in is their/hub integration work.</summary>
    public IReadOnlyList<SerialConflictAlertEvent> CollectSerialConflictAlerts(DateTimeOffset now) =>
        GetSerialConflicts()
            .Select(c => new SerialConflictAlertEvent(
                c.SerialNumber, c.DeviceIds, SerialConflictAlertEvent.KindSerialConflict, now))
            .ToList();

    /// <summary>Warranty alerts across the fleet at `now` (the
    /// RMM-01 hook, evaluated from stored data only).</summary>
    public IReadOnlyList<WarrantyAlertEvent> CollectWarrantyAlerts(DateTimeOffset now,
        int warningWindowDays = WarrantyAlertEvaluator.DefaultWarningWindowDays,
        int criticalWindowDays = WarrantyAlertEvaluator.DefaultCriticalWindowDays)
    {
        lock (_gate)
            return _records.Values
                .Select(r => WarrantyAlertEvaluator.Evaluate(r, now, warningWindowDays, criticalWindowDays))
                .Where(e => e is not null).Select(e => e!)
                .OrderBy(e => e.ExpiresUtc).ToList();
    }

    // ---- persistence (Roster discipline: explicit DTOs — the record
    // types carry IReadOnlySet/IReadOnlyDictionary members that
    // System.Text.Json cannot round-trip, so the wire shape is its
    // own flat DTO set, mapped in both directions) -------------------

    private sealed record DiskDto(string Name, string? Model, string? SerialNumber, long SizeBytes, string? InterfaceType, string? MediaType);
    private sealed record PeripheralDto(string Kind, string Name, string? Vendor, string? Model);
    private sealed record HardwareDto(
        string Manufacturer, string Model, string? SerialNumber, string CpuModel, int CpuCores,
        long RamBytes, string OsName, string OsBuild, string OsVersion, string? BiosVersion,
        DiskDto[] Disks, PeripheralDto[] Peripherals, DateTimeOffset CollectedUtc);
    private sealed record SoftwareDto(string Name, string Version, string? Publisher, DateTimeOffset? InstallDateUtc, string? Source);
    private sealed record WarrantyDto(
        string Vendor, string SerialNumber, string Status, DateTimeOffset? ExpiresUtc,
        string? PlanName, DateTimeOffset RetrievedUtc, bool IsOutboundLookup, string Source);
    private sealed record RecordDto(
        string DeviceId, string ScopeId, string Hostname, HardwareDto Hardware, SoftwareDto[] Software,
        Dictionary<string, string> CustomFields, string[] Tags,
        DateTimeOffset FirstSeenUtc, DateTimeOffset LastSeenUtc, DateTimeOffset LastChangedUtc,
        long Revision, DateTimeOffset? PurchaseDateUtc, WarrantyDto? Warranty,
        int DroppedSoftwareCount = 0, int DroppedTagsCount = 0, int UnknownVersionSoftwareCount = 0,
        DateTimeOffset? SoftwareCollectedUtc = null);

    private static RecordDto ToDto(DeviceInventoryRecord r) => new(
        r.DeviceId, r.ScopeId, r.Hostname,
        new HardwareDto(r.Hardware.Manufacturer, r.Hardware.Model, r.Hardware.SerialNumber,
            r.Hardware.CpuModel, r.Hardware.CpuCores, r.Hardware.RamBytes, r.Hardware.OsName,
            r.Hardware.OsBuild, r.Hardware.OsVersion, r.Hardware.BiosVersion,
            r.Hardware.Disks.Select(d => new DiskDto(d.Name, d.Model, d.SerialNumber, d.SizeBytes, d.InterfaceType, d.MediaType)).ToArray(),
            r.Hardware.Peripherals.Select(p => new PeripheralDto(p.Kind, p.Name, p.Vendor, p.Model)).ToArray(),
            r.Hardware.CollectedUtc),
        r.Software.Select(s => new SoftwareDto(s.Name, s.Version, s.Publisher, s.InstallDateUtc, s.Source)).ToArray(),
        new Dictionary<string, string>(r.CustomFields),
        r.Tags.ToArray(),
        r.FirstSeenUtc, r.LastSeenUtc, r.LastChangedUtc, r.Revision, r.PurchaseDateUtc,
        r.Warranty is null ? null : new WarrantyDto(r.Warranty.Vendor, r.Warranty.SerialNumber,
            r.Warranty.Status, r.Warranty.ExpiresUtc, r.Warranty.PlanName, r.Warranty.RetrievedUtc,
            r.Warranty.IsOutboundLookup, r.Warranty.Source),
        r.DroppedSoftwareCount, r.DroppedTagsCount, r.UnknownVersionSoftwareCount, r.SoftwareCollectedUtc);

    private static DeviceInventoryRecord FromDto(RecordDto d) => new(
        d.DeviceId, d.ScopeId, d.Hostname,
        new HardwareSnapshot(d.Hardware.Manufacturer, d.Hardware.Model, d.Hardware.SerialNumber,
            d.Hardware.CpuModel, d.Hardware.CpuCores, d.Hardware.RamBytes, d.Hardware.OsName,
            d.Hardware.OsBuild, d.Hardware.OsVersion, d.Hardware.BiosVersion,
            (d.Hardware.Disks ?? Array.Empty<DiskDto>()).Select(x => new DiskInfo(x.Name, x.Model, x.SerialNumber, x.SizeBytes, x.InterfaceType, x.MediaType)).ToList(),
            (d.Hardware.Peripherals ?? Array.Empty<PeripheralDto>()).Select(x => new PeripheralInfo(x.Kind, x.Name, x.Vendor, x.Model)).ToList(),
            d.Hardware.CollectedUtc),
        (d.Software ?? Array.Empty<SoftwareDto>()).Select(x => new SoftwareItem(x.Name, x.Version, x.Publisher, x.InstallDateUtc, x.Source)).ToList(),
        d.CustomFields ?? new Dictionary<string, string>(),
        new HashSet<string>(d.Tags ?? Array.Empty<string>()),
        d.FirstSeenUtc, d.LastSeenUtc, d.LastChangedUtc, d.Revision, d.PurchaseDateUtc,
        d.Warranty is null ? null : new WarrantyInfo(d.Warranty.Vendor, d.Warranty.SerialNumber,
            d.Warranty.Status, d.Warranty.ExpiresUtc, d.Warranty.PlanName, d.Warranty.RetrievedUtc,
            d.Warranty.IsOutboundLookup, d.Warranty.Source),
        d.DroppedSoftwareCount, d.DroppedTagsCount, d.UnknownVersionSoftwareCount, d.SoftwareCollectedUtc);

    public string ExportJson()
    {
        lock (_gate) return JsonSerializer.Serialize(_records.Values.Select(ToDto).ToList());
    }

    /// <summary>Restore records into an EMPTY store region: existing
    /// device ids are skipped (import never overwrites a live
    /// record), malformed entries are skipped, never fatal.</summary>
    public int ImportJson(string json)
    {
        List<RecordDto>? dtos;
        try { dtos = JsonSerializer.Deserialize<List<RecordDto>>(json); }
        catch { return 0; }
        if (dtos is null) return 0;
        var restored = 0;
        foreach (var dto in dtos)
        {
            if (dto is null) continue;
            DeviceInventoryRecord candidate;
            try { candidate = FromDto(dto); } catch { continue; }
            var norm = Normalize(candidate);
            if (norm is null) continue;
            lock (_gate)
            {
                if (_records.ContainsKey(norm.Value.Record.DeviceId)) continue;
                // D38-F5(a): warranty survives import ONLY when it
                // passes the same rule as SetWarranty — genuine
                // outbound lookup AND serial/vendor/status matching
                // THIS record. A planted flag alone honors nothing.
                var warranty = ValidateWarrantyForRecord(candidate.Warranty, norm.Value.Record);
                _records[norm.Value.Record.DeviceId] = norm.Value.Record with
                {
                    FirstSeenUtc = candidate.FirstSeenUtc,
                    LastSeenUtc = candidate.LastSeenUtc,
                    LastChangedUtc = candidate.LastChangedUtc,
                    Revision = Math.Max(1, candidate.Revision),
                    PurchaseDateUtc = candidate.PurchaseDateUtc,
                    Warranty = warranty,
                    DroppedSoftwareCount = Math.Max(norm.Value.Record.DroppedSoftwareCount, candidate.DroppedSoftwareCount),
                    DroppedTagsCount = Math.Max(norm.Value.Record.DroppedTagsCount, candidate.DroppedTagsCount),
                    UnknownVersionSoftwareCount = Math.Max(norm.Value.Record.UnknownVersionSoftwareCount, candidate.UnknownVersionSoftwareCount),
                };
                restored++;
            }
        }
        if (restored > 0) Changed?.Invoke();
        return restored;
    }
}

// ---- fleet query -------------------------------------------------------

public enum VersionComparison { LessThan, LessOrEqual, Equal, GreaterOrEqual, GreaterThan, Present, Absent }

/// <summary>One structured fleet query. All criteria are ANDed; a
/// null criterion does not constrain. This is the "every machine with
/// Acrobat &lt; vX" surface: SoftwareName + VersionOp + Version.</summary>
public sealed record InventoryQuery(
    string? SoftwareName = null,
    VersionComparison? VersionOp = null,
    string? Version = null,
    string? OsBuild = null,
    string? Manufacturer = null,
    string? Tag = null,
    string? CustomFieldKey = null,
    string? CustomFieldValue = null,
    string? ScopeId = null,
    int? WarrantyExpiringWithinDays = null);

public sealed record InventoryQueryResult(
    bool Accepted,
    string? RefusalReason,
    IReadOnlyList<DeviceInventoryRecord> Matches)
{
    public static InventoryQueryResult Refused(string reason) =>
        new(false, reason, Array.Empty<DeviceInventoryRecord>());
}

public static class InventoryQueryEngine
{
    public static InventoryQueryResult Query(InventoryStore store, InventoryQuery query, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(query);

        if (query.VersionOp is { } versionOp &&
            versionOp is not VersionComparison.Present and not VersionComparison.Absent
            && string.IsNullOrWhiteSpace(query.Version))
            return InventoryQueryResult.Refused("a version comparison requires a version to compare against");
        if (query.VersionOp is not null && string.IsNullOrWhiteSpace(query.SoftwareName))
            return InventoryQueryResult.Refused("a version comparison requires a software name");
        // D38-F10: malformed queries REFUSE, never silently widen.
        if (query.Version is not null && query.VersionOp is null)
            return InventoryQueryResult.Refused("a version without a version operator is malformed — query refused, never widened to Present");
        if (query.CustomFieldValue is not null && query.CustomFieldKey is null)
            return InventoryQueryResult.Refused("a custom-field value without a key is malformed — query refused, never ignored");
        if (query.SoftwareName is not null && string.IsNullOrWhiteSpace(query.SoftwareName))
            return InventoryQueryResult.Refused("an empty software-name criterion is malformed — query refused");
        if (query.Manufacturer is not null && string.IsNullOrWhiteSpace(query.Manufacturer))
            return InventoryQueryResult.Refused("an empty manufacturer criterion is malformed — query refused, never widened to match-everything");
        if (query.OsBuild is not null && string.IsNullOrWhiteSpace(query.OsBuild))
            return InventoryQueryResult.Refused("an empty os-build criterion is malformed — query refused");
        if (query.CustomFieldValue is not null && string.IsNullOrWhiteSpace(query.CustomFieldValue))
            return InventoryQueryResult.Refused("an empty custom-field value is malformed — query refused");
        if (query.ScopeId is not null && string.IsNullOrWhiteSpace(query.ScopeId))
            return InventoryQueryResult.Refused("an empty scope criterion is malformed — query refused");
        if (query.CustomFieldKey is not null && !InventoryValidation.IsValidCustomFieldKey(query.CustomFieldKey))
            return InventoryQueryResult.Refused(
                $"custom-field key '{query.CustomFieldKey}' is not a valid field key — query refused, never widened to a wildcard");
        if (query.Tag is not null && InventoryValidation.NormalizeTag(query.Tag) is null)
            return InventoryQueryResult.Refused($"tag '{query.Tag}' is not a valid tag — query refused");

        var tag = query.Tag is null ? null : InventoryValidation.NormalizeTag(query.Tag);
        var matches = store.List(query.ScopeId).Where(r => Matches(r, query, tag, now)).ToList();
        return new InventoryQueryResult(true, null, matches);
    }

    private static bool Matches(DeviceInventoryRecord r, InventoryQuery q, string? tag, DateTimeOffset now)
    {
        if (q.SoftwareName is not null || q.VersionOp is not null)
        {
            var name = InventoryValidation.NormalizeSoftwareName(q.SoftwareName);
            // D38-F7: ANY install counts — with side-by-side installs,
            // "Acrobat < vX" must see the vulnerable 32-bit copy even
            // when a newer 64-bit copy is also present.
            var items = r.Software.Where(s =>
                string.Equals(s.NormalizedName, name, StringComparison.OrdinalIgnoreCase)).ToList();
            var op = q.VersionOp ?? VersionComparison.Present;
            var ok = op switch
            {
                VersionComparison.Present => items.Count > 0,
                VersionComparison.Absent => items.Count == 0,
                _ => items.Any(item => ApplyOp(SoftwareVersion.Compare(item.Version, q.Version!), op)),
            };
            if (!ok) return false;
        }
        if (q.OsBuild is not null &&
            !string.Equals(r.Hardware.OsBuild ?? "", q.OsBuild, StringComparison.OrdinalIgnoreCase)) return false;
        if (q.Manufacturer is not null &&
            !(r.Hardware.Manufacturer ?? "").Contains(q.Manufacturer, StringComparison.OrdinalIgnoreCase)) return false;
        if (tag is not null && !r.Tags.Contains(tag)) return false;
        if (q.CustomFieldKey is not null)
        {
            if (!r.CustomFields.TryGetValue(q.CustomFieldKey, out var value)) return false;
            if (q.CustomFieldValue is not null &&
                !string.Equals(value, q.CustomFieldValue, StringComparison.OrdinalIgnoreCase)) return false;
        }
        if (q.WarrantyExpiringWithinDays is { } days)
        {
            if (r.Warranty?.ExpiresUtc is not { } exp) return false;
            if (exp < now || exp > now.AddDays(days)) return false;
        }
        return true;
    }

    private static bool ApplyOp(int cmp, VersionComparison op) => op switch
    {
        VersionComparison.LessThan => cmp < 0,
        VersionComparison.LessOrEqual => cmp <= 0,
        VersionComparison.Equal => cmp == 0,
        VersionComparison.GreaterOrEqual => cmp >= 0,
        VersionComparison.GreaterThan => cmp > 0,
        _ => false,
    };
}

// ---- lifecycle / refresh reporting --------------------------------------

public sealed record RefreshCandidate(string DeviceId, string Reason);

/// <summary>The computed lifecycle view over the inventory data:
/// age cohorts (from purchase date, else first-seen), warranty
/// cohorts, OS-build distribution, and the refresh-candidate list
/// with a named reason per device. Pure computation over the store —
/// the reporting half of RMM-04 that IT forwards upward.</summary>
public sealed record FleetLifecycleReport(
    DateTimeOffset GeneratedUtc,
    int TotalDevices,
    int TotalUnmanagedAssets,
    IReadOnlyDictionary<string, int> AgeCohorts,
    IReadOnlyDictionary<string, int> WarrantyCohorts,
    IReadOnlyDictionary<string, int> OsBuildCounts,
    IReadOnlyList<RefreshCandidate> RefreshCandidates);

public static class LifecycleReporting
{
    public const int RefreshAgeYears = 5;

    public static FleetLifecycleReport Build(
        InventoryStore store, UnmanagedAssetRegister? unmanaged, DateTimeOffset now,
        int refreshAgeYears = RefreshAgeYears, string? scopeId = null,
        int warrantyWarningDays = 90)
    {
        // BD-SHARED-RMM-2/F12: a scopeId scopes BOTH the device list
        // and the unmanaged count — a company/MSP report must never
        // mix tenants. Null keeps the legacy whole-store shape.
        var records = store.List()
            .Where(r => scopeId is null || string.Equals(r.ScopeId, scopeId, StringComparison.OrdinalIgnoreCase))
            .ToList();
        var age = new Dictionary<string, int>
        {
            ["0-3y"] = 0, ["3-5y"] = 0, ["5y+"] = 0, ["unknown"] = 0,
        };
        var warranty = new Dictionary<string, int>
        {
            ["active"] = 0, ["expiring_90d"] = 0, ["expired"] = 0, ["unknown"] = 0,
        };
        var osBuilds = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var candidates = new List<RefreshCandidate>();

        foreach (var r in records)
        {
            var anchor = r.PurchaseDateUtc ?? r.FirstSeenUtc;
            var years = (now - anchor).TotalDays / 365.25;
            // BD-SHARED-RMM-2/F12: a future anchor (clock skew, bad
            // import) is not a newborn device — it buckets 'unknown',
            // the cohort that previously existed but was never
            // incremented.
            if (years < 0) { age["unknown"]++; years = 0; }
            else
            {
                var bucket = years < 3 ? "0-3y" : years < 5 ? "3-5y" : "5y+";
                age[bucket]++;
            }

            if (r.Warranty is null || r.Warranty.Status == WarrantyInfo.StatusUnknown || r.Warranty.ExpiresUtc is null)
                warranty["unknown"]++;
            else if (r.Warranty.ExpiresUtc < now || r.Warranty.Status == WarrantyInfo.StatusExpired)
                warranty["expired"]++;
            else if (r.Warranty.ExpiresUtc <= now.AddDays(warrantyWarningDays))
                warranty["expiring_90d"]++;
            else
                warranty["active"]++;

            // D38-F6 defense in depth: a null OsBuild (only possible
            // from a record that bypassed Normalize) buckets as
            // "unknown" instead of crashing the fleet report.
            var osBuildKey = r.Hardware.OsBuild ?? "unknown";
            osBuilds[osBuildKey] = osBuilds.GetValueOrDefault(osBuildKey) + 1;

            if (years >= refreshAgeYears)
                candidates.Add(new RefreshCandidate(r.DeviceId, $"age {years:F1}y >= {refreshAgeYears}y refresh threshold"));
            else if (r.Warranty is not null && r.Warranty.ExpiresUtc is { } exp && exp < now)
                candidates.Add(new RefreshCandidate(r.DeviceId, $"warranty expired {exp:yyyy-MM-dd}"));
        }

        return new FleetLifecycleReport(
            now, records.Count,
            scopeId is null ? (unmanaged?.List().Count ?? 0) : (unmanaged?.List(scopeId).Count ?? 0),
            age, warranty, osBuilds,
            candidates.OrderBy(c => c.DeviceId, StringComparer.Ordinal).ToList());
    }
}
