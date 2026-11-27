using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DeskGuest.Shared.Hub;
using DeskGuest.Shared.Inventory;
using DeskGuest.Shared.Reporting;

namespace DeskGuest.Shared.SoftwareMetering;

// =====================================================================
// RMM-26 — Software metering + licence-compliance reporting (local).
//
// A reporting pack over RMM-04 inventory data + admin-entered
// licence entitlements. It CONSUMES inventory (RMM-04 records are
// the install truth; this layer never re-collects) and rides the
// RMM-13 reporting shapes: every report carries an RMM-13
// ReportHeader whose provenance + staleness are COMPUTED from the
// inputs' own timestamps, and exports go through RMM-13's
// ReportExporter so no format sheds the header.
//
// HONESTY RULES (structural, not editorial — there is no code path
// that breaks them):
//   * An ENTITLEMENT is an admin-asserted CLAIM, not a measurement.
//     The model labels it so on every surface: the provenance source
//     is named "admin-asserted", and every entitlement value in a
//     report is a snapshot of the claim as it stood at generation.
//   * An install whose edition cannot be determined counts as
//     UNKNOWN EDITION. It is never silently absorbed into the
//     entitled edition, and it blocks a clean product delta.
//   * A product with installs but NO entitlement record reads
//     UNLICENSED-UNKNOWN with NO delta — never zero, never
//     "compliant".
//   * Reports are POINT-IN-TIME SNAPSHOTS. Entitlement edits and
//     deletions after generation never rewrite a stored report;
//     history is append-only in the entitlement store (deletion is
//     a tombstone revision, retained), so an over-licence finding
//     cannot be erased from history by deleting its entitlement.
//   * USAGE is reported only where a usage fact from a named
//     platform source exists. Install data is NEVER read as usage:
//     a product with no usage facts says "usage not measured".
//   * Staleness is per-device (inventory age) and in aggregate
//     (the header's inventory input rests on the OLDEST device, the
//     RMM-13 rule): a position computed from stale inventory says
//     so on its face.
// =====================================================================

/// <summary>TOTAL POLICY CONTROL keys for RMM-26. The RMM-07
/// registry seeds the feature toggle as "rmm.metering.enabled"
/// (default ON); the directive-named content key
/// "rmm.software_metering.enabled" is the same feature under the
/// register's fuller name — the Core service consults BOTH and
/// either one set false disables (fail closed on conflict).</summary>
public static class MeteringPolicyKeys
{
    public const string SoftwareMeteringEnabled = "rmm.software_metering.enabled";
    public const string RegistryToggle = "rmm.metering.enabled";

    public static readonly IReadOnlySet<string> All = new HashSet<string>
    {
        SoftwareMeteringEnabled, RegistryToggle,
    };

    /// <summary>Both keys default ON. An unknown key is refused
    /// (fail closed), the InventoryPolicyKeys.DefaultCheck pattern.</summary>
    public static readonly IReadOnlyDictionary<string, bool> Defaults =
        new Dictionary<string, bool>
        {
            [SoftwareMeteringEnabled] = true,
            [RegistryToggle] = true,
        };

    public static bool DefaultCheck(string key) =>
        key is not null && Defaults.TryGetValue(key, out var enabled) && enabled;
}

/// <summary>Named bounds for metering data. A value outside one is
/// refused by name — never clamped into plausibility.</summary>
public static class MeteringLimits
{
    public const int MaxSeatsPerEntitlement = 1_000_000; // beyond this is absurd, not generous
    public const int MaxProductLength = 256;
    public const int MaxEditionLength = 128;
    public const int MaxEvidenceNoteLength = 1024;
    public const int MaxEnteredByLength = 128;
    public const int MaxUsageSourceLength = 128;
    public const int EntitlementExpiryWarningDays = 90;

    /// <summary>How far ahead of the reader's clock a usage fact's
    /// timestamps may sit before the fact is refused as future-dated
    /// (RMM-26 F3). Small, named clock tolerance — not a window a
    /// forged fact can hide a position inside.</summary>
    public static readonly TimeSpan MaxUsageFutureSkew = TimeSpan.FromMinutes(5);
}

/// <summary>Position states for one product/edition line. The set
/// is closed: a line is always exactly one of these.</summary>
public static class LicenceStates
{
    public const string Compliant = "compliant";               // delta == 0
    // BD-SHARED-RMM-3/F11: the old names inverted standard
    // software-asset-management usage — installs ABOVE entitlement
    // (a compliance shortfall, the critical finding) were labelled
    // "over_licensed", which an auditor reads as spare licences.
    // The states are now named for what they ARE: deficit (installed
    // > entitled) and surplus (installed < entitled). The old
    // constant NAMES survive as aliases carrying the CORRECTED
    // values, so call sites compile unchanged and now emit the
    // honest strings.
    public const string Deficit = "deficit";                     // installed > effective entitled (shortfall)
    public const string Surplus = "surplus";                     // installed < entitled (unused seats)
    public const string OverLicensed = Deficit;                  // legacy alias — see F11 note above
    public const string UnderLicensed = Surplus;                 // legacy alias — see F11 note above
    public const string UnlicensedUnknown = "unlicensed_unknown"; // installs, no entitlement record — delta NOT computable
    public const string UnknownEdition = "unknown_edition";     // installs whose edition is undetermined
    public const string EntitledNotInstalled = "entitled_not_installed"; // entitlement, zero installs
}

// ---- entitlements (admin-asserted claims) ------------------------------

/// <summary>One licence entitlement AS ASSERTED BY AN ADMIN: what
/// the org claims to own (product, edition, seat/unit count,
/// expiry, evidence note). This is a claim entered by a person —
/// the type name and every report surface say so. Edition null
/// means the claim is product-wide (any edition of the product).
/// Revision is monotonic per Id; every revision is retained in the
/// store's history, including the deletion tombstone.</summary>
public sealed record LicenceEntitlement(
    string Id,
    string ScopeId,
    string Product,
    string? Edition,
    int Seats,
    DateTimeOffset? ExpiresUtc,
    string? EvidenceNote,
    string EnteredBy,
    DateTimeOffset EnteredUtc,
    long Revision,
    bool Deleted = false)
{
    /// <summary>The provenance label that rides every surface this
    /// value touches. An entitlement is asserted, never measured.</summary>
    public const string ProvenanceLabel = "admin-asserted claim (entered by an admin; not a measurement)";

    public string NormalizedProduct => InventoryValidation.NormalizeSoftwareName(Product);
    public string? NormalizedEdition => string.IsNullOrWhiteSpace(Edition) ? null : Edition.Trim();

    public bool IsExpired(DateTimeOffset now) => ExpiresUtc is { } e && e <= now;
}

/// <summary>Validation for an entitlement at admission. Returns the
/// refusal reason, or null when admissible. Negative, zero and
/// absurd seat counts refuse — a licence position built on a
/// negative entitlement is worse than no position.</summary>
public static class EntitlementValidation
{
    public static string? Validate(LicenceEntitlement? e)
    {
        if (e is null) return "no entitlement — refused";
        if (string.IsNullOrWhiteSpace(e.Id)) return "entitlement needs an id — refused";
        if (string.IsNullOrWhiteSpace(e.ScopeId)) return "entitlement needs a scope id — refused";
        if (string.IsNullOrWhiteSpace(e.Product) || e.Product.Trim().Length > MeteringLimits.MaxProductLength ||
            InventoryValidation.HasControlChars(e.Product))
            return "entitlement product is empty, over bounds, or control-charred — refused";
        if (e.Edition is not null && (e.Edition.Trim().Length > MeteringLimits.MaxEditionLength ||
            InventoryValidation.HasControlChars(e.Edition)))
            return "entitlement edition is over bounds or control-charred — refused";
        if (e.Edition is not null && string.Equals(e.Edition.Trim(),
                EditionClassifier.UnknownEditionLabel, StringComparison.OrdinalIgnoreCase))
            return $"entitlement edition '{EditionClassifier.UnknownEditionLabel}' is the reserved unknown-edition label — refused (an entitlement may not claim the unknown bucket; unknown is a verdict, not an edition)";
        if (e.Seats <= 0)
            return $"entitlement seats {e.Seats} is not positive — refused (a zero or negative entitlement is not a licence position)";
        if (e.Seats > MeteringLimits.MaxSeatsPerEntitlement)
            return $"entitlement seats {e.Seats} exceeds the absurdity bound {MeteringLimits.MaxSeatsPerEntitlement} — refused by name, never clamped";
        if (string.IsNullOrWhiteSpace(e.EnteredBy) || e.EnteredBy.Trim().Length > MeteringLimits.MaxEnteredByLength)
            return "entitlement needs an entering admin within bounds — refused (an unattributed claim is not admitted)";
        if (e.EvidenceNote is not null && (e.EvidenceNote.Length > MeteringLimits.MaxEvidenceNoteLength ||
            InventoryValidation.HasControlChars(e.EvidenceNote)))
            return "entitlement evidence note is over bounds or control-charred — refused";
        if (e.Revision < 1) return "entitlement revision must be >= 1 — refused";
        return null;
    }
}

/// <summary>The outcome of an entitlement import: how many
/// revisions were restored, how many were SKIPPED (invalid entries
/// and broken revision chains, refused whole per id), and why.
/// Skips are always counted and named — never silent (RMM-26 F4).</summary>
public sealed record EntitlementImportResult(int Restored, int Skipped, string Reason);

/// <summary>The entitlement store: current view + FULL append-only
/// history. Updates must name the revision they replace (a stale
/// editor cannot silently overwrite a newer claim); deletion is a
/// tombstone revision that stays in history forever, so deleting
/// an entitlement can hide it from FUTURE reports but never from
/// the record of what past reports rested on.
/// DURABILITY: this store is IN-MEMORY ONLY — nothing here survives
/// a process restart; persistence is hub integration work and is
/// NOT claimed by this build (RMM-26 F11).</summary>
public sealed class EntitlementStore
{
    private readonly Dictionary<string, LicenceEntitlement> _current = new(StringComparer.Ordinal);
    private readonly List<LicenceEntitlement> _history = new();
    private readonly object _gate = new();

    public (bool Ok, string Reason) Add(LicenceEntitlement? entitlement)
    {
        if (EntitlementValidation.Validate(entitlement) is { } invalid) return (false, invalid);
        var e = entitlement!;
        if (e.Revision != 1) return (false, $"new entitlement '{e.Id}' must enter at revision 1 (got {e.Revision}) — refused");
        if (e.Deleted) return (false, $"new entitlement '{e.Id}' cannot enter as deleted — refused");
        lock (_gate)
        {
            if (_current.ContainsKey(e.Id) || _history.Any(h => h.Id == e.Id))
                return (false, $"entitlement id '{e.Id}' already exists — refused (ids are never recycled; a recycled id would rewrite history)");
            var stored = e with { Product = e.Product.Trim(), Edition = e.NormalizedEdition, EnteredBy = e.EnteredBy.Trim() };
            _current[stored.Id] = stored;
            _history.Add(stored);
            return (true, $"entitlement '{stored.Id}' admitted at revision 1 ({LicenceEntitlement.ProvenanceLabel})");
        }
    }

    /// <summary>Replace the current claim for an id. The caller
    /// names the revision it edited FROM; a mismatch refuses, so
    /// two admins editing the same claim cannot lose each other's
    /// change silently. The superseded revision stays in history.</summary>
    public (bool Ok, string Reason) Update(LicenceEntitlement? next, long expectedRevision)
    {
        if (EntitlementValidation.Validate(next) is { } invalid) return (false, invalid);
        var e = next!;
        lock (_gate)
        {
            if (!_current.TryGetValue(e.Id, out var cur) || cur.Deleted)
                return (false, $"entitlement '{e.Id}' has no live current revision to update — refused");
            if (cur.Revision != expectedRevision)
                return (false, $"entitlement '{e.Id}' is at revision {cur.Revision}, not the expected {expectedRevision} — refused (stale edit; re-read and retry)");
            if (e.Revision != cur.Revision + 1)
                return (false, $"entitlement '{e.Id}' update must be revision {cur.Revision + 1} (got {e.Revision}) — refused");
            if (!string.Equals(e.ScopeId, cur.ScopeId, StringComparison.OrdinalIgnoreCase))
                return (false, $"entitlement '{e.Id}' cannot move scope on update — refused (delete and re-enter in the new scope, so history shows the move)");
            var stored = e with { Product = e.Product.Trim(), Edition = e.NormalizedEdition, EnteredBy = e.EnteredBy.Trim(), Deleted = false };
            _current[stored.Id] = stored;
            _history.Add(stored);
            return (true, $"entitlement '{stored.Id}' updated to revision {stored.Revision}; revision {cur.Revision} retained in history");
        }
    }

    /// <summary>Delete = tombstone. The current view loses the
    /// entitlement (future reports will show its installs as
    /// unlicensed-unknown, which is the honest consequence); the
    /// tombstone revision and every prior revision stay in
    /// history, so past reports remain explainable and a deletion
    /// can never erase an over-licence finding retroactively.</summary>
    public (bool Ok, string Reason) Delete(string id, string deletedBy, DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(deletedBy)) return (false, "deletion needs an acting admin — refused (an unattributed deletion is not admitted)");
        lock (_gate)
        {
            if (id is null || !_current.TryGetValue(id, out var cur) || cur.Deleted)
                return (false, $"entitlement '{id}' has no live current revision to delete — refused");
            var tombstone = cur with
            {
                Deleted = true,
                Revision = cur.Revision + 1,
                EnteredBy = deletedBy.Trim(),
                EnteredUtc = now,
            };
            _current[id] = tombstone;
            _history.Add(tombstone);
            return (true, $"entitlement '{id}' deleted at revision {tombstone.Revision} (tombstone retained in history; past reports are snapshots and do not change)");
        }
    }

    /// <summary>Live entitlements for a scope (tombstones excluded).</summary>
    public IReadOnlyList<LicenceEntitlement> Current(string? scopeId = null)
    {
        lock (_gate)
            return _current.Values
                .Where(e => !e.Deleted && (scopeId is null || string.Equals(e.ScopeId, scopeId, StringComparison.OrdinalIgnoreCase)))
                .OrderBy(e => e.NormalizedProduct, StringComparer.Ordinal)
                .ThenBy(e => e.NormalizedEdition ?? "", StringComparer.Ordinal).ToList();
    }

    /// <summary>Every revision ever admitted for an id, oldest
    /// first — including tombstones. This is the audit surface.</summary>
    public IReadOnlyList<LicenceEntitlement> History(string id)
    {
        lock (_gate)
            return _history.Where(h => string.Equals(h.Id, id, StringComparison.Ordinal))
                .OrderBy(h => h.Revision).ToList();
    }

    public IReadOnlyList<LicenceEntitlement> FullHistory
    {
        get { lock (_gate) return _history.OrderBy(h => h.Id, StringComparer.Ordinal).ThenBy(h => h.Revision).ToList(); }
    }

    // ---- persistence (explicit DTOs, house pattern) -------------------

    private sealed record EntitlementDto(
        string Id, string ScopeId, string Product, string? Edition, int Seats,
        DateTimeOffset? ExpiresUtc, string? EvidenceNote, string EnteredBy,
        DateTimeOffset EnteredUtc, long Revision, bool Deleted);

    private static EntitlementDto ToDto(LicenceEntitlement e) => new(
        e.Id, e.ScopeId, e.Product, e.Edition, e.Seats, e.ExpiresUtc, e.EvidenceNote,
        e.EnteredBy, e.EnteredUtc, e.Revision, e.Deleted);

    private static LicenceEntitlement FromDto(EntitlementDto d) => new(
        d.Id, d.ScopeId, d.Product, d.Edition, d.Seats, d.ExpiresUtc, d.EvidenceNote,
        d.EnteredBy, d.EnteredUtc, d.Revision, d.Deleted);

    /// <summary>Export carries the FULL history (tombstones
    /// included) — an export that dropped history would be a
    /// deletion channel.</summary>
    public string ExportJson()
    {
        lock (_gate) return JsonSerializer.Serialize(_history.Select(ToDto).ToList());
    }

    /// <summary>Restore into an EMPTY store. Every entry is
    /// re-validated, and every id's revisions must form an
    /// UNBROKEN chain 1..N with no duplicate (id, revision): a
    /// gapped or duplicated chain is refused WHOLE for that id —
    /// a partial chain would silently rewrite what the entitlement
    /// claimed at the revisions a stored report rests on. Every
    /// refusal is counted in the result's Skipped and named in its
    /// Reason — never silent (RMM-26 F4). Import never overwrites:
    /// a non-empty store refuses the whole payload.</summary>
    public EntitlementImportResult ImportJson(string json)
    {
        List<EntitlementDto>? dtos;
        try { dtos = JsonSerializer.Deserialize<List<EntitlementDto>>(json); }
        catch { return new EntitlementImportResult(0, 0, "import refused: payload is not a valid entitlement export (unparseable) — nothing restored"); }
        if (dtos is null) return new EntitlementImportResult(0, 0, "import refused: payload is empty — nothing restored");
        lock (_gate)
        {
            if (_history.Count > 0)
                return new EntitlementImportResult(0, dtos.Count(d => d is not null),
                    "import refused: the store already holds history — import is a restore into an EMPTY store, never a merge over live history; nothing restored");
            var skipped = dtos.Count(d => d is null);
            var restored = 0;
            foreach (var g in dtos.Where(d => d is not null)
                         .GroupBy(d => d.Id, StringComparer.Ordinal))
            {
                var entries = g.OrderBy(d => d.Revision).ToList();
                var chainOk = entries.Select((d, i) => d.Revision == i + 1).All(x => x);
                if (!chainOk) { skipped += entries.Count; continue; }
                var admitted = new List<LicenceEntitlement>();
                var valid = true;
                foreach (var dto in entries)
                {
                    LicenceEntitlement e;
                    try { e = FromDto(dto); } catch { valid = false; break; }
                    if (EntitlementValidation.Validate(e) is not null) { valid = false; break; }
                    admitted.Add(e);
                }
                if (!valid) { skipped += entries.Count; continue; }
                _history.AddRange(admitted);
                restored += admitted.Count;
            }
            // Current view = the highest revision per id.
            foreach (var g in _history.GroupBy(h => h.Id, StringComparer.Ordinal))
                _current[g.Key] = g.OrderByDescending(h => h.Revision).First();
            return new EntitlementImportResult(restored, skipped,
                $"import complete: {restored} revision(s) restored, {skipped} skipped (invalid entries and gapped/duplicate revision chains are refused whole per id and counted — never silently dropped)");
        }
    }
}

// ---- edition classification ---------------------------------------------

/// <summary>One admin-registered edition rule: installs of a
/// product whose VERSION falls in [MinVersion, MaxVersionExclusive)
/// (either bound optional) belong to the named edition. Rules are
/// the ONLY source of edition knowledge: inventory (RMM-04) carries
/// name + version + publisher, no edition — so without a matching
/// rule an install's edition is UNKNOWN, and the report says so.
/// Overlapping rules resolve to the FIRST registered match
/// (registration order is the admin's stated precedence, and the
/// classifier reports which rule decided).</summary>
public sealed record EditionRule(string Product, string Edition, string? MinVersion = null, string? MaxVersionExclusive = null)
{
    public string NormalizedProduct => InventoryValidation.NormalizeSoftwareName(Product);
}

public sealed class EditionClassifier
{
    private readonly List<EditionRule> _rules = new();
    private readonly object _gate = new();

    public (bool Ok, string Reason) AddRule(EditionRule? rule)
    {
        if (rule is null) return (false, "no edition rule — refused");
        if (string.IsNullOrWhiteSpace(rule.Product) || rule.Product.Trim().Length > MeteringLimits.MaxProductLength)
            return (false, "edition rule needs a product within bounds — refused");
        if (string.IsNullOrWhiteSpace(rule.Edition) || rule.Edition.Trim().Length > MeteringLimits.MaxEditionLength)
            return (false, "edition rule needs an edition label within bounds — refused");
        if (string.Equals(rule.Edition.Trim(), EditionClassifier.UnknownEditionLabel, StringComparison.OrdinalIgnoreCase))
            return (false, $"edition rule may not name the reserved label '{EditionClassifier.UnknownEditionLabel}' — refused (unknown is a verdict, not an edition)");
        lock (_gate) _rules.Add(rule with { Product = rule.Product.Trim(), Edition = rule.Edition.Trim() });
        return (true, $"edition rule admitted: '{rule.Product.Trim()}' [{rule.MinVersion ?? "-"}..{rule.MaxVersionExclusive ?? "-"}) -> '{rule.Edition.Trim()}'");
    }

    public IReadOnlyList<EditionRule> Rules
    {
        get { lock (_gate) return _rules.ToList(); }
    }

    public const string UnknownEditionLabel = "UNKNOWN";

    /// <summary>The edition of one install, or null when no rule
    /// determines it (the caller buckets null as UNKNOWN — never as
    /// any entitled edition). An EMPTY or unparsable version
    /// determines NOTHING (RMM-26 F6): SoftwareVersion.Parse only
    /// orders versions that begin with a digit; anything else falls
    /// back to raw string order, under which "" sorts below every
    /// bound and would slip into max-only rules — a versionless
    /// install classified by accident. Unclassifiable is UNKNOWN.</summary>
    public string? Classify(string product, string? version)
    {
        var v = (version ?? "").Trim();
        if (v.Length == 0 || !char.IsDigit(v[0])) return null;
        var key = InventoryValidation.NormalizeSoftwareName(product);
        lock (_gate)
        {
            foreach (var rule in _rules)
            {
                if (!string.Equals(rule.NormalizedProduct, key, StringComparison.OrdinalIgnoreCase)) continue;
                if (rule.MinVersion is not null && SoftwareVersion.Compare(v, rule.MinVersion) < 0) continue;
                if (rule.MaxVersionExclusive is not null && SoftwareVersion.Compare(v, rule.MaxVersionExclusive) >= 0) continue;
                return rule.Edition;
            }
        }
        return null;
    }
}

// ---- usage facts (the honest subset) -------------------------------------

/// <summary>One usage fact: a NAMED platform source reports that a
/// product on a device was last used at a time. This is the only
/// usage input metering accepts. Inventory install dates are NOT
/// usage and are never read as such — an install with no usage
/// fact is "not measured", full stop.</summary>
public sealed record SoftwareUsageFact(
    string DeviceId,
    string Product,
    string Source,
    DateTimeOffset LastUsedUtc,
    DateTimeOffset CollectedUtc)
{
    public string NormalizedProduct => InventoryValidation.NormalizeSoftwareName(Product);

    /// <summary>Validate against the reader's clock (RMM-26 F3):
    /// a fact whose collection OR last-used time sits beyond
    /// now + the named skew is future-dated and refused — without
    /// a `now` check, a future LastUsedUtc also silently reads as
    /// "recently used" forever in the unused-software test.</summary>
    public string? Validate(DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(DeviceId)) return "usage fact needs a device id — refused";
        if (string.IsNullOrWhiteSpace(Product) || Product.Trim().Length > MeteringLimits.MaxProductLength)
            return "usage fact needs a product within bounds — refused";
        if (string.IsNullOrWhiteSpace(Source) || Source.Trim().Length > MeteringLimits.MaxUsageSourceLength)
            return "usage fact needs a NAMED source within bounds — refused (anonymous usage is not measured usage)";
        if (LastUsedUtc > CollectedUtc)
            return "usage fact claims a last-used time after its own collection time — refused (a fact from the future is not a fact)";
        if (CollectedUtc > now + MeteringLimits.MaxUsageFutureSkew)
            return "usage fact claims a collection time in the future — refused (a fact from the future is not a fact)";
        if (LastUsedUtc > now + MeteringLimits.MaxUsageFutureSkew)
            return "usage fact claims a last-used time in the future — refused (a fact from the future is not a fact)";
        return null;
    }
}

/// <summary>Per-product usage summary inside a position line.
/// State is one of measured / partially_measured / not_measured,
/// computed from fact coverage of the product's installs — never
/// from install data.</summary>
public sealed record UsageSummary(
    string State,
    int MeasuredInstalls,
    int UnmeasuredInstalls,
    int UnusedMeasuredInstalls,
    string Note)
{
    public const string StateMeasured = "measured";
    public const string StatePartial = "partially_measured";
    public const string StateNotMeasured = "not_measured";
    public const string NotMeasuredNote = "usage not measured";
}

// ---- the position report --------------------------------------------------

/// <summary>One device's staleness inside a report: when its
/// inventory was last seen, how old that is at generation, and the
/// verdict against the RMM-13 inventory bound.</summary>
public sealed record DeviceStaleness(
    string DeviceId, DateTimeOffset InventoryAsOfUtc, double AgeHours, bool IsStale);

/// <summary>One product(/edition) line of the position: the
/// entitlement snapshot it rests on (ids + revisions + seats AS
/// THEY STOOD at generation), the install position from inventory,
/// and the delta — null whenever a delta is not honestly
/// computable (no entitlement, or unknown-edition installs that no
/// product-wide claim covers).</summary>
public sealed record LicencePositionLine(
    string Product,
    string? Edition,                 // null = product-wide line / unknown-edition line (see State)
    bool IsUnknownEditionLine,
    IReadOnlyList<string> EntitlementRefs,  // "id@rN" snapshots this line rests on
    int? EntitledSeats,              // as asserted (null = no entitlement record)
    int EffectiveEntitledSeats,      // expired claims contribute 0
    bool HasExpiredEntitlement,
    int InstalledCount,
    int DeviceCount,
    int? Delta,                      // EffectiveEntitledSeats - InstalledCount, when computable
    string State,
    UsageSummary Usage,
    int StaleDeviceInstalls)         // installs resting on stale inventory
{
    public IReadOnlyList<string> EntitlementRefs { get; init; } = EntitlementRefs ?? Array.Empty<string>();
}

/// <summary>One report finding: over/under-licence, unlicensed
/// product, unknown editions, expiring/expired claims, stale
/// inventory, unmeasured or unused software. Findings are part of
/// the snapshot — they are computed at generation and frozen.</summary>
public sealed record LicenceFinding(string Kind, string Severity, string Product, string? Edition, string Detail)
{
    // BD-SHARED-RMM-3/F11: finding kinds renamed with the states.
    public const string KindDeficit = "deficit";
    public const string KindSurplus = "surplus";
    public const string KindOverLicensed = KindDeficit;          // legacy alias
    public const string KindUnderLicensed = KindSurplus;         // legacy alias
    public const string KindUnlicensedUnknown = "unlicensed_unknown";
    public const string KindUnknownEdition = "unknown_edition_installs";
    public const string KindEntitlementExpired = "entitlement_expired";
    public const string KindEntitlementExpiring = "entitlement_expiring";
    public const string KindStaleInventory = "stale_inventory";
    public const string KindClockSkew = "clock_skew";
    public const string KindUsageNotMeasured = "usage_not_measured";
    public const string KindUnusedSoftware = "unused_software";
    public const string SeverityCritical = "critical";
    public const string SeverityWarning = "warning";
    public const string SeverityInfo = "info";
}

/// <summary>The licence position report: a point-in-time, immutable
/// snapshot. It snapshots entitlement VALUES (not references into
/// the live store), so later edits/deletions cannot rewrite it.
/// ContentHash is an UNKEYED SHA-256 CHECKSUM over the canonical
/// form (RMM-26 F8): it proves a stored snapshot still matches its
/// contents, but anyone can recompute it, so it is NOT proof of
/// origin. Its trust anchor is the generation event in the hub's
/// hash-chained audit log, which records the hash VALUE at
/// generation time — a forged snapshot must also forge the chain.</summary>
public sealed record LicencePositionReport(
    ReportHeader Header,
    IReadOnlyList<LicencePositionLine> Lines,
    IReadOnlyList<LicenceFinding> Findings,
    IReadOnlyList<DeviceStaleness> Devices,
    IReadOnlyList<string> Notes,
    string ContentHash)
{
    public IReadOnlyList<LicencePositionLine> Lines { get; init; } = Lines ?? Array.Empty<LicencePositionLine>();
    public IReadOnlyList<LicenceFinding> Findings { get; init; } = Findings ?? Array.Empty<LicenceFinding>();
    public IReadOnlyList<DeviceStaleness> Devices { get; init; } = Devices ?? Array.Empty<DeviceStaleness>();
    public IReadOnlyList<string> Notes { get; init; } = Notes ?? Array.Empty<string>();

    public int StaleDeviceCount => Devices.Count(d => d.IsStale);
    public bool HasStaleInventory => StaleDeviceCount > 0;

    /// <summary>Recompute the content hash over the canonical form
    /// and compare — a stored report whose lines were tampered with
    /// after generation fails here.</summary>
    public bool VerifyContentHash() =>
        string.Equals(ContentHash, ComputeContentHash(Header, Lines, Findings, Devices, Notes), StringComparison.Ordinal);

    internal static string ComputeContentHash(ReportHeader header,
        IReadOnlyList<LicencePositionLine> lines, IReadOnlyList<LicenceFinding> findings,
        IReadOnlyList<DeviceStaleness> devices, IReadOnlyList<string> notes)
    {
        var sb = new StringBuilder();
        sb.Append(header.ReportId).Append('|').Append(header.Kind).Append('|')
          .Append(header.ScopeId).Append('|').Append(header.GeneratedUtc.ToString("O")).Append('\n');
        // Header INPUTS are content too (RMM-26 F8): a snapshot
        // whose provenance/staleness basis was rewritten after
        // generation must fail verification just like a tampered line.
        foreach (var i in header.Inputs)
            sb.Append("I|").Append(i.Source).Append('|').Append(i.DataAsOfUtc?.ToString("O") ?? "-").Append('|')
              .Append(i.StaleAfter.Ticks).Append('|').Append(i.Present).Append('\n');
        foreach (var l in lines)
        {
            sb.Append("L|").Append(l.Product).Append('|').Append(l.Edition ?? "(pw)").Append('|')
              .Append(l.IsUnknownEditionLine).Append('|').Append(string.Join(",", l.EntitlementRefs)).Append('|')
              .Append(l.EntitledSeats?.ToString() ?? "-").Append('|').Append(l.EffectiveEntitledSeats).Append('|')
              .Append(l.HasExpiredEntitlement).Append('|').Append(l.InstalledCount).Append('|')
              .Append(l.DeviceCount).Append('|').Append(l.Delta?.ToString() ?? "-").Append('|')
              .Append(l.State).Append('|').Append(l.StaleDeviceInstalls).Append('|')
              .Append(l.Usage.State).Append('|').Append(l.Usage.MeasuredInstalls).Append('|')
              .Append(l.Usage.UnmeasuredInstalls).Append('|').Append(l.Usage.UnusedMeasuredInstalls).Append('|')
              .Append(l.Usage.Note).Append('\n');
        }
        foreach (var f in findings)
            sb.Append("F|").Append(f.Kind).Append('|').Append(f.Severity).Append('|')
              .Append(f.Product).Append('|').Append(f.Edition ?? "-").Append('|').Append(f.Detail).Append('\n');
        foreach (var d in devices)
            sb.Append("D|").Append(d.DeviceId).Append('|').Append(d.InventoryAsOfUtc.ToString("O")).Append('|')
              .Append(d.AgeHours.ToString("R", CultureInfo.InvariantCulture)).Append('|')
              .Append(d.IsStale).Append('\n');
        foreach (var n in notes) sb.Append("N|").Append(n).Append('\n');
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(sb.ToString()))).ToLowerInvariant();
    }

    /// <summary>Render through the RMM-13 report shapes so the
    /// licence position exports (json/csv/text) with the computed
    /// provenance + staleness header intact, via ReportExporter.</summary>
    public HubReport ToHubReport()
    {
        var counts = new Dictionary<string, long>
        {
            ["products"] = Lines.Select(l => l.Product).Distinct(StringComparer.OrdinalIgnoreCase).Count(),
            ["lines"] = Lines.Count,
            ["entitled_seats"] = Lines.Sum(l => (long)(l.EntitledSeats ?? 0)),
            ["installed"] = Lines.Sum(l => (long)l.InstalledCount),
            ["deficit_lines"] = Lines.Count(l => l.State == LicenceStates.Deficit),
            ["unlicensed_unknown_lines"] = Lines.Count(l => l.State == LicenceStates.UnlicensedUnknown),
            ["unknown_edition_installs"] = Lines.Where(l => l.IsUnknownEditionLine).Sum(l => (long)l.InstalledCount),
            ["findings"] = Findings.Count,
            ["devices"] = Devices.Count,
            ["stale_devices"] = StaleDeviceCount,
        };
        var rows = Lines.Select(l => (IReadOnlyList<string>)new[]
        {
            l.Product, l.IsUnknownEditionLine ? EditionClassifier.UnknownEditionLabel : l.Edition ?? "(product-wide)",
            l.EntitledSeats?.ToString() ?? "(no entitlement record)",
            // Effective seats on a row with NO entitlement record is
            // not "0" (RMM-26 F12a): 0 would read as a measured zero
            // position; the honest render is the same no-record label.
            l.EntitledSeats is null ? "(no entitlement record)" : l.EffectiveEntitledSeats.ToString(),
            l.InstalledCount.ToString(),
            l.Delta?.ToString() ?? "(not computable)", l.State,
            l.Usage.State, string.Join(",", l.EntitlementRefs),
        }).ToList();
        var notes = new List<string>(Notes)
        {
            $"entitlements are {LicenceEntitlement.ProvenanceLabel}",
        };
        notes.AddRange(Findings.Select(f => $"finding[{f.Kind}/{f.Severity}] {f.Product}: {f.Detail}"));
        return new HubReport(Header, counts,
            new[] { "product", "edition", "entitled_seats_asserted", "effective_entitled", "installed", "delta", "state", "usage", "entitlement_refs" },
            rows, notes);
    }
}

/// <summary>The report store: generated reports, by id, immutable.
/// A report is stored exactly as generated; there is no update or
/// delete path — history cannot be rewritten through this store.
/// Store enforces that in code, not just in this comment (RMM-26
/// F2): an id that is already stored is REFUSED, never overwritten,
/// and a report whose content checksum does not verify is never
/// stored at all.
/// DURABILITY: export/import through the HubPersistence envelope
/// (BD-SHARED-RMM-3/F12); the host persists the export and restores
/// it at start.</summary>
public sealed class LicenceReportStore
{
    /// <summary>W3 host wiring: raised after every committed
    /// store/import so CoreRuntime can write the store through
    /// to disk.</summary>
    public event Action? Changed;

    private readonly Dictionary<string, LicencePositionReport> _reports = new(StringComparer.Ordinal);
    private readonly object _gate = new();

    public (bool Ok, string Reason) Store(LicencePositionReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        if (!report.VerifyContentHash())
            return (false, $"report '{report.Header.ReportId}' refused: its content checksum does not verify — a snapshot that fails its own integrity check is never stored");
        lock (_gate)
        {
            if (_reports.ContainsKey(report.Header.ReportId))
                return (false, $"report '{report.Header.ReportId}' is already stored — refused (stored reports are immutable; a second store under the same id never overwrites the snapshot)");
            _reports[report.Header.ReportId] = report;
            Changed?.Invoke();
            return (true, $"report '{report.Header.ReportId}' stored");
        }
    }

    public LicencePositionReport? Get(string reportId)
    {
        lock (_gate) return reportId is not null && _reports.TryGetValue(reportId, out var r) ? r : null;
    }

    // ---- durability (BD-SHARED-RMM-3/F12) --------------------------
    // The store was IN-MEMORY ONLY, so a restart lost licence-report
    // history. Reports now round-trip through the HubPersistence
    // envelope; every restored report must pass Store()'s own
    // content-hash verification and id-immutability, exactly as a
    // freshly generated one does.

    public string ExportJson()
    {
        lock (_gate)
            return HubPersistence.Wrap("deskguest-licence-reports-v1",
                JsonSerializer.Serialize(_reports.Values.OrderBy(r => r.Header.ReportId, StringComparer.Ordinal).ToList()));
    }

    /// <summary>Restore reports. Returns how many were admitted;
    /// reports failing their content hash, or duplicating a standing
    /// id, are refused by name in the count's complement.</summary>
    public int ImportJson(string json)
    {
        var payload = HubPersistence.Unwrap(json, "deskguest-licence-reports-v1");
        if (payload is null) return 0;
        List<LicencePositionReport>? reports;
        try { reports = JsonSerializer.Deserialize<List<LicencePositionReport>>(payload); } catch { return 0; }
        if (reports is null) return 0;
        var admitted = 0;
        foreach (var r in reports)
            if (r is not null && Store(r).Ok) admitted++;
        return admitted; // Store() raises Changed per admitted report
    }

    public IReadOnlyList<LicencePositionReport> List(string? scopeId = null)
    {
        lock (_gate)
            return _reports.Values
                .Where(r => scopeId is null || string.Equals(r.Header.ScopeId, scopeId, StringComparison.OrdinalIgnoreCase))
                .OrderBy(r => r.Header.GeneratedUtc).ToList();
    }
}

// ---- alert-centre seam (RMM-01 shapes, compose don't fork) ----------------

/// <summary>The licence-finding alert event shape for the RMM-01
/// alert centre — the seam pattern RMM-04 set with
/// SerialConflictAlertEvent: raised from a generated report only;
/// wiring it into the centre is hub integration work.</summary>
public sealed record LicenceFindingAlertEvent(
    string Product, string? Edition, string Kind, string Severity, string Detail, DateTimeOffset RaisedUtc);

/// <summary>The finding sink: over/under-licence findings surface
/// here (and optionally onward to RMM-01's centre via the event
/// shape above). The recording double is the contract.</summary>
public interface ILicenceFindingSink
{
    void OnFinding(LicenceFindingAlertEvent alert, DateTimeOffset now);
}

public sealed class RecordingLicenceFindingSink : ILicenceFindingSink
{
    public List<LicenceFindingAlertEvent> Alerts { get; } = new();
    public void OnFinding(LicenceFindingAlertEvent alert, DateTimeOffset now) => Alerts.Add(alert);
}

// ---- the builder -------------------------------------------------------------

public static class LicencePositionBuilder
{
    public const string ReportKind = "licence_position";
    public const string EntitlementsSource = "rmm26.entitlements (admin-asserted claims, not measurements)";
    public const string InventorySource = "rmm04.inventory";

    /// <summary>Build the position report. Pure: same inputs, same
    /// report (modulo the generated id). Duplicate device records
    /// in the input collapse by RMM-04 identity (device id): the
    /// highest-Revision record wins (ties: latest LastSeenUtc) and
    /// the collapse is NAMED in the notes with its count — the same
    /// install is never counted twice. Within a device, duplicate
    /// installs collapse by install identity (name+version+
    /// publisher): the reporting SOURCE is provenance, not identity,
    /// so the same install reported by two sources is one install
    /// (RMM-26 F9).</summary>
    public static LicencePositionReport Build(
        IReadOnlyList<LicenceEntitlement> entitlements,
        IReadOnlyList<DeviceInventoryRecord> inventory,
        EditionClassifier classifier,
        IReadOnlyList<SoftwareUsageFact>? usageFacts,
        string scopeId, DateTimeOffset now,
        TimeSpan? inventoryStaleAfter = null, TimeSpan? unusedAfter = null)
    {
        entitlements ??= Array.Empty<LicenceEntitlement>();
        inventory ??= Array.Empty<DeviceInventoryRecord>();
        classifier ??= new EditionClassifier();
        var staleBound = inventoryStaleAfter ?? ReportingStaleness.Inventory;
        var unusedBound = unusedAfter ?? TimeSpan.FromDays(90);

        var notes = new List<string>();

        // -- dedupe devices by identity (RMM-04: identity is the device id)
        var byDevice = new Dictionary<string, DeviceInventoryRecord>(StringComparer.OrdinalIgnoreCase);
        var collapsedDevices = 0;
        var blankDeviceRecords = 0;
        foreach (var rec in inventory)
        {
            // A blank device id is NOT a duplicate (RMM-26 F12b): it
            // is an invalid record that cannot be attributed to any
            // device, counted and named separately — never folded
            // silently into the duplicate-collapse count.
            if (rec is null || string.IsNullOrWhiteSpace(rec.DeviceId)) { blankDeviceRecords++; continue; }
            if (!byDevice.TryGetValue(rec.DeviceId, out var kept)) { byDevice[rec.DeviceId] = rec; continue; }
            collapsedDevices++;
            if (rec.Revision > kept.Revision ||
                (rec.Revision == kept.Revision && rec.LastSeenUtc > kept.LastSeenUtc))
                byDevice[rec.DeviceId] = rec;
        }
        if (collapsedDevices > 0)
            notes.Add($"duplicate inventory records collapsed by device identity: {collapsedDevices} record(s) dropped — the surviving record per device is the highest revision (ties: latest last-seen); no install is counted twice");
        if (blankDeviceRecords > 0)
            notes.Add($"inventory records with a blank device id dropped as INVALID: {blankDeviceRecords} — they are not duplicates and none of their installs is counted (a record that cannot name its device cannot be attributed)");

        var devices = byDevice.Values.OrderBy(r => r.DeviceId, StringComparer.Ordinal).ToList();
        // A future-dated last-seen is NOT fresh (RMM-26 F12c): its
        // age would clamp to 0 and present a skewed or forged
        // timestamp as perfect freshness. It counts as not-fresh
        // and is named by a clock-skew finding below.
        var deviceStaleness = devices.Select(r => new DeviceStaleness(
            r.DeviceId, r.LastSeenUtc, Math.Max(0, (now - r.LastSeenUtc).TotalHours),
            r.LastSeenUtc > now || now - r.LastSeenUtc > staleBound)).ToList();
        var staleDeviceIds = new HashSet<string>(
            deviceStaleness.Where(d => d.IsStale).Select(d => d.DeviceId), StringComparer.OrdinalIgnoreCase);

        // -- usage facts: validated, invalid dropped AND counted
        var usageByKey = new Dictionary<string, SoftwareUsageFact>(StringComparer.OrdinalIgnoreCase);
        var droppedUsage = 0;
        foreach (var fact in usageFacts ?? Array.Empty<SoftwareUsageFact>())
        {
            if (fact is null || fact.Validate(now) is not null) { droppedUsage++; continue; }
            var key = $"{fact.DeviceId}|{fact.NormalizedProduct}";
            if (!usageByKey.TryGetValue(key, out var kept) || fact.LastUsedUtc > kept.LastUsedUtc)
                usageByKey[key] = fact;
        }
        if (droppedUsage > 0)
            notes.Add($"usage facts dropped as invalid: {droppedUsage} (unnamed source, future-dated, or malformed — dropped, never repaired)");

        // -- installs per product/edition
        // install entry: (product, editionLabelOrNull, deviceId)
        var installs = new List<(string Product, string? Edition, string DeviceId)>();
        var collapsedInstalls = 0;
        foreach (var rec in devices)
        {
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var item in rec.Software ?? Array.Empty<SoftwareItem>())
            {
                if (item is null || string.IsNullOrWhiteSpace(item.Name)) continue;
                // Install identity is name+version+publisher (RMM-26
                // F9): the reporting source is provenance, not
                // identity — the same install seen by two sources is
                // ONE install — and the publisher is compared trimmed.
                var exactKey = $"{item.NormalizedName}|{(item.Version ?? "").Trim()}|{(item.Publisher ?? "").Trim()}";
                if (!seen.Add(exactKey)) { collapsedInstalls++; continue; }
                installs.Add((item.NormalizedName, classifier.Classify(item.NormalizedName, item.Version), rec.DeviceId));
            }
        }
        if (collapsedInstalls > 0)
            notes.Add($"exact-duplicate installs within a device collapsed: {collapsedInstalls} (identity is name+version+publisher — the same install reported by multiple sources is counted once; distinct versions/installs are kept)");

        // -- entitlements grouped per product
        var liveEntitlements = entitlements.Where(e => e is not null && !e.Deleted).ToList();
        var entByProduct = liveEntitlements
            .GroupBy(e => e.NormalizedProduct, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.ToList(), StringComparer.OrdinalIgnoreCase);
        var installByProduct = installs
            .GroupBy(i => i.Product, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.ToList(), StringComparer.OrdinalIgnoreCase);

        var products = entByProduct.Keys.Union(installByProduct.Keys, StringComparer.OrdinalIgnoreCase)
            .OrderBy(p => p, StringComparer.Ordinal).ToList();

        var lines = new List<LicencePositionLine>();
        var findings = new List<LicenceFinding>();

        UsageSummary UsageFor(string product, List<(string Product, string? Edition, string DeviceId)> productInstalls)
        {
            var measured = 0; var unused = 0;
            foreach (var inst in productInstalls)
            {
                if (usageByKey.TryGetValue($"{inst.DeviceId}|{product}", out var fact))
                {
                    measured++;
                    if (now - fact.LastUsedUtc > unusedBound) unused++;
                }
            }
            var unmeasured = productInstalls.Count - measured;
            var state = productInstalls.Count == 0 || measured == 0
                ? UsageSummary.StateNotMeasured
                : unmeasured == 0 ? UsageSummary.StateMeasured : UsageSummary.StatePartial;
            var note = state == UsageSummary.StateNotMeasured
                ? UsageSummary.NotMeasuredNote + " — no usage fact from a named platform source covers these installs; install data is not usage and is never read as such"
                : $"usage measured for {measured} of {productInstalls.Count} install(s) from named platform source(s); {unused} measured install(s) unused for over {unusedBound.TotalDays:F0} days";
            return new UsageSummary(state, measured, unmeasured, unused, note);
        }

        LicencePositionLine MakeLine(string product, string? edition, bool unknownLine,
            List<LicenceEntitlement> ents, List<(string Product, string? Edition, string DeviceId)> lineInstalls,
            UsageSummary usage)
        {
            var refs = ents.Select(e => $"{e.Id}@r{e.Revision}").OrderBy(x => x, StringComparer.Ordinal).ToList();
            int? entitled = ents.Count == 0 ? null : ents.Sum(e => e.Seats);
            var hasExpired = ents.Any(e => e.IsExpired(now));
            var effective = ents.Where(e => !e.IsExpired(now)).Sum(e => e.Seats);
            int? delta = entitled is null ? null : effective - lineInstalls.Count;
            string state;
            if (unknownLine) state = LicenceStates.UnknownEdition;
            else if (entitled is null) state = LicenceStates.UnlicensedUnknown;
            else if (lineInstalls.Count == 0) state = LicenceStates.EntitledNotInstalled;
            else if (delta!.Value < 0) state = LicenceStates.OverLicensed;
            else if (delta.Value > 0) state = LicenceStates.UnderLicensed;
            else state = LicenceStates.Compliant;
            var staleInstalls = lineInstalls.Count(i => staleDeviceIds.Contains(i.DeviceId));
            return new LicencePositionLine(product, edition, unknownLine, refs, entitled, effective,
                hasExpired, lineInstalls.Count,
                lineInstalls.Select(i => i.DeviceId).Distinct(StringComparer.OrdinalIgnoreCase).Count(),
                delta, state, usage, staleInstalls);
        }

        foreach (var product in products)
        {
            var ents = entByProduct.GetValueOrDefault(product) ?? new List<LicenceEntitlement>();
            var productInstalls = installByProduct.GetValueOrDefault(product)
                ?? new List<(string Product, string? Edition, string DeviceId)>();
            // Usage is a PER-LINE fact (RMM-26 F10): each line's
            // summary is computed from ITS OWN installs, never the
            // product-wide summary pasted onto every line. The
            // product-wide summary is kept only for the product-
            // level usage findings below.
            var productUsage = UsageFor(product, productInstalls);
            var productWide = ents.Where(e => e.NormalizedEdition is null).ToList();
            var editionEnts = ents.Where(e => e.NormalizedEdition is not null)
                .GroupBy(e => e.NormalizedEdition!, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(g => g.Key, g => g.ToList(), StringComparer.OrdinalIgnoreCase);
            var knownInstalls = productInstalls.Where(i => i.Edition is not null).ToList();
            var unknownInstalls = productInstalls.Where(i => i.Edition is null).ToList();
            var coveredEditions = new HashSet<string>(editionEnts.Keys, StringComparer.OrdinalIgnoreCase);

            // Edition-specific lines. An edition gets its own line
            // when it has its own entitlement — or, when there is NO
            // product-wide claim, when it has installs (which then
            // read unlicensed-unknown). When a product-wide claim
            // exists, installs in editions WITHOUT their own claim
            // belong solely to the product-wide remainder line
            // below: an install must appear in exactly ONE line, or
            // the report's totals double-count it.
            var editionNames = editionEnts.Keys
                .Union(productWide.Count == 0
                    ? knownInstalls.Select(i => i.Edition!)
                    : Array.Empty<string>(), StringComparer.OrdinalIgnoreCase)
                .OrderBy(x => x, StringComparer.Ordinal).ToList();
            foreach (var edition in editionNames)
            {
                var lineInstalls = knownInstalls.Where(i => string.Equals(i.Edition, edition, StringComparison.OrdinalIgnoreCase)).ToList();
                lines.Add(MakeLine(product, edition, false,
                    editionEnts.GetValueOrDefault(edition) ?? new List<LicenceEntitlement>(), lineInstalls,
                    UsageFor(product, lineInstalls)));
            }

            // Product-wide claim covers what edition-specific claims
            // do not: installs in editions with no own entitlement,
            // plus unknown-edition installs (the claim is for the
            // product, any edition — unknown edition is still this
            // product). The remainder is NAMED, never silent.
            if (productWide.Count > 0)
            {
                var remainder = productInstalls
                    .Where(i => i.Edition is null || !coveredEditions.Contains(i.Edition!)).ToList();
                lines.Add(MakeLine(product, null, false, productWide, remainder, UsageFor(product, remainder)));
                if (unknownInstalls.Count > 0)
                    notes.Add($"product '{product}': {unknownInstalls.Count} unknown-edition install(s) are counted against the product-wide entitlement only because that claim is edition-agnostic; they are NOT attributed to any specific edition");
            }
            else if (unknownInstalls.Count > 0)
            {
                // THE edition-laundering wall: unknown installs get
                // their own line, entitled = null, delta = null.
                lines.Add(MakeLine(product, null, true, new List<LicenceEntitlement>(), unknownInstalls,
                    UsageFor(product, unknownInstalls)));
            }

            // Product with installs but no entitlement at all: the
            // known-edition lines above already carry
            // UnlicensedUnknown (entitled null); make sure a product
            // whose ONLY installs are unknown still names the state.
            // (Handled by the lines themselves — no extra line.)

            // ---- findings for this product
            foreach (var line in lines.Where(l => string.Equals(l.Product, product, StringComparison.OrdinalIgnoreCase)))
            {
                if (line.State == LicenceStates.OverLicensed)
                    findings.Add(new LicenceFinding(LicenceFinding.KindOverLicensed, LicenceFinding.SeverityCritical,
                        product, line.Edition,
                        $"installed {line.InstalledCount} against effective entitlement {line.EffectiveEntitledSeats} (asserted {line.EntitledSeats}) — over-licensed by {-(line.Delta ?? 0)}; entitlement refs: {string.Join(",", line.EntitlementRefs)}"));
                else if (line.State == LicenceStates.UnderLicensed)
                    findings.Add(new LicenceFinding(LicenceFinding.KindUnderLicensed, LicenceFinding.SeverityInfo,
                        product, line.Edition,
                        $"installed {line.InstalledCount} against entitlement {line.EntitledSeats} — surplus of {line.Delta} seat(s) (asserted, per {string.Join(",", line.EntitlementRefs)})"));
                else if (line.State == LicenceStates.UnlicensedUnknown)
                    findings.Add(new LicenceFinding(LicenceFinding.KindUnlicensedUnknown, LicenceFinding.SeverityWarning,
                        product, line.Edition,
                        $"{line.InstalledCount} install(s) across {line.DeviceCount} device(s) with NO entitlement record — position is UNLICENSED-UNKNOWN; no delta is computable and none is shown"));
                if (line.IsUnknownEditionLine)
                    findings.Add(new LicenceFinding(LicenceFinding.KindUnknownEdition, LicenceFinding.SeverityWarning,
                        product, null,
                        $"{line.InstalledCount} install(s) have an UNKNOWN edition (no edition rule in the classifier determines one) — they are counted as unknown, never as any entitled edition"));
                // A product with NO entitlement at all must raise
                // UnlicensedUnknown even when its only line is the
                // unknown-edition line (RMM-26 F7): the unknown-
                // edition verdict never masks the missing claim,
                // whatever other products in the fleet are entitled.
                if (line.IsUnknownEditionLine && ents.Count == 0)
                    findings.Add(new LicenceFinding(LicenceFinding.KindUnlicensedUnknown, LicenceFinding.SeverityWarning,
                        product, null,
                        $"{line.InstalledCount} install(s) across {line.DeviceCount} device(s) with NO entitlement record — position is UNLICENSED-UNKNOWN; no delta is computable and none is shown (the unknown-edition line does not mask the missing entitlement)"));
                if (line.HasExpiredEntitlement)
                    findings.Add(new LicenceFinding(LicenceFinding.KindEntitlementExpired, LicenceFinding.SeverityCritical,
                        product, line.Edition,
                        $"entitlement(s) {string.Join(",", line.EntitlementRefs)} expired at or before report time — expired claims contribute 0 effective seats"));
            }
            foreach (var e in ents.Where(e => !e.IsExpired(now) && e.ExpiresUtc is { } exp &&
                         exp <= now.AddDays(MeteringLimits.EntitlementExpiryWarningDays)))
                findings.Add(new LicenceFinding(LicenceFinding.KindEntitlementExpiring, LicenceFinding.SeverityWarning,
                    product, e.NormalizedEdition,
                    $"entitlement '{e.Id}@r{e.Revision}' ({e.Seats} seats, {LicenceEntitlement.ProvenanceLabel}) expires {e.ExpiresUtc:yyyy-MM-dd}"));
            if (productUsage.State == UsageSummary.StateNotMeasured && productInstalls.Count > 0)
                findings.Add(new LicenceFinding(LicenceFinding.KindUsageNotMeasured, LicenceFinding.SeverityInfo,
                    product, null, UsageSummary.NotMeasuredNote + $" for '{product}' — no usage fact from a named platform source; unused-software claims are not made from install data"));
            else if (productUsage.UnusedMeasuredInstalls > 0)
                findings.Add(new LicenceFinding(LicenceFinding.KindUnusedSoftware, LicenceFinding.SeverityInfo,
                    product, null,
                    $"{productUsage.UnusedMeasuredInstalls} measured install(s) of '{product}' unused for over {unusedBound.TotalDays:F0} days (usage facts only; {productUsage.UnmeasuredInstalls} install(s) not measured)"));
        }

        // ---- staleness findings (fleet-wide masking wall: any stale
        // device is named, per-device and in aggregate)
        foreach (var d in deviceStaleness.Where(d => d.IsStale && d.InventoryAsOfUtc <= now))
            findings.Add(new LicenceFinding(LicenceFinding.KindStaleInventory, LicenceFinding.SeverityWarning,
                "(fleet)", null,
                $"device '{d.DeviceId}' inventory is {d.AgeHours:F1}h old (bound {staleBound.TotalHours:F1}h) — installs resting on it may no longer exist, and installs it has gained are invisible to this report"));
        // Future-dated inventory is named as clock skew (RMM-26
        // F12c) — never silently clamped into freshness.
        foreach (var r in devices.Where(r => r.LastSeenUtc > now))
            findings.Add(new LicenceFinding(LicenceFinding.KindClockSkew, LicenceFinding.SeverityWarning,
                "(fleet)", null,
                $"device '{r.DeviceId}' inventory last-seen {r.LastSeenUtc:O} is {(r.LastSeenUtc - now).TotalHours:F1}h in the FUTURE at generation — clock skew or a forged timestamp; its freshness is unverifiable and it is NOT counted as fresh"));
        if (deviceStaleness.Count > 0 && deviceStaleness.All(d => d.IsStale))
            notes.Add("EVERY device's inventory is stale — this position is computed entirely from stale inventory and must not be presented as the current position");
        if (devices.Count == 0)
            notes.Add("no inventory records in scope — the install position is empty because there is no inventory, not because nothing is installed");

        // ---- header: provenance + staleness COMPUTED (RMM-13 shapes)
        var inventoryAsOf = devices.Count == 0 ? (DateTimeOffset?)null : devices.Min(r => r.LastSeenUtc);
        var entAsOf = liveEntitlements.Count == 0 ? (DateTimeOffset?)null : liveEntitlements.Max(e => e.EnteredUtc);
        var header = new ReportHeader(
            HubReport.NewReportId(ReportKind, now), ReportKind, scopeId, now,
            new[]
            {
                new ReportInputProvenance(EntitlementsSource, entAsOf, TimeSpan.MaxValue, liveEntitlements.Count > 0),
                new ReportInputProvenance(InventorySource, inventoryAsOf, staleBound, devices.Count > 0),
            });
        if (liveEntitlements.Count == 0)
            notes.Add("no entitlement records in scope — every installed product reads UNLICENSED-UNKNOWN (absence of a claim is not a zero position)");

        // Standing honesty notes (RMM-26 F9/F11): the seat basis and
        // the durability basis are named on EVERY report's face, not
        // buried in a design document.
        notes.Add("seat basis: every delta is computed per INSTALL (installed count) against effective entitled seats; the device count is shown on every line — if a licence is granted per device, judge it against the device count, not the install count");
        notes.Add("durability: the entitlement store and the report store behind this report round-trip through the HubPersistence envelope (BD-SHARED-RMM-3/F12) — a hub restart loses only what the host has not exported; on-disk persistence is the host's wiring of that export, not claimed here");

        lines = lines.OrderBy(l => l.Product, StringComparer.Ordinal)
            .ThenBy(l => l.IsUnknownEditionLine ? 2 : l.Edition is null ? 1 : 0)
            .ThenBy(l => l.Edition ?? "", StringComparer.Ordinal).ToList();
        findings = findings.OrderBy(f => f.Product, StringComparer.Ordinal)
            .ThenBy(f => f.Kind, StringComparer.Ordinal).ToList();

        var hash = LicencePositionReport.ComputeContentHash(header, lines, findings, deviceStaleness, notes);
        return new LicencePositionReport(header, lines, findings, deviceStaleness, notes, hash);
    }

    /// <summary>Emit a report's over/under/unlicensed findings to a
    /// sink as RMM-01-shaped alert events. Info findings (surplus,
    /// usage) are report-only; the alert centre hears about
    /// positions that need action.</summary>
    public static int EmitFindings(LicencePositionReport report, ILicenceFindingSink sink, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(report);
        ArgumentNullException.ThrowIfNull(sink);
        var emitted = 0;
        foreach (var f in report.Findings)
        {
            if (f.Severity == LicenceFinding.SeverityInfo) continue;
            sink.OnFinding(new LicenceFindingAlertEvent(f.Product, f.Edition, f.Kind, f.Severity, f.Detail, now), now);
            emitted++;
        }
        return emitted;
    }
}
