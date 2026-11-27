using System.Security.Cryptography;
using System.Text;

using System.Text.Json;
using DeskGuest.Shared.Hub;

namespace DeskGuest.Shared.Compliance;

// =====================================================================
// RMM-09 — Compliance evidence packs: offline GRC over DeskGuest-collected
// facts (ADOPTED 2026-11-20).
//
// THE HONESTY RULE (the whole directive): a pack must be able to say
// "we cannot evidence this". A control is SATISFIED only when a fact
// DeskGuest actually collected — for a device IN THIS PACK'S SCOPE, fresh
// enough to mean something — says so. A control with no backing fact
// is a GAP, never satisfied-by-assertion; a pack with gaps says so
// on its face, and the staleness of every underlying fact is carried
// on the pack's face. An evidence pack that always passes is a
// forgery machine; this model is built so it cannot be one:
//
//   * verdicts are computed by the pure compiler from a fact set —
//     there is no API that sets a verdict directly;
//   * vacuous truth is forbidden: an empty scope satisfies nothing
//     (zero devices is a missing-fact gap, not a pass);
//   * facts are scope-bound: a fact recorded for device A is never
//     evidence for device B, and a fact from another scope is never
//     evidence here (the compiler filters by scope + device);
//   * a treatment plan NEVER satisfies a control — it marks the gap
//     TREATED (owned, dated), and an expired treatment reopens it.
//
// This file is the MODEL: fact kinds + the fact record, gap kinds,
// control verdicts, treatment plans + their store, the compiled
// pack artefact, and the pack-over-pack movement diff. Checklist
// content packs live in CompliancePacks.cs; the pure compiler in
// ComplianceCompiler.cs; the hub service in DeskGuest.Core.
// =====================================================================

/// <summary>TOTAL POLICY CONTROL keys for RMM-09. The feature toggle
/// (rmm.compliance.enabled, seeded ON) lives in the RMM-07 registry;
/// the keys below are POLICY CONTENT read through Effective Policy.</summary>
public static class CompliancePolicyKeys
{
    public const string Enabled = "rmm.compliance.enabled";
    public const string FactStaleDays = "rmm.compliance.fact_stale_days";
    public const string InventoryStaleDays = "rmm.compliance.inventory_stale_days";
}

public static class ComplianceLimits
{
    public const int MaxControlsPerPack = 512;
    public const int MaxControlIdLength = 128;
    public const int MaxControlTitleLength = 512;
    public const int MaxTreatmentLength = 4096;
    public const int MaxOwnerLength = 128;
    /// <summary>A treatment target may be at most this far out: a
    /// treatment that never comes due is a permanent exception
    /// wearing a plan's clothes (the RMM-05 review-date discipline).</summary>
    public const int MaxTreatmentDays = 365;
    public const int DefaultFactStaleDays = 7;
    public const int DefaultInventoryStaleDays = 7;
    /// <summary>D38-F3: an observation further in the future than
    /// this cannot be a clock-skewed genuine reading — it is a
    /// forgery/poisoning attempt and is refused at intake and
    /// judged stale at compile time. Five minutes covers honest
    /// endpoint/hub clock skew; a year does not.</summary>
    public static readonly TimeSpan MaxFutureSkew = TimeSpan.FromMinutes(5);
}

public static class ComplianceHash
{
    public static string Sha256Hex(string s) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(s))).ToLowerInvariant();

    public static bool IsSha256Hex(string? hash) =>
        hash is not null && hash.Trim().Length == 64 &&
        hash.Trim().All(c => char.IsDigit(c) || c is >= 'a' and <= 'f' or >= 'A' and <= 'F');
}

// ---- facts --------------------------------------------------------------

/// <summary>The fact kinds DeskGuest collects that compliance controls map
/// to (DIR-24's mapping discipline, extended): patch state (RMM-02
/// over RMM-04), encryption + security state (RMM-01 samples),
/// inventory presence (RMM-04), the chained audit (history + chain
/// integrity), access reviews (DIR-54 campaigns), vulnerability
/// state (RMM-05). A checklist control may only require one of
/// these — content-pack admission refuses any other kind, so a pack
/// can never demand (or claim) evidence DeskGuest does not collect.</summary>
public static class ComplianceFactKinds
{
    public const string PatchState = "patch_state";
    public const string EncryptionState = "encryption_state";
    public const string SecurityState = "security_state";
    public const string InventoryPresence = "inventory_presence";
    public const string AuditChain = "audit_chain";
    public const string AuditHistory = "audit_history";
    public const string AccessReview = "access_review";
    public const string VulnerabilityState = "vulnerability_state";
    /// <summary>bd-shared-sec-1/F6: DLP discovery (RMM-30's
    /// DlpComplianceFacts) — registered so a content pack CAN
    /// require it; previously the kind existed only on the producer
    /// side and pack admission refused every control requiring it,
    /// so DLP could never evidence any control.</summary>
    public const string DlpDiscovery = "dlp_discovery";

    public static readonly IReadOnlySet<string> All = new HashSet<string>
    {
        PatchState, EncryptionState, SecurityState, InventoryPresence,
        AuditChain, AuditHistory, AccessReview, VulnerabilityState, DlpDiscovery,
    };

    /// <summary>Device-scoped kinds are evaluated per device in the
    /// pack's scope; scope kinds once for the whole scope.</summary>
    public static readonly IReadOnlySet<string> DeviceScoped = new HashSet<string>
    {
        PatchState, EncryptionState, SecurityState, InventoryPresence, DlpDiscovery,
    };

    public static bool IsDeviceScoped(string kind) => DeviceScoped.Contains(kind ?? "");
}

/// <summary>One collected fact, as the hub holds it. DeviceId null
/// marks a scope-level fact (audit chain, access review, vuln
/// posture). ObservedUtc is when the underlying state was OBSERVED
/// (e.g. the inventory record's LastSeenUtc) — never the pack's
/// compile time: presenting an old observation as current is the
/// stale-fact laundering the destruction pass attacks, and the
/// compiler judges freshness from this field alone. UpstreamStale
/// carries a source's own staleness verdict (the RMM-05 feed
/// provenance): a fact whose source names itself stale IS stale,
/// whatever its timestamps say. EvidenceRef is a hash reference to
/// the underlying record, so a pack names exactly what it rests on.</summary>
public sealed record ComplianceFact(
    string Kind,
    string? DeviceId,
    string ScopeId,
    bool Passing,
    DateTimeOffset ObservedUtc,
    string Detail,
    string EvidenceRef,
    bool UpstreamStale = false,
    string? UpstreamStaleNote = null);

/// <summary>The fact set one compilation runs over: the scope's
/// facts plus the scope's device roster (the roster is what makes
/// vacuous truth impossible — a device with no fact is a gap, and
/// the compiler knows the device exists only from the roster).</summary>
public sealed record ComplianceFactSet(
    string ScopeId,
    IReadOnlyList<string> DeviceIds,
    IReadOnlyList<ComplianceFact> Facts,
    DateTimeOffset CollectedUtc)
{
    public IReadOnlyList<string> DeviceIds { get; init; } = DeviceIds ?? Array.Empty<string>();
    public IReadOnlyList<ComplianceFact> Facts { get; init; } = Facts ?? Array.Empty<ComplianceFact>();

    /// <summary>SHA-256 over the canonical fact content — the pack
    /// binds to exactly the facts it was compiled from.</summary>
    public string ContentHash => ComplianceHash.Sha256Hex(string.Join("\n",
        new[] { $"scope={ScopeId}", $"devices={string.Join(",", DeviceIds.OrderBy(d => d, StringComparer.Ordinal))}" }
        .Concat(Facts
            .OrderBy(f => f.Kind, StringComparer.Ordinal)
            .ThenBy(f => f.DeviceId ?? "", StringComparer.Ordinal)
            .ThenBy(f => f.EvidenceRef, StringComparer.Ordinal)
            .Select(f => $"{f.Kind}|{f.DeviceId ?? "-"}|{f.ScopeId}|{f.Passing}|{f.ObservedUtc:O}|{f.Detail}|{f.EvidenceRef}|{f.UpstreamStale}"))));
}

/// <summary>How old a fact may be before the compiler calls it
/// stale, per kind, from policy content with these defaults. A
/// non-positive or absurd policy value falls back to the default
/// for that kind — a typo can never mint an infinite freshness
/// window (the RMM-05 SLA fallback discipline).</summary>
public sealed record ComplianceStalenessPolicy(
    int DefaultDays = ComplianceLimits.DefaultFactStaleDays,
    int InventoryDays = ComplianceLimits.DefaultInventoryStaleDays)
{
    public static ComplianceStalenessPolicy Default { get; } = new();

    public TimeSpan WindowFor(string kind)
    {
        var days = kind == ComplianceFactKinds.InventoryPresence ? InventoryDays : DefaultDays;
        if (days <= 0 || days > 365) days = kind == ComplianceFactKinds.InventoryPresence
            ? ComplianceLimits.DefaultInventoryStaleDays : ComplianceLimits.DefaultFactStaleDays;
        return TimeSpan.FromDays(days);
    }
}

// ---- gaps + verdicts ------------------------------------------------------

/// <summary>The three gaps, named differently because they ARE
/// different: the fact was never collected, the fact exists but is
/// too old to evidence anything now, or the fact exists, is fresh,
/// and says the control is NOT met.</summary>
public static class GapKinds
{
    public const string MissingFact = "missing_fact";
    public const string StaleFact = "stale_fact";
    public const string FailingFact = "failing_fact";
}

public static class ControlOutcomes
{
    public const string Satisfied = "satisfied";
    public const string Gap = "gap";
    /// <summary>A gap with a live treatment plan: still a gap (the
    /// control is NOT satisfied), but owned and dated on the face.</summary>
    public const string GapTreated = "gap_treated";
}

/// <summary>One control's verdict in one pack. EvidenceRefs are the
/// backing facts' refs (satisfied) or the offending facts' refs
/// (failing/stale); FailingDevices names every device that did not
/// pass a device-scoped control — a control is satisfied only when
/// EVERY device in scope passes. FactObservedUtc is the OLDEST
/// backing observation: the pack's freshness is its weakest fact,
/// stated plainly.</summary>
public sealed record ControlVerdict(
    string ControlId,
    string FrameworkRef,
    string Title,
    string RequiredFactKind,
    string Rule,                  // D38-F5: the pass rule the verdict was judged under, carried so movement diffs + the pack hash can detect a control hollowed out by remapping
    string Outcome,               // ControlOutcomes.*
    string? GapKind,              // GapKinds.* when Outcome != satisfied
    string Reason,
    IReadOnlyList<string> EvidenceRefs,
    IReadOnlyList<string> FailingDevices,
    DateTimeOffset? FactObservedUtc,
    string? TreatmentId)
{
    public IReadOnlyList<string> EvidenceRefs { get; init; } = EvidenceRefs ?? Array.Empty<string>();
    public IReadOnlyList<string> FailingDevices { get; init; } = FailingDevices ?? Array.Empty<string>();
    public bool IsGap => Outcome != ControlOutcomes.Satisfied;

    /// <summary>The gap's stable identity across packs (movement
    /// diffs key on this): framework + control + scope.</summary>
    public string GapKey(string packScopeId) => $"{RequiredFactKind}::{ControlId}@{packScopeId}";
}

// ---- treatment plans -------------------------------------------------------

public static class TreatmentStates
{
    public const string Active = "active";
    public const string Expired = "expired";
}

/// <summary>A treatment plan for one compliance gap (the RMM-05
/// compensating-control discipline applied to compliance gaps): a
/// gap gets an owner + an intended treatment + a target date. It
/// never satisfies the control; it marks the gap treated while the
/// plan is live, and an expired plan reopens the gap (the compiler
/// checks expiry against its own clock — a stored "active" flag is
/// never trusted).</summary>
public sealed record ComplianceTreatment(
    string TreatmentId,
    string FrameworkId,
    string ControlId,
    string ScopeId,
    string Owner,
    string Treatment,
    string RecordedBy,
    DateTimeOffset RecordedUtc,
    DateTimeOffset TargetDateUtc,
    // bd-shared-sec-1/F9: extension bookkeeping. OriginalRecordedUtc
    // is the FIRST plan's recording instant for this gap (null = this
    // IS the first plan); the total treated span is capped from it,
    // so serial extensions cannot keep a gap treated forever.
    DateTimeOffset? OriginalRecordedUtc = null,
    int ExtensionCount = 0)
{
    /// <summary>The instant the FIRST plan for this gap was
    /// recorded — the anchor of the total-span cap (F9).</summary>
    public DateTimeOffset FirstRecordedUtc => OriginalRecordedUtc ?? RecordedUtc;
    public bool IsExpired(DateTimeOffset now) => now > TargetDateUtc;
    public string StateAt(DateTimeOffset now) =>
        IsExpired(now) ? TreatmentStates.Expired : TreatmentStates.Active;

    public static string IdFor(string frameworkId, string controlId, string scopeId, string owner, DateTimeOffset targetDateUtc) =>
        "trt-" + ComplianceHash.Sha256Hex(
            $"{frameworkId}|{controlId}|{scopeId}|{owner}|{targetDateUtc:O}")[..20];
}

/// <summary>The treatment store: recording is validated (owner
/// mandatory, treatment text mandatory, target in the future and
/// within the cap, the gap identity fully named) and idempotent per
/// (framework, control, scope) — recording a fresh plan for a gap
/// replaces the expired one, it never stacks silent duplicates.</summary>
public sealed class TreatmentStore
{
    private readonly Dictionary<string, ComplianceTreatment> _byGap = new(StringComparer.Ordinal);
    private readonly object _gate = new();

    private static string Key(string frameworkId, string controlId, string scopeId) =>
        $"{frameworkId}|{controlId}|{scopeId}";

    /// <summary>The field-level admission checks, shared by Record
    /// and ImportJson (D38-F9): a restored plan must pass exactly
    /// the checks a live recording passes — owner mandatory, text
    /// mandatory, identity fully named. Returns the refusal reason
    /// or null.</summary>
    private static string? ValidateFields(string? frameworkId, string? controlId, string? scopeId,
        string? owner, string? treatment)
    {
        if (string.IsNullOrWhiteSpace(frameworkId) || string.IsNullOrWhiteSpace(controlId) ||
            string.IsNullOrWhiteSpace(scopeId))
            return "a treatment must name its framework, control and scope — refused";
        if (string.IsNullOrWhiteSpace(owner) || owner.Trim().Length > ComplianceLimits.MaxOwnerLength)
            return "a treatment without an owner is not a plan — refused (owner is mandatory)";
        if (string.IsNullOrWhiteSpace(treatment) || treatment.Trim().Length > ComplianceLimits.MaxTreatmentLength)
            return "a treatment must state the intended treatment — refused";
        return null;
    }

    public (bool Ok, string Reason, ComplianceTreatment? Treatment) Record(
        string frameworkId, string controlId, string scopeId,
        string owner, string treatment, string recordedBy,
        DateTimeOffset targetDateUtc, DateTimeOffset now)
    {
        if (ValidateFields(frameworkId, controlId, scopeId, owner, treatment) is { } fieldDefect)
            return (false, fieldDefect, null);
        // bd-shared-sec-1/F9: recordedBy is validated — a plan
        // recorded by NOBODY is not a plan.
        if (string.IsNullOrWhiteSpace(recordedBy))
            return (false, "a treatment must name who recorded it — refused (recordedBy is mandatory)", null);
        if (targetDateUtc <= now)
            return (false, $"treatment target {targetDateUtc:O} is not in the future — an already-expired plan closes nothing; refused", null);
        if (targetDateUtc > now.AddDays(ComplianceLimits.MaxTreatmentDays))
            return (false, $"treatment target {targetDateUtc:O} is more than {ComplianceLimits.MaxTreatmentDays} days out — a plan that never comes due is a permanent exception; refused", null);
        var t = new ComplianceTreatment(
            ComplianceTreatment.IdFor(frameworkId, controlId, scopeId, owner.Trim(), targetDateUtc),
            frameworkId, controlId, scopeId, owner.Trim(), treatment.Trim(),
            recordedBy.Trim(), now, targetDateUtc);
        lock (_gate)
        {
            // bd-shared-sec-1/F9: a LIVE plan cannot be silently
            // overwritten. Re-recording every 364 days previously
            // kept a gap 'gap_treated' forever, each replacement
            // leaving no trace. A live plan may only be EXTENDED
            // through Extend(), which counts extensions and caps
            // the total span from the first plan's recording.
            if (_byGap.TryGetValue(Key(frameworkId, controlId, scopeId), out var existing) &&
                !existing.IsExpired(now))
                return (false, $"a LIVE treatment '{existing.TreatmentId}' already stands for {frameworkId}/{controlId}@{scopeId} (recorded {existing.RecordedUtc:O}, target {existing.TargetDateUtc:O}) — Record refuses to silently overwrite it; use Extend to move a live plan, with the extension counted and the total span capped", null);
            _byGap[Key(frameworkId, controlId, scopeId)] = t;
        }
        Changed?.Invoke();
        return (true, $"treatment '{t.TreatmentId}' recorded for {frameworkId}/{controlId}@{scopeId}: owner={t.Owner} target={targetDateUtc:O}", t);
    }

    /// <summary>bd-shared-sec-1/F9: the ONLY way to move a LIVE
    /// plan. The extension is explicit and counted on the plan
    /// itself, the new target must move FORWARD, and the total
    /// treated span — from the FIRST plan's RecordedUtc to the new
    /// target — may not exceed MaxTreatmentDays: a gap can be
    /// treated for at most one cap-period in total, however many
    /// extensions are chained.</summary>
    public (bool Ok, string Reason, ComplianceTreatment? Treatment) Extend(
        string frameworkId, string controlId, string scopeId,
        string extendedBy, DateTimeOffset newTargetDateUtc, DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(extendedBy))
            return (false, "an extension must name who extended the plan — refused", null);
        lock (_gate)
        {
            if (!_byGap.TryGetValue(Key(frameworkId, controlId, scopeId), out var existing))
                return (false, $"no treatment stands for {frameworkId}/{controlId}@{scopeId} — there is nothing to extend; refused (record a plan first)", null);
            if (existing.IsExpired(now))
                return (false, $"treatment '{existing.TreatmentId}' expired at {existing.TargetDateUtc:O} — an expired plan is not extended; record a fresh plan so the gap's reopening stays on the record", null);
            if (newTargetDateUtc <= existing.TargetDateUtc)
                return (false, $"extension target {newTargetDateUtc:O} does not move the plan forward past {existing.TargetDateUtc:O} — refused", null);
            if (newTargetDateUtc > existing.FirstRecordedUtc.AddDays(ComplianceLimits.MaxTreatmentDays))
                return (false, $"extension target {newTargetDateUtc:O} would stretch the total treated span past {ComplianceLimits.MaxTreatmentDays} days from the first plan's recording ({existing.FirstRecordedUtc:O}) — refused: a gap cannot be kept 'treated' forever by serial extension", null);
            var t = existing with
            {
                TreatmentId = ComplianceTreatment.IdFor(frameworkId, controlId, scopeId, existing.Owner, newTargetDateUtc),
                RecordedBy = extendedBy.Trim(),
                RecordedUtc = now,
                TargetDateUtc = newTargetDateUtc,
                OriginalRecordedUtc = existing.FirstRecordedUtc,
                ExtensionCount = existing.ExtensionCount + 1,
            };
            _byGap[Key(frameworkId, controlId, scopeId)] = t;
            Changed?.Invoke();
            return (true, $"treatment '{existing.TreatmentId}' extended to '{t.TreatmentId}' for {frameworkId}/{controlId}@{scopeId}: extension #{t.ExtensionCount}, new target {newTargetDateUtc:O}, total span from first recording {existing.FirstRecordedUtc:O} stays within the {ComplianceLimits.MaxTreatmentDays}-day cap", t);
        }
    }

    public ComplianceTreatment? Get(string frameworkId, string controlId, string scopeId)
    {
        lock (_gate) return _byGap.TryGetValue(Key(frameworkId, controlId, scopeId), out var t) ? t : null;
    }

    public IReadOnlyList<ComplianceTreatment> All
    {
        get { lock (_gate) return _byGap.Values.OrderBy(t => t.TreatmentId, StringComparer.Ordinal).ToList(); }
    }

    /// <summary>Lane A: raised after every successful mutation so
    /// CoreRuntime can write the store through to disk.</summary>
    public event Action? Changed;

    // ---- hub persistence (Lane A: RMM-04 pattern + integrity envelope) ----

    public string ExportJson()
    {
        lock (_gate)
            return HubPersistence.Wrap("deskguest-compliance-treatments-v1",
                JsonSerializer.Serialize(_byGap.Values.OrderBy(t => t.TreatmentId, StringComparer.Ordinal).ToList()));
    }

    /// <summary>Restore treatments whose gap key does not already
    /// stand; a payload failing the integrity envelope restores
    /// nothing. Restored plans are re-keyed by their own gap
    /// identity, never by file position.</summary>
    public int ImportJson(string json) => ImportJson(json, DateTimeOffset.UtcNow);

    /// <summary>D38-F9: restore RE-RUNS Record's admission checks
    /// on every entry. The persistence envelope is unkeyed, so a
    /// hand-edited file could otherwise plant a plan Record would
    /// have refused — ownerless, textless, or with a target in
    /// year 9999 (a permanent gap_treated exception). An entry
    /// restores only when: its fields pass ValidateFields; its
    /// TreatmentId recomputes from its own content (a relabelled
    /// plan is a forgery); it was recorded in the past (within
    /// clock skew); its target was in the future when recorded
    /// and within the 365-day cap FROM ITS RECORDED INSTANT; and
    /// its target is still in the future at restore time (a plan
    /// that expired while persisted is dead — the gap it treated
    /// stands open on the next pack's face, never treated by a
    /// restored corpse). Failing entries are skipped, never
    /// imported.</summary>
    public int ImportJson(string json, DateTimeOffset now)
    {
        var payload = HubPersistence.Unwrap(json, "deskguest-compliance-treatments-v1");
        if (payload is null) return 0;
        List<ComplianceTreatment>? list;
        try { list = JsonSerializer.Deserialize<List<ComplianceTreatment>>(payload); } catch { return 0; }
        if (list is null) return 0;
        var restored = 0;
        lock (_gate)
        {
            foreach (var t in list)
            {
                if (t is null) continue;
                if (ValidateFields(t.FrameworkId, t.ControlId, t.ScopeId, t.Owner, t.Treatment) is not null) continue;
                if (!string.Equals(t.TreatmentId,
                        ComplianceTreatment.IdFor(t.FrameworkId, t.ControlId, t.ScopeId, t.Owner.Trim(), t.TargetDateUtc),
                        StringComparison.Ordinal)) continue;
                if (t.RecordedUtc > now + ComplianceLimits.MaxFutureSkew) continue;
                if (string.IsNullOrWhiteSpace(t.RecordedBy)) continue; // F9: recordedBy is mandatory, live and restored alike
                if (t.TargetDateUtc <= t.RecordedUtc) continue;
                if (t.TargetDateUtc > t.RecordedUtc.AddDays(ComplianceLimits.MaxTreatmentDays)) continue;
                if (t.TargetDateUtc > t.FirstRecordedUtc.AddDays(ComplianceLimits.MaxTreatmentDays)) continue; // F9: total-span cap from the FIRST plan
                if (t.TargetDateUtc <= now) continue;
                var key = Key(t.FrameworkId, t.ControlId, t.ScopeId);
                if (_byGap.ContainsKey(key)) continue;
                _byGap[key] = t;
                restored++;
            }
        }
        if (restored > 0) Changed?.Invoke();
        return restored;
    }
}

// ---- the compiled pack ------------------------------------------------------

public static class PackKinds
{
    public const string EvidencePack = "evidence_pack";
    public const string SiteAssessment = "site_assessment";
}

/// <summary>One compiled compliance evidence pack: an exportable
/// artefact binding a content pack (id + revision + content hash)
/// to a fact set (content hash) at a scope, with every control's
/// verdict, the gap list, the treatments applied, and the honesty
/// summary on its face. ContentHash is computed over the canonical
/// verdict content: a hand-edited pack (a gap flipped to satisfied)
/// fails <see cref="VerifyContentHash"/>.</summary>
public sealed record CompliancePack(
    string PackId,
    string Kind,                       // PackKinds.*
    string FrameworkId,
    string ContentPackId,
    long ContentPackRevision,
    string ContentPackHash,
    string ScopeId,
    string? SiteLabel,
    DateTimeOffset GeneratedUtc,
    string GeneratedBy,
    string FactSetHash,
    IReadOnlyList<ControlVerdict> Verdicts,
    IReadOnlyList<string> ProvenanceNotes,
    // D38-F7: the freshness windows this pack was judged under,
    // recorded on its face and inside its content hash — a pack
    // judged under 365-day windows must not be indistinguishable
    // from one judged under 7-day windows. 0 = not recorded
    // (packs built before this field existed).
    int StalenessDefaultDays = 0,
    int StalenessInventoryDays = 0)
{
    public IReadOnlyList<ControlVerdict> Verdicts { get; init; } = Verdicts ?? Array.Empty<ControlVerdict>();
    public IReadOnlyList<string> ProvenanceNotes { get; init; } = ProvenanceNotes ?? Array.Empty<string>();

    public int SatisfiedCount => Verdicts.Count(v => v.Outcome == ControlOutcomes.Satisfied);
    public int GapCount => Verdicts.Count(v => v.IsGap);
    public int TreatedGapCount => Verdicts.Count(v => v.Outcome == ControlOutcomes.GapTreated);
    public IReadOnlyList<ControlVerdict> Gaps => Verdicts.Where(v => v.IsGap).ToList();

    /// <summary>The pack's headline, stated the honest way: a pack
    /// with any gap CANNOT claim the framework is evidenced.</summary>
    public string Headline => GapCount == 0
        ? $"EVIDENCED: all {Verdicts.Count} controls in '{FrameworkId}' are backed by fresh, passing DeskGuest-collected facts for scope '{ScopeId}'"
        : $"GAPS PRESENT: {GapCount} of {Verdicts.Count} controls in '{FrameworkId}' cannot be evidenced for scope '{ScopeId}' ({TreatedGapCount} under treatment) — this pack does NOT attest compliance";

    /// <summary>D38-F6: the canonical content binds EVERY field
    /// that carries meaning on the pack's face — per verdict the
    /// framework ref, title, required fact kind, outcome, gap
    /// kind, REASON prose, evidence refs, failing devices, oldest
    /// observation and treatment; plus the provenance notes (the
    /// EXCLUDED / no-facts notes live there) and the staleness
    /// windows (F7). Before this fix a satisfied inventory verdict
    /// could be relabelled as the encryption requirement, reason
    /// prose softened, and the EXCLUDED notes stripped, all
    /// without breaking the hash. NOTE on what the hash is: an
    /// UNKEYED SHA-256 — tamper-evidence against an independently
    /// held expected hash, not authenticity by itself. The
    /// independent channel is the chained audit: the service
    /// records every pack's ContentHash in a
    /// compliance_pack_compiled event at compile time, and
    /// ComplianceService.VerifyStoredPack checks a stored pack
    /// against that anchored hash (and the chain's integrity).</summary>
    public string CanonicalContent() => string.Join("\n",
        new[]
        {
            $"deskguest-compliance-pack-v2|{Kind}|{FrameworkId}|{ContentPackId}|{ContentPackRevision}|{ContentPackHash}|{ScopeId}|{SiteLabel ?? "-"}|{GeneratedUtc:O}|{GeneratedBy}|{FactSetHash}|staleDefaultDays={StalenessDefaultDays}|staleInventoryDays={StalenessInventoryDays}",
        }.Concat(ProvenanceNotes.Select(n => $"note|{n}"))
         .Concat(Verdicts.OrderBy(v => v.ControlId, StringComparer.Ordinal).Select(v =>
            $"{v.ControlId}|{v.FrameworkRef}|{v.Title}|{v.RequiredFactKind}|{v.Rule}|{v.Outcome}|{v.GapKind ?? "-"}|{v.Reason}|{string.Join(",", v.EvidenceRefs.OrderBy(e => e, StringComparer.Ordinal))}|{string.Join(",", v.FailingDevices.OrderBy(d => d, StringComparer.Ordinal))}|{v.FactObservedUtc?.ToString("O") ?? "-"}|{v.TreatmentId ?? "-"}")));

    public string ContentHash => ComplianceHash.Sha256Hex(CanonicalContent());

    public bool VerifyContentHash(string expectedHash) =>
        ComplianceHash.IsSha256Hex(expectedHash) &&
        string.Equals(ContentHash, expectedHash.Trim(), StringComparison.OrdinalIgnoreCase);

    public static string IdFor(string frameworkId, string scopeId, string factSetHash, DateTimeOffset generatedUtc) =>
        "pack-" + ComplianceHash.Sha256Hex($"{frameworkId}|{scopeId}|{factSetHash}|{generatedUtc:O}")[..20];
}

// ---- movement: pack-over-pack diff -------------------------------------------

public sealed record ControlMovement(
    string ControlId,
    string FromOutcome,     // "absent" when the control is new to the later pack
    string ToOutcome,       // "absent" when the control vanished from the later pack
    string Category,        // MovementCategories.*
    string Detail);

public static class MovementCategories
{
    public const string Closed = "closed";                 // gap → satisfied
    public const string Opened = "opened";                 // satisfied → gap, or a NEW gap
    public const string StillSatisfied = "still_satisfied";
    public const string StillOpen = "still_open";          // gap → gap (aged)
    public const string NewSatisfied = "new_satisfied";    // control new, satisfied
    public const string ControlRemoved = "control_removed"; // in the earlier pack, gone later — NAMED, never silent
    public const string ControlRemapped = "control_remapped"; // D38-F5: same id, different fact kind/rule/title — a hollowed control, NAMED, never shown as closed
    public const string TreatmentChanged = "treatment_changed"; // gap both times, treatment state moved
}

/// <summary>The movement between two packs of the same framework +
/// scope. COMPLETENESS IS THE ANTI-FORGERY PROPERTY: every control
/// in either pack appears exactly once, so
/// AccountedFor == union count by construction and a diff that
/// hides a newly-opened gap cannot be produced by this type —
/// Opened lists it, and the counts reconcile or the diff is
/// visibly broken (UnaccountedCount != 0).</summary>
public sealed record CompliancePackDiff(
    string FrameworkId,
    string ScopeId,
    string EarlierPackId,
    string LaterPackId,
    DateTimeOffset EarlierUtc,
    DateTimeOffset LaterUtc,
    IReadOnlyList<ControlMovement> Movements)
{
    public IReadOnlyList<ControlMovement> Movements { get; init; } = Movements ?? Array.Empty<ControlMovement>();

    public IReadOnlyList<ControlMovement> Closed => Movements.Where(m => m.Category == MovementCategories.Closed).ToList();
    public IReadOnlyList<ControlMovement> Opened => Movements.Where(m => m.Category == MovementCategories.Opened).ToList();
    public IReadOnlyList<ControlMovement> StillOpen => Movements.Where(m => m.Category == MovementCategories.StillOpen).ToList();
    public IReadOnlyList<ControlMovement> Removed => Movements.Where(m => m.Category == MovementCategories.ControlRemoved).ToList();

    public int UnionControlCount { get; init; }
    public int UnaccountedCount => UnionControlCount - Movements.Count;

    public string Summary =>
        $"movement {EarlierPackId} → {LaterPackId} ({FrameworkId}@{ScopeId}): " +
        $"{Closed.Count} closed, {Opened.Count} opened, {StillOpen.Count} still open, " +
        $"{Movements.Count(m => m.Category == MovementCategories.StillSatisfied)} still satisfied, " +
        $"{Removed.Count} controls removed" +
        (UnaccountedCount != 0 ? $" — WARNING: {UnaccountedCount} controls UNACCOUNTED (diff incomplete)" : " — all controls accounted for");
}
