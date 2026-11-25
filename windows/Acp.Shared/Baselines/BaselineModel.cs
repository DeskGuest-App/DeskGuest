using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Acp.Shared.Enterprise;
using Acp.Shared.Inventory;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Monitoring;

namespace Acp.Shared.Baselines;

// =====================================================================
// RMM-19 — Desired-state baselines + endpoint drift detection
// (ADOPTED 2026-11-20). MODEL LAYER: the baseline document (signed
// policy content), the observed-state shape comparison consumes,
// the pure per-item evaluator, the versioned baseline store with
// inheritance + absorption (anti-laundering) records, the policy
// resolver (cadence / scope / remediation), the auto-remediation
// gate, and the hub-side cross-check.
//
// Doctrine carried from the register + DIR-55 + the lane assignment:
//   * DIR-55 covered drift of ACP's OWN configuration (policy/build
//     version vs desired — EnterpriseBacklog.DriftReport). RMM-19
//     extends that discipline to the endpoint's whole managed
//     state and keeps its shape: a drift finding NAMES the field,
//     the observed value and the desired value. A bare "drifted"
//     flag is not expressible here — every deviation carries
//     expected vs observed for one named item.
//   * A baseline is SIGNED POLICY CONTENT (RMM-07 delivery, RMM-03
//     verification) assigned org → group → device with the same
//     inheritance discipline as management policy: a child inherits,
//     may override an item (same item id), and the Effective
//     Baseline keeps per-item provenance (which level / document /
//     revision set it).
//   * Comparison is AGENT-LOCAL and PURE: the evaluator reads only
//     the effective baseline and one observed-state snapshot. A
//     reading the collectors did not take is INDETERMINATE for that
//     item — never compliant, never drift (the RMM-01/RMM-18
//     honesty rule: silence is not health, a gap is not a pass).
//   * Baselines are VERSIONED and re-baselining is DELIBERATE: a
//     new revision takes effect only from its EffectiveUtc (drift
//     before that instant is judged against the revision then in
//     force), the change itself is audited, and a revision that
//     would ABSORB an existing deviation — remove the item, disable
//     it, or move its expectation onto the drifted observed value —
//     NAMES that fact in its admission result, in a permanent
//     in-model revision record, and in the audit chain. Nobody
//     launders real drift by quietly editing the baseline: the
//     drift alert stays in history and the absorption is on record.
//   * Drift reports AS RMM-01 CONDITIONS: each deviation raises one
//     HealthAlertCentre alert (kind baseline_drift, condition id
//     per item) through the centre's own dedup / cooldown / flood
//     discipline — there is no second alert surface (service layer).
//   * Auto-remediation is a LINK + A GATE, never an execution here:
//     an item may name an RMM-08 remediation id, but drift fires it
//     only when policy explicitly allows auto-remediation AND the
//     id is on the policy remediation allowlist. A baseline author
//     naming an id is not approval — the allowlist is.
//   * TRUST BOUNDARY, stated plainly: comparison inputs are the
//     collectors' readings, carried in ObservedEndpointState. A
//     fully compromised agent can lie about anything, including its
//     observed state — no model on the agent can prevent that. The
//     defence that exists is hub-side: HubDriftCrossCheck recomputes
//     the software half of the baseline from the hub's RMM-04
//     inventory record (a DIFFERENT reporting path than the drift
//     evaluation) and flags every disagreement by name. It flags;
//     it never silently overrides either side.
// =====================================================================

/// <summary>TOTAL POLICY CONTROL keys for RMM-19. The feature toggle
/// (rmm.baselines.enabled, seeded ON in the RMM-07 registry) gates
/// the whole feature; the keys below are POLICY CONTENT read through
/// Effective Policy / the resolver.</summary>
public static class BaselinePolicyKeys
{
    public const string Enabled = "rmm.baselines.enabled";
    /// <summary>Comparison cadence in seconds. Default 300; clamped
    /// 30..86400 — a policy asking for a tighter or looser cadence
    /// than the bounds falls back to the nearest bound and the clamp
    /// is named in the resolved policy.</summary>
    public const string CadenceSeconds = "rmm.baselines.cadence_seconds";
    public const int DefaultCadenceSeconds = 300;
    public const int MinCadenceSeconds = 30;
    public const int MaxCadenceSeconds = 86_400;
    /// <summary>Item classes in scope: comma list of
    /// BaselineItemKinds values. Absent = all kinds. An unknown kind
    /// name in the list is dropped AND named (a scope typo must not
    /// silently widen or narrow the comparison).</summary>
    public const string ScopeKinds = "rmm.baselines.scope_kinds";
    /// <summary>"true" allows drift to fire linked remediation at
    /// all. Default false: drift reports; it does not act, until
    /// policy says otherwise.</summary>
    public const string AutoRemediate = "rmm.baselines.auto_remediate";
    /// <summary>Comma list of remediation ids policy approves for
    /// drift-triggered auto-remediation. REQUIRED for any firing:
    /// auto_remediate=true alone approves nothing by name.</summary>
    public const string RemediationAllowlist = "rmm.baselines.remediation_allowlist";
    /// <summary>Per-item drift-alert cooldown in seconds (the centre
    /// dedup discipline). Default 1800; clamped 60..86400.</summary>
    public const string DriftCooldownSeconds = "rmm.baselines.drift_cooldown_seconds";
    public const int DefaultDriftCooldownSeconds = 1800;
    public const int MinDriftCooldownSeconds = 60;
    public const int MaxDriftCooldownSeconds = 86_400;
}

/// <summary>The closed set of baseline item kinds. A baseline naming
/// a kind outside this set refuses at admission — an unknown kind is
/// a field that changes meaning (house fail-closed rule).</summary>
public static class BaselineItemKinds
{
    public const string ServiceState = "service_state";           // Target = service name; Expected = Running | Stopped
    public const string Setting = "setting";                      // Target = setting key; Expected = value
    public const string SoftwareRequired = "software_required";   // Target = app name; ExpectedVersion = minimum version (optional)
    public const string SoftwareForbidden = "software_forbidden"; // Target = app name; presence is drift
    public const string SecurityPosture = "security_posture";     // Target = av | firewall | encryption; Expected = on | off

    public static readonly IReadOnlySet<string> All = new HashSet<string>
    { ServiceState, Setting, SoftwareRequired, SoftwareForbidden, SecurityPosture };

    public static readonly IReadOnlySet<string> PostureTargets = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    { "av", "firewall", "encryption" };

    public static readonly IReadOnlySet<string> ServiceStates = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    { "Running", "Stopped" };
}

/// <summary>Named bounds for baseline admission. Every bound refuses
/// by name — none is a hidden constant an author discovers by
/// hanging the store.</summary>
public static class BaselineLimits
{
    public const int MaxItemsPerDocument = 512;
    public const int MaxIdLength = 128;
    public const int MaxTargetLength = 256;
    public const int MaxExpectedLength = 512;
    public const int MaxDescriptionLength = 1024;
    /// <summary>Cap on retained revisions per baseline id. History
    /// is the anti-laundering record; the cap is generous and a
    /// refusal at the cap is named, never a silent prune.</summary>
    public const int MaxRevisionsPerBaseline = 256;
    /// <summary>Clock-skew grace for a document's EffectiveUtc at
    /// admission (BD-SHARED-RMM-1 F9): within this window a
    /// just-past effective instant is admitted in force from the
    /// admission instant; beyond it the forward-only refusal
    /// stands. Five minutes — the same skew allowance the fleet
    /// uses for envelope and snapshot freshness.</summary>
    public static readonly TimeSpan EffectiveSkewGrace = TimeSpan.FromMinutes(5);
}

/// <summary>One desired-state assertion. Expected semantics by kind:
/// service_state → "Running"/"Stopped"; setting → the exact value
/// (ordinal-ignore-case compare, like the collectors' own matching);
/// software_required → presence, plus ExpectedVersion as a MINIMUM
/// (SoftwareVersion semantics: observed &gt;= expected);
/// software_forbidden → presence is the deviation (Expected unused);
/// security_posture → "on"/"off". RemediationId is the optional
/// RMM-08 link — data only; the gate decides whether it may fire.</summary>
public sealed record BaselineItem(
    string Id,
    string Kind,
    string Target,
    string? Expected,
    string? ExpectedVersion,
    string? RemediationId,
    bool Enabled,
    string Severity,
    string Description)
{
    public static BaselineItem Create(
        string id, string kind, string target, string? expected = null,
        string? expectedVersion = null, string? remediationId = null,
        bool enabled = true, string severity = AlertSeverities.Warning, string description = "") =>
        new(id, kind, target, expected, expectedVersion, remediationId, enabled, severity, description);
}

/// <summary>One signed baseline document: desired state for a device
/// class, assigned at org, group or device level. Revision is
/// monotonic per Id; EffectiveUtc is when this revision starts
/// judging (re-baselining is deliberate — never retroactive).</summary>
public sealed record BaselineDocument(
    string Id,
    long Revision,
    string Level,          // PolicyLevels.*
    string TargetId,       // org: scope id | group: group id | device: device id
    DateTimeOffset EffectiveUtc,
    string AuthoredBy,
    IReadOnlyList<BaselineItem> Items,
    string Description)
{
    public IReadOnlyList<BaselineItem> Items { get; init; } = Items ?? Array.Empty<BaselineItem>();

    /// <summary>Deterministic canonical JSON (items in authored
    /// order — item order is presentation, identity is by item id;
    /// documents sort by id at merge time) — the exact bytes the
    /// RMM-03 envelope payload carries and hashes.</summary>
    public string ToCanonicalJson()
    {
        var items = Items.Select(i => new
        {
            id = i.Id, kind = i.Kind, target = i.Target, expected = i.Expected,
            expectedVersion = i.ExpectedVersion, remediationId = i.RemediationId,
            enabled = i.Enabled, severity = i.Severity, description = i.Description,
        }).ToList();
        return JsonSerializer.Serialize(new
        {
            id = Id, revision = Revision, level = Level, targetId = TargetId,
            effectiveUtc = EffectiveUtc, authoredBy = AuthoredBy, description = Description, items,
        });
    }

    /// <summary>SHA-256 of the canonical JSON — the content identity
    /// audit events and drift reports carry.</summary>
    public string ContentHash =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(ToCanonicalJson()))).ToLowerInvariant();

    public static BaselineDocument? FromCanonicalJson(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            var items = new List<BaselineItem>();
            foreach (var el in root.GetProperty("items").EnumerateArray())
            {
                items.Add(new BaselineItem(
                    el.GetProperty("id").GetString() ?? "",
                    el.GetProperty("kind").GetString() ?? "",
                    el.GetProperty("target").GetString() ?? "",
                    OptString(el, "expected"), OptString(el, "expectedVersion"), OptString(el, "remediationId"),
                    el.GetProperty("enabled").GetBoolean(),
                    el.GetProperty("severity").GetString() ?? "",
                    OptString(el, "description") ?? ""));
            }
            return new BaselineDocument(
                root.GetProperty("id").GetString() ?? "",
                root.GetProperty("revision").GetInt64(),
                root.GetProperty("level").GetString() ?? "",
                root.GetProperty("targetId").GetString() ?? "",
                root.GetProperty("effectiveUtc").GetDateTimeOffset(),
                OptString(root, "authoredBy") ?? "",
                items,
                OptString(root, "description") ?? "");
        }
        catch { return null; }
    }

    private static string? OptString(JsonElement el, string name) =>
        el.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    /// <summary>Admission validation. Null when admissible;
    /// otherwise the refusal reason naming the first defect. A
    /// refused document changes NOTHING — the baseline in force
    /// stays in force.</summary>
    public string? Validate()
    {
        if (string.IsNullOrWhiteSpace(Id) || Id.Length > BaselineLimits.MaxIdLength)
            return "baseline needs an id within bounds — refused";
        if (Revision < 1)
            return $"baseline '{Id}' revision {Revision} is not positive — refused";
        if (!PolicyLevels.All.Contains(Level ?? ""))
            return $"baseline '{Id}': unknown level '{Level}' — refused";
        if (string.IsNullOrWhiteSpace(TargetId) || TargetId.Length > BaselineLimits.MaxTargetLength)
            return $"baseline '{Id}': target empty or over bounds — refused";
        if (string.IsNullOrWhiteSpace(AuthoredBy))
            return $"baseline '{Id}': no author recorded — refused (a baseline change is an attributed act; anonymous desired state is not admitted)";
        if (Description is { Length: > BaselineLimits.MaxDescriptionLength })
            return $"baseline '{Id}': description over bounds — refused";
        if (Items.Count > BaselineLimits.MaxItemsPerDocument)
            return $"baseline '{Id}' carries {Items.Count} items over the cap {BaselineLimits.MaxItemsPerDocument} — refused";
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var i in Items)
        {
            if (string.IsNullOrWhiteSpace(i.Id) || i.Id.Length > BaselineLimits.MaxIdLength)
                return $"baseline '{Id}': an item id is empty or over bounds — refused";
            // D38 fix (F11): item ids are matched case-insensitively
            // everywhere and DriftAlerting.ConditionIdFor TRIMS +
            // lowercases — an id carrying surrounding whitespace
            // (' svc' vs 'svc') would stay distinct at admission and
            // merge yet share one alert condition id, one deviation
            // masking the other. Whitespace-padded ids refuse.
            if (!string.Equals(i.Id, i.Id.Trim(), StringComparison.Ordinal))
                return $"baseline '{Id}': item id '{i.Id}' carries surrounding whitespace — refused (item ids are trimmed when condition ids are derived; a padded id would collide with its trimmed twin)";
            if (!seen.Add(i.Id))
                return $"baseline '{Id}': duplicate item id '{i.Id}' — refused";
            if (!BaselineItemKinds.All.Contains(i.Kind ?? ""))
                return $"baseline '{Id}' item '{i.Id}': unknown kind '{i.Kind}' — refused (an unknown kind is a field that changes meaning)";
            if (string.IsNullOrWhiteSpace(i.Target) || i.Target.Length > BaselineLimits.MaxTargetLength)
                return $"baseline '{Id}' item '{i.Id}': target empty or over bounds — refused";
            if (!AlertSeverities.All.Contains(i.Severity ?? ""))
                return $"baseline '{Id}' item '{i.Id}': unknown severity '{i.Severity}' — refused";
            if (i.Expected is { Length: > BaselineLimits.MaxExpectedLength } ||
                i.ExpectedVersion is { Length: > BaselineLimits.MaxExpectedLength } ||
                i.RemediationId is { Length: > BaselineLimits.MaxIdLength })
                return $"baseline '{Id}' item '{i.Id}': an expected/remediation value is over bounds — refused";
            switch (i.Kind)
            {
                case BaselineItemKinds.ServiceState:
                    if (i.Expected is null || !BaselineItemKinds.ServiceStates.Contains(i.Expected))
                        return $"baseline '{Id}' item '{i.Id}': service_state expects 'Running' or 'Stopped' — refused";
                    break;
                case BaselineItemKinds.Setting:
                    if (i.Expected is null)
                        return $"baseline '{Id}' item '{i.Id}': a setting item needs an expected value — refused";
                    break;
                case BaselineItemKinds.SecurityPosture:
                    if (!BaselineItemKinds.PostureTargets.Contains(i.Target))
                        return $"baseline '{Id}' item '{i.Id}': security_posture target must be av|firewall|encryption — refused";
                    if (i.Expected is not ("on" or "off"))
                        return $"baseline '{Id}' item '{i.Id}': security_posture expects 'on' or 'off' — refused";
                    break;
            }
        }
        return null;
    }
}

// ---- observed state ---------------------------------------------------------

/// <summary>Section names an observed-state snapshot can carry.
/// The evaluator treats a section NOT in CollectedSections as not
/// read: its items are indeterminate, never judged. Builders set
/// exactly the sections their source actually read.</summary>
public static class ObservedSections
{
    public const string Services = "services";
    public const string Settings = "settings";
    public const string Software = "software";
    public const string Security = "security";
    public static readonly IReadOnlySet<string> All = new HashSet<string> { Services, Settings, Software, Security };
}

/// <summary>Everything the collectors observed about one endpoint at
/// one instant, in the shapes RMM-04 (inventory SoftwareItem) and
/// RMM-01 (ServiceSample / SecurityStateSample) already produce —
/// comparison consumes their shapes, it does not invent its own.
/// Settings is the endpoint's key-settings map (name → value); the
/// production settings collector is host wiring (named remainder),
/// the shape is the contract.</summary>
public sealed record ObservedEndpointState(
    string DeviceId,
    DateTimeOffset ObservedUtc,
    IReadOnlyList<ServiceSample> Services,
    IReadOnlyDictionary<string, string>? Settings,
    IReadOnlyList<SoftwareItem> Software,
    SecurityStateSample? Security,
    IReadOnlySet<string> CollectedSections,
    IReadOnlyList<string> CollectorNotes)
{
    public IReadOnlyList<ServiceSample> Services { get; init; } = Services ?? Array.Empty<ServiceSample>();
    public IReadOnlyList<SoftwareItem> Software { get; init; } = Software ?? Array.Empty<SoftwareItem>();
    public IReadOnlySet<string> CollectedSections { get; init; } = CollectedSections ?? new HashSet<string>();
    public IReadOnlyList<string> CollectorNotes { get; init; } = CollectorNotes ?? Array.Empty<string>();

    public bool HasSection(string section) => CollectedSections.Contains(section);
}

/// <summary>Builders that project the existing reporting paths into
/// the observed-state shape. FromInventory is the RMM-04 path (the
/// hub cross-check uses the same projection, so agent and hub read
/// inventory identically); FromMonitorSample is the RMM-01 path.</summary>
public static class ObservedStateFactory
{
    public static ObservedEndpointState FromInventory(
        DeviceInventoryRecord record,
        IReadOnlyList<ServiceSample>? services = null,
        IReadOnlyDictionary<string, string>? settings = null,
        SecurityStateSample? security = null)
    {
        var sections = new HashSet<string> { ObservedSections.Software };
        if (services is not null) sections.Add(ObservedSections.Services);
        if (settings is not null) sections.Add(ObservedSections.Settings);
        if (security is not null) sections.Add(ObservedSections.Security);
        return new ObservedEndpointState(
            record.DeviceId, record.LastSeenUtc,
            services ?? Array.Empty<ServiceSample>(), settings,
            record.Software, security, sections,
            new[] { "source:rmm04-inventory" });
    }

    public static ObservedEndpointState FromMonitorSample(
        EndpointSample sample,
        IReadOnlyList<SoftwareItem>? software = null,
        IReadOnlyDictionary<string, string>? settings = null)
    {
        var sections = new HashSet<string>();
        // D38 fix (F7): an RMM-01 monitor sample carries WATCHED
        // lists — the services and applications the monitor was
        // told to watch — not complete enumerations of the
        // endpoint. Marking Services/Software "collected" whenever
        // the watched list was non-empty made the evaluator read a
        // service or app ABSENT from the watched list as "not
        // present", so a Stopped expectation or a forbidden-app
        // rule passed on an item that was never observed. The
        // sample's data is still carried (a watched service that IS
        // present can be read by other surfaces), but the sections
        // are NOT claimed collected: baseline items over them are
        // indeterminate from this source, never compliant. Only an
        // explicitly supplied software list (a caller's complete
        // enumeration) claims the Software section. The security
        // sample is a whole-posture reading, not a list, so it
        // still claims its section.
        if (sample.Security is not null) sections.Add(ObservedSections.Security);
        if (software is not null) sections.Add(ObservedSections.Software);
        if (settings is not null) sections.Add(ObservedSections.Settings);
        var invSoftware = software ?? sample.Applications
            .Where(a => a.Installed)
            .Select(a => new SoftwareItem(a.Name, a.Version ?? "", null, null, null))
            .ToList();
        var notes = sample.CollectorNotes.Prepend("source:rmm01-monitor-sample").ToList();
        if (sample.Services.Count > 0)
            notes.Add("monitor sample services are a watched subset, not a complete service enumeration — the services section is not claimed collected");
        if (software is null && sample.Applications.Count > 0)
            notes.Add("monitor sample applications are a watched subset, not a complete software inventory — the software section is not claimed collected");
        return new ObservedEndpointState(
            sample.DeviceId, sample.AtUtc, sample.Services, settings,
            invSoftware, sample.Security, sections, notes);
    }
}

/// <summary>The collector seam the drift service reads observed
/// state through. Implementations must not fabricate: an unreadable
/// section is absent from CollectedSections, and a wholly failed
/// observation returns null (the cycle is UNKNOWN, never compliant).</summary>
public interface IObservedStateProvider
{
    ObservedEndpointState? Observe(string deviceId, DateTimeOffset now);
}

/// <summary>Test double: a scripted current state per device,
/// call-counted.</summary>
public sealed class FakeObservedStateProvider : IObservedStateProvider
{
    private readonly Dictionary<string, ObservedEndpointState?> _byDevice = new(StringComparer.OrdinalIgnoreCase);
    public int CallCount { get; private set; }
    /// <summary>When set, Observe returns this state for ANY device
    /// query — the seam destruction tests use to simulate a provider
    /// answering for the wrong device.</summary>
    public ObservedEndpointState? Forced { get; set; }
    public void Set(ObservedEndpointState? state)
    {
        if (state is not null) _byDevice[state.DeviceId] = state;
    }
    public void SetNull(string deviceId) => _byDevice[deviceId] = null;
    public ObservedEndpointState? Observe(string deviceId, DateTimeOffset now)
    {
        CallCount++;
        if (Forced is not null) return Forced;
        return _byDevice.TryGetValue(deviceId ?? "", out var s) ? s : null;
    }
}

/// <summary>The honest placeholder where no collectors are wired:
/// every observation is null — the drift cycle reports UNKNOWN,
/// never a fabricated "compliant". Host wiring (service controller,
/// settings readers, Security Center) is a named remainder.</summary>
public sealed class UnavailableObservedStateProvider : IObservedStateProvider
{
    public ObservedEndpointState? Observe(string deviceId, DateTimeOffset now) => null;
}

// ---- effective baseline -------------------------------------------------------

/// <summary>One item in the Effective Baseline, with the provenance
/// Effective Policy discipline requires: which level, document and
/// revision set it.</summary>
public sealed record EffectiveBaselineItem(
    BaselineItem Item, string SourceLevel, string SourceDocumentId, long SourceRevision);

/// <summary>The computed baseline for one device at one instant:
/// the merged items (org → group → device, later level wins per
/// item id), the contributing documents, and a content hash over
/// the merged result — the identity a drift report carries, so a
/// report can always be tied to the exact desired state it judged
/// against.</summary>
public sealed record EffectiveBaseline(
    string DeviceId,
    DateTimeOffset AsOfUtc,
    IReadOnlyList<EffectiveBaselineItem> Items,
    IReadOnlyList<string> ContributingDocuments)
{
    public IReadOnlyList<EffectiveBaselineItem> Items { get; init; } = Items ?? Array.Empty<EffectiveBaselineItem>();
    public IReadOnlyList<string> ContributingDocuments { get; init; } = ContributingDocuments ?? Array.Empty<string>();

    public EffectiveBaselineItem? Get(string itemId) =>
        Items.FirstOrDefault(i => string.Equals(i.Item.Id, itemId ?? "", StringComparison.OrdinalIgnoreCase));

    public string ContentHash => BaselineHash.Sha256Hex(string.Join(";", Items
        .OrderBy(i => i.Item.Id, StringComparer.Ordinal)
        .Select(i => $"{i.Item.Id}|{i.Item.Kind}|{i.Item.Target}|{i.Item.Expected}|{i.Item.ExpectedVersion}|{i.Item.RemediationId}|{i.Item.Enabled}|{i.SourceDocumentId}@{i.SourceRevision}")));

    public bool IsEmpty => Items.Count == 0;
}

public static class BaselineHash
{
    public static string Sha256Hex(string s) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(s))).ToLowerInvariant();
}

// ---- drift findings -----------------------------------------------------------

public static class DriftOutcomes
{
    public const string Compliant = "compliant";
    public const string Drifted = "drifted";
    /// <summary>At least one in-scope item could not be judged and
    /// none deviated: NOT compliant, NOT proven drifted — a third
    /// state, never folded into either.</summary>
    public const string Unknown = "unknown";
    public const string NoBaseline = "no_baseline";
}

/// <summary>The RMM-01 alert kind drift findings ride. It is
/// deliberately NOT in RMM-01's NeverSuppressible set (this lane
/// does not edit RMM-01's files): a maintenance window can suppress
/// a drift NOTIFICATION during planned change work — never the
/// evaluation, the audit entries, or the deviation record.</summary>
public static class DriftAlerting
{
    public const string Kind = "baseline_drift";
    public const string Source = "endpoint";
    /// <summary>One condition per (baseline item): the centre dedups
    /// on (device, condition), so a persistent deviation is ONE
    /// active alert that refreshes — never a stream of duplicates.</summary>
    public static string ConditionIdFor(string itemId) =>
        "drift:" + (itemId ?? "").Trim().ToLowerInvariant();
}

/// <summary>One named deviation: the item, what was expected, what
/// was observed, and where the expectation came from. This is the
/// unit a drift report is made of — per item, never a bare flag.</summary>
public sealed record DriftDeviation(
    string ItemId,
    string Kind,
    string Target,
    string Expected,
    string Observed,
    string Detail,
    string Severity,
    string? RemediationId,
    string SourceDocumentId,
    long SourceRevision)
{
    public string ConditionId => DriftAlerting.ConditionIdFor(ItemId);
}

/// <summary>One item that could not be judged (its section was not
/// collected, or the specific reading was absent). Named, with the
/// reason — a gap is a finding about visibility, not a pass.</summary>
public sealed record DriftIndeterminate(string ItemId, string Kind, string Target, string Reason);

/// <summary>One full comparison of one device against its effective
/// baseline at one instant.</summary>
public sealed record DriftEvaluation(
    string DeviceId,
    DateTimeOffset EvaluatedUtc,
    DateTimeOffset ObservedUtc,
    string BaselineHash,
    IReadOnlyList<string> BaselineDocuments,
    string Outcome,
    IReadOnlyList<DriftDeviation> Deviations,
    IReadOnlyList<DriftIndeterminate> Indeterminate,
    int ItemsJudged,
    int ItemsSkippedOutOfScope,
    int ItemsSkippedDisabled)
{
    public IReadOnlyList<DriftDeviation> Deviations { get; init; } = Deviations ?? Array.Empty<DriftDeviation>();
    public IReadOnlyList<DriftIndeterminate> Indeterminate { get; init; } = Indeterminate ?? Array.Empty<DriftIndeterminate>();
    public bool IsDrifted => Outcome == DriftOutcomes.Drifted;
}

/// <summary>The pure evaluator. No state, no clock beyond the
/// instants it is handed, no I/O: the same (baseline, observed,
/// scope) always yields the same evaluation.</summary>
public static class BaselineEvaluator
{
    public static DriftEvaluation Evaluate(
        EffectiveBaseline baseline, ObservedEndpointState observed,
        IReadOnlySet<string> inScopeKinds, DateTimeOffset now)
    {
        var deviations = new List<DriftDeviation>();
        var indeterminate = new List<DriftIndeterminate>();
        var judged = 0; var outOfScope = 0; var disabled = 0;

        foreach (var entry in baseline.Items.OrderBy(i => i.Item.Id, StringComparer.Ordinal))
        {
            var item = entry.Item;
            if (!item.Enabled) { disabled++; continue; }
            if (!inScopeKinds.Contains(item.Kind)) { outOfScope++; continue; }
            judged++;

            DriftDeviation Dev(string expected, string obs) => new(
                item.Id, item.Kind, item.Target, expected, obs,
                $"{item.Kind} '{item.Target}': expected {expected}, observed {obs}",
                item.Severity, item.RemediationId, entry.SourceDocumentId, entry.SourceRevision);
            DriftIndeterminate Gap(string reason) => new(item.Id, item.Kind, item.Target, reason);

            switch (item.Kind)
            {
                case BaselineItemKinds.ServiceState:
                {
                    if (!observed.HasSection(ObservedSections.Services)) { indeterminate.Add(Gap("service list not collected")); break; }
                    var svc = observed.Services.FirstOrDefault(s =>
                        string.Equals(s.Name, item.Target, StringComparison.OrdinalIgnoreCase));
                    if (svc is null)
                    {
                        // A missing service is not running: it
                        // satisfies a Stopped expectation and
                        // deviates from a Running one.
                        if (string.Equals(item.Expected, "Running", StringComparison.OrdinalIgnoreCase))
                            deviations.Add(Dev("Running", "not present"));
                        break;
                    }
                    if (!string.Equals(svc.State, item.Expected, StringComparison.OrdinalIgnoreCase))
                        deviations.Add(Dev(item.Expected!, svc.State));
                    break;
                }
                case BaselineItemKinds.Setting:
                {
                    if (!observed.HasSection(ObservedSections.Settings) || observed.Settings is null)
                    { indeterminate.Add(Gap("settings not collected")); break; }
                    // Key lookup is ordinal-ignore-case like the
                    // value comparison (the model's own doctrine):
                    // the collectors' map may carry the key in a
                    // different casing than the baseline's target,
                    // and a casing difference is not an absence
                    // (recovery-lane fix, RMM-19 — a case-sensitive
                    // TryGetValue read a present setting as absent
                    // and reported false drift).
                    string? value = null; var found = false;
                    foreach (var kv in observed.Settings)
                        if (string.Equals(kv.Key, item.Target, StringComparison.OrdinalIgnoreCase))
                        { value = kv.Value; found = true; break; }
                    if (!found)
                        deviations.Add(Dev(item.Expected!, "(absent)"));
                    else if (!string.Equals(value, item.Expected, StringComparison.OrdinalIgnoreCase))
                        deviations.Add(Dev(item.Expected!, value!));
                    break;
                }
                case BaselineItemKinds.SoftwareRequired:
                {
                    if (!observed.HasSection(ObservedSections.Software)) { indeterminate.Add(Gap("software list not collected")); break; }
                    var app = observed.Software.FirstOrDefault(s =>
                        string.Equals(s.NormalizedName, item.Target, StringComparison.OrdinalIgnoreCase));
                    if (app is null) { deviations.Add(Dev("installed", "not installed")); break; }
                    if (!string.IsNullOrWhiteSpace(item.ExpectedVersion) &&
                        SoftwareVersion.Compare(app.Version, item.ExpectedVersion) < 0)
                        deviations.Add(Dev($"version >= {item.ExpectedVersion}", $"version {app.Version}"));
                    break;
                }
                case BaselineItemKinds.SoftwareForbidden:
                {
                    if (!observed.HasSection(ObservedSections.Software)) { indeterminate.Add(Gap("software list not collected")); break; }
                    var app = observed.Software.FirstOrDefault(s =>
                        string.Equals(s.NormalizedName, item.Target, StringComparison.OrdinalIgnoreCase));
                    if (app is not null)
                        deviations.Add(Dev("not installed", $"installed (version {app.Version})"));
                    break;
                }
                case BaselineItemKinds.SecurityPosture:
                {
                    if (!observed.HasSection(ObservedSections.Security) || observed.Security is null)
                    { indeterminate.Add(Gap("security state not collected")); break; }
                    bool? reading = item.Target.ToLowerInvariant() switch
                    {
                        "av" => observed.Security.AvEnabled,
                        "firewall" => observed.Security.FirewallEnabled,
                        "encryption" => observed.Security.EncryptionEnabled,
                        _ => null,
                    };
                    if (reading is not { } on) { indeterminate.Add(Gap($"security posture '{item.Target}' not read")); break; }
                    var observedText = on ? "on" : "off";
                    if (observedText != item.Expected) deviations.Add(Dev(item.Expected!, observedText));
                    break;
                }
                default:
                    indeterminate.Add(Gap($"unknown kind '{item.Kind}' — never judged"));
                    break;
            }
        }

        var outcome = baseline.IsEmpty ? DriftOutcomes.NoBaseline
            : deviations.Count > 0 ? DriftOutcomes.Drifted
            : indeterminate.Count > 0 ? DriftOutcomes.Unknown
            : DriftOutcomes.Compliant;
        return new DriftEvaluation(
            baseline.DeviceId, now, observed.ObservedUtc, baseline.ContentHash,
            baseline.ContributingDocuments, outcome, deviations, indeterminate,
            judged, outOfScope, disabled);
    }
}

// ---- absorption (the anti-laundering record) -----------------------------------

/// <summary>One existing deviation a baseline change would absorb:
/// under the new effective baseline the deviation no longer reads
/// as drift — because the item was removed, disabled, taken out of
/// scope, or its expectation moved onto the observed value. The
/// notice NAMES which, with the old expectation and the observed
/// value, so the absorption is a reviewed fact, never a quiet edit.</summary>
public sealed record BaselineAbsorptionNotice(
    string ItemId,
    string Kind,
    string Target,
    string OldExpected,
    string Observed,
    string NewExpected,
    string Mechanism); // item_removed | item_disabled | expectation_moved | item_replaced | out_of_scope

/// <summary>A permanent in-model record of one re-baselining: which
/// baseline moved from which revision to which, when it was
/// admitted, when it takes effect, who authored it, and every
/// absorption it carried (empty when it absorbed nothing).</summary>
public sealed record BaselineRevisionRecord(
    string BaselineId,
    long FromRevision,
    long ToRevision,
    DateTimeOffset AdmittedUtc,
    DateTimeOffset EffectiveUtc,
    string AuthoredBy,
    IReadOnlyList<BaselineAbsorptionNotice> Absorptions)
{
    public IReadOnlyList<BaselineAbsorptionNotice> Absorptions { get; init; } =
        Absorptions ?? Array.Empty<BaselineAbsorptionNotice>();
}

public sealed record BaselineAdmissionResult(
    bool Accepted,
    string Reason,
    IReadOnlyList<BaselineAbsorptionNotice> Absorptions,
    BaselineRevisionRecord? RevisionRecord)
{
    public IReadOnlyList<BaselineAbsorptionNotice> Absorptions { get; init; } =
        Absorptions ?? Array.Empty<BaselineAbsorptionNotice>();
}

/// <summary>Pure absorption analysis: given the deviations an
/// evaluation actually found, which of them would the NEW effective
/// baseline (and scope) no longer report? Re-evaluating the SAME
/// observed state under the new baseline is the ground truth: a
/// deviation that disappears was absorbed; the mechanism is read
/// off what changed for that item.</summary>
public static class BaselineAbsorption
{
    // D38 fix (F12): the old signature carried an oldBaseline
    // parameter nothing read (the store computed it only to pass
    // it in) — removed. D38 fix (F2/F12): the mechanism label is
    // now read off WHAT changed for the item, honestly:
    //   * item_removed / item_disabled / out_of_scope — the
    //     baseline change itself ends the judgment; these are
    //     named even when the rejudged cycle cannot re-observe
    //     the item.
    //   * item_replaced — the same item id now names a DIFFERENT
    //     kind or target: the old deviation was not "expected
    //     differently", the item was swapped; NewExpected
    //     describes the replacement item, never the old item's
    //     expectation values pasted onto it.
    //   * expectation_moved — same kind + target, and the item
    //     was actually RE-JUDGED against the supplied observed
    //     state and no longer deviates. If the rejudged cycle
    //     leaves the item INDETERMINATE (its section was not in
    //     the supplied snapshot), no absorption is claimed: a
    //     collector gap must not launder drift by making the
    //     deviation merely unprovable at admission time.
    public static IReadOnlyList<BaselineAbsorptionNotice> Analyze(
        EffectiveBaseline newBaseline,
        DriftEvaluation lastEvaluation, ObservedEndpointState observed,
        IReadOnlySet<string> newScopeKinds)
    {
        if (lastEvaluation.Deviations.Count == 0) return Array.Empty<BaselineAbsorptionNotice>();
        var rejudged = BaselineEvaluator.Evaluate(newBaseline, observed, newScopeKinds, lastEvaluation.EvaluatedUtc);
        var stillDeviating = rejudged.Deviations
            .Select(d => d.ItemId).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var rejudgedIndeterminate = rejudged.Indeterminate
            .Select(g => g.ItemId).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var notices = new List<BaselineAbsorptionNotice>();
        foreach (var dev in lastEvaluation.Deviations)
        {
            if (stillDeviating.Contains(dev.ItemId)) continue;
            var newEntry = newBaseline.Get(dev.ItemId);
            string mechanism; string newExpected;
            if (newEntry is null) { mechanism = "item_removed"; newExpected = "(item removed)"; }
            else if (!newEntry.Item.Enabled) { mechanism = "item_disabled"; newExpected = "(item disabled)"; }
            else if (!newScopeKinds.Contains(newEntry.Item.Kind)) { mechanism = "out_of_scope"; newExpected = "(kind out of scope)"; }
            else if (!string.Equals(newEntry.Item.Kind, dev.Kind, StringComparison.OrdinalIgnoreCase) ||
                     !string.Equals(newEntry.Item.Target, dev.Target, StringComparison.OrdinalIgnoreCase))
            {
                mechanism = "item_replaced";
                newExpected = $"{newEntry.Item.Kind} '{newEntry.Item.Target}' expected " +
                    (newEntry.Item.Kind == BaselineItemKinds.SoftwareRequired &&
                     !string.IsNullOrWhiteSpace(newEntry.Item.ExpectedVersion)
                        ? $"version >= {newEntry.Item.ExpectedVersion}"
                        : newEntry.Item.Expected ?? "(presence judged)");
            }
            else
            {
                if (rejudgedIndeterminate.Contains(dev.ItemId)) continue;
                mechanism = "expectation_moved";
                newExpected = newEntry.Item.Kind == BaselineItemKinds.SoftwareRequired &&
                              !string.IsNullOrWhiteSpace(newEntry.Item.ExpectedVersion)
                    ? $"version >= {newEntry.Item.ExpectedVersion}"
                    : newEntry.Item.Expected ?? "(none)";
            }
            notices.Add(new BaselineAbsorptionNotice(
                dev.ItemId, dev.Kind, dev.Target, dev.Expected, dev.Observed, newExpected, mechanism));
        }
        return notices;
    }
}

// ---- the versioned store ---------------------------------------------------------

/// <summary>The baseline store: versioned documents with revision
/// discipline, per-id history, Effective Baseline computation with
/// inheritance, and the permanent revision-record trail. Admission
/// refuses: invalid content, consent-floor-shaped targets (a
/// baseline item can never name presence/STOP/audit as a setting —
/// baselines judge managed state, the floor is not managed state),
/// stale revisions, same-revision conflicts, and BACKDATED
/// effective dates (a new revision whose EffectiveUtc precedes the
/// current revision's would rewrite the past — re-baselining is
/// forward-only).</summary>
/// <summary>Capability token for a LOCKED BaselineStore (D38 fix,
/// F9). A store on its own is a model component and admits freely
/// (hub-side authoring, tests). A store OWNED by a
/// BaselineDriftService is locked to that service: the service
/// registers its private token, and Admit then refuses any call
/// that does not present it — so the service's public surface can
/// no longer be used to bypass the signed-delivery gate and the
/// chained audit by calling Store.Admit directly. Identity is
/// reference equality: a caller minting its own token gains
/// nothing, because it is not the registered instance.</summary>
public sealed class BaselineAdmissionToken
{
    public BaselineAdmissionToken() { }
}

public sealed class BaselineStore
{
    private readonly Dictionary<string, List<BaselineDocument>> _history = new(StringComparer.Ordinal);
    private readonly List<BaselineRevisionRecord> _revisionRecords = new();
    private readonly object _gate = new();
    private BaselineAdmissionToken? _admissionToken;

    /// <summary>Lock this store's admission to the holder of
    /// `token` (the owning BaselineDriftService). First lock wins;
    /// later calls with a different token are ignored, so a caller
    /// who reaches the store cannot re-lock it to themselves.</summary>
    public void LockAdmission(BaselineAdmissionToken token)
    {
        if (token is null) return;
        lock (_gate) _admissionToken ??= token;
    }

    /// <summary>True once an owning service has locked admission.</summary>
    public bool AdmissionLocked { get { lock (_gate) return _admissionToken is not null; } }

    public IReadOnlyList<BaselineRevisionRecord> RevisionRecords
    {
        get { lock (_gate) return _revisionRecords.ToList(); }
    }

    public BaselineDocument? Current(string baselineId)
    {
        lock (_gate)
            return baselineId is not null && _history.TryGetValue(baselineId, out var list) && list.Count > 0
                ? list[^1] : null;
    }

    public IReadOnlyList<BaselineDocument> History(string baselineId)
    {
        lock (_gate)
            return baselineId is not null && _history.TryGetValue(baselineId, out var list)
                ? list.ToList() : Array.Empty<BaselineDocument>();
    }

    public IReadOnlyList<BaselineDocument> AllCurrent
    {
        get { lock (_gate) return _history.Values.Where(l => l.Count > 0).Select(l => l[^1])
            .OrderBy(d => d.Id, StringComparer.Ordinal).ToList(); }
    }

    /// <summary>Admit a document. Absorption analysis runs when the
    /// caller supplies the context (the device whose drift is on
    /// record, its old effective baseline, its last evaluation and
    /// the observed state that produced it, and the new scope): the
    /// store computes the new effective baseline for that device
    /// WITH the candidate admitted and names every absorption.
    /// Without context the admission is still recorded — absorption
    /// is then the service layer's duty for its other devices.</summary>
    public BaselineAdmissionResult Admit(
        BaselineDocument doc, DateTimeOffset now,
        IDeviceFacts? absorptionFacts = null,
        IReadOnlyList<string>? absorptionMemberGroups = null,
        DriftEvaluation? lastEvaluation = null,
        ObservedEndpointState? lastObserved = null,
        IReadOnlySet<string>? newScopeKinds = null,
        BaselineAdmissionToken? admissionToken = null)
    {
        if (doc is null) return new BaselineAdmissionResult(false, "no baseline document — refused", null, null);
        var invalid = doc.Validate();
        if (invalid is not null) return new BaselineAdmissionResult(false, invalid, null, null);
        foreach (var item in doc.Items)
            if (ConsentFloorGuard.IsDenied(item.Target) || ConsentFloorGuard.IsDenied(item.Id))
                return new BaselineAdmissionResult(false,
                    $"baseline '{doc.Id}' item '{item.Id}' names the §7.10 consent floor ('{item.Target}') — REFUSED: presence, STOP and the audit chain are never baseline-managed state", null, null);
        // D38 fix (F9): a store locked by its owning service admits
        // ONLY through that service (which enforces signed delivery
        // or the audited local-authoring path). A direct Admit call
        // on a locked store — the bypass around RMM-03 and the
        // chained audit — refuses by name.
        lock (_gate)
        {
            if (_admissionToken is not null && !ReferenceEquals(admissionToken, _admissionToken))
                return new BaselineAdmissionResult(false,
                    "this baseline store is owned by a BaselineDriftService — admission runs through the service (signed delivery or its audited local path), never by calling Store.Admit directly — refused", null, null);
        }
        // D38 fix (F8): forward-only applies to EVERY document, not
        // just a new revision of an existing id. A document whose
        // EffectiveUtc precedes its admission instant — a fresh
        // device-level override id carrying a past date, or a new
        // revision effective after its predecessor's date but
        // before now — would retroactively rewrite what
        // ComputeEffective reports for instants already judged.
        // Re-baselining takes effect from admission onward, never
        // into the judged past.
        // BD-SHARED-RMM-1 F9: a small named grace for clock skew.
        // The forward-only rule refused ANY past-effective
        // document, so a baseline authored on a hub whose clock
        // ran seconds ahead — the routine case for a document
        // delivered across machines — could never be admitted at
        // all. Within EffectiveSkewGrace the document is admitted
        // with its in-force instant recorded as the ADMISSION
        // instant (never the past instant): forward-only still
        // holds absolutely, judged history is never rewritten,
        // and the adjustment is named in the admission reason and
        // the revision record. Beyond the grace the refusal
        // stands exactly as before.
        var effectiveUtc = doc.EffectiveUtc;
        var skewAdjusted = false;
        if (doc.EffectiveUtc < now)
        {
            if (now - doc.EffectiveUtc <= BaselineLimits.EffectiveSkewGrace)
            { effectiveUtc = now; skewAdjusted = true; }
            else
                return new BaselineAdmissionResult(false,
                    $"baseline '{doc.Id}' r{doc.Revision} is effective {doc.EffectiveUtc:O}, BEFORE its admission time {now:O} by more than the {BaselineLimits.EffectiveSkewGrace} skew grace — refused (re-baselining is forward-only from admission; a past-effective document would rewrite judged history)", null, null);
        }

        lock (_gate)
        {
            _history.TryGetValue(doc.Id, out var list);
            var current = list is { Count: > 0 } ? list[^1] : null;
            if (current is not null)
            {
                if (doc.Revision < current.Revision)
                    return new BaselineAdmissionResult(false,
                        $"baseline '{doc.Id}' revision {doc.Revision} is stale (current {current.Revision}) — refused (an older baseline never replaces a newer one)", null, null);
                if (doc.Revision == current.Revision)
                {
                    if (doc.ToCanonicalJson() != current.ToCanonicalJson())
                        return new BaselineAdmissionResult(false,
                            $"baseline '{doc.Id}' revision {doc.Revision} conflicts with the admitted document of the same id+revision — refused", null, null);
                    return new BaselineAdmissionResult(true,
                        $"baseline '{doc.Id}' r{doc.Revision} already admitted (idempotent)", null, null);
                }
                if (effectiveUtc < current.EffectiveUtc)
                    return new BaselineAdmissionResult(false,
                        $"baseline '{doc.Id}' r{doc.Revision} is effective {effectiveUtc:O}, BEFORE the current revision's {current.EffectiveUtc:O} — refused (re-baselining is forward-only; a backdated revision would rewrite judged history)", null, null);
                if (list!.Count >= BaselineLimits.MaxRevisionsPerBaseline)
                    return new BaselineAdmissionResult(false,
                        $"baseline '{doc.Id}' already carries {list.Count} revisions (cap {BaselineLimits.MaxRevisionsPerBaseline}) — refused (history is never silently pruned)", null, null);
            }

            // Absorption analysis BEFORE the candidate lands, so the
            // old effective baseline is still computable.
            IReadOnlyList<BaselineAbsorptionNotice> absorptions = Array.Empty<BaselineAbsorptionNotice>();
            EffectiveBaseline? oldEffective = null;
            if (absorptionFacts is not null && lastEvaluation is not null && lastObserved is not null)
            {
                oldEffective = ComputeEffectiveLocked(absorptionFacts,
                    absorptionMemberGroups ?? Array.Empty<string>(), lastEvaluation.EvaluatedUtc);
            }

            // Defensive copy: the admitted document is frozen at
            // admission (the RMM-07 destruction lesson — a caller
            // holding the original items list must not be able to
            // mutate live desired state with no revision, no
            // signature and no audit).
            var frozen = doc with { Items = doc.Items.ToList(), EffectiveUtc = effectiveUtc };
            if (list is null) _history[doc.Id] = list = new List<BaselineDocument>();
            list.Add(frozen);

            if (oldEffective is not null && absorptionFacts is not null && lastEvaluation is not null && lastObserved is not null)
            {
                // The new effective baseline is computed at the
                // instant the candidate takes effect (or the
                // evaluation instant, if that is later): absorption
                // asks "when this revision judges, does the drift
                // still count?" — not "does it count before the
                // revision is even in force?".
                var newAsOf = effectiveUtc > lastEvaluation.EvaluatedUtc
                    ? effectiveUtc : lastEvaluation.EvaluatedUtc;
                var newEffective = ComputeEffectiveLocked(absorptionFacts,
                    absorptionMemberGroups ?? Array.Empty<string>(), newAsOf);
                absorptions = BaselineAbsorption.Analyze(newEffective,
                    lastEvaluation, lastObserved,
                    newScopeKinds ?? BaselineItemKinds.All);
            }

            var record = new BaselineRevisionRecord(
                doc.Id, current?.Revision ?? 0, doc.Revision, now, effectiveUtc,
                doc.AuthoredBy, absorptions);
            _revisionRecords.Add(record);
            var reason = $"baseline '{doc.Id}' r{doc.Revision} admitted at {doc.Level} level for '{doc.TargetId}' (effective {effectiveUtc:O})" +
                (skewAdjusted ? $" — authored effective {doc.EffectiveUtc:O} fell inside the {BaselineLimits.EffectiveSkewGrace} skew grace and was recorded in force from admission, never retroactively" : "") +
                (absorptions.Count > 0
                    ? $"; ABSORBS {absorptions.Count} existing deviation(s): {string.Join("; ", absorptions.Select(a => $"{a.ItemId} ({a.Mechanism}: expected was {a.OldExpected}, observed {a.Observed})"))} — the absorbed drift stays in the alert/audit history; this revision does not erase it"
                    : "");
            return new BaselineAdmissionResult(true, reason, absorptions, record);
        }
    }

    /// <summary>Compute the Effective Baseline for one device at one
    /// instant: for each baseline id, the revision in force at
    /// `asOfUtc` (greatest EffectiveUtc &lt;= asOf among admitted
    /// revisions — a future-effective revision does not judge yet);
    /// documents then merge org → group → device, later level wins
    /// per item id, provenance kept per item.</summary>
    public EffectiveBaseline ComputeEffective(IDeviceFacts facts, IReadOnlyList<string> memberGroupIds, DateTimeOffset asOfUtc)
    {
        lock (_gate) return ComputeEffectiveLocked(facts, memberGroupIds, asOfUtc);
    }

    /// <summary>D38 fix (F1): absorption analysis for a candidate
    /// document and a device WITHOUT admitting anything — the
    /// owning service runs this for every OTHER device whose drift
    /// is on record when a revision is admitted for one device, so
    /// an org/group revision cannot absorb drift on devices the
    /// caller never named, silently. The candidate is folded into
    /// the in-force selection exactly as admission would fold it
    /// (same id, higher revision, in force at the later of its
    /// EffectiveUtc and the evaluation instant).</summary>
    public IReadOnlyList<BaselineAbsorptionNotice> PreviewAbsorptions(
        BaselineDocument candidate, IDeviceFacts facts, IReadOnlyList<string> memberGroupIds,
        DriftEvaluation lastEvaluation, ObservedEndpointState lastObserved,
        IReadOnlySet<string>? newScopeKinds = null)
    {
        if (candidate is null || facts is null || lastEvaluation is null || lastObserved is null)
            return Array.Empty<BaselineAbsorptionNotice>();
        lock (_gate)
        {
            var newAsOf = candidate.EffectiveUtc > lastEvaluation.EvaluatedUtc
                ? candidate.EffectiveUtc : lastEvaluation.EvaluatedUtc;
            var newEffective = ComputeEffectiveLocked(facts,
                memberGroupIds ?? Array.Empty<string>(), newAsOf, candidate);
            return BaselineAbsorption.Analyze(newEffective, lastEvaluation, lastObserved,
                newScopeKinds ?? BaselineItemKinds.All);
        }
    }

    private EffectiveBaseline ComputeEffectiveLocked(IDeviceFacts facts, IReadOnlyList<string> memberGroupIds, DateTimeOffset asOfUtc,
        BaselineDocument? extraCandidate = null)
    {
        var memberSet = new HashSet<string>(memberGroupIds, StringComparer.OrdinalIgnoreCase);
        var inForce = new List<BaselineDocument>();
        foreach (var (id, stored) in _history)
        {
            var list = stored;
            if (extraCandidate is not null && string.Equals(id, extraCandidate.Id, StringComparison.Ordinal))
                list = stored.Concat(new[] { extraCandidate }).ToList();
            BaselineDocument? best = null;
            foreach (var d in list)
                if (d.EffectiveUtc <= asOfUtc && (best is null || d.Revision > best.Revision))
                    best = d;
            if (best is not null) inForce.Add(best);
        }
        if (extraCandidate is not null && !_history.ContainsKey(extraCandidate.Id) &&
            extraCandidate.EffectiveUtc <= asOfUtc)
            inForce.Add(extraCandidate);

        var merged = new Dictionary<string, EffectiveBaselineItem>(StringComparer.OrdinalIgnoreCase);
        var contributing = new List<string>();
        void Apply(IEnumerable<BaselineDocument> levelDocs)
        {
            foreach (var doc in levelDocs.OrderBy(d => d.TargetId, StringComparer.Ordinal).ThenBy(d => d.Id, StringComparer.Ordinal))
            {
                contributing.Add($"{doc.Id}@r{doc.Revision}");
                foreach (var item in doc.Items)
                    merged[item.Id] = new EffectiveBaselineItem(item, doc.Level, doc.Id, doc.Revision);
            }
        }

        Apply(inForce.Where(d => d.Level == PolicyLevels.Org &&
            (d.TargetId == facts.ScopeId || d.TargetId == "*")));
        Apply(inForce.Where(d => d.Level == PolicyLevels.Group && memberSet.Contains(d.TargetId)));
        Apply(inForce.Where(d => d.Level == PolicyLevels.Device && d.TargetId == facts.DeviceId));
        return new EffectiveBaseline(facts.DeviceId, asOfUtc,
            merged.Values.OrderBy(i => i.Item.Id, StringComparer.Ordinal).ToList(), contributing);
    }
}

// ---- policy resolution ------------------------------------------------------------

/// <summary>The resolved RMM-19 policy for one device: cadence,
/// in-scope kinds, the auto-remediation posture, and the drift
/// cooldown — with every clamp/drop named in Notes.</summary>
public sealed record ResolvedBaselinePolicy(
    int CadenceSeconds,
    IReadOnlySet<string> ScopeKinds,
    bool AutoRemediate,
    IReadOnlySet<string> RemediationAllowlist,
    int DriftCooldownSeconds,
    IReadOnlyList<string> Notes)
{
    public IReadOnlyList<string> Notes { get; init; } = Notes ?? Array.Empty<string>();
    public TimeSpan Cadence => TimeSpan.FromSeconds(CadenceSeconds);
    public TimeSpan DriftCooldown => TimeSpan.FromSeconds(DriftCooldownSeconds);
}

public static class BaselinePolicyResolver
{
    public static ResolvedBaselinePolicy Resolve(ManagementPolicyEngine engine, IDeviceFacts facts)
    {
        var eff = engine.ComputeEffective(facts);
        var notes = new List<string>();

        var cadence = BaselinePolicyKeys.DefaultCadenceSeconds;
        if (eff.Get(BaselinePolicyKeys.CadenceSeconds) is { } c)
        {
            if (int.TryParse(c.Value, out var v))
            {
                cadence = Math.Clamp(v, BaselinePolicyKeys.MinCadenceSeconds, BaselinePolicyKeys.MaxCadenceSeconds);
                if (cadence != v) notes.Add($"cadence {v}s clamped to {cadence}s (bounds {BaselinePolicyKeys.MinCadenceSeconds}–{BaselinePolicyKeys.MaxCadenceSeconds})");
            }
            else notes.Add($"cadence value '{c.Value}' is not a number — default {cadence}s applies");
        }

        var scope = new HashSet<string>(BaselineItemKinds.All, StringComparer.Ordinal);
        if (eff.Get(BaselinePolicyKeys.ScopeKinds) is { } s && !string.IsNullOrWhiteSpace(s.Value))
        {
            scope = new HashSet<string>(StringComparer.Ordinal);
            foreach (var raw in s.Value.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
            {
                var kind = raw.ToLowerInvariant();
                if (BaselineItemKinds.All.Contains(kind)) scope.Add(kind);
                else notes.Add($"scope kind '{raw}' is not a baseline item kind — dropped from scope (named, never silently applied)");
            }
            if (scope.Count == 0) notes.Add("scope list named no known kind — NOTHING is in scope; comparison will judge zero items (a scope that watches nothing is stated, not hidden)");
        }

        var auto = eff.Get(BaselinePolicyKeys.AutoRemediate) is { } a &&
                   bool.TryParse(a.Value, out var av) && av;
        var allowlist = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (eff.Get(BaselinePolicyKeys.RemediationAllowlist) is { } al && !string.IsNullOrWhiteSpace(al.Value))
            foreach (var id in al.Value.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
                allowlist.Add(id);

        var cooldown = BaselinePolicyKeys.DefaultDriftCooldownSeconds;
        if (eff.Get(BaselinePolicyKeys.DriftCooldownSeconds) is { } cd)
        {
            if (int.TryParse(cd.Value, out var v))
            {
                cooldown = Math.Clamp(v, BaselinePolicyKeys.MinDriftCooldownSeconds, BaselinePolicyKeys.MaxDriftCooldownSeconds);
                if (cooldown != v) notes.Add($"drift cooldown {v}s clamped to {cooldown}s");
            }
            else notes.Add($"drift cooldown value '{cd.Value}' is not a number — default {cooldown}s applies");
        }

        return new ResolvedBaselinePolicy(cadence, scope, auto, allowlist, cooldown, notes);
    }
}

// ---- the remediation gate ------------------------------------------------------------

public static class DriftRemediationGate
{
    /// <summary>May this deviation fire its linked remediation?
    /// Every condition must hold: the item links an id; baselines
    /// are enabled; policy allows auto-remediation at all; the id
    /// is ON THE POLICY ALLOWLIST (the baseline author's naming is
    /// not approval); and the RMM-08 engine is enabled for the
    /// device. Refusals name the first failed condition — a drift
    /// that wanted to act and was refused is auditable, never
    /// silent, and never partially allowed.</summary>
    public static (bool Allowed, string Reason) Evaluate(
        DriftDeviation deviation, ResolvedBaselinePolicy policy,
        bool baselinesEnabled, bool remediationEngineEnabled)
    {
        if (string.IsNullOrWhiteSpace(deviation.RemediationId))
            return (false, "the drifted item links no remediation — report only");
        if (!baselinesEnabled)
            return (false, $"baselines are disabled by policy ({BaselinePolicyKeys.Enabled}) — no remediation fires");
        if (!policy.AutoRemediate)
            return (false, $"policy does not allow drift auto-remediation ({BaselinePolicyKeys.AutoRemediate} is not true) — the linked remediation '{deviation.RemediationId}' does NOT fire; a baseline naming an action is not policy approving it");
        if (!policy.RemediationAllowlist.Contains(deviation.RemediationId))
            return (false, $"remediation '{deviation.RemediationId}' is not on the policy allowlist ({BaselinePolicyKeys.RemediationAllowlist}) — does NOT fire (policy approves actions by name; anything else a baseline links is report-only)");
        if (!remediationEngineEnabled)
            return (false, $"the remediation engine is disabled by policy ({MonitoringPolicyKeys.RemediationEnabled}) — drift remediation does NOT fire");
        return (true, $"policy allows drift auto-remediation of '{deviation.RemediationId}' (auto_remediate on, id allowlisted, engine enabled)");
    }
}

// ---- the hub-side cross-check ------------------------------------------------------------

/// <summary>Hub-side cross-check of an agent's drift evaluation
/// against the hub's OWN RMM-04 inventory record for the device —
/// a different reporting path than the agent's comparison inputs.
/// Software items are recomputed hub-side; every disagreement is
/// named (agent says compliant, hub inventory shows the deviation;
/// agent says drifted, hub inventory does not show it; the agent
/// judged against a different baseline hash than the hub's
/// effective baseline; the agent's observation is older than the
/// inventory's last change). Disagreement FLAGS — it never
/// overrides: either path could be the stale one, and the record
/// must show the conflict, not a winner picked silently. This is
/// the honest bound on the compromised-agent problem: an agent
/// that forges its observed state to match the baseline is caught
/// exactly where a second path holds contradicting facts, and
/// named as UNCHECKED where none does.</summary>
public static class HubDriftCrossCheck
{
    public sealed record Result(
        IReadOnlyList<string> Discrepancies,
        IReadOnlyList<string> CheckedItemIds,
        IReadOnlyList<string> UncheckedItemIds)
    {
        public IReadOnlyList<string> Discrepancies { get; init; } = Discrepancies ?? Array.Empty<string>();
        public IReadOnlyList<string> CheckedItemIds { get; init; } = CheckedItemIds ?? Array.Empty<string>();
        public IReadOnlyList<string> UncheckedItemIds { get; init; } = UncheckedItemIds ?? Array.Empty<string>();
        public bool Clean => Discrepancies.Count == 0;
    }

    public static Result Check(
        DriftEvaluation agentEvaluation, DeviceInventoryRecord hubInventory,
        EffectiveBaseline hubEffectiveBaseline)
    {
        var discrepancies = new List<string>();
        var checkedIds = new List<string>();
        var uncheckedIds = new List<string>();

        if (!string.Equals(agentEvaluation.DeviceId, hubInventory.DeviceId, StringComparison.OrdinalIgnoreCase))
            return new Result(new[] { $"device mismatch: agent evaluation is for '{agentEvaluation.DeviceId}', hub inventory is for '{hubInventory.DeviceId}' — cross-check refuses to compare two devices" },
                Array.Empty<string>(), Array.Empty<string>());

        if (agentEvaluation.BaselineHash != hubEffectiveBaseline.ContentHash)
            discrepancies.Add($"baseline mismatch: the agent judged against baseline hash {agentEvaluation.BaselineHash}, the hub's effective baseline hashes {hubEffectiveBaseline.ContentHash} — the two sides are not judging the same desired state");

        // D38 fix (F5): a software item is CHECKED only when the
        // hub inventory record carries evidence the inventory path
        // actually collected software for this device — a populated
        // software list, a revision recorded by a change report, or
        // a record seen again after its first sighting. An empty,
        // never-populated record (first sighting, revision 0, no
        // software) corroborates NOTHING: from it, "forbidden app
        // absent" is not a check that was performed, it is an
        // absence of evidence — and a forging agent's clean report
        // must not be confirmed by it. Such items are UNCHECKED.
        // BD-SHARED-RMM-1 F10: "collected" now means the
        // inventory path stamped an actual collection
        // (SoftwareCollectedUtc, set by baseline/change-report
        // admission) or the record carries software. The Revision
        // and LastSeen clauses are GONE: a heartbeat-only record
        // (revision bumped by non-software changes, LastSeen
        // advanced by seen_unchanged) satisfied both without a
        // single software item ever being collected, and its
        // empty software list then "confirmed" a forging agent's
        // clean forbidden-software report.
        var softwareCollected = hubInventory.Software.Count > 0
            || hubInventory.SoftwareCollectedUtc is not null;

        // Recompute the software half hub-side from inventory.
        var hubObserved = ObservedStateFactory.FromInventory(hubInventory);
        var hubEval = BaselineEvaluator.Evaluate(hubEffectiveBaseline, hubObserved,
            new HashSet<string> { BaselineItemKinds.SoftwareRequired, BaselineItemKinds.SoftwareForbidden },
            agentEvaluation.EvaluatedUtc);
        var hubDeviated = hubEval.Deviations.Select(d => d.ItemId).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var agentDeviated = agentEvaluation.Deviations.Select(d => d.ItemId).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var agentIndeterminate = agentEvaluation.Indeterminate.Select(d => d.ItemId).ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var entry in hubEffectiveBaseline.Items)
        {
            var item = entry.Item;
            // A disabled item is never judged by the evaluator on
            // either side — it is UNCHECKED, never claimed checked
            // (recovery-lane fix, RMM-19).
            if (!item.Enabled)
            { uncheckedIds.Add(item.Id); continue; }
            if (item.Kind is not (BaselineItemKinds.SoftwareRequired or BaselineItemKinds.SoftwareForbidden))
            { uncheckedIds.Add(item.Id); continue; }
            if (!softwareCollected)
            { uncheckedIds.Add(item.Id); continue; }
            checkedIds.Add(item.Id);
            var hubSays = hubDeviated.Contains(item.Id);
            var agentSays = agentDeviated.Contains(item.Id);
            // D38 fix (F6): membership above is OrdinalIgnoreCase;
            // the detail lookups must be too. An ordinal First()
            // here threw InvalidOperationException for an agent
            // reporting 'FORBID-GAME' against a hub 'forbid-game' —
            // a compromised agent could CRASH the only defence
            // against a forging agent with a casing difference.
            if (hubSays && !agentSays)
                discrepancies.Add($"item '{item.Id}' ({item.Kind} '{item.Target}'): hub inventory shows the deviation ({hubEval.Deviations.First(d => string.Equals(d.ItemId, item.Id, StringComparison.OrdinalIgnoreCase)).Detail}) but the agent's evaluation does not report it — the agent's observed state disagrees with the inventory path{(agentIndeterminate.Contains(item.Id) ? " (agent marked it indeterminate)" : "")}");
            if (agentSays && !hubSays)
                discrepancies.Add($"item '{item.Id}' ({item.Kind} '{item.Target}'): the agent reports drift ({agentEvaluation.Deviations.First(d => string.Equals(d.ItemId, item.Id, StringComparison.OrdinalIgnoreCase)).Detail}) but hub inventory does not show it — one of the two reporting paths is stale or wrong; flagged, not resolved silently");
        }

        if (agentEvaluation.ObservedUtc < hubInventory.LastChangedUtc)
            discrepancies.Add($"freshness: the agent's observation ({agentEvaluation.ObservedUtc:O}) predates the hub inventory's last change ({hubInventory.LastChangedUtc:O}) — the evaluation may predate a change the inventory already holds");
        // D38 fix (F5, freshness the other way): a hub inventory
        // OLDER than the agent's observation corroborates against
        // stale facts — a weeks-old inventory must be flagged, not
        // silently treated as a second opinion.
        if (hubInventory.LastSeenUtc < agentEvaluation.ObservedUtc)
            discrepancies.Add($"freshness: the hub inventory was last seen at {hubInventory.LastSeenUtc:O}, BEFORE the agent's observation ({agentEvaluation.ObservedUtc:O}) — the cross-check is corroborating against an inventory older than the evaluation it checks");

        return new Result(discrepancies, checkedIds, uncheckedIds);
    }
}
