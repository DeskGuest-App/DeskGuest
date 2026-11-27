using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DeskGuest.Shared.Backup;
using DeskGuest.Shared.EndpointSecurity;
using DeskGuest.Shared.Inventory;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.Monitoring;
using DeskGuest.Shared.Reporting;
using DeskGuest.Shared.Vulnerability;

namespace DeskGuest.Shared.HealthScoring;

// =====================================================================
// RMM-28 — Endpoint health scoring (DEX-style), locally computed
// (ADOPTED 2026-11-20). MODEL LAYER: the per-device health score as
// a WEIGHTED COMPOSITION of named component scores, each computed
// from its source system's OWN shapes:
//
//   monitoring  ← RMM-01 DeviceHealthView + HealthAlertEvent
//   exposure    ← RMM-05 ExposureWorkItem + FeedProvenance
//                 (the BuildReport seam's underlying shapes)
//   backup      ← RMM-06 BackupHealthFacts (IBackupHealthFactsProvider)
//   posture     ← RMM-17 AvPostureReport + IsolationStatus
//   inventory   ← RMM-04 DeviceInventoryRecord (age / warranty /
//                 freshness facts as stored, never re-looked-up)
//
// Doctrine carried from the register + lane scope, enforced in the
// model (not in comments alone):
//   * EXPLAINABILITY IS THE FEATURE. A score IS its decomposition:
//     component values, the weights used, the facts behind each
//     component, and the timestamp of every input. There is no
//     bare-number score shape in this model.
//   * UNKNOWN IS NOT ZERO AND NOT FINE. A component whose source
//     data is missing or stale scores UNKNOWN; the aggregate is
//     computed over the KNOWN components only (exclude-and-label),
//     labelled PARTIAL, with the unknowns named and the coverage
//     fraction (known weight / total weight) carried on the score.
//     An aggregate never silently averages an unknown away.
//   * WEIGHTS ARE POLICY (RMM-07). Weights arrive as policy
//     content, are versioned, and every score records the weights
//     version it was computed under. Historical snapshots are
//     immutable: a weights change never recomputes them (the store
//     has no recompute path; import re-VALIDATES a snapshot against
//     its own recorded decomposition, never against current policy).
//   * NO SCORE LAUNDERING. Two structural floors sit OUTSIDE the
//     weights, so no weight assignment can hide them: an open
//     critical or KEV exposure caps the aggregate at 49, and a
//     device RMM-01 reports DOWN caps it at 39. The caps and their
//     reasons ride the score itself.
//   * COMPONENTS CONSUME SOURCE SHAPES ONLY. Each component
//     function takes exactly its source system's records — there is
//     no raw-data path by which a component could re-derive (or a
//     caller could fabricate) another system's facts. The integrity
//     check re-derives the aggregate AND the caps from the recorded
//     decomposition + facts, so a forged snapshot that inflates a
//     number without changing its facts does not validate.
//   * HISTORY IS SNAPSHOTS. The store keeps point-in-time scores;
//     trend is a report OVER snapshots, never a recomputation.
// =====================================================================

/// <summary>TOTAL POLICY CONTROL keys for RMM-28. The feature
/// toggle itself is seeded in the RMM-07 registry
/// (`rmm.health_scoring.enabled`, default ON); weights and
/// staleness bounds are POLICY CONTENT read through Effective
/// Policy, parsed by <see cref="HealthScoreWeightsPolicy"/> and
/// <see cref="HealthStalenessPolicy"/>.</summary>
public static class HealthScoringPolicyKeys
{
    public const string Enabled = "rmm.health_scoring.enabled";
    public const string WeightsVersion = "rmm.health_scoring.weights_version";
    public static string WeightKey(string component) => $"rmm.health_scoring.weight.{component}";
    public static string StaleHoursKey(string component) => $"rmm.health_scoring.stale_hours.{component}";
}

/// <summary>The closed set of score components, in canonical
/// (decomposition display + hash) order.</summary>
public static class HealthComponents
{
    public const string Monitoring = "monitoring";
    public const string Exposure = "exposure";
    public const string Backup = "backup";
    public const string Posture = "posture";
    public const string Inventory = "inventory";

    public static readonly IReadOnlyList<string> All =
        new[] { Monitoring, Exposure, Backup, Posture, Inventory };
}

public static class ComponentScoreStates
{
    public const string Scored = "scored";
    public const string Unknown = "unknown";
}

public static class HealthScoreStates
{
    /// <summary>Every component scored: the aggregate covers the
    /// full weights.</summary>
    public const string Complete = "complete";
    /// <summary>At least one component unknown: the aggregate is
    /// computed over known components only and is labelled partial,
    /// with the unknowns named and coverage shown.</summary>
    public const string Partial = "partial";
}

/// <summary>One fact behind a component score: a named value taken
/// from the source system's own record, with the timestamp OF THE
/// SOURCE DATA it rests on where the source carries one. Facts are
/// the audit trail of the component — and the integrity check keys
/// its anti-laundering caps off them, so they are load-bearing,
/// not decoration.</summary>
public sealed record ComponentFact(
    string Name,
    string Value,
    DateTimeOffset? SourceTimestampUtc);

/// <summary>One component of a health score. A SCORED component
/// carries a 0–100 value; an UNKNOWN component carries a null value
/// and a named reason (missing source, stale source). The weight
/// recorded is the weight from the weights version in force — for
/// an unknown component it is the weight EXCLUDED from the
/// aggregate, shown so the coverage fraction can be checked.</summary>
public sealed record ComponentScore(
    string Component,
    string State,
    double? Value,
    double Weight,
    string SourceSystem,
    DateTimeOffset? InputTimestampUtc,
    string? UnknownReason,
    IReadOnlyList<ComponentFact> Facts)
{
    public IReadOnlyList<ComponentFact> Facts { get; init; } = Facts ?? Array.Empty<ComponentFact>();

    public string? FactValue(string name) =>
        Facts.FirstOrDefault(f => f.Name == name)?.Value;
}

/// <summary>THE per-device health score. It cannot exist without
/// its decomposition: the components, the weights version, the
/// coverage fraction and any aggregate cap are all part of the
/// record, and <see cref="ContentHash"/> binds them together.
/// Aggregate is null exactly when NO component could be scored —
/// a device about which nothing is known has no number, not a
/// zero and not a hundred.</summary>
public sealed record DeviceHealthScore(
    string DeviceId,
    string ScopeId,
    DateTimeOffset ComputedUtc,
    string WeightsVersion,
    string State,
    double? Aggregate,
    double CoverageFraction,
    string? AggregateCapReason,
    IReadOnlyList<ComponentScore> Components,
    // FL-28a (F1/F6): provenance + keyed signature. Origin is
    // "computed" for scores this hub scored itself.
    // BD-SHARED-RMM-1 F8: an earlier text here claimed the store
    // re-stamps Origin to "imported" on import — it does NOT and
    // must not: imported snapshots are stored byte-verbatim (the
    // content hash and keyed signature cover the record as
    // authored), so imported provenance lives STORE-SIDE in the
    // store's imported-key set, which segregates Latest and is
    // persisted with the store (ExportStoreJson).
    // Signature is an HMAC over ContentHash under the hub's
    // signing key when the store is keyed (null on unkeyed
    // stores); it is NOT part of the content hash it signs.
    string? Signature = null,
    string Origin = "computed")
{
    public IReadOnlyList<ComponentScore> Components { get; init; } =
        Components ?? Array.Empty<ComponentScore>();

    // FL-28b / F12: the content hash was recomputed from scratch on
    // EVERY access — and the store's duplicate check, signing,
    // export and audit paths access it repeatedly over the same
    // immutable record. It is now computed once per record instance
    // and cached. Records are immutable (init-only), so the cached
    // value cannot go stale within an instance — but a record
    // `with` copy COPIES private fields, so the copy constructor
    // below explicitly resets the cache: an edited copy must hash
    // its own content, never inherit the original's hash (caught
    // by Rmm28Fix2Tests.F12_ContentHash during this lane).
    private string? _contentHash;
    private string ContentHashCached => _contentHash ??= HealthScoreHash.Compute(this);

    private DeviceHealthScore(DeviceHealthScore original)
    {
        DeviceId = original.DeviceId;
        ScopeId = original.ScopeId;
        ComputedUtc = original.ComputedUtc;
        WeightsVersion = original.WeightsVersion;
        State = original.State;
        Aggregate = original.Aggregate;
        CoverageFraction = original.CoverageFraction;
        AggregateCapReason = original.AggregateCapReason;
        Components = original.Components;
        Signature = original.Signature;
        Origin = original.Origin;
        _contentHash = null; // never inherit: a copy hashes its own content
    }

    public IReadOnlyList<string> UnknownComponents =>
        Components.Where(c => c.State == ComponentScoreStates.Unknown)
            .Select(c => c.Component).ToList();

    public ComponentScore? Component(string name) =>
        Components.FirstOrDefault(c => c.Component == name);

    /// <summary>SHA-256 over the score's canonical decomposition.
    /// Any edit to a value, weight, fact or timestamp changes the
    /// hash — the snapshot store refuses a score whose recorded
    /// content does not match its hash on import. Computed once
    /// per instance and cached (FL-28b / F12).</summary>
    public string ContentHash => ContentHashCached;
}

public static class HealthScoreHash
{
    public static string Compute(DeviceHealthScore s)
    {
        var sb = new StringBuilder();
        sb.Append("deskguest-health-score-v1|").Append(s.DeviceId).Append('|').Append(s.ScopeId)
          .Append('|').Append(s.ComputedUtc.ToString("O")).Append('|').Append(s.WeightsVersion)
          .Append('|').Append(s.State).Append('|')
          .Append(s.Aggregate is { } a ? a.ToString("F1", CultureInfo.InvariantCulture) : "null")
          .Append('|').Append(s.CoverageFraction.ToString("F4", CultureInfo.InvariantCulture))
          .Append('|').Append(s.AggregateCapReason ?? "")
          .Append('|').Append(s.Origin ?? "computed");
        foreach (var c in s.Components.OrderBy(c => c.Component, StringComparer.Ordinal))
        {
            sb.Append("|c:").Append(c.Component).Append(',').Append(c.State).Append(',')
              .Append(c.Value is { } v ? v.ToString("F1", CultureInfo.InvariantCulture) : "null")
              .Append(',').Append(c.Weight.ToString("F4", CultureInfo.InvariantCulture))
              .Append(',').Append(c.SourceSystem).Append(',')
              .Append(c.InputTimestampUtc?.ToString("O") ?? "null").Append(',')
              .Append(c.UnknownReason ?? "");
            foreach (var f in c.Facts.OrderBy(f => f.Name, StringComparer.Ordinal))
                sb.Append("|f:").Append(f.Name).Append('=').Append(f.Value).Append('@')
                  .Append(f.SourceTimestampUtc?.ToString("O") ?? "null");
        }
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(sb.ToString()))).ToLowerInvariant();
    }
}

/// <summary>FL-28a (F1): KEYED snapshot signatures. The plain
/// content hash is public SHA-256 — anyone can recompute it over
/// a forged decomposition. An HMAC under a hub-held key cannot:
/// a keyed store refuses imported snapshots whose signature does
/// not verify under its key, so provenance is cryptographic, not
/// merely structural.</summary>
public static class HealthScoreSigning
{
    public static string Sign(DeviceHealthScore s, byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);
        return Convert.ToHexString(HMACSHA256.HashData(key,
            Encoding.UTF8.GetBytes("deskguest-health-score-sig-v1|" + s.ContentHash))).ToLowerInvariant();
    }

    public static bool Verify(DeviceHealthScore s, byte[] key)
    {
        if (string.IsNullOrWhiteSpace(s.Signature)) return false;
        var expected = Sign(s, key);
        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(expected), Encoding.UTF8.GetBytes(s.Signature));
    }
}

// ---- weights (policy content) -------------------------------------------

/// <summary>A versioned weights assignment: one non-negative weight
/// per component. Weights need not sum to 1 — aggregation
/// normalises over the KNOWN components' weights — but every
/// component must be present and the total must be positive, or no
/// score can be computed under the set at all.</summary>
public sealed record HealthScoreWeights(
    string Version,
    IReadOnlyDictionary<string, double> ByComponent)
{
    public double WeightOf(string component) =>
        ByComponent.TryGetValue(component, out var w) ? w : 0;

    public double TotalWeight => HealthComponents.All.Sum(WeightOf);

    public string? Validate()
    {
        if (string.IsNullOrWhiteSpace(Version)) return "weights carry no version — refused";
        foreach (var c in HealthComponents.All)
        {
            if (!ByComponent.TryGetValue(c, out var w))
                return $"weights are missing component '{c}' — refused (a partial weight set would silently re-weight the score)";
            if (double.IsNaN(w) || double.IsInfinity(w) || w < 0)
                return $"weight for '{c}' is {w} — refused (weights are finite and non-negative)";
            if (w > HealthScoreWeightsPolicy.MaxWeight)
                return $"weight for '{c}' is {w} — refused (above the {HealthScoreWeightsPolicy.MaxWeight} sanity bound)";
        }
        if (TotalWeight <= 0)
            return "weights sum to zero — refused (no score can be computed under a zero weight set)";
        return null;
    }

    /// <summary>Deterministic canonical form (ordinal component
    /// order, invariant numbers) — the bytes a derived version id
    /// hashes, so the same weight set always names the same
    /// version.</summary>
    public string Canonical() => string.Join(";",
        HealthComponents.All.OrderBy(c => c, StringComparer.Ordinal)
            .Select(c => $"{c}={WeightOf(c).ToString("0.################", CultureInfo.InvariantCulture)}"));
}

public static class HealthScoreWeightsPolicy
{
    public const double MaxWeight = 10.0;

    /// <summary>The registered default weight set. Exposure leads:
    /// an exploitable machine is the fleet's most urgent fact.</summary>
    public static HealthScoreWeights Default { get; } = new("default-1",
        new Dictionary<string, double>
        {
            [HealthComponents.Monitoring] = 0.25,
            [HealthComponents.Exposure] = 0.30,
            [HealthComponents.Backup] = 0.20,
            [HealthComponents.Posture] = 0.15,
            [HealthComponents.Inventory] = 0.10,
        });

    /// <summary>Parse the weights out of an Effective Policy tree.
    /// Unset components inherit the registered defaults. Malformed
    /// content refuses BY NAME (returned, never thrown, never
    /// silently defaulted): an admin who typo'd a weight gets a
    /// refusal, not a quietly different score. The version is the
    /// explicit `weights_version` setting when present; otherwise
    /// "default-1" when nothing is overridden, else a derived
    /// `custom-&lt;hash&gt;` of the canonical weight set — so every
    /// distinct weight set has a distinct, stable version name.</summary>
    public static (HealthScoreWeights? Weights, IReadOnlyList<string> Refusals) Parse(EffectivePolicy effective)
    {
        var refusals = new List<string>();
        var byComponent = new Dictionary<string, double>(StringComparer.Ordinal);
        var anyOverride = false;
        foreach (var c in HealthComponents.All)
        {
            var raw = effective.Get(HealthScoringPolicyKeys.WeightKey(c))?.Value;
            if (raw is null) { byComponent[c] = Default.WeightOf(c); continue; }
            anyOverride = true;
            if (!double.TryParse(raw, NumberStyles.Float, CultureInfo.InvariantCulture, out var w))
            {
                refusals.Add($"health-scoring weight for '{c}' is '{raw}' — not a number, refused");
                continue;
            }
            byComponent[c] = w;
        }
        if (refusals.Count > 0) return (null, refusals);

        var weights = new HealthScoreWeights("pending", byComponent);
        if (weights.Validate() is { } invalid)
        {
            refusals.Add($"health-scoring weights refused: {invalid}");
            return (null, refusals);
        }
        var explicitVersion = effective.Get(HealthScoringPolicyKeys.WeightsVersion)?.Value?.Trim();
        // FL-28a (F4): the version is ALWAYS content-bound. An
        // explicit label names the set but never replaces its
        // identity: the recorded version is "<label>@<hash>" over
        // the canonical weight content, so the same label over
        // different weights is a DIFFERENT version (and trends
        // break), and the same content under any label hashes the
        // same.
        var contentHash = Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes(weights.Canonical())))[..12].ToLowerInvariant();
        var version = !string.IsNullOrWhiteSpace(explicitVersion)
            ? $"{explicitVersion}@{contentHash}"
            : !anyOverride
                ? Default.Version
                : "custom-" + contentHash;
        return (weights with { Version = version }, refusals);
    }
}

// ---- staleness bounds (policy content) ------------------------------------

/// <summary>How old a component's source data may be before the
/// component scores UNKNOWN instead of trusting it. Exposure has
/// no bound here: its staleness verdict is RMM-05's own
/// (FeedProvenance.IsStale, computed under RMM-05's policy).</summary>
public sealed record HealthStalenessBounds(
    TimeSpan Monitoring,
    TimeSpan Backup,
    TimeSpan Posture,
    TimeSpan Inventory)
{
    public static HealthStalenessBounds Default { get; } = new(
        TimeSpan.FromHours(1), TimeSpan.FromHours(48),
        TimeSpan.FromHours(24), TimeSpan.FromHours(72));
}

public static class HealthStalenessPolicy
{
    /// <summary>Parse per-component staleness bounds (hours) out of
    /// an Effective Policy tree. Non-positive or absurd values
    /// refuse by name — a zero bound would make every component
    /// permanently unknown, and a century-long bound would launder
    /// stale data into fresh scores; neither is honoured.</summary>
    public static (HealthStalenessBounds Bounds, IReadOnlyList<string> Refusals) Parse(EffectivePolicy effective)
    {
        var refusals = new List<string>();
        TimeSpan Bound(string component, TimeSpan fallback)
        {
            var raw = effective.Get(HealthScoringPolicyKeys.StaleHoursKey(component))?.Value;
            if (raw is null) return fallback;
            if (!double.TryParse(raw, NumberStyles.Float, CultureInfo.InvariantCulture, out var hours) ||
                hours <= 0 || hours > 24 * 365)
            {
                refusals.Add($"health-scoring stale_hours for '{component}' is '{raw}' — refused (must be a positive number of hours within one year)");
                return fallback;
            }
            return TimeSpan.FromHours(hours);
        }
        var d = HealthStalenessBounds.Default;
        var bounds = new HealthStalenessBounds(
            Bound(HealthComponents.Monitoring, d.Monitoring),
            Bound(HealthComponents.Backup, d.Backup),
            Bound(HealthComponents.Posture, d.Posture),
            Bound(HealthComponents.Inventory, d.Inventory));
        return (bounds, refusals);
    }
}

// ---- component inputs: the source systems' own shapes ---------------------

/// <summary>RMM-01's shapes for one device: the hub health view
/// (state + last report) and the centre's active alerts.</summary>
public sealed record MonitoringHealthInput(
    DeviceHealthView View,
    IReadOnlyList<HealthAlertEvent> ActiveAlerts)
{
    public IReadOnlyList<HealthAlertEvent> ActiveAlerts { get; init; } =
        ActiveAlerts ?? Array.Empty<HealthAlertEvent>();
}

/// <summary>RMM-05's shapes for one device: the device's unclosed
/// exposure work items and the feed provenance (staleness verdict
/// already evaluated by RMM-05's own policy at the caller's now).</summary>
public sealed record ExposureHealthInput(
    IReadOnlyList<ExposureWorkItem> OpenItems,
    FeedProvenance Provenance)
{
    public IReadOnlyList<ExposureWorkItem> OpenItems { get; init; } =
        OpenItems ?? Array.Empty<ExposureWorkItem>();
}

/// <summary>RMM-17's shapes for one device: the AV posture report
/// and the isolation status. Either may be absent (never evaluated
/// / not an isolation-managed device) — absence is data.</summary>
public sealed record PostureHealthInput(
    AvPostureReport? Posture,
    IsolationStatus? Isolation);

/// <summary>Everything the scorer consumes for one device, one slot
/// per source system. A null slot means the source provided NO data
/// for this device — the component scores UNKNOWN and names it.</summary>
public sealed record HealthScoreInputs(
    MonitoringHealthInput? Monitoring,
    ExposureHealthInput? Exposure,
    BackupHealthFacts? Backup,
    PostureHealthInput? Posture,
    DeviceInventoryRecord? Inventory);

// ---- facts sources (the seams the Core service wires) ----------------------

public interface IMonitoringFactsSource
{
    MonitoringHealthInput? Get(string deviceId, DateTimeOffset now);
}

public interface IExposureFactsSource
{
    ExposureHealthInput? Get(string deviceId, DateTimeOffset now);
}

public interface IPostureFactsSource
{
    PostureHealthInput? Get(string deviceId, DateTimeOffset now);
}

public interface IInventoryFactsSource
{
    DeviceInventoryRecord? Get(string deviceId, DateTimeOffset now);
}

/// <summary>Scripted monitoring double (house pattern: fakes live
/// beside the model).</summary>
public sealed class FakeMonitoringFactsSource : IMonitoringFactsSource
{
    private readonly Dictionary<string, MonitoringHealthInput> _byDevice = new(StringComparer.OrdinalIgnoreCase);
    public FakeMonitoringFactsSource Set(string deviceId, MonitoringHealthInput input) { _byDevice[deviceId] = input; return this; }
    public MonitoringHealthInput? Get(string deviceId, DateTimeOffset now) =>
        _byDevice.TryGetValue(deviceId ?? "", out var v) ? v : null;
}

public sealed class FakeExposureFactsSource : IExposureFactsSource
{
    private readonly Dictionary<string, ExposureHealthInput> _byDevice = new(StringComparer.OrdinalIgnoreCase);
    public FakeExposureFactsSource Set(string deviceId, ExposureHealthInput input) { _byDevice[deviceId] = input; return this; }
    public ExposureHealthInput? Get(string deviceId, DateTimeOffset now) =>
        _byDevice.TryGetValue(deviceId ?? "", out var v) ? v : null;
}

public sealed class FakePostureFactsSource : IPostureFactsSource
{
    private readonly Dictionary<string, PostureHealthInput> _byDevice = new(StringComparer.OrdinalIgnoreCase);
    public FakePostureFactsSource Set(string deviceId, PostureHealthInput input) { _byDevice[deviceId] = input; return this; }
    public PostureHealthInput? Get(string deviceId, DateTimeOffset now) =>
        _byDevice.TryGetValue(deviceId ?? "", out var v) ? v : null;
}

public sealed class FakeInventoryFactsSource : IInventoryFactsSource
{
    private readonly Dictionary<string, DeviceInventoryRecord> _byDevice = new(StringComparer.OrdinalIgnoreCase);
    public FakeInventoryFactsSource Set(DeviceInventoryRecord record) { _byDevice[record.DeviceId] = record; return this; }
    public DeviceInventoryRecord? Get(string deviceId, DateTimeOffset now) =>
        _byDevice.TryGetValue(deviceId ?? "", out var v) ? v : null;
}

/// <summary>Backup facts double implementing RMM-06's own provider
/// interface. An unregistered device returns the same shape
/// BackupEngine.GetFacts returns for one: every field null/zero —
/// "never ran" facts, not an absence the scorer could mistake for
/// health.</summary>
public sealed class FakeBackupHealthFactsProvider : IBackupHealthFactsProvider
{
    private readonly Dictionary<string, BackupHealthFacts> _byDevice = new(StringComparer.OrdinalIgnoreCase);
    public FakeBackupHealthFactsProvider Set(BackupHealthFacts facts) { _byDevice[facts.DeviceId] = facts; return this; }
    public BackupHealthFacts GetFacts(string deviceId, DateTimeOffset now) =>
        _byDevice.TryGetValue(deviceId ?? "", out var v)
            ? v
            : new BackupHealthFacts(deviceId ?? "", null, null, null, 0, 0, 0, false, null, false, now);
}
