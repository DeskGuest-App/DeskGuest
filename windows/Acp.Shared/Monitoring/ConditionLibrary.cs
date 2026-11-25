using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Acp.Shared.Monitoring;

// =====================================================================
// RMM-01 — the TUNED CONDITION LIBRARY: monitoring content shipped as
// local data (the ConnectWise lesson the register cites: incumbent
// signal quality is CONTENT — 1,200 NOC-tuned alerts — and content
// can ship as files at $0). The library is signed policy content:
// it travels inside an RMM-03 signed-command envelope (class
// policy_delivery) and the endpoint verifies the customer's
// signature BEFORE parsing (EndpointMonitorService.ApplySignedLibrary).
// An unsigned, altered or malformed library refuses WHOLE — a
// partially-applied condition set would silently un-watch whatever
// the tamper removed.
//
// Validation is admission discipline, in the engine's own voice:
// unknown kinds, duplicate ids, out-of-range thresholds, unknown
// severities and unbounded cooldowns all refuse the library, never
// just the offending condition. The one built-in exception is the
// code-seeded Default library below: it is part of the signed agent
// binary, not data, so it needs no envelope — and any DATA library
// replaces it only through the signed path.
// =====================================================================

/// <summary>Named bounds for condition-library admission. A library
/// that exceeds one refuses whole, with the bound named.</summary>
public static class ConditionLibraryLimits
{
    public const int MaxConditions = 512;
    public const int MaxIdLength = 128;
    public const int MaxNameLength = 256;
    public const int MaxTargetLength = 256;
    public const int MaxConsecutiveSamples = 60;
    public static readonly TimeSpan MaxCooldown = TimeSpan.FromHours(24);
    public static readonly TimeSpan MinCooldown = TimeSpan.FromMinutes(1);
}

/// <summary>A versioned set of monitor conditions. Revision is
/// monotonic per library Id: a stale or same-revision-conflicting
/// re-delivery refuses (the management-policy discipline, applied to
/// monitoring content).</summary>
public sealed record ConditionLibrary(
    string Id,
    long Revision,
    IReadOnlyList<MonitorCondition> Conditions)
{
    public IReadOnlyList<MonitorCondition> Conditions { get; init; } =
        Conditions ?? Array.Empty<MonitorCondition>();

    /// <summary>Deterministic canonical JSON — the exact bytes the
    /// RMM-03 envelope payload carries and hashes. Conditions are
    /// emitted in ordinal id order so two serializations of the same
    /// library are byte-identical.</summary>
    public string ToCanonicalJson()
    {
        var conditions = Conditions.OrderBy(c => c.Id, StringComparer.Ordinal).Select(c => new
        {
            id = c.Id, name = c.Name, kind = c.Kind, target = c.Target, eventId = c.EventId,
            thresholdPercent = c.ThresholdPercent, thresholdBytes = c.ThresholdBytes,
            thresholdSeconds = c.ThresholdSeconds, severity = c.Severity,
            consecutiveSamples = c.ConsecutiveSamples, cooldownSeconds = c.Cooldown.TotalSeconds,
            notify = c.Actions.Notify, openWorkItem = c.Actions.OpenWorkItem,
            remediationId = c.Actions.RemediationId, enabled = c.Enabled, description = c.Description,
        }).ToList();
        return JsonSerializer.Serialize(new { id = Id, revision = Revision, conditions });
    }

    /// <summary>SHA-256 of the canonical JSON — the content identity
    /// audit events and health reports carry.</summary>
    public string ContentHash =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(ToCanonicalJson()))).ToLowerInvariant();

    public static ConditionLibrary? FromCanonicalJson(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            var conditions = new List<MonitorCondition>();
            foreach (var el in root.GetProperty("conditions").EnumerateArray())
            {
                conditions.Add(new MonitorCondition(
                    el.GetProperty("id").GetString() ?? "",
                    el.GetProperty("name").GetString() ?? "",
                    el.GetProperty("kind").GetString() ?? "",
                    OptString(el, "target"),
                    OptInt(el, "eventId"),
                    OptDouble(el, "thresholdPercent"),
                    OptLong(el, "thresholdBytes"),
                    OptLong(el, "thresholdSeconds"),
                    el.GetProperty("severity").GetString() ?? "",
                    el.GetProperty("consecutiveSamples").GetInt32(),
                    TimeSpan.FromSeconds(el.GetProperty("cooldownSeconds").GetDouble()),
                    new AlertActions(
                        el.GetProperty("notify").GetBoolean(),
                        el.GetProperty("openWorkItem").GetBoolean(),
                        OptString(el, "remediationId")),
                    el.GetProperty("enabled").GetBoolean(),
                    OptString(el, "description") ?? ""));
            }
            return new ConditionLibrary(
                root.GetProperty("id").GetString() ?? "",
                root.GetProperty("revision").GetInt64(),
                conditions);
        }
        catch { return null; }
    }

    private static string? OptString(JsonElement el, string name) =>
        el.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
    private static int? OptInt(JsonElement el, string name) =>
        el.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number ? v.GetInt32() : null;
    private static long? OptLong(JsonElement el, string name) =>
        el.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number ? v.GetInt64() : null;
    private static double? OptDouble(JsonElement el, string name) =>
        el.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number ? v.GetDouble() : null;

    /// <summary>Admission validation. Null when the library is
    /// admissible; otherwise the refusal reason naming the first
    /// defect. A refused library changes NOTHING on the endpoint —
    /// the previously admitted library (or the built-in default)
    /// stays in force.</summary>
    public string? Validate()
    {
        if (string.IsNullOrWhiteSpace(Id) || Id.Length > ConditionLibraryLimits.MaxIdLength)
            return "condition library needs an id within bounds — refused";
        if (Revision < 1)
            return $"condition library '{Id}' revision {Revision} is not positive — refused";
        if (Conditions.Count > ConditionLibraryLimits.MaxConditions)
            return $"condition library '{Id}' carries {Conditions.Count} conditions over the cap {ConditionLibraryLimits.MaxConditions} — refused";
        // D38-F12: an empty library, or one whose every condition is
        // disabled, is total silence delivered as valid content — it
        // would turn monitoring off without the policy toggle
        // (rmm.monitoring.enabled), which is the ONLY sanctioned off
        // switch. Refused whole, like every other admission defect.
        if (Conditions.Count == 0)
            return $"condition library '{Id}' carries no conditions — refused (an empty library is total silence, not monitoring content; the policy toggle is the only off switch)";
        if (!Conditions.Any(c => c.Enabled))
            return $"condition library '{Id}': every condition is disabled — refused (a library that watches nothing is an off switch, and the policy toggle is the only off switch)";
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var c in Conditions)
        {
            if (string.IsNullOrWhiteSpace(c.Id) || c.Id.Length > ConditionLibraryLimits.MaxIdLength)
                return $"condition library '{Id}': a condition id is empty or over bounds — refused";
            if (!seen.Add(c.Id))
                return $"condition library '{Id}': duplicate condition id '{c.Id}' — refused";
            // D38-F9: system alert ids are reserved. A library
            // condition named e.g. 'monitor-failure' would share the
            // centre's dedup key with the monitor's own failure alert
            // and absorb it as a refresh under a suppressible kind.
            if (SystemAlertConditionIds.IsReserved(c.Id))
                return $"condition '{c.Id}': this id is reserved for system alerts — refused (library conditions share the alert dedup namespace with system alerts)";
            // D38-F9: kinds that are never sample-evaluated (warranty,
            // serial_conflict, device_down, monitor_failure) arrive
            // through their own paths; as library content they would
            // be silently skipped while looking like coverage.
            if (ConditionKinds.All.Contains(c.Kind ?? "") && !ConditionKinds.IsSampleEvaluated(c.Kind ?? ""))
                return $"condition '{c.Id}': kind '{c.Kind}' is not sample-evaluated — it arrives through its own path and cannot be library content — refused";
            if (string.IsNullOrWhiteSpace(c.Name) || c.Name.Length > ConditionLibraryLimits.MaxNameLength)
                return $"condition '{c.Id}': name empty or over bounds — refused";
            if (!ConditionKinds.All.Contains(c.Kind ?? ""))
                return $"condition '{c.Id}': unknown kind '{c.Kind}' — refused (an unknown kind is a field that changes meaning)";
            if (!AlertSeverities.All.Contains(c.Severity ?? ""))
                return $"condition '{c.Id}': unknown severity '{c.Severity}' — refused";
            if (c.Target is { Length: > ConditionLibraryLimits.MaxTargetLength })
                return $"condition '{c.Id}': target over bounds — refused";
            if (c.ThresholdPercent is { } pct && (pct < 0 || pct > 100))
                return $"condition '{c.Id}': threshold percent {pct} outside 0–100 — refused";
            if (c.ThresholdBytes is { } bytes && bytes < 0)
                return $"condition '{c.Id}': negative byte threshold — refused";
            if (c.ThresholdSeconds is { } secs && secs < 0)
                return $"condition '{c.Id}': negative second threshold — refused";
            if (c.ConsecutiveSamples < 1 || c.ConsecutiveSamples > ConditionLibraryLimits.MaxConsecutiveSamples)
                return $"condition '{c.Id}': consecutive-samples {c.ConsecutiveSamples} outside 1–{ConditionLibraryLimits.MaxConsecutiveSamples} — refused";
            if (c.Cooldown < ConditionLibraryLimits.MinCooldown || c.Cooldown > ConditionLibraryLimits.MaxCooldown)
                return $"condition '{c.Id}': cooldown {c.Cooldown} outside {ConditionLibraryLimits.MinCooldown}–{ConditionLibraryLimits.MaxCooldown} — refused (a cooldown is dedup discipline, not a silencer)";
            if ((c.Kind is ConditionKinds.ServiceStopped or ConditionKinds.ProcessMissing or
                 ConditionKinds.ProcessHighMemory or ConditionKinds.AppMissing or ConditionKinds.AppNotRunning)
                && string.IsNullOrWhiteSpace(c.Target))
                return $"condition '{c.Id}': kind '{c.Kind}' requires a target — refused";
            if (c.Kind == ConditionKinds.EventLogMatch && (string.IsNullOrWhiteSpace(c.Target) || c.EventId is null))
                return $"condition '{c.Id}': event-log conditions require a source and an event id — refused";
            if (c.Actions.WantsRemediation && string.IsNullOrWhiteSpace(c.Actions.RemediationId))
                return $"condition '{c.Id}': remediation action without a remediation id — refused";
        }
        return null;
    }

    /// <summary>The built-in tuned default library (code-seeded, part
    /// of the signed agent binary). Thresholds are the conservative
    /// fleet defaults: warn early on space, never debounce a SMART
    /// or security-state failure, debounce CPU/RAM so a compile spike
    /// is not a page. The BAS template watches a site JACE/vendor
    /// daemon service: it ships DISABLED with the placeholder service
    /// name because the real service name is site fact — enabling it
    /// is a one-line signed library revision per site, and a template
    /// that guessed a service name would alert on machines that never
    /// had the service.</summary>
    public static ConditionLibrary Default() => new("acp-default", 1, new[]
    {
        MonitorCondition.Create("cpu-sustained-high", "CPU sustained high", ConditionKinds.CpuHigh,
            AlertSeverities.Warning, thresholdPercent: 90, consecutiveSamples: 3,
            description: "CPU at or above 90% on 3 consecutive samples."),
        MonitorCondition.Create("ram-sustained-high", "RAM sustained high", ConditionKinds.RamHigh,
            AlertSeverities.Warning, thresholdPercent: 90, consecutiveSamples: 3,
            description: "Memory at or above 90% on 3 consecutive samples."),
        MonitorCondition.Create("disk-space-low", "Disk space low", ConditionKinds.DiskLow,
            AlertSeverities.Warning, target: "*", thresholdPercent: 10,
            actions: new AlertActions(true, true, null),
            description: "Any volume at or below 10% free."),
        MonitorCondition.Create("disk-space-critical", "Disk space critical", ConditionKinds.DiskLow,
            AlertSeverities.Critical, target: "*", thresholdPercent: 5,
            actions: new AlertActions(true, true, null),
            description: "Any volume at or below 5% free."),
        MonitorCondition.Create("disk-smart-failure", "Disk SMART failure", ConditionKinds.DiskSmartFailure,
            AlertSeverities.Critical, target: "*",
            actions: new AlertActions(true, true, null),
            description: "SMART status not OK on any read disk. Never debounced: a failing disk does not heal between samples."),
        MonitorCondition.Create("disk-predictive-failure", "Disk predictive failure", ConditionKinds.DiskPredictiveFailure,
            AlertSeverities.Critical, target: "*",
            actions: new AlertActions(true, true, null),
            description: "OS predictive-failure flag on any read disk."),
        MonitorCondition.Create("security-av-off", "Antivirus off", ConditionKinds.SecurityAvOff,
            AlertSeverities.Critical,
            actions: new AlertActions(true, true, null),
            description: "Antivirus disabled. Never suppressible by a maintenance window."),
        MonitorCondition.Create("security-firewall-off", "Firewall off", ConditionKinds.SecurityFirewallOff,
            AlertSeverities.Critical,
            actions: new AlertActions(true, true, null),
            description: "Firewall disabled. Never suppressible by a maintenance window."),
        MonitorCondition.Create("security-encryption-off", "Disk encryption off", ConditionKinds.SecurityEncryptionOff,
            AlertSeverities.Warning,
            description: "Disk encryption disabled (feeds RMM-18's enforcement view). Never suppressible by a maintenance window."),
        MonitorCondition.Create("eventlog-application-crash", "Application crash pattern", ConditionKinds.EventLogMatch,
            AlertSeverities.Warning, target: "Application Error", eventId: 1000,
            description: "Windows Event Log: Application Error 1000 (application crash) in the sampled window."),
        MonitorCondition.Create("eventlog-service-crash", "Service crash pattern", ConditionKinds.EventLogMatch,
            AlertSeverities.Warning, target: "Service Control Manager", eventId: 7031,
            description: "Windows Event Log: Service Control Manager 7031 (service terminated unexpectedly)."),
        MonitorCondition.Create("uptime-reboot-overdue", "Reboot overdue", ConditionKinds.UptimeExceeded,
            AlertSeverities.Info, thresholdSeconds: 2_592_000, // 30 days
            description: "Uptime over 30 days: patch reboots are being deferred past the fleet norm."),
        MonitorCondition.Create("bas-jace-service", "BAS site service (template)", ConditionKinds.ServiceStopped,
            AlertSeverities.Critical, target: "Niagara",
            actions: new AlertActions(true, true, null), enabled: false,
            description: "TEMPLATE — rename Target to the site's actual JACE/vendor daemon service name (e.g. the Niagara service on a site server) and enable in a signed site library revision. Ships disabled: the service name is site fact, never guessed."),
    });
}
