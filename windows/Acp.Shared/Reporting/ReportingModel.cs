using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Acp.Shared.Backup;
using Acp.Shared.Enterprise;
using Acp.Shared.Inventory;
using Acp.Shared.Monitoring;
using Acp.Shared.Vulnerability;

namespace Acp.Shared.Reporting;

// =====================================================================
// RMM-13 — Local reporting: IT's upward voice (MODEL LAYER).
//
// Dashboards + reports computed ENTIRELY from hub data: fleet
// health (RMM-01 hub ingest), patch compliance (RMM-02 over RMM-04),
// inventory/lifecycle (RMM-04), backup status (RMM-06 facts),
// vulnerability posture (RMM-05 BuildReport shape) and audit
// summaries (the chained ledger). No external service is consulted;
// no network exists in this layer.
//
// HONESTY DISCIPLINE (the RMM-05 / RMM-09 rule, structural here):
// every report carries a ReportHeader whose provenance + staleness
// are COMPUTED by the builder from the inputs' own timestamps —
// never asserted by the caller. A report over stale (or missing)
// inputs says so on its face, in every export format: the header is
// part of the JSON, a banner in the text rendering, and preamble
// rows in the CSV. There is no code path that produces a report
// whose header understates its inputs' age: staleness is a computed
// property of the input records, not a flag anyone can clear.
// =====================================================================

/// <summary>TOTAL POLICY CONTROL keys for RMM-13. The feature toggle
/// itself is seeded in the RMM-07 registry (`rmm.reporting.enabled`,
/// default ON); these are the sub-surface policy-content keys, read
/// through Effective Policy by the Core service.</summary>
public static class ReportingPolicyKeys
{
    public const string ReportingEnabled = "rmm.reporting.enabled";
    public const string ApiEnabled = "rmm.reporting.api.enabled";               // default ON (still key-gated)
    public const string WebhooksEnabled = "rmm.reporting.webhooks.enabled";     // default OFF (outbound is opt-in)
    public const string ScheduledEnabled = "rmm.reporting.scheduled.enabled";   // default ON
    public const string FleetMcpEnabled = "rmm.reporting.fleet_mcp.enabled";    // default ON (read-only by default)
    public const string LocalModelEnabled = "rmm.reporting.local_model.enabled"; // default OFF (no model until the user hosts one)
}

/// <summary>The closed set of report kinds. A kind outside this set
/// refuses — an unknown kind is a field that changes meaning.</summary>
public static class ReportKinds
{
    public const string FleetHealth = "fleet_health";
    public const string PatchCompliance = "patch_compliance";
    public const string InventoryLifecycle = "inventory_lifecycle";
    public const string BackupStatus = "backup_status";
    public const string AuditSummary = "audit_summary";
    public const string VulnerabilityPosture = "vulnerability_posture";

    public static readonly IReadOnlySet<string> All = new HashSet<string>
    {
        FleetHealth, PatchCompliance, InventoryLifecycle, BackupStatus, AuditSummary, VulnerabilityPosture,
    };
}

/// <summary>Default staleness bounds per data source. A source older
/// than its bound (or absent) makes the report name itself stale.
/// Bounds are named constants, overridable per-build by the caller
/// passing an explicit bound into the provenance factory — never by
/// clearing a flag.</summary>
public static class ReportingStaleness
{
    public static readonly TimeSpan HealthReports = TimeSpan.FromMinutes(30);
    public static readonly TimeSpan Inventory = TimeSpan.FromHours(24);
    public static readonly TimeSpan PatchScan = TimeSpan.FromHours(24);
    public static readonly TimeSpan BackupFacts = TimeSpan.FromHours(48);
    public static readonly TimeSpan AuditLedger = TimeSpan.MaxValue; // the ledger is live state: never stale by age, only by chain break (D38-F6: Zero made every summary noise-stale)
    public static readonly TimeSpan VulnerabilityFeed = TimeSpan.FromDays(7);
}

/// <summary>Provenance for ONE input of a report: which hub source
/// produced it, the timestamp OF THE DATA ITSELF (the newest fact the
/// input rests on — for fleet inputs, the OLDEST device timestamp,
/// so one silent device cannot be averaged into freshness), and the
/// bound it is judged against. Staleness is computed, never stored:
/// there is no constructor path that yields a fresh verdict for old
/// data.</summary>
public sealed record ReportInputProvenance(
    string Source,
    DateTimeOffset? DataAsOfUtc,
    TimeSpan StaleAfter,
    bool Present,
    string? BrokenReason = null)
{
    public TimeSpan? Age(DateTimeOffset now) => DataAsOfUtc is { } t ? now - t : null;

    public bool IsStale(DateTimeOffset now) =>
        BrokenReason is not null || !Present || DataAsOfUtc is null || now - DataAsOfUtc.Value > StaleAfter;

    public string Note(DateTimeOffset now)
    {
        if (BrokenReason is not null)
            return $"source '{Source}': BROKEN — {BrokenReason} (untrusted, which is worse than stale)";
        if (!Present || DataAsOfUtc is null)
            return $"source '{Source}': NO DATA — the report states this rather than treating absence as a clean result";
        var age = now - DataAsOfUtc.Value;
        return IsStale(now)
            ? $"source '{Source}': STALE — data as of {DataAsOfUtc:O} ({age.TotalHours:F1}h old, bound {StaleAfter.TotalHours:F1}h)"
            : $"source '{Source}': data as of {DataAsOfUtc:O} ({age.TotalHours:F1}h old, bound {StaleAfter.TotalHours:F1}h)";
    }
}

/// <summary>The header every report carries on its face. Overall
/// staleness is a computed property of the inputs at read time —
/// a header built over old inputs reads stale forever; it cannot be
/// laundered by re-rendering.</summary>
public sealed record ReportHeader(
    string ReportId,
    string Kind,
    string ScopeId,
    DateTimeOffset GeneratedUtc,
    IReadOnlyList<ReportInputProvenance> Inputs)
{
    public IReadOnlyList<ReportInputProvenance> Inputs { get; init; } =
        Inputs ?? Array.Empty<ReportInputProvenance>();

    public bool HasStaleInputs(DateTimeOffset now) => Inputs.Any(i => i.IsStale(now));

    public string StalenessBanner(DateTimeOffset now) => HasStaleInputs(now)
        ? "STALE INPUTS: " + string.Join("; ", Inputs.Where(i => i.IsStale(now)).Select(i => i.Note(now)))
        : "all inputs within their freshness bounds";
}

/// <summary>One report: header + summary counts + one table. The
/// table is plain strings end-to-end (device names included) — the
/// EXPORTERS own injection safety (CSV formula neutralisation), so
/// a hostile device name is data here and defused at render.</summary>
public sealed record HubReport(
    ReportHeader Header,
    IReadOnlyDictionary<string, long> Counts,
    IReadOnlyList<string> Columns,
    IReadOnlyList<IReadOnlyList<string>> Rows,
    IReadOnlyList<string> Notes)
{
    public IReadOnlyDictionary<string, long> Counts { get; init; } =
        Counts ?? new Dictionary<string, long>();
    public IReadOnlyList<string> Columns { get; init; } = Columns ?? Array.Empty<string>();
    public IReadOnlyList<IReadOnlyList<string>> Rows { get; init; } =
        Rows ?? Array.Empty<IReadOnlyList<string>>();
    public IReadOnlyList<string> Notes { get; init; } = Notes ?? Array.Empty<string>();

    public static string NewReportId(string kind, DateTimeOffset now) =>
        "rpt-" + Convert.ToHexString(SHA256.HashData(
            Encoding.UTF8.GetBytes($"{kind}|{now:O}|{Guid.NewGuid():N}")))[..20].ToLowerInvariant();
}

// ---- builders (pure; inputs are the data sources' own shapes) -----------

public static class ReportBuilders
{
    private static ReportHeader Header(string kind, string scopeId, DateTimeOffset now,
        params ReportInputProvenance[] inputs) =>
        new(HubReport.NewReportId(kind, now), kind, scopeId, now, inputs);

    /// <summary>Fleet health from RMM-01's hub ingest views. The
    /// input's DataAsOf is the OLDEST device report time: fleet
    /// freshness is the worst device, never the average.</summary>
    public static HubReport FleetHealth(IReadOnlyList<DeviceHealthView> views, string scopeId, DateTimeOffset now)
    {
        views ??= Array.Empty<DeviceHealthView>();
        // D38-F1: a never-reported device (null LastReportUtc) must
        // NOT vanish from the freshness calculation — LINQ Min over
        // nullable timestamps skips nulls, which laundered fleet
        // freshness. Any never-reported device forces DataAsOf null
        // (stale by definition) and is counted on the report's face.
        var neverReported = views.Count(v => v.LastReportUtc is null);
        var asOf = views.Count == 0 || neverReported > 0 ? (DateTimeOffset?)null : views.Min(v => v.LastReportUtc);
        var prov = new ReportInputProvenance("rmm01.hub_health_ingest", asOf, ReportingStaleness.HealthReports, views.Count > 0);
        var counts = new Dictionary<string, long>
        {
            ["devices"] = views.Count,
            ["never_reported"] = neverReported,
            ["healthy"] = views.Count(v => v.State == DeviceHealthStates.Healthy),
            ["alerting"] = views.Count(v => v.State == DeviceHealthStates.Alerting),
            ["degraded"] = views.Count(v => v.State == DeviceHealthStates.Degraded),
            ["down"] = views.Count(v => v.State == DeviceHealthStates.Down),
            ["unknown"] = views.Count(v => v.State == DeviceHealthStates.Unknown),
        };
        var rows = views.OrderBy(v => v.DeviceId, StringComparer.OrdinalIgnoreCase)
            .Select(v => (IReadOnlyList<string>)new[]
            {
                v.DeviceId, v.State, v.LastReportUtc?.ToString("O") ?? "(never)",
                string.Join(",", v.FiringConditionIds), v.Detail ?? "",
            }).ToList();
        var notes = new List<string>();
        if (views.Count == 0) notes.Add("no device has ever reported health to this hub — the fleet is unknown, not healthy");
        if (neverReported > 0) notes.Add($"{neverReported} device(s) have NEVER reported health — fleet freshness is stale by definition, not averaged from the devices that did report");
        return new HubReport(Header(ReportKinds.FleetHealth, scopeId, now, prov), counts,
            new[] { "device", "state", "last_report_utc", "firing_conditions", "detail" }, rows, notes);
    }

    /// <summary>One device's patch posture, computed by the caller
    /// from RMM-02's PatchScanner over RMM-04 inventory (the service
    /// adapts; the builder stays pure).</summary>
    public sealed record PatchPostureRow(
        string DeviceId, string Hostname, int Missing, int CriticalMissing, int HighMissing,
        DateTimeOffset InventoryAsOfUtc);

    /// <summary>Patch compliance: a device is compliant only when it
    /// is BOTH inventoried and missing nothing. A device with no
    /// inventory record is not in this report at all — it is named
    /// in the inventory report as unseen; compliance never invents
    /// a denominator.</summary>
    public static HubReport PatchCompliance(IReadOnlyList<PatchPostureRow> posture, string scopeId, DateTimeOffset now)
    {
        posture ??= Array.Empty<PatchPostureRow>();
        var asOf = posture.Count == 0 ? (DateTimeOffset?)null : posture.Min(p => p.InventoryAsOfUtc);
        var prov = new ReportInputProvenance("rmm02.patch_scan_over_rmm04.inventory", asOf, ReportingStaleness.PatchScan, posture.Count > 0);
        var compliant = posture.Count(p => p.Missing == 0);
        var counts = new Dictionary<string, long>
        {
            ["devices"] = posture.Count,
            ["compliant"] = compliant,
            ["non_compliant"] = posture.Count - compliant,
            ["missing_total"] = posture.Sum(p => (long)p.Missing),
            ["missing_critical"] = posture.Sum(p => (long)p.CriticalMissing),
            ["missing_high"] = posture.Sum(p => (long)p.HighMissing),
        };
        var rows = posture.OrderByDescending(p => p.CriticalMissing).ThenByDescending(p => p.Missing)
            .ThenBy(p => p.DeviceId, StringComparer.OrdinalIgnoreCase)
            .Select(p => (IReadOnlyList<string>)new[]
            {
                p.DeviceId, p.Hostname, p.Missing.ToString(), p.CriticalMissing.ToString(),
                p.HighMissing.ToString(), p.Missing == 0 ? "compliant" : "non-compliant",
                p.InventoryAsOfUtc.ToString("O"),
            }).ToList();
        var notes = new List<string>();
        if (posture.Count == 0) notes.Add("no inventoried devices — patch compliance has no denominator and claims none");
        return new HubReport(Header(ReportKinds.PatchCompliance, scopeId, now, prov), counts,
            new[] { "device", "hostname", "missing", "missing_critical", "missing_high", "state", "inventory_as_of_utc" }, rows, notes);
    }

    /// <summary>Inventory + lifecycle from RMM-04 records: age from
    /// purchase date where recorded (never guessed), warranty state
    /// as recorded on the hub (never re-looked-up here), refresh
    /// candidates = purchase age beyond the threshold.</summary>
    public static HubReport InventoryLifecycle(IReadOnlyList<DeviceInventoryRecord> records, string scopeId,
        DateTimeOffset now, int refreshAfterYears = 5, int warrantyWarnDays = 90)
    {
        records ??= Array.Empty<DeviceInventoryRecord>();
        var asOf = records.Count == 0 ? (DateTimeOffset?)null : records.Min(r => r.LastSeenUtc);
        var prov = new ReportInputProvenance("rmm04.inventory", asOf, ReportingStaleness.Inventory, records.Count > 0);
        var refresh = records.Where(r => r.PurchaseDateUtc is { } p && now - p > TimeSpan.FromDays(365.25 * refreshAfterYears)).ToList();
        var warrantyExpired = records.Where(r => r.Warranty?.ExpiresUtc is { } e && e < now).ToList();
        var warrantySoon = records.Where(r => r.Warranty?.ExpiresUtc is { } e && e >= now && e < now.AddDays(warrantyWarnDays)).ToList();
        var counts = new Dictionary<string, long>
        {
            ["devices"] = records.Count,
            ["refresh_candidates"] = refresh.Count,
            ["warranty_expired"] = warrantyExpired.Count,
            ["warranty_expiring_soon"] = warrantySoon.Count,
            ["warranty_unknown"] = records.Count(r => r.Warranty is null),
            ["software_items_total"] = records.Sum(r => (long)r.Software.Count),
        };
        var rows = records.OrderBy(r => r.DeviceId, StringComparer.OrdinalIgnoreCase)
            .Select(r => (IReadOnlyList<string>)new[]
            {
                r.DeviceId, r.Hostname, r.Hardware?.OsName ?? "", r.Hardware?.Model ?? "",
                r.PurchaseDateUtc?.ToString("yyyy-MM-dd") ?? "(unrecorded)",
                r.Warranty?.ExpiresUtc?.ToString("yyyy-MM-dd") ?? "(unknown)",
                refresh.Contains(r) ? "refresh-candidate" : "in-life",
                r.LastSeenUtc.ToString("O"),
            }).ToList();
        var notes = new List<string>();
        if (records.Any(r => r.PurchaseDateUtc is null))
            notes.Add("devices without a recorded purchase date are never aged by guess — they read '(unrecorded)' and are excluded from refresh candidacy");
        return new HubReport(Header(ReportKinds.InventoryLifecycle, scopeId, now, prov), counts,
            new[] { "device", "hostname", "os", "model", "purchased", "warranty_expires", "lifecycle", "last_seen_utc" }, rows, notes);
    }

    /// <summary>Backup status from RMM-06's BackupHealthFacts (the
    /// same facts RMM-01's monitor consumes — one truth, two
    /// readers). Findings are evaluated with the caller's staleness
    /// bound; a device with NO facts is not silently absent — the
    /// caller passes an explicit device list and missing devices get
    /// a 'no facts' row (silence is never health).</summary>
    public static HubReport BackupStatus(IReadOnlyList<BackupHealthFacts> facts, IReadOnlyList<string> expectedDeviceIds,
        string scopeId, DateTimeOffset now, TimeSpan? staleAfter = null)
    {
        facts ??= Array.Empty<BackupHealthFacts>();
        expectedDeviceIds ??= Array.Empty<string>();
        var bound = staleAfter ?? ReportingStaleness.BackupFacts;
        var asOf = facts.Count == 0 ? (DateTimeOffset?)null : facts.Min(f => f.GeneratedUtc);
        var byDevice = facts.GroupBy(f => f.DeviceId, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.OrderByDescending(f => f.GeneratedUtc).First(), StringComparer.OrdinalIgnoreCase);
        var deviceIds = expectedDeviceIds.Union(facts.Select(f => f.DeviceId), StringComparer.OrdinalIgnoreCase)
            .OrderBy(id => id, StringComparer.OrdinalIgnoreCase).ToList();
        var rows = new List<IReadOnlyList<string>>();
        long ok = 0, failing = 0, noFacts = 0;
        foreach (var id in deviceIds)
        {
            if (!byDevice.TryGetValue(id, out var f))
            {
                noFacts++;
                rows.Add(new[] { id, "no-facts", "", "", "no backup facts reported — unprotected until proven otherwise" });
                continue;
            }
            var findings = BackupHealthEvaluator.Evaluate(f, bound, now);
            var state = findings.Count == 0 ? "ok" : findings.Any(x => x.Severity == "critical") ? "critical" : "warning";
            if (state == "ok") ok++; else failing++;
            rows.Add(new[]
            {
                id, state, f.LastSuccessUtc?.ToString("O") ?? "(never)", f.ConsecutiveFailures.ToString(),
                string.Join("; ", findings.Select(x => x.Detail)),
            });
        }
        var counts = new Dictionary<string, long>
        {
            ["devices"] = deviceIds.Count, ["ok"] = ok, ["with_findings"] = failing, ["no_facts"] = noFacts,
            ["locked_snapshots"] = facts.Sum(f => (long)f.LockedSnapshots),
            ["locked_bytes"] = facts.Sum(f => f.LockedBytes),
            ["catalogue_tampered"] = facts.Count(f => f.CatalogueTampered),
        };
        // D38-F7: the header judges the facts against the CALLER's
        // bound (not the module default the findings ignored), and
        // an expected device with NO facts (absent, or its provider
        // threw and it was omitted upstream) marks the input NOT
        // PRESENT — the header can no longer read fresh off the
        // facts that happen to exist.
        var prov = new ReportInputProvenance("rmm06.backup_health_facts", asOf, bound, facts.Count > 0 && noFacts == 0);
        return new HubReport(Header(ReportKinds.BackupStatus, scopeId, now, prov), counts,
            new[] { "device", "state", "last_success_utc", "consecutive_failures", "findings" }, rows,
            Array.Empty<string>());
    }

    /// <summary>Audit summary over the chained ledger. The ledger's
    /// own verification verdict rides the report: a BROKEN chain is
    /// the headline, never a footnote — and the input provenance
    /// names the break as its staleness (a broken chain's data is
    /// not 'old', it is untrusted, which is worse and says so).</summary>
    public static HubReport AuditSummary(ChainedAuditLog log, string scopeId, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(log);
        var verification = log.Verify();
        var entries = log.Entries;
        var asOf = entries.Count == 0 ? (DateTimeOffset?)null : entries.Max(e => e.AtUtc);
        // D38-F6: a BROKEN chain feeds the provenance itself (the
        // docstring always claimed this; the code never did), and
        // the caller-supplied kindCountsOverride laundering hook is
        // REMOVED — counts come from the ledger, only from the ledger.
        var prov = new ReportInputProvenance("audit.chained_ledger", asOf, ReportingStaleness.AuditLedger,
            entries.Count > 0, verification.Ok ? null : $"audit chain verification failed: {verification.Summary}");
        var byKind = entries.GroupBy(e => e.Kind, StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => (long)g.Count(), StringComparer.Ordinal);
        var counts = new Dictionary<string, long>();
        foreach (var (kind, n) in byKind)
        {
            // A ledger kind literally named 'entries_total' or
            // 'chain_ok' must not clobber the summary's own keys:
            // reserved names are exposed under a ledger_kind: prefix.
            var key = kind is "entries_total" or "chain_ok" or "clock_skew_flagged" ? "ledger_kind:" + kind : kind;
            counts[key] = n;
        }
        counts["entries_total"] = entries.Count;
        counts["chain_ok"] = verification.Ok ? 1 : 0;
        counts["clock_skew_flagged"] = entries.Count(e => e.ClockSkewFlagged);
        var rows = byKind.OrderByDescending(kv => kv.Value).ThenBy(kv => kv.Key, StringComparer.Ordinal)
            .Select(kv => (IReadOnlyList<string>)new[] { kv.Key, kv.Value.ToString() }).ToList();
        var notes = new List<string>
        {
            $"chain verification: {verification.Summary}",
        };
        if (!verification.Ok) notes.Add("THE AUDIT CHAIN IS BROKEN — every count in this report rests on a tampered ledger and is named as such");
        if (entries.Count == 0) notes.Add("the audit ledger is empty — no activity has been recorded on this hub");
        return new HubReport(Header(ReportKinds.AuditSummary, scopeId, now, prov), counts,
            new[] { "event_kind", "count" }, rows, notes);
    }

    /// <summary>Vulnerability posture, adapted from RMM-05's
    /// BuildReport shape. The RMM-05 FeedProvenance rides through
    /// untouched: a stale feed makes this report stale through its
    /// own provenance input, with the feed's note verbatim.</summary>
    public sealed record VulnPostureInput(
        int Open, int Compensated, int RemediationRequested, int Closed, int KevOpen,
        int Overdue, FeedProvenance Provenance,
        // BD-WIN-CORE-4/F4: the policy verdict rides through — a
        // policy-disabled posture must never render as "0 open,
        // 0 KEV" (a clean fleet). Defaults keep older callers
        // honest-by-default (evaluated).
        bool PolicyEnabled = true, string? RefusalReason = null);

    public static HubReport VulnerabilityPosture(VulnPostureInput input, string scopeId, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(input);
        // D38-F7: ONE staleness verdict for the whole report. The
        // feed provenance is evaluated ONCE, here, at render time
        // against this module's own 7-day bound, and that single
        // evaluated verdict drives the header provenance, the
        // feed_stale count, the rows and the notes — previously the
        // header used the render-time bound while counts/notes used
        // RMM-05's BuildReport-time verdict, and the two disagreed.
        var feed = input.Provenance.Evaluate(now, (int)ReportingStaleness.VulnerabilityFeed.TotalDays);
        var prov = new ReportInputProvenance("rmm05.vulnerability_feed:" + (feed.FeedId ?? "(none)"),
            feed.FeedPublishedUtc, ReportingStaleness.VulnerabilityFeed, feed.FeedId is not null);
        var counts = new Dictionary<string, long>
        {
            ["open"] = input.Open, ["compensated"] = input.Compensated,
            ["remediation_requested"] = input.RemediationRequested, ["closed"] = input.Closed,
            ["kev_open"] = input.KevOpen, ["overdue"] = input.Overdue,
            ["feed_stale"] = feed.IsStale ? 1 : 0,
            ["policy_enabled"] = input.PolicyEnabled ? 1 : 0,
        };
        var rows = new List<IReadOnlyList<string>>
        {
            new[] { "feed", feed.FeedId ?? "(none imported)" },
            new[] { "feed_source", feed.Source ?? "" },
            new[] { "feed_published_utc", feed.FeedPublishedUtc?.ToString("O") ?? "" },
            new[] { "feed_staleness", feed.StalenessNote },
            new[] { "policy_enabled", input.PolicyEnabled ? "true" : "false" },
        };
        var notes = new List<string> { feed.StalenessNote };
        if (!input.PolicyEnabled)
            notes.Add("not evaluated (policy off): vulnerability management is disabled by policy for this scope — the zero counts above are NOT a clean-fleet verdict" +
                (input.RefusalReason is null ? "" : $": {input.RefusalReason}"));
        return new HubReport(Header(ReportKinds.VulnerabilityPosture, scopeId, now, prov), counts,
            new[] { "field", "value" }, rows, notes);
    }
}

// ---- exporters -------------------------------------------------------------

public static class ReportExportFormats
{
    public const string Json = "json";
    public const string Csv = "csv";
    public const string Text = "text";
    public static readonly IReadOnlySet<string> All = new HashSet<string> { Json, Csv, Text };
}

/// <summary>Exporters. All three formats carry the header (with its
/// computed staleness) — there is no format in which a report sheds
/// its provenance. CSV cells pass through formula neutralisation:
/// a cell whose first character could start a spreadsheet formula
/// (= + - @, tab, CR) is prefixed with a single quote, so a hostile
/// device name like "=cmd|..." exports as inert text.</summary>
public static class ReportExporter
{
    public static string Export(HubReport report, string format, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(report);
        return (format ?? "").Trim().ToLowerInvariant() switch
        {
            ReportExportFormats.Json => ToJson(report, now),
            ReportExportFormats.Csv => ToCsv(report, now),
            ReportExportFormats.Text => ToText(report, now),
            _ => throw new ArgumentException($"unknown export format '{format}' — refused (formats are json, csv, text)", nameof(format)),
        };
    }

    public static string ToJson(HubReport report, DateTimeOffset now)
    {
        var h = report.Header;
        return JsonSerializer.Serialize(new
        {
            reportId = h.ReportId,
            kind = h.Kind,
            scopeId = h.ScopeId,
            generatedUtc = h.GeneratedUtc,
            staleInputs = h.HasStaleInputs(now),
            staleness = h.StalenessBanner(now),
            inputs = h.Inputs.Select(i => new
            {
                source = i.Source,
                dataAsOfUtc = i.DataAsOfUtc,
                present = i.Present,
                stale = i.IsStale(now),
                note = i.Note(now),
            }).ToArray(),
            counts = report.Counts,
            columns = report.Columns,
            rows = report.Rows,
            notes = report.Notes,
        }, new JsonSerializerOptions { WriteIndented = true });
    }

    public static string ToText(HubReport report, DateTimeOffset now)
    {
        var h = report.Header;
        var sb = new StringBuilder();
        sb.AppendLine($"REPORT {h.Kind}  id={h.ReportId}  scope={h.ScopeId}  generated={h.GeneratedUtc:O}");
        if (h.HasStaleInputs(now)) sb.AppendLine($"*** {h.StalenessBanner(now)} ***");
        sb.AppendLine("provenance:");
        foreach (var i in h.Inputs) sb.AppendLine($"  - {i.Note(now)}");
        sb.AppendLine("counts:");
        foreach (var (k, v) in report.Counts.OrderBy(kv => kv.Key, StringComparer.Ordinal))
            sb.AppendLine($"  {k} = {v}");
        foreach (var n in report.Notes) sb.AppendLine($"note: {n}");
        sb.AppendLine(string.Join(" | ", report.Columns));
        foreach (var row in report.Rows) sb.AppendLine(string.Join(" | ", row));
        return sb.ToString();
    }

    public static string ToCsv(HubReport report, DateTimeOffset now)
    {
        var h = report.Header;
        var sb = new StringBuilder();
        // Provenance preamble: comment rows (first cell starts '#'),
        // then the table. The staleness verdict is a preamble row —
        // a CSV consumer sees it before any data row.
        CsvRow(sb, "# report", h.Kind, "id", h.ReportId, "scope", h.ScopeId, "generated", h.GeneratedUtc.ToString("O"));
        CsvRow(sb, "# stale_inputs", h.HasStaleInputs(now) ? "true" : "false", "staleness", h.StalenessBanner(now));
        foreach (var i in h.Inputs) CsvRow(sb, "# input", i.Source, i.Note(now));
        foreach (var n in report.Notes) CsvRow(sb, "# note", n);
        CsvRow(sb, report.Columns.ToArray());
        foreach (var row in report.Rows) CsvRow(sb, row.ToArray());
        return sb.ToString();
    }

    /// <summary>Neutralise one CSV cell: formula-leading characters
    /// get a leading single quote; quoting follows RFC 4180.</summary>
    public static string CsvCell(string? cell)
    {
        var c = cell ?? "";
        if (c.Length > 0 && (c[0] is '=' or '+' or '-' or '@' or '\t' or '\r'))
            c = "'" + c;
        if (c.Contains(',') || c.Contains('"') || c.Contains('\n') || c.Contains('\r'))
            c = "\"" + c.Replace("\"", "\"\"") + "\"";
        return c;
    }

    private static void CsvRow(StringBuilder sb, params string[] cells)
    {
        sb.Append(string.Join(",", cells.Select(CsvCell)));
        sb.Append("\r\n");
    }
}
