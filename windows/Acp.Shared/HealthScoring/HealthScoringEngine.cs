using System.Globalization;
using System.Text.Json;
using Acp.Shared.Backup;
using Acp.Shared.Hub; // HubPersistence envelope for the store round-trip (BD-SHARED-RMM-1 F8)
using Acp.Shared.EndpointSecurity;
using Acp.Shared.Inventory;
using Acp.Shared.Monitoring;
using Acp.Shared.Patching;
using Acp.Shared.Reporting; // ReportingStaleness (RMM-06's backup bound, FL-28b/F8)
using Acp.Shared.Vulnerability;

namespace Acp.Shared.HealthScoring;

// =====================================================================
// RMM-28 — the scorer, the integrity check, the snapshot store, and
// the fleet / trend report shapes. The scorer is PURE: device,
// inputs (source-system shapes), weights, staleness bounds, now →
// score. All state lives in the store; all policy lives in the
// Core service.
// =====================================================================

/// <summary>Structural aggregate caps. These sit OUTSIDE the
/// weights on purpose: they are the anti-laundering floors. No
/// weight assignment — including zeroing a component's weight —
/// can present a device with an open critical/KEV exposure, or a
/// device that is down, as healthy.</summary>
public static class HealthScoreCaps
{
    public const double CriticalExposureCap = 49;
    public const double DeviceDownCap = 39;
}

public static class HealthScoreEngine
{
    public static DeviceHealthScore Compute(
        string deviceId, string scopeId, HealthScoreInputs inputs,
        HealthScoreWeights weights, HealthStalenessBounds bounds, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(inputs);
        ArgumentNullException.ThrowIfNull(weights);
        if (weights.Validate() is { } invalid)
            throw new ArgumentException($"cannot score under invalid weights: {invalid}", nameof(weights));

        var components = new[]
        {
            ScoreMonitoring(inputs.Monitoring, weights, bounds, now),
            ScoreExposure(inputs.Exposure, weights, now),
            ScoreBackup(inputs.Backup, weights, bounds, now),
            ScorePosture(inputs.Posture, weights, bounds, now),
            ScoreInventory(inputs.Inventory, weights, bounds, now),
        };

        var scored = components.Where(c => c.State == ComponentScoreStates.Scored).ToList();
        var knownWeight = scored.Sum(c => c.Weight);
        var coverage = weights.TotalWeight > 0 ? knownWeight / weights.TotalWeight : 0;

        double? aggregate = null;
        string? capReason = null;
        if (scored.Count > 0 && knownWeight > 0)
        {
            aggregate = Math.Round(
                scored.Sum(c => c.Value!.Value * c.Weight) / knownWeight, 1);

            // Anti-laundering caps, judged from the components' own
            // recorded facts — the same facts the integrity check
            // re-judges a stored/imported snapshot by.
            // FL-28a (F2/F3): caps fire on KNOWN FACTS regardless of
            // the component's scored state. A stale feed makes the
            // exposure VALUE untrustworthy, but the open critical /
            // KEV items it recorded are still known facts; likewise
            // RMM-01's DOWN verdict is authoritative even when this
            // report's own staleness bound re-derives the monitoring
            // component UNKNOWN. A component with NO facts at all
            // (source absent) triggers no cap — there is nothing
            // known to cap on.
            var caps = new List<string>();
            var exposure = components.First(c => c.Component == HealthComponents.Exposure);
            var openCritical = FactInt(exposure, "open_critical");
            var openKev = FactInt(exposure, "open_kev");
            if (exposure.FactValue("open_critical") is not null &&
                exposure.FactValue("open_kev") is not null &&
                (openCritical > 0 || openKev > 0))
            {
                caps.Add($"open critical/KEV exposure present (critical={openCritical}, kev={openKev}) — aggregate capped at {HealthScoreCaps.CriticalExposureCap}");
                aggregate = Math.Min(aggregate.Value, HealthScoreCaps.CriticalExposureCap);
            }
            var monitoring = components.First(c => c.Component == HealthComponents.Monitoring);
            if (monitoring.FactValue("health_state") == DeviceHealthStates.Down)
            {
                caps.Add($"device is DOWN per RMM-01 — aggregate capped at {HealthScoreCaps.DeviceDownCap}");
                aggregate = Math.Min(aggregate.Value, HealthScoreCaps.DeviceDownCap);
            }
            if (caps.Count > 0) capReason = string.Join("; ", caps);
        }

        return new DeviceHealthScore(
            deviceId, scopeId, now, weights.Version,
            scored.Count == HealthComponents.All.Count ? HealthScoreStates.Complete : HealthScoreStates.Partial,
            aggregate, Math.Round(coverage, 4), capReason, components);
    }

    private static int FactInt(ComponentScore c, string name) =>
        int.TryParse(c.FactValue(name), NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) ? v : 0;

    private static ComponentScore Unknown(string component, double weight, string source, string reason,
        DateTimeOffset? inputTs = null, IReadOnlyList<ComponentFact>? facts = null) =>
        new(component, ComponentScoreStates.Unknown, null, weight, source, inputTs, reason,
            facts ?? Array.Empty<ComponentFact>());

    private static ComponentScore Scored(string component, double value, double weight, string source,
        DateTimeOffset? inputTs, IReadOnlyList<ComponentFact> facts) =>
        new(component, ComponentScoreStates.Scored,
            Math.Round(Math.Clamp(value, 0, 100), 1), weight, source, inputTs, null, facts);

    private static ComponentFact Fact(string name, object? value, DateTimeOffset? ts = null) =>
        new(name, value?.ToString() ?? "(none)", ts);

    // ---- monitoring (RMM-01) -------------------------------------------

    private static ComponentScore ScoreMonitoring(
        MonitoringHealthInput? input, HealthScoreWeights weights,
        HealthStalenessBounds bounds, DateTimeOffset now)
    {
        var w = weights.WeightOf(HealthComponents.Monitoring);
        const string source = "rmm01.monitoring";
        if (input is null)
            return Unknown(HealthComponents.Monitoring, w, source,
                "RMM-01 provided no health data for this device — monitoring state is unknown, not healthy");
        var view = input.View;
        var last = view.LastReportUtc;
        var facts = new List<ComponentFact>
        {
            Fact("health_state", view.State, last),
            Fact("firing_conditions", string.Join(",", view.FiringConditionIds), last),
            Fact("active_alerts", input.ActiveAlerts.Count, last),
            Fact("critical_alerts", input.ActiveAlerts.Count(a => a.Severity == AlertSeverities.Critical), last),
            Fact("warning_alerts", input.ActiveAlerts.Count(a => a.Severity == AlertSeverities.Warning), last),
            Fact("info_alerts", input.ActiveAlerts.Count(a => a.Severity == AlertSeverities.Info), last),
        };
        if (view.State == DeviceHealthStates.Unknown || last is null)
            return Unknown(HealthComponents.Monitoring, w, source,
                "device has never reported health to the hub (RMM-01 state 'unknown')", last, facts);
        // FL-28b / F9: a future-dated report made `now - last`
        // negative, so it counted as fresh indefinitely. A source
        // timestamp ahead of now is a clock problem, not freshness.
        if (last.Value > now)
            return Unknown(HealthComponents.Monitoring, w, source,
                $"last health report {last:O} is dated in the FUTURE relative to scoring time {now:O} — a future timestamp is a clock fault, not freshness, so monitoring scores unknown", last, facts);
        if (now - last.Value > bounds.Monitoring)
            return Unknown(HealthComponents.Monitoring, w, source,
                $"last health report {last:O} is older than the monitoring staleness bound {bounds.Monitoring} — stale monitoring data does not certify health", last, facts);

        double value;
        if (view.State == DeviceHealthStates.Down) value = 0;
        else if (view.State == DeviceHealthStates.Degraded) value = 40;
        else
        {
            value = 100;
            foreach (var a in input.ActiveAlerts)
                value -= a.Severity switch
                {
                    AlertSeverities.Critical => 40,
                    AlertSeverities.Warning => 15,
                    AlertSeverities.Info => 5,
                    _ => 10,
                };
            // A firing set the centre holds no alert objects for
            // still costs: the view's firing ids are RMM-01 facts.
            if (input.ActiveAlerts.Count == 0)
                value -= 15 * view.FiringConditionIds.Count;
        }
        return Scored(HealthComponents.Monitoring, value, w, source, last, facts);
    }

    // ---- exposure (RMM-05) ----------------------------------------------

    private static ComponentScore ScoreExposure(
        ExposureHealthInput? input, HealthScoreWeights weights, DateTimeOffset now)
    {
        var w = weights.WeightOf(HealthComponents.Exposure);
        const string source = "rmm05.vulnerability";
        if (input is null)
            return Unknown(HealthComponents.Exposure, w, source,
                "RMM-05 provided no exposure data for this device");
        var prov = input.Provenance;
        var open = input.OpenItems;
        int BySeverity(string sev) => open.Count(i =>
            string.Equals(i.Severity, sev, StringComparison.OrdinalIgnoreCase));
        // FL-28b / F7: items whose severity is outside the closed
        // PatchSeverities set. Previously they matched NO pricing
        // bucket and cost exactly 0 — an unrecognised severity was
        // silently free (the monitoring component prices unknown
        // alert severities at a fallback; exposure priced them at
        // nothing, with no fact recording they existed).
        var unclassified = open.Count(i => !PatchSeverities.All.Contains(
            (i.Severity ?? "").Trim().ToLowerInvariant()));
        var facts = new List<ComponentFact>
        {
            Fact("open_total", open.Count, prov.FeedPublishedUtc),
            Fact("open_critical", BySeverity(PatchSeverities.Critical), prov.FeedPublishedUtc),
            Fact("open_high", BySeverity(PatchSeverities.High), prov.FeedPublishedUtc),
            Fact("open_medium", BySeverity(PatchSeverities.Medium), prov.FeedPublishedUtc),
            Fact("open_low", BySeverity(PatchSeverities.Low), prov.FeedPublishedUtc),
            Fact("open_unclassified", unclassified, prov.FeedPublishedUtc),
            Fact("open_kev", open.Count(i => i.IsKev), prov.FeedPublishedUtc),
            Fact("open_overdue", open.Count(i => i.IsOverdue(now)), prov.FeedPublishedUtc),
            Fact("feed_id", prov.FeedId ?? "(none)", prov.FeedPublishedUtc),
            Fact("feed_stale", prov.IsStale ? "true" : "false", prov.FeedPublishedUtc),
            Fact("feed_staleness_note", prov.StalenessNote, prov.FeedPublishedUtc),
        };
        if (prov.FeedId is null)
            return Unknown(HealthComponents.Exposure, w, source,
                "no vulnerability feed has been imported — there is no exposure data to score against", null, facts);
        if (prov.IsStale)
            return Unknown(HealthComponents.Exposure, w, source,
                $"vulnerability feed is STALE ({prov.StalenessNote}) — exposure state may be understated, so it scores unknown rather than trusting old data", prov.FeedPublishedUtc, facts);
        // FL-28b / F7: an unrecognised severity cannot be priced —
        // the feed is speaking a severity vocabulary this scorer
        // does not know, so the component scores UNKNOWN with the
        // fact named (open_unclassified), never a silently-free 0.
        if (unclassified > 0)
            return Unknown(HealthComponents.Exposure, w, source,
                $"{unclassified} open exposure item(s) carry a severity outside the recognised set (critical|high|medium|low|none) — an unrecognised severity cannot be priced, so exposure scores unknown rather than treating it as free", prov.FeedPublishedUtc, facts);

        var value = 100.0;
        value -= 35 * BySeverity(PatchSeverities.Critical);
        value -= 20 * BySeverity(PatchSeverities.High);
        value -= 8 * BySeverity(PatchSeverities.Medium);
        value -= 3 * BySeverity(PatchSeverities.Low);
        value -= 15 * open.Count(i => i.IsKev);
        value -= 10 * open.Count(i => i.IsOverdue(now));
        return Scored(HealthComponents.Exposure, value, w, source, prov.FeedPublishedUtc, facts);
    }

    // ---- backup (RMM-06) --------------------------------------------------

    private static ComponentScore ScoreBackup(
        BackupHealthFacts? facts0, HealthScoreWeights weights,
        HealthStalenessBounds bounds, DateTimeOffset now)
    {
        var w = weights.WeightOf(HealthComponents.Backup);
        const string source = "rmm06.backup";
        if (facts0 is null)
            return Unknown(HealthComponents.Backup, w, source,
                "RMM-06 provided no backup health facts for this device");
        var f = facts0;
        var facts = new List<ComponentFact>
        {
            Fact("last_attempt_utc", f.LastAttemptUtc?.ToString("O") ?? "(never)", f.LastAttemptUtc),
            Fact("last_success_utc", f.LastSuccessUtc?.ToString("O") ?? "(never)", f.LastSuccessUtc),
            Fact("last_outcome", f.LastOutcome, f.LastAttemptUtc),
            Fact("consecutive_failures", f.ConsecutiveFailures, f.GeneratedUtc),
            Fact("locked_snapshots", f.LockedSnapshots, f.GeneratedUtc),
            Fact("storage_reachable", f.StorageReachable ? "true" : "false", f.GeneratedUtc),
            Fact("catalogue_tampered", f.CatalogueTampered ? "true" : "false", f.GeneratedUtc),
        };
        // FL-28b / F8+F9: staleness is judged on the AGE OF THE
        // BACKUP ITSELF (last success / last attempt), never on
        // GeneratedUtc. The facts provider stamps GeneratedUtc with
        // the QUERY time (BackupEngine.GetFacts(device, now) →
        // GeneratedUtc = now), so the previous check
        // `now - GeneratedUtc > bound` could never fire — months-old
        // backups scored fresh forever. A backup whose last success
        // (or, if it never succeeded, last attempt) is older than
        // the bound scores UNKNOWN; future-dated success/attempt
        // timestamps are a clock fault, not freshness (F9).
        var newestBackupActivity = f.LastSuccessUtc is { } ls && f.LastAttemptUtc is { } la
            ? (ls > la ? ls : la)
            : f.LastSuccessUtc ?? f.LastAttemptUtc;
        if (newestBackupActivity is { } activity && activity > now)
            return Unknown(HealthComponents.Backup, w, source,
                $"backup activity is dated in the FUTURE (newest success/attempt {activity:O} vs scoring time {now:O}) — a future timestamp is a clock fault, not freshness, so backup scores unknown", f.GeneratedUtc, facts);
        if (f.LastSuccessUtc is { } lastSuccess)
        {
            if (now - lastSuccess > bounds.Backup)
                return Unknown(HealthComponents.Backup, w, source,
                    $"last successful backup {lastSuccess:O} is older than the backup staleness bound {bounds.Backup} — stale backup data does not certify protection", f.GeneratedUtc, facts);
        }
        else if (f.LastAttemptUtc is { } lastAttempt && now - lastAttempt > bounds.Backup)
            return Unknown(HealthComponents.Backup, w, source,
                $"backups have been attempted but never succeeded, and the last attempt {lastAttempt:O} is older than the backup staleness bound {bounds.Backup}", f.GeneratedUtc, facts);

        // FL-28b / F8: findings are consumed under RMM-06's OWN
        // policy bound — the same ReportingStaleness.BackupFacts
        // bound the RMM-13 backup report evaluates them under —
        // not under RMM-28's per-component staleness bound. Two
        // different bounds for the same findings meant the health
        // score and the backup report could disagree about whether
        // the same backup was stale.
        var findings = BackupHealthEvaluator.Evaluate(f, ReportingStaleness.BackupFacts, now);
        double value;
        if (f.CatalogueTampered) value = 0;
        else if (f.LastAttemptUtc is null && f.LastSuccessUtc is null) value = 25; // never ran: unprotected, named
        else if (f.LastSuccessUtc is null) value = 20;                            // attempted, never succeeded
        else
        {
            value = 100;
            foreach (var finding in findings)
                value -= finding.Severity == AlertSeverities.Critical ? 45 : 20;
            if (f.ConsecutiveFailures >= 3) value = Math.Min(value, 30);
        }
        foreach (var finding in findings)
            // FL-28a (F1): the severity rides the fact value so the
            // integrity check can re-price this component from its
            // recorded facts alone ("<severity>|<detail>").
            facts.Add(Fact($"finding:{finding.Kind}", $"{finding.Severity}|{finding.Detail}", f.GeneratedUtc));
        return Scored(HealthComponents.Backup, value, w, source, f.GeneratedUtc, facts);
    }

    // ---- posture (RMM-17) -------------------------------------------------

    private static ComponentScore ScorePosture(
        PostureHealthInput? input, HealthScoreWeights weights,
        HealthStalenessBounds bounds, DateTimeOffset now)
    {
        var w = weights.WeightOf(HealthComponents.Posture);
        const string source = "rmm17.endpoint_security";
        if (input is null || input.Posture is null)
            return Unknown(HealthComponents.Posture, w, source,
                "RMM-17 has no AV posture report for this device — protection is unknown, not assumed",
                input?.Posture?.EvaluatedUtc,
                input?.Isolation is { } iso0
                    ? new[] { Fact("isolation_state", iso0.State, iso0.SinceUtc) }
                    : Array.Empty<ComponentFact>());
        var report = input.Posture;
        var facts = new List<ComponentFact>
        {
            Fact("any_protected", report.AnyProtected ? "true" : "false", report.EvaluatedUtc),
            Fact("has_gap", report.HasGap ? "true" : "false", report.EvaluatedUtc),
        };
        foreach (var finding in report.Findings)
            facts.Add(Fact($"av:{finding.ProductId}", finding.State, report.EvaluatedUtc));
        if (input.Isolation is { } iso)
            facts.Add(Fact("isolation_state", iso.State, iso.SinceUtc));
        // FL-28b / F9: future-dated evaluation = clock fault, not fresh.
        if (report.EvaluatedUtc > now)
            return Unknown(HealthComponents.Posture, w, source,
                $"AV posture evaluation {report.EvaluatedUtc:O} is dated in the FUTURE relative to scoring time {now:O} — a future timestamp is a clock fault, not freshness, so posture scores unknown", report.EvaluatedUtc, facts);
        if (now - report.EvaluatedUtc > bounds.Posture)
            return Unknown(HealthComponents.Posture, w, source,
                $"AV posture was evaluated {report.EvaluatedUtc:O}, older than the posture staleness bound {bounds.Posture} — a stale 'protected' claim does not score", report.EvaluatedUtc, facts);

        double value;
        if (report.AnyProtected && !report.HasGap) value = 100;
        else if (report.AnyProtected) value = 70;
        else if (report.Findings.Any(x => x.State is AvPostureStates.Missing or AvPostureStates.Disabled)) value = 10;
        else value = 40; // stale/unknown findings only

        if (input.Isolation is { } iso2)
        {
            if (iso2.IsIsolated) value = Math.Min(value, 20);
            else if (iso2.State == IsolationStates.IsolationFailed) value = Math.Min(value, 30);
        }
        return Scored(HealthComponents.Posture, value, w, source, report.EvaluatedUtc, facts);
    }

    // ---- inventory (RMM-04) -----------------------------------------------

    private static ComponentScore ScoreInventory(
        DeviceInventoryRecord? record, HealthScoreWeights weights,
        HealthStalenessBounds bounds, DateTimeOffset now)
    {
        var w = weights.WeightOf(HealthComponents.Inventory);
        const string source = "rmm04.inventory";
        if (record is null)
            return Unknown(HealthComponents.Inventory, w, source,
                "RMM-04 holds no inventory record for this device");
        var hw = record.Hardware;
        var facts = new List<ComponentFact>
        {
            Fact("os", hw is null ? "(unknown)" : $"{hw.OsName} {hw.OsVersion} (build {hw.OsBuild})", record.LastSeenUtc),
            Fact("model", hw?.Model ?? "(unknown)", record.LastSeenUtc),
            Fact("purchase_date_utc", record.PurchaseDateUtc?.ToString("O") ?? "(unrecorded)", record.PurchaseDateUtc),
            Fact("warranty_status", record.Warranty?.Status ?? "(unknown)", record.Warranty?.RetrievedUtc),
            Fact("warranty_expires_utc", record.Warranty?.ExpiresUtc?.ToString("O") ?? "(unknown)", record.Warranty?.RetrievedUtc),
            Fact("warranty_retrieved_utc", record.Warranty?.RetrievedUtc.ToString("O") ?? "(unknown)", record.Warranty?.RetrievedUtc),
            Fact("inventory_revision", record.Revision, record.LastChangedUtc),
            Fact("dropped_items", record.DroppedSoftwareCount + record.DroppedTagsCount, record.LastSeenUtc),
        };
        // FL-28b / F9: future-dated last-seen = clock fault, not fresh.
        if (record.LastSeenUtc > now)
            return Unknown(HealthComponents.Inventory, w, source,
                $"inventory record last-seen {record.LastSeenUtc:O} is dated in the FUTURE relative to scoring time {now:O} — a future timestamp is a clock fault, not freshness, so inventory scores unknown", record.LastSeenUtc, facts);
        if (now - record.LastSeenUtc > bounds.Inventory)
            return Unknown(HealthComponents.Inventory, w, source,
                $"inventory record was last seen {record.LastSeenUtc:O}, older than the inventory staleness bound {bounds.Inventory} — age/warranty facts that old do not score", record.LastSeenUtc, facts);
        // FL-28b / F10: warranty facts are priced from RMM-04's
        // recorded STATUS, and only while the lookup that produced
        // them is itself fresh. Previously the engine re-derived
        // expiry from ExpiresUtc against `now` while ignoring
        // RetrievedUtc entirely — a years-old lookup saying
        // "active, expires 2030" priced as current truth forever.
        // A warranty lookup older than the inventory staleness
        // bound (or dated in the future) makes the component
        // UNKNOWN: the warranty fact is stale, not active.
        if (record.Warranty is { } warrantyFact)
        {
            if (warrantyFact.RetrievedUtc > now)
                return Unknown(HealthComponents.Inventory, w, source,
                    $"warranty information was retrieved {warrantyFact.RetrievedUtc:O}, dated in the FUTURE relative to scoring time {now:O} — warranty scores unknown", record.LastSeenUtc, facts);
            if (now - warrantyFact.RetrievedUtc > bounds.Inventory)
                return Unknown(HealthComponents.Inventory, w, source,
                    $"warranty information was retrieved {warrantyFact.RetrievedUtc:O}, older than the inventory staleness bound {bounds.Inventory} — a stale warranty lookup does not certify coverage, so inventory scores unknown", record.LastSeenUtc, facts);
        }

        var value = 100.0;
        if (record.PurchaseDateUtc is { } purchased)
        {
            var ageYears = (now - purchased).TotalDays / 365.25;
            facts.Add(Fact("device_age_years", ageYears.ToString("F1", CultureInfo.InvariantCulture), purchased));
            if (ageYears > 7) value -= 40;
            else if (ageYears > 5) value -= 25;
            else if (ageYears > 3) value -= 10;
        }
        else value -= 10; // unrecorded purchase date: age unknown — a named deduction, never assumed new

        // FL-28b / F10: price from the RECORDED status (RMM-04's
        // own verdict), not from a local re-derivation off
        // ExpiresUtc. Status active → no deduction; expiring within
        // 90 days per the recorded expiry → the named smaller
        // deduction; expired (or unknown status) → as recorded.
        if (record.Warranty is null) value -= 10;
        else if (record.Warranty.Status == WarrantyInfo.StatusExpired) value -= 30;
        else if (record.Warranty.Status == WarrantyInfo.StatusUnknown) value -= 10;
        else if (record.Warranty.ExpiresUtc is { } exp && exp < now.AddDays(90)) value -= 15;
        if (record.DroppedSoftwareCount + record.DroppedTagsCount > 0) value -= 5;
        return Scored(HealthComponents.Inventory, value, w, source, record.LastSeenUtc, facts);
    }
}

// ---- integrity: a stored/imported score must prove itself -----------------

/// <summary>Re-validation of a score against ITS OWN recorded
/// decomposition. This is what makes snapshots trustworthy and
/// forgery hard: the aggregate must recompute from the recorded
/// component values + weights, the coverage must match, the state
/// must agree with the unknowns, the anti-laundering caps must hold
/// against the recorded facts, and the content hash must match.
/// Nothing here consults current policy — a historical score is
/// judged under the weights IT records, never today's.</summary>
public static class HealthScoreIntegrity
{
    public static string? Validate(DeviceHealthScore? s)
    {
        if (s is null) return "no score — refused";
        if (string.IsNullOrWhiteSpace(s.DeviceId)) return "score carries no device id — refused";
        if (string.IsNullOrWhiteSpace(s.WeightsVersion)) return "score records no weights version — refused (a score without its weights version cannot be trusted or trended)";
        if (s.Components.Count != HealthComponents.All.Count)
            return $"score carries {s.Components.Count} components, expected {HealthComponents.All.Count} — a score without its full decomposition does not exist in this model";
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var c in s.Components)
        {
            if (!HealthComponents.All.Contains(c.Component))
                return $"score carries unknown component '{c.Component}' — refused";
            if (!seen.Add(c.Component))
                return $"score carries component '{c.Component}' twice — refused";
            if (double.IsNaN(c.Weight) || double.IsInfinity(c.Weight) || c.Weight < 0)
                return $"component '{c.Component}' carries invalid weight {c.Weight} — refused";
            if (c.State == ComponentScoreStates.Scored)
            {
                if (c.Value is not { } v || double.IsNaN(v) || v < 0 || v > 100)
                    return $"scored component '{c.Component}' carries value {c.Value} outside 0–100 — refused";
                if (c.UnknownReason is not null)
                    return $"scored component '{c.Component}' also carries an unknown reason — refused (a component is scored or unknown, never both)";
            }
            else if (c.State == ComponentScoreStates.Unknown)
            {
                if (c.Value is not null)
                    return $"unknown component '{c.Component}' carries a value — refused (unknown is not a number)";
                if (string.IsNullOrWhiteSpace(c.UnknownReason))
                    return $"unknown component '{c.Component}' names no reason — refused (an unnamed unknown could be hiding anything)";
            }
            else return $"component '{c.Component}' carries unknown state '{c.State}' — refused";
        }

        var scored = s.Components.Where(c => c.State == ComponentScoreStates.Scored).ToList();
        var totalWeight = s.Components.Sum(c => c.Weight);
        if (totalWeight <= 0) return "score's recorded weights sum to zero — refused";
        var coverage = Math.Round(scored.Sum(c => c.Weight) / totalWeight, 4);
        if (Math.Abs(coverage - s.CoverageFraction) > 0.001)
            return $"coverage mismatch: score claims {s.CoverageFraction} but its decomposition covers {coverage} — refused";

        var expectedState = scored.Count == HealthComponents.All.Count
            ? HealthScoreStates.Complete : HealthScoreStates.Partial;
        if (s.State != expectedState)
            return $"state mismatch: score claims '{s.State}' but its decomposition is '{expectedState}' — refused (a partial score may not present as complete)";

        if (scored.Count == 0)
        {
            if (s.Aggregate is not null)
                return "score claims an aggregate with NO scored components — refused (nothing known is not a number)";
        }
        else
        {
            if (s.Aggregate is not { } agg)
                return "score has scored components but no aggregate — refused";
            var recomputed = Math.Round(scored.Sum(c => c.Value!.Value * c.Weight) / scored.Sum(c => c.Weight), 1);
            // Caps judged from recorded facts, exactly as the engine
            // applies them — FL-28a (F2/F3): on KNOWN facts,
            // regardless of the component's scored state.
            var exposure = s.Components.First(c => c.Component == HealthComponents.Exposure);
            var monitoring = s.Components.First(c => c.Component == HealthComponents.Monitoring);
            var caps = new List<string>();
            if (exposure.FactValue("open_critical") is not null &&
                exposure.FactValue("open_kev") is not null &&
                (FactInt(exposure, "open_critical") > 0 || FactInt(exposure, "open_kev") > 0))
            {
                recomputed = Math.Min(recomputed, HealthScoreCaps.CriticalExposureCap);
                caps.Add("exposure");
            }
            if (monitoring.FactValue("health_state") == DeviceHealthStates.Down)
            {
                recomputed = Math.Min(recomputed, HealthScoreCaps.DeviceDownCap);
                caps.Add("down");
            }
            // FL-28b / F12: tolerance tightened 0.11 → 0.05.
            // Values are recorded at 1dp, so honest recomputation
            // agrees to within one rounding step (0.05); the old
            // 0.11 let a forged aggregate drift a full step and a
            // half past its own decomposition and still validate.
            if (Math.Abs(recomputed - agg) > 0.05)
                return $"aggregate mismatch: score claims {agg} but its decomposition recomputes to {recomputed} — refused (the number does not follow from its own decomposition)";
            if (caps.Count > 0 && string.IsNullOrWhiteSpace(s.AggregateCapReason))
                return "score's facts trigger an anti-laundering cap but the score names no cap reason — refused (a capped score must say why)";
            if (caps.Count == 0 && !string.IsNullOrWhiteSpace(s.AggregateCapReason))
                return "score names an aggregate cap its facts do not trigger — refused";

            // FL-28a (F1): a missing cap fact is a REFUSAL, not a
            // zero. A component that is scored, or that carries any
            // facts at all, must carry the facts its cap is judged
            // from; only a fact-free unknown (source absent) has
            // nothing to judge.
            if ((exposure.State == ComponentScoreStates.Scored || exposure.Facts.Count > 0) &&
                (exposure.FactValue("open_critical") is null || exposure.FactValue("open_kev") is null))
                return "exposure component is missing its cap facts (open_critical/open_kev) — refused (a missing cap fact is not a zero)";
            if ((monitoring.State == ComponentScoreStates.Scored || monitoring.Facts.Count > 0) &&
                monitoring.FactValue("health_state") is null)
                return "monitoring component is missing its cap fact (health_state) — refused (a missing cap fact is not a down-free pass)";

            // FL-28a (F1): FACT-LEVEL re-pricing. The aggregate
            // check above only proves the number follows from the
            // recorded COMPONENT VALUES; this proves each scored
            // component's value follows from its recorded FACTS —
            // so inflating a component value (and the aggregate to
            // match) without changing the facts does not validate.
            foreach (var c in scored)
            {
                var repriced = RepriceFromFacts(c, s);
                if (repriced is null)
                    return $"component '{c.Component}' cannot be re-priced from its recorded facts — refused (a scored component must carry the facts its value was priced from)";
                if (Math.Abs(repriced.Value - c.Value!.Value) > 0.05)
                    return $"component value mismatch: '{c.Component}' records {c.Value} but its facts re-price to {repriced.Value} — refused (the value does not follow from its own facts)";
            }
        }
        return null;
    }

    private static int FactInt(ComponentScore c, string name) =>
        int.TryParse(c.FactValue(name), NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) ? v : 0;

    private static int? FactIntOrNull(ComponentScore c, string name) =>
        int.TryParse(c.FactValue(name), NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) ? v : null;

    private static bool? FactBoolOrNull(ComponentScore c, string name) =>
        bool.TryParse(c.FactValue(name), out var v) ? v : null;

    private static DateTimeOffset? FactTimeOrNever(ComponentScore c, string name, out bool present)
    {
        var raw = c.FactValue(name);
        present = raw is not null;
        if (raw is null || raw == "(never)" || raw == "(unrecorded)" || raw == "(unknown)") return null;
        return DateTimeOffset.TryParse(raw, CultureInfo.InvariantCulture, DateTimeStyles.None, out var v) ? v : null;
    }

    /// <summary>Recompute one scored component's value from its
    /// recorded facts ONLY, mirroring the engine's pricing rules.
    /// Null = the facts needed for pricing are absent or
    /// unparseable (the caller refuses).</summary>
    private static double? RepriceFromFacts(ComponentScore c, DeviceHealthScore s)
    {
        double ClampRound(double v) => Math.Round(Math.Clamp(v, 0, 100), 1);
        switch (c.Component)
        {
            case HealthComponents.Monitoring:
            {
                var state = c.FactValue("health_state");
                if (state is null) return null;
                if (state == DeviceHealthStates.Down) return 0;
                if (state == DeviceHealthStates.Degraded) return 40;
                if (state == DeviceHealthStates.Unknown) return null;
                if (FactIntOrNull(c, "active_alerts") is not { } active ||
                    FactIntOrNull(c, "critical_alerts") is not { } crit ||
                    FactIntOrNull(c, "warning_alerts") is not { } warn ||
                    FactIntOrNull(c, "info_alerts") is not { } info) return null;
                var unclassified = active - crit - warn - info;
                if (unclassified < 0) return null;
                var v = 100.0 - 40 * crit - 15 * warn - 5 * info - 10 * unclassified;
                if (active == 0)
                {
                    var firing = c.FactValue("firing_conditions");
                    if (firing is null) return null;
                    var n = string.IsNullOrWhiteSpace(firing) || firing == "(none)"
                        ? 0 : firing.Split(',').Length;
                    v -= 15 * n;
                }
                return ClampRound(v);
            }
            case HealthComponents.Exposure:
            {
                if (FactIntOrNull(c, "open_critical") is not { } crit ||
                    FactIntOrNull(c, "open_high") is not { } high ||
                    FactIntOrNull(c, "open_medium") is not { } med ||
                    FactIntOrNull(c, "open_low") is not { } low ||
                    FactIntOrNull(c, "open_kev") is not { } kev ||
                    FactIntOrNull(c, "open_overdue") is not { } overdue) return null;
                return ClampRound(100.0 - 35 * crit - 20 * high - 8 * med - 3 * low - 15 * kev - 10 * overdue);
            }
            case HealthComponents.Backup:
            {
                if (FactBoolOrNull(c, "catalogue_tampered") is not { } tampered) return null;
                if (tampered) return 0;
                var attempt = FactTimeOrNever(c, "last_attempt_utc", out var aPresent);
                var success = FactTimeOrNever(c, "last_success_utc", out var sPresent);
                if (!aPresent || !sPresent) return null;
                if (attempt is null && success is null) return 25;
                if (success is null) return 20;
                var v = 100.0;
                foreach (var f in c.Facts.Where(f => f.Name.StartsWith("finding:", StringComparison.Ordinal)))
                {
                    var severity = f.Value.Contains('|') ? f.Value.Split('|')[0] : AlertSeverities.Warning;
                    v -= severity == AlertSeverities.Critical ? 45 : 20;
                }
                if (FactIntOrNull(c, "consecutive_failures") is { } failures && failures >= 3)
                    v = Math.Min(v, 30);
                return ClampRound(v);
            }
            case HealthComponents.Posture:
            {
                if (FactBoolOrNull(c, "any_protected") is not { } anyProtected ||
                    FactBoolOrNull(c, "has_gap") is not { } hasGap) return null;
                double v;
                if (anyProtected && !hasGap) v = 100;
                else if (anyProtected) v = 70;
                else if (c.Facts.Any(f => f.Name.StartsWith("av:", StringComparison.Ordinal) &&
                        f.Value is AvPostureStates.Missing or AvPostureStates.Disabled)) v = 10;
                else v = 40;
                var iso = c.FactValue("isolation_state");
                if (iso == IsolationStates.Isolated) v = Math.Min(v, 20);
                else if (iso == IsolationStates.IsolationFailed) v = Math.Min(v, 30);
                return ClampRound(v);
            }
            case HealthComponents.Inventory:
            {
                var purchased = FactTimeOrNever(c, "purchase_date_utc", out var pPresent);
                if (!pPresent) return null;
                var v = 100.0;
                if (purchased is { } bought)
                {
                    var ageYears = (s.ComputedUtc - bought).TotalDays / 365.25;
                    if (ageYears > 7) v -= 40;
                    else if (ageYears > 5) v -= 25;
                    else if (ageYears > 3) v -= 10;
                }
                else v -= 10;
                var wStatus = c.FactValue("warranty_status");
                if (wStatus is null) return null;
                var expires = FactTimeOrNever(c, "warranty_expires_utc", out var ePresent);
                if (!ePresent) return null;
                // FL-28b / F10: mirror the engine — price from the
                // RECORDED status, never re-derive expiry locally.
                var warrantyAbsent = wStatus == "(unknown)" && expires is null;
                if (warrantyAbsent) v -= 10;
                else if (wStatus == WarrantyInfo.StatusExpired) v -= 30;
                else if (wStatus == WarrantyInfo.StatusUnknown) v -= 10;
                else if (expires is { } exp && exp < s.ComputedUtc.AddDays(90)) v -= 15;
                if (FactIntOrNull(c, "dropped_items") is not { } dropped) return null;
                if (dropped > 0) v -= 5;
                return ClampRound(v);
            }
            default:
                return null;
        }
    }
}

// ---- the snapshot store -----------------------------------------------------

/// <summary>Point-in-time health-score snapshots. Append-only per
/// device: there is deliberately NO update or recompute path — a
/// weights change produces NEW snapshots under the new version and
/// leaves history exactly as recorded. Admission runs the full
/// integrity check; import additionally verifies the content hash,
/// so a forged or edited snapshot JSON refuses by name.</summary>
public sealed class HealthScoreStore
{
    /// <summary>FL-28b / F12: retention bound — snapshots retained
    /// per device. The store was append-only without limit; a hub
    /// scoring a fleet hourly grew it forever. Past the cap the
    /// OLDEST snapshots for that device are dropped on admission
    /// (history is point-in-time snapshots; the newest record of
    /// every device is never dropped by retention).</summary>
    public const int MaxSnapshotsPerDevice = 512;

    // BD-SHARED-RMM-1 F8: snapshots are keyed per device. Add
    // previously scanned the FLEET-WIDE list for the duplicate
    // check and again for retention on every admission — O(fleet)
    // per snapshot on a hub scoring hourly.
    private readonly Dictionary<string, List<DeviceHealthScore>> _byDevice = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();
    private readonly byte[]? _signingKey;
    private readonly byte[]? _previousSigningKey;

    /// <summary>FL-28a (F1): when a signing key is supplied, the
    /// store signs snapshots it admits and REQUIRES the signature
    /// on import — the unkeyed public content hash alone no longer
    /// vouches for a foreign snapshot. Unkeyed stores keep the
    /// legacy hash+integrity import path (named, not silent).</summary>
    public HealthScoreStore(byte[]? signingKey = null, byte[]? previousSigningKey = null)
    {
        _signingKey = signingKey;
        _previousSigningKey = previousSigningKey;
    }

    /// <summary>Lane A (item 3): verification accepts the current
    /// key OR the retired previous key inside its verify window
    /// (the provisioning service enforces the window by only
    /// supplying an in-window previous key). Signing is current-only.</summary>
    private bool VerifyAny(DeviceHealthScore score) =>
        _signingKey is not null && HealthScoreSigning.Verify(score, _signingKey) ||
        _previousSigningKey is not null && HealthScoreSigning.Verify(score, _previousSigningKey);

    public bool IsKeyed => _signingKey is not null;

    public int Count { get { lock (_gate) return _byDevice.Values.Sum(l => l.Count); } }

    private IEnumerable<DeviceHealthScore> AllSnapshots() => _byDevice.Values.SelectMany(l => l);

    public (bool Ok, string Reason) Add(DeviceHealthScore? score)
    {
        if (HealthScoreIntegrity.Validate(score) is { } refusal)
            return (false, refusal);
        lock (_gate)
        {
            // FL-28a (F6): ANY snapshot for the same device at the
            // same timestamp is a duplicate — not only a
            // byte-identical one. Two different scores claiming the
            // same device-instant cannot both be history.
            if (!_byDevice.TryGetValue(score!.DeviceId, out var mine))
                _byDevice[score.DeviceId] = mine = new List<DeviceHealthScore>();
            if (mine.Any(x => x.ComputedUtc == score.ComputedUtc))
                return (false, $"a snapshot for '{score.DeviceId}' at {score.ComputedUtc:O} is already recorded — refused (duplicate device+timestamp)");
            var stored = score!;
            if (_signingKey is not null && !VerifyAny(stored))
                stored = stored with { Signature = HealthScoreSigning.Sign(stored, _signingKey) };
            mine.Add(stored);
            // FL-28b / F12: retention — drop this device's oldest
            // snapshots past the per-device cap (imported-key set
            // pruned alongside so it cannot grow unbounded either).
            if (mine.Count > MaxSnapshotsPerDevice)
            {
                foreach (var old in mine.OrderBy(x => x.ComputedUtc)
                             .Take(mine.Count - MaxSnapshotsPerDevice).ToList())
                {
                    mine.Remove(old);
                    _importedKeys.Remove(KeyOf(old));
                }
            }
            return (true, $"snapshot recorded for '{score.DeviceId}' at {score.ComputedUtc:O} under weights '{score.WeightsVersion}'");
        }
    }

    // FL-28a (F6): imported snapshots are SEGREGATED in Latest —
    // a computed snapshot always outranks an imported one, so a
    // (future-dated) import can never shadow this hub's own
    // scoring. Imported only surfaces when nothing computed
    // exists. Segregation is tracked store-side (the imported-key
    // set), NOT by editing the snapshot: an imported record stays
    // byte-verbatim, hash and signature intact.
    private readonly HashSet<string> _importedKeys = new(StringComparer.Ordinal);
    private static string KeyOf(DeviceHealthScore s) =>
        $"{s.DeviceId}|{s.ComputedUtc:O}|{s.ContentHash}";
    public bool IsImported(DeviceHealthScore s) { lock (_gate) return _importedKeys.Contains(KeyOf(s)); }

    private IOrderedEnumerable<DeviceHealthScore> LatestFirst(IEnumerable<DeviceHealthScore> xs) =>
        xs.OrderBy(s => _importedKeys.Contains(KeyOf(s)) ? 1 : 0)
          .ThenByDescending(s => s.ComputedUtc);

    public DeviceHealthScore? Latest(string deviceId)
    {
        lock (_gate)
            return _byDevice.TryGetValue(deviceId ?? "", out var mine)
                ? LatestFirst(mine).FirstOrDefault() : null;
    }

    /// <summary>One latest snapshot per device, device-id ordered —
    /// the fleet view's input. FL-28a (F5): an optional filter is
    /// applied BEFORE the per-device latest selection, so an
    /// out-of-scope (or otherwise excluded) snapshot can never
    /// shadow the snapshot that should represent its device.</summary>
    public IReadOnlyList<DeviceHealthScore> LatestAll(Func<DeviceHealthScore, bool>? filter = null)
    {
        lock (_gate)
            return AllSnapshots()
                .Where(s => filter is null || filter(s))
                .GroupBy(s => s.DeviceId, StringComparer.OrdinalIgnoreCase)
                .Select(g => LatestFirst(g).First())
                .OrderBy(s => s.DeviceId, StringComparer.OrdinalIgnoreCase).ToList();
    }

    public IReadOnlyList<DeviceHealthScore> History(string deviceId,
        DateTimeOffset? fromUtc = null, DateTimeOffset? toUtc = null)
    {
        lock (_gate)
            return _byDevice.TryGetValue(deviceId ?? "", out var mine)
                ? mine.Where(s => (fromUtc is null || s.ComputedUtc >= fromUtc) &&
                                  (toUtc is null || s.ComputedUtc <= toUtc))
                      .OrderBy(s => s.ComputedUtc).ToList()
                : new List<DeviceHealthScore>();
    }

    public string Export(DeviceHealthScore score)
    {
        // A keyed store exports SIGNED snapshots, so the receiving
        // hub can verify provenance under the shared hub key.
        if (_signingKey is not null && !VerifyAny(score))
            score = score with { Signature = HealthScoreSigning.Sign(score, _signingKey) };
        return JsonSerializer.Serialize(score, new JsonSerializerOptions { WriteIndented = true });
    }

    /// <summary>Parse + verify one snapshot JSON WITHOUT admitting
    /// it: content hash, keyed signature (when this store is
    /// keyed), and full fact-level integrity. The service layer
    /// runs its policy/scope/time gates over the verified score
    /// before calling <see cref="AddImported"/>.</summary>
    public (bool Ok, string Reason, DeviceHealthScore? Score) TryParseVerified(string? json)
    {
        DeviceHealthScore? score;
        string claimedHash;
        try
        {
            if (string.IsNullOrWhiteSpace(json)) return (false, "empty snapshot import — refused", null);
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("ContentHash", out var hashEl) &&
                !doc.RootElement.TryGetProperty("contentHash", out hashEl))
                return (false, "snapshot import carries no content hash — refused (an unhashed snapshot cannot be verified)", null);
            claimedHash = hashEl.GetString() ?? "";
            score = JsonSerializer.Deserialize<DeviceHealthScore>(json);
        }
        catch (Exception ex) { return (false, $"snapshot import does not parse: {ex.Message}", null); }
        if (score is null) return (false, "snapshot import produced no score — refused", null);
        if (!string.Equals(claimedHash, score.ContentHash, StringComparison.OrdinalIgnoreCase))
            return (false, "snapshot content hash does not match its decomposition — the snapshot was edited after scoring; refused", null);
        if (_signingKey is not null && !VerifyAny(score))
            return (false, "snapshot signature does not verify under this hub's signing key — refused (an unkeyed public hash is not provenance)", null);
        if (HealthScoreIntegrity.Validate(score) is { } refusal)
            return (false, refusal, null);
        return (true, "snapshot verified", score);
    }

    /// <summary>Admit a verified imported snapshot. The record is
    /// stored VERBATIM; its imported provenance is tracked in the
    /// store's imported-key set so Latest segregates it from this
    /// hub's own computed snapshots.
    /// BD-SHARED-RMM-1 F8: the future-date gate Import applies
    /// now applies HERE too (against <paramref name="now"/>, or
    /// the wall clock when not supplied) — AddImported was public
    /// and ungated, so any caller other than Import could admit
    /// a future-dated snapshot that Import itself would refuse.
    /// The scope gate applies whenever an expected scope is
    /// supplied. (The one production caller, HealthScoringService,
    /// runs its own policy/scope/time gates first; these are the
    /// store's own floor, not a substitute for them.)</summary>
    public (bool Ok, string Reason, DeviceHealthScore? Score) AddImported(
        DeviceHealthScore score, DateTimeOffset? now = null, string? expectedScopeId = null)
    {
        if (score is null) return (false, "no snapshot — refused", null);
        var n = now ?? DateTimeOffset.UtcNow;
        if (score.ComputedUtc > n.AddMinutes(5))
            return (false, $"snapshot ComputedUtc {score.ComputedUtc:O} is in the future (beyond the 5-minute skew allowance) — refused (a future-dated import would shadow real snapshots)", null);
        if (expectedScopeId is not null &&
            !string.Equals(expectedScopeId, score.ScopeId, StringComparison.OrdinalIgnoreCase))
            return (false, $"snapshot scope '{score.ScopeId}' does not match the expected scope '{expectedScopeId}' — refused", null);
        lock (_gate)
        {
            var (ok, reason) = Add(score);
            if (ok) _importedKeys.Add(KeyOf(score));
            return (ok, reason, ok ? score : null);
        }
    }

    // BD-SHARED-RMM-1 F8: store persistence WITH provenance. The
    // imported-key set previously lived only in memory — a hub
    // restart forgot which snapshots were imported, and on
    // re-export they passed as this hub's own computed scores.
    // The store now round-trips through the HubPersistence
    // envelope carrying the imported keys alongside the snapshots.
    private sealed record StoreDto(List<string> Snapshots, List<string> ImportedKeys);

    public string ExportStoreJson()
    {
        lock (_gate)
        {
            var dto = new StoreDto(
                AllSnapshots().OrderBy(s => s.DeviceId, StringComparer.OrdinalIgnoreCase)
                    .ThenBy(s => s.ComputedUtc).Select(Export).ToList(),
                _importedKeys.OrderBy(k => k, StringComparer.Ordinal).ToList());
            return HubPersistence.Wrap("health-score-store", JsonSerializer.Serialize(dto));
        }
    }

    /// <summary>Restore a store exported by ExportStoreJson.
    /// Every snapshot is re-verified (hash/signature/integrity)
    /// before admission; imported provenance is restored from the
    /// envelope, intersected with what actually verified.</summary>
    public (int Restored, int Refused) ImportStoreJson(string? envelopeJson, DateTimeOffset? now = null)
    {
        var payload = HubPersistence.Unwrap(envelopeJson, "health-score-store");
        if (payload is null) return (0, 0);
        StoreDto? dto;
        try { dto = JsonSerializer.Deserialize<StoreDto>(payload); } catch { return (0, 0); }
        if (dto is null) return (0, 0);
        var imported = new HashSet<string>(dto.ImportedKeys ?? new List<string>(), StringComparer.Ordinal);
        var restored = 0; var refused = 0;
        foreach (var json in dto.Snapshots ?? new List<string>())
        {
            var (ok, _, score) = TryParseVerified(json);
            if (!ok || score is null) { refused++; continue; }
            bool admitted;
            if (imported.Contains(KeyOf(score)))
                admitted = AddImported(score, now).Ok;
            else
                admitted = Add(score).Ok;
            if (admitted) restored++; else refused++;
        }
        return (restored, refused);
    }

    /// <summary>Import one snapshot JSON. Parse, integrity,
    /// signature and content-hash verification all run; any
    /// failure refuses by name and records nothing.
    /// FL-28a (F6) gates: when <paramref name="now"/> is supplied a
    /// future-dated ComputedUtc (beyond a 5-minute clock-skew
    /// allowance) refuses, and when
    /// <paramref name="expectedScopeId"/> is supplied a scope
    /// mismatch refuses.</summary>
    public (bool Ok, string Reason, DeviceHealthScore? Score) Import(
        string? json, DateTimeOffset? now = null, string? expectedScopeId = null)
    {
        var (ok, reason, score) = TryParseVerified(json);
        if (!ok) return (false, reason, null);
        if (now is { } n && score!.ComputedUtc > n.AddMinutes(5))
            return (false, $"snapshot ComputedUtc {score.ComputedUtc:O} is in the future (beyond the 5-minute skew allowance) — refused (a future-dated import would shadow real snapshots)", null);
        if (expectedScopeId is not null &&
            !string.Equals(expectedScopeId, score!.ScopeId, StringComparison.OrdinalIgnoreCase))
            return (false, $"snapshot scope '{score.ScopeId}' does not match the expected scope '{expectedScopeId}' — refused", null);
        // BD-SHARED-RMM-1 F8 repair: AddImported now enforces the
        // future-date gate itself, so Import must hand it the
        // SAME clock and scope it just validated against —
        // dropping them made AddImported fall back to wall-clock
        // and refuse imports the caller's timeline allows.
        return AddImported(score, now, expectedScopeId);
    }
}

// ---- fleet + trend report shapes (RMM-13 style) ------------------------------

/// <summary>The fleet health-score report: header with RMM-13
/// provenance inputs (each source's DataAsOf is the OLDEST input
/// timestamp across the fleet — one stale device cannot be
/// averaged into freshness), the aggregate distribution, and the
/// worst-first listing carrying each device's FULL decomposition.</summary>
public sealed record HealthFleetReport(
    ReportHeader Header,
    IReadOnlyList<string> WeightsVersions,
    IReadOnlyDictionary<string, long> Distribution,
    long PartialCount,
    long UnscoredCount,
    IReadOnlyList<DeviceHealthScore> WorstFirst);

public static class HealthFleetReportBuilder
{
    public static HealthFleetReport Build(IReadOnlyList<DeviceHealthScore> latest, string scopeId, DateTimeOffset now)
    {
        // FL-28a (F5): the report is FOR a scope — snapshots from
        // any other scope never enter its distribution, header
        // provenance, or worst-first listing.
        latest = (latest ?? Array.Empty<DeviceHealthScore>())
            .Where(s => string.Equals(s.ScopeId, scopeId, StringComparison.OrdinalIgnoreCase))
            .ToList();
        ReportInputProvenance Prov(string component, string source, TimeSpan bound)
        {
            var stamps = latest.Select(s => s.Component(component)?.InputTimestampUtc)
                .Where(t => t is not null).Select(t => t!.Value).ToList();
            return new ReportInputProvenance(source,
                stamps.Count == 0 ? null : stamps.Min(), bound, stamps.Count > 0);
        }
        var header = new ReportHeader(
            HubReport.NewReportId("health_score", now), "health_score", scopeId, now,
            new[]
            {
                Prov(HealthComponents.Monitoring, "rmm01.monitoring", ReportingStaleness.HealthReports),
                Prov(HealthComponents.Exposure, "rmm05.vulnerability_feed", ReportingStaleness.VulnerabilityFeed),
                Prov(HealthComponents.Backup, "rmm06.backup_health_facts", ReportingStaleness.BackupFacts),
                Prov(HealthComponents.Posture, "rmm17.endpoint_security", TimeSpan.FromHours(24)),
                Prov(HealthComponents.Inventory, "rmm04.inventory", ReportingStaleness.Inventory),
            });

        // FL-28b / F11: distribution buckets are split by COVERAGE.
        // Previously a PARTIAL score — computed over as little as
        // 10% of the weights — landed in the same bucket as a
        // complete one, so a fleet of barely-known 100s read as
        // "excellent". Full-coverage scores keep the plain bucket
        // names; partial scores land in "<bucket>_partial_coverage"
        // companions, so no bucket mixes the two kinds of claim.
        var distribution = new Dictionary<string, long>();
        void Bucket(string name, Func<DeviceHealthScore, bool> inBand)
        {
            distribution[name] = latest.Count(s => s.CoverageFraction >= 1.0 && inBand(s));
            distribution[name + "_partial_coverage"] = latest.Count(s => s.CoverageFraction < 1.0 && inBand(s));
        }
        Bucket("excellent_90_100", s => s.Aggregate is >= 90);
        Bucket("good_75_89", s => s.Aggregate is >= 75 and < 90);
        Bucket("fair_50_74", s => s.Aggregate is >= 50 and < 75);
        Bucket("poor_25_49", s => s.Aggregate is >= 25 and < 50);
        Bucket("critical_0_24", s => s.Aggregate is >= 0 and < 25);
        distribution["unscored_unknown"] = latest.Count(s => s.Aggregate is null);
        // Worst first: a device with NO trustworthy number leads
        // (it needs eyes first), then ascending aggregate; partial
        // scores sort by aggregate but are counted and labelled.
        var worstFirst = latest
            .OrderBy(s => s.Aggregate is null ? 0 : 1)
            .ThenBy(s => s.Aggregate ?? 0)
            .ThenBy(s => s.DeviceId, StringComparer.OrdinalIgnoreCase)
            .ToList();
        return new HealthFleetReport(
            header,
            latest.Select(s => s.WeightsVersion).Distinct(StringComparer.Ordinal)
                .OrderBy(v => v, StringComparer.Ordinal).ToList(),
            distribution,
            latest.Count(s => s.State == HealthScoreStates.Partial),
            latest.Count(s => s.Aggregate is null),
            worstFirst);
    }
}

/// <summary>One point in a device's score trend — a snapshot's own
/// recorded values, never recomputed.</summary>
public sealed record HealthTrendPoint(
    DateTimeOffset ComputedUtc, double? Aggregate, string State, string WeightsVersion,
    // FL-28a (F4): the weights RECORDED on the snapshot (from its
    // decomposition), so a trend run breaks on a content change
    // even when two snapshots carry the same version STRING.
    IReadOnlyDictionary<string, double>? Weights = null)
{
    internal string RunKey => WeightsVersion + "|" + (Weights is null
        ? ""
        : string.Join(";", Weights.OrderBy(kv => kv.Key, StringComparer.Ordinal)
            .Select(kv => $"{kv.Key}={kv.Value.ToString("0.################", CultureInfo.InvariantCulture)}")));
}

/// <summary>A device's score trend over its snapshots. The delta is
/// computed ONLY within the trailing run of snapshots sharing the
/// latest weights version: comparing numbers computed under
/// different weights as if they were one series is exactly the
/// quiet rewrite history must never perform — a version change is
/// named in the notes instead.</summary>
public sealed record DeviceHealthTrend(
    string DeviceId,
    IReadOnlyList<HealthTrendPoint> Points,
    double? SameVersionDelta,
    IReadOnlyList<string> Notes);

public static class HealthTrendBuilder
{
    public static DeviceHealthTrend Build(string deviceId, IReadOnlyList<DeviceHealthScore> history)
    {
        history ??= Array.Empty<DeviceHealthScore>();
        var points = history.OrderBy(s => s.ComputedUtc)
            .Select(s => new HealthTrendPoint(s.ComputedUtc, s.Aggregate, s.State, s.WeightsVersion,
                s.Components.ToDictionary(c => c.Component, c => c.Weight))).ToList();
        var notes = new List<string>();
        double? delta = null;
        if (points.Count > 0)
        {
            var versions = points.Select(p => p.WeightsVersion).Distinct(StringComparer.Ordinal).ToList();
            if (versions.Count > 1)
                notes.Add($"weights version changed across this series ({string.Join(" → ", versions)}) — the delta covers only the trailing '{points[^1].WeightsVersion}' run; earlier points are shown as recorded and are not recomputed");
            else if (points.Select(p => p.RunKey).Distinct(StringComparer.Ordinal).Count() > 1)
                notes.Add($"weights CONTENT changed across this series under the same version string '{points[^1].WeightsVersion}' — the delta covers only the trailing run of identical recorded weights; earlier points are shown as recorded and are not recomputed");
            var run = new List<HealthTrendPoint>();
            for (var i = points.Count - 1; i >= 0 && points[i].RunKey == points[^1].RunKey; i--)
                run.Add(points[i]);
            run.Reverse();
            var withNumbers = run.Where(p => p.Aggregate is not null).ToList();
            if (withNumbers.Count >= 2)
                delta = Math.Round(withNumbers[^1].Aggregate!.Value - withNumbers[0].Aggregate!.Value, 1);
            else if (run.Count >= 2)
                notes.Add("fewer than two scored snapshots in the current weights-version run — no delta is claimed");
        }
        return new DeviceHealthTrend(deviceId, points, delta, notes);
    }
}
