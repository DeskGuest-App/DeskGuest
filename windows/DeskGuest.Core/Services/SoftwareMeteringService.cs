using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.Inventory;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.Reporting;
using DeskGuest.Shared.SoftwareMetering;

namespace DeskGuest.Core.Services;

// =====================================================================
// RMM-26 — SoftwareMeteringService: the hub-side wiring for
// software metering + licence-compliance reporting.
//
// Consumes, through their public surfaces only:
//   * RMM-04: InventoryStore (the install truth — metering never
//     re-collects; it reads the hub's maintained records);
//   * RMM-13: ReportHeader/ReportInputProvenance shapes +
//     ReportExporter (via LicencePositionReport.ToHubReport) —
//     licence reports ride the reporting shapes, with provenance
//     and staleness computed by the builder, never asserted here;
//   * RMM-07: ManagementPolicyService — TOTAL POLICY CONTROL.
//     The registry toggle "rmm.metering.enabled" (seeded ON) gates
//     through the engine; the directive-named key
//     "rmm.software_metering.enabled" is consulted as policy
//     content and an explicit "false" on EITHER disables (fail
//     closed on conflict).
//
// Every entitlement act and every report generation/refusal is a
// hash-chained audit event: entitlements are admin-asserted claims,
// and the chain is what makes the assertion attributable.
//
// The stores are PRIVATE (RMM-26 F1): no caller reaches the
// entitlement store, the classifier, or the report store directly,
// so no act can bypass the policy gate or the audit chain. Every
// access — writes, imports, exports, and report reads — goes
// through a gated method on this service; exports and imports are
// audited with the acting admin named.
// =====================================================================
public sealed class SoftwareMeteringService
{
    private readonly ChainedAuditLog _audit;
    private readonly ManagementPolicyService _policies;
    private readonly InventoryStore _inventory;
    private readonly Func<DateTimeOffset> _now;

    private readonly EntitlementStore _entitlements = new();
    private readonly EditionClassifier _classifier = new();
    private readonly LicenceReportStore _reports = new();

    // W3 host wiring (BD-SHARED-RMM-3/F12 durability): the host
    // persists licence reports through these GATED seams -- the
    // store itself is never exposed (RMM-26 F1 invariant: no
    // public store surface on this service). Export/import are
    // the store's own HubPersistence envelope round-trip;
    // LicenceReportsChanged forwards the store's Changed so the
    // host can write through on every committed mutation.
    public event Action? LicenceReportsChanged
    {
        add => _reports.Changed += value;
        remove => _reports.Changed -= value;
    }

    /// <summary>Host write-through export of stored licence reports.</summary>
    public string ExportLicenceReportsJson() => _reports.ExportJson();

    /// <summary>Host restore of stored licence reports; returns
    /// how many were admitted (hash-verified by the store).</summary>
    public int ImportLicenceReportsJson(string json) => _reports.ImportJson(json);

    public SoftwareMeteringService(ChainedAuditLog audit, ManagementPolicyService policies,
        InventoryStore inventory, Func<DateTimeOffset>? now = null)
    {
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _policies = policies ?? throw new ArgumentNullException(nameof(policies));
        _inventory = inventory ?? throw new ArgumentNullException(nameof(inventory));
        _now = now ?? (() => DateTimeOffset.UtcNow);
    }

    // ---- policy ------------------------------------------------------

    /// <summary>TOTAL POLICY CONTROL for RMM-26: enabled only when
    /// the registry toggle resolves enabled AND the directive-named
    /// key is not explicitly set false in Effective Policy.</summary>
    public bool IsEnabled(IDeviceFacts facts)
    {
        if (!_policies.IsEnabled(facts, MeteringPolicyKeys.RegistryToggle)) return false;
        var named = _policies.ComputeEffective(facts).Get(MeteringPolicyKeys.SoftwareMeteringEnabled);
        if (named is not null)
        {
            if (bool.TryParse(named.Value, out var v)) return v;
            return false; // an unparsable toggle value never enables anything
        }
        return true;
    }

    private (bool Ok, string Reason) Gate(IDeviceFacts facts, string actor, string act)
    {
        if (IsEnabled(facts)) return (true, "enabled");
        var reason = $"software metering is disabled by policy for this scope ({MeteringPolicyKeys.SoftwareMeteringEnabled} / {MeteringPolicyKeys.RegistryToggle}) — {act} refuses (fail closed)";
        _audit.Append("metering_refused", actor, reason, _now());
        return (false, reason);
    }

    // ---- entitlement acts (admin-asserted claims, audited) ------------

    public (bool Ok, string Reason) AddEntitlement(IDeviceFacts facts, LicenceEntitlement? entitlement)
    {
        if (Gate(facts, entitlement?.EnteredBy ?? "(unknown)", "entitlement entry") is { Ok: false } g)
            return g;
        var (ok, reason) = _entitlements.Add(entitlement);
        _audit.Append(ok ? "entitlement_entered" : "entitlement_refused",
            entitlement?.EnteredBy ?? "(unknown)",
            $"id={entitlement?.Id} product={entitlement?.Product} edition={entitlement?.Edition ?? "(product-wide)"} seats={entitlement?.Seats} provenance={LicenceEntitlement.ProvenanceLabel} reason={reason}", _now());
        return (ok, reason);
    }

    public (bool Ok, string Reason) UpdateEntitlement(IDeviceFacts facts, LicenceEntitlement? next, long expectedRevision)
    {
        if (Gate(facts, next?.EnteredBy ?? "(unknown)", "entitlement update") is { Ok: false } g)
            return g;
        var (ok, reason) = _entitlements.Update(next, expectedRevision);
        _audit.Append(ok ? "entitlement_updated" : "entitlement_refused",
            next?.EnteredBy ?? "(unknown)",
            $"id={next?.Id} expectedRevision={expectedRevision} seats={next?.Seats} reason={reason}", _now());
        return (ok, reason);
    }

    public (bool Ok, string Reason) DeleteEntitlement(IDeviceFacts facts, string id, string deletedBy)
    {
        if (Gate(facts, deletedBy ?? "(unknown)", "entitlement deletion") is { Ok: false } g)
            return g;
        var (ok, reason) = _entitlements.Delete(id, deletedBy, _now());
        _audit.Append(ok ? "entitlement_deleted" : "entitlement_refused",
            deletedBy ?? "(unknown)", $"id={id} reason={reason}", _now());
        return (ok, reason);
    }

    public (bool Ok, string Reason) AddEditionRule(IDeviceFacts facts, EditionRule? rule, string actor)
    {
        if (Gate(facts, actor ?? "(unknown)", "edition rule entry") is { Ok: false } g)
            return g;
        var (ok, reason) = _classifier.AddRule(rule);
        _audit.Append(ok ? "edition_rule_added" : "edition_rule_refused",
            actor ?? "(unknown)", $"product={rule?.Product} edition={rule?.Edition} reason={reason}", _now());
        return (ok, reason);
    }

    // ---- report generation ----------------------------------------------

    /// <summary>Generate + store one licence position report for
    /// the facts' scope, over the hub's CURRENT inventory records
    /// and entitlement claims. The stored report is a snapshot:
    /// later entitlement edits never touch it. Findings optionally
    /// emit to a sink (the RMM-01 alert-centre seam).</summary>
    public (bool Ok, string Reason, LicencePositionReport? Report) GenerateReport(
        IDeviceFacts facts, IReadOnlyList<SoftwareUsageFact>? usageFacts = null,
        ILicenceFindingSink? sink = null)
    {
        var now = _now();
        if (Gate(facts, "software-metering", "report generation") is { Ok: false } g)
            return (false, g.Reason, null);
        var scope = facts.ScopeId;
        var report = LicencePositionBuilder.Build(
            _entitlements.Current(scope), _inventory.List(scope), _classifier,
            usageFacts, scope, now);
        var (stored, storeReason) = _reports.Store(report);
        if (!stored)
        {
            _audit.Append("licence_report_store_refused", "software-metering",
                $"report={report.Header.ReportId} scope={scope} reason={storeReason}", now);
            return (false, storeReason, null);
        }
        var emitted = sink is null ? 0 : LicencePositionBuilder.EmitFindings(report, sink, now);
        // The generation event records the report's content checksum
        // VALUE and the usage sources relied on (RMM-26 F3/F8): the
        // checksum is unkeyed, so this hash-chained record is its
        // trust anchor, and the sources a position rested on are
        // attributable, not anonymous.
        var usageSources = usageFacts is null
            ? "(none)"
            : string.Join(",", usageFacts.Where(f => f is not null)
                .Select(f => f.Source.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(s => s, StringComparer.Ordinal));
        _audit.Append("licence_report_generated", "software-metering",
            $"report={report.Header.ReportId} scope={scope} lines={report.Lines.Count} findings={report.Findings.Count} staleDevices={report.StaleDeviceCount} findingsEmitted={emitted} hash={report.ContentHash} usageSources={usageSources}", now);
        return (true, $"licence position report '{report.Header.ReportId}' generated for scope '{scope}' (snapshot; entitlement values are {LicenceEntitlement.ProvenanceLabel})", report);
    }

    // ---- gated store surface (RMM-26 F1/F4) ---------------------------

    // BD-WIN-CORE-4/F9: a read's scope is BOUND to the caller's
    // facts. A caller-supplied scopeId that differs from
    // facts.ScopeId refuses (empty) — the old shape gated on the
    // caller's facts but read ANOTHER scope's data. Hub scope ""
    // is the fleet-wide caller and may name a scope explicitly.
    private bool ScopeAllowed(IDeviceFacts facts, string? requestedScope) =>
        string.IsNullOrEmpty(facts.ScopeId) ||
        requestedScope is null ||
        string.Equals(requestedScope, facts.ScopeId, StringComparison.OrdinalIgnoreCase);

    private bool ReportScopeAllowed(IDeviceFacts facts, LicencePositionReport report) =>
        string.IsNullOrEmpty(facts.ScopeId) ||
        string.Equals(report.Header.ScopeId, facts.ScopeId, StringComparison.OrdinalIgnoreCase);

    /// <summary>Live entitlement claims for a scope, through the
    /// gate. (Reads are gated; acts and exports are also audited.)</summary>
    public IReadOnlyList<LicenceEntitlement> CurrentEntitlements(IDeviceFacts facts, string? scopeId = null)
    {
        if (Gate(facts, "software-metering", "entitlement read") is { Ok: false })
            return Array.Empty<LicenceEntitlement>();
        if (!ScopeAllowed(facts, scopeId))
            return Array.Empty<LicenceEntitlement>();
        return _entitlements.Current(scopeId ?? facts.ScopeId);
    }

    /// <summary>Full entitlement history for an id (tombstones
    /// included), through the gate — the audit surface.</summary>
    public IReadOnlyList<LicenceEntitlement> EntitlementHistory(IDeviceFacts facts, string id)
    {
        if (Gate(facts, "software-metering", "entitlement history read") is { Ok: false })
            return Array.Empty<LicenceEntitlement>();
        return _entitlements.History(id);
    }

    /// <summary>Export the FULL entitlement history (tombstones
    /// included) as JSON. Gated AND audited with the acting admin
    /// named: an export is a read of every claim ever entered, and
    /// it never leaves this service unattributed.</summary>
    public (bool Ok, string Reason, string? Json) ExportEntitlements(IDeviceFacts facts, string actor)
    {
        if (Gate(facts, actor ?? "(unknown)", "entitlement export") is { Ok: false } g)
            return (false, g.Reason, null);
        var json = _entitlements.ExportJson();
        _audit.Append("entitlements_exported", actor ?? "(unknown)",
            $"revisions={_entitlements.FullHistory.Count} (full history, tombstones included)", _now());
        return (true, "entitlement history exported (full history, tombstones included)", json);
    }

    /// <summary>Restore an entitlement export into the (empty)
    /// store. Gated AND audited; the store refuses broken revision
    /// chains whole per id and reports restored/skipped counts —
    /// the audit event carries both, so a partial restore is never
    /// silent (RMM-26 F4).</summary>
    public (bool Ok, string Reason, EntitlementImportResult? Result) ImportEntitlements(
        IDeviceFacts facts, string? json, string actor)
    {
        if (Gate(facts, actor ?? "(unknown)", "entitlement import") is { Ok: false } g)
            return (false, g.Reason, null);
        if (json is null)
        {
            const string reason = "entitlement import needs a payload — refused";
            _audit.Append("entitlements_import_refused", actor ?? "(unknown)", reason, _now());
            return (false, reason, null);
        }
        var result = _entitlements.ImportJson(json);
        _audit.Append(result.Restored > 0 || result.Skipped == 0 ? "entitlements_imported" : "entitlements_import_refused",
            actor ?? "(unknown)",
            $"restored={result.Restored} skipped={result.Skipped} reason={result.Reason}", _now());
        return (result.Restored > 0 || result.Skipped == 0, result.Reason, result);
    }

    /// <summary>Read one stored report, through the gate.</summary>
    public LicencePositionReport? GetStoredReport(IDeviceFacts facts, string reportId)
    {
        if (Gate(facts, "software-metering", "stored report read") is { Ok: false })
            return null;
        var report = _reports.Get(reportId);
        // BD-WIN-CORE-4/F9: a bare report id is not a scope
        // credential — a report from another scope reads as absent.
        return report is not null && ReportScopeAllowed(facts, report) ? report : null;
    }

    /// <summary>List stored reports (optionally per scope), through
    /// the gate.</summary>
    public IReadOnlyList<LicencePositionReport> ListStoredReports(IDeviceFacts facts, string? scopeId = null)
    {
        if (Gate(facts, "software-metering", "stored report list") is { Ok: false })
            return Array.Empty<LicencePositionReport>();
        if (!ScopeAllowed(facts, scopeId))
            return Array.Empty<LicencePositionReport>();
        return _reports.List(scopeId ?? facts.ScopeId);
    }

    /// <summary>Export a stored report through the RMM-13 exporter
    /// (json/csv/text — every format carries the computed header).
    /// Gated AND audited (RMM-26 F1): an export names its actor in
    /// the chain, and an unknown report id is a ledgered refusal,
    /// not a silent null.</summary>
    public string? ExportStored(IDeviceFacts facts, string reportId, string format, string actor)
    {
        if (Gate(facts, actor ?? "(unknown)", "report export") is { Ok: false })
            return null;
        var report = _reports.Get(reportId);
        if (report is null || !ReportScopeAllowed(facts, report))
        {
            _audit.Append("licence_report_export_refused", actor ?? "(unknown)",
                $"report={reportId} format={format} reason=no stored report with that id in the caller's scope", _now());
            return null;
        }
        var exported = ReportExporter.Export(report.ToHubReport(), format, _now());
        _audit.Append("licence_report_exported", actor ?? "(unknown)",
            $"report={reportId} format={format} hash={report.ContentHash}", _now());
        return exported;
    }
}
