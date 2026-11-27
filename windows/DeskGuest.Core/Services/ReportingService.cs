using System.Text.Json;
using DeskGuest.Shared.Backup;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.Inventory;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.Monitoring;
using DeskGuest.Shared.Patching;
using DeskGuest.Shared.Reporting;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.WorkItems;

namespace DeskGuest.Core.Services;

// =====================================================================
// RMM-13 — ReportingService: the hub-side wiring for local
// reporting + hub API/webhooks.
//
// Consumes, through their public surfaces only:
//   * RMM-01: HubHealthIngest views (fleet health);
//   * RMM-02: PatchService.Catalogue + PatchScanner (patch posture);
//   * RMM-04: InventoryStore (inventory/lifecycle + denominators);
//   * RMM-05: VulnerabilityService.BuildReport (posture + feed
//     provenance, carried through untouched);
//   * RMM-06: IBackupHealthFactsProvider (BackupEngine) facts;
//   * the enterprise ChainedAuditLog: report generations, API key
//     issuance/revocation, EVERY API call, webhook configuration,
//     raises and delivery transitions, scheduled definitions and
//     deliveries, fleet-MCP calls, and local-model runs are chained
//     events — IT's upward voice is itself audited;
//   * RMM-07: ManagementPolicyService — rmm.reporting.enabled gates
//     the whole surface (TOTAL POLICY CONTROL); the api / webhooks /
//     scheduled / fleet_mcp / local_model sub-toggles are policy
//     content read through Effective Policy.
//
// Everything is computed locally from hub data. The only outbound
// paths are the guarded webhook pump and scheduled delivery, both
// through injected transports/sinks — no live client is created
// here, and no real model is integrated (ILocalModel seam + fake).
// =====================================================================
public sealed class ReportingService : IHubApiData
{
    // D38-F9: the fleet MCP host is handed THIS private adapter —
    // never the service itself. The adapter's only verbs are the
    // six report builds; there is no reference a query handler
    // could downcast to reach IssueApiKey / RaiseEvent /
    // ConfigureWebhook or any other mutating surface.
    private sealed class FleetReadModelAdapter : IFleetReadModel
    {
        private readonly ReportingService _svc;
        public FleetReadModelAdapter(ReportingService svc) => _svc = svc;
        public HubReport FleetHealth(DateTimeOffset now) => _svc.Build(ReportKinds.FleetHealth, "", now);
        public HubReport PatchCompliance(DateTimeOffset now) => _svc.Build(ReportKinds.PatchCompliance, "", now);
        public HubReport InventoryLifecycle(DateTimeOffset now) => _svc.Build(ReportKinds.InventoryLifecycle, "", now);
        public HubReport BackupStatus(DateTimeOffset now) => _svc.Build(ReportKinds.BackupStatus, "", now);
        public HubReport AuditSummary(DateTimeOffset now) => _svc.Build(ReportKinds.AuditSummary, "", now);
        public HubReport VulnerabilityPosture(DateTimeOffset now) => _svc.Build(ReportKinds.VulnerabilityPosture, "", now);
    }

    // D38-F9: backup-facts failures observed during a READ are
    // queued here, not appended to the chained ledger by the read
    // itself; the gated entry points (Generate / DispatchApi /
    // CallFleetTool / RunScheduled) flush the queue into the
    // chain. A bare FleetMcp.Call therefore writes nothing.
    private readonly List<(string DeviceId, string Error)> _pendingInputFailures = new();
    private readonly object _pendingGate = new();

    private void QueueInputFailure(string deviceId, string error)
    {
        lock (_pendingGate) _pendingInputFailures.Add((deviceId, error));
    }

    private void FlushPendingInputFailures(DateTimeOffset now)
    {
        List<(string DeviceId, string Error)> pending;
        lock (_pendingGate)
        {
            if (_pendingInputFailures.Count == 0) return;
            pending = _pendingInputFailures.ToList();
            _pendingInputFailures.Clear();
        }
        foreach (var (deviceId, error) in pending)
            _audit.Append("report_input_failed", "reporting-service",
                $"source=rmm06.backup_health_facts device={deviceId} error={error}", now);
    }

    // D38-F11: unauthenticated api_call audit coalescing — the
    // first unauthenticated call in a 60-second window is chained;
    // the rest are counted and the count is folded into the next
    // chained unauthenticated record, so an unauthenticated flood
    // cannot grow the chained ledger without bound.
    private DateTimeOffset? _lastUnauthAuditUtc;
    private long _suppressedUnauthAudits;

    // D38-F8: per-device policy visibility. A device is visible in
    // a build when (a) its own inventory scope has NOT disabled
    // reporting, and (b) when the build is for a specific scope,
    // the device's scope matches it. A device with NO inventory
    // record has no scope to disable and stays visible — named
    // residual: fleet-health views carry no scope in RMM-01's
    // shape, so an uninventoried device cannot be scope-bound.
    private bool ScopeReportingEnabled(string scopeId, Dictionary<string, bool> cache)
    {
        if (!cache.TryGetValue(scopeId, out var enabled))
        {
            enabled = _policies.IsEnabled(HubFacts(scopeId), ReportingPolicyKeys.ReportingEnabled);
            cache[scopeId] = enabled;
        }
        return enabled;
    }

    private bool DeviceVisible(string deviceId, string buildScope, Dictionary<string, bool> cache)
    {
        var record = _inventory.Get(deviceId);
        if (record is null) return true;
        if (!ScopeReportingEnabled(record.ScopeId ?? "", cache)) return false;
        return buildScope == "" || string.Equals(record.ScopeId, buildScope, StringComparison.OrdinalIgnoreCase);
    }

    private List<DeviceInventoryRecord> VisibleRecords(string buildScope, Dictionary<string, bool> cache) =>
        _inventory.List(buildScope == "" ? null : buildScope)
            .Where(r => ScopeReportingEnabled(r.ScopeId ?? "", cache)).ToList();

    /// <summary>D38-F11: sanitise a caller-supplied path for the
    /// audit detail string — any character outside the safe set
    /// becomes '_', and the result is length-capped, so a crafted
    /// path like '/api/v1/x status=200 detail=ok' cannot forge
    /// key=value fields in the chained record.</summary>
    internal static string SanitizePathForAudit(string? path)
    {
        var raw = path ?? "";
        var chars = raw.Select(c => char.IsLetterOrDigit(c) || c is '/' or '.' or '_' or '-' or '?' or '=' or '&' or '%' ? c : '_').ToArray();
        var s = new string(chars);
        return s.Length <= 128 ? s : s[..128];
    }

    private readonly ChainedAuditLog _audit;
    private readonly ManagementPolicyService _policies;
    private readonly InventoryStore _inventory;
    private readonly HubHealthIngest? _health;
    private readonly PatchService? _patches;
    private readonly IBackupHealthFactsProvider? _backupFacts;
    private readonly VulnerabilityService? _vuln;
    private readonly IWebhookTransport? _webhookTransport;
    private readonly IReportDeliverySink? _reportSink;
    private readonly Func<DateTimeOffset> _now;

    public HubApiKeyStore ApiKeys { get; } = new();
    public HubWebhookHub Webhooks { get; }
    public ScheduledReportRunner Scheduler { get; } = new();
    public FleetApprovalBook FleetApprovals { get; } = new();
    public FleetMcpHost FleetMcp { get; }
    public LocalModelRunner LocalModel { get; }
    public HubApiDispatcher Api { get; }

    public ReportingService(ChainedAuditLog audit, ManagementPolicyService policies,
        InventoryStore inventory, DeviceIdentity signingKey,
        HubHealthIngest? health = null, PatchService? patches = null,
        IBackupHealthFactsProvider? backupFacts = null, VulnerabilityService? vuln = null,
        IWebhookTransport? webhookTransport = null, IReportDeliverySink? reportSink = null,
        ILocalModel? localModel = null, IFleetActionExecutor? fleetActions = null,
        Func<DateTimeOffset>? now = null)
    {
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _policies = policies ?? throw new ArgumentNullException(nameof(policies));
        _inventory = inventory ?? throw new ArgumentNullException(nameof(inventory));
        ArgumentNullException.ThrowIfNull(signingKey);
        _health = health;
        _patches = patches;
        _backupFacts = backupFacts;
        _vuln = vuln;
        _webhookTransport = webhookTransport;
        _reportSink = reportSink;
        _now = now ?? (() => DateTimeOffset.UtcNow);
        Webhooks = new HubWebhookHub(signingKey);
        LocalModel = new LocalModelRunner(localModel, signingKey);
        FleetMcp = new FleetMcpHost(new FleetReadModelAdapter(this), FleetApprovals, fleetActions);
        FleetMcp.RegisterStandardQueries();
        Api = new HubApiDispatcher(ApiKeys, this);
    }

    // ---- policy ------------------------------------------------------

    public bool IsEnabled(IDeviceFacts facts) =>
        _policies.IsEnabled(facts, ReportingPolicyKeys.ReportingEnabled);

    private bool PolicyContentBool(IDeviceFacts facts, string key, bool defaultValue)
    {
        var s = _policies.ComputeEffective(facts).Get(key);
        return s is not null && bool.TryParse(s.Value, out var v) ? v : defaultValue;
    }

    public bool ApiEnabledFor(IDeviceFacts facts) =>
        IsEnabled(facts) && PolicyContentBool(facts, ReportingPolicyKeys.ApiEnabled, true);
    public bool WebhooksEnabledFor(IDeviceFacts facts) =>
        IsEnabled(facts) && PolicyContentBool(facts, ReportingPolicyKeys.WebhooksEnabled, false);
    public bool ScheduledEnabledFor(IDeviceFacts facts) =>
        IsEnabled(facts) && PolicyContentBool(facts, ReportingPolicyKeys.ScheduledEnabled, true);
    public bool FleetMcpEnabledFor(IDeviceFacts facts) =>
        IsEnabled(facts) && PolicyContentBool(facts, ReportingPolicyKeys.FleetMcpEnabled, true);
    public bool LocalModelEnabledFor(IDeviceFacts facts) =>
        IsEnabled(facts) && PolicyContentBool(facts, ReportingPolicyKeys.LocalModelEnabled, false);

    private static IDeviceFacts HubFacts(string scopeId) => StaticDeviceFacts.Of("hub", scopeId ?? "");

    // ---- report building (ungated core; public entry points gate) -----

    private HubReport Build(string kind, string scopeId, DateTimeOffset now)
    {
        // One per-scope policy cache per build (D38-F8).
        var cache = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        return kind switch
        {
            ReportKinds.FleetHealth => ReportBuilders.FleetHealth(
                (_health?.Views(now) ?? Array.Empty<DeviceHealthView>())
                    .Where(v => DeviceVisible(v.DeviceId, scopeId, cache)).ToList(), scopeId, now),
            ReportKinds.PatchCompliance => ReportBuilders.PatchCompliance(PatchPosture(scopeId, cache), scopeId, now),
            ReportKinds.InventoryLifecycle => ReportBuilders.InventoryLifecycle(
                VisibleRecords(scopeId, cache), scopeId, now),
            ReportKinds.BackupStatus => ReportBuilders.BackupStatus(BackupFacts(scopeId, now, cache),
                VisibleRecords(scopeId, cache).Select(r => r.DeviceId).ToList(), scopeId, now),
            ReportKinds.AuditSummary => ReportBuilders.AuditSummary(_audit, scopeId, now),
            ReportKinds.VulnerabilityPosture => ReportBuilders.VulnerabilityPosture(VulnInput(scopeId), scopeId, now),
            _ => throw new ArgumentException($"unknown report kind '{kind}'", nameof(kind)),
        };
    }

    private IReadOnlyList<ReportBuilders.PatchPostureRow> PatchPosture(string scopeId,
        Dictionary<string, bool>? cache = null)
    {
        cache ??= new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        var rows = new List<ReportBuilders.PatchPostureRow>();
        if (_patches is null) return rows;
        foreach (var record in VisibleRecords(scopeId, cache))
        {
            var missing = PatchScanner.DetermineMissing(record, _patches.Catalogue);
            rows.Add(new ReportBuilders.PatchPostureRow(record.DeviceId, record.Hostname,
                missing.Count,
                missing.Count(m => string.Equals(m.Severity, "critical", StringComparison.OrdinalIgnoreCase)),
                missing.Count(m => string.Equals(m.Severity, "high", StringComparison.OrdinalIgnoreCase)),
                record.LastSeenUtc));
        }
        return rows;
    }

    private IReadOnlyList<BackupHealthFacts> BackupFacts(string scopeId, DateTimeOffset now,
        Dictionary<string, bool>? cache = null)
    {
        cache ??= new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        if (_backupFacts is null) return Array.Empty<BackupHealthFacts>();
        var facts = new List<BackupHealthFacts>();
        foreach (var record in VisibleRecords(scopeId, cache))
        {
            try { facts.Add(_backupFacts.GetFacts(record.DeviceId, now)); }
            catch (Exception ex)
            {
                // One device's facts provider failing must not kill
                // the whole report — and must not be silent either:
                // the device is omitted here so the builder renders
                // its explicit no-facts row, and the failure is
                // QUEUED for the gated entry points to chain
                // (D38-F9: a read must not itself write the ledger;
                // destruction-pass find: a throwing provider
                // previously crashed the backup report).
                QueueInputFailure(record.DeviceId, $"{ex.GetType().Name}: {ex.Message}");
            }
        }
        return facts;
    }

    private ReportBuilders.VulnPostureInput VulnInput(string scopeId)
    {
        if (_vuln is null)
            return new ReportBuilders.VulnPostureInput(0, 0, 0, 0, 0, 0,
                DeskGuest.Shared.Vulnerability.FeedProvenance.None(_now()));
        // BD-WIN-CORE-4/F4: (1) the READ-ONLY build — this path is
        // reached by bare fleet-MCP/report reads, which must write
        // nothing (no audit appends, no expiration reopenings);
        // (2) PolicyEnabled/RefusalReason are carried through, so
        // a policy-off posture renders "not evaluated", not zeros.
        var report = _vuln.BuildReportReadOnly(HubFacts(scopeId));
        return new ReportBuilders.VulnPostureInput(
            report.OpenCount, report.CompensatedCount, report.RemediationRequestedCount,
            report.ClosedCount, report.KevOpenCount, report.Overdue.Count, report.Provenance,
            report.PolicyEnabled, report.RefusalReason);
    }

    /// <summary>Generate one report on demand. Refuses (named) when
    /// reporting is policy-disabled or the kind is unknown; every
    /// generation — and every refusal — is a chained audit event,
    /// and the generation raises the report.generated webhook event
    /// when webhooks are enabled for the scope.</summary>
    public (bool Ok, string Reason, HubReport? Report) Generate(IDeviceFacts facts, string kind)
    {
        var now = _now();
        if (!IsEnabled(facts))
        {
            const string reason = "reporting is disabled by policy for this scope (rmm.reporting.enabled) — generation refuses (fail closed)";
            _audit.Append("report_refused", "reporting-service", reason, now);
            return (false, reason, null);
        }
        if (!ReportKinds.All.Contains(kind ?? ""))
        {
            var reason = $"unknown report kind '{kind}' — refused";
            _audit.Append("report_refused", "reporting-service", reason, now);
            return (false, reason, null);
        }
        var report = Build(kind, facts.ScopeId, now);
        FlushPendingInputFailures(now);
        _audit.Append("report_generated", "reporting-service",
            $"report={report.Header.ReportId} kind={kind} scope={facts.ScopeId} stale={report.Header.HasStaleInputs(now)}", now);
        if (WebhooksEnabledFor(facts))
            RaiseEvent(facts, HubEventKinds.ReportGenerated,
                JsonSerializer.Serialize(new { reportId = report.Header.ReportId, kind, scopeId = facts.ScopeId, staleInputs = report.Header.HasStaleInputs(now) }));
        return (true, $"report '{report.Header.ReportId}' generated ({kind})", report);
    }

    // ---- IHubApiData (dispatcher surface; scope = the key's) -------

    // D38-F8: every API read is built for the scope the caller's
    // KEY was issued under — never hub-global data gated only by
    // the dispatch caller's facts. (audit_summary is hub-global by
    // nature: the chained ledger has no scope dimension — named
    // residual, not a silent claim.)
    public string? ReportExport(string kind, string format, string scopeId, DateTimeOffset now)
    {
        if (!ReportKinds.All.Contains(kind ?? "")) return null;
        var report = Build(kind, scopeId ?? "", now);
        return ReportExporter.Export(report, format, now);
    }

    public string FleetHealthJson(string scopeId, DateTimeOffset now) =>
        ReportExporter.ToJson(Build(ReportKinds.FleetHealth, scopeId ?? "", now), now);

    public string FleetDevicesJson(string scopeId, DateTimeOffset now)
    {
        var cache = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        var records = VisibleRecords(scopeId ?? "", cache);
        return JsonSerializer.Serialize(new
        {
            generatedUtc = now,
            devices = records.Select(r => new
            {
                deviceId = r.DeviceId, scopeId = r.ScopeId, hostname = r.Hostname,
                os = r.Hardware?.OsName, model = r.Hardware?.Model,
                softwareCount = r.Software.Count, lastSeenUtc = r.LastSeenUtc, revision = r.Revision,
            }).ToArray(),
        });
    }

    public string AuditSummaryJson(string scopeId, DateTimeOffset now) =>
        ReportExporter.ToJson(Build(ReportKinds.AuditSummary, scopeId ?? "", now), now);

    // ---- API keys + dispatch -------------------------------------------

    /// <summary>Issue an API key (hub-admin act, performed here —
    /// never through the API itself). The plaintext secret is
    /// returned ONCE, in this result; the store keeps only its
    /// hash. Issuance is a chained audit event (without the
    /// secret).</summary>
    public (bool Ok, string Reason, string? Secret) IssueApiKey(IDeviceFacts facts, string issuedBy, IReadOnlySet<string> scopes, DateTimeOffset? expiresUtc = null)
    {
        var now = _now();
        if (!ApiEnabledFor(facts))
        {
            const string refusal = "the hub API is disabled by policy for this scope (rmm.reporting.enabled / rmm.reporting.api.enabled) — key issuance refuses";
            _audit.Append("api_key_refused", issuedBy ?? "(unknown)", refusal, now);
            return (false, refusal, null);
        }
        var secret = HubApiKeyStore.NewSecret();
        // D38-F8: the key is bound to the scope it is issued under.
        var (ok, reason, _) = ApiKeys.Issue(HubApiKeyStore.NewKeyId(), secret, scopes, issuedBy ?? "", now, expiresUtc, facts.ScopeId);
        _audit.Append(ok ? "api_key_issued" : "api_key_refused", issuedBy ?? "(unknown)",
            $"scopes=[{string.Join(",", scopes ?? new HashSet<string>())}] reason={reason}", now);
        return (ok, reason, ok ? secret : null);
    }

    public (bool Ok, string Reason) RevokeApiKey(string keyId, string revokedBy)
    {
        var now = _now();
        var (ok, reason) = ApiKeys.Revoke(keyId, now);
        _audit.Append(ok ? "api_key_revoked" : "api_key_refused", revokedBy ?? "(unknown)", $"key={keyId} reason={reason}", now);
        return (ok, reason);
    }

    /// <summary>Dispatch one API call. The per-call audit record is
    /// appended BEFORE the response returns (the McpHandler rule);
    /// a policy-disabled API refuses every call, audited.</summary>
    public ApiResponse DispatchApi(IDeviceFacts facts, string? method, string? path, string? presentedSecret)
    {
        var now = _now();
        FlushPendingInputFailures(now);
        if (!ApiEnabledFor(facts))
        {
            var record = new ApiCallRecord("(unauthenticated)", (method ?? "").ToUpperInvariant(), path ?? "", "(none)", 403,
                "the hub API is disabled by policy for this scope", now);
            _audit.Append("api_call", "(unauthenticated)", $"method={record.Method} path={SanitizePathForAudit(record.Path)} status=403 detail={record.Detail}", now);
            return new ApiResponse(403, "{\"error\":\"the hub API is disabled by policy for this scope\"}", record);
        }
        var response = Api.Dispatch(method, path, presentedSecret, now);
        var r = response.Record;
        if (r.KeyId == "(unauthenticated)")
        {
            // D38-F11 coalescing: chain the first unauthenticated
            // call per 60s window; count the rest and fold the
            // count into the next chained record.
            if (_lastUnauthAuditUtc is { } last && now - last < TimeSpan.FromSeconds(60))
            {
                _suppressedUnauthAudits++;
                return response;
            }
            var suppressed = _suppressedUnauthAudits;
            _suppressedUnauthAudits = 0;
            _lastUnauthAuditUtc = now;
            _audit.Append("api_call", r.KeyId,
                $"method={r.Method} path={SanitizePathForAudit(r.Path)} endpoint={r.EndpointId} status={r.Status} detail={r.Detail}" +
                (suppressed > 0 ? $" suppressedUnauthenticated={suppressed}" : ""), now);
            return response;
        }
        _audit.Append("api_call", r.KeyId, $"method={r.Method} path={SanitizePathForAudit(r.Path)} endpoint={r.EndpointId} status={r.Status} detail={r.Detail}", now);
        return response;
    }

    // ---- webhooks --------------------------------------------------------

    public (bool Ok, string Reason) ConfigureWebhook(IDeviceFacts facts, WebhookEndpoint? endpoint)
    {
        var now = _now();
        if (!WebhooksEnabledFor(facts))
        {
            const string refusal = "outbound webhooks are disabled by policy for this scope (rmm.reporting.webhooks.enabled, default OFF) — configuration refuses";
            _audit.Append("webhook_config_refused", endpoint?.ConfiguredBy ?? "(unknown)", refusal, now);
            return (false, refusal);
        }
        var (ok, reason) = Webhooks.Configure(endpoint);
        _audit.Append(ok ? "webhook_configured" : "webhook_config_refused", endpoint?.ConfiguredBy ?? "(unknown)",
            $"endpoint={endpoint?.Id} url={endpoint?.Url} reason={reason}", now);
        return (ok, reason);
    }

    /// <summary>Raise a hub event into the webhook hub. When
    /// webhooks are policy-disabled for the scope, the raise is
    /// refused and audited — events never leak out under a disabled
    /// toggle.</summary>
    public (bool Ok, string Reason, IReadOnlyList<WebhookDelivery> Deliveries) RaiseEvent(IDeviceFacts facts, string eventKind, string bodyJson)
    {
        var now = _now();
        if (!WebhooksEnabledFor(facts))
        {
            const string refusal = "outbound webhooks are disabled by policy for this scope (rmm.reporting.webhooks.enabled) — event not emitted";
            _audit.Append("webhook_raise_refused", "reporting-service", $"kind={eventKind} reason={refusal}", now);
            return (false, refusal, Array.Empty<WebhookDelivery>());
        }
        if (!HubEventKinds.All.Contains(eventKind ?? ""))
        {
            var reason = $"unknown hub event kind '{eventKind}' — refused";
            _audit.Append("webhook_raise_refused", "reporting-service", reason, now);
            return (false, reason, Array.Empty<WebhookDelivery>());
        }
        var deliveries = Webhooks.Raise(eventKind, bodyJson, now);
        _audit.Append("webhook_raised", "reporting-service",
            $"kind={eventKind} deliveries={deliveries.Count} (0 = no enabled endpoint subscribes — a named fact, not a drop)", now);
        return (true, $"event '{eventKind}' raised to {deliveries.Count} endpoint(s)", deliveries);
    }

    /// <summary>One webhook delivery pump pass; every state change
    /// is chained. Refuses (named) when no transport is wired —
    /// deliveries stay pending and visible rather than vanishing.</summary>
    public (bool Ok, string Reason, IReadOnlyList<WebhookDelivery> Changed) PumpWebhooks()
    {
        var now = _now();
        if (_webhookTransport is null)
            return (false, "no webhook transport is wired on this hub — deliveries remain pending and visible, none are dropped", Array.Empty<WebhookDelivery>());
        var changed = Webhooks.Pump(_webhookTransport, now);
        foreach (var d in changed)
            _audit.Append("webhook_delivery", "reporting-service",
                $"delivery={d.DeliveryId} endpoint={d.EndpointId} kind={d.EventKind} state={d.State} attempts={d.Attempts} error={d.LastError}", now);
        return (true, $"pump pass complete: {changed.Count} deliver(y/ies) changed state", changed);
    }

    // ---- scheduled reports -----------------------------------------------

    public (bool Ok, string Reason) DefineScheduled(IDeviceFacts facts, ScheduledReportDefinition? def)
    {
        var now = _now();
        if (!ScheduledEnabledFor(facts))
        {
            const string refusal = "scheduled reports are disabled by policy for this scope (rmm.reporting.scheduled.enabled) — definition refuses";
            _audit.Append("scheduled_report_refused", def?.DefinedBy ?? "(unknown)", refusal, now);
            return (false, refusal);
        }
        // D38-F8: the definition is stamped with the defining
        // scope; RunScheduled only ever runs its own scope's.
        var stamped = def is null ? null : def with { ScopeId = facts.ScopeId };
        var (ok, reason) = Scheduler.Define(stamped);
        _audit.Append(ok ? "scheduled_report_defined" : "scheduled_report_refused", def?.DefinedBy ?? "(unknown)",
            $"id={def?.Id} kind={def?.ReportKind} scope={facts.ScopeId} dest={def?.Destination.Kind}:{def?.Destination.Locator} reason={reason}", now);
        return (ok, reason);
    }

    /// <summary>One scheduler pass for a scope: generates due
    /// reports through the gated Generate path and delivers through
    /// the wired sink. No sink wired → due deliveries record FAILED
    /// with the reason, never silence.</summary>
    public (bool Ok, string Reason, IReadOnlyList<ScheduledDelivery> Deliveries) RunScheduled(IDeviceFacts facts)
    {
        var now = _now();
        if (!ScheduledEnabledFor(facts))
            return (false, "scheduled reports are disabled by policy for this scope (rmm.reporting.scheduled.enabled)", Array.Empty<ScheduledDelivery>());
        var sink = _reportSink ?? new RecordingReportSink();
        var deliveries = Scheduler.RunDue((def, _) =>
        {
            var (ok, reason, report) = Generate(facts, def.ReportKind);
            if (!ok || report is null) return (null, null, reason);
            return (report.Header.ReportId, ReportExporter.Export(report, def.Format, _now()), null);
        }, sink, now,
            filter: def => string.Equals(def.ScopeId, facts.ScopeId, StringComparison.OrdinalIgnoreCase));
        foreach (var d in deliveries)
            _audit.Append("scheduled_delivery", "reporting-service",
                $"delivery={d.DeliveryId} def={d.DefinitionId} report={d.ReportId} state={d.State} attempts={d.Attempts} error={d.LastError}", now);
        return (true, $"scheduler pass complete: {deliveries.Count} deliver(y/ies)", deliveries);
    }

    // ---- fleet MCP ---------------------------------------------------------

    /// <summary>One fleet-MCP tool call. Policy-gated; the result —
    /// executed, denied, or errored — is chained BEFORE returning
    /// (the McpHandler audit rule).</summary>
    public FleetToolResult CallFleetTool(IDeviceFacts facts, string toolName, string argumentsJson,
        IReadOnlySet<string> callerScopes, string? approvalGrantId, string callerName)
    {
        var now = _now();
        FleetToolResult result;
        if (!FleetMcpEnabledFor(facts))
            result = new FleetToolResult(false, "denied: fleet MCP is disabled by policy for this scope (rmm.reporting.fleet_mcp.enabled)", "fleet MCP disabled by policy");
        else
            result = FleetMcp.Call(toolName, argumentsJson, callerScopes, approvalGrantId, now, callerName);
        FlushPendingInputFailures(now);
        _audit.Append("fleet_mcp_call", callerName ?? "(unknown)",
            $"tool={toolName} outcome={result.Outcome}", now);
        // D38-F2 + BD-WIN-CORE-4/F5: grant consumption is itself
        // chained — but ONLY when the grant was actually redeemed.
        // The old unconditional append recorded consumption for
        // calls the policy toggle refused before FleetMcp.Call
        // ever ran (the grant was NOT consumed there).
        if (!string.IsNullOrWhiteSpace(approvalGrantId) && result.GrantConsumed)
            _audit.Append("fleet_grant_consumed", callerName ?? "(unknown)",
                $"tool={toolName} grant={approvalGrantId} outcome={result.Outcome}", now);
        return result;
    }

    public (bool Ok, string Reason, ApprovalGrant? Grant) GrantFleetApproval(
        string actionName, string approver1, string approver2, TimeSpan ttl,
        string? requester = null, string? argumentsJson = null, string? redeemingCaller = null)
    {
        var now = _now();
        // D38-F3: the requester may not be one of the approvers —
        // asking for an action and approving it is not dual
        // control. (Approver identities remain hub-local names:
        // there is no external IdP in this build — the binding
        // that IS enforced is arguments + targets + redeemer.)
        if (!string.IsNullOrWhiteSpace(requester))
        {
            var req = FleetApprovalBook.CanonicalIdentity(requester);
            if (string.Equals(req, FleetApprovalBook.CanonicalIdentity(approver1), StringComparison.OrdinalIgnoreCase) ||
                string.Equals(req, FleetApprovalBook.CanonicalIdentity(approver2), StringComparison.OrdinalIgnoreCase))
            {
                const string refusal = "the requester may not be an approver of their own fleet action — refused (dual control is two OTHER people)";
                _audit.Append("fleet_approval_refused", approver1 ?? "(unknown)",
                    $"action={actionName} requester={requester} reason={refusal}", now);
                return (false, refusal, null);
            }
        }
        var (ok, reason, grant) = FleetApprovals.Grant(actionName, approver1, approver2, now, ttl,
            argumentsJson, null, redeemingCaller);
        _audit.Append(ok ? "fleet_approval_granted" : "fleet_approval_refused", approver1 ?? "(unknown)",
            $"action={actionName} approvers={approver1}+{approver2} reason={reason}", now);
        return (ok, reason, grant);
    }

    // ---- local model -------------------------------------------------------

    /// <summary>Run one local-AI task. Policy-gated (default OFF —
    /// no model until the user hosts one); the signed output and
    /// every refusal are chained.</summary>
    public (bool Ok, string Reason, SignedModelOutput? Output) RunLocalModel(IDeviceFacts facts, string taskKind, string prompt, string requestedBy)
    {
        var now = _now();
        if (!LocalModelEnabledFor(facts))
        {
            const string refusal = "local AI functions are disabled by policy for this scope (rmm.reporting.local_model.enabled, default OFF) — refused";
            _audit.Append("local_model_refused", requestedBy ?? "(unknown)", $"task={taskKind} reason={refusal}", now);
            return (false, refusal, null);
        }
        var (ok, reason, output) = LocalModel.Run(taskKind, prompt, now);
        _audit.Append(ok ? "local_model_output" : "local_model_refused", requestedBy ?? "(unknown)",
            $"task={taskKind} model={output?.ModelName} key={output?.KeyId} reason={reason}", now);
        return (ok, reason, output);
    }
}
