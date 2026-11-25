using System.Text.Json;
using Acp.Core.Services;
using Acp.Shared.Backup;
using Acp.Shared.Enterprise;
using Acp.Shared.Inventory;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Monitoring;
using Acp.Shared.Reporting;
using Acp.Shared.Security;
using Acp.Shared.WorkItems;

namespace Acp.Tests;

// RMM-13 — Local reporting + hub API/webhooks: report models over
// hub data (fleet health, patch compliance, inventory/lifecycle,
// backup status, audit summaries, vulnerability posture) with
// provenance + staleness on their face; scheduled reports to
// user-owned destinations; the versioned, scoped, revocable local
// API; signed outbound webhooks; the governed fleet-MCP extension;
// and the signed local-model seam (fake only — no real model).
public class Rmm13Tests
{
    internal static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);

    internal sealed class MutableClock
    {
        public DateTimeOffset Now = T0;
        public DateTimeOffset UtcNow() => Now;
    }

    internal sealed class FakeBackupFacts : IBackupHealthFactsProvider
    {
        private readonly Dictionary<string, BackupHealthFacts> _byDevice = new(StringComparer.OrdinalIgnoreCase);
        public FakeBackupFacts With(BackupHealthFacts facts) { _byDevice[facts.DeviceId] = facts; return this; }
        public BackupHealthFacts GetFacts(string deviceId, DateTimeOffset now) =>
            _byDevice.TryGetValue(deviceId, out var f) ? f : throw new KeyNotFoundException(deviceId);
    }

    internal sealed class FakeFleetActions : IFleetActionExecutor
    {
        public List<string> Executed { get; } = new();
        public (bool Ok, string Detail) Execute(string actionName, string argumentsJson)
        {
            Executed.Add(actionName);
            return (true, $"fake executor ran {actionName}");
        }
    }

    internal sealed record Rig(
        ReportingService Service,
        ChainedAuditLog Audit,
        ManagementPolicyService Policies,
        InventoryStore Inventory,
        HubHealthIngest Health,
        MutableClock Clock,
        DeviceIdentity Signer,
        RecordingWebhookTransport WebhookTransport,
        RecordingReportSink ReportSink,
        FakeBackupFacts BackupFacts,
        FakeFleetActions FleetActions);

    internal static Rig NewRig(ILocalModel? localModel = null)
    {
        var clock = new MutableClock();
        var audit = new ChainedAuditLog();
        var policies = new ManagementPolicyService(audit, null, now: clock.UtcNow);
        var inventory = new InventoryStore();
        var centre = new HealthAlertCentre(audit, new AlertCenter());
        var health = new HubHealthIngest(centre, TimeSpan.FromMinutes(15));
        var signer = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var webhookTransport = new RecordingWebhookTransport();
        var reportSink = new RecordingReportSink();
        var backupFacts = new FakeBackupFacts();
        var fleetActions = new FakeFleetActions();
        var svc = new ReportingService(audit, policies, inventory, signer,
            health: health, backupFacts: backupFacts,
            webhookTransport: webhookTransport, reportSink: reportSink,
            localModel: localModel, fleetActions: fleetActions, now: clock.UtcNow);
        return new Rig(svc, audit, policies, inventory, health, clock, signer, webhookTransport, reportSink, backupFacts, fleetActions);
    }

    internal static IDeviceFacts Facts(string scopeId = "scope1", string deviceId = "hub") =>
        StaticDeviceFacts.Of(deviceId, scopeId);

    /// <summary>Set one org-level policy-content value for a scope
    /// through the real engine (admission is the service's local
    /// path; the value rides Effective Policy like production).</summary>
    internal static void SetPolicy(Rig rig, string scopeId, string key, string value, long revision = 1)
    {
        var doc = new ManagementPolicyDocument($"test-{key}-{revision}", PolicyLevels.Org, scopeId,
            new Dictionary<string, string> { [key] = value }, revision);
        var verdict = rig.Policies.AdmitLocalDocument(doc, "test");
        Assert.True(verdict.Allowed, verdict.Reason);
    }

    internal static void EnableWebhooks(Rig rig, string scopeId = "scope1") =>
        SetPolicy(rig, scopeId, ReportingPolicyKeys.WebhooksEnabled, "true", 101);

    internal static DeviceInventoryRecord Record(string deviceId, DateTimeOffset? purchase = null,
        params (string Name, string Version)[] software) => new(
            DeviceId: deviceId, ScopeId: "scope1", Hostname: "host-" + deviceId,
            Hardware: new HardwareSnapshot("Contoso", "Model", "SN-" + deviceId, "CPU", 4, 16L << 30,
                "Windows 11 Pro", "22631.1000", "22631.1000", null, Array.Empty<DiskInfo>(), Array.Empty<PeripheralInfo>(), T0),
            Software: software.Select(s => new SoftwareItem(s.Name, s.Version, "Contoso", null, null)).ToList(),
            CustomFields: new Dictionary<string, string>(), Tags: new HashSet<string>(),
            FirstSeenUtc: T0, LastSeenUtc: T0, LastChangedUtc: T0, Revision: 1,
            PurchaseDateUtc: purchase);

    /// <summary>Warranty is hub-filled state (RMM-04): ApplyBaseline
    /// nulls it by design, so tests set it through SetWarranty —
    /// exactly the hub's own path.</summary>
    private static void SetWarranty(InventoryStore store, string deviceId, DateTimeOffset expires) =>
        Assert.True(store.SetWarranty(deviceId,
            new WarrantyInfo("Dell", "SN-" + deviceId, "active", expires, null, T0)));

    private static DeviceHealthReport HealthReport(string deviceId, long seq, DateTimeOffset at,
        string monitorStatus = "ok", params string[] firing) => new(
            deviceId, seq, at, "lib-1", "hash-1", monitorStatus,
            Array.Empty<string>(), firing, Array.Empty<HealthAlertEvent>());

    // ---- (a) reports over hub data --------------------------------------

    [Fact]
    public void FleetHealthReport_CountsStatesFromHubIngest()
    {
        var rig = NewRig();
        Assert.True(rig.Health.Ingest(HealthReport("dev1", 1, T0), T0).Accepted);
        Assert.True(rig.Health.Ingest(HealthReport("dev2", 1, T0, "ok", "cpu_high"), T0).Accepted);
        var (ok, _, report) = rig.Service.Generate(Facts(), ReportKinds.FleetHealth);
        Assert.True(ok);
        Assert.Equal(2, report!.Counts["devices"]);
        Assert.Equal(1, report.Counts["healthy"]);
        Assert.Equal(1, report.Counts["alerting"]);
        Assert.False(report.Header.HasStaleInputs(T0));
        Assert.Contains(report.Rows, r => r[0] == "dev2" && r[1] == "alerting");
    }

    [Fact]
    public void FleetHealthReport_NoDevices_StatesUnknownNotHealthy()
    {
        var rig = NewRig();
        var (ok, _, report) = rig.Service.Generate(Facts(), ReportKinds.FleetHealth);
        Assert.True(ok);
        Assert.Equal(0, report!.Counts["devices"]);
        Assert.True(report.Header.HasStaleInputs(T0)); // no data = named, never fresh
        Assert.Contains(report.Notes, n => n.Contains("unknown, not healthy"));
    }

    [Fact]
    public void PatchComplianceReport_FromRealPatchScanOverInventory()
    {
        // Build the RMM-02 rig for a real catalogue + PatchService,
        // then a ReportingService over the same audit/policies.
        var patches = Rmm02Tests.NewRig();
        var entry = Rmm02Tests.ThirdParty(severity: "critical");
        Assert.True(patches.Service.AdmitEntries(new[] { entry }, "test").Ok);
        var clock = new MutableClock();
        var inventory = new InventoryStore();
        inventory.ApplyBaseline(Record("dev1", software: ("Contoso App", "1.0")), T0); // below fixed 2.0
        inventory.ApplyBaseline(Record("dev2", software: ("Contoso App", "2.0")), T0); // compliant
        var svc = new ReportingService(patches.Audit, patches.Policies, inventory,
            new DeviceIdentity(new DevOnlyPassThroughProtector()),
            patches: patches.Service, now: clock.UtcNow);
        var (ok, _, report) = svc.Generate(Facts(), ReportKinds.PatchCompliance);
        Assert.True(ok);
        Assert.Equal(2, report!.Counts["devices"]);
        Assert.Equal(1, report.Counts["compliant"]);
        Assert.Equal(1, report.Counts["non_compliant"]);
        Assert.Equal(1, report.Counts["missing_critical"]);
    }

    [Fact]
    public void InventoryLifecycleReport_RefreshAndWarrantyFromRecords()
    {
        var rig = NewRig();
        rig.Inventory.ApplyBaseline(Record("old1", purchase: T0.AddYears(-7)), T0);
        rig.Inventory.ApplyBaseline(Record("new1", purchase: T0.AddYears(-1)), T0);
        SetWarranty(rig.Inventory, "old1", T0.AddDays(-10));
        SetWarranty(rig.Inventory, "new1", T0.AddDays(30));
        var (ok, _, report) = rig.Service.Generate(Facts(), ReportKinds.InventoryLifecycle);
        Assert.True(ok);
        Assert.Equal(2, report!.Counts["devices"]);
        Assert.Equal(1, report.Counts["refresh_candidates"]);
        Assert.Equal(1, report.Counts["warranty_expired"]);
        Assert.Equal(1, report.Counts["warranty_expiring_soon"]);
    }

    [Fact]
    public void BackupStatusReport_OkAndNeverRunDevicesBothNamed()
    {
        var rig = NewRig();
        rig.Inventory.ApplyBaseline(Record("dev1"), T0);
        rig.Inventory.ApplyBaseline(Record("dev2"), T0);
        var svc = new ReportingService(rig.Audit, rig.Policies, rig.Inventory,
            new DeviceIdentity(new DevOnlyPassThroughProtector()),
            backupFacts: new StaticFactsProvider(new BackupHealthFacts("dev1", T0, T0, "completed", 0, 3, 1024, true, 50.0, false, T0)),
            now: rig.Clock.UtcNow);
        var (ok, _, report) = svc.Generate(Facts(), ReportKinds.BackupStatus);
        Assert.True(ok);
        Assert.Equal(1, report!.Counts["ok"]);
        Assert.Equal(1, report.Counts["with_findings"]); // dev2: never ran — a finding, not silence
        Assert.Contains(report.Rows, r => r[0] == "dev2" && r[4].Contains("no backup has ever run"));
    }

    [Fact]
    public void BackupStatusReport_BuilderNamesDevicesWithNoFactsAtAll()
    {
        // Builder-level contract: a device the caller expects but
        // has NO facts for gets an explicit no-facts row — absence
        // is never rendered as health.
        var facts = new[] { new BackupHealthFacts("dev1", T0, T0, "completed", 0, 1, 10, true, 50.0, false, T0) };
        var report = ReportBuilders.BackupStatus(facts, new[] { "dev1", "dev2" }, "scope1", T0);
        Assert.Equal(1, report.Counts["no_facts"]);
        Assert.Contains(report.Rows, r => r[0] == "dev2" && r[1] == "no-facts");
    }

    private sealed class StaticFactsProvider : IBackupHealthFactsProvider
    {
        private readonly BackupHealthFacts _facts;
        public StaticFactsProvider(BackupHealthFacts facts) => _facts = facts;
        public BackupHealthFacts GetFacts(string deviceId, DateTimeOffset now) =>
            deviceId == _facts.DeviceId ? _facts : new BackupHealthFacts(deviceId, null, null, null, 0, 0, 0, true, null, false, now);
    }

    [Fact]
    public void AuditSummaryReport_CountsByKindAndChainVerdict()
    {
        var rig = NewRig();
        rig.Audit.Append("custom_event", "tester", "one", T0);
        rig.Audit.Append("custom_event", "tester", "two", T0);
        var (ok, _, report) = rig.Service.Generate(Facts(), ReportKinds.AuditSummary);
        Assert.True(ok);
        Assert.Equal(1, report!.Counts["chain_ok"]);
        Assert.True(report.Counts["entries_total"] >= 2);
        Assert.Contains(report.Notes, n => n.Contains("chain verification: OK"));
    }

    [Fact]
    public void VulnerabilityPosture_NoFeed_NamesItselfStale()
    {
        var rig = NewRig();
        var (ok, _, report) = rig.Service.Generate(Facts(), ReportKinds.VulnerabilityPosture);
        Assert.True(ok);
        Assert.Equal(1, report!.Counts["feed_stale"]);
        Assert.True(report.Header.HasStaleInputs(T0));
        Assert.Contains(report.Notes, n => n.Contains("no vulnerability feed"));
    }

    [Fact]
    public void Exports_AllFormatsCarryProvenance()
    {
        var rig = NewRig();
        rig.Health.Ingest(HealthReport("dev1", 1, T0), T0);
        var (_, _, report) = rig.Service.Generate(Facts(), ReportKinds.FleetHealth);
        var json = ReportExporter.Export(report!, ReportExportFormats.Json, T0);
        var text = ReportExporter.Export(report!, ReportExportFormats.Text, T0);
        var csv = ReportExporter.Export(report!, ReportExportFormats.Csv, T0);
        Assert.Contains("rmm01.hub_health_ingest", json);
        Assert.Contains("provenance:", text);
        Assert.Contains("# stale_inputs", csv);
        Assert.Contains("dev1", csv);
        using var doc = JsonDocument.Parse(json);
        Assert.False(doc.RootElement.GetProperty("staleInputs").GetBoolean());
    }

    [Fact]
    public void Generate_UnknownKindAndPolicyDisabled_Refuse()
    {
        var rig = NewRig();
        Assert.False(rig.Service.Generate(Facts(), "nonsense").Ok);
        SetPolicy(rig, "scope1", ReportingPolicyKeys.ReportingEnabled, "false", 102);
        var (ok, reason, _) = rig.Service.Generate(Facts(), ReportKinds.FleetHealth);
        Assert.False(ok);
        Assert.Contains("disabled by policy", reason);
    }

    // ---- (b) scheduled reports -------------------------------------------

    [Fact]
    public void ScheduledReport_GeneratesAndDeliversOnSchedule()
    {
        var rig = NewRig();
        rig.Health.Ingest(HealthReport("dev1", 1, T0), T0);
        var def = new ScheduledReportDefinition("nightly-health", ReportKinds.FleetHealth,
            ReportExportFormats.Json, 24, new ReportDestination(ReportDestinationKinds.LocalPath, @"C:\acp-reports"), true, "admin");
        Assert.True(rig.Service.DefineScheduled(Facts(), def).Ok);
        var (ok, _, deliveries) = rig.Service.RunScheduled(Facts());
        Assert.True(ok);
        Assert.Single(deliveries);
        Assert.Equal(ScheduledDeliveryStates.Delivered, deliveries[0].State);
        Assert.Single(rig.ReportSink.Sent);
        Assert.Contains("fleet_health", rig.ReportSink.Sent[0].Content);
        // Not due again immediately.
        Assert.Empty(rig.Service.RunScheduled(Facts()).Deliveries);
    }

    [Fact]
    public void ScheduledReport_BadDefinitionsRefuse()
    {
        var rig = NewRig();
        Assert.False(rig.Service.DefineScheduled(Facts(), new ScheduledReportDefinition(
            "x", "nope", "json", 24, new ReportDestination("local_path", @"C:\r"), true, "admin")).Ok);
        Assert.False(rig.Service.DefineScheduled(Facts(), new ScheduledReportDefinition(
            "x", ReportKinds.FleetHealth, "json", 0, new ReportDestination("local_path", @"C:\r"), true, "admin")).Ok);
    }

    // ---- (c) hub API --------------------------------------------------------

    [Fact]
    public void Api_IssuedKeyReadsReports_AndEveryCallIsAudited()
    {
        var rig = NewRig();
        rig.Health.Ingest(HealthReport("dev1", 1, T0), T0);
        var (ok, _, secret) = rig.Service.IssueApiKey(Facts(), "admin", new HashSet<string> { HubApiScopes.ReportsRead });
        Assert.True(ok);
        var before = rig.Audit.Entries.Count;
        var resp = rig.Service.DispatchApi(Facts(), "GET", "/api/v1/reports/fleet_health", secret);
        Assert.Equal(200, resp.Status);
        Assert.Contains("fleet_health", resp.BodyJson);
        Assert.True(rig.Audit.Entries.Count > before);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "api_call" && e.Detail.Contains("status=200"));
        // The store never holds the plaintext secret.
        Assert.DoesNotContain(rig.Service.ApiKeys.Keys, k => k.SecretHash == secret);
    }

    [Fact]
    public void Api_CatalogueNamesEveryEndpointsScope()
    {
        var rig = NewRig();
        var (_, _, secret) = rig.Service.IssueApiKey(Facts(), "admin",
            new HashSet<string> { HubApiScopes.ReportsRead, HubApiScopes.FleetRead, HubApiScopes.AuditRead });
        var resp = rig.Service.DispatchApi(Facts(), "GET", "/api/v1/catalogue", secret);
        Assert.Equal(200, resp.Status);
        foreach (var ep in HubApiCatalogue.Endpoints)
        {
            Assert.Contains(ep.Id, resp.BodyJson);
            Assert.Contains(ep.RequiredScope, resp.BodyJson);
            Assert.False(ep.MutatesState);
        }
    }

    [Fact]
    public void Api_UnknownVersionAndKind_RefuseByName()
    {
        var rig = NewRig();
        var (_, _, secret) = rig.Service.IssueApiKey(Facts(), "admin", new HashSet<string> { HubApiScopes.ReportsRead });
        Assert.Equal(404, rig.Service.DispatchApi(Facts(), "GET", "/api/v2/reports", secret).Status);
        Assert.Equal(404, rig.Service.DispatchApi(Facts(), "GET", "/api/v1/reports/bogus", secret).Status);
        Assert.Equal(404, rig.Service.DispatchApi(Facts(), "GET", "/api/v1/nope", secret).Status);
    }

    // ---- (d) webhooks -------------------------------------------------------

    [Fact]
    public void Webhook_SignedDeliveryVerifiesAtReceiver()
    {
        var rig = NewRig();
        EnableWebhooks(rig);
        var ep = new WebhookEndpoint("psa", "https://hooks.example.org/acp",
            new HashSet<string> { HubEventKinds.BackupFailed }, true, "admin");
        Assert.True(rig.Service.ConfigureWebhook(Facts(), ep).Ok);
        var (ok, _, deliveries) = rig.Service.RaiseEvent(Facts(), HubEventKinds.BackupFailed, "{\"device\":\"dev1\"}");
        Assert.True(ok);
        Assert.Single(deliveries);
        var (pumpOk, _, changed) = rig.Service.PumpWebhooks();
        Assert.True(pumpOk);
        Assert.Equal(WebhookDeliveryStates.Delivered, changed.Single().State);
        Assert.Single(rig.WebhookTransport.Sent);
        var payload = rig.WebhookTransport.Sent[0].PayloadJson;
        Assert.True(HubWebhookSigning.VerifyPayload(payload, rig.Service.Webhooks.HubPublicKey));
    }

    [Fact]
    public void Webhook_DisabledByDefault_NothingLeaves()
    {
        var rig = NewRig();
        var ep = new WebhookEndpoint("psa", "https://hooks.example.org/acp",
            new HashSet<string> { HubEventKinds.AlertRaised }, true, "admin");
        Assert.False(rig.Service.ConfigureWebhook(Facts(), ep).Ok); // webhooks default OFF
        Assert.False(rig.Service.RaiseEvent(Facts(), HubEventKinds.AlertRaised, "{}").Ok);
        Assert.Empty(rig.WebhookTransport.Sent);
    }

    // ---- (e) fleet MCP + local model -----------------------------------------

    [Fact]
    public void FleetMcp_StandardQueriesAnswerFromHubData()
    {
        var rig = NewRig();
        rig.Health.Ingest(HealthReport("dev1", 1, T0), T0);
        var result = rig.Service.CallFleetTool(Facts(), "fleet.health", "",
            new HashSet<string> { FleetScopes.Read }, null, "tester");
        Assert.True(result.Ok, result.Outcome);
        Assert.Contains("dev1", result.Text);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "fleet_mcp_call");
    }

    [Fact]
    public void FleetMcp_ActionExecutesOnlyWithDualControlGrant()
    {
        var rig = NewRig();
        rig.Service.FleetMcp.RegisterAction("fleet.restart_service", "Restart a service (fake executor in tests)");
        var scopes = new HashSet<string> { FleetScopes.Read, FleetScopes.Act };
        // No grant → refused, nothing executed.
        var denied = rig.Service.CallFleetTool(Facts(), "fleet.restart_service", "{}", scopes, null, "tester");
        Assert.False(denied.Ok);
        Assert.Empty(rig.FleetActions.Executed);
        // Dual-control grant → executes exactly once.
        var (gOk, _, grant) = rig.Service.GrantFleetApproval("fleet.restart_service", "alice", "bob", TimeSpan.FromMinutes(10));
        Assert.True(gOk);
        var done = rig.Service.CallFleetTool(Facts(), "fleet.restart_service", "{}", scopes, grant!.GrantId, "tester");
        Assert.True(done.Ok, done.Outcome);
        Assert.Single(rig.FleetActions.Executed);
    }

    [Fact]
    public void LocalModel_SignedOutputVerifies_AndPolicyGates()
    {
        var rig = NewRig(new FakeLocalModel());
        // Default OFF.
        Assert.False(rig.Service.RunLocalModel(Facts(), LocalModelTaskKinds.Worklog, "summarise", "tester").Ok);
        SetPolicy(rig, "scope1", ReportingPolicyKeys.LocalModelEnabled, "true", 103);
        var (ok, _, output) = rig.Service.RunLocalModel(Facts(), LocalModelTaskKinds.Worklog, "summarise the session", "tester");
        Assert.True(ok);
        Assert.True(LocalModelRunner.Verify(output, rig.Signer.PublicKey));
        Assert.Contains("fake local model", output!.Output);
    }

    [Fact]
    public void LocalModel_NoModelHosted_RefusesByName()
    {
        var rig = NewRig(localModel: null);
        SetPolicy(rig, "scope1", ReportingPolicyKeys.LocalModelEnabled, "true", 104);
        var (ok, reason, _) = rig.Service.RunLocalModel(Facts(), LocalModelTaskKinds.ScriptDraft, "draft", "tester");
        Assert.False(ok);
        Assert.Contains("no local model is hosted", reason);
    }
}
