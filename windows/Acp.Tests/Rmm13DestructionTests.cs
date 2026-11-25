using Acp.Core.Services;
using Acp.Shared.Enterprise;
using Acp.Shared.Inventory;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Monitoring;
using Acp.Shared.Reporting;
using Acp.Shared.Security;
using Acp.Shared.WorkItems;

namespace Acp.Tests;

// RMM-13 — DESTRUCTION PASS. Attacks: API auth bypass (unsigned /
// wrong-scope / revoked / expired keys, hash-as-secret), a
// read-only key attempting state changes, the webhook SSRF battery
// (loopback / link-local / metadata / redirect chains), webhook
// payload forgery, scheduled-report destination smuggling (vendor
// cloud dressed as local), report staleness laundering, MCP
// fleet-action escalation, and CSV/formula injection from device
// names. Every break found converts to a fix + a test here.
public class Rmm13DestructionTests
{
    private static readonly DateTimeOffset T0 = Rmm13Tests.T0;

    private static Rmm13Tests.Rig RigWithWebhooks()
    {
        var rig = Rmm13Tests.NewRig();
        Rmm13Tests.EnableWebhooks(rig);
        return rig;
    }

    private static string IssueKey(Rmm13Tests.Rig rig, params string[] scopes)
    {
        var (ok, reason, secret) = rig.Service.IssueApiKey(Rmm13Tests.Facts(), "admin", new HashSet<string>(scopes));
        Assert.True(ok, reason);
        return secret!;
    }

    // ---- API auth bypass battery -------------------------------------------

    [Fact]
    public void Api_NoSecretGarbageSecretAndHashAsSecret_AllRefuse401()
    {
        var rig = Rmm13Tests.NewRig();
        var secret = IssueKey(rig, HubApiScopes.ReportsRead);
        Assert.Equal(401, rig.Service.DispatchApi(Rmm13Tests.Facts(), "GET", "/api/v1/reports/fleet_health", null).Status);
        Assert.Equal(401, rig.Service.DispatchApi(Rmm13Tests.Facts(), "GET", "/api/v1/reports/fleet_health", "").Status);
        Assert.Equal(401, rig.Service.DispatchApi(Rmm13Tests.Facts(), "GET", "/api/v1/reports/fleet_health", "acp_deadbeefdeadbeef").Status);
        // Presenting the stored HASH as the secret must not work:
        // the store hashes what it is given, so hash-as-secret
        // authenticates as hash-of-hash — nothing.
        var storedHash = rig.Service.ApiKeys.Keys.Single().SecretHash;
        Assert.Equal(401, rig.Service.DispatchApi(Rmm13Tests.Facts(), "GET", "/api/v1/reports/fleet_health", storedHash).Status);
        // The real secret still works (the battery did not break the door).
        Assert.Equal(200, rig.Service.DispatchApi(Rmm13Tests.Facts(), "GET", "/api/v1/reports/fleet_health", secret).Status);
    }

    [Fact]
    public void Api_RevokedKeyDiesImmediately_ExpiredKeyDiesOnTime()
    {
        var rig = Rmm13Tests.NewRig();
        var secret = IssueKey(rig, HubApiScopes.ReportsRead);
        var keyId = rig.Service.ApiKeys.Keys.Single().KeyId;
        Assert.Equal(200, rig.Service.DispatchApi(Rmm13Tests.Facts(), "GET", "/api/v1/reports", secret).Status);
        Assert.True(rig.Service.RevokeApiKey(keyId, "admin").Ok);
        Assert.Equal(401, rig.Service.DispatchApi(Rmm13Tests.Facts(), "GET", "/api/v1/reports", secret).Status);

        var rig2 = Rmm13Tests.NewRig();
        var (ok, _, expiring) = rig2.Service.IssueApiKey(Rmm13Tests.Facts(), "admin",
            new HashSet<string> { HubApiScopes.ReportsRead }, T0.AddHours(1));
        Assert.True(ok);
        Assert.Equal(200, rig2.Service.DispatchApi(Rmm13Tests.Facts(), "GET", "/api/v1/reports", expiring).Status);
        rig2.Clock.Now = T0.AddHours(2);
        Assert.Equal(401, rig2.Service.DispatchApi(Rmm13Tests.Facts(), "GET", "/api/v1/reports", expiring).Status);
    }

    [Fact]
    public void Api_WrongScopeKey_ReadsNothingOutsideItsScope()
    {
        var rig = Rmm13Tests.NewRig();
        var reportsOnly = IssueKey(rig, HubApiScopes.ReportsRead);
        Assert.Equal(403, rig.Service.DispatchApi(Rmm13Tests.Facts(), "GET", "/api/v1/fleet/health", reportsOnly).Status);
        Assert.Equal(403, rig.Service.DispatchApi(Rmm13Tests.Facts(), "GET", "/api/v1/fleet/devices", reportsOnly).Status);
        Assert.Equal(403, rig.Service.DispatchApi(Rmm13Tests.Facts(), "GET", "/api/v1/audit/summary", reportsOnly).Status);
        Assert.Equal(200, rig.Service.DispatchApi(Rmm13Tests.Facts(), "GET", "/api/v1/reports", reportsOnly).Status);
        // Scopeless and unknown-scope keys are never issued.
        Assert.False(rig.Service.IssueApiKey(Rmm13Tests.Facts(), "admin", new HashSet<string>()).Ok);
        Assert.False(rig.Service.IssueApiKey(Rmm13Tests.Facts(), "admin", new HashSet<string> { "fleet.write" }).Ok);
    }

    [Fact]
    public void Api_ReadOnlyKey_CannotChangeStateByAnyVerb()
    {
        var rig = Rmm13Tests.NewRig();
        var secret = IssueKey(rig, HubApiScopes.ReportsRead, HubApiScopes.FleetRead, HubApiScopes.AuditRead);
        foreach (var verb in new[] { "POST", "PUT", "PATCH", "DELETE" })
        {
            Assert.Equal(405, rig.Service.DispatchApi(Rmm13Tests.Facts(), verb, "/api/v1/reports/fleet_health", secret).Status);
            Assert.Equal(405, rig.Service.DispatchApi(Rmm13Tests.Facts(), verb, "/api/v1/catalogue", secret).Status);
        }
        // And the catalogue itself contains no mutating endpoint to find.
        Assert.All(HubApiCatalogue.Endpoints, e => Assert.False(e.MutatesState));
        Assert.All(HubApiCatalogue.Endpoints, e => Assert.Equal("GET", e.Method));
    }

    [Fact]
    public void Api_PolicyDisabled_RefusesEveryCallAndAuditsTheRefusal()
    {
        var rig = Rmm13Tests.NewRig();
        var secret = IssueKey(rig, HubApiScopes.ReportsRead);
        Rmm13Tests.SetPolicy(rig, "scope1", ReportingPolicyKeys.ReportingEnabled, "false", 777);
        var resp = rig.Service.DispatchApi(Rmm13Tests.Facts(), "GET", "/api/v1/reports", secret);
        Assert.Equal(403, resp.Status);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "api_call" && e.Detail.Contains("status=403"));
    }

    // ---- webhook SSRF battery ----------------------------------------------

    [Theory]
    [InlineData("http://hooks.example.org/acp")]                 // cleartext
    [InlineData("https://127.0.0.1/hook")]                        // loopback literal
    [InlineData("https://localhost/hook")]                        // loopback name
    [InlineData("https://169.254.169.254/latest/meta-data")]      // cloud metadata
    [InlineData("https://169.254.10.20/hook")]                    // link-local
    [InlineData("https://[::1]/hook")]                            // IPv6 loopback
    [InlineData("https://[fe80::1]/hook")]                        // IPv6 link-local
    [InlineData("https://[fd00::1]/hook")]                        // IPv6 ULA
    [InlineData("https://metadata.google.internal/hook")]         // metadata name
    [InlineData("https://hooks.example.org:8443/hook")]           // non-443 port
    [InlineData("https://user:pass@hooks.example.org/hook")]      // userinfo
    [InlineData("")]                                              // empty
    public void WebhookGuard_RefusesSsrfBattery(string url)
    {
        Assert.NotNull(WebhookTargetGuard.ValidateTarget(url));
    }

    [Theory]
    [InlineData("https://hooks.example.org/hook")]                // public name
    [InlineData("https://192.168.1.50/hook")]                     // org LAN (RFC1918) — the local-API point
    [InlineData("https://10.2.3.4/hook")]                         // org LAN (RFC1918)
    public void WebhookGuard_AdmitsOrgTargets(string url)
    {
        Assert.Null(WebhookTargetGuard.ValidateTarget(url));
    }

    [Fact]
    public void WebhookGuard_DnsRebindingAndRedirectHalves()
    {
        var publicIp = System.Net.IPAddress.Parse("93.184.216.34");
        var metadata = System.Net.IPAddress.Parse("169.254.169.254");
        var loopback = System.Net.IPAddress.Parse("127.0.0.1");
        Assert.True(WebhookTargetGuard.ValidateResolvedAddresses(new[] { publicIp }));
        Assert.False(WebhookTargetGuard.ValidateResolvedAddresses(new[] { publicIp, metadata })); // one poisoned answer poisons the set
        Assert.False(WebhookTargetGuard.ValidateResolvedAddresses(new[] { loopback }));
        Assert.False(WebhookTargetGuard.ValidateResolvedAddresses(Array.Empty<System.Net.IPAddress>()));
        Assert.False(WebhookTargetGuard.ValidateResolvedAddresses(null));
        // Redirect chains: a good endpoint 302ing to a guarded
        // target is refused at the hop, never followed.
        Assert.NotNull(WebhookTargetGuard.ValidateRedirectTarget("https://169.254.169.254/"));
        Assert.NotNull(WebhookTargetGuard.ValidateRedirectTarget("http://192.168.1.50/hook"));
        Assert.Null(WebhookTargetGuard.ValidateRedirectTarget("https://hooks.example.org/other"));
    }

    [Fact]
    public void Webhook_SsrfEndpointRefusedAtConfigurationAndNeverStored()
    {
        var rig = RigWithWebhooks();
        var ep = new WebhookEndpoint("evil", "https://169.254.169.254/hook",
            new HashSet<string> { HubEventKinds.AlertRaised }, true, "admin");
        Assert.False(rig.Service.ConfigureWebhook(Rmm13Tests.Facts(), ep).Ok);
        Assert.Empty(rig.Service.Webhooks.Endpoints);
        var (ok, _, deliveries) = rig.Service.RaiseEvent(Rmm13Tests.Facts(), HubEventKinds.AlertRaised, "{}");
        Assert.True(ok);
        Assert.Empty(deliveries);
        Assert.Empty(rig.WebhookTransport.Sent);
    }

    // ---- webhook forgery battery ---------------------------------------------

    [Fact]
    public void Webhook_ForgeryBattery_ReceiversRejectEverythingButTheRealPayload()
    {
        var rig = RigWithWebhooks();
        var ep = new WebhookEndpoint("psa", "https://hooks.example.org/acp",
            new HashSet<string> { HubEventKinds.AlertRaised }, true, "admin");
        Assert.True(rig.Service.ConfigureWebhook(Rmm13Tests.Facts(), ep).Ok);
        rig.Service.RaiseEvent(Rmm13Tests.Facts(), HubEventKinds.AlertRaised, "{\"device\":\"dev1\"}");
        rig.Service.PumpWebhooks();
        var genuine = rig.WebhookTransport.Sent.Single().PayloadJson;
        var hubKey = rig.Service.Webhooks.HubPublicKey;
        Assert.True(HubWebhookSigning.VerifyPayload(genuine, hubKey));

        // Unsigned payload (plain body, no envelope).
        Assert.False(HubWebhookSigning.VerifyPayload("{\"device\":\"dev1\"}", hubKey));
        // Tampered body inside a genuine envelope.
        Assert.False(HubWebhookSigning.VerifyPayload(genuine.Replace("dev1", "dev9"), hubKey));
        // Signature stripped.
        using (var doc = System.Text.Json.JsonDocument.Parse(genuine))
        {
            var root = doc.RootElement;
            var stripped = $"{{\"eventKind\":\"{root.GetProperty("eventKind").GetString()}\",\"deliveryId\":\"{root.GetProperty("deliveryId").GetString()}\",\"atUtc\":\"{root.GetProperty("atUtc").GetString()}\",\"keyId\":\"{root.GetProperty("keyId").GetString()}\",\"body\":\"x\",\"signature\":\"\"}}";
            Assert.False(HubWebhookSigning.VerifyPayload(stripped, hubKey));
        }
        // A stranger's key signing a well-formed envelope: the
        // receiver's hub key rejects it (wrong key id + bad sig).
        var stranger = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var forged = HubWebhookSigning.SignedPayload(HubEventKinds.AlertRaised, "whd-forged", "{\"device\":\"dev1\"}", stranger, T0);
        Assert.False(HubWebhookSigning.VerifyPayload(forged, hubKey));
        // Genuine payload, wrong verification key.
        Assert.False(HubWebhookSigning.VerifyPayload(genuine, stranger.PublicKey));
    }

    [Fact]
    public void Webhook_FailedDeliveriesRetryWithBoundsThenDieVisibly()
    {
        var rig = RigWithWebhooks();
        var ep = new WebhookEndpoint("down-psa", "https://hooks.example.org/acp",
            new HashSet<string> { HubEventKinds.BackupFailed }, true, "admin");
        Assert.True(rig.Service.ConfigureWebhook(Rmm13Tests.Facts(), ep).Ok);
        rig.WebhookTransport.Result = (false, "503 from recording double");
        rig.Service.RaiseEvent(Rmm13Tests.Facts(), HubEventKinds.BackupFailed, "{}");
        for (var i = 0; i < WebhookTargetGuard.MaxAttempts; i++)
        {
            rig.Service.PumpWebhooks();
            rig.Clock.Now = rig.Clock.Now.AddMinutes(30); // outrun every backoff
        }
        var delivery = rig.Service.Webhooks.Deliveries.Single();
        Assert.Equal(WebhookDeliveryStates.Dead, delivery.State);
        Assert.Equal(WebhookTargetGuard.MaxAttempts, delivery.Attempts);
        Assert.Contains("503", delivery.LastError);
        // Dead is terminal: further pumps change nothing.
        var count = rig.WebhookTransport.Sent.Count;
        rig.Service.PumpWebhooks();
        Assert.Equal(count, rig.WebhookTransport.Sent.Count);
    }

    // ---- scheduled-report destination smuggling -------------------------------

    [Theory]
    [InlineData("smtp", "smtp.gmail.com")]                        // consumer cloud as "our SMTP"
    [InlineData("smtp", "admin@sendgrid.net")]                    // vendor relay with a local costume
    [InlineData("smtp", "ses.amazonaws.com")]                     // vendor cloud
    [InlineData("smtp", "169.254.169.254")]                       // metadata as SMTP
    [InlineData("local_path", "https://storage.googleapis.com/bucket/reports")] // remote-object URL as a path
    [InlineData("local_path", "s3://org-backups/reports")]        // object store as a path
    [InlineData("local_path", @"\\bucket.s3.amazonaws.com\share")] // vendor cloud dressed as a UNC share
    [InlineData("local_path", "reports\\nightly")]                // relative path — not a user-owned absolute destination
    [InlineData("webhook", "https://169.254.169.254/hook")]       // metadata webhook
    [InlineData("webhook", "http://192.168.1.50/hook")]           // cleartext webhook
    [InlineData("cloud", "https://example.org/x")]                // a kind that does not exist
    public void ScheduledDestination_SmugglingBatteryRefuses(string kind, string locator)
    {
        Assert.NotNull(ReportDestinationGuard.Validate(kind, locator));
    }

    [Theory]
    [InlineData("local_path", @"C:\acp-reports")]
    [InlineData("local_path", @"\\nas01\reports")]
    [InlineData("smtp", "mail.corp.example")]
    [InlineData("smtp", "ops@mail.corp.example:587")]
    [InlineData("webhook", "https://hooks.corp.example/acp")]
    public void ScheduledDestination_UserOwnedShapesAdmit(string kind, string locator)
    {
        Assert.Null(ReportDestinationGuard.Validate(kind, locator));
    }

    [Fact]
    public void Scheduled_FailedDeliveryIsARecordNotASilence()
    {
        var rig = Rmm13Tests.NewRig();
        rig.ReportSink.Result = (false, "disk full (recording double)");
        var def = new ScheduledReportDefinition("nightly", ReportKinds.AuditSummary, "json", 1,
            new ReportDestination(ReportDestinationKinds.LocalPath, @"C:\acp-reports"), true, "admin");
        Assert.True(rig.Service.DefineScheduled(Rmm13Tests.Facts(), def).Ok);
        var first = rig.Service.RunScheduled(Rmm13Tests.Facts()).Deliveries.Single();
        Assert.Equal(ScheduledDeliveryStates.Failed, first.State);
        Assert.Contains("disk full", first.LastError);
        // Retries burn down to DEAD — visibly, in the records.
        rig.Service.RunScheduled(Rmm13Tests.Facts());
        var last = rig.Service.RunScheduled(Rmm13Tests.Facts()).Deliveries.Last();
        Assert.Equal(ScheduledDeliveryStates.Dead, last.State);
        Assert.All(rig.Service.Scheduler.Deliveries, d => Assert.False(string.IsNullOrEmpty(d.State)));
    }

    // ---- staleness laundering --------------------------------------------------

    [Fact]
    public void Staleness_OldInputsNameThemselvesStaleInEveryFormat()
    {
        var rig = Rmm13Tests.NewRig();
        var old = T0.AddHours(-3);
        // A health report from 3 hours ago: the ingest accepts it
        // (it is the newest seq), the device reads DOWN, and the
        // report must say STALE — there is no rendering in which
        // this fleet looks current.
        var report = new DeviceHealthReport("dev1", 1, old, "lib-1", "h", MonitorStatuses.Ok,
            Array.Empty<string>(), Array.Empty<string>(), Array.Empty<HealthAlertEvent>());
        Assert.True(rig.Health.Ingest(report, old).Accepted);
        var (ok, _, built) = rig.Service.Generate(Rmm13Tests.Facts(), ReportKinds.FleetHealth);
        Assert.True(ok);
        Assert.True(built!.Header.HasStaleInputs(T0));
        var text = ReportExporter.Export(built, ReportExportFormats.Text, T0);
        Assert.Contains("STALE", text);
        var json = ReportExporter.Export(built, ReportExportFormats.Json, T0);
        Assert.Contains("\"staleInputs\": true", json);
        var csv = ReportExporter.Export(built, ReportExportFormats.Csv, T0);
        var staleLine = csv.Split("\r\n").First(l => l.StartsWith("# stale_inputs"));
        Assert.Contains(",true,", staleLine);
        // Time only makes it staler: re-rendering tomorrow cannot launder it.
        Assert.True(built.Header.HasStaleInputs(T0.AddDays(1)));
    }

    [Fact]
    public void Staleness_ProvenanceIsComputed_NotAsserted()
    {
        // The provenance record offers no constructor path to a
        // fresh verdict for old data: staleness is a method over
        // (DataAsOf, bound, now), and a missing input is stale too.
        var stale = new ReportInputProvenance("src", T0.AddDays(-2), TimeSpan.FromHours(1), true);
        Assert.True(stale.IsStale(T0));
        var missing = new ReportInputProvenance("src", T0, TimeSpan.FromHours(1), false);
        Assert.True(missing.IsStale(T0));
        var fresh = new ReportInputProvenance("src", T0, TimeSpan.FromHours(1), true);
        Assert.False(fresh.IsStale(T0));
        Assert.True(fresh.IsStale(T0.AddHours(2))); // the same input ages into staleness on its own
    }

    // ---- MCP fleet-action escalation --------------------------------------------

    [Fact]
    public void FleetMcp_QueryToolsCannotMutateHubState()
    {
        var rig = Rmm13Tests.NewRig();
        rig.Inventory.ApplyBaseline(Rmm13Tests.Record("dev1"), T0);
        var devicesBefore = rig.Inventory.List().Count;
        var auditKindsBefore = rig.Audit.Entries.Count;
        var scopes = new HashSet<string> { FleetScopes.Read };
        foreach (var tool in rig.Service.FleetMcp.Tools.Where(t => !t.MutatesState))
        {
            var r = rig.Service.CallFleetTool(Rmm13Tests.Facts(), tool.Name, "", scopes, null, "attacker");
            Assert.True(r.Ok, $"{tool.Name}: {r.Outcome}");
        }
        Assert.Equal(devicesBefore, rig.Inventory.List().Count);
        // The only new audit entries are the calls themselves and
        // read-failure records (report_input_failed — the backup
        // query naming its dead facts provider on-chain, per the
        // adapter's honesty rule). No query wrote fleet state:
        // no inventory, health, or policy entry kinds appear.
        var newKinds = rig.Audit.Entries.Skip(auditKindsBefore).Select(e => e.Kind).Distinct().ToList();
        Assert.All(newKinds, k => Assert.True(k is "fleet_mcp_call" or "report_input_failed",
            $"query tools produced an unexpected audit kind: {k}"));
    }

    [Fact]
    public void FleetMcp_EscalationBattery()
    {
        var rig = Rmm13Tests.NewRig();
        rig.Service.FleetMcp.RegisterAction("fleet.reboot_device", "Reboot (fake executor)");
        var readOnly = new HashSet<string> { FleetScopes.Read };
        var actScopes = new HashSet<string> { FleetScopes.Read, FleetScopes.Act };

        // 1. Read-only scope + a VALID grant: still refused (scope first).
        var (_, _, grant) = rig.Service.GrantFleetApproval("fleet.reboot_device", "alice", "bob", TimeSpan.FromMinutes(10));
        Assert.False(rig.Service.CallFleetTool(Rmm13Tests.Facts(), "fleet.reboot_device", "{}", readOnly, grant!.GrantId, "attacker").Ok);
        Assert.Empty(rig.FleetActions.Executed);

        // 2. One approver twice is not dual control.
        Assert.False(rig.Service.GrantFleetApproval("fleet.reboot_device", "alice", "alice", TimeSpan.FromMinutes(10)).Ok);
        Assert.False(rig.Service.GrantFleetApproval("fleet.reboot_device", "alice", "ALICE", TimeSpan.FromMinutes(10)).Ok);

        // 3. A grant for a DIFFERENT action does not open this one.
        var (_, _, otherGrant) = rig.Service.GrantFleetApproval("fleet.other_action", "alice", "bob", TimeSpan.FromMinutes(10));
        Assert.False(rig.Service.CallFleetTool(Rmm13Tests.Facts(), "fleet.reboot_device", "{}", actScopes, otherGrant!.GrantId, "attacker").Ok);

        // 4. Expired grant refuses.
        var (_, _, staleGrant) = rig.Service.GrantFleetApproval("fleet.reboot_device", "alice", "bob", TimeSpan.FromMinutes(5));
        rig.Clock.Now = T0.AddMinutes(30);
        Assert.False(rig.Service.CallFleetTool(Rmm13Tests.Facts(), "fleet.reboot_device", "{}", actScopes, staleGrant!.GrantId, "attacker").Ok);
        rig.Clock.Now = T0;

        // 5. The genuine path executes ONCE; replaying the same
        //    grant refuses (single-use), even though it worked before.
        var (_, _, realGrant) = rig.Service.GrantFleetApproval("fleet.reboot_device", "alice", "bob", TimeSpan.FromMinutes(10));
        Assert.True(rig.Service.CallFleetTool(Rmm13Tests.Facts(), "fleet.reboot_device", "{}", actScopes, realGrant!.GrantId, "operator").Ok);
        Assert.Single(rig.FleetActions.Executed);
        Assert.False(rig.Service.CallFleetTool(Rmm13Tests.Facts(), "fleet.reboot_device", "{}", actScopes, realGrant.GrantId, "attacker").Ok);
        Assert.Single(rig.FleetActions.Executed);

        // 6. Query tools refuse callers without fleet_read.
        Assert.False(rig.Service.CallFleetTool(Rmm13Tests.Facts(), "fleet.health", "", new HashSet<string>(), null, "attacker").Ok);
    }

    // ---- export injection ---------------------------------------------------------

    [Fact]
    public void Export_CsvFormulaInjectionFromDeviceNamesIsNeutralised()
    {
        // A hostile device name that IS a spreadsheet formula must
        // export as inert text in every row it touches.
        var views = new[]
        {
            new DeviceHealthView("=2+5+cmd|'/C calc'!A0", DeviceHealthStates.Alerting, T0, 1, Array.Empty<string>(), "+SUM(1+1)"),
            new DeviceHealthView("@evil", DeviceHealthStates.Healthy, T0, 1, Array.Empty<string>(), "-2+3"),
            new DeviceHealthView("plain-device", DeviceHealthStates.Healthy, T0, 1, Array.Empty<string>(), "ok"),
        };
        var report = ReportBuilders.FleetHealth(views, "scope1", T0);
        var csv = ReportExporter.Export(report, ReportExportFormats.Csv, T0);
        Assert.Contains("'=2+5+cmd", csv);
        Assert.Contains("'@evil", csv);
        Assert.Contains("'-2+3", csv);
        foreach (var line in csv.Split("\r\n"))
        {
            var firstCell = line.Split(',')[0];
            Assert.False(firstCell.StartsWith("=") || firstCell.StartsWith("+") ||
                         firstCell.StartsWith("@") || firstCell.StartsWith("-2"),
                $"CSV line begins with a live formula cell: {line}");
        }
        // Cell-level: every formula leader is defused, ordinary text untouched.
        Assert.Equal("'=x", ReportExporter.CsvCell("=x"));
        Assert.Equal("'+x", ReportExporter.CsvCell("+x"));
        Assert.Equal("'-x", ReportExporter.CsvCell("-x"));
        Assert.Equal("'@x", ReportExporter.CsvCell("@x"));
        Assert.Equal("'\tx", ReportExporter.CsvCell("\tx"));
        Assert.Equal("plain", ReportExporter.CsvCell("plain"));
        Assert.Equal("\"a,b\"", ReportExporter.CsvCell("a,b"));
    }

    // ---- breaks found by this pass, fixed, regression-tested -------------------------

    [Fact]
    public void Regression_ValidScheduledDestinationAdmits()
    {
        // BREAK (found by this lane's first run): Validate() used
        // `Destination?.Validate() ?? refusal` — a destination that
        // validated CLEAN (null) was refused as "no destination".
        // Every scheduled report was undeletable-by-definition.
        // Fixed by separating the null check from the verdict.
        var def = new ScheduledReportDefinition("ok", ReportKinds.FleetHealth, "json", 24,
            new ReportDestination(ReportDestinationKinds.LocalPath, @"C:\acp-reports"), true, "admin");
        Assert.Null(def.Validate());
        var rig = Rmm13Tests.NewRig();
        Assert.True(rig.Service.DefineScheduled(Rmm13Tests.Facts(), def).Ok);
    }

    [Fact]
    public void Regression_ThrowingBackupFactsProviderCannotKillTheReport()
    {
        // BREAK: one device whose facts provider throws took down
        // the whole backup report (and the fleet.backup_status MCP
        // query with it). Fixed in the service adapter: the device
        // is omitted, the builder renders its explicit no-facts
        // row, and the failure is a chained audit event.
        var rig = Rmm13Tests.NewRig(); // FakeBackupFacts knows NO devices → throws for all
        rig.Inventory.ApplyBaseline(Rmm13Tests.Record("dev1"), T0);
        var (ok, _, report) = rig.Service.Generate(Rmm13Tests.Facts(), ReportKinds.BackupStatus);
        Assert.True(ok);
        Assert.Equal(1, report!.Counts["no_facts"]);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "report_input_failed" && e.Detail.Contains("dev1"));
        var mcp = rig.Service.CallFleetTool(Rmm13Tests.Facts(), "fleet.backup_status", "",
            new HashSet<string> { FleetScopes.Read }, null, "tester");
        Assert.True(mcp.Ok, mcp.Outcome);
    }

    // ---- local-model output forgery -------------------------------------------------

    [Fact]
    public void LocalModel_TamperedOutputsFailVerification()
    {
        var rig = Rmm13Tests.NewRig(new FakeLocalModel());
        Rmm13Tests.SetPolicy(rig, "scope1", ReportingPolicyKeys.LocalModelEnabled, "true", 555);
        var (ok, _, output) = rig.Service.RunLocalModel(Rmm13Tests.Facts(), LocalModelTaskKinds.SessionSummary, "session 42", "tester");
        Assert.True(ok);
        var key = rig.Signer.PublicKey;
        Assert.True(LocalModelRunner.Verify(output, key));
        Assert.False(LocalModelRunner.Verify(output! with { Output = "a summary the model never wrote" }, key));
        Assert.False(LocalModelRunner.Verify(output! with { PromptHash = SignedModelOutput.HashPrompt("a different prompt") }, key));
        Assert.False(LocalModelRunner.Verify(output! with { TaskKind = LocalModelTaskKinds.Worklog }, key));
        Assert.False(LocalModelRunner.Verify(null, key));
        // Unknown task kinds refuse at the runner.
        Assert.False(rig.Service.RunLocalModel(Rmm13Tests.Facts(), "shell_exec", "rm -rf", "attacker").Ok);
    }
}
