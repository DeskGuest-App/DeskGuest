using System.Text;
using Acp.Core.Services;
using Acp.Shared.Enterprise;
using Acp.Shared.Inventory;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Monitoring;
using Acp.Shared.Security;

namespace Acp.Tests;

// RMM-01 — Continuous endpoint health monitoring + threshold
// alerting: on-endpoint evaluation, tuned condition library,
// maintenance windows, alert lifecycle, per-condition actions,
// warranty consumption, hub ingest + device-down.
public class Rmm01Tests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    private const string Dev = "dev-1";
    private const string Scope = "co-1";

    // ---- fixtures ------------------------------------------------------

    private sealed class Rig
    {
        public DateTimeOffset Now = T0;
        public ChainedAuditLog Audit = new();
        public AlertCenter Dir57 = new();
        public HealthAlertCentre Centre;
        public ManagementPolicyEngine Policy = new();
        public StaticDeviceFacts Facts = StaticDeviceFacts.Of(Dev, Scope);
        public RecordingWorkItemSink WorkItems = new();
        public RecordingRemediationSink Remediation = new();
        public EndpointMonitorService Service = null!;

        public Rig(IHealthCollector collector, SignedCommandGate? gate = null,
            Func<DateTimeOffset, IReadOnlyList<WarrantyAlertEvent>>? warranty = null,
            Func<DateTimeOffset, IReadOnlyList<SerialConflictAlertEvent>>? serialConflicts = null)
        {
            Centre = new HealthAlertCentre(Audit, Dir57);
            Service = new EndpointMonitorService(Dev, Facts, Policy, collector, Centre, Audit,
                gate, WorkItems, Remediation, () => Now, warranty, serialConflicts);
        }

        public void DisablePolicy(string key)
        {
            Policy.AddDocument(new ManagementPolicyDocument(
                $"doc-{key}", PolicyLevels.Org, Scope,
                new Dictionary<string, string> { [key] = "false" }, 1));
        }
    }

    private static EndpointSample Sample(
        double? cpu = null, double? ram = null,
        IReadOnlyList<DiskSample>? disks = null,
        IReadOnlyList<ServiceSample>? services = null,
        IReadOnlyList<ProcessSample>? processes = null,
        IReadOnlyList<AppSample>? apps = null,
        IReadOnlyList<EventLogSample>? events = null,
        SecurityStateSample? security = null,
        TimeSpan? uptime = null,
        IReadOnlyList<GuestSample>? guests = null,
        DateTimeOffset? at = null) => new(
            Dev, at ?? T0, cpu, ram,
            disks ?? Array.Empty<DiskSample>(),
            services ?? Array.Empty<ServiceSample>(),
            processes ?? Array.Empty<ProcessSample>(),
            apps ?? Array.Empty<AppSample>(),
            events ?? Array.Empty<EventLogSample>(),
            security, uptime,
            guests ?? Array.Empty<GuestSample>(),
            Array.Empty<string>());

    private static DiskSample Disk(string name, double freePct, string? smart = "OK", bool? predictive = false)
    {
        const long total = 100_000_000_000;
        return new DiskSample(name, (long)(total * freePct / 100.0), total, smart, predictive);
    }

    private static MonitorCondition Cond(string id, string kind, string severity = AlertSeverities.Warning,
        string? target = null, double? pct = null, int consecutive = 1, AlertActions? actions = null,
        int? eventId = null, long? seconds = null) =>
        MonitorCondition.Create(id, id, kind, severity, target: target, thresholdPercent: pct,
            consecutiveSamples: consecutive, actions: actions, eventId: eventId, thresholdSeconds: seconds,
            cooldown: TimeSpan.FromMinutes(5));

    private static ConditionLibrary Library(params MonitorCondition[] conditions) =>
        new("test-lib", 1, conditions);

    // ---- evaluator -------------------------------------------------------

    [Fact]
    public void Evaluator_DiskLow_FiresAtThreshold_AndGapsWithoutReading()
    {
        var c = Cond("d", ConditionKinds.DiskLow, pct: 10, target: "*");
        Assert.Equal(ConditionOutcome.Firing,
            ConditionEvaluator.Evaluate(c, Sample(disks: new[] { Disk("C:", 8) })).Outcome);
        Assert.Equal(ConditionOutcome.Clear,
            ConditionEvaluator.Evaluate(c, Sample(disks: new[] { Disk("C:", 40) })).Outcome);
        // No disk reading at all: indeterminate — never a guess.
        Assert.Equal(ConditionOutcome.Indeterminate,
            ConditionEvaluator.Evaluate(c, Sample()).Outcome);
    }

    [Fact]
    public void Evaluator_ServiceSecurityEventLogAndGuestKinds()
    {
        var svc = Cond("s", ConditionKinds.ServiceStopped, target: "Niagara");
        Assert.Equal(ConditionOutcome.Firing, ConditionEvaluator.Evaluate(svc,
            Sample(services: new[] { new ServiceSample("Niagara", "Stopped") })).Outcome);
        Assert.Equal(ConditionOutcome.Firing, ConditionEvaluator.Evaluate(svc,
            Sample(services: new[] { new ServiceSample("Other", "Running") })).Outcome); // missing = firing
        Assert.Equal(ConditionOutcome.Clear, ConditionEvaluator.Evaluate(svc,
            Sample(services: new[] { new ServiceSample("Niagara", "Running") })).Outcome);
        Assert.Equal(ConditionOutcome.Indeterminate, ConditionEvaluator.Evaluate(svc, Sample()).Outcome);

        var av = Cond("av", ConditionKinds.SecurityAvOff, severity: AlertSeverities.Critical);
        Assert.Equal(ConditionOutcome.Firing, ConditionEvaluator.Evaluate(av,
            Sample(security: new SecurityStateSample(false, true, true))).Outcome);
        Assert.Equal(ConditionOutcome.Indeterminate, ConditionEvaluator.Evaluate(av, Sample()).Outcome);

        var ev = Cond("ev", ConditionKinds.EventLogMatch, target: "Application Error", eventId: 1000);
        Assert.Equal(ConditionOutcome.Firing, ConditionEvaluator.Evaluate(ev,
            Sample(events: new[] { new EventLogSample("Application Error", 1000, "Error", T0, "crashed") })).Outcome);
        Assert.Equal(ConditionOutcome.Clear, ConditionEvaluator.Evaluate(ev,
            Sample(events: new[] { new EventLogSample("Application Error", 1001, "Error", T0, "other") })).Outcome);

        var guest = Cond("g", ConditionKinds.GuestDown, target: "*");
        Assert.Equal(ConditionOutcome.Firing, ConditionEvaluator.Evaluate(guest,
            Sample(guests: new[] { new GuestSample("vm-1", "Stopped") })).Outcome);
        Assert.Equal(ConditionOutcome.Clear, ConditionEvaluator.Evaluate(guest,
            Sample(guests: new[] { new GuestSample("vm-1", "Running") })).Outcome);
    }

    [Fact]
    public void Evaluator_SmartAndPredictive_GapWhenUnread_NeverFabricated()
    {
        var smart = Cond("smart", ConditionKinds.DiskSmartFailure, target: "*");
        Assert.Equal(ConditionOutcome.Indeterminate, ConditionEvaluator.Evaluate(smart,
            Sample(disks: new[] { Disk("C:", 50, smart: null) })).Outcome);
        Assert.Equal(ConditionOutcome.Firing, ConditionEvaluator.Evaluate(smart,
            Sample(disks: new[] { Disk("C:", 50, smart: "Failed") })).Outcome);
        var pred = Cond("pred", ConditionKinds.DiskPredictiveFailure, target: "*");
        Assert.Equal(ConditionOutcome.Firing, ConditionEvaluator.Evaluate(pred,
            Sample(disks: new[] { Disk("C:", 50, predictive: true) })).Outcome);
        Assert.Equal(ConditionOutcome.Indeterminate, ConditionEvaluator.Evaluate(pred,
            Sample(disks: new[] { Disk("C:", 50, predictive: null) })).Outcome);
    }

    // ---- default library ---------------------------------------------------

    [Fact]
    public void DefaultLibrary_IsValid_Tuned_AndBasTemplateShipsDisabled()
    {
        var lib = ConditionLibrary.Default();
        Assert.Null(lib.Validate());
        Assert.Contains(lib.Conditions, c => c.Id == "disk-smart-failure" && c.Severity == AlertSeverities.Critical);
        Assert.Contains(lib.Conditions, c => c.Id == "security-av-off");
        Assert.Contains(lib.Conditions, c => c.Id == "eventlog-application-crash" && c.EventId == 1000);
        var bas = lib.Conditions.Single(c => c.Id == "bas-jace-service");
        Assert.False(bas.Enabled); // site fact (service name) is never guessed
        Assert.Equal(ConditionKinds.ServiceStopped, bas.Kind);
        // CPU/RAM are debounced; SMART and security are not.
        Assert.Equal(3, lib.Conditions.Single(c => c.Id == "cpu-sustained-high").ConsecutiveSamples);
        Assert.Equal(1, lib.Conditions.Single(c => c.Id == "disk-smart-failure").ConsecutiveSamples);
        // Canonical JSON round-trips byte-identically (the signed payload shape).
        var round = ConditionLibrary.FromCanonicalJson(lib.ToCanonicalJson());
        Assert.NotNull(round);
        Assert.Equal(lib.ContentHash, round!.ContentHash);
    }

    // ---- the cycle ---------------------------------------------------------

    [Fact]
    public void Cycle_DiskLow_RaisesAlert_MirroredToDir57_AndChained()
    {
        var collector = new FakeHealthCollector(
            Sample(disks: new[] { Disk("C:", 50) }),
            Sample(disks: new[] { Disk("C:", 7) }));
        var rig = new Rig(collector);
        rig.Service.AdmitLocalLibrary(Library(
            Cond("disk-low", ConditionKinds.DiskLow, pct: 10, target: "*",
                actions: new AlertActions(true, true, null))), "test");

        var ok = rig.Service.RunCycle();
        Assert.Empty(ok.NewAlerts);
        var bad = rig.Service.RunCycle();
        Assert.Single(bad.NewAlerts);
        Assert.Contains("disk-low", bad.FiringConditionIds);
        var alert = bad.NewAlerts[0];
        Assert.Equal(HealthAlertStates.Raised, alert.State);
        Assert.Contains(rig.Dir57.Alerts, a => a.EventClass == "endpoint_health");
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "health_alert_raised");
        Assert.True(rig.Audit.Verify().Ok);
        // Work-item action fired on the new alert.
        Assert.Single(rig.WorkItems.Opened);
    }

    [Fact]
    public void Cycle_Dedup_RepeatedFiringRefreshesOneAlert()
    {
        var low = Sample(disks: new[] { Disk("C:", 5) });
        var rig = new Rig(new FakeHealthCollector(low));
        rig.Service.AdmitLocalLibrary(Library(Cond("disk-low", ConditionKinds.DiskLow, pct: 10, target: "*")), "test");
        rig.Service.RunCycle();
        rig.Now = T0.AddMinutes(1);
        var second = rig.Service.RunCycle();
        Assert.Empty(second.NewAlerts); // refreshed, not duplicated
        var active = rig.Centre.ActiveAlerts;
        Assert.Single(active);
        Assert.Equal(2, active[0].OccurrenceCount);
    }

    [Fact]
    public void Cycle_AutoReset_WhenConditionClears_AndWorkItemCloses()
    {
        var rig = new Rig(new FakeHealthCollector(
            Sample(disks: new[] { Disk("C:", 5) }),
            Sample(disks: new[] { Disk("C:", 60) })));
        rig.Service.AdmitLocalLibrary(Library(
            Cond("disk-low", ConditionKinds.DiskLow, pct: 10, target: "*",
                actions: new AlertActions(true, true, null))), "test");
        rig.Service.RunCycle();
        Assert.Single(rig.Centre.ActiveAlerts);
        var cleared = rig.Service.RunCycle();
        Assert.Single(cleared.AutoResetAlerts);
        Assert.Empty(rig.Centre.ActiveAlerts);
        Assert.Single(rig.WorkItems.Closed);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "health_alert_reset");
    }

    [Fact]
    public void Cycle_Debounce_CpuNeedsConsecutiveSamples()
    {
        var hot = Sample(cpu: 99, disks: new[] { Disk("C:", 80) });
        var rig = new Rig(new FakeHealthCollector(hot));
        rig.Service.AdmitLocalLibrary(Library(
            Cond("cpu", ConditionKinds.CpuHigh, pct: 90, consecutive: 3)), "test");
        Assert.Empty(rig.Service.RunCycle().NewAlerts);
        Assert.Empty(rig.Service.RunCycle().NewAlerts);
        Assert.Single(rig.Service.RunCycle().NewAlerts);
    }

    [Fact]
    public void Cycle_PolicyDisabled_NoSampling_AuditedOnce()
    {
        var collector = new FakeHealthCollector(Sample(cpu: 99));
        var rig = new Rig(collector);
        rig.DisablePolicy(MonitoringPolicyKeys.MonitoringEnabled);
        var r1 = rig.Service.RunCycle();
        var r2 = rig.Service.RunCycle();
        Assert.False(r1.MonitorEnabled);
        Assert.False(r2.MonitorEnabled);
        Assert.Equal(0, collector.CallCount); // the endpoint is not even sampled
        Assert.Single(rig.Audit.Entries, e => e.Kind == "monitoring_disabled");
        Assert.Empty(rig.Centre.Alerts);
    }

    [Fact]
    public void Cycle_AcknowledgeLifecycle_AndManualReset()
    {
        var rig = new Rig(new FakeHealthCollector(Sample(disks: new[] { Disk("C:", 5) })));
        rig.Service.AdmitLocalLibrary(Library(Cond("disk-low", ConditionKinds.DiskLow, pct: 10, target: "*")), "test");
        var alert = rig.Service.RunCycle().NewAlerts.Single();
        Assert.True(rig.Centre.Acknowledge(alert.AlertId, "tech-1", T0.AddMinutes(5)));
        Assert.Equal(HealthAlertStates.Acknowledged, rig.Centre.Get(alert.AlertId)!.State);
        Assert.False(rig.Centre.Acknowledge("no-such-alert", "tech-1", T0));
        var reset = rig.Centre.Reset(alert.AlertId, "tech-1", "disk replaced", T0.AddHours(1));
        Assert.NotNull(reset);
        Assert.Equal(HealthAlertStates.Reset, rig.Centre.Get(alert.AlertId)!.State);
        Assert.True(rig.Audit.Verify().Ok);
    }

    // ---- actions ------------------------------------------------------------

    [Fact]
    public void Actions_RemediationDispatched_WhenPolicyAllows()
    {
        var rig = new Rig(new FakeHealthCollector(
            Sample(services: new[] { new ServiceSample("Niagara", "Stopped") })));
        rig.Service.AdmitLocalLibrary(Library(
            Cond("svc", ConditionKinds.ServiceStopped, target: "Niagara",
                actions: new AlertActions(true, false, "restart-service"))), "test");
        rig.Service.RunCycle();
        Assert.Single(rig.Remediation.Dispatches);
        Assert.Equal("restart-service", rig.Remediation.Dispatches[0].RemediationId);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "health_action_fired");
    }

    [Fact]
    public void Actions_PolicyGated_WorkItemAndRemediationSkippedWhenDisabled()
    {
        var rig = new Rig(new FakeHealthCollector(
            Sample(services: new[] { new ServiceSample("Niagara", "Stopped") })));
        rig.Service.AdmitLocalLibrary(Library(
            Cond("svc", ConditionKinds.ServiceStopped, target: "Niagara",
                actions: new AlertActions(true, true, "restart-service"))), "test");
        rig.DisablePolicy(MonitoringPolicyKeys.WorkItemsEnabled);
        rig.DisablePolicy(MonitoringPolicyKeys.RemediationEnabled);
        var result = rig.Service.RunCycle();
        Assert.Single(result.NewAlerts); // the alert itself still raises + notifies
        Assert.Empty(rig.WorkItems.Opened);
        Assert.Empty(rig.Remediation.Dispatches);
        Assert.Equal(2, rig.Audit.Entries.Count(e => e.Kind == "health_action_skipped"));
    }

    // ---- maintenance windows -------------------------------------------------

    [Fact]
    public void MaintenanceWindow_SuppressesCoveredAlert_AndSuppressionIsAudited()
    {
        var rig = new Rig(new FakeHealthCollector(Sample(disks: new[] { Disk("C:", 5) })));
        rig.Service.AdmitLocalLibrary(Library(Cond("disk-low", ConditionKinds.DiskLow, pct: 10, target: "*")), "test");
        var (accepted, _) = rig.Centre.AddWindow(new MaintenanceWindow(
            "w1", Dev, T0, T0.AddHours(4), "planned disk swap", "admin-1", T0), T0);
        Assert.True(accepted);
        var result = rig.Service.RunCycle();
        Assert.Equal(1, result.SuppressedCount);
        Assert.Empty(result.NewAlerts);
        Assert.Empty(rig.Centre.ActiveAlerts);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "maintenance_window_created");
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "health_alert_suppressed");
        Assert.True(rig.Audit.Verify().Ok); // the window never suppressed the audit
    }

    // ---- warranty consumption ---------------------------------------------------

    [Fact]
    public void WarrantyAlerts_ConsumedIntoSameCentre_ExpiredSupersedesExpiring()
    {
        var expiring = new WarrantyAlertEvent(Dev, "ABC1234", "dell",
            WarrantyAlertEvent.KindExpiring, WarrantyAlertEvent.SeverityWarning,
            T0.AddDays(20), 20, T0);
        var expired = expiring with
        {
            Kind = WarrantyAlertEvent.KindExpired, Severity = WarrantyAlertEvent.SeverityExpired,
            DaysRemaining = -3,
        };
        var queue = new Queue<IReadOnlyList<WarrantyAlertEvent>>(new IReadOnlyList<WarrantyAlertEvent>[]
        {
            new[] { expiring }, new[] { expired },
        });
        var rig = new Rig(new FakeHealthCollector(Sample(cpu: 10)),
            warranty: _ => queue.Count > 0 ? queue.Dequeue() : Array.Empty<WarrantyAlertEvent>());
        rig.Service.AdmitLocalLibrary(Library(Cond("cpu", ConditionKinds.CpuHigh, pct: 95)), "test");

        rig.Service.RunCycle();
        var active1 = rig.Centre.ActiveAlerts;
        Assert.Single(active1);
        Assert.Equal(ConditionKinds.Warranty, active1[0].Kind);
        Assert.Contains(rig.Dir57.Alerts, a => a.EventClass == "warranty");

        rig.Service.RunCycle();
        var active2 = rig.Centre.ActiveAlerts;
        Assert.Single(active2); // expired superseded the expiring warning
        Assert.Equal(AlertSeverities.Critical, active2[0].Severity);
    }

    // ---- serial-conflict consumption (RMM-04 D38-F5(d)) -------------------------

    [Fact]
    public void SerialConflicts_FromRealStore_RaisePerDevice_AndAutoResetWhenResolved()
    {
        // Two devices claiming one serial in the REAL inventory store.
        var store = new InventoryStore();
        HardwareSnapshot Hw() => new(
            Manufacturer: "Dell Inc.", Model: "OptiPlex 7010", SerialNumber: "ABC1234",
            CpuModel: "Intel i7", CpuCores: 8, RamBytes: 16_000_000_000,
            OsName: "Windows 11 Pro", OsBuild: "26100.1", OsVersion: "10.0.26100",
            BiosVersion: null, Disks: Array.Empty<DiskInfo>(), Peripherals: Array.Empty<PeripheralInfo>(),
            CollectedUtc: T0);
        DeviceInventoryRecord Rec(string id) => new(
            id, Scope, id, Hw(), Array.Empty<SoftwareItem>(),
            new Dictionary<string, string>(), new HashSet<string>(), T0, T0, T0, 0);
        Assert.True(store.ApplyBaseline(Rec("dev-1"), T0).Accepted);
        Assert.True(store.ApplyBaseline(Rec("dev-2"), T0).Accepted);

        var rig = new Rig(new FakeHealthCollector(Sample(cpu: 5)),
            serialConflicts: now => store.CollectSerialConflictAlerts(now));
        rig.Service.AdmitLocalLibrary(Library(Cond("cpu", ConditionKinds.CpuHigh, pct: 95)), "test");

        var first = rig.Service.RunCycle();
        var conflicts = first.NewAlerts.Where(a => a.Kind == ConditionKinds.SerialConflict).ToList();
        Assert.Equal(2, conflicts.Count); // one per claiming device
        Assert.Contains(conflicts, a => a.DeviceId == "dev-1");
        Assert.Contains(conflicts, a => a.DeviceId == "dev-2");
        Assert.Contains("ABC1234", conflicts[0].Detail);

        // Re-ingesting the same conflict dedups — no new alerts.
        var second = rig.Service.RunCycle();
        Assert.DoesNotContain(second.NewAlerts, a => a.Kind == ConditionKinds.SerialConflict);
        Assert.Equal(2, rig.Centre.ActiveAlerts.Count(a => a.Kind == ConditionKinds.SerialConflict));

        // The store stops reporting the conflict (one device removed):
        // the next cycle auto-resets both alerts.
        Assert.True(store.Remove("dev-2"));
        rig.Service.RunCycle();
        Assert.DoesNotContain(rig.Centre.ActiveAlerts, a => a.Kind == ConditionKinds.SerialConflict);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "health_alert_reset" && e.Detail.Contains("serial conflict"));
    }

    // ---- signed library delivery ------------------------------------------------

    private static (Rig Rig, SignedCommandSigner Signer) SignedRig()
    {
        var customer = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var audit = new ChainedAuditLog();
        var ring = new CustomerCommandKeyRing();
        ring.AddCurrent(customer.PublicKey);
        var gate = new SignedCommandGate(new SignedCommandVerifier(ring), audit);
        var rig = new Rig(new FakeHealthCollector(Sample(cpu: 1)), gate);
        // Rebuild the rig around the SAME audit the gate writes to.
        rig.Audit = audit;
        rig.Centre = new HealthAlertCentre(audit, rig.Dir57);
        rig.Service = new EndpointMonitorService(Dev, rig.Facts, rig.Policy,
            new FakeHealthCollector(Sample(cpu: 1)), rig.Centre, audit, gate,
            rig.WorkItems, rig.Remediation, () => rig.Now);
        return (rig, new SignedCommandSigner(customer));
    }

    [Fact]
    public void SignedLibrary_ValidEnvelope_Admitted()
    {
        var (rig, signer) = SignedRig();
        var lib = Library(Cond("x", ConditionKinds.CpuHigh, pct: 50)) with { Id = "site-lib", Revision = 7 };
        var env = signer.Sign(SignedCommandClasses.PolicyDelivery,
            Encoding.UTF8.GetBytes(lib.ToCanonicalJson()), T0, TimeSpan.FromMinutes(5));
        var verdict = rig.Service.ApplySignedLibrary(env);
        Assert.True(verdict.Allowed, verdict.Reason);
        Assert.Equal("site-lib", rig.Service.Library.Id);
        Assert.Equal(7, rig.Service.Library.Revision);
    }

    [Fact]
    public void SignedLibrary_NoGate_RefusesNamed()
    {
        var rig = new Rig(new FakeHealthCollector(Sample()));
        var verdict = rig.Service.ApplySignedLibrary(null);
        Assert.False(verdict.Allowed);
        Assert.Contains("no customer command key", verdict.Reason);
    }

    // ---- hub ingest + device-down --------------------------------------------

    [Fact]
    public void Hub_UnknownDevice_IsUnknownNeverHealthy_ThenReportsFlow()
    {
        var audit = new ChainedAuditLog();
        var centre = new HealthAlertCentre(audit, new AlertCenter());
        var hub = new HubHealthIngest(centre, TimeSpan.FromMinutes(15));
        Assert.Equal(DeviceHealthStates.Unknown, hub.View("ghost", T0).State);

        var rig = new Rig(new FakeHealthCollector(Sample(cpu: 10, disks: new[] { Disk("C:", 80) })));
        rig.Service.AdmitLocalLibrary(Library(Cond("cpu", ConditionKinds.CpuHigh, pct: 95)), "test");
        rig.Service.RunCycle();
        var report = rig.Service.BuildReport();
        var (ok, _) = hub.Ingest(report, T0);
        Assert.True(ok);
        Assert.Equal(DeviceHealthStates.Healthy, hub.View(Dev, T0).State);
    }

    [Fact]
    public void Hub_SilenceBecomesDown_DownAlertRaised_ReturnAutoResets()
    {
        var audit = new ChainedAuditLog();
        var centre = new HealthAlertCentre(audit, new AlertCenter());
        var hub = new HubHealthIngest(centre, TimeSpan.FromMinutes(15));
        var rig = new Rig(new FakeHealthCollector(Sample(cpu: 10)));
        rig.Service.AdmitLocalLibrary(Library(Cond("cpu", ConditionKinds.CpuHigh, pct: 95)), "test");
        rig.Service.RunCycle();
        Assert.True(hub.Ingest(rig.Service.BuildReport(), T0).Accepted);

        var later = T0.AddMinutes(20);
        Assert.Equal(DeviceHealthStates.Down, hub.View(Dev, later).State); // silence != healthy
        var newly = hub.SweepDeviceDown(later);
        Assert.Contains(Dev, newly);
        Assert.Contains(centre.ActiveAlerts, a => a.Kind == ConditionKinds.DeviceDown);

        // The device returns: next report clears the down state + alert.
        rig.Now = later;
        rig.Service.RunCycle();
        Assert.True(hub.Ingest(rig.Service.BuildReport(), later).Accepted);
        Assert.Equal(DeviceHealthStates.Healthy, hub.View(Dev, later).State);
        Assert.DoesNotContain(centre.ActiveAlerts, a => a.Kind == ConditionKinds.DeviceDown);
    }

    [Fact]
    public void Report_CarriesLibraryIdentityAndMonotonicSeq()
    {
        var rig = new Rig(new FakeHealthCollector(Sample(cpu: 1)));
        var r1 = rig.Service.BuildReport();
        var r2 = rig.Service.BuildReport();
        Assert.True(r2.Seq > r1.Seq);
        Assert.Equal(ConditionLibrary.Default().Id, r1.LibraryId);
        Assert.Equal(ConditionLibrary.Default().ContentHash, r1.LibraryHash);
        Assert.Equal(MonitorStatuses.Ok, r1.MonitorStatus);
    }

    [Fact]
    public void RuntimeCollector_ReadsHonestly_NamesWhatItCannot()
    {
        var collector = RuntimeHealthCollector.Create();
        var sample = collector.Collect(Dev, T0);
        Assert.NotNull(sample.Uptime);
        // CPU/RAM/SMART/security are host wiring: absent + named, never invented.
        Assert.Null(sample.CpuPercent);
        Assert.Contains(sample.CollectorNotes, n => n.Contains("not_read"));
        Assert.All(sample.Disks, d => Assert.Null(d.SmartStatus));
    }
}
