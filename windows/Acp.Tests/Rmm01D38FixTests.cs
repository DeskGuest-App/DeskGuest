using System.Text;
using Acp.Core.Services;
using Acp.Shared.Enterprise;
using Acp.Shared.Inventory;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Monitoring;
using Acp.Shared.Security;

namespace Acp.Tests;

// RMM-01 D38 FIX (packet 1ef85c62) — regression tests for the twelve
// cross-review findings. Every test here pins a CONFIRMED defect:
// each fails against the pre-fix code and passes after it (verdicts
// + evidence in ~/workspace/builds/rmm-r-logs/log-rmm01-fix.md).
public class Rmm01D38FixTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    private const string Dev = "dev-1";
    private const string Scope = "co-1";

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

        public Rig(IHealthCollector collector, SignedCommandGate? gate = null)
        {
            Centre = new HealthAlertCentre(Audit, Dir57);
            Service = new EndpointMonitorService(Dev, Facts, Policy, collector, Centre, Audit,
                gate, WorkItems, Remediation, () => Now);
        }

        public void DisablePolicy(string key)
        {
            Policy.AddDocument(new ManagementPolicyDocument(
                $"doc-{key}", PolicyLevels.Org, Scope,
                new Dictionary<string, string> { [key] = "false" }, 1));
        }
    }

    private static (Rig Rig, SignedCommandSigner Signer) SignedRig()
    {
        var customer = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var audit = new ChainedAuditLog();
        var ring = new CustomerCommandKeyRing();
        ring.AddCurrent(customer.PublicKey);
        var gate = new SignedCommandGate(new SignedCommandVerifier(ring), audit);
        var rig = new Rig(new FakeHealthCollector(Sample(cpu: 1)), gate);
        rig.Audit = audit;
        rig.Centre = new HealthAlertCentre(audit, rig.Dir57);
        rig.Service = new EndpointMonitorService(Dev, rig.Facts, rig.Policy,
            new FakeHealthCollector(Sample(cpu: 1)), rig.Centre, audit, gate,
            rig.WorkItems, rig.Remediation, () => rig.Now);
        return (rig, new SignedCommandSigner(customer));
    }

    private static EndpointSample Sample(
        double? cpu = null,
        IReadOnlyList<DiskSample>? disks = null,
        IReadOnlyList<EventLogSample>? events = null,
        SecurityStateSample? security = null,
        IReadOnlyList<string>? notes = null) => new(
            Dev, T0, cpu, null,
            disks ?? Array.Empty<DiskSample>(),
            Array.Empty<ServiceSample>(), Array.Empty<ProcessSample>(), Array.Empty<AppSample>(),
            events ?? Array.Empty<EventLogSample>(),
            security, null, Array.Empty<GuestSample>(),
            notes ?? Array.Empty<string>());

    private static DiskSample Disk(double freePct)
    {
        const long total = 100_000_000_000;
        return new DiskSample("C:", (long)(total * freePct / 100.0), total, "OK", false);
    }

    private static MonitorCondition Cond(string id, string kind, string severity = AlertSeverities.Warning,
        string? target = null, double? pct = null, int consecutive = 1, AlertActions? actions = null,
        int? eventId = null) =>
        MonitorCondition.Create(id, id, kind, severity, target: target, thresholdPercent: pct,
            consecutiveSamples: consecutive, actions: actions, eventId: eventId,
            cooldown: TimeSpan.FromMinutes(5));

    private static ConditionLibrary Library(params MonitorCondition[] conditions) =>
        new("test-lib", 1, conditions);

    private static SignedCommandEnvelope Sign(SignedCommandSigner signer, ConditionLibrary lib, DateTimeOffset at) =>
        signer.Sign(SignedCommandClasses.PolicyDelivery,
            Encoding.UTF8.GetBytes(lib.ToCanonicalJson()), at, TimeSpan.FromMinutes(5));

    // ---- F1: eventlog_match on a never-read section -------------------

    [Fact]
    public void F1_EventLogNotRead_EvaluatesIndeterminate_NeverClear()
    {
        var ev = Cond("ev", ConditionKinds.EventLogMatch, target: "Application Error", eventId: 1000);
        // Section never read (empty list — the shape RuntimeHealthCollector
        // produces, since it leaves the EventLog delegate unset).
        Assert.Equal(ConditionOutcome.Indeterminate,
            ConditionEvaluator.Evaluate(ev, Sample(notes: new[] { "not_read:eventlog" })).Outcome);
        Assert.Equal(ConditionOutcome.Indeterminate,
            ConditionEvaluator.Evaluate(ev, Sample()).Outcome);
        // A read section with other events is a genuine Clear.
        Assert.Equal(ConditionOutcome.Clear, ConditionEvaluator.Evaluate(ev,
            Sample(events: new[] { new EventLogSample("Application Error", 1001, "Error", T0, "other") })).Outcome);
        Assert.Equal(ConditionOutcome.Firing, ConditionEvaluator.Evaluate(ev,
            Sample(events: new[] { new EventLogSample("Application Error", 1000, "Error", T0, "crashed") })).Outcome);
    }

    [Fact]
    public void F1_EventLogAlert_SurvivesBlindCycle()
    {
        var rig = new Rig(new FakeHealthCollector(
            Sample(events: new[] { new EventLogSample("Application Error", 1000, "Error", T0, "crashed") }),
            Sample(notes: new[] { "not_read:eventlog" }))); // blind cycle: section unread
        rig.Service.AdmitLocalLibrary(Library(
            Cond("ev", ConditionKinds.EventLogMatch, target: "Application Error", eventId: 1000)), "test");
        Assert.Single(rig.Service.RunCycle().NewAlerts);
        var blind = rig.Service.RunCycle();
        Assert.Contains("ev", blind.IndeterminateConditionIds);
        Assert.Empty(blind.AutoResetAlerts); // the blind cycle must not clear the real alert
        Assert.Single(rig.Centre.ActiveAlerts);
    }

    // ---- F2: unread sections degrade status + hub view -----------------

    [Fact]
    public void F2_UnreadSecuritySection_DegradesMonitorStatusAndHubView()
    {
        var rig = new Rig(new FakeHealthCollector(Sample(cpu: 10))); // security never read
        rig.Service.AdmitLocalLibrary(Library(
            Cond("cpu", ConditionKinds.CpuHigh, pct: 95),
            Cond("av", ConditionKinds.SecurityAvOff, severity: AlertSeverities.Critical)), "test");
        var cycle = rig.Service.RunCycle();
        Assert.Contains("av", cycle.IndeterminateConditionIds);
        Assert.Equal(MonitorStatuses.Degraded, rig.Service.MonitorStatus); // was: Ok

        var report = rig.Service.BuildReport();
        Assert.Equal(MonitorStatuses.Degraded, report.MonitorStatus);
        Assert.Contains(report.MonitorNotes, n => n == "indeterminate:av");
        Assert.Contains(report.MonitorNotes, n => n.Contains("not_read") || n == "indeterminate:av");

        var hubCentre = new HealthAlertCentre(new ChainedAuditLog(), new AlertCenter());
        var hub = new HubHealthIngest(hubCentre, TimeSpan.FromMinutes(15));
        Assert.True(hub.Ingest(report, T0).Accepted);
        Assert.Equal(DeviceHealthStates.Degraded, hub.View(Dev, T0).State); // was: Healthy
    }

    [Fact]
    public void F2_WindowSuppressedFiring_StillReachesHubView()
    {
        var rig = new Rig(new FakeHealthCollector(Sample(disks: new[] { Disk(3) })));
        rig.Service.AdmitLocalLibrary(Library(Cond("disk-low", ConditionKinds.DiskLow, pct: 10, target: "*")), "test");
        Assert.True(rig.Centre.AddWindow(new MaintenanceWindow(
            "w1", Dev, T0, T0.AddHours(4), "planned disk swap", "admin-1", T0), T0).Accepted);
        var cycle = rig.Service.RunCycle();
        Assert.Equal(1, cycle.SuppressedCount);
        Assert.Empty(rig.Centre.ActiveAlerts); // nothing raised — but the disk IS at 3%
        var report = rig.Service.BuildReport();
        Assert.Contains("disk-low", report.FiringConditionIds); // was: absent (built from active alerts)
        var hub = new HubHealthIngest(new HealthAlertCentre(new ChainedAuditLog(), new AlertCenter()),
            TimeSpan.FromMinutes(15));
        Assert.True(hub.Ingest(report, T0).Accepted);
        Assert.Equal(DeviceHealthStates.Alerting, hub.View(Dev, T0).State); // was: Healthy
    }

    // ---- F3: unverified content / Default restore -----------------------

    [Fact]
    public void F3_SignedLibraryInForce_ClosesLocalPath_AndRetiresDefaultId()
    {
        var (rig, signer) = SignedRig();
        var siteLib = new ConditionLibrary("site-lib", 1,
            new[] { Cond("cpu", ConditionKinds.CpuHigh, pct: 50) });
        Assert.True(rig.Service.ApplySignedLibrary(Sign(signer, siteLib, T0)).Allowed);
        Assert.Equal("site-lib", rig.Service.Library.Id);

        // The unsigned local path can no longer restore the Default…
        var local = rig.Service.AdmitLocalLibrary(ConditionLibrary.Default(), "attack");
        Assert.False(local.Allowed);
        Assert.Contains("signed condition library is in force", local.Reason);
        // …nor admit anything else.
        Assert.False(rig.Service.AdmitLocalLibrary(
            new ConditionLibrary("other", 1, new[] { Cond("x", ConditionKinds.CpuHigh, pct: 1) }), "attack").Allowed);
        // A SIGNED switch back to the retired default id refuses too,
        // even at a higher revision.
        var backToDefault = new ConditionLibrary("acp-default", 9,
            new[] { Cond("cpu", ConditionKinds.CpuHigh, pct: 50) });
        var verdict = rig.Service.ApplySignedLibrary(Sign(signer, backToDefault, T0));
        Assert.False(verdict.Allowed);
        Assert.Contains("retired", verdict.Reason);
        Assert.Equal("site-lib", rig.Service.Library.Id); // signed library still in force
    }

    [Fact]
    public void F3_IdSwitch_IsOneWay_RetiredIdCannotReturnAtAnyRevision()
    {
        var rig = new Rig(new FakeHealthCollector(Sample(cpu: 1)));
        var a = new ConditionLibrary("lib-a", 1, new[] { Cond("cpu", ConditionKinds.CpuHigh, pct: 50) });
        var b = new ConditionLibrary("lib-b", 1, new[] { Cond("ram", ConditionKinds.RamHigh, pct: 50) });
        Assert.True(rig.Service.AdmitLocalLibrary(a, "test").Allowed);
        Assert.True(rig.Service.AdmitLocalLibrary(b, "test").Allowed); // switch: lib-a retires
        var back = rig.Service.AdmitLocalLibrary(a with { Revision = 99 }, "attack");
        Assert.False(back.Allowed);
        Assert.Contains("retired", back.Reason);
        // The boot default retired at the first switch as well.
        Assert.False(rig.Service.AdmitLocalLibrary(ConditionLibrary.Default(), "attack").Allowed);
        Assert.Equal("lib-b", rig.Service.Library.Id);
    }

    [Fact]
    public void F3_ServiceLibraryInForce_IsAdmissible()
    {
        // The constructor validates the built-in Default through the
        // same Validate() admission uses (ValidatedDefault) — a fresh
        // service's library in force satisfies admission rules.
        var rig = new Rig(new FakeHealthCollector(Sample()));
        Assert.Null(rig.Service.Library.Validate());
    }

    // ---- F4: hub mirroring cross-device + flood-cap victim ---------------

    [Fact]
    public void F4_ReportAlertNamingAnotherDevice_IsRefused()
    {
        var centre = new HealthAlertCentre(new ChainedAuditLog(), new AlertCenter());
        var hub = new HubHealthIngest(centre, TimeSpan.FromMinutes(15));
        var foreign = new HealthAlertEvent("forged-1", "dev-2", "disk-low", ConditionKinds.DiskLow,
            AlertSeverities.Critical, HealthAlertStates.Raised, T0, T0, 1,
            "forged alert riding dev-1's report", null, null, null, null, "endpoint");
        var report = new DeviceHealthReport(Dev, 1, T0, "lib", "hash", MonitorStatuses.Ok,
            Array.Empty<string>(), new[] { "disk-low" }, new[] { foreign });
        var (accepted, reason) = hub.Ingest(report, T0);
        Assert.True(accepted); // the report itself is dev-1's; its foreign payload is refused
        Assert.Contains("naming a different device refused", reason);
        Assert.Empty(centre.Alerts); // nothing raised on dev-2 (or anywhere)
    }

    [Fact]
    public void F4_FloodCap_NeverAppliesToNeverSuppressibleKinds()
    {
        var centre = new HealthAlertCentre(new ChainedAuditLog(), new AlertCenter());
        for (var i = 0; i < HealthAlertCentre.MaxNewAlertsPerDevicePerHour; i++)
            Assert.Equal(RaiseOutcome.New, centre.Raise(Dev, $"flood-{i}", ConditionKinds.CpuHigh,
                AlertSeverities.Warning, "flood", "endpoint", TimeSpan.Zero, T0).Outcome);
        // The cap is now full for suppressible kinds…
        Assert.Equal(RaiseOutcome.FloodCapped, centre.Raise(Dev, "one-more", ConditionKinds.CpuHigh,
            AlertSeverities.Warning, "flood", "endpoint", TimeSpan.Zero, T0).Outcome);
        // …but the device's real device_down and security alerts still raise.
        Assert.Equal(RaiseOutcome.New, centre.Raise(Dev, SystemAlertConditionIds.DeviceDown,
            ConditionKinds.DeviceDown, AlertSeverities.Critical, "device down", "hub", TimeSpan.Zero, T0).Outcome);
        Assert.Equal(RaiseOutcome.New, centre.Raise(Dev, "security-av-off",
            ConditionKinds.SecurityAvOff, AlertSeverities.Critical, "AV off", "endpoint", TimeSpan.Zero, T0).Outcome);
    }

    // ---- F5: report sequence survives a restart ----------------------------

    [Fact]
    public void F5_ReportSequence_SurvivesAgentRestart()
    {
        var hub = new HubHealthIngest(new HealthAlertCentre(new ChainedAuditLog(), new AlertCenter()),
            TimeSpan.FromMinutes(15));
        var rig1 = new Rig(new FakeHealthCollector(Sample(cpu: 5)));
        rig1.Service.RunCycle();
        var r1 = rig1.Service.BuildReport();
        Assert.True(hub.Ingest(r1, T0).Accepted);

        // A NEW service instance (agent restart): its in-memory
        // counter starts over, but the clock-anchored sequence must
        // still be newer than anything the hub accepted pre-restart.
        var rig2 = new Rig(new FakeHealthCollector(Sample(cpu: 5))) { Now = T0.AddMinutes(2) };
        rig2.Service.RunCycle();
        var r2 = rig2.Service.BuildReport();
        Assert.True(r2.Seq > r1.Seq);
        var (accepted, reason) = hub.Ingest(r2, T0.AddMinutes(2));
        Assert.True(accepted, reason); // was: refused as replay/stale until the counter caught up
    }

    // ---- F6: hub mirrors reset when the endpoint clears ----------------------

    [Fact]
    public void F6_HubMirror_ResetsWhenEndpointStopsReportingAlert()
    {
        var hubCentre = new HealthAlertCentre(new ChainedAuditLog(), new AlertCenter());
        var hub = new HubHealthIngest(hubCentre, TimeSpan.FromMinutes(15));
        var rig = new Rig(new FakeHealthCollector(
            Sample(disks: new[] { Disk(3) }),
            Sample(disks: new[] { Disk(80) })));
        rig.Service.AdmitLocalLibrary(Library(Cond("disk-low", ConditionKinds.DiskLow, pct: 10, target: "*")), "test");

        rig.Service.RunCycle();
        Assert.True(hub.Ingest(rig.Service.BuildReport(), T0).Accepted);
        Assert.Single(hubCentre.ActiveAlerts); // mirrored on the hub
        Assert.Equal("hub", hubCentre.ActiveAlerts[0].Source);

        rig.Now = T0.AddMinutes(1);
        rig.Service.RunCycle(); // disk healed on the endpoint
        Assert.True(hub.Ingest(rig.Service.BuildReport(), T0.AddMinutes(1)).Accepted);
        Assert.Empty(hubCentre.ActiveAlerts); // was: stayed active forever
        var mirror = Assert.Single(hubCentre.Alerts);
        Assert.Equal(HealthAlertStates.Reset, mirror.State);
        Assert.Contains("no longer reports", mirror.ResetReason);
    }

    // ---- F7: debounce-pending + admission streak discipline --------------------

    [Fact]
    public void F7_DebouncePendingCondition_DoesNotAutoResetItsActiveAlert()
    {
        var hot = Sample(cpu: 99);
        var rig = new Rig(new FakeHealthCollector(hot));
        rig.Service.AdmitLocalLibrary(new ConditionLibrary("lib", 1,
            new[] { Cond("cpu", ConditionKinds.CpuHigh, pct: 90, consecutive: 1) }), "test");
        Assert.Single(rig.Service.RunCycle().NewAlerts);
        // New revision raises the debounce to 3: the condition
        // legitimately restarts its streak (its content changed)…
        Assert.True(rig.Service.AdmitLocalLibrary(new ConditionLibrary("lib", 2,
            new[] { Cond("cpu", ConditionKinds.CpuHigh, pct: 90, consecutive: 3) }), "test").Allowed);
        var pending = rig.Service.RunCycle(); // streak 1 of 3: firing, still debouncing
        Assert.Empty(pending.AutoResetAlerts); // was: reset as "condition cleared" mid-breach
        Assert.Single(rig.Centre.ActiveAlerts);
        rig.Service.RunCycle();
        rig.Service.RunCycle(); // debounce completes: refresh, still exactly one alert
        Assert.Single(rig.Centre.Alerts);
        Assert.Single(rig.Centre.ActiveAlerts);
    }

    [Fact]
    public void F7_UnchangedCondition_KeepsDebounceStreakAcrossAdmission()
    {
        var hot = Sample(cpu: 99);
        var rig = new Rig(new FakeHealthCollector(hot));
        var cpu = Cond("cpu", ConditionKinds.CpuHigh, pct: 90, consecutive: 3);
        rig.Service.AdmitLocalLibrary(new ConditionLibrary("lib", 1, new[] { cpu }), "test");
        Assert.Empty(rig.Service.RunCycle().NewAlerts); // streak 1
        Assert.Empty(rig.Service.RunCycle().NewAlerts); // streak 2
        // Admit a new revision that leaves the cpu condition
        // byte-identical and adds a disk condition.
        Assert.True(rig.Service.AdmitLocalLibrary(new ConditionLibrary("lib", 2,
            new[] { cpu, Cond("disk", ConditionKinds.DiskLow, pct: 10, target: "*") }), "test").Allowed);
        var third = rig.Service.RunCycle(); // streak 3 completes — was: streak restarted at 1
        Assert.Single(third.NewAlerts);
        Assert.Equal("cpu", third.NewAlerts[0].ConditionId);
    }

    [Fact]
    public void F7_RemovedCondition_ResetsAlertWithTrueReason()
    {
        var rig = new Rig(new FakeHealthCollector(Sample(disks: new[] { Disk(3) })));
        rig.Service.AdmitLocalLibrary(new ConditionLibrary("lib", 1,
            new[] { Cond("disk", ConditionKinds.DiskLow, pct: 10, target: "*") }), "test");
        Assert.Single(rig.Service.RunCycle().NewAlerts);
        Assert.True(rig.Service.AdmitLocalLibrary(new ConditionLibrary("lib", 2,
            new[] { Cond("cpu", ConditionKinds.CpuHigh, pct: 95) }), "test").Allowed);
        var alert = Assert.Single(rig.Centre.Alerts);
        Assert.Equal(HealthAlertStates.Reset, alert.State);
        Assert.Contains("removed or disabled", alert.ResetReason); // was: "condition cleared"
        Assert.DoesNotContain("condition cleared", alert.ResetReason);
    }

    // ---- F8: maintenance windows ------------------------------------------------

    [Fact]
    public void F8_WindowCreatedAfterBreachBegan_DoesNotSuppress()
    {
        var rig = new Rig(new FakeHealthCollector(Sample(disks: new[] { Disk(3) })));
        rig.Service.AdmitLocalLibrary(Library(
            Cond("disk", ConditionKinds.DiskLow, pct: 10, target: "*", consecutive: 2)), "test");
        rig.Service.RunCycle(); // T0: breach begins (streak 1 of 2)
        // Window created 3 minutes later, backdated to T0 — inside
        // the 5-minute grace, so admission accepts it…
        var created = T0.AddMinutes(3);
        Assert.True(rig.Centre.AddWindow(new MaintenanceWindow(
            "w", Dev, T0, T0.AddHours(4), "disk swap, honest work", "admin", created), created).Accepted);
        rig.Now = T0.AddMinutes(4);
        var second = rig.Service.RunCycle(); // debounce completes under the window
        Assert.Equal(0, second.SuppressedCount); // …but it must not hide a breach that predates it
        Assert.Single(second.NewAlerts);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "health_alert_window_postdated");
    }

    [Fact]
    public void F8_WindowDoesNotFreezeActiveAlertRefresh()
    {
        var rig = new Rig(new FakeHealthCollector(Sample(disks: new[] { Disk(3) })));
        rig.Service.AdmitLocalLibrary(Library(Cond("disk", ConditionKinds.DiskLow, pct: 10, target: "*")), "test");
        rig.Service.RunCycle();
        Assert.Equal(1, rig.Centre.ActiveAlerts[0].OccurrenceCount);
        Assert.True(rig.Centre.AddWindow(new MaintenanceWindow(
            "w", Dev, T0, T0.AddHours(4), "planned work", "admin", T0), T0).Accepted);
        rig.Now = T0.AddMinutes(1);
        var second = rig.Service.RunCycle();
        Assert.Equal(0, second.SuppressedCount);
        // The already-active alert keeps refreshing under the window:
        // occurrence count and last-seen move (was: frozen by the
        // suppression check running before dedup).
        Assert.Equal(2, rig.Centre.ActiveAlerts[0].OccurrenceCount);
        Assert.Equal(T0.AddMinutes(1), rig.Centre.ActiveAlerts[0].LastSeenUtc);
    }

    [Fact]
    public void F8_WindowCanBeCancelled_AndExpiredWindowsArePruned()
    {
        var audit = new ChainedAuditLog();
        var centre = new HealthAlertCentre(audit, new AlertCenter());
        Assert.True(centre.AddWindow(new MaintenanceWindow(
            "w", Dev, T0, T0.AddHours(2), "work", "admin", T0), T0).Accepted);
        Assert.Equal(RaiseOutcome.Suppressed, centre.Raise(Dev, "disk", ConditionKinds.DiskLow,
            AlertSeverities.Warning, "low", "endpoint", TimeSpan.Zero, T0).Outcome);
        var (removed, _) = centre.RemoveWindow("w", "admin", T0.AddMinutes(5));
        Assert.True(removed);
        Assert.Equal(RaiseOutcome.New, centre.Raise(Dev, "disk", ConditionKinds.DiskLow,
            AlertSeverities.Warning, "low", "endpoint", TimeSpan.Zero, T0.AddMinutes(6)).Outcome);
        Assert.Contains(audit.Entries, e => e.Kind == "maintenance_window_removed");
        // Unattributed cancellation refuses.
        Assert.False(centre.RemoveWindow("w", "", T0).Removed);

        // Expired windows are pruned when a new one is admitted.
        Assert.True(centre.AddWindow(new MaintenanceWindow(
            "old", Dev, T0, T0.AddMinutes(30), "old work", "admin", T0), T0).Accepted);
        Assert.True(centre.AddWindow(new MaintenanceWindow(
            "new", Dev, T0.AddHours(2), T0.AddHours(3), "new work", "admin", T0.AddHours(2)), T0.AddHours(2)).Accepted);
        Assert.DoesNotContain(centre.Windows, w => w.Id == "old");
        Assert.Contains(audit.Entries, e => e.Kind == "maintenance_windows_pruned");
    }

    // ---- F9: condition-id namespace ----------------------------------------------

    [Fact]
    public void F9_ReservedIdsAndNonSampleKinds_RefusedAtValidation()
    {
        var reserved = new ConditionLibrary("lib", 1,
            new[] { Cond("monitor-failure", ConditionKinds.CpuHigh, pct: 90) });
        Assert.Contains("reserved", reserved.Validate());
        var warrantyId = new ConditionLibrary("lib", 1,
            new[] { Cond("warranty:expired", ConditionKinds.CpuHigh, pct: 90) });
        Assert.Contains("reserved", warrantyId.Validate());
        var deviceDownId = new ConditionLibrary("lib", 1,
            new[] { Cond("device-down", ConditionKinds.CpuHigh, pct: 90) });
        Assert.Contains("reserved", deviceDownId.Validate());
        // Kinds that are never sample-evaluated cannot be library
        // content — they would be silently skipped while looking
        // like coverage.
        var warrantyKind = new ConditionLibrary("lib", 1,
            new[] { Cond("w", ConditionKinds.Warranty) });
        Assert.Contains("not sample-evaluated", warrantyKind.Validate());
        var downKind = new ConditionLibrary("lib", 1,
            new[] { Cond("d", ConditionKinds.DeviceDown) });
        Assert.Contains("not sample-evaluated", downKind.Validate());
    }

    [Fact]
    public void F9_CollectorRecovery_DoesNotResetForeignAlertSharingReservedId()
    {
        // A foreign alert that merely SHARES the reserved id (kind
        // cpu_high — not the monitor's own failure alert) absorbs
        // the monitor-failure raise by dedup, exactly the F9
        // absorption. Collector recovery previously matched on
        // ConditionId ALONE and would close it as "recovered"; it
        // now requires kind monitor_failure + source monitor too.
        var collector = new FakeHealthCollector()
            .ThenThrow(new InvalidOperationException("dead"))
            .ThenThrow(new InvalidOperationException("dead"))
            .ThenThrow(new InvalidOperationException("dead"))
            .Then(Sample(cpu: 5));
        var rig = new Rig(collector);
        rig.Centre.Raise(Dev, SystemAlertConditionIds.MonitorFailure, ConditionKinds.CpuHigh,
            AlertSeverities.Warning, "foreign alert sharing the id", "monitor", TimeSpan.Zero, T0);
        rig.Service.RunCycle();
        rig.Service.RunCycle();
        rig.Service.RunCycle(); // monitor failing; its raise dedup-refreshes the foreign alert
        rig.Service.RunCycle(); // collector recovers
        var foreign = Assert.Single(rig.Centre.ActiveAlerts);
        Assert.Equal(ConditionKinds.CpuHigh, foreign.Kind);
        Assert.Equal(HealthAlertStates.Raised, foreign.State); // still active — not "recovered" away

        // Control: the monitor's OWN failure alert (right kind +
        // source) still auto-resets on recovery.
        var collector2 = new FakeHealthCollector()
            .ThenThrow(new InvalidOperationException("dead"))
            .ThenThrow(new InvalidOperationException("dead"))
            .ThenThrow(new InvalidOperationException("dead"))
            .Then(Sample(cpu: 5));
        var rig2 = new Rig(collector2);
        rig2.Service.RunCycle();
        rig2.Service.RunCycle();
        rig2.Service.RunCycle();
        Assert.Contains(rig2.Centre.ActiveAlerts, a => a.Kind == ConditionKinds.MonitorFailure);
        rig2.Service.RunCycle(); // recovery
        Assert.DoesNotContain(rig2.Centre.ActiveAlerts, a => a.Kind == ConditionKinds.MonitorFailure);
    }

    // ---- F10: work-item close gating -----------------------------------------------

    [Fact]
    public void F10_AutoResetClose_RespectsPolicyGate_AndManualResetCloses()
    {
        var actions = new AlertActions(true, true, null);
        // (a) Policy disabled between open and clear: the sink is
        // NOT touched on close, and the skip is audited.
        var rig = new Rig(new FakeHealthCollector(
            Sample(disks: new[] { Disk(3) }),
            Sample(disks: new[] { Disk(80) })));
        rig.Service.AdmitLocalLibrary(Library(
            Cond("disk", ConditionKinds.DiskLow, pct: 10, target: "*", actions: actions)), "test");
        rig.Service.RunCycle();
        Assert.Single(rig.WorkItems.Opened);
        rig.DisablePolicy(MonitoringPolicyKeys.WorkItemsEnabled);
        var cleared = rig.Service.RunCycle();
        Assert.Single(cleared.AutoResetAlerts);      // the alert still auto-resets…
        Assert.Empty(rig.WorkItems.Closed);          // …but the disabled sink is never touched
        Assert.Contains(rig.Audit.Entries,
            e => e.Kind == "health_action_skipped" && e.Detail.Contains("work_item_close"));

        // (b) Manual reset closes the work item too (was: never).
        var rig2 = new Rig(new FakeHealthCollector(Sample(disks: new[] { Disk(3) })));
        rig2.Service.AdmitLocalLibrary(Library(
            Cond("disk", ConditionKinds.DiskLow, pct: 10, target: "*", actions: actions)), "test");
        var alert = rig2.Service.RunCycle().NewAlerts.Single();
        Assert.Single(rig2.WorkItems.Opened);
        Assert.NotNull(rig2.Centre.Reset(alert.AlertId, "tech-1", "disk replaced", T0.AddHours(1)));
        Assert.Single(rig2.WorkItems.Closed);
        Assert.Equal("disk replaced", rig2.WorkItems.Closed[0].Reason);
    }

    [Fact]
    public void F10_NeverOpenedWorkItem_IsNeverClosed()
    {
        var rig = new Rig(new FakeHealthCollector(
            Sample(disks: new[] { Disk(3) }),
            Sample(disks: new[] { Disk(80) })));
        rig.Service.AdmitLocalLibrary(Library(
            Cond("disk", ConditionKinds.DiskLow, pct: 10, target: "*",
                actions: new AlertActions(true, false, null))), "test"); // notify only
        rig.Service.RunCycle();
        rig.Service.RunCycle(); // auto-reset
        Assert.Empty(rig.WorkItems.Opened);
        Assert.Empty(rig.WorkItems.Closed); // was: CloseWorkItem called for never-opened alerts
    }

    // ---- F11: audit flooding bounds ---------------------------------------------------

    [Fact]
    public void F11_SuppressionAndCooldownAudit_AreThrottledWithCountsKept()
    {
        var audit = new ChainedAuditLog();
        var centre = new HealthAlertCentre(audit, new AlertCenter());
        centre.AddWindow(new MaintenanceWindow("w", Dev, T0, T0.AddHours(48), "long work", "admin", T0), T0);
        for (var i = 0; i < 100; i++)
            centre.Raise(Dev, "disk", ConditionKinds.DiskLow, AlertSeverities.Warning,
                "low", "endpoint", TimeSpan.Zero, T0.AddMinutes(i % 50));
        // 100 suppressions inside the hour → ONE chained entry.
        Assert.Single(audit.Entries, e => e.Kind == "health_alert_suppressed");
        // The next hour's first suppression carries the throttled count.
        centre.Raise(Dev, "disk", ConditionKinds.DiskLow, AlertSeverities.Warning,
            "low", "endpoint", TimeSpan.Zero, T0.AddHours(2));
        var suppressed = audit.Entries.Where(e => e.Kind == "health_alert_suppressed").ToList();
        Assert.Equal(2, suppressed.Count);
        Assert.Contains("99 further occurrences", suppressed[1].Detail);

        // Cooldown hits are throttled the same way.
        var audit2 = new ChainedAuditLog();
        var centre2 = new HealthAlertCentre(audit2, new AlertCenter());
        var first = centre2.Raise(Dev, "cpu", ConditionKinds.CpuHigh, AlertSeverities.Warning,
            "hot", "endpoint", TimeSpan.FromHours(1), T0);
        centre2.Reset(first.Alert!.AlertId, "tech", "done", T0.AddMinutes(1));
        for (var i = 0; i < 50; i++)
            centre2.Raise(Dev, "cpu", ConditionKinds.CpuHigh, AlertSeverities.Warning,
                "hot", "endpoint", TimeSpan.FromHours(1), T0.AddMinutes(2 + i));
        Assert.Single(audit2.Entries, e => e.Kind == "health_alert_cooldown");
        Assert.True(audit.Verify().Ok && audit2.Verify().Ok);
    }

    [Fact]
    public void F11_CallerDetail_IsBoundedInStorageAndAudit()
    {
        var audit = new ChainedAuditLog();
        var centre = new HealthAlertCentre(audit, new AlertCenter());
        var huge = new string('x', 100_000);
        var outcome = centre.Raise(Dev, "disk", ConditionKinds.DiskLow, AlertSeverities.Warning,
            huge, "endpoint", TimeSpan.Zero, T0);
        Assert.True(outcome.Alert!.Detail.Length <= HealthAlertCentre.MaxStoredDetailLength + 16);
        var raised = Assert.Single(audit.Entries, e => e.Kind == "health_alert_raised");
        Assert.True(raised.Detail.Length < HealthAlertCentre.MaxAuditDetailLength + 256,
            $"audit detail was {raised.Detail.Length} chars");
    }

    // ---- F12: admission gaps + warranty lifecycle ---------------------------------------

    [Fact]
    public void F12_EmptyOrAllDisabledLibrary_Refused_MonitoringStaysOn()
    {
        Assert.Contains("no conditions", new ConditionLibrary("lib", 1,
            Array.Empty<MonitorCondition>()).Validate());
        var allDisabled = new ConditionLibrary("lib", 1, new[]
        {
            MonitorCondition.Create("cpu", "cpu", ConditionKinds.CpuHigh, AlertSeverities.Warning,
                thresholdPercent: 90, enabled: false),
        });
        Assert.Contains("every condition is disabled", allDisabled.Validate());

        // Through the service: a validly delivered empty library
        // cannot turn monitoring off — the in-force library stays.
        var rig = new Rig(new FakeHealthCollector(Sample(disks: new[] { Disk(3) })));
        var verdict = rig.Service.AdmitLocalLibrary(
            new ConditionLibrary("silencer", 1, Array.Empty<MonitorCondition>()), "attack");
        Assert.False(verdict.Allowed);
        Assert.Equal(ConditionLibrary.Default().Id, rig.Service.Library.Id);
        Assert.NotEmpty(rig.Service.RunCycle().NewAlerts); // default disk conditions still fire
    }

    [Fact]
    public void F12_WarrantyAlert_AutoResetsWhenSourceStopsReporting()
    {
        var centre = new HealthAlertCentre(new ChainedAuditLog(), new AlertCenter());
        var expiring = new WarrantyAlertEvent(Dev, "ABC1234", "dell",
            WarrantyAlertEvent.KindExpiring, WarrantyAlertEvent.SeverityWarning,
            T0.AddDays(20), 20, T0);
        Assert.Single(centre.IngestWarrantyAlerts(new[] { expiring }, T0));
        Assert.Single(centre.ActiveAlerts);
        // The warranty is renewed; the store's next snapshot no
        // longer reports it. The alert closes itself (was: never).
        centre.IngestWarrantyAlerts(Array.Empty<WarrantyAlertEvent>(), T0.AddDays(1));
        Assert.Empty(centre.ActiveAlerts);
        var alert = Assert.Single(centre.Alerts);
        Assert.Contains("no longer reported", alert.ResetReason);
    }
}
