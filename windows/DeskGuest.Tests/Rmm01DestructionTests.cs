using System.Text;
using DeskGuest.Core.Services;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.Monitoring;
using DeskGuest.Shared.Security;

namespace DeskGuest.Tests;

// RMM-01 DESTRUCTION PASS — hostile attacks on the monitoring lane:
// library tampering, maintenance-window abuse, alert flooding,
// clock games, dead-monitor honesty, sink spoofing, and the
// post-admission mutation class. Every break found became a fix +
// a test in this file; see ledger-rmm01.md.
public class Rmm01DestructionTests
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
    }

    private static EndpointSample Sample(
        IReadOnlyList<DiskSample>? disks = null,
        IReadOnlyList<ServiceSample>? services = null,
        SecurityStateSample? security = null,
        double? cpu = null) => new(
            Dev, T0, cpu, null,
            disks ?? Array.Empty<DiskSample>(),
            services ?? Array.Empty<ServiceSample>(),
            Array.Empty<ProcessSample>(), Array.Empty<AppSample>(), Array.Empty<EventLogSample>(),
            security, null, Array.Empty<GuestSample>(), Array.Empty<string>());

    private static DiskSample Disk(double freePct)
    {
        const long total = 100_000_000_000;
        return new DiskSample("C:", (long)(total * freePct / 100.0), total, "OK", false);
    }

    private static MonitorCondition Cond(string id, string kind, string? target = null,
        double? pct = null, AlertActions? actions = null, TimeSpan? cooldown = null) =>
        MonitorCondition.Create(id, id, kind, AlertSeverities.Critical, target: target,
            thresholdPercent: pct, actions: actions, cooldown: cooldown ?? TimeSpan.FromMinutes(5));

    private static (Rig Rig, SignedCommandSigner Signer, DeviceIdentity Customer) SignedRig(
        IHealthCollector? collector = null)
    {
        var customer = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var audit = new ChainedAuditLog();
        var ring = new CustomerCommandKeyRing();
        ring.AddCurrent(customer.PublicKey);
        var gate = new SignedCommandGate(new SignedCommandVerifier(ring), audit);
        var rig = new Rig(collector ?? new FakeHealthCollector(Sample(cpu: 1)), gate)
        {
            Audit = audit,
        };
        rig.Centre = new HealthAlertCentre(audit, rig.Dir57);
        rig.Service = new EndpointMonitorService(Dev, rig.Facts, rig.Policy,
            collector ?? new FakeHealthCollector(Sample(cpu: 1)), rig.Centre, audit, gate,
            rig.WorkItems, rig.Remediation, () => rig.Now);
        return (rig, new SignedCommandSigner(customer), customer);
    }

    // ---- condition-library tampering ------------------------------------

    [Fact]
    public void ATTACK_UnsignedLibrary_Refused_LibraryInForceUnchanged()
    {
        var rig = new Rig(new FakeHealthCollector(Sample()));
        // No gate at all: even a well-formed envelope-shaped delivery refuses.
        Assert.False(rig.Service.ApplySignedLibrary(null).Allowed);
        Assert.Equal(ConditionLibrary.Default().Id, rig.Service.Library.Id);

        var (srig, _, _) = SignedRig();
        Assert.False(srig.Service.ApplySignedLibrary(null).Allowed);
        Assert.Equal(ConditionLibrary.Default().Id, srig.Service.Library.Id);
    }

    [Fact]
    public void ATTACK_TamperedSignedLibrary_PayloadSwappedAfterSigning_Refused()
    {
        var (rig, signer, _) = SignedRig();
        var good = new ConditionLibrary("site-lib", 3,
            new[] { Cond("disk", ConditionKinds.DiskLow, pct: 10, target: "*") });
        var env = signer.Sign(SignedCommandClasses.PolicyDelivery,
            Encoding.UTF8.GetBytes(good.ToCanonicalJson()), T0, TimeSpan.FromMinutes(5));
        // Attacker swaps the payload for a library that un-watches
        // everything (empty condition set = total silence).
        var evil = new ConditionLibrary("site-lib", 3, Array.Empty<MonitorCondition>());
        var tampered = env with
        {
            PayloadBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(evil.ToCanonicalJson())),
        };
        var verdict = rig.Service.ApplySignedLibrary(tampered);
        Assert.False(verdict.Allowed);
        Assert.Equal(ConditionLibrary.Default().Id, rig.Service.Library.Id); // default still watches
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "signed_command_refused");
    }

    [Fact]
    public void ATTACK_ValidlySignedMaliciousLibrary_UnknownKindAndSilencerCooldown_Refused()
    {
        var (rig, signer, _) = SignedRig();
        // A compromised-but-key-holding author signs a library whose
        // conditions are individually poisonous: an unknown kind, and
        // a 7-day cooldown that would silence re-alerting for a week.
        var unknownKind = new ConditionLibrary("evil-1", 1, new[]
        {
            MonitorCondition.Create("x", "teleport_user", AlertSeverities.Critical),
        });
        var env1 = signer.Sign(SignedCommandClasses.PolicyDelivery,
            Encoding.UTF8.GetBytes(unknownKind.ToCanonicalJson()), T0, TimeSpan.FromMinutes(5));
        Assert.False(rig.Service.ApplySignedLibrary(env1).Allowed);

        var silencer = new ConditionLibrary("evil-2", 1, new[]
        {
            MonitorCondition.Create("disk", "disk", ConditionKinds.DiskLow, AlertSeverities.Critical,
                target: "*", thresholdPercent: 10, cooldown: TimeSpan.FromDays(7)),
        });
        var env2 = signer.Sign(SignedCommandClasses.PolicyDelivery,
            Encoding.UTF8.GetBytes(silencer.ToCanonicalJson()), T0, TimeSpan.FromMinutes(5));
        var v2 = rig.Service.ApplySignedLibrary(env2);
        Assert.False(v2.Allowed);
        Assert.Contains("cooldown", v2.Reason);
        Assert.Equal(ConditionLibrary.Default().Id, rig.Service.Library.Id);
    }

    [Fact]
    public void ATTACK_StaleAndConflictingLibraryRevisions_Refused()
    {
        var rig = new Rig(new FakeHealthCollector(Sample()));
        var lib5 = new ConditionLibrary("site-lib", 5, new[] { Cond("a", ConditionKinds.CpuHigh, pct: 90) });
        Assert.True(rig.Service.AdmitLocalLibrary(lib5, "test").Allowed);
        Assert.True(rig.Service.AdmitLocalLibrary(lib5, "test").Allowed); // idempotent
        var stale = new ConditionLibrary("site-lib", 4, new[] { Cond("a", ConditionKinds.CpuHigh, pct: 10) });
        Assert.False(rig.Service.AdmitLocalLibrary(stale, "test").Allowed);
        var conflict = new ConditionLibrary("site-lib", 5, new[] { Cond("a", ConditionKinds.CpuHigh, pct: 20) });
        var cv = rig.Service.AdmitLocalLibrary(conflict, "test");
        Assert.False(cv.Allowed);
        Assert.Contains("conflicts", cv.Reason);
        Assert.Equal(90, rig.Service.Library.Conditions[0].ThresholdPercent);
    }

    [Fact]
    public void ATTACK_PostAdmissionMutation_CannotChangeLiveLibrary()
    {
        // The RMM-07 BREAK-1 class, aimed at this lane: the caller
        // keeps the conditions list it passed in and mutates it after
        // admission — clearing every condition (total silence) with
        // no revision, signature or audit.
        var rig = new Rig(new FakeHealthCollector(Sample(disks: new[] { Disk(3) })));
        var conditions = new List<MonitorCondition> { Cond("disk", ConditionKinds.DiskLow, pct: 10, target: "*") };
        Assert.True(rig.Service.AdmitLocalLibrary(new ConditionLibrary("site-lib", 1, conditions), "test").Allowed);
        conditions.Clear(); // the attack
        Assert.Single(rig.Service.Library.Conditions); // frozen at admission
        var result = rig.Service.RunCycle();
        Assert.Single(result.NewAlerts); // the disk is still watched
    }

    // ---- maintenance-window abuse -----------------------------------------

    [Fact]
    public void ATTACK_ForeverWindow_Refused()
    {
        var audit = new ChainedAuditLog();
        var centre = new HealthAlertCentre(audit, new AlertCenter());
        var forever = new MaintenanceWindow("w", Dev, T0, T0.AddDays(365), "just always", "admin", T0);
        var (accepted, reason) = centre.AddWindow(forever, T0);
        Assert.False(accepted);
        Assert.Contains("maximum", reason);
        Assert.Contains(audit.Entries, e => e.Kind == "maintenance_window_refused");
    }

    [Fact]
    public void ATTACK_RetroactiveWindow_Refused_CannotCoverPastFaults()
    {
        var audit = new ChainedAuditLog();
        var centre = new HealthAlertCentre(audit, new AlertCenter());
        // Fault happened at T0-2h; the window is created NOW claiming
        // to have covered it since T0-3h.
        var retro = new MaintenanceWindow("w", Dev, T0.AddHours(-3), T0.AddHours(1), "planned, honest", "admin", T0);
        Assert.False(centre.AddWindow(retro, T0).Accepted);
        // Unattributed and reason-less windows refuse too.
        Assert.False(centre.AddWindow(new MaintenanceWindow("w2", Dev, T0, T0.AddHours(1), "", "admin", T0), T0).Accepted);
        Assert.False(centre.AddWindow(new MaintenanceWindow("w3", Dev, T0, T0.AddHours(1), "work", "", T0), T0).Accepted);
    }

    [Fact]
    public void ATTACK_WindowCannotSuppressSecurityStateAlerts()
    {
        // AV goes off DURING legitimate planned work. The window must
        // not swallow it: an unprotected machine is not made
        // protected by a calendar entry.
        var rig = new Rig(new FakeHealthCollector(Sample(
            disks: new[] { Disk(3) },
            security: new SecurityStateSample(false, true, true))));
        rig.Service.AdmitLocalLibrary(new ConditionLibrary("lib", 1, new[]
        {
            Cond("disk", ConditionKinds.DiskLow, pct: 10, target: "*"),
            Cond("av", ConditionKinds.SecurityAvOff),
        }), "test");
        Assert.True(rig.Centre.AddWindow(
            new MaintenanceWindow("w", Dev, T0, T0.AddHours(4), "planned work", "admin", T0), T0).Accepted);
        var result = rig.Service.RunCycle();
        Assert.Equal(1, result.SuppressedCount);              // disk alert suppressed…
        Assert.Single(result.NewAlerts);                      // …but the AV alert raises
        Assert.Equal(ConditionKinds.SecurityAvOff, result.NewAlerts[0].Kind);
    }

    [Fact]
    public void ATTACK_WindowCannotSuppressItsOwnAuditTrail()
    {
        var rig = new Rig(new FakeHealthCollector(Sample(disks: new[] { Disk(3) })));
        rig.Service.AdmitLocalLibrary(new ConditionLibrary("lib", 1, new[]
        {
            Cond("disk", ConditionKinds.DiskLow, pct: 10, target: "*"),
        }), "test");
        rig.Centre.AddWindow(new MaintenanceWindow("w", Dev, T0, T0.AddHours(2), "work", "admin", T0), T0);
        rig.Service.RunCycle();
        // Creation AND the suppression are both in the chain, and the
        // chain still verifies — suppression touched alerting only.
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "maintenance_window_created");
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "health_alert_suppressed");
        Assert.True(rig.Audit.Verify().Ok);
    }

    [Fact]
    public void ATTACK_ExpiredWindow_StopsSuppressing()
    {
        var rig = new Rig(new FakeHealthCollector(Sample(disks: new[] { Disk(3) })));
        rig.Service.AdmitLocalLibrary(new ConditionLibrary("lib", 1, new[]
        {
            Cond("disk", ConditionKinds.DiskLow, pct: 10, target: "*"),
        }), "test");
        rig.Centre.AddWindow(new MaintenanceWindow("w", Dev, T0, T0.AddHours(1), "work", "admin", T0), T0);
        Assert.Equal(1, rig.Service.RunCycle().SuppressedCount);
        rig.Now = T0.AddHours(2); // window over; clock moved honestly forward
        // Rebuild service clock is the rig's Now via the Rig ctor —
        // the service reads () => Now, so the new time applies.
        var after = rig.Service.RunCycle();
        Assert.Single(after.NewAlerts);
    }

    [Fact]
    public void ATTACK_WindowCannotSuppressSerialConflictAlerts()
    {
        // A duplicate serial is an inventory-integrity fact: planned
        // work on one of the machines does not make it unique, and a
        // fleet-wide window must not hide it either.
        var audit = new ChainedAuditLog();
        var centre = new HealthAlertCentre(audit, new AlertCenter());
        centre.AddWindow(new MaintenanceWindow("w", "*", T0, T0.AddHours(4), "work", "admin", T0), T0);
        var created = centre.IngestSerialConflictAlerts(new[]
        {
            new DeskGuest.Shared.Inventory.SerialConflictAlertEvent(
                "ABC1234", new[] { "dev-1", "dev-2" },
                DeskGuest.Shared.Inventory.SerialConflictAlertEvent.KindSerialConflict, T0),
        }, T0);
        Assert.Equal(2, created.Count);
        Assert.Equal(2, centre.ActiveAlerts.Count);
    }

    // ---- flooding / DoS shapes ----------------------------------------------

    [Fact]
    public void ATTACK_AlertFlood_CappedPerDevicePerHour_AndCounted()
    {
        var audit = new ChainedAuditLog();
        var centre = new HealthAlertCentre(audit, new AlertCenter());
        var news = 0;
        for (var i = 0; i < 300; i++)
        {
            var outcome = centre.Raise(Dev, $"cond-{i}", ConditionKinds.CpuHigh,
                AlertSeverities.Warning, "flood", "endpoint", TimeSpan.Zero, T0.AddSeconds(i));
            if (outcome.Outcome == RaiseOutcome.New) news++;
        }
        Assert.Equal(HealthAlertCentre.MaxNewAlertsPerDevicePerHour, news);
        Assert.True(centre.FloodedOccurrences[Dev] > 0); // counted, visible — not silent
        Assert.Contains(audit.Entries, e => e.Kind == "health_alert_flood_capped");
        Assert.True(audit.Verify().Ok);
    }

    [Fact]
    public void ATTACK_SameConditionFlood_DedupsToOneAlert()
    {
        var audit = new ChainedAuditLog();
        var centre = new HealthAlertCentre(audit, new AlertCenter());
        for (var i = 0; i < 1000; i++)
            centre.Raise(Dev, "disk", ConditionKinds.DiskLow, AlertSeverities.Critical,
                "still low", "endpoint", TimeSpan.FromMinutes(5), T0.AddSeconds(i));
        Assert.Single(centre.Alerts);
        Assert.Equal(1000, centre.Alerts[0].OccurrenceCount);
    }

    [Fact]
    public void ATTACK_CooldownFlapping_CannotSpamSinks()
    {
        // A condition flapping around its threshold: raise → clear →
        // raise inside the cooldown must not re-fire the work-item /
        // remediation sinks.
        var rig = new Rig(new FakeHealthCollector(
            Sample(disks: new[] { Disk(3) }),
            Sample(disks: new[] { Disk(80) }),
            Sample(disks: new[] { Disk(3) })));
        rig.Service.AdmitLocalLibrary(new ConditionLibrary("lib", 1, new[]
        {
            Cond("disk", ConditionKinds.DiskLow, pct: 10, target: "*",
                actions: new AlertActions(true, true, "free-space"),
                cooldown: TimeSpan.FromMinutes(30)),
        }), "test");
        rig.Service.RunCycle();                       // raises, sinks fire
        rig.Now = T0.AddMinutes(1);
        rig.Service.RunCycle();                       // clears, auto-reset
        rig.Now = T0.AddMinutes(2);
        var third = rig.Service.RunCycle();           // fires again — inside cooldown
        Assert.Empty(third.NewAlerts);                // cooldown outcome, no new alert
        Assert.Single(rig.WorkItems.Opened);
        Assert.Single(rig.Remediation.Dispatches);
    }

    // ---- clock games -----------------------------------------------------------

    [Fact]
    public void ATTACK_FutureDatedHealthReport_Refused()
    {
        var audit = new ChainedAuditLog();
        var centre = new HealthAlertCentre(audit, new AlertCenter());
        var hub = new HubHealthIngest(centre, TimeSpan.FromMinutes(15));
        var report = new DeviceHealthReport(Dev, 1, T0.AddHours(2), "lib", "hash",
            MonitorStatuses.Ok, Array.Empty<string>(), Array.Empty<string>(), Array.Empty<HealthAlertEvent>());
        var (accepted, reason) = hub.Ingest(report, T0);
        Assert.False(accepted);
        Assert.Contains("future-dated", reason);
        Assert.Equal(DeviceHealthStates.Unknown, hub.View(Dev, T0).State);
    }

    [Fact]
    public void ATTACK_ReplayedHealthReport_Refused()
    {
        var audit = new ChainedAuditLog();
        var centre = new HealthAlertCentre(audit, new AlertCenter());
        var hub = new HubHealthIngest(centre, TimeSpan.FromMinutes(15));
        DeviceHealthReport Report(long seq) => new(Dev, seq, T0, "lib", "hash",
            MonitorStatuses.Ok, Array.Empty<string>(), Array.Empty<string>(), Array.Empty<HealthAlertEvent>());
        Assert.True(hub.Ingest(Report(5), T0).Accepted);
        Assert.False(hub.Ingest(Report(5), T0).Accepted);  // exact replay
        Assert.False(hub.Ingest(Report(3), T0).Accepted);  // stale
        Assert.True(hub.Ingest(Report(6), T0).Accepted);
    }

    // ---- dead monitor honesty -----------------------------------------------------

    [Fact]
    public void ATTACK_DeadCollector_MonitorReportsFailing_NeverHealthy()
    {
        var collector = new FakeHealthCollector()
            .ThenThrow(new InvalidOperationException("wmi dead"))
            .ThenThrow(new InvalidOperationException("wmi dead"))
            .ThenThrow(new InvalidOperationException("wmi dead"));
        var rig = new Rig(collector);
        rig.Service.RunCycle();
        rig.Service.RunCycle();
        var third = rig.Service.RunCycle();
        Assert.Equal(MonitorStatuses.Failing, third.MonitorStatus);
        var report = rig.Service.BuildReport();
        Assert.Equal(MonitorStatuses.Failing, report.MonitorStatus);
        Assert.Contains(rig.Centre.ActiveAlerts, a => a.Kind == ConditionKinds.MonitorFailure);

        // The hub reads a failing monitor as DEGRADED — never healthy.
        var audit = new ChainedAuditLog();
        var hub = new HubHealthIngest(new HealthAlertCentre(audit, new AlertCenter()), TimeSpan.FromMinutes(15));
        Assert.True(hub.Ingest(report, T0).Accepted);
        Assert.Equal(DeviceHealthStates.Degraded, hub.View(Dev, T0).State);
    }

    [Fact]
    public void ATTACK_MonitorFailureAlert_CannotBeSuppressedByWindow()
    {
        var collector = new FakeHealthCollector()
            .ThenThrow(new InvalidOperationException("dead"))
            .ThenThrow(new InvalidOperationException("dead"))
            .ThenThrow(new InvalidOperationException("dead"));
        var rig = new Rig(collector);
        rig.Centre.AddWindow(new MaintenanceWindow("w", "*", T0, T0.AddHours(4), "work", "admin", T0), T0);
        rig.Service.RunCycle();
        rig.Service.RunCycle();
        rig.Service.RunCycle();
        Assert.Contains(rig.Centre.ActiveAlerts, a => a.Kind == ConditionKinds.MonitorFailure);
    }

    [Fact]
    public void ATTACK_CollectorGap_MustNotAutoResetARealAlert()
    {
        // Disk alert is active; the next sample simply has NO disk
        // section (collector gap). The alert must survive — a blind
        // cycle is not a healed disk.
        var rig = new Rig(new FakeHealthCollector(
            Sample(disks: new[] { Disk(3) }),
            Sample(cpu: 5))); // no disks this cycle
        rig.Service.AdmitLocalLibrary(new ConditionLibrary("lib", 1, new[]
        {
            Cond("disk", ConditionKinds.DiskLow, pct: 10, target: "*"),
        }), "test");
        rig.Service.RunCycle();
        Assert.Single(rig.Centre.ActiveAlerts);
        var gapCycle = rig.Service.RunCycle();
        Assert.Contains("disk", gapCycle.IndeterminateConditionIds);
        Assert.Single(rig.Centre.ActiveAlerts); // still active
        Assert.Empty(gapCycle.AutoResetAlerts);
    }

    // ---- sink spoofing / failure -----------------------------------------------------

    [Fact]
    public void ATTACK_RemediationSinkFailure_Audited_AlertStillRaised()
    {
        var rig = new Rig(new FakeHealthCollector(
            Sample(services: new[] { new ServiceSample("Niagara", "Stopped") })));
        rig.Remediation.Result = new RemediationDispatchResult(false, "sink refused: unknown remediation");
        rig.Service.AdmitLocalLibrary(new ConditionLibrary("lib", 1, new[]
        {
            Cond("svc", ConditionKinds.ServiceStopped, target: "Niagara",
                actions: new AlertActions(true, false, "restart-service")),
        }), "test");
        var result = rig.Service.RunCycle();
        Assert.Single(result.NewAlerts); // a failing sink never swallows the alert
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "health_action_failed");
        Assert.True(rig.Audit.Verify().Ok);
    }

    [Fact]
    public void ATTACK_ForgedHubReport_UnknownMonitorStatus_Refused()
    {
        var audit = new ChainedAuditLog();
        var hub = new HubHealthIngest(new HealthAlertCentre(audit, new AlertCenter()), TimeSpan.FromMinutes(15));
        var forged = new DeviceHealthReport(Dev, 1, T0, "lib", "hash",
            "totally_fine_trust_me", Array.Empty<string>(), Array.Empty<string>(), Array.Empty<HealthAlertEvent>());
        Assert.False(hub.Ingest(forged, T0).Accepted);
        Assert.Equal(DeviceHealthStates.Unknown, hub.View(Dev, T0).State);
    }

    [Fact]
    public void ATTACK_AckAndResetAgainstNothing_Refused()
    {
        var audit = new ChainedAuditLog();
        var centre = new HealthAlertCentre(audit, new AlertCenter());
        Assert.False(centre.Acknowledge("forged-id", "attacker", T0));
        Assert.Null(centre.Reset("forged-id", "attacker", "erasing", T0));
        Assert.Empty(centre.Alerts);
        Assert.DoesNotContain(audit.Entries, e => e.Kind == "health_alert_acknowledged");
    }
}
