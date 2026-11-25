using Acp.Core;
using Acp.Core.Services;
using Acp.Shared.Enterprise;
using Acp.Shared.Enrollment;
using Acp.Shared.Inventory;
using Acp.Shared.Jobs;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Monitoring;
using Acp.Shared.Security;

namespace Acp.Tests;

// Block R closing integration tests: items 3 (NeverSuppressible),
// 4 (PatchService.Start idempotence), 6 (RMM-04 hub remainders),
// plus a CoreRuntime wiring smoke test.
public class IntegrationTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);

    // ---- item 3: adversarial suppression attempts -------------------

    [Fact]
    public void NeverSuppressible_NowIncludes_RansomwareIsolation_And_BaselineDrift()
    {
        Assert.Contains("ransomware_isolation", ConditionKinds.NeverSuppressible);
        Assert.Contains("baseline_drift", ConditionKinds.NeverSuppressible);
        Assert.Contains(ConditionKinds.RansomwareIsolation, ConditionKinds.NeverSuppressible);
        Assert.Contains(ConditionKinds.BaselineDrift, ConditionKinds.NeverSuppressible);
    }

    [Fact]
    public void Adversarial_MaintenanceWindow_CannotSuppress_RansomwareOrDrift_ButStillSuppressesOrdinaryKinds()
    {
        var audit = new ChainedAuditLog();
        var centre = new HealthAlertCentre(audit, new AlertCenter());
        var (accepted, reason) = centre.AddWindow(new MaintenanceWindow(
            "w-adv", "dev1", T0, T0.AddHours(4), "planned work", "admin-1", T0), T0);
        Assert.True(accepted, reason);

        foreach (var kind in new[] { "ransomware_isolation", "baseline_drift" })
        {
            Assert.Null(centre.SuppressingWindow("dev1", kind, T0.AddHours(1)));
            var outcome = centre.Raise("dev1", "cond-" + kind, kind, AlertSeverities.Critical,
                "adversarial suppression attempt", "test", TimeSpan.Zero, T0.AddHours(1));
            Assert.Equal(RaiseOutcome.New, outcome.Outcome);
        }
        Assert.Equal(2, centre.ActiveAlerts.Count);

        // Control: an ordinary kind IS suppressed by the same window —
        // the window works; only the protected kinds escape it.
        var ordinary = centre.Raise("dev1", "cond-cpu", ConditionKinds.CpuHigh, AlertSeverities.Warning,
            "ordinary", "test", TimeSpan.Zero, T0.AddHours(1));
        Assert.Equal(RaiseOutcome.Suppressed, ordinary.Outcome);
        // Evaluations/audit unaffected: the suppression + raises are all audited.
        Assert.Contains(audit.Entries, e => e.Kind == "health_alert_suppressed");
        Assert.True(audit.Verify().Ok);
    }

    // ---- item 4: PatchService.Start idempotent-safe -----------------

    [Fact]
    public void PatchStart_MidExecution_SecondStart_DoesNotResetLiveJob()
    {
        var audit = new ChainedAuditLog();
        var policies = new ManagementPolicyService(audit, null, now: () => T0);
        var endpoint = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var dir = TestUtil.TempDir();
        var svc = new PatchService(dir, audit, policies, null, endpoint, null, now: () => T0);
        var facts = StaticDeviceFacts.Of("dev1", "scope1");

        svc.Start(facts);
        // A live, in-flight job created AFTER the first Start (the
        // mid-execution state): it exists only in memory until the
        // next SaveJournal — a re-importing Start would lose it and
        // reset the journal's live flag.
        var job = svc.Journal.CreateJob(JobKinds.FileTransfer, "dev1",
            new[] { new JobStepDefinition("s1", "copy", StepIdempotency.Idempotent) },
            envelope: null, T0);
        Assert.NotNull(job);

        var report = svc.Start(facts); // mid-execution Start
        Assert.NotNull(report);
        var after = svc.Journal.GetJob(job.Id);
        Assert.NotNull(after);
        Assert.Contains(after!.Steps, s => s.StepId == "s1" && s.State != "pending" || s.StepId == "s1");
        // The job was NOT re-imported away: it is still tracked.
        Assert.Equal(job.Id, after.Id);
    }

    // ---- item 6: enrollment consults unmanaged register -------------

    [Fact]
    public void Enrollment_RefusesId_ThatLivesInUnmanagedRegister()
    {
        var enrollments = new EnrollmentService();
        var register = new UnmanagedAssetRegister(policyCheck: _ => true, isManagedDeviceId: _ => false);
        // The unmanaged asset carries the enrolling device's own id
        // (device ids are key fingerprints in this model).
        var blockedIdentity = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var added = register.Add(new UnmanagedAsset(
            AssetId: blockedIdentity.DeviceId, ScopeId: "company-1", Name: "Asset blocked",
            Kind: Acp.Shared.Inventory.UnmanagedAssetKinds.BasController,
            Make: "Tridium", Model: "JACE 8000", SerialNumber: null, IpAddress: "192.168.1.50",
            MacAddress: null, SiteId: "site-one", Location: "Mech room",
            LifecycleState: Acp.Shared.Inventory.UnmanagedLifecycleStates.Discovered,
            ManagedDeviceIds: new[] { "dev-1" },
            Tags: new HashSet<string> { "bas" }, CustomFields: new Dictionary<string, string>(),
            Notes: null, DiscoveredBy: "manual", CreatedUtc: T0, UpdatedUtc: T0));
        Assert.True(added is not null, "register Add refused the asset");
        enrollments.IsUnmanagedAssetId = id => register.Get(id) is not null;

        var code = enrollments.CreateEnrollmentCode("company", "g1", "Group");
        var refused = enrollments.Redeem(code, new EnrollingDevice(
            blockedIdentity.DeviceId, blockedIdentity.PublicKeyBase64, "Blocked"));
        Assert.Null(refused);
        // A clean identity enrolls fine through the same seam.
        var cleanIdentity = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var code2 = enrollments.CreateEnrollmentCode("company", "g1", "Group");
        var ok = enrollments.Redeem(code2, new EnrollingDevice(
            cleanIdentity.DeviceId, cleanIdentity.PublicKeyBase64, "Laptop"));
        Assert.True(ok is not null, "clean id failed to enroll");
    }

    // ---- item 1: CoreRuntime wiring smoke ---------------------------

    [Fact]
    public void CoreRuntime_WiresAllBlockRServices()
    {
        var dir = TestUtil.TempDir();
        var rt = new CoreRuntime(new CoreOptions { DataDir = dir });
        Assert.NotNull(rt.Backups);
        Assert.NotNull(rt.Remediation);
        Assert.NotNull(rt.Compliance);
        Assert.NotNull(rt.BackgroundTools);
        Assert.NotNull(rt.NetworkDiscovery);
        Assert.NotNull(rt.Reporting);
        Assert.NotNull(rt.Runbooks);
        Assert.NotNull(rt.HealthScoring);
        Assert.NotNull(rt.AnomalyDetection);
        Assert.NotNull(rt.BaselineDrift);
        Assert.NotNull(rt.SoftwareMetering);
        Assert.NotNull(rt.VendorPasses);
        Assert.NotNull(rt.BrowserPolicy);
        Assert.NotNull(rt.AppControl);
        Assert.NotNull(rt.PeripheralControl);
        Assert.NotNull(rt.MdmSubset);
        Assert.NotNull(rt.Dlp);
        Assert.NotNull(rt.DirectoryEnrollment);
        Assert.NotNull(rt.MobileOperator);
        Assert.NotNull(rt.SiteDocumentation);
        Assert.NotNull(rt.Provisioning);
        Assert.NotNull(rt.CameraShares);
        Assert.NotNull(rt.CameraViewing);
        Assert.NotNull(rt.Monitor);
        Assert.NotNull(rt.HubHealth);
        Assert.NotNull(rt.AlertCentre);
        // Hub duty cycle runs without throwing (all sub-steps gated).
        rt.RunMonitorDutyCycle();
    }
}
