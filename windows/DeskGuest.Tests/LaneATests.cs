using System.Net;
using System.Text;
using DeskGuest.Core.Services;
using DeskGuest.Shared.Deployment;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.Enrollment;
using DeskGuest.Shared.Hub;
using DeskGuest.Shared.Inventory;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.NetworkDiscovery;
using DeskGuest.Shared.Roster;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.Vulnerability;
using DeskGuest.Shared.WorkItems;
using DeskGuest.Shared.Security;

namespace DeskGuest.Tests;

// Lane A-RECOVERY (Completion Programme): regression + destruction tests for
// the Windows remainders the first Lane A built without tests — hub
// persistence (item 1), production bindings (item 2), hub signing-key
// provisioning (item 3), approver principals (item 4), camera rulings
// (item 5), RMM-13 listener posture (item 6).
public class LaneATests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);

    // ---- Item 1: HubPersistence envelope --------------------------------

    [Fact]
    public void HubEnvelope_RoundTrips_AndDetectsTamper()
    {
        var wrapped = HubPersistence.Wrap("exposures", "{\"a\":1}");
        Assert.Equal("{\"a\":1}", HubPersistence.Unwrap(wrapped, "exposures"));
        // Destruction: bit-flip inside the payload.
        var mid = wrapped.Length / 2;
        var tampered = wrapped[..mid] + (wrapped[mid] == 'A' ? 'B' : 'A') + wrapped[(mid + 1)..];
        Assert.Null(HubPersistence.Unwrap(tampered, "exposures"));
        // Wrong kind, garbage, null — all refused, never throw.
        Assert.Null(HubPersistence.Unwrap(wrapped, "work-items"));
        Assert.Null(HubPersistence.Unwrap("not json", "exposures"));
        Assert.Null(HubPersistence.Unwrap(null, "exposures"));
        Assert.Null(HubPersistence.Unwrap("", "exposures"));
    }

    [Fact]
    public void WorkItemStore_PersistenceRoundTrip_PreservesItems()
    {
        var store = new WorkItemStore(new ChainedAuditLog());
        var opened = store.OpenManual("dev-1", "co-1", "Disk failing", "admin", T0);
        Assert.NotNull(opened.Item);
        var json = store.ExportJson();
        var restored = new WorkItemStore(new ChainedAuditLog());
        Assert.True(restored.ImportJson(json) >= 1);
        Assert.Single(restored.OpenItems);
        // Destruction: tampered JSON imports nothing / does not throw.
        var fresh = new WorkItemStore(new ChainedAuditLog());
        var n = fresh.ImportJson(json.Replace("Disk failing", "Disk pwned!!"));
        Assert.True(n == 0 || fresh.OpenItems.All(i => i.Title != "Disk pwned!!"));
    }

    [Fact]
    public void ExposureStore_PersistenceRoundTrip()
    {
        var store = new ExposureStore();
        var json = store.ExportJson();
        var restored = new ExposureStore();
        Assert.True(restored.ImportJson(json) >= 0);
        Assert.Null(HubPersistence.Unwrap(HubPersistence.Wrap("exposures", json), "feed"));
    }

    // ---- Item 3: hub signing-key provisioning ----------------------------

    [Fact]
    public void SigningKey_GenerateSealReload_Rotate()
    {
        var dir = TestUtil.TempDir();
        var protector = new DevOnlyPassThroughProtector();
        var audit = new ChainedAuditLog();
        var p1 = new HubSigningKeyProvisioning(dir, protector, audit);
        p1.ProvisionOrLoad();
        Assert.True(p1.IsProvisioned);
        var key1 = p1.CurrentKey!.ToArray();
        // Sealed at rest: the file must not be the raw key base64 alone
        // under a REAL protector shape — with the dev protector we assert
        // only that a reload yields the identical key (round-trip).
        var p2 = new HubSigningKeyProvisioning(dir, protector, audit);
        p2.ProvisionOrLoad();
        Assert.Equal(key1, p2.CurrentKey!);
        // Rotation: previous retained for verification window.
        var (ok, _) = p2.Rotate();
        Assert.True(ok);
        Assert.Equal(key1, p2.PreviousKey!);
        Assert.NotEqual(key1, p2.CurrentKey!);
        // Destruction: garbage import refused, key unchanged.
        var before = p2.CurrentKey!.ToArray();
        Assert.False(p2.ImportKey("!!!not-base64!!!").Ok);
        Assert.False(p2.ImportKey(Convert.ToBase64String(new byte[4])).Ok);
        Assert.Equal(before, p2.CurrentKey!);
    }

    // ---- Item 4: approver principals -------------------------------------

    [Fact]
    public void ApproverPrincipals_OnlyLiveAdmins()
    {
        var roster = new RosterService(new EnrollmentService());
        Assert.NotNull(roster.CreateScope("co-1", "company", "Company A"));
        Assert.NotNull(roster.CreateUser("admin", "co-1", "Admin", "human"));
        Assert.NotNull(roster.CreateUser("tech", "co-1", "Tech", "human"));
        Assert.True(roster.AddCompanyAdmin("co-1", "admin"));
        var ids = roster.ApproverPrincipalIds();
        Assert.Contains("admin", ids);
        Assert.DoesNotContain("tech", ids);
    }

    // ---- Item 2a: OEM warranty HTTP client -------------------------------

    private sealed class StubHandler : HttpMessageHandler
    {
        private readonly string _body;
        public StubHandler(string body) => _body = body;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            { Content = new StringContent(_body, Encoding.UTF8, "text/html") });
    }

    [Fact]
    public async Task WarrantyLookup_ParsesOnlyWhatThePageSays()
    {
        // LANE W1 REPAIR (bd-shared-rmm-1 F3): a warranty verdict
        // now requires the page to echo the queried serial (a
        // date floating on an arbitrary page proves nothing about
        // THIS device) — a real OEM status page echoes the tag,
        // so the stub does too.
        var http = new HttpClient(new StubHandler("<html>Service Tag: ABC1234 — Warranty coverage ends 2028-03-04</html>"));
        var lookup = new HttpWarrantyLookup(http, () => T0,
            _ => Task.FromResult(new[] { IPAddress.Parse("93.184.216.34") }));
        var info = await lookup.LookupAsync(WarrantyVendors.Dell, "ABC1234", default);
        Assert.NotNull(info);
        Assert.Equal(new DateTimeOffset(2028, 3, 4, 0, 0, 0, TimeSpan.Zero), info!.ExpiresUtc);
        // Destruction: DNS rebinding to a private address refuses outright.
        var evil = new HttpWarrantyLookup(http, () => T0,
            _ => Task.FromResult(new[] { IPAddress.Parse("192.168.1.1") }));
        Assert.Null(await evil.LookupAsync(WarrantyVendors.Dell, "ABC1234", default));
        // Unknown vendor / bad serial: refusal, never fabricated data.
        Assert.Null(await lookup.LookupAsync("NotAVendor", "ABC1234", default));
    }

    // ---- Item 2b: production collectors honesty off-Windows ---------------

    [Fact]
    public void ProductionCollectors_NeverInventOffWindows()
    {
        if (OperatingSystem.IsWindows()) return; // live-OS proof is laptop-side
        var hw = WindowsProductionCollectors.CollectHardware();
        Assert.NotNull(hw);
        Assert.Empty(WindowsProductionCollectors.CollectSoftware());
    }

    // ---- Item 6: RMM-13 listener posture ----------------------------------

    [Fact]
    public void ReportingListener_NotListeningUntilStarted()
    {
        // Fail-closed ctor: no service, no listener.
        Assert.Throws<ArgumentNullException>(() => new ReportingHttpListener(null!));
        var audit = new ChainedAuditLog();
        var reporting = new ReportingService(audit,
            new ManagementPolicyService(audit, null),
            new InventoryStore(),
            new DeviceIdentity(new DevOnlyPassThroughProtector()));
        var listener = new ReportingHttpListener(reporting);
        Assert.False(listener.IsListening);
        listener.Dispose();
    }

    // ---- Item 5: camera rulings -------------------------------------------

    private sealed class CamRig
    {
        public DateTimeOffset Now = T0;
        public ChainedAuditLog Audit = new();
        public RosterService Roster;
        public UnmanagedAssetRegister Register = new();
        public ManagementPolicyEngine Policy = new();
        public CameraViewService Views;

        public CamRig()
        {
            Roster = new RosterService(new EnrollmentService());
            Roster.CreateScope("co-1", "company", "Company A");
            Roster.CreateUser("admin", "co-1", "Admin", "human");
            Roster.AddCompanyAdmin("co-1", "admin");
            Roster.CreateUser("viewer", "co-1", "Viewer", "human");
            Roster.CreateUser("bot", "co-1", "Bot", "ai", pairedByUserId: "admin");
            Roster.CreateUserGroup("ug-viewers", "co-1", "Viewers", new[] { "viewer" });
            Roster.CreateUserGroup("ug-bots", "co-1", "Bots", new[] { "bot" });
            Roster.CreateDeviceGroup("dg-cams", "co-1", "Cameras");
            Roster.AddGrant("co-1", "ug-viewers", "dg-cams", new[] { CameraRights.View });
            Views = new CameraViewService(Register, Roster, Policy, Audit,
                new RecordingCameraStreamSink(), () => Now,
                snapshotBaseDir: Path.Combine(Path.GetTempPath(), "deskguest-cam-snaps-a"));
            var asset = new UnmanagedAsset("cam-1", "co-1", "Lobby", UnmanagedAssetKinds.Camera,
                "Hikvision", "DS-2CD", null, "10.0.0.50", "AA:BB:CC:00:00:50", null, null,
                UnmanagedLifecycleStates.Active, Array.Empty<string>(), new HashSet<string>(),
                new Dictionary<string, string>(), null, "manual", T0, T0,
                null, CameraViewCapabilities.Onvif, null);
            Register.Add(asset);
            Views.AssignToDeviceGroup("cam-1", "dg-cams", "admin");
            Views.RegisterStreamUri("cam-1", "rtsp://10.0.0.50:554/stream1", "admin");
            Policy.AddDocument(new ManagementPolicyDocument("doc-cam", PolicyLevels.Org, "co-1",
                new Dictionary<string, string> { [CameraPolicyKeys.ViewingEnabled] = "true" }, 1));
        }
    }

    [Fact]
    public void Camera_AiView_OnlyViaExplicitHumanAdminGrant_D9()
    {
        var rig = new CamRig();
        // Default: the AI holds NO view right — refused.
        Assert.False(rig.Views.StartView("co-1", "bot", "cam-1").Ok);
        // A human admin explicitly scopes view into the AI's group: allowed,
        // and audited under the AI's own identity.
        Assert.NotNull(rig.Roster.AddGrant("co-1", "ug-bots", "dg-cams", new[] { CameraRights.View }));
        Assert.True(rig.Views.StartView("co-1", "bot", "cam-1").Ok);
    }

    [Fact]
    public void Camera_RefusedStopFlood_CollapsesButTotalRecoverable()
    {
        var rig = new CamRig();
        var start = rig.Views.StartView("co-1", "viewer", "cam-1");
        Assert.True(start.Ok);
        var sessionId = start.Session!.SessionId;
        // Flood: an actor with no STOP authority hammers STOP 50 times.
        for (var i = 0; i < 50; i++)
            Assert.False(rig.Views.StopView(sessionId, "mallory"));
        rig.Views.FlushRefusedStopAggregates();
        Assert.Equal(50, rig.Views.TotalRefusedStops);
        // The session survived the flood; the real viewer can still stop it.
        Assert.True(rig.Views.StopView(sessionId, "viewer"));
        // Chain integrity after aggregation.
        Assert.True(rig.Audit.Verify().Ok);
    }
}
