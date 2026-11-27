using System.Text;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.Enrollment;
using DeskGuest.Shared.Inventory;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.NetworkDiscovery;
using DeskGuest.Shared.Roster;

namespace DeskGuest.Tests;

// RMM-11 EXTENSION — Camera viewing: ONVIF parsers, cloud-locked
// classification, the D12 view right, the policy gate (seeded
// OFF), the RTSP guard, hash-chained audit of every view.
public class RmmCameraTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    private const string Scope = "co-1";
    private const string CamIp = "10.0.0.50";
    private const string CamId = "cam-lobby";

    private sealed class Rig
    {
        public DateTimeOffset Now = T0;
        public ChainedAuditLog Audit = new();
        public RosterService Roster;
        public UnmanagedAssetRegister Register = new();
        public ManagementPolicyEngine Policy = new();
        public RecordingCameraStreamSink Sink = new();
        public CameraViewService Views = null!;

        public Rig()
        {
            Roster = new RosterService(new EnrollmentService());
            Assert.NotNull(Roster.CreateScope(Scope, "company", "Company A"));
            Assert.NotNull(Roster.CreateUser("admin", Scope, "Admin", "human"));
            Assert.True(Roster.AddCompanyAdmin(Scope, "admin"));
            Assert.NotNull(Roster.CreateUser("viewer", Scope, "Viewer", "human"));
            Assert.NotNull(Roster.CreateUser("lead", Scope, "Lead", "human"));
            Assert.NotNull(Roster.CreateUser("outsider", Scope, "Outsider", "human"));
            Assert.NotNull(Roster.CreateUserGroup("ug-viewers", Scope, "Viewers", new[] { "viewer" }));
            Assert.NotNull(Roster.CreateUserGroup("ug-leads", Scope, "Leads", new[] { "lead" }));
            Assert.NotNull(Roster.CreateDeviceGroup("dg-cams", Scope, "Cameras"));
            Assert.NotNull(Roster.AddGrant(Scope, "ug-viewers", "dg-cams", new[] { CameraRights.View }));
            Assert.NotNull(Roster.AddGrant(Scope, "ug-leads", "dg-cams", new[] { CameraRights.View, "admin" }));
            Views = new CameraViewService(Register, Roster, Policy, Audit, Sink, () => Now,
                snapshotBaseDir: Path.Combine(Path.GetTempPath(), "deskguest-cam-snaps"));
        }

        public UnmanagedAsset AddCamera(string id = CamId, string ip = CamIp,
            string capability = CameraViewCapabilities.Onvif, string? reason = null,
            string make = "Hikvision", string model = "DS-2CD2143")
        {
            var asset = new UnmanagedAsset(id, Scope, "Lobby camera", UnmanagedAssetKinds.Camera,
                make, model, null, ip, "AA:BB:CC:00:00:50", null, null,
                UnmanagedLifecycleStates.Active, Array.Empty<string>(), new HashSet<string>(),
                new Dictionary<string, string>(), null, "manual", T0, T0,
                null, capability, reason);
            var added = Register.Add(asset);
            Assert.NotNull(added);
            return added!;
        }

        public void EnableViewing(bool audio = false)
        {
            var settings = new Dictionary<string, string> { [CameraPolicyKeys.ViewingEnabled] = "true" };
            if (audio) settings[CameraPolicyKeys.AudioEnabled] = "true";
            Policy.AddDocument(new ManagementPolicyDocument("doc-cam", PolicyLevels.Org, Scope, settings, 1));
        }

        /// <summary>A fully-wired viewable camera: record + group + URI.</summary>
        public UnmanagedAsset ViewableCamera()
        {
            var cam = AddCamera();
            Assert.True(Views.AssignToDeviceGroup(CamId, "dg-cams", "admin"));
            Assert.True(Views.RegisterStreamUri(CamId, $"rtsp://{CamIp}:554/stream1", "admin").Ok);
            return cam;
        }
    }

    // ---- ONVIF parsers ------------------------------------------------

    private const string ProbeMatchesXml = """
        <?xml version="1.0" encoding="utf-8"?>
        <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">
          <s:Body>
            <d:ProbeMatches>
              <d:ProbeMatch>
                <d:XAddrs>http://10.0.0.50/onvif/device_service</d:XAddrs>
                <d:Types>dn:NetworkVideoTransmitter</d:Types>
                <d:Scopes>onvif://www.onvif.org/type/video_encoder onvif://www.onvif.org/manufacturer/Hikvision onvif://www.onvif.org/name/DS-2CD2143 onvif://www.onvif.org/location/lobby</d:Scopes>
              </d:ProbeMatch>
            </d:ProbeMatches>
          </s:Body>
        </s:Envelope>
        """;

    [Fact]
    public void Onvif_ProbeMatches_ParsesAddressTypesAndMakeModel()
    {
        var info = OnvifParsers.ParseProbeMatches(Encoding.UTF8.GetBytes(ProbeMatchesXml));
        Assert.NotNull(info);
        Assert.Equal("http://10.0.0.50/onvif/device_service", info!.XAddr);
        Assert.Contains(info.Types, t => t.Contains("NetworkVideoTransmitter"));
        Assert.Equal("Hikvision", info.Make);
        Assert.Equal("DS-2CD2143", info.Model);
        Assert.Null(OnvifParsers.ParseProbeMatches(Encoding.UTF8.GetBytes("<not-xml")));
        Assert.Null(OnvifParsers.ParseProbeMatches(ReadOnlySpan<byte>.Empty));
    }

    [Fact]
    public void Onvif_ProfilesAndStreamUri_Parse()
    {
        const string profiles = """
            <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:trt="http://www.onvif.org/ver10/media/wsdl">
              <s:Body><trt:GetProfilesResponse>
                <trt:Profiles token="Profile_1"><Name>MainStream</Name></trt:Profiles>
                <trt:Profiles token="Profile_2"><Name>SubStream</Name></trt:Profiles>
              </trt:GetProfilesResponse></s:Body>
            </s:Envelope>
            """;
        var parsed = OnvifParsers.ParseProfiles(Encoding.UTF8.GetBytes(profiles));
        Assert.Equal(2, parsed.Count);
        Assert.Equal("Profile_1", parsed[0].Token);
        Assert.Equal("MainStream", parsed[0].Name);

        const string streamUri = """
            <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:trt="http://www.onvif.org/ver10/media/wsdl">
              <s:Body><trt:GetStreamUriResponse><trt:MediaUri><Uri>rtsp://10.0.0.50:554/stream1</Uri></trt:MediaUri></trt:GetStreamUriResponse></s:Body>
            </s:Envelope>
            """;
        Assert.Equal("rtsp://10.0.0.50:554/stream1",
            OnvifParsers.ParseStreamUri(Encoding.UTF8.GetBytes(streamUri)));
    }

    // ---- cloud classification -------------------------------------------

    [Fact]
    public void CloudClassifier_RingNestWyzeBlinkArlo_AreInventoryOnlyWithPlainReason()
    {
        foreach (var make in new[] { "Ring", "Nest", "Wyze", "Blink", "Arlo" })
        {
            var (locked, reason) = CloudCameraClassifier.Classify(make, "Cam", null, false, false);
            Assert.True(locked, make);
            Assert.Contains("no local ONVIF/RTSP stream", reason);
            Assert.Contains("Inventory-only", reason);
        }
        // Capability evidence outranks brand: RTSP-firmware Wyze is viewable.
        Assert.False(CloudCameraClassifier.Classify("Wyze", "Cam v3", null, false, true).CloudLocked);
        Assert.False(CloudCameraClassifier.Classify("Hikvision", "DS", null, false, false).CloudLocked);
    }

    [Fact]
    public void CapabilityFor_OnvifRtspAndUnknown()
    {
        Assert.Equal((CameraViewCapabilities.Onvif, (string?)null),
            CloudCameraClassifier.CapabilityFor(true, false, "Hikvision", "DS", null));
        Assert.Equal(CameraViewCapabilities.Rtsp,
            CloudCameraClassifier.CapabilityFor(false, true, "Generic", "IP", null).Capability);
        var unknown = CloudCameraClassifier.CapabilityFor(false, false, "Generic", "IP", null);
        Assert.Equal(CameraViewCapabilities.InventoryOnly, unknown.Capability);
        Assert.Contains("did not advertise ONVIF or RTSP", unknown.Reason);
    }

    // ---- RTSP guard --------------------------------------------------------

    [Fact]
    public void RtspGuard_AcceptsTheCamerasOwnRtspUri_Only()
    {
        var rig = new Rig();
        var cam = rig.AddCamera();
        var (ok, _, normalized) = RtspUriGuard.Validate(cam, $"rtsp://{CamIp}:554/stream1");
        Assert.True(ok);
        Assert.Equal($"rtsp://{CamIp}:554/stream1", normalized);
        Assert.True(RtspUriGuard.Validate(cam, $"rtsp://{CamIp}:8554/live").Ok);
        Assert.False(RtspUriGuard.Validate(cam, $"http://{CamIp}:554/stream1").Ok);       // scheme
        Assert.False(RtspUriGuard.Validate(cam, "rtsp://10.0.0.99:554/stream1").Ok);      // another host
        Assert.False(RtspUriGuard.Validate(cam, $"rtsp://user:pass@{CamIp}:554/s").Ok);   // userinfo
        Assert.False(RtspUriGuard.Validate(cam, $"rtsp://{CamIp}:554/s?token=x").Ok);     // query
        Assert.False(RtspUriGuard.Validate(cam, $"rtsp://{CamIp}:22/stream1").Ok);        // ssh port
        Assert.False(RtspUriGuard.Validate(cam, $"rtsp://{CamIp}:554/../admin").Ok);      // traversal
        Assert.False(RtspUriGuard.Validate(cam, "rtsp://cam-hostname:554/s").Ok);         // hostname, not IP
        Assert.False(RtspUriGuard.Validate(cam, null).Ok);
    }

    // ---- the view gates --------------------------------------------------------

    [Fact]
    public void View_HappyPath_StartsAuditsAndStopsWithDuration()
    {
        var rig = new Rig();
        rig.ViewableCamera();
        rig.EnableViewing();
        var start = rig.Views.StartView(Scope, "viewer", CamId);
        Assert.True(start.Ok);
        Assert.NotNull(start.Session);
        Assert.False(start.Session!.AudioEnabled); // audio OFF by default
        Assert.Single(rig.Sink.Opened);
        Assert.Equal($"rtsp://{CamIp}:554/stream1", rig.Sink.Opened[0].Uri);
        Assert.False(rig.Sink.Opened[0].Audio);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "camera_view_started" && e.Actor == "viewer");

        rig.Now += TimeSpan.FromSeconds(95);
        Assert.True(rig.Views.StopView(start.Session.SessionId, "viewer"));
        Assert.Equal(new[] { start.Session.SessionId }, rig.Sink.Closed);
        var ended = rig.Audit.Entries.Single(e => e.Kind == "camera_view_ended");
        Assert.Contains("durationSeconds=95", ended.Detail);
        Assert.True(rig.Audit.Verify().Ok);
    }

    [Fact]
    public void View_PolicyOffByDefault_RefusedEvenWithGrant()
    {
        var rig = new Rig();
        rig.ViewableCamera();
        // rmm.camera_viewing.enabled is seeded OFF: no enabling doc.
        var start = rig.Views.StartView(Scope, "viewer", CamId);
        Assert.False(start.Ok);
        Assert.Contains("disabled by policy", start.Reason);
        Assert.Empty(rig.Sink.Opened);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "camera_view_refused");
    }

    [Fact]
    public void View_WithoutGrant_Refused()
    {
        var rig = new Rig();
        rig.ViewableCamera();
        rig.EnableViewing();
        var start = rig.Views.StartView(Scope, "outsider", CamId);
        Assert.False(start.Ok);
        Assert.Contains("no 'view' grant", start.Reason);
        Assert.Empty(rig.Sink.Opened);
    }

    [Fact]
    public void View_InventoryOnlyCamera_RefusedWithTheStatedReason()
    {
        var rig = new Rig();
        rig.AddCamera("cam-ring", "10.0.0.51", CameraViewCapabilities.InventoryOnly,
            "Cloud-locked consumer camera (ring): no local stream.", make: "Ring");
        rig.EnableViewing();
        var start = rig.Views.StartView(Scope, "admin", "cam-ring");
        Assert.False(start.Ok);
        Assert.Contains("inventory-only", start.Reason);
        Assert.Contains("Cloud-locked", start.Reason);
        Assert.Empty(rig.Sink.Opened);
    }

    [Fact]
    public void View_UnknownCrossScopeAndUngrouped_Refused()
    {
        var rig = new Rig();
        rig.EnableViewing();
        Assert.False(rig.Views.StartView(Scope, "viewer", "no-such-cam").Ok);
        rig.AddCamera();
        Assert.False(rig.Views.StartView("other-scope", "viewer", CamId).Ok); // cross-scope
        var ungrouped = rig.Views.StartView(Scope, "viewer", CamId);           // no group yet
        Assert.False(ungrouped.Ok);
        Assert.Contains("not filed in any device group", ungrouped.Reason);
        Assert.True(rig.Views.AssignToDeviceGroup(CamId, "dg-cams", "admin"));
        var noUri = rig.Views.StartView(Scope, "viewer", CamId);               // group but no URI
        Assert.False(noUri.Ok);
        Assert.Contains("no registered stream URI", noUri.Reason);
    }

    [Fact]
    public void View_CompanyAdmin_HoldsViewThroughScopeAdmin()
    {
        var rig = new Rig();
        rig.ViewableCamera();
        rig.EnableViewing();
        // The admin is in no user group: scope-admin holds every right.
        Assert.True(rig.Views.StartView(Scope, "admin", CamId).Ok);
    }

    // ---- audio ----------------------------------------------------------------

    [Fact]
    public void Audio_RequestedWithoutAudioPolicyOrGrant_Refused()
    {
        var rig = new Rig();
        rig.ViewableCamera();
        rig.EnableViewing(); // viewing on, audio policy still OFF
        var byViewer = rig.Views.StartView(Scope, "viewer", CamId, includeAudio: true);
        Assert.False(byViewer.Ok);
        Assert.Contains("audio", byViewer.Reason);
        // Even the lead (admin grant) is refused while the audio POLICY is off.
        var byLead = rig.Views.StartView(Scope, "lead", CamId, includeAudio: true);
        Assert.False(byLead.Ok);
        Assert.Empty(rig.Sink.Opened);
    }

    [Fact]
    public void Audio_WithAudioPolicyAndAdminGrant_Allowed_ViewerStillRefused()
    {
        var rig = new Rig();
        rig.ViewableCamera();
        rig.EnableViewing(audio: true);
        var lead = rig.Views.StartView(Scope, "lead", CamId, includeAudio: true);
        Assert.True(lead.Ok);
        Assert.True(lead.Session!.AudioEnabled);
        Assert.True(rig.Sink.Opened[0].Audio);
        // The plain viewer (view grant only, no admin grant) is still refused audio.
        Assert.False(rig.Views.StartView(Scope, "viewer", CamId, includeAudio: true).Ok);
        // And a plain view by anyone still carries NO audio.
        var plain = rig.Views.StartView(Scope, "lead", CamId);
        Assert.True(plain.Ok);
        Assert.False(plain.Session!.AudioEnabled);
    }

    // ---- snapshots + stop rights --------------------------------------------------

    [Fact]
    public void Snapshot_RequiresActiveOwnedView_AndPathStaysUnderBase()
    {
        var rig = new Rig();
        rig.ViewableCamera();
        rig.EnableViewing();
        var start = rig.Views.StartView(Scope, "viewer", CamId);
        Assert.True(start.Ok);
        // F1: the snapshot directory is the service's own — the
        // caller no longer supplies any path at all.
        var (ok, _, path) = rig.Views.TakeSnapshot(start.Session!.SessionId, "viewer");
        Assert.True(ok);
        Assert.NotNull(path);
        Assert.StartsWith(Path.GetFullPath(rig.Views.SnapshotBaseDir), path);
        Assert.EndsWith(".jpg", path);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "camera_snapshot");
        // Another user's snapshot on this view is refused.
        var foreign = rig.Views.TakeSnapshot(start.Session.SessionId, "lead");
        Assert.False(foreign.Ok);
        // After the view ends, snapshots end with it.
        rig.Views.StopView(start.Session.SessionId, "viewer");
        Assert.False(rig.Views.TakeSnapshot(start.Session.SessionId, "viewer").Ok);
    }

    [Fact]
    public void StopView_OnlyOwnerOrCompanyAdmin()
    {
        var rig = new Rig();
        rig.ViewableCamera();
        rig.EnableViewing();
        var start = rig.Views.StartView(Scope, "viewer", CamId);
        Assert.True(start.Ok);
        Assert.False(rig.Views.StopView(start.Session!.SessionId, "lead")); // not owner, not company admin
        Assert.True(rig.Views.Sessions.Single().IsActive);
        Assert.True(rig.Views.StopView(start.Session.SessionId, "admin"));   // company admin may end it
        Assert.False(rig.Views.Sessions.Single().IsActive);
        Assert.False(rig.Views.StopView(start.Session.SessionId, "admin")); // already ended
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "camera_view_stop_refused");
    }

    [Fact]
    public void RegisterStreamUri_FromOnvifResponse_Validated()
    {
        var rig = new Rig();
        rig.AddCamera();
        const string good = """
            <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>
            <GetStreamUriResponse><MediaUri><Uri>rtsp://10.0.0.50:554/stream1</Uri></MediaUri></GetStreamUriResponse>
            </s:Body></s:Envelope>
            """;
        Assert.True(rig.Views.RegisterStreamUriFromOnvif(CamId, Encoding.UTF8.GetBytes(good), "admin").Ok);
        const string evil = """
            <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>
            <GetStreamUriResponse><MediaUri><Uri>rtsp://127.0.0.1:554/stream1</Uri></MediaUri></GetStreamUriResponse>
            </s:Body></s:Envelope>
            """;
        var (ok, reason) = rig.Views.RegisterStreamUriFromOnvif(CamId, Encoding.UTF8.GetBytes(evil), "admin");
        Assert.False(ok);
        Assert.Contains("SSRF", reason);
    }
}
