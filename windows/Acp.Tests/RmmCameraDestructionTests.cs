using System.Reflection;
using System.Text;
using Acp.Shared.Enterprise;
using Acp.Shared.Enrollment;
using Acp.Shared.Inventory;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.NetworkDiscovery;
using Acp.Shared.Roster;

namespace Acp.Tests;

// RMM-11 CAMERA EXTENSION — DESTRUCTION PASS. The camera bounds
// are the adoption: view without grant, view with policy OFF,
// inventory-only views, smuggled audio, audit-less views, RTSP
// SSRF, snapshot traversal. Every path must AUDIT or REFUSE —
// most must do both. Ledger:
// ~/workspace/builds/rmm-r-logs/ledger-rmm-camera.md
public class RmmCameraDestructionTests
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
            Roster.CreateScope(Scope, "company", "Company A");
            Roster.CreateUser("admin", Scope, "Admin", "human");
            Roster.AddCompanyAdmin(Scope, "admin");
            Roster.CreateUser("viewer", Scope, "Viewer", "human");
            Roster.CreateUser("outsider", Scope, "Outsider", "human");
            Roster.CreateUserGroup("ug-viewers", Scope, "Viewers", new[] { "viewer" });
            Roster.CreateDeviceGroup("dg-cams", Scope, "Cameras");
            Roster.AddGrant(Scope, "ug-viewers", "dg-cams", new[] { CameraRights.View });
            Views = new CameraViewService(Register, Roster, Policy, Audit, Sink, () => Now);
            var cam = new UnmanagedAsset(CamId, Scope, "Lobby camera", UnmanagedAssetKinds.Camera,
                "Hikvision", "DS-2CD2143", null, CamIp, "AA:BB:CC:00:00:50", null, null,
                UnmanagedLifecycleStates.Active, Array.Empty<string>(), new HashSet<string>(),
                new Dictionary<string, string>(), null, "manual", T0, T0,
                null, CameraViewCapabilities.Onvif, null);
            Assert.NotNull(Register.Add(cam));
            Assert.True(Views.AssignToDeviceGroup(CamId, "dg-cams", "admin"));
            Assert.True(Views.RegisterStreamUri(CamId, $"rtsp://{CamIp}:554/stream1", "admin").Ok);
        }

        public void EnableViewing()
        {
            Policy.AddDocument(new ManagementPolicyDocument("doc-cam", PolicyLevels.Org, Scope,
                new Dictionary<string, string> { [CameraPolicyKeys.ViewingEnabled] = "true" }, 1));
        }
    }

    // DG-RCAM-01 — view without grant: refused, sink untouched,
    // and the attempt itself is chained.
    [Fact]
    public void ATTACK_ViewWithoutGrant_RefusedSinkUntouchedAudited()
    {
        var rig = new Rig();
        rig.EnableViewing();
        var before = rig.Audit.Entries.Count;
        var result = rig.Views.StartView(Scope, "outsider", CamId);
        Assert.False(result.Ok);
        Assert.Empty(rig.Sink.Opened);
        Assert.True(rig.Audit.Entries.Count > before);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "camera_view_refused" && e.Actor == "outsider");
        Assert.True(rig.Audit.Verify().Ok);
    }

    // DG-RCAM-02 — view with a valid grant but policy OFF (the
    // seeded default): refused. Policy is a gate independent of
    // grants; neither substitutes for the other.
    [Fact]
    public void ATTACK_ViewWithGrantButPolicyOff_Refused()
    {
        var rig = new Rig(); // no enabling document: seeded OFF
        var result = rig.Views.StartView(Scope, "viewer", CamId);
        Assert.False(result.Ok);
        Assert.Contains("disabled by policy", result.Reason);
        Assert.Empty(rig.Sink.Opened);
        // And the company admin — who holds every grant — is ALSO
        // refused by the policy gate.
        Assert.False(rig.Views.StartView(Scope, "admin", CamId).Ok);
        Assert.Empty(rig.Sink.Opened);
    }

    // DG-RCAM-03 — inventory-only camera view attempts: every
    // actor class refused, reason stated, sink untouched.
    [Fact]
    public void ATTACK_InventoryOnlyCamera_ViewAttemptsRefused()
    {
        var rig = new Rig();
        rig.EnableViewing();
        var ring = new UnmanagedAsset("cam-ring", Scope, "Doorbell", UnmanagedAssetKinds.Camera,
            "Ring", "Video Doorbell", null, "10.0.0.51", "AA:BB:CC:00:00:51", null, null,
            UnmanagedLifecycleStates.Active, Array.Empty<string>(), new HashSet<string>(),
            new Dictionary<string, string>(), null, "manual", T0, T0,
            null, CameraViewCapabilities.InventoryOnly,
            "Cloud-locked consumer camera (ring): no local ONVIF/RTSP stream.");
        Assert.NotNull(rig.Register.Add(ring));
        Assert.True(rig.Views.AssignToDeviceGroup("cam-ring", "dg-cams", "admin"));
        foreach (var actor in new[] { "viewer", "admin" })
        {
            var result = rig.Views.StartView(Scope, actor, "cam-ring");
            Assert.False(result.Ok);
            Assert.Contains("inventory-only", result.Reason);
        }
        Assert.Empty(rig.Sink.Opened);
    }

    // DG-RCAM-04 — audio smuggled into a view: includeAudio with
    // no audio policy, and with audio policy but no admin grant.
    // Both refuse the WHOLE view (no silent video-only downgrade
    // that would let a caller believe audio state differs).
    [Fact]
    public void ATTACK_AudioSmuggled_RefusedWholeView()
    {
        var rig = new Rig();
        rig.EnableViewing(); // audio policy OFF
        Assert.False(rig.Views.StartView(Scope, "viewer", CamId, includeAudio: true).Ok);
        Assert.Empty(rig.Sink.Opened);

        var rig2 = new Rig();
        rig2.Policy.AddDocument(new ManagementPolicyDocument("doc-cam2", PolicyLevels.Org, Scope,
            new Dictionary<string, string>
            {
                [CameraPolicyKeys.ViewingEnabled] = "true",
                [CameraPolicyKeys.AudioEnabled] = "true",
            }, 1));
        // Audio policy ON, but "viewer" holds only the view grant.
        Assert.False(rig2.Views.StartView(Scope, "viewer", CamId, includeAudio: true).Ok);
        Assert.Empty(rig2.Sink.Opened);
        // No sink open anywhere ever carried audio in this test.
        Assert.All(rig.Sink.Opened.Concat(rig2.Sink.Opened), o => Assert.False(o.Audio));
    }

    // DG-RCAM-05 — audit-less view attempts: hammer every refusal
    // path; each one must grow the chain, the chain must verify,
    // and the sink must never open. A view that starts when the
    // stream layer fails is also closed out in the audit.
    [Fact]
    public void ATTACK_NoAuditlessPath_EveryRefusalChains()
    {
        var rig = new Rig();
        var attempts = new List<Func<ViewStartResult>>
        {
            () => rig.Views.StartView(Scope, "viewer", "ghost-cam"),     // unknown
            () => rig.Views.StartView("other", "viewer", CamId),         // cross-scope
            () => rig.Views.StartView(Scope, "outsider", CamId),         // policy off (also no grant)
            () => rig.Views.StartView(Scope, "viewer", CamId, true),     // audio smuggle
        };
        foreach (var attempt in attempts)
        {
            var before = rig.Audit.Entries.Count;
            Assert.False(attempt().Ok);
            Assert.True(rig.Audit.Entries.Count > before, "a refusal path did not audit");
        }
        rig.EnableViewing();
        rig.Sink.FailOpen = true;
        var beforeFail = rig.Audit.Entries.Count;
        Assert.False(rig.Views.StartView(Scope, "viewer", CamId).Ok);
        Assert.Contains(rig.Audit.Entries.Skip(beforeFail), e => e.Kind == "camera_view_failed");
        Assert.Empty(rig.Views.Sessions);
        Assert.True(rig.Audit.Verify().Ok);
    }

    // DG-RCAM-06 — RTSP URI injection (SSRF through the viewer):
    // URIs pointing at loopback, the cloud-metadata address,
    // internal services on other ports, OTHER devices, and
    // credential-carrying URIs are all refused at registration —
    // and the register itself refuses those IPs at filing time
    // (two independent lines).
    [Fact]
    public void ATTACK_RtspUriInjection_InternalServicesRefused()
    {
        var rig = new Rig();
        var cam = rig.Register.Get(CamId)!;
        string[] attacks =
        {
            "rtsp://127.0.0.1:554/stream",              // loopback (also not the camera)
            "rtsp://169.254.169.254:554/latest",        // cloud metadata
            $"rtsp://{CamIp}:22/stream",                // the camera's SSH port, not RTSP
            $"rtsp://{CamIp}:80/stream",                // HTTP admin surface
            $"rtsp://{CamIp}:3389/stream",              // RDP-shaped
            "rtsp://10.0.0.1:554/stream",               // the site's gateway, not the camera
            $"rtsp://admin:hunter2@{CamIp}:554/stream", // credentials in the URI
            $"rtsp://{CamIp}:554/stream?url=http://169.254.169.254/", // query smuggle
            $"https://{CamIp}:554/stream",              // wrong scheme entirely
        };
        foreach (var uri in attacks)
            Assert.False(RtspUriGuard.Validate(cam, uri).Ok, uri);
        foreach (var uri in attacks)
            Assert.False(rig.Views.RegisterStreamUri(CamId, uri, "admin").Ok, uri);
        // The good URI still registers afterwards (refusals are not sticky).
        Assert.True(rig.Views.RegisterStreamUri(CamId, $"rtsp://{CamIp}:554/stream1", "admin").Ok);
    }

    // DG-RCAM-07 — the camera record's address is changed AFTER a
    // good URI was registered (admin error or tampered record):
    // the view re-validates and refuses — registration-time checks
    // alone would have waved it through.
    [Fact]
    public void ATTACK_UriRevalidatedAtViewTime_RecordAddressChangeRefuses()
    {
        var rig = new Rig();
        rig.EnableViewing();
        var cam = rig.Register.Get(CamId)!;
        var moved = cam with { IpAddress = "10.0.0.60" };
        Assert.True(rig.Register.Update(moved));
        var result = rig.Views.StartView(Scope, "viewer", CamId);
        Assert.False(result.Ok);
        Assert.Contains("re-validation", result.Reason);
        Assert.Empty(rig.Sink.Opened);
    }

    // DG-RCAM-08 — snapshot path traversal: the guard builds the
    // filename itself; hostile asset ids / base dirs cannot escape.
    [Fact]
    public void ATTACK_SnapshotPathTraversal_Refused()
    {
        var baseDir = Path.Combine(Path.GetTempPath(), "acp-cam-guard");
        Assert.Null(SnapshotPathGuard.Resolve(baseDir, "../evil", T0));
        Assert.Null(SnapshotPathGuard.Resolve(baseDir, "..\\evil", T0));
        Assert.Null(SnapshotPathGuard.Resolve(baseDir, "a/b", T0));
        Assert.Null(SnapshotPathGuard.Resolve(baseDir, "", T0));
        Assert.Null(SnapshotPathGuard.Resolve("", "cam-1", T0));
        var ok = SnapshotPathGuard.Resolve(baseDir, "cam-1", T0);
        Assert.NotNull(ok);
        Assert.StartsWith(Path.GetFullPath(baseDir), ok);
    }

    // DG-RCAM-09 — XXE / oversized ONVIF answers: DTDs prohibited,
    // size capped; both refuse as null, never throw.
    [Fact]
    public void ATTACK_OnvifXxeAndOversize_Refused()
    {
        const string xxe = """
            <?xml version="1.0"?>
            <!DOCTYPE Envelope [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
            <Envelope><Body><ProbeMatches><ProbeMatch><XAddrs>&xxe;</XAddrs></ProbeMatch></ProbeMatches></Body></Envelope>
            """;
        Assert.Null(OnvifParsers.ParseProbeMatches(Encoding.UTF8.GetBytes(xxe)));
        var oversized = new byte[OnvifParsers.MaxXmlBytes + 1];
        Assert.Null(OnvifParsers.ParseProbeMatches(oversized));
        Assert.Empty(OnvifParsers.ParseProfiles(oversized));
        Assert.Null(OnvifParsers.ParseStreamUri(oversized));
        // Billion-laughs shape (nested entities) dies with the DTD ban too.
        const string laughs = """
            <?xml version="1.0"?>
            <!DOCTYPE lolz [ <!ENTITY lol "lollollollollollollollollol"> <!ENTITY lol2 "&lol;&lol;&lol;&lol;"> ]>
            <Envelope><Body><ProbeMatches><ProbeMatch><XAddrs>&lol2;</XAddrs></ProbeMatch></ProbeMatches></Body></Envelope>
            """;
        Assert.Null(OnvifParsers.ParseProbeMatches(Encoding.UTF8.GetBytes(laughs)));
    }

    // DG-RCAM-10 — the no-recording bound is STRUCTURAL: the view
    // service exposes no record / retain / motion / NVR surface at
    // all. If a future edit adds one, this test fails by name.
    [Fact]
    public void ATTACK_NoRecordingSurface_ExistsOnTheViewService()
    {
        var methods = typeof(CameraViewService)
            .GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Select(m => m.Name).ToList();
        foreach (var banned in new[] { "Record", "Retain", "Motion", "Archive", "Store" })
            Assert.DoesNotContain(methods, m => m.Contains(banned, StringComparison.OrdinalIgnoreCase));
    }

    // DG-RCAM-11 — a suspended user's grant evaporates: the roster
    // check is live at view time, not cached at assignment time.
    [Fact]
    public void ATTACK_SuspendedViewer_ViewRefused()
    {
        var rig = new Rig();
        rig.EnableViewing();
        Assert.True(rig.Roster.SetUserSuspended(Scope, "viewer", true));
        var result = rig.Views.StartView(Scope, "viewer", CamId);
        Assert.False(result.Ok);
        Assert.Contains("no 'view' grant", result.Reason);
        Assert.Empty(rig.Sink.Opened);
    }

    // DG-RCAM-12 — cross-scope grant bleed: a view grant in ANOTHER
    // scope (same group ids, different scope) buys nothing here.
    [Fact]
    public void ATTACK_CrossScopeGrantBuysNothing()
    {
        var rig = new Rig();
        rig.EnableViewing();
        // Build a parallel scope where "viewer" DOES hold view on dg-cams.
        rig.Roster.CreateScope("co-2", "company", "Other Co");
        rig.Roster.CreateUser("viewer", "co-2", "Viewer Two", "human");
        rig.Roster.CreateUserGroup("ug-viewers", "co-2", "Viewers", new[] { "viewer" });
        rig.Roster.CreateDeviceGroup("dg-cams-2", "co-2", "Cameras");
        rig.Roster.AddGrant("co-2", "ug-viewers", "dg-cams-2", new[] { CameraRights.View });
        // The co-1 camera still refuses co-2's context: wrong scope id.
        Assert.False(rig.Views.StartView("co-2", "viewer", CamId).Ok);
        Assert.Empty(rig.Sink.Opened);
    }
}
