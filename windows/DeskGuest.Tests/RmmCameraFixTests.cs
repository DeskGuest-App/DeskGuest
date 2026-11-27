using System.Globalization;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.Enrollment;
using DeskGuest.Shared.Inventory;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.NetworkDiscovery;
using DeskGuest.Shared.Roster;

namespace DeskGuest.Tests;

// D38 CAMERA-EXTENSION FIX LANE — regression tests for findings
// F1–F10 + F12 of packet 5a9d0d59 (F11 is a packet-completeness
// verification, evidenced in the lane log, not a code test).
// Every test here failed against the pre-fix code by construction
// (new API surface or new behavior) or by assertion.
public class RmmCameraFixTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    private const string Scope = "co-1";
    private const string CamIp = "10.0.0.50";
    private const string CamId = "cam-lobby";

    /// <summary>A sink that can be told to throw at each stage —
    /// the double the F2 finding noted did not exist.</summary>
    private sealed class ThrowingSink : ICameraStreamSink
    {
        public List<string> Opened { get; } = new();
        public List<string> Closed { get; } = new();
        public List<string> Snapshots { get; } = new();
        public bool ThrowOnOpen, ThrowOnCapture, ThrowOnClose, WriteFileOnCapture;

        public (bool Ok, string Detail) OpenStream(string viewSessionId, string assetId, string rtspUri, bool audioEnabled)
        {
            Opened.Add(viewSessionId); // the stream IS open internally…
            if (ThrowOnOpen) throw new InvalidOperationException("sink exploded after opening");
            return (true, "opened");
        }
        public void CloseStream(string viewSessionId)
        {
            Closed.Add(viewSessionId);
            if (ThrowOnClose) throw new InvalidOperationException("sink exploded on close");
        }
        public (bool Ok, string Detail) CaptureSnapshot(string viewSessionId, string targetPath)
        {
            if (WriteFileOnCapture) File.WriteAllText(targetPath, "jpeg-bytes");
            Snapshots.Add(targetPath); // …the file exists…
            if (ThrowOnCapture) throw new InvalidOperationException("sink exploded after writing");
            return (true, "captured");
        }
    }

    private sealed class Rig
    {
        public DateTimeOffset Now = T0;
        public ChainedAuditLog Audit = new();
        public RosterService Roster;
        public UnmanagedAssetRegister Register = new();
        public ManagementPolicyEngine Policy = new();
        public ICameraStreamSink Sink;
        public CameraViewService Views = null!;
        public string SnapshotDir = Path.Combine(Path.GetTempPath(), "deskguest-cam-fix-" + Guid.NewGuid().ToString("N"));

        public Rig(ICameraStreamSink? sink = null)
        {
            Sink = sink ?? new RecordingCameraStreamSink();
            Roster = new RosterService(new EnrollmentService());
            Roster.CreateScope(Scope, "company", "Company A");
            Roster.CreateUser("admin", Scope, "Admin", "human");
            Roster.AddCompanyAdmin(Scope, "admin");
            Roster.CreateUser("viewer", Scope, "Viewer", "human");
            Roster.CreateUser("lead", Scope, "Lead", "human");
            Roster.CreateUser("outsider", Scope, "Outsider", "human");
            Roster.CreateUserGroup("ug-viewers", Scope, "Viewers", new[] { "viewer" });
            Roster.CreateUserGroup("ug-leads", Scope, "Leads", new[] { "lead" });
            Roster.CreateDeviceGroup("dg-cams", Scope, "Cameras");
            Roster.CreateDeviceGroup("dg-other", Scope, "Other Cams");
            Roster.AddGrant(Scope, "ug-viewers", "dg-cams", new[] { CameraRights.View });
            Roster.AddGrant(Scope, "ug-leads", "dg-cams", new[] { CameraRights.View, "admin" });
            Views = new CameraViewService(Register, Roster, Policy, Audit, Sink, () => Now,
                snapshotBaseDir: SnapshotDir);
        }

        public UnmanagedAsset AddCamera(string id = CamId, string ip = CamIp,
            string lifecycle = UnmanagedLifecycleStates.Active,
            string capability = CameraViewCapabilities.Onvif)
        {
            var asset = new UnmanagedAsset(id, Scope, "Lobby camera", UnmanagedAssetKinds.Camera,
                "Hikvision", "DS-2CD2143", null, ip, "AA:BB:CC:00:00:50", null, null,
                lifecycle, Array.Empty<string>(), new HashSet<string>(),
                new Dictionary<string, string>(), null, "manual", T0, T0,
                null, capability, null);
            var added = Register.Add(asset);
            Assert.NotNull(added);
            return added!;
        }

        public void EnableViewing()
        {
            Policy.AddDocument(new ManagementPolicyDocument("doc-cam", PolicyLevels.Org, Scope,
                new Dictionary<string, string> { [CameraPolicyKeys.ViewingEnabled] = "true" }, 1));
        }

        public CameraViewSession ViewableView()
        {
            AddCamera();
            Assert.True(Views.AssignToDeviceGroup(CamId, "dg-cams", "admin"));
            Assert.True(Views.RegisterStreamUri(CamId, $"rtsp://{CamIp}:554/stream1", "admin").Ok);
            EnableViewing();
            var start = Views.StartView(Scope, "viewer", CamId);
            Assert.True(start.Ok, start.Reason);
            return start.Session!;
        }
    }

    // F1 — the snapshot directory is the service's own; no caller
    // parameter exists that could aim writes at a UNC share, and
    // the guard itself refuses a UNC base as defence-in-depth.
    [Fact]
    public void F1_SnapshotDirIsServiceOwned_UncBaseRefusedByGuard()
    {
        var rig = new Rig();
        var session = rig.ViewableView();
        var (ok, _, path) = rig.Views.TakeSnapshot(session.SessionId, "viewer");
        Assert.True(ok);
        Assert.StartsWith(Path.GetFullPath(rig.SnapshotDir), path);
        Assert.Null(SnapshotPathGuard.Resolve(@"\\10.0.0.9\loot", "cam-1", T0));
        // The old caller-shaped API is gone: no TakeSnapshot
        // overload takes a directory.
        Assert.DoesNotContain(typeof(CameraViewService).GetMethods(),
            m => m.Name == "TakeSnapshot" && m.GetParameters().Any(p => p.ParameterType == typeof(string) && p.Name!.Contains("dir", StringComparison.OrdinalIgnoreCase)));
    }

    // F2 — a sink that throws after opening internally: the
    // failure is chained, the stream is closed best-effort, and
    // no session is left behind.
    [Fact]
    public void F2_OpenStreamThrows_FailureChained_NoSession_StreamClosed()
    {
        var sink = new ThrowingSink { ThrowOnOpen = true };
        var rig = new Rig(sink);
        rig.AddCamera();
        Assert.True(rig.Views.AssignToDeviceGroup(CamId, "dg-cams", "admin"));
        Assert.True(rig.Views.RegisterStreamUri(CamId, $"rtsp://{CamIp}:554/stream1", "admin").Ok);
        rig.EnableViewing();
        var start = rig.Views.StartView(Scope, "viewer", CamId);
        Assert.False(start.Ok);
        Assert.Contains("threw", start.Reason);
        Assert.Empty(rig.Views.Sessions);
        Assert.Single(sink.Closed); // best-effort close of the internally-opened stream
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "camera_view_failed");
        Assert.True(rig.Audit.Verify().Ok);
    }

    // F2 — a sink that writes the snapshot file and THEN throws:
    // the snapshot act is already on the chain (audit-first), and
    // the failure is chained after it.
    [Fact]
    public void F2_CaptureThrowsAfterWriting_SnapshotActAlreadyChained()
    {
        var sink = new ThrowingSink { ThrowOnCapture = true };
        var rig = new Rig(sink);
        var session = rig.ViewableView();
        var (ok, reason, _) = rig.Views.TakeSnapshot(session.SessionId, "viewer");
        Assert.False(ok);
        Assert.Contains("threw", reason);
        var kinds = rig.Audit.Entries.Select(e => e.Kind).ToList();
        Assert.Contains("camera_snapshot", kinds);
        Assert.Contains("camera_snapshot_failed", kinds);
        Assert.True(kinds.IndexOf("camera_snapshot") < kinds.IndexOf("camera_snapshot_failed"));
        Assert.True(rig.Audit.Verify().Ok);
    }

    // F2 — a sink that throws on close: the view still ends, the
    // end entry is chained, and the close failure is chained too.
    [Fact]
    public void F2_CloseStreamThrows_ViewStillEnds_BothFactsChained()
    {
        var sink = new ThrowingSink { ThrowOnClose = true };
        var rig = new Rig(sink);
        var session = rig.ViewableView();
        Assert.True(rig.Views.StopView(session.SessionId, "viewer"));
        Assert.False(rig.Views.Sessions.Single().IsActive);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "camera_view_ended");
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "camera_view_close_failed");
        Assert.True(rig.Audit.Verify().Ok);
    }

    // F3 — suspending the viewer mid-view: the next snapshot
    // revalidates, ends the view, closes the stream, refuses.
    [Fact]
    public void F3_SuspendedMidView_SnapshotRefused_ViewEnded_StreamClosed()
    {
        var rig = new Rig();
        var session = rig.ViewableView();
        Assert.True(rig.Roster.SetUserSuspended(Scope, "viewer", true));
        var (ok, reason, _) = rig.Views.TakeSnapshot(session.SessionId, "viewer");
        Assert.False(ok);
        Assert.Contains("no longer holds", reason);
        Assert.False(rig.Views.Sessions.Single().IsActive);
        Assert.Contains(rig.Audit.Entries,
            e => e.Kind == "camera_view_ended" && e.Detail.Contains("revalidation"));
    }

    // F3 — the sweep ends views whose grant was revoked or whose
    // camera moved groups, without anyone touching the view.
    [Fact]
    public void F3_RevalidateSweep_EndsRevokedAndMovedViews()
    {
        var rig = new Rig();
        var session = rig.ViewableView();
        Assert.Equal(0, rig.Views.RevalidateActiveViews()); // still authorized
        Assert.True(rig.Roster.RemoveGrant(Scope, "ug-viewers", "dg-cams", "admin"));
        Assert.Equal(1, rig.Views.RevalidateActiveViews());
        Assert.False(rig.Views.Sessions.Single().IsActive);

        var rig2 = new Rig();
        var session2 = rig2.ViewableView();
        Assert.True(rig2.Views.AssignToDeviceGroup(CamId, "dg-other", "admin")); // moved mid-view
        Assert.Equal(1, rig2.Views.RevalidateActiveViews());
        Assert.False(rig2.Views.Sessions.Single().IsActive);
    }

    // F3 — no view outlives the maximum duration.
    [Fact]
    public void F3_ViewPastMaxDuration_TerminatedBySweep()
    {
        var rig = new Rig();
        rig.ViewableView();
        rig.Now += CameraViewService.MaxViewDuration + TimeSpan.FromMinutes(1);
        Assert.Equal(1, rig.Views.RevalidateActiveViews());
    }

    // F4 — group assignment and URI registration refuse actors
    // without an admin right, and every outcome is audited.
    [Fact]
    public void F4_GateInputs_ActorGatedAndAudited()
    {
        var rig = new Rig();
        rig.AddCamera();
        // A plain viewer (and a stranger) cannot file the camera
        // into a group or register its URI.
        Assert.False(rig.Views.AssignToDeviceGroup(CamId, "dg-cams", "viewer"));
        Assert.False(rig.Views.AssignToDeviceGroup(CamId, "dg-cams", "outsider"));
        Assert.False(rig.Views.RegisterStreamUri(CamId, $"rtsp://{CamIp}:554/stream1", "viewer").Ok);
        // The company admin can, and both acts are on the chain.
        Assert.True(rig.Views.AssignToDeviceGroup(CamId, "dg-cams", "admin"));
        Assert.True(rig.Views.RegisterStreamUri(CamId, $"rtsp://{CamIp}:554/stream1", "admin").Ok);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "camera_group_assignment_refused" && e.Actor == "viewer");
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "camera_group_assigned" && e.Actor == "admin");
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "camera_stream_uri_registered" && e.Actor == "admin");
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "camera_stream_uri_refused");
        Assert.True(rig.Audit.Verify().Ok);
        // Reassignment records the previous group (no silent overwrite).
        Assert.True(rig.Views.AssignToDeviceGroup(CamId, "dg-other", "admin"));
        Assert.Contains(rig.Audit.Entries, e =>
            e.Kind == "camera_group_assigned" && e.Detail.Contains("previousGroup=dg-cams"));
    }

    // F5 — snapshots are rate-limited per view, and tracked files
    // are pruned past the retention window.
    [Fact]
    public void F5_SnapshotRateLimit_AndRetentionPruning()
    {
        var sink = new ThrowingSink { WriteFileOnCapture = true };
        var rig = new Rig(sink);
        Directory.CreateDirectory(rig.SnapshotDir);
        var session = rig.ViewableView();
        var first = rig.Views.TakeSnapshot(session.SessionId, "viewer");
        Assert.True(first.Ok, first.Reason);
        Assert.True(File.Exists(first.Path));
        // Immediate second snapshot: refused — no time-lapse.
        var second = rig.Views.TakeSnapshot(session.SessionId, "viewer");
        Assert.False(second.Ok);
        Assert.Contains("rate limit", second.Reason);
        // After the interval it is allowed again.
        rig.Now += CameraViewService.MinSnapshotInterval + TimeSpan.FromSeconds(1);
        var third = rig.Views.TakeSnapshot(session.SessionId, "viewer");
        Assert.True(third.Ok, third.Reason);
        // Past retention, a snapshot from a NEW view (the old one
        // is past MaxViewDuration by then) prunes the old files.
        Assert.True(rig.Views.StopView(session.SessionId, "viewer"));
        rig.Now += CameraViewService.SnapshotRetention + TimeSpan.FromHours(1);
        var session2 = rig.Views.StartView(Scope, "viewer", CamId);
        Assert.True(session2.Ok, session2.Reason);
        var fourth = rig.Views.TakeSnapshot(session2.Session!.SessionId, "viewer");
        Assert.True(fourth.Ok, fourth.Reason);
        Assert.False(File.Exists(first.Path));
        Assert.False(File.Exists(third.Path));
        Assert.True(File.Exists(fourth.Path));
    }

    // F6 — brand matching is word-boundary: substrings inside
    // other words never label a camera cloud-locked, multi-word
    // brands win over their suffix, real brands still match.
    [Fact]
    public void F6_BrandMatchIsWordBoundary_GoogleNestReachable()
    {
        Assert.False(CloudCameraClassifier.Classify("Axis", "P3245", "Network Monitoring Camera", false, false).CloudLocked);
        Assert.False(CloudCameraClassifier.Classify("Axis", "P3245", "honest engineering string", false, false).CloudLocked);
        Assert.False(CloudCameraClassifier.Classify("Carlo", "X1", null, false, false).CloudLocked);
        var googleNest = CloudCameraClassifier.Classify("Google Nest", "Cam", null, false, false);
        Assert.True(googleNest.CloudLocked);
        Assert.Contains("(google nest)", googleNest.Reason);
        Assert.True(CloudCameraClassifier.Classify("Ring", "Doorbell", null, false, false).CloudLocked);
        Assert.True(CloudCameraClassifier.Classify("Nest", "Cam", null, false, false).CloudLocked);
    }

    // F7 — the unknown-capability reason distinguishes probed
    // from never-probed; the record never states an unmade
    // observation.
    [Fact]
    public void F7_UnknownReason_DistinguishesProbedFromNeverProbed()
    {
        var probed = CloudCameraClassifier.CapabilityFor(false, false, "Generic", "IP", null, capabilityProbed: true);
        Assert.Contains("was probed during discovery and did not advertise", probed.Reason);
        var unprobed = CloudCameraClassifier.CapabilityFor(false, false, "Generic", "IP", null, capabilityProbed: false);
        Assert.Contains("has not yet been probed", unprobed.Reason);
        Assert.DoesNotContain("did not advertise", unprobed.Reason);
    }

    // F8 — audit details cannot be forged through caller strings:
    // a session id carrying " camera=other reason=ok" enters the
    // chain flattened, and repeated made-up-session snapshot
    // refusals aggregate instead of growing the chain per call.
    [Fact]
    public void F8_AuditDetailForgeryFlattened_AndSnapshotRefusalFloodAggregates()
    {
        var rig = new Rig();
        var evilSession = "x camera=cam-other reason=ok";
        Assert.False(rig.Views.TakeSnapshot(evilSession, "mallory").Ok);
        var entry = rig.Audit.Entries.Single(e => e.Kind == "camera_snapshot_refused");
        Assert.DoesNotContain("camera=cam-other", entry.Detail);
        Assert.DoesNotContain(" reason=ok", entry.Detail);
        // Flood: 20 more refusals with the same made-up id add NO
        // further individual entries, but the total still counts all.
        var before = rig.Audit.Entries.Count;
        for (var i = 0; i < 20; i++)
            Assert.False(rig.Views.TakeSnapshot(evilSession, "mallory").Ok);
        Assert.Equal(before, rig.Audit.Entries.Count);
        Assert.Equal(21, rig.Views.TotalRefusedSnapshots);
        Assert.True(rig.Audit.Verify().Ok);
    }

    // F9 — retired / disposed / maintenance / discovered cameras
    // refuse views even with capability, group, URI, policy, grant.
    [Fact]
    public void F9_NonActiveLifecycle_Refused()
    {
        foreach (var state in new[]
        {
            UnmanagedLifecycleStates.Retired, UnmanagedLifecycleStates.Disposed,
            UnmanagedLifecycleStates.Maintenance, UnmanagedLifecycleStates.Discovered,
        })
        {
            var rig = new Rig();
            // A camera cannot be BORN disposed (the register
            // refuses it) — states are reached by transition,
            // except Discovered, which is a legitimate birth state.
            if (state == UnmanagedLifecycleStates.Discovered)
                rig.AddCamera(lifecycle: state);
            else
            {
                rig.AddCamera();
                Assert.True(rig.Register.Transition(CamId, state), state);
            }
            Assert.True(rig.Views.AssignToDeviceGroup(CamId, "dg-cams", "admin"));
            Assert.True(rig.Views.RegisterStreamUri(CamId, $"rtsp://{CamIp}:554/stream1", "admin").Ok);
            rig.EnableViewing();
            var start = rig.Views.StartView(Scope, "viewer", CamId);
            Assert.False(start.Ok, state);
            Assert.Contains("lifecycle", start.Reason);
        }
    }

    // F10(a) — an IPv6 camera's normalized URI is bracketed.
    [Fact]
    public void F10_Ipv6NormalizedUriIsBracketed()
    {
        var rig = new Rig();
        var cam = rig.AddCamera(ip: "2001:db8::50");
        var (ok, _, normalized) = RtspUriGuard.Validate(cam, "rtsp://[2001:db8::50]:554/stream1");
        Assert.True(ok);
        Assert.Equal("rtsp://[2001:db8::50]:554/stream1", normalized);
    }

    // F10(b) — the register/guard line the packet could not see:
    // 0.0.0.0 and broadcast are not probeable hosts, so a URI
    // naming them refuses even if a record somehow carried them.
    [Fact]
    public void F10_UnspecifiedAndBroadcastHostsRefused()
    {
        Assert.False(NetworkAddressing.IsProbeableHost(System.Net.IPAddress.Any));
        Assert.False(NetworkAddressing.IsProbeableHost(System.Net.IPAddress.Broadcast));
        Assert.False(NetworkAddressing.IsProbeableHost(System.Net.IPAddress.IPv6Any));
        var rig = new Rig();
        var cam = new UnmanagedAsset("cam-zero", Scope, "Zero", UnmanagedAssetKinds.Camera,
            "Generic", "IP", null, "0.0.0.0", null, null, null,
            UnmanagedLifecycleStates.Active, Array.Empty<string>(), new HashSet<string>(),
            new Dictionary<string, string>(), null, "manual", T0, T0,
            null, CameraViewCapabilities.Onvif, null);
        Assert.False(RtspUriGuard.Validate(cam, "rtsp://0.0.0.0:554/stream1").Ok);
    }

    // F12(a) — ended sessions are pruned after the retention
    // window instead of accumulating forever.
    [Fact]
    public void F12_EndedSessionsPrunedAfterRetention()
    {
        var rig = new Rig();
        var session = rig.ViewableView();
        Assert.True(rig.Views.StopView(session.SessionId, "viewer"));
        Assert.Single(rig.Views.Sessions); // still readable inside the window
        rig.Now += CameraViewService.EndedSessionRetention + TimeSpan.FromMinutes(1);
        Assert.Empty(rig.Views.Sessions); // pruned
    }

    // F12(b) — snapshot filenames are culture-invariant and unique
    // within the same second (sequence suffix): under th-TH the
    // year is the Gregorian year, and two resolves never collide.
    [Fact]
    public void F12_SnapshotFilename_InvariantCulture_UniquePerSecond()
    {
        var prev = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = new CultureInfo("th-TH");
            var a = SnapshotPathGuard.Resolve("/tmp/snaps", "cam-1", T0, 1);
            var b = SnapshotPathGuard.Resolve("/tmp/snaps", "cam-1", T0, 2);
            Assert.NotNull(a);
            Assert.Contains("20261121", a);
            Assert.NotEqual(a, b);
        }
        finally { CultureInfo.CurrentCulture = prev; }
    }
}
