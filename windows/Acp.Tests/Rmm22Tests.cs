using System.Text.Json;
using Acp.Shared.CameraShare;
using Acp.Shared.Enterprise;
using Acp.Shared.Enrollment;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Roster;
using Acp.Shared.Security;
using Acp.Shared.Sessions;
using Acp.Shared.Streaming;

namespace Acp.Tests;

// RMM-22 — Camera-share sessions: "see the rack." The phone owner
// initiates, naming one watcher; frames flow phone → watcher only
// as Block D ACPF envelopes; voice is a separate default-OFF
// toggle; every end is audited with its cause; an AI watcher needs
// an explicit owner-minted grant. All identities/devices are fake
// test fixtures.
public class Rmm22Tests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 14, 0, 0, TimeSpan.Zero);
    private const string Scope = "co-1";
    private const string Scope2 = "co-2";
    private const string Owner = "owner-1";
    private const string Tech = "tech-1";
    private const string Peer = "peer-1";
    private const string Admin = "admin-1";
    private const string Ai = "ai-1";
    private const string Ai2 = "ai-2";

    internal sealed class Rig
    {
        public DateTimeOffset Now = T0;
        public ChainedAuditLog Audit = new();
        public EnrollmentService Enrollments = new();
        public RosterService Roster;
        public ManagementPolicyEngine Policy = new();
        public RecordingCameraShareSink Sink = new();
        public CameraShareService Shares;
        public string PhoneId;
        public string Phone2Id;

        public Rig()
        {
            Roster = new RosterService(Enrollments);
            Assert.NotNull(Roster.CreateScope(Scope, "company", "Company A"));
            Assert.NotNull(Roster.CreateScope(Scope2, "company", "Other"));
            Assert.NotNull(Roster.CreateUser(Owner, Scope, "Olivia Owner", "human"));
            Assert.NotNull(Roster.CreateUser(Tech, Scope, "Tom Tech", "human"));
            Assert.NotNull(Roster.CreateUser(Peer, Scope, "Pat Peer", "human"));
            Assert.NotNull(Roster.CreateUser(Admin, Scope, "Ada Admin", "human"));
            Assert.True(Roster.AddCompanyAdmin(Scope, Admin));
            Assert.NotNull(Roster.CreateUser(Ai, Scope, "Agent One", "ai", pairedByUserId: Admin));
            Assert.NotNull(Roster.CreateUser(Ai2, Scope, "Agent Two", "ai", pairedByUserId: Admin));
            Assert.NotNull(Roster.CreateUser("outsider-2", Scope2, "Otto Outsider", "human"));
            Assert.NotNull(Roster.CreateDeviceGroup("dg-1", Scope, "Phones"));
            Shares = new CameraShareService(Roster, Enrollments, Policy, Audit, Sink, () => Now);
            PhoneId = EnrollPhone("Olivia's phone");
            Phone2Id = EnrollPhone("Spare phone");
        }

        private string EnrollPhone(string name)
        {
            var identity = new DeviceIdentity(new DevOnlyPassThroughProtector());
            var code = Enrollments.CreateEnrollmentCode("company", "dg-1", "Phones");
            var device = Enrollments.Redeem(code, new EnrollingDevice(identity.DeviceId, identity.PublicKeyBase64, name));
            Assert.NotNull(device);
            // D38 F1: a phone must be BOUND to its owner before it
            // can share — the rig's phones are Olivia's, bound by
            // Olivia herself.
            Assert.True(Shares.BindPhoneOwner(Scope, Owner, device!.DeviceId, Owner));
            return device.DeviceId;
        }

        public CameraShareSession Start(string watcher = Tech)
        {
            var (ok, share, reason) = Shares.InitiateShare(Scope, Owner, PhoneId, watcher);
            Assert.True(ok, reason);
            return share!;
        }

        public CameraShareSession Sharing(string watcher = Tech)
        {
            var share = Start(watcher);
            Assert.True(Shares.WatcherJoin(share.Id, watcher));
            return Shares.GetShare(share.Id)!;
        }

        public void SetPolicy(string key, string value, string id = "doc-1", long revision = 1)
        {
            var verdict = Policy.AddDocument(new ManagementPolicyDocument(id, PolicyLevels.Org, Scope,
                new Dictionary<string, string> { [key] = value }, revision));
            Assert.True(verdict.Allowed, verdict.Reason);
        }
    }

    // ---- frame fixtures (Block D ACPF envelopes) --------------------------------

    private static byte[] Nal(int type, params byte[] payload)
    {
        var bytes = new byte[5 + payload.Length];
        bytes[3] = 1;
        bytes[4] = (byte)type;
        payload.CopyTo(bytes, 5);
        return bytes;
    }

    private static byte[] KeyAu() => Nal(7, 0x64, 0x00).Concat(Nal(8, 0xEE)).Concat(Nal(5, 0x88)).ToArray();

    internal static byte[] KeyFrame(long seq = 1) => StreamProtocol.Pack(
        new StreamProtocol.FrameHeader(seq, 100, 1_700_000_000_000, true, 1280, 720, 0,
            "h264", "CameraX-test", true, "camera", null), KeyAu());

    // ---- (a) initiation + presence -------------------------------------------------

    [Fact]
    public void Initiate_OwnerNamesWatcher_StartsWaiting_PresenceNamesWatcherWithStop()
    {
        var rig = new Rig();
        var share = rig.Start();
        Assert.Equal("camera_share", share.Kind);
        Assert.Equal(CameraShareStates.Waiting, share.State);
        Assert.Equal(Owner, share.OwnerUserId);
        Assert.Equal(Tech, share.WatcherUserId);
        Assert.Equal("human", share.WatcherKind);
        Assert.False(share.VoiceEnabled);
        Assert.False(share.IsRecording);
        Assert.Equal("none", share.Recording);

        var presence = rig.Shares.GetPresence(share.Id);
        Assert.NotNull(presence);
        Assert.Equal("Tom Tech", presence!.WatcherDisplayName);
        Assert.Contains("Tom Tech", presence.BannerText);
        Assert.True(presence.StopAvailable);          // STOP is in the contract, live states only
        Assert.False(presence.IsBeingWatched);        // not joined yet — presence does not overclaim
        Assert.False(presence.IsRecording);
        Assert.Single(rig.Sink.Opened);
        Assert.True(rig.Audit.Verify().Ok);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "camera_share_started" && e.Actor == Owner);
    }

    [Fact]
    public void Initiate_Refusals_UnknownWatcher_SelfWatch_SuspendedWatcher_UnknownPhone_CrossScope()
    {
        var rig = new Rig();
        Assert.False(rig.Shares.InitiateShare(Scope, Owner, rig.PhoneId, "ghost").Ok);
        Assert.False(rig.Shares.InitiateShare(Scope, Owner, rig.PhoneId, Owner).Ok);       // self-watch
        Assert.False(rig.Shares.InitiateShare(Scope, Owner, "no-such-phone", Tech).Ok);
        Assert.False(rig.Shares.InitiateShare(Scope, Owner, rig.PhoneId, "outsider-2").Ok); // other scope's user
        Assert.False(rig.Shares.InitiateShare("no-scope", Owner, rig.PhoneId, Tech).Ok);
        Assert.True(rig.Roster.SetUserSuspended(Scope, Tech, true));
        Assert.False(rig.Shares.InitiateShare(Scope, Owner, rig.PhoneId, Tech).Ok);
        Assert.Empty(rig.Shares.ListShares());
        Assert.Empty(rig.Sink.Opened);
    }

    [Fact]
    public void Initiate_OneLiveSharePerPhone_SecondRefused_UntilFirstEnds()
    {
        var rig = new Rig();
        var first = rig.Start();
        Assert.False(rig.Shares.InitiateShare(Scope, Owner, rig.PhoneId, Peer).Ok);
        Assert.True(rig.Shares.StopShare(first.Id, Owner));
        var second = rig.Shares.InitiateShare(Scope, Owner, rig.PhoneId, Peer);
        Assert.True(second.Ok, second.Reason);
        Assert.Equal(Peer, second.Share!.WatcherUserId);
    }

    [Fact]
    public void Policy_ToggleSeededOn_DisabledRefuses()
    {
        var rig = new Rig();
        // Seeded ON in the RMM-07 registry: no policy document needed.
        Assert.True(rig.Shares.InitiateShare(Scope, Owner, rig.PhoneId, Tech).Ok);
        var rig2 = new Rig();
        rig2.SetPolicy(CameraSharePolicyKeys.Enabled, "false");
        var (ok, _, reason) = rig2.Shares.InitiateShare(Scope, Owner, rig2.PhoneId, Tech);
        Assert.False(ok);
        Assert.Contains("disabled by policy", reason);
        Assert.Empty(rig2.Sink.Opened);
    }

    [Fact]
    public void GenericSessionService_CannotMintOrStartCameraShare()
    {
        var rig = new Rig();
        Assert.Contains("camera_share", SessionService.ValidKinds); // a session KIND in the shared model
        var sessions = new SessionService(rig.Roster, rig.Enrollments);
        Assert.Null(sessions.CreateSession(Scope, rig.PhoneId, Owner, "camera_share", "lan"));
    }

    // ---- (b) join + one-way stream -----------------------------------------------------

    [Fact]
    public void WatcherJoin_OnlyTheNamedWatcher_ThenPresenceShowsWatching()
    {
        var rig = new Rig();
        var share = rig.Start();
        Assert.False(rig.Shares.WatcherJoin(share.Id, Peer));
        Assert.False(rig.Shares.WatcherJoin(share.Id, Owner));
        Assert.False(rig.Shares.WatcherJoin(share.Id, Admin));
        Assert.Equal(CameraShareStates.Waiting, rig.Shares.GetShare(share.Id)!.State);
        Assert.True(rig.Shares.WatcherJoin(share.Id, Tech));
        var joined = rig.Shares.GetShare(share.Id)!;
        Assert.Equal(CameraShareStates.Sharing, joined.State);
        Assert.NotNull(joined.WatcherJoinedUtc);
        Assert.True(rig.Shares.GetPresence(share.Id)!.IsBeingWatched);
        Assert.False(rig.Shares.WatcherJoin(share.Id, Tech)); // no double join
    }

    [Fact]
    public void Frames_FlowPhoneToWatcher_OnlyAfterJoin_OnlyValidEnvelopes()
    {
        var rig = new Rig();
        var share = rig.Start();
        Assert.False(rig.Shares.SubmitFrame(share.Id, Owner, KeyFrame())); // watcher not joined: dropped, never buffered
        Assert.True(rig.Shares.WatcherJoin(share.Id, Tech));
        Assert.False(rig.Shares.SubmitFrame(share.Id, Tech, KeyFrame()));   // reverse flow refuses
        Assert.False(rig.Shares.SubmitFrame(share.Id, Owner, new byte[] { 1, 2, 3 })); // not an ACPF envelope
        Assert.False(rig.Shares.SubmitFrame(share.Id, Owner, null));
        Assert.True(rig.Shares.SubmitFrame(share.Id, Owner, KeyFrame(1)));
        Assert.True(rig.Shares.SubmitFrame(share.Id, Owner, KeyFrame(2)));
        var after = rig.Shares.GetShare(share.Id)!;
        Assert.Equal(2, after.FramesForwarded);
        Assert.Equal(2, rig.Sink.Frames.Count);
        Assert.All(rig.Sink.Frames, f => Assert.Equal(share.Id, f.ShareId));
    }

    [Fact]
    public void Annotation_NamedWatcherOnly_BoundedCoordinates()
    {
        var rig = new Rig();
        var share = rig.Sharing();
        Assert.False(rig.Shares.SendAnnotation(share.Id, Peer, 10, 10));
        Assert.False(rig.Shares.SendAnnotation(share.Id, Owner, 10, 10));
        Assert.False(rig.Shares.SendAnnotation(share.Id, Tech, -1, 10));
        Assert.False(rig.Shares.SendAnnotation(share.Id, Tech, 10, 1001));
        Assert.True(rig.Shares.SendAnnotation(share.Id, Tech, 500, 250));
        Assert.Equal(1, rig.Shares.GetShare(share.Id)!.AnnotationsForwarded);
        Assert.Single(rig.Sink.Annotations);
    }

    // ---- voice + torch ---------------------------------------------------------------------

    [Fact]
    public void Voice_DefaultOff_WatcherCannotEnable_OwnerNeedsPolicy_ThenOwnerEnables()
    {
        var rig = new Rig();
        var share = rig.Sharing();
        Assert.False(rig.Shares.GetShare(share.Id)!.VoiceEnabled);
        Assert.False(rig.Shares.SetVoice(share.Id, Tech, true));   // watcher cannot open their own mic
        Assert.False(rig.Shares.SetVoice(share.Id, Owner, true));  // policy key unset: default OFF (REC-06)
        rig.SetPolicy(CameraSharePolicyKeys.VoiceEnabled, "true");
        Assert.True(rig.Shares.SetVoice(share.Id, Owner, true));
        Assert.True(rig.Shares.GetShare(share.Id)!.VoiceEnabled);
        Assert.True(rig.Shares.GetPresence(share.Id)!.VoiceEnabled);
        Assert.True(rig.Shares.SetVoice(share.Id, Tech, false));   // watcher may silence themselves
        Assert.False(rig.Shares.GetShare(share.Id)!.VoiceEnabled);
    }

    [Fact]
    public void Torch_OwnerControls_WatcherRequestsOnly()
    {
        var rig = new Rig();
        var share = rig.Sharing();
        Assert.False(rig.Shares.SetTorch(share.Id, Tech, true));
        Assert.False(rig.Shares.GetShare(share.Id)!.TorchEnabled);
        Assert.True(rig.Shares.RequestTorch(share.Id, Tech));
        Assert.False(rig.Shares.GetShare(share.Id)!.TorchEnabled); // a request changes nothing
        Assert.True(rig.Shares.SetTorch(share.Id, Owner, true));
        Assert.True(rig.Shares.GetShare(share.Id)!.TorchEnabled);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "camera_share_torch_requested");
    }

    // ---- (c) lifecycle ends -------------------------------------------------------------------

    [Fact]
    public void StopShare_OwnerOnly_EndsInstantly_AuditedWithCauseAndDuration()
    {
        var rig = new Rig();
        var share = rig.Sharing();
        Assert.True(rig.Shares.SubmitFrame(share.Id, Owner, KeyFrame()));
        Assert.False(rig.Shares.StopShare(share.Id, Tech));   // watcher cannot STOP (their act is disconnect)
        Assert.False(rig.Shares.StopShare(share.Id, Admin));  // no admin off-switch for someone's camera
        rig.Now = T0.AddMinutes(3);
        Assert.True(rig.Shares.StopShare(share.Id, Owner));
        var ended = rig.Shares.GetShare(share.Id)!;
        Assert.Equal(CameraShareStates.Ended, ended.State);
        Assert.Equal(CameraShareEndReasons.OwnerStop, ended.EndReason);
        Assert.Equal(TimeSpan.FromMinutes(3), ended.Duration);
        Assert.False(ended.VoiceEnabled);
        Assert.Contains(rig.Sink.Closed, c => c.ShareId == share.Id && c.Reason == CameraShareEndReasons.OwnerStop);
        var endEntry = rig.Audit.Entries.Single(e => e.Kind == "camera_share_ended");
        Assert.Contains("cause=owner_stop", endEntry.Detail);
        Assert.Contains("durationSeconds=180", endEntry.Detail);
        Assert.Contains("frames=1", endEntry.Detail);
        Assert.True(rig.Audit.Verify().Ok);
    }

    [Fact]
    public void WatcherDisconnect_AndOwnerNavigation_EndWithTheirCauses()
    {
        var rig = new Rig();
        var a = rig.Sharing();
        Assert.False(rig.Shares.WatcherDisconnect(a.Id, Peer));
        Assert.True(rig.Shares.WatcherDisconnect(a.Id, Tech));
        Assert.Equal(CameraShareEndReasons.WatcherDisconnect, rig.Shares.GetShare(a.Id)!.EndReason);

        var b = rig.Start();
        Assert.True(rig.Shares.OwnerNavigatedAway(b.Id, Owner));
        Assert.Equal(CameraShareEndReasons.OwnerNavigatedAway, rig.Shares.GetShare(b.Id)!.EndReason);
        Assert.Equal(2, rig.Audit.Entries.Count(e => e.Kind == "camera_share_ended"));
    }

    [Fact]
    public void Timeout_TickEndsShareAtMaxDuration_NotBefore()
    {
        var rig = new Rig();
        var share = rig.Sharing();
        rig.Now = T0.AddMinutes(59);
        Assert.Equal(0, rig.Shares.Tick());
        Assert.True(rig.Shares.GetShare(share.Id)!.IsLive);
        rig.Now = T0.AddMinutes(60);
        Assert.Equal(1, rig.Shares.Tick());
        Assert.Equal(CameraShareEndReasons.Timeout, rig.Shares.GetShare(share.Id)!.EndReason);
    }

    // ---- (e) AI watcher grants -----------------------------------------------------------------

    [Fact]
    public void AiWatcher_DeniedByDefault_GrantMakesItPossible_GrantIsScoped()
    {
        var rig = new Rig();
        var denied = rig.Shares.InitiateShare(Scope, Owner, rig.PhoneId, Ai);
        Assert.False(denied.Ok);
        Assert.Contains("no live explicit camera-share grant", denied.Reason);

        var grant = rig.Shares.GrantAiWatcher(Scope, Owner, Ai, rig.PhoneId, TimeSpan.FromHours(1));
        Assert.NotNull(grant);
        var ok = rig.Shares.InitiateShare(Scope, Owner, rig.PhoneId, Ai);
        Assert.True(ok.Ok, ok.Reason);
        Assert.Equal("ai", ok.Share!.WatcherKind);
        Assert.True(rig.Shares.WatcherJoin(ok.Share.Id, Ai));

        // The same grant does not cover the spare phone, nor the other AI.
        var rig2 = new Rig();
        Assert.NotNull(rig2.Shares.GrantAiWatcher(Scope, Owner, Ai, rig2.PhoneId, TimeSpan.FromHours(1)));
        Assert.False(rig2.Shares.InitiateShare(Scope, Owner, rig2.Phone2Id, Ai).Ok);
        Assert.False(rig2.Shares.InitiateShare(Scope, Owner, rig2.PhoneId, Ai2).Ok);
    }

    [Fact]
    public void AiGrant_ExpiryAndRevocation_RefuseAndEndLiveShares()
    {
        var rig = new Rig();
        var grant = rig.Shares.GrantAiWatcher(Scope, Owner, Ai, rig.PhoneId, TimeSpan.FromMinutes(30));
        Assert.NotNull(grant);
        var share = rig.Sharing(Ai);
        rig.Now = T0.AddMinutes(31); // grant expired under a live share
        Assert.Equal(1, rig.Shares.Tick());
        Assert.Equal(CameraShareEndReasons.ParticipantRemoved, rig.Shares.GetShare(share.Id)!.EndReason);
        Assert.False(rig.Shares.InitiateShare(Scope, Owner, rig.PhoneId, Ai).Ok); // expired grant mints nothing new

        var rig2 = new Rig();
        var grant2 = rig2.Shares.GrantAiWatcher(Scope, Owner, Ai, rig2.PhoneId, TimeSpan.FromHours(1));
        var share2 = rig2.Sharing(Ai);
        Assert.False(rig2.Shares.RevokeAiGrant(grant2!.Id, Peer)); // neither grantor nor admin
        Assert.True(rig2.Shares.RevokeAiGrant(grant2.Id, Owner));
        Assert.Equal(CameraShareStates.Ended, rig2.Shares.GetShare(share2.Id)!.State);
    }

    [Fact]
    public void AiGrant_Refusals_AiGrantor_HumanGrantee_ZeroTtl()
    {
        var rig = new Rig();
        Assert.Null(rig.Shares.GrantAiWatcher(Scope, Ai, Ai2, rig.PhoneId, TimeSpan.FromHours(1)));   // AI cannot grant
        Assert.Null(rig.Shares.GrantAiWatcher(Scope, Owner, Tech, rig.PhoneId, TimeSpan.FromHours(1))); // grantee not an AI
        Assert.Null(rig.Shares.GrantAiWatcher(Scope, Owner, Ai, rig.PhoneId, TimeSpan.Zero));
        Assert.Null(rig.Shares.GrantAiWatcher(Scope, Owner, Ai, "no-phone", TimeSpan.FromHours(1)));
        Assert.Empty(rig.Shares.ListAiGrants());
    }

    // ---- persistence ------------------------------------------------------------------------------

    [Fact]
    public void ExportImport_GrantsSurvive_LiveShareImportsEnded_NeverResumes()
    {
        var rig = new Rig();
        Assert.NotNull(rig.Shares.GrantAiWatcher(Scope, Owner, Ai, rig.PhoneId, TimeSpan.FromHours(1)));
        var share = rig.Sharing();
        Assert.True(rig.Shares.SubmitFrame(share.Id, Owner, KeyFrame()));
        var json = rig.Shares.ExportJson();

        var rig2 = new Rig();
        var restored = rig2.Shares.ImportJson(json);
        Assert.Equal(4, restored); // 2 phone-owner bindings + 1 grant + 1 share (D38 F1: bindings persist with the store)
        var imported = rig2.Shares.GetShare(share.Id)!;
        Assert.Equal(CameraShareStates.Ended, imported.State);
        Assert.Equal(CameraShareEndReasons.ImportRepair, imported.EndReason);
        Assert.Equal(1, imported.FramesForwarded); // the count survives; the frames never existed here
        Assert.Single(rig2.Shares.ListAiGrants());
        Assert.False(rig2.Shares.SubmitFrame(share.Id, Owner, KeyFrame())); // a restored share takes no frames
        Assert.Equal(0, rig2.Shares.ImportJson("not json"));
    }
}
