using System.Threading.Tasks;
using DeskGuest.Shared.CameraShare;
using DeskGuest.Shared.Enrollment;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.Sessions;

namespace DeskGuest.Tests;

// RMM-22 D38 FIX lane (packet a3e4fd9f) — permanent regression
// tests for the 12 cross-review findings against CameraShare.
// Each test names its finding. Fixtures reuse Rmm22Tests.Rig (real
// roster / enrollment / policy / chained audit; only the sink is
// doubled where the sink itself is the boundary under attack).
public class Rmm22D38FixTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 14, 0, 0, TimeSpan.Zero);
    private const string Scope = "co-1";
    private const string Owner = "owner-1";
    private const string Tech = "tech-1";
    private const string Peer = "peer-1";
    private const string Admin = "admin-1";
    private const string Ai = "ai-1";

    private sealed class ThrowingSink : ICameraShareSink
    {
        public bool ThrowOpen { get; set; }
        public bool ThrowClose { get; set; }
        public int CloseCalls { get; private set; }
        public (bool Ok, string Detail) OpenShare(string shareId, string watcherUserId)
        {
            if (ThrowOpen) throw new InvalidOperationException("open boom");
            return (true, "ok");
        }
        public void DeliverFrame(string shareId, byte[] envelope) { }
        public void DeliverAnnotation(string shareId, int x, int y) { }
        public void CloseShare(string shareId, string reason)
        {
            CloseCalls++;
            if (ThrowClose) throw new InvalidOperationException("close boom");
        }
    }

    private sealed class BlockingSink : ICameraShareSink
    {
        public readonly ManualResetEventSlim Entered = new(false);
        public readonly ManualResetEventSlim Release = new(false);
        public (bool Ok, string Detail) OpenShare(string shareId, string watcherUserId) => (true, "ok");
        public void DeliverFrame(string shareId, byte[] envelope)
        {
            Entered.Set();
            Release.Wait(TimeSpan.FromSeconds(60));
        }
        public void DeliverAnnotation(string shareId, int x, int y) { }
        public void CloseShare(string shareId, string reason) { }
    }

    private static CameraShareService ServiceWith(Rmm22Tests.Rig rig, ICameraShareSink sink)
    {
        var svc = new CameraShareService(rig.Roster, rig.Enrollments, rig.Policy, rig.Audit, sink, () => rig.Now);
        Assert.True(svc.BindPhoneOwner(Scope, Owner, rig.PhoneId, Owner));
        Assert.True(svc.BindPhoneOwner(Scope, Owner, rig.Phone2Id, Owner));
        return svc;
    }

    private static string EnrollUnboundPhone(Rmm22Tests.Rig rig)
    {
        var identity = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var code = rig.Enrollments.CreateEnrollmentCode("company", "dg-1", "Phones");
        var device = rig.Enrollments.Redeem(code, new EnrollingDevice(identity.DeviceId, identity.PublicKeyBase64, "Unbound phone"));
        Assert.NotNull(device);
        return device!.DeviceId;
    }

    // ---- F1: the owner must be tied to the phone -------------------------------

    [Fact]
    public void F1_NonOwnerHuman_CannotInitiateOrGrant_OnAnotherUsersPhone()
    {
        var rig = new Rmm22Tests.Rig();
        // Tech is a live human of the scope — and still cannot start
        // a share on Olivia's phone, nor mint an AI grant for it.
        var start = rig.Shares.InitiateShare(Scope, Tech, rig.PhoneId, Peer);
        Assert.False(start.Ok);
        Assert.Contains("bound owner", start.Reason);
        Assert.Null(rig.Shares.GrantAiWatcher(Scope, Tech, Ai, rig.PhoneId, TimeSpan.FromHours(1)));
        Assert.Empty(rig.Shares.ListShares());
        Assert.Empty(rig.Sink.Opened);
        // The real owner is not locked out by the attempt: she can
        // start and STOP her own share.
        var share = rig.Start();
        Assert.True(rig.Shares.StopShare(share.Id, Owner));
    }

    [Fact]
    public void F1_UnboundPhone_FailsClosed_UntilBoundByOwnerOrAdmin()
    {
        var rig = new Rmm22Tests.Rig();
        var phone3 = EnrollUnboundPhone(rig);
        var refused = rig.Shares.InitiateShare(Scope, Owner, phone3, Tech);
        Assert.False(refused.Ok);
        Assert.Contains("not bound", refused.Reason);
        Assert.Null(rig.Shares.GrantAiWatcher(Scope, Owner, Ai, phone3, TimeSpan.FromHours(1)));
        // A peer cannot bind someone else's phone to them.
        Assert.False(rig.Shares.BindPhoneOwner(Scope, Peer, phone3, Owner));
        Assert.Null(rig.Shares.BoundOwnerOf(Scope, phone3));
        // A company admin provisioning the phone can.
        Assert.True(rig.Shares.BindPhoneOwner(Scope, Admin, phone3, Owner));
        Assert.Equal(Owner, rig.Shares.BoundOwnerOf(Scope, phone3));
        Assert.True(rig.Shares.InitiateShare(Scope, Owner, phone3, Tech).Ok);
    }

    // ---- F2: one-live-share check must be atomic --------------------------------

    [Fact]
    public void F2_ConcurrentInitiation_ExactlyOneLiveSharePerPhone()
    {
        var rig = new Rmm22Tests.Rig();
        var results = new CameraShareStartResult[16];
        Parallel.For(0, results.Length, i =>
            results[i] = rig.Shares.InitiateShare(Scope, Owner, rig.PhoneId, i % 2 == 0 ? Tech : Peer));
        Assert.Single(results, r => r.Ok);
        Assert.Single(rig.Shares.ListShares().Where(s => s.IsLive));
        Assert.Single(rig.Sink.Opened);
        Assert.True(rig.Audit.Verify().Ok);
    }

    // ---- F3: duration ceiling applied before TimeSpan construction -------------

    [Fact]
    public void F3_OverflowingMaxDurationPolicy_ClampsToCeiling_TickNeverThrows()
    {
        var rig = new Rmm22Tests.Rig();
        rig.SetPolicy(CameraSharePolicyKeys.MaxDurationMinutes, "99999999999"); // > ~1.54e10 minutes
        var share = rig.Sharing();
        rig.Now = T0.AddHours(7).AddMinutes(59);
        Assert.Equal(0, rig.Shares.Tick());
        rig.Now = T0.AddHours(8).AddMinutes(1);
        Assert.Equal(1, rig.Shares.Tick());
        Assert.Equal(CameraShareEndReasons.Timeout, rig.Shares.GetShare(share.Id)!.EndReason);
    }

    // ---- F4: sink delivery + Changed must not run under the gate -----------------

    [Fact]
    public void F4_BlockingSink_DoesNotStallOwnerStop()
    {
        var rig = new Rmm22Tests.Rig();
        var sink = new BlockingSink();
        var svc = ServiceWith(rig, sink);
        var started = svc.InitiateShare(Scope, Owner, rig.PhoneId, Tech);
        Assert.True(started.Ok, started.Reason);
        Assert.True(svc.WatcherJoin(started.Share!.Id, Tech));

        var frameTask = Task.Run(() => svc.SubmitFrame(started.Share.Id, Owner, Rmm22Tests.KeyFrame()));
        Assert.True(sink.Entered.Wait(TimeSpan.FromSeconds(10)), "sink delivery never started");
        var stopTask = Task.Run(() => svc.StopShare(started.Share.Id, Owner));
        var finished = Task.WhenAny(stopTask, Task.Delay(TimeSpan.FromSeconds(10))).GetAwaiter().GetResult();
        sink.Release.Set();
        Assert.Same(stopTask, finished); // STOP completed while a frame delivery was blocked
        Assert.True(stopTask.GetAwaiter().GetResult());
        Assert.Equal(CameraShareStates.Ended, svc.GetShare(started.Share.Id)!.State);
        frameTask.GetAwaiter().GetResult();
    }

    [Fact]
    public void F4_Changed_DoesNotFirePerFrameOrAnnotation()
    {
        var rig = new Rmm22Tests.Rig();
        var share = rig.Sharing();
        var changed = 0;
        rig.Shares.Changed += () => Interlocked.Increment(ref changed);
        Assert.True(rig.Shares.SubmitFrame(share.Id, Owner, Rmm22Tests.KeyFrame(1)));
        Assert.True(rig.Shares.SubmitFrame(share.Id, Owner, Rmm22Tests.KeyFrame(2)));
        Assert.True(rig.Shares.SendAnnotation(share.Id, Tech, 10, 10));
        Assert.Equal(0, changed); // counts persist with the next durable mutation, not at frame rate
        Assert.Equal(2, rig.Shares.GetShare(share.Id)!.FramesForwarded);
    }

    // ---- F5: StartSession refusal for the camera_share kind -----------------------

    [Fact]
    public void F5_StartSession_RefusesImportedCameraShareRecord()
    {
        var rig = new Rmm22Tests.Rig();
        var sessions = new SessionService(rig.Roster, rig.Enrollments);
        const string json = """
            {"Sessions":[
              {"Id":"cs-1","ScopeId":"co-1","HostDeviceId":"x","InitiatorUserId":"owner-1",
               "Kind":"camera_share","State":"requested","StartedUtc":null,"EndedUtc":null,
               "TransportRung":"lan","Recording":"none","RecordingRef":null,
               "AcceptedByUserId":null,"EndReason":null,"AcceptOrigin":null,
               "Blanked":false,"InputBlocked":false,"Watermarked":false}],
             "Participants":[],"Events":[],"Chat":[],"FileJobs":[],"Calls":[]}
            """;
        Assert.True(sessions.ImportJson(json) > 0);
        Assert.NotNull(sessions.GetSession("cs-1")); // the record exists…
        Assert.False(sessions.StartSession("cs-1")); // …and still can never be started generically
        Assert.Null(sessions.CreateSession(Scope, rig.PhoneId, Owner, "camera_share", "lan"));
    }

    // ---- F6: ImportJson must not trust grants or overwrite live shares ------------

    [Fact]
    public void F6_Import_CannotUnrevokeAGrant()
    {
        var rig = new Rmm22Tests.Rig();
        var grant = rig.Shares.GrantAiWatcher(Scope, Owner, Ai, rig.PhoneId, TimeSpan.FromHours(1));
        Assert.NotNull(grant);
        var liveExport = rig.Shares.ExportJson(); // grant live in this snapshot
        Assert.True(rig.Shares.RevokeAiGrant(grant!.Id, Owner));
        rig.Shares.ImportJson(liveExport);        // stale store replayed
        Assert.True(rig.Shares.ListAiGrants().Single(g => g.Id == grant.Id).Revoked);
        Assert.False(rig.Shares.InitiateShare(Scope, Owner, rig.PhoneId, Ai).Ok);
    }

    [Fact]
    public void F6_Import_ClampsGrantExpiryToCeiling_AndAuditsRestore()
    {
        var rig = new Rmm22Tests.Rig();
        var json = $$"""
            {"Shares":[],"Bindings":[],
             "Grants":[{"Id":"g-far","ScopeId":"co-1","OwnerUserId":"owner-1","AiUserId":"ai-1",
               "PhoneDeviceId":"{{rig.PhoneId}}","GrantedUtc":"2026-11-21T14:00:00+00:00",
               "ExpiresUtc":"9999-01-01T00:00:00+00:00","Revoked":false}]}
            """;
        Assert.Equal(1, rig.Shares.ImportJson(json));
        var grant = rig.Shares.ListAiGrants().Single();
        Assert.Equal(grant.GrantedUtc + CameraShareService.AbsoluteMaxDuration, grant.ExpiresUtc);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "camera_share_ai_grant_restored" && e.Detail.Contains("g-far"));
    }

    [Fact]
    public void F6_ImportOverLiveShare_EndsItProperly_SinkClosedAndChained()
    {
        var rig = new Rmm22Tests.Rig();
        var share = rig.Sharing();
        var export = rig.Shares.ExportJson();
        var ended = export.Replace("\"State\":\"sharing\"", "\"State\":\"ended\"");
        Assert.NotEqual(export, ended);
        rig.Shares.ImportJson(ended);
        Assert.Equal(CameraShareStates.Ended, rig.Shares.GetShare(share.Id)!.State);
        Assert.Contains(rig.Sink.Closed, c => c.ShareId == share.Id && c.Reason == CameraShareEndReasons.ImportRepair);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "camera_share_ended" && e.Detail.Contains(share.Id));
    }

    // ---- F7: a throwing sink cannot leave unaudited / half-finished transitions ---

    [Fact]
    public void F7_OpenShareThrows_StartedAndFailedChained_NoShare()
    {
        var rig = new Rmm22Tests.Rig();
        var sink = new ThrowingSink { ThrowOpen = true };
        var svc = ServiceWith(rig, sink);
        var result = svc.InitiateShare(Scope, Owner, rig.PhoneId, Tech);
        Assert.False(result.Ok);
        Assert.Empty(svc.ListShares());
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "camera_share_started");
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "camera_share_failed");
        Assert.True(rig.Audit.Verify().Ok);
    }

    [Fact]
    public void F7_CloseShareThrows_SharesStillEnd_AuditComplete_TickContinues()
    {
        var rig = new Rmm22Tests.Rig();
        var sink = new ThrowingSink { ThrowClose = true };
        var svc = ServiceWith(rig, sink);
        var a = svc.InitiateShare(Scope, Owner, rig.PhoneId, Tech).Share!;
        var b = svc.InitiateShare(Scope, Owner, rig.Phone2Id, Tech).Share!;
        rig.Now = T0.AddMinutes(61);
        Assert.Equal(2, svc.Tick()); // the throwing close aborts neither end nor the loop
        Assert.Equal(CameraShareStates.Ended, svc.GetShare(a.Id)!.State);
        Assert.Equal(CameraShareStates.Ended, svc.GetShare(b.Id)!.State);
        Assert.Equal(2, rig.Audit.Entries.Count(e => e.Kind == "camera_share_ended"));
        Assert.Equal(2, rig.Audit.Entries.Count(e => e.Kind == "camera_share_sink_close_failed"));
        Assert.Equal(2, sink.CloseCalls);
        Assert.True(rig.Audit.Verify().Ok);
    }

    // ---- F8: act-time revalidation + voice policy in Tick ---------------------------

    [Fact]
    public void F8_WatcherSuspendedMidShare_NextFrameEndsShare_NothingDelivered()
    {
        var rig = new Rmm22Tests.Rig();
        var share = rig.Sharing();
        Assert.True(rig.Roster.SetUserSuspended(Scope, Tech, true));
        Assert.False(rig.Shares.SubmitFrame(share.Id, Owner, Rmm22Tests.KeyFrame()));
        var after = rig.Shares.GetShare(share.Id)!;
        Assert.Equal(CameraShareStates.Ended, after.State);
        Assert.Equal(CameraShareEndReasons.ParticipantRemoved, after.EndReason);
        Assert.Empty(rig.Sink.Frames);
    }

    [Fact]
    public void F8_OwnerSuspendedMidShare_TickEndsShare()
    {
        var rig = new Rmm22Tests.Rig();
        var share = rig.Sharing();
        Assert.True(rig.Roster.SetUserSuspended(Scope, Owner, true));
        Assert.Equal(1, rig.Shares.Tick());
        Assert.Equal(CameraShareEndReasons.ParticipantRemoved, rig.Shares.GetShare(share.Id)!.EndReason);
    }

    [Fact]
    public void F8_VoicePolicyFlippedOffMidShare_TickTurnsVoiceOff_ShareContinues()
    {
        var rig = new Rmm22Tests.Rig();
        rig.SetPolicy(CameraSharePolicyKeys.VoiceEnabled, "true");
        var share = rig.Sharing();
        Assert.True(rig.Shares.SetVoice(share.Id, Owner, true));
        rig.SetPolicy(CameraSharePolicyKeys.VoiceEnabled, "false", id: "doc-voice-off", revision: 2);
        Assert.Equal(0, rig.Shares.Tick()); // the share itself is not ended
        var after = rig.Shares.GetShare(share.Id)!;
        Assert.True(after.IsLive);
        Assert.False(after.VoiceEnabled);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "camera_share_voice_disabled");
    }

    // ---- F9: bounded growth ----------------------------------------------------------

    [Fact]
    public void F9_RefusedFrameFlood_AuditAggregatedNotPerFrame()
    {
        var rig = new Rmm22Tests.Rig();
        var share = rig.Start(); // waiting: the normal pre-join stream race
        for (var i = 0; i < 50; i++)
            Assert.False(rig.Shares.SubmitFrame(share.Id, Owner, Rmm22Tests.KeyFrame(i + 1)));
        Assert.Equal(1, rig.Audit.Entries.Count(e => e.Kind == "camera_share_frame_refused"));
        Assert.True(rig.Audit.Verify().Ok);
    }

    [Fact]
    public void F9_EndedShares_PrunedAfterRetention_RecentOnesKept()
    {
        var rig = new Rmm22Tests.Rig();
        var old = rig.Sharing();
        Assert.True(rig.Shares.StopShare(old.Id, Owner));
        rig.Now = T0.AddHours(25);
        var recent = rig.Sharing();
        Assert.True(rig.Shares.StopShare(recent.Id, Owner));
        rig.Shares.Tick();
        Assert.Null(rig.Shares.GetShare(old.Id));       // past 24 h retention: pruned
        Assert.NotNull(rig.Shares.GetShare(recent.Id)); // freshly ended: kept
    }

    // ---- F10: revoke refusals audited; sweep ends only the grant's own shares ---------

    [Fact]
    public void F10_RevokeUnknownOrAlreadyRevoked_AuditedRefusal()
    {
        var rig = new Rmm22Tests.Rig();
        var before = rig.Audit.Entries.Count;
        Assert.False(rig.Shares.RevokeAiGrant("no-such-grant", Owner));
        Assert.True(rig.Audit.Entries.Count > before);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "camera_share_ai_grant_refused" && e.Detail.Contains("no-such-grant"));

        var grant = rig.Shares.GrantAiWatcher(Scope, Owner, Ai, rig.PhoneId, TimeSpan.FromHours(1));
        Assert.True(rig.Shares.RevokeAiGrant(grant!.Id, Owner));
        var before2 = rig.Audit.Entries.Count;
        Assert.False(rig.Shares.RevokeAiGrant(grant.Id, Owner)); // already revoked
        Assert.True(rig.Audit.Entries.Count > before2);
    }

    [Fact]
    public void F10_Revoke_EndsOnlySharesThatGrantCarries()
    {
        var rig = new Rmm22Tests.Rig();
        var grant1 = rig.Shares.GrantAiWatcher(Scope, Owner, Ai, rig.PhoneId, TimeSpan.FromHours(1))!;
        var grant2 = rig.Shares.GrantAiWatcher(Scope, Owner, Ai, rig.PhoneId, TimeSpan.FromHours(1))!;
        var share = rig.Sharing(Ai);
        Assert.NotNull(share.AiGrantId);
        var other = share.AiGrantId == grant1.Id ? grant2 : grant1;
        var carrying = share.AiGrantId == grant1.Id ? grant1 : grant2;
        Assert.True(rig.Shares.RevokeAiGrant(other.Id, Owner));
        Assert.True(rig.Shares.GetShare(share.Id)!.IsLive); // a different grant carries this share
        Assert.True(rig.Shares.RevokeAiGrant(carrying.Id, Owner));
        Assert.Equal(CameraShareStates.Ended, rig.Shares.GetShare(share.Id)!.State);
        Assert.Single(rig.Sink.Closed, c => c.ShareId == share.Id);
    }

    // ---- F11: AuthorizeUse must not call a Waiting share "camera viewing" ----------------

    [Fact]
    public void F11_AuthorizeUse_RefusesWhileWaiting_GrantsAfterJoin()
    {
        var rig = new Rmm22Tests.Rig();
        var share = rig.Start(); // Waiting: the watcher has not joined
        Assert.False(rig.Shares.AuthorizeUse(share.Id, Tech, "camera_view"));
        Assert.True(rig.Shares.WatcherJoin(share.Id, Tech));
        Assert.True(rig.Shares.AuthorizeUse(share.Id, Tech, "camera_view"));
    }

    // ---- F12: sink closed exactly once --------------------------------------------------

    [Fact]
    public void F12_SinkClosedExactlyOnce_AcrossTickStopAndReTick()
    {
        var rig = new Rmm22Tests.Rig();
        var share = rig.Sharing();
        rig.Now = T0.AddMinutes(61);
        Assert.Equal(1, rig.Shares.Tick());
        Assert.False(rig.Shares.StopShare(share.Id, Owner)); // already ended: nothing to stop
        Assert.Equal(0, rig.Shares.Tick());
        Assert.Single(rig.Sink.Closed, c => c.ShareId == share.Id);
        Assert.Single(rig.Audit.Entries, e => e.Kind == "camera_share_ended");
    }
}
