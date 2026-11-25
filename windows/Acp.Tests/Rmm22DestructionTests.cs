using System.Reflection;
using System.Text.Json;
using Acp.Shared.CameraShare;
using Acp.Shared.Enterprise;
using Acp.Shared.ManagementPolicy;

namespace Acp.Tests;

// RMM-22 DESTRUCTION PASS — hostile attempts against the
// camera-share model, each converted to a permanent regression
// test. Attacker classes: a compromised/malicious watcher client,
// a compromised hub trying to start or redirect shares, a second
// user reaching for someone else's share, and the product's own
// future features reaching for silent recording / scope creep.
// Ledger: ~/workspace/builds/rmm-r-logs/ledger-rmm22.md (DG-R22-*).
public class Rmm22DestructionTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 14, 0, 0, TimeSpan.Zero);
    private const string Scope = "co-1";
    private const string Owner = "owner-1";
    private const string Tech = "tech-1";
    private const string Peer = "peer-1";
    private const string Admin = "admin-1";
    private const string Ai = "ai-1";

    // DG-R22-01 — REMOTE START: the watcher side (or a hub acting
    // for it) tries every creation-shaped path. None may create a
    // share; the named watcher-side request refuses AND audits.
    [Fact]
    public void DG_R22_01_RemoteStart_WatcherSideRequestRefusedAudited_NothingCreated()
    {
        var rig = new Rmm22Tests.Rig();
        var before = rig.Audit.Entries.Count;
        var result = rig.Shares.RequestShareFromWatcher(Scope, Tech, rig.PhoneId, Owner);
        Assert.False(result.Ok);
        Assert.Null(result.Share);
        Assert.Contains("only be started by the phone owner", result.Reason);
        Assert.Empty(rig.Shares.ListShares());
        Assert.Empty(rig.Sink.Opened);
        Assert.True(rig.Audit.Entries.Count > before);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "camera_share_remote_start_refused" && e.Actor == Tech);
        // An AI posing as the initiating owner is refused at the same door:
        // the camera side must be a human phone owner.
        Assert.False(rig.Shares.InitiateShare(Scope, Ai, rig.PhoneId, Tech).Ok);
        Assert.Empty(rig.Shares.ListShares());
    }

    // DG-R22-02 — WATCHER SUBSTITUTION MID-SHARE: join as someone
    // else, reassign as the owner, reassign as an admin. The named
    // watcher is a consent fact; it does not move.
    [Fact]
    public void DG_R22_02_WatcherSubstitution_JoinAndReassignRefused_NamedWatcherUnaffected()
    {
        var rig = new Rmm22Tests.Rig();
        var share = rig.Start();
        Assert.False(rig.Shares.WatcherJoin(share.Id, Peer));
        Assert.False(rig.Shares.ReassignWatcher(share.Id, Owner, Peer));
        Assert.False(rig.Shares.ReassignWatcher(share.Id, Admin, Peer));
        Assert.Equal(Tech, rig.Shares.GetShare(share.Id)!.WatcherUserId);
        Assert.True(rig.Shares.WatcherJoin(share.Id, Tech)); // the real watcher still joins cleanly
        // Even after joining, substitution stays refused.
        Assert.False(rig.Shares.ReassignWatcher(share.Id, Owner, Peer));
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "camera_share_reassign_refused");
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "camera_share_join_refused" && e.Actor == Peer);
    }

    // DG-R22-03 — STOP BYPASS / DELAY: after STOP, try to keep the
    // share alive or feed it — frames, annotations, voice, torch,
    // a Tick, a re-join. Every path refuses; the record stays ended
    // with its original cause.
    [Fact]
    public void DG_R22_03_StopBypass_NothingRevivesOrFeedsAStoppedShare()
    {
        var rig = new Rmm22Tests.Rig();
        var share = rig.Sharing();
        Assert.True(rig.Shares.StopShare(share.Id, Owner));
        Assert.False(rig.Shares.SubmitFrame(share.Id, Owner, Rmm22Tests.KeyFrame()));
        Assert.False(rig.Shares.SendAnnotation(share.Id, Tech, 1, 1));
        Assert.False(rig.Shares.SetVoice(share.Id, Owner, true));
        Assert.False(rig.Shares.SetTorch(share.Id, Owner, true));
        Assert.False(rig.Shares.WatcherJoin(share.Id, Tech));
        Assert.False(rig.Shares.StopShare(share.Id, Owner)); // double STOP: nothing to stop
        Assert.Equal(0, rig.Shares.Tick());
        var ended = rig.Shares.GetShare(share.Id)!;
        Assert.Equal(CameraShareStates.Ended, ended.State);
        Assert.Equal(CameraShareEndReasons.OwnerStop, ended.EndReason);
        Assert.Equal(0, ended.FramesForwarded);
        Assert.Empty(rig.Sink.Frames);
        Assert.Single(rig.Sink.Closed);
        Assert.Single(rig.Audit.Entries, e => e.Kind == "camera_share_ended");
    }

    // DG-R22-04 — SILENT RECORDING: reach for frame persistence
    // through every surface — the record's shape, the export, the
    // recording toggle. There is nothing to reach: no media member
    // exists, the export carries counts only, recording refuses.
    [Fact]
    public void DG_R22_04_SilentRecording_NoMediaSurfaceExists_RecordingRefuses()
    {
        // Structural: the share record carries no byte[] / stream /
        // media member of any kind — persistence is unrepresentable.
        var mediaMembers = typeof(CameraShareSession).GetMembers(BindingFlags.Public | BindingFlags.Instance)
            .Where(m => m.Name.Contains("Frame") || m.Name.Contains("Media") || m.Name.Contains("Stream"))
            .Where(m => m is PropertyInfo p && p.PropertyType != typeof(long))
            .ToList();
        Assert.Empty(mediaMembers);
        Assert.False(typeof(CameraShareSession).GetProperties().Any(p => p.PropertyType == typeof(byte[])));

        var rig = new Rmm22Tests.Rig();
        var share = rig.Sharing();
        var frame = Rmm22Tests.KeyFrame();
        Assert.True(rig.Shares.SubmitFrame(share.Id, Owner, frame));
        Assert.False(rig.Shares.GetShare(share.Id)!.IsRecording);
        Assert.False(rig.Shares.TryEnableRecording(share.Id, Owner));
        Assert.False(rig.Shares.TryEnableRecording(share.Id, Tech));
        var export = rig.Shares.ExportJson();
        Assert.DoesNotContain(Convert.ToBase64String(frame), export);
        Assert.DoesNotContain("AccessUnit", export);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "camera_share_recording_refused");
        // Presence never claims recording either, in any state.
        Assert.False(rig.Shares.GetPresence(share.Id)!.IsRecording);
    }

    // DG-R22-05 — WATCHER-SCOPE CREEP: spend a camera share (or an
    // AI grant) on something it is not — a full session purpose, a
    // file channel, a second device, a different AI.
    [Fact]
    public void DG_R22_05_ScopeCreep_ShareAndGrantSpendOnlyOnCameraView()
    {
        var rig = new Rmm22Tests.Rig();
        var share = rig.Sharing();
        Assert.True(rig.Shares.AuthorizeUse(share.Id, Tech, "camera_view"));
        Assert.False(rig.Shares.AuthorizeUse(share.Id, Tech, "full_session"));
        Assert.False(rig.Shares.AuthorizeUse(share.Id, Tech, "file_transfer"));
        Assert.False(rig.Shares.AuthorizeUse(share.Id, Tech, "second_device"));
        Assert.False(rig.Shares.AuthorizeUse(share.Id, Peer, "camera_view")); // not a party at all
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "camera_share_use_refused");

        // An AI grant minted for the spare phone does not spend on this one.
        Assert.NotNull(rig.Shares.GrantAiWatcher(Scope, Owner, Ai, rig.Phone2Id, TimeSpan.FromHours(1)));
        Assert.False(rig.Shares.InitiateShare(Scope, Owner, rig.PhoneId, Ai).Ok);
    }

    // DG-R22-06 — AUDIT GAPS: refusals and failures must be as
    // audited as successes. A stream layer that refuses to open
    // leaves no share — but leaves BOTH audit entries; every
    // refusal kind appends; the chain verifies at the end.
    [Fact]
    public void DG_R22_06_AuditGaps_RefusalsAndStreamFailureAreChained()
    {
        var rig = new Rmm22Tests.Rig();
        rig.Sink.FailOpen = true;
        var failed = rig.Shares.InitiateShare(Scope, Owner, rig.PhoneId, Tech);
        Assert.False(failed.Ok);
        Assert.Empty(rig.Shares.ListShares());
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "camera_share_started");
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "camera_share_failed");
        rig.Sink.FailOpen = false;

        var share = rig.Start();
        var kinds = new[]
        {
            (Action)(() => rig.Shares.WatcherJoin(share.Id, Peer)),
            () => rig.Shares.SubmitFrame(share.Id, Tech, Rmm22Tests.KeyFrame()),
            () => rig.Shares.StopShare(share.Id, Admin),
            () => rig.Shares.ReassignWatcher(share.Id, Owner, Peer),
            () => rig.Shares.TryEnableRecording(share.Id, Tech),
        };
        foreach (var act in kinds)
        {
            var before = rig.Audit.Entries.Count;
            act();
            Assert.True(rig.Audit.Entries.Count > before, "a refusal that appends no audit entry is a gap");
        }
        Assert.True(rig.Audit.Verify().Ok);
        var json = JsonSerializer.Serialize(rig.Audit.Entries);
        Assert.Contains(Tech, json); // watcher identity is in the chain
        Assert.Contains(share.Id, json);
    }

    // DG-R22-07 — VOICE-CHANNEL DEFAULT CREEP: the watcher tries to
    // open the mic; the owner tries without policy; a share that
    // ends with voice on must not carry voice into its ended
    // record or into the next share.
    [Fact]
    public void DG_R22_07_VoiceCreep_DefaultOffAndDiesWithTheShare()
    {
        var rig = new Rmm22Tests.Rig();
        var share = rig.Sharing();
        Assert.False(rig.Shares.SetVoice(share.Id, Tech, true));
        Assert.False(rig.Shares.SetVoice(share.Id, Owner, true)); // no policy: OFF stands
        rig.SetPolicy(CameraSharePolicyKeys.VoiceEnabled, "true");
        Assert.True(rig.Shares.SetVoice(share.Id, Owner, true));
        Assert.True(rig.Shares.StopShare(share.Id, Owner));
        Assert.False(rig.Shares.GetShare(share.Id)!.VoiceEnabled); // ended record carries no live mic
        var next = rig.Start();
        Assert.False(next.VoiceEnabled);                            // and the next share starts silent
    }

    // DG-R22-08 — MID-SHARE WORLD CHANGES: policy flips off, the
    // watcher is suspended, the phone is revoked. Tick must end
    // the share under each — a live camera never outlives the
    // facts that consented to it.
    [Fact]
    public void DG_R22_08_MidShareRevocations_PolicyFlip_Suspension_DeviceRevoke_EndTheShare()
    {
        var rigA = new Rmm22Tests.Rig();
        var a = rigA.Sharing();
        rigA.SetPolicy(CameraSharePolicyKeys.Enabled, "false", id: "doc-off", revision: 2);
        Assert.Equal(1, rigA.Shares.Tick());
        Assert.Equal(CameraShareEndReasons.PolicyDisabled, rigA.Shares.GetShare(a.Id)!.EndReason);

        var rigB = new Rmm22Tests.Rig();
        var b = rigB.Sharing();
        Assert.True(rigB.Roster.SetUserSuspended(Scope, Tech, true));
        Assert.Equal(1, rigB.Shares.Tick());
        Assert.Equal(CameraShareEndReasons.ParticipantRemoved, rigB.Shares.GetShare(b.Id)!.EndReason);

        var rigC = new Rmm22Tests.Rig();
        var c = rigC.Sharing();
        Assert.True(rigC.Enrollments.Revoke(rigC.PhoneId));
        Assert.Equal(1, rigC.Shares.Tick());
        Assert.Equal(CameraShareStates.Ended, rigC.Shares.GetShare(c.Id)!.State);
    }

    // DG-R22-09 — DURATION INFLATION: policy tries to make shares
    // effectively unbounded. The absolute ceiling clamps it: the
    // share still dies at 8 hours.
    [Fact]
    public void DG_R22_09_DurationInflation_PolicyCannotMakeSharesUnbounded()
    {
        var rig = new Rmm22Tests.Rig();
        rig.SetPolicy(CameraSharePolicyKeys.MaxDurationMinutes, "99999999");
        var share = rig.Sharing();
        rig.Now = T0.AddHours(7).AddMinutes(59);
        Assert.Equal(0, rig.Shares.Tick());
        rig.Now = T0.AddHours(8).AddMinutes(1);
        Assert.Equal(1, rig.Shares.Tick());
        Assert.Equal(CameraShareEndReasons.Timeout, rig.Shares.GetShare(share.Id)!.EndReason);
    }

    // DG-R22-10 — STORE TAMPERING: a hand-edited export that marks
    // an ended share live again, or invents a share, imports as
    // ended (import_repair) or is skipped — a restored record
    // never resumes a camera under stale consent.
    [Fact]
    public void DG_R22_10_StoreTamper_ResurrectedShareImportsEnded()
    {
        var rig = new Rmm22Tests.Rig();
        var share = rig.Sharing();
        Assert.True(rig.Shares.StopShare(share.Id, Owner));
        var json = rig.Shares.ExportJson();
        // D38 F12: the tamper targets the State field precisely —
        // the old fallback (replace every "ended" in the document)
        // could pass for the wrong reason by mangling unrelated
        // fields. If neither known serializer casing matches, the
        // Assert.NotEqual below fails loudly instead.
        var tampered = json.Replace("\"State\":\"ended\"", "\"State\":\"sharing\"");
        if (tampered == json)
            tampered = json.Replace("\"state\":\"ended\"", "\"state\":\"sharing\"");
        Assert.NotEqual(json, tampered);

        var rig2 = new Rmm22Tests.Rig();
        rig2.Shares.ImportJson(tampered);
        var imported = rig2.Shares.GetShare(share.Id);
        Assert.NotNull(imported);
        Assert.Equal(CameraShareStates.Ended, imported!.State);
        Assert.Equal(CameraShareEndReasons.ImportRepair, imported.EndReason);
        Assert.False(rig2.Shares.SubmitFrame(share.Id, Owner, Rmm22Tests.KeyFrame()));
    }
}
