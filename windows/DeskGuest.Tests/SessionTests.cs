using DeskGuest.Shared.Enrollment;
using DeskGuest.Shared.Roster;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.Sessions;

namespace DeskGuest.Tests;

/// <summary>Slice 3 — human session model, first-class. Every test
/// cites the decision or spec clause it enforces in its name
/// (BUILD-PROGRAMME Slice 3 spec; D9/D14/D32/D35/D36).</summary>
public class SessionTests
{
    private sealed class World
    {
        public required EnrollmentService Enrollments { get; init; }
        public required RosterService Roster { get; init; }
        public required SessionService Sessions { get; init; }
        public required string DeviceId { get; init; }
    }

    private static World Setup()
    {
        var enrollments = new EnrollmentService();
        var roster = new RosterService(enrollments);
        Assert.NotNull(roster.CreateScope("personal-1", "personal", "Personal"));
        Assert.NotNull(roster.CreateScope("company-1", "company", "Company A"));
        Assert.NotNull(roster.CreateUser("owner", "personal-1", "Owner One", "human"));
        Assert.NotNull(roster.CreateUser("admin", "company-1", "Admin", "human"));
        Assert.True(roster.AddCompanyAdmin("company-1", "admin"));
        Assert.NotNull(roster.CreateUser("host", "company-1", "Host User", "human"));
        Assert.NotNull(roster.CreateUser("ctrl", "company-1", "Controller", "human"));
        Assert.NotNull(roster.CreateUser("peer", "company-1", "Peer", "human"));
        Assert.NotNull(roster.CreateUser("outsider", "company-1", "Outsider", "human"));
        Assert.NotNull(roster.CreateUser("ai-1", "company-1", "Agent One", "ai", pairedByUserId: "admin"));
        // ug-1 members hold the "use" grant on dg-1; "outsider" is in
        // no group and holds nothing; "admin" acts via the admin seat.
        Assert.NotNull(roster.CreateUserGroup("ug-1", "company-1", "Techs",
            new[] { "ctrl", "host", "peer", "ai-1" }));
        Assert.NotNull(roster.CreateDeviceGroup("dg-1", "company-1", "Fleet", new[] { "lan", "hub" }));
        Assert.NotNull(roster.AddGrant("company-1", "ug-1", "dg-1", new[] { "use" }));

        var identity = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var code = enrollments.CreateEnrollmentCode("company", "dg-1", "Fleet");
        var device = enrollments.Redeem(code, new EnrollingDevice(identity.DeviceId, identity.PublicKeyBase64, "Site PC"));
        Assert.NotNull(device);
        return new World
        {
            Enrollments = enrollments,
            Roster = roster,
            Sessions = new SessionService(roster, enrollments),
            DeviceId = device!.DeviceId,
        };
    }

    private static Session CreateAttended(World w, string initiator = "ctrl", string rung = "lan",
        string recording = "none", string? recordingRef = null)
    {
        var s = w.Sessions.CreateSession("company-1", w.DeviceId, initiator, "attended", rung, recording, recordingRef);
        Assert.NotNull(s);
        return s!;
    }

    /// <summary>Drive a fresh attended session (accepted by "host")
    /// into the requested state. Returns the session id.</summary>
    private static string SessionInState(World w, string state)
    {
        var s = CreateAttended(w);
        Assert.True(w.Sessions.AcceptSession(s.Id, "host", SessionAcceptOrigin.EndpointLocal));
        switch (state)
        {
            case "requested":
                break;
            case "active":
                Assert.True(w.Sessions.StartSession(s.Id));
                break;
            case "paused":
                Assert.True(w.Sessions.StartSession(s.Id));
                Assert.True(w.Sessions.PauseSession(s.Id, "ctrl"));
                break;
            case "blocked":
                Assert.True(w.Sessions.StartSession(s.Id));
                Assert.True(w.Sessions.BlockSession(s.Id, "ctrl"));
                break;
            case "ended":
                Assert.True(w.Sessions.StartSession(s.Id));
                Assert.True(w.Sessions.EndSession(s.Id, "ctrl"));
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(state), state, null);
        }
        Assert.Equal(state, w.Sessions.GetSession(s.Id)!.State);
        return s.Id;
    }

    // ---- creation guards (Slice 3 spec / D8 / D14) ------------------------------

    [Fact]
    public void CreateSession_StartsRequested_WithInitiatorAsController_Slice3()
    {
        var w = Setup();
        var s = CreateAttended(w);
        Assert.Equal("requested", s.State);
        Assert.Null(s.StartedUtc);
        Assert.Null(s.EndedUtc);
        Assert.Equal("ctrl", s.InitiatorUserId);
        var participants = w.Sessions.ListParticipants(s.Id);
        var initiator = Assert.Single(participants);
        Assert.Equal("controller", initiator.Role);
        Assert.Equal("watching", initiator.Floor);
        Assert.Contains(w.Sessions.ListEvents(s.Id), e => e.Kind == "created");
    }

    [Fact]
    public void CreateSession_Refusals_AreFailClosed_Slice3_D8_D14()
    {
        var w = Setup();
        // Unknown scope / unknown device / unknown initiator.
        Assert.Null(w.Sessions.CreateSession("nope", w.DeviceId, "ctrl", "attended", "lan"));
        Assert.Null(w.Sessions.CreateSession("company-1", "deadbeef", "ctrl", "attended", "lan"));
        Assert.Null(w.Sessions.CreateSession("company-1", w.DeviceId, "ghost", "attended", "lan"));
        // The wall (D8): the device is filed in a company device
        // group; a personal-scope session over it is refused.
        Assert.Null(w.Sessions.CreateSession("personal-1", w.DeviceId, "owner", "attended", "lan"));
        // Unknown kind / non-rung transport.
        Assert.Null(w.Sessions.CreateSession("company-1", w.DeviceId, "ctrl", "drive-by", "lan"));
        Assert.Null(w.Sessions.CreateSession("company-1", w.DeviceId, "ctrl", "attended", "webrtc"));
        // A revoked device cannot host.
        Assert.True(w.Enrollments.Revoke(w.DeviceId));
        Assert.Null(w.Sessions.CreateSession("company-1", w.DeviceId, "ctrl", "attended", "lan"));
    }

    [Fact]
    public void CreateSession_SuspendedUser_CannotInitiate_D14()
    {
        var w = Setup();
        Assert.True(w.Roster.SetUserSuspended("company-1", "ctrl", true));
        Assert.Null(w.Sessions.CreateSession("company-1", w.DeviceId, "ctrl", "attended", "lan"));
        Assert.True(w.Roster.SetUserSuspended("company-1", "ai-1", true));
        Assert.Null(w.Sessions.CreateSession("company-1", w.DeviceId, "ai-1", "unattended", "lan"));
    }

    // ---- the closed transition set (Slice 3 spec) --------------------------------

    [Fact]
    public void TransitionMatrix_IsExactlyTheClosedSet_Slice3()
    {
        var legal = new HashSet<(string, string)>
        {
            ("requested", "active"), ("requested", "ended"),
            ("active", "paused"), ("active", "blocked"), ("active", "ended"),
            ("paused", "active"), ("paused", "blocked"), ("paused", "ended"),
            ("blocked", "ended"), // blocked → ended ONLY: no other way out, none needed
        };
        foreach (var from in SessionService.ValidStates)
        foreach (var to in SessionService.ValidStates)
            Assert.Equal(legal.Contains((from, to)), SessionService.IsLegalTransition(from, to));
    }

    [Fact]
    public void IllegalTransitions_RefuseAndChangeNothing_Slice3()
    {
        var w = Setup();
        // (state, illegal acts available in that state)
        var cases = new (string State, Func<World, string, bool>[] Acts)[]
        {
            ("requested", new Func<World, string, bool>[]
            {
                (ww, id) => ww.Sessions.PauseSession(id, "ctrl"),
                (ww, id) => ww.Sessions.ResumeSession(id, "ctrl"),
                (ww, id) => ww.Sessions.BlockSession(id, "ctrl"),
            }),
            ("active", new Func<World, string, bool>[]
            {
                (ww, id) => ww.Sessions.StartSession(id),
                (ww, id) => ww.Sessions.ResumeSession(id, "ctrl"),
            }),
            ("paused", new Func<World, string, bool>[]
            {
                (ww, id) => ww.Sessions.StartSession(id),
                (ww, id) => ww.Sessions.PauseSession(id, "ctrl"),
            }),
            ("blocked", new Func<World, string, bool>[]
            {
                // From blocked, EVERYTHING except ending is illegal —
                // the session can never be wedged alive (STOP trap).
                (ww, id) => ww.Sessions.StartSession(id),
                (ww, id) => ww.Sessions.PauseSession(id, "ctrl"),
                (ww, id) => ww.Sessions.ResumeSession(id, "ctrl"),
                (ww, id) => ww.Sessions.BlockSession(id, "ctrl"),
            }),
            ("ended", new Func<World, string, bool>[]
            {
                (ww, id) => ww.Sessions.StartSession(id),
                (ww, id) => ww.Sessions.PauseSession(id, "ctrl"),
                (ww, id) => ww.Sessions.ResumeSession(id, "ctrl"),
                (ww, id) => ww.Sessions.BlockSession(id, "ctrl"),
                (ww, id) => ww.Sessions.EndSession(id, "ctrl"),
            }),
        };
        foreach (var (state, acts) in cases)
        {
            var id = SessionInState(w, state);
            var before = w.Sessions.GetSession(id)!;
            var eventsBefore = w.Sessions.ListEvents(id).Count;
            foreach (var act in acts)
            {
                Assert.False(act(w, id));
                // NOTHING changed: same record, no new events.
                Assert.Equal(before, w.Sessions.GetSession(id));
                Assert.Equal(eventsBefore, w.Sessions.ListEvents(id).Count);
            }
        }
    }

    [Fact]
    public void BlockedSession_ClearsOnlyByEnding_Slice3_StopTrap()
    {
        var w = Setup();
        var id = SessionInState(w, "blocked");
        Assert.True(w.Sessions.EndSession(id, "host"));
        var s = w.Sessions.GetSession(id)!;
        Assert.Equal("ended", s.State);
        Assert.NotNull(s.EndedUtc);
        Assert.Equal("ended", s.EndReason);
    }

    // ---- STOP: terminates from every state (Slice 3 spec, exhaustive) -------------

    [Fact]
    public void StopSession_TerminatesFromEveryNonEndedState_Slice3_Exhaustive()
    {
        foreach (var state in new[] { "requested", "active", "paused", "blocked" })
        {
            var w = Setup();
            var id = SessionInState(w, state);
            Assert.True(w.Sessions.StopSession(id, "host"), $"STOP from {state}");
            var s = w.Sessions.GetSession(id)!;
            Assert.Equal("ended", s.State);
            Assert.Equal("host_stop", s.EndReason);
            Assert.NotNull(s.EndedUtc);
            // The replay shows the whole path: stopped, then
            // ended — in order. DS-P5-F20 (Wave 12): "blocked" is a
            // pass-through only from active/paused (and pre-existing
            // from blocked); from "requested" STOP ends directly —
            // the pre-fix assertion demanded the illegal
            // requested→blocked edge for every state.
            var kinds = w.Sessions.ListEvents(id).Select(e => e.Kind).ToList();
            var stoppedAt = kinds.IndexOf("stopped");
            var endedAt = kinds.IndexOf("ended");
            Assert.True(stoppedAt >= 0 && endedAt > stoppedAt, $"event order from {state}");
            if (state == "requested")
                Assert.DoesNotContain("blocked", kinds);
            else
                Assert.Contains("blocked", kinds.Take(stoppedAt + 1));
        }
    }

    [Fact]
    public void StopSession_FromEnded_Refuses_AndNonHostActor_Refuses_Slice3()
    {
        var w = Setup();
        var endedId = SessionInState(w, "ended");
        var before = w.Sessions.GetSession(endedId);
        Assert.False(w.Sessions.StopSession(endedId, "host"));
        Assert.Equal(before, w.Sessions.GetSession(endedId));

        // STOP is a host-side act: the initiator/controller and a
        // watching participant cannot stop the session.
        var activeId = SessionInState(w, "active");
        Assert.False(w.Sessions.StopSession(activeId, "ctrl"));
        Assert.False(w.Sessions.StopSession(activeId, "peer"));
        Assert.Equal("active", w.Sessions.GetSession(activeId)!.State);
        // The company admin is host-side authority too.
        Assert.True(w.Sessions.StopSession(activeId, "admin"));
        Assert.Equal("ended", w.Sessions.GetSession(activeId)!.State);
    }

    // ---- consent gates (Slice 3 spec / SPEC §7.10) ----------------------------------

    [Fact]
    public void AttendedSession_CannotStart_WithoutRecordedHostAccept_Slice3()
    {
        var w = Setup();
        var s = CreateAttended(w);
        Assert.False(w.Sessions.StartSession(s.Id));
        Assert.Equal("requested", w.Sessions.GetSession(s.Id)!.State);
        Assert.DoesNotContain(w.Sessions.ListEvents(s.Id), e => e.Kind == "started");
        // A ghost cannot accept; the real host can, exactly once.
        Assert.False(w.Sessions.AcceptSession(s.Id, "ghost", SessionAcceptOrigin.EndpointLocal));
        Assert.True(w.Sessions.AcceptSession(s.Id, "host", SessionAcceptOrigin.EndpointLocal));
        Assert.Equal("host", w.Sessions.GetSession(s.Id)!.AcceptedByUserId);
        Assert.False(w.Sessions.AcceptSession(s.Id, "host", SessionAcceptOrigin.EndpointLocal));
        // The acceptor is now the host participant.
        Assert.Contains(w.Sessions.ListParticipants(s.Id),
            p => p.UserId == "host" && p.Role == "host");
        Assert.True(w.Sessions.StartSession(s.Id));
        Assert.Equal("active", w.Sessions.GetSession(s.Id)!.State);
        Assert.NotNull(w.Sessions.GetSession(s.Id)!.StartedUtc);
    }

    [Fact]
    public void UnattendedSession_RequiresUseGrantOnHostDeviceGroup_Slice3_D12()
    {
        var w = Setup();
        // "outsider" holds no grant: start refused, nothing changes.
        var denied = w.Sessions.CreateSession("company-1", w.DeviceId, "outsider", "unattended", "lan");
        Assert.NotNull(denied);
        Assert.False(w.Sessions.StartSession(denied!.Id));
        Assert.Equal("requested", w.Sessions.GetSession(denied.Id)!.State);
        // "ctrl" holds `use` via ug-1's grant: starts with NO accept
        // (unattended has no accept gate — the grant IS the consent).
        var allowed = w.Sessions.CreateSession("company-1", w.DeviceId, "ctrl", "unattended", "lan");
        Assert.NotNull(allowed);
        Assert.False(w.Sessions.AcceptSession(allowed!.Id, "host", SessionAcceptOrigin.EndpointLocal)); // no accept gate exists here
        Assert.True(w.Sessions.StartSession(allowed.Id));
        Assert.Equal("active", w.Sessions.GetSession(allowed.Id)!.State);
    }

    [Fact]
    public void StartSession_RungOutsideEffectiveTransports_Refused_Slice3_D32()
    {
        var w = Setup();
        // dg-1's set is [lan, hub]; "tor" is a valid rung but not in
        // the host's resolved set — refused at start, stays requested.
        var s = CreateAttended(w, rung: "tor");
        Assert.True(w.Sessions.AcceptSession(s.Id, "host", SessionAcceptOrigin.EndpointLocal));
        Assert.False(w.Sessions.StartSession(s.Id));
        Assert.Equal("requested", w.Sessions.GetSession(s.Id)!.State);
        // A rung inside the set starts.
        var ok = CreateAttended(w, rung: "hub");
        Assert.True(w.Sessions.AcceptSession(ok.Id, "host", SessionAcceptOrigin.EndpointLocal));
        Assert.True(w.Sessions.StartSession(ok.Id));
    }

    // ---- participants & the floor (D35, exhaustive one-holder) ----------------------

    [Fact]
    public void OneFloorHolder_Exhaustive_EveryStateEveryGrant_D35()
    {
        foreach (var state in new[] { "requested", "active", "paused", "blocked" })
        {
            var w = Setup();
            var id = SessionInState(w, state);
            Assert.True(w.Sessions.AddParticipant(id, "peer", "controller", "ctrl"));
            Assert.True(w.Sessions.AddParticipant(id, "ai-1", "watcher", "ctrl"));
            // Nobody holds the floor yet — at most one, possibly zero.
            Assert.True(w.Sessions.ListParticipants(id).Count(p => p.Floor == "holds") <= 1);
            // Grant to EVERY participant in turn: after each grant,
            // exactly one holder exists and it is the target — the
            // previous holder was revoked in the same atomic act.
            foreach (var target in new[] { "ctrl", "host", "peer", "ai-1", "ctrl" })
            {
                Assert.True(w.Sessions.GrantFloor(id, target, "host"), $"{state} → {target}");
                var holders = w.Sessions.ListParticipants(id).Where(p => p.Floor == "holds").ToList();
                var holder = Assert.Single(holders);
                Assert.Equal(target, holder.UserId);
            }
            // Take-back lands the floor on the host participant, still
            // exactly one holder. Watch-only releases it to zero.
            Assert.True(w.Sessions.TakeFloorBack(id, "host"));
            Assert.Equal("host", Assert.Single(
                w.Sessions.ListParticipants(id).Where(p => p.Floor == "holds")).UserId);
            Assert.True(w.Sessions.SetWatchOnly(id, "host", "host"));
            Assert.Empty(w.Sessions.ListParticipants(id).Where(p => p.Floor == "holds"));
        }
    }

    [Fact]
    public void FloorActs_OnEndedSession_Refuse_D35()
    {
        var w = Setup();
        var id = SessionInState(w, "ended");
        Assert.False(w.Sessions.GrantFloor(id, "ctrl", "host"));
        Assert.False(w.Sessions.TakeFloorBack(id, "host"));
        Assert.False(w.Sessions.SetWatchOnly(id, "ctrl", "host"));
        Assert.False(w.Sessions.RemoveParticipant(id, "ctrl", "host"));
        Assert.False(w.Sessions.AddParticipant(id, "peer", "watcher", "host"));
    }

    [Fact]
    public void HostActs_RequireHostParticipantOrCompanyAdmin_D35()
    {
        var w = Setup();
        var id = SessionInState(w, "active");
        Assert.True(w.Sessions.AddParticipant(id, "peer", "controller", "ctrl"));
        // A plain controller participant is NOT host authority.
        Assert.False(w.Sessions.GrantFloor(id, "peer", "ctrl"));
        Assert.False(w.Sessions.RemoveParticipant(id, "peer", "ctrl"));
        Assert.False(w.Sessions.SetWatchOnly(id, "peer", "ctrl"));
        // Grant the floor to peer: holding the floor grants NO host
        // acts (D35) — peer still cannot grant or remove.
        Assert.True(w.Sessions.GrantFloor(id, "peer", "host"));
        Assert.False(w.Sessions.GrantFloor(id, "ctrl", "peer"));
        Assert.False(w.Sessions.RemoveParticipant(id, "ctrl", "peer"));
        Assert.False(w.Sessions.TakeFloorBack(id, "peer"));
        // The host participant and the company admin both can act.
        Assert.True(w.Sessions.SetWatchOnly(id, "peer", "admin"));
        Assert.True(w.Sessions.RemoveParticipant(id, "peer", "host"));
        Assert.DoesNotContain(w.Sessions.ListParticipants(id), p => p.UserId == "peer");
        Assert.Contains(w.Sessions.ListEvents(id),
            e => e.Kind == "participant_removed" && e.SubjectId == "peer");
    }

    [Fact]
    public void SuspendedAi_CanNeverHoldTheFloor_D9_D14()
    {
        var w = Setup();
        var id = SessionInState(w, "active");
        Assert.True(w.Sessions.AddParticipant(id, "ai-1", "controller", "ctrl"));
        Assert.True(w.Roster.SetUserSuspended("company-1", "ai-1", true));
        Assert.False(w.Sessions.GrantFloor(id, "ai-1", "host"));
        Assert.Empty(w.Sessions.ListParticipants(id).Where(p => p.Floor == "holds"));
        // And a suspended user cannot be added as a participant at all.
        Assert.False(w.Sessions.AddParticipant(id, "ai-1", "watcher", "host"));
    }

    // ---- offboarding hook (D14) -----------------------------------------------------

    [Fact]
    public void Offboarding_LiveSessionOfRemovedUser_EndsParticipantRemoved_D14()
    {
        var w = Setup();
        var id = SessionInState(w, "active");
        var job = w.Sessions.CreateFileJob(id, "to_host", "logs.zip", 10, "ctrl");
        Assert.NotNull(job);
        // Slice 2 offboarding fires: ctrl is removed from the scope.
        Assert.NotNull(w.Roster.RemoveUser("company-1", "ctrl", "admin"));
        // The hook ends the live session with the named reason, and
        // the end cascade cancels its file job.
        Assert.True(w.Sessions.EnforceOffboarding(id));
        var s = w.Sessions.GetSession(id)!;
        Assert.Equal("ended", s.State);
        Assert.Equal("participant_removed", s.EndReason);
        Assert.Equal("cancelled", w.Sessions.GetFileJob(job!.Id)!.State);
        // A removed user can never initiate again.
        Assert.Null(w.Sessions.CreateSession("company-1", w.DeviceId, "ctrl", "attended", "lan"));
    }

    [Fact]
    public void Offboarding_ReReadOnEveryTransition_D14()
    {
        var w = Setup();
        var id = SessionInState(w, "active");
        Assert.True(w.Sessions.AddParticipant(id, "peer", "watcher", "ctrl"));
        // A mere PARTICIPANT is offboarded (not the initiator): the
        // next transition attempt ends the session instead of moving.
        Assert.NotNull(w.Roster.RemoveUser("company-1", "peer", "admin"));
        Assert.False(w.Sessions.PauseSession(id, "ctrl"));
        var s = w.Sessions.GetSession(id)!;
        Assert.Equal("ended", s.State);
        Assert.Equal("participant_removed", s.EndReason);
    }

    [Fact]
    public void Offboarding_SuspendedParticipant_EndsSession_D14()
    {
        var w = Setup();
        var id = SessionInState(w, "active");
        Assert.True(w.Sessions.AddParticipant(id, "ai-1", "watcher", "ctrl"));
        // Offboarding suspends owned AIs (D14); suspension alone is
        // enough for the hook — the AI's session cannot continue.
        Assert.True(w.Roster.SetUserSuspended("company-1", "ai-1", true));
        Assert.True(w.Sessions.EnforceOffboarding(id));
        Assert.Equal("participant_removed", w.Sessions.GetSession(id)!.EndReason);
        // Intact sessions are untouched by the hook.
        var clean = SessionInState(w, "active");
        Assert.False(w.Sessions.EnforceOffboarding(clean));
        Assert.Equal("active", w.Sessions.GetSession(clean)!.State);
    }

    [Fact]
    public void Offboarding_BlocksStart_WhenInitiatorRemovedAfterCreate_D14()
    {
        var w = Setup();
        var s = w.Sessions.CreateSession("company-1", w.DeviceId, "ctrl", "unattended", "lan");
        Assert.NotNull(s);
        Assert.NotNull(w.Roster.RemoveUser("company-1", "ctrl", "admin"));
        Assert.False(w.Sessions.StartSession(s!.Id));
        // Refused to start BY ending: participant_removed, not stuck.
        Assert.Equal("ended", w.Sessions.GetSession(s.Id)!.State);
        Assert.Equal("participant_removed", w.Sessions.GetSession(s.Id)!.EndReason);
    }

    // ---- recording (D36) --------------------------------------------------------------

    [Fact]
    public void RecordingRef_RemoteUrlsRefused_LocalPathsAccepted_D36()
    {
        var w = Setup();
        foreach (var remote in new[]
                 {
                     "https://cloud.example.com/rec/s1.mp4",
                     "http://storage.example.com/s1.mp4",
                     "ftp://files.example.com/s1.mp4",
                     "s3://bucket/s1.mp4",
                     "//server/share/s1.mp4",
                     "\\\\server\\share\\s1.mp4",
                 })
        {
            Assert.True(SessionService.IsRemoteRecordingRef(remote), remote);
            Assert.Null(w.Sessions.CreateSession("company-1", w.DeviceId, "ctrl",
                "attended", "lan", "video", remote));
        }
        foreach (var local in new[]
                 {
                     "C:\\Recordings\\s1.mp4",
                     "recordings/s1.mp4",
                     "/var/deskguest/recordings/s1.mp4",
                     "file:///var/deskguest/recordings/s1.mp4",
                 })
        {
            Assert.False(SessionService.IsRemoteRecordingRef(local), local);
            Assert.NotNull(w.Sessions.CreateSession("company-1", w.DeviceId, "ctrl",
                "attended", "lan", "video", local));
        }
        // SetRecording enforces the same rule on a live session.
        var id = SessionInState(w, "active");
        Assert.False(w.Sessions.SetRecording(id, "video", "https://cloud.example.com/x.mp4", "host"));
        Assert.Equal("none", w.Sessions.GetSession(id)!.Recording);
    }

    [Fact]
    public void IsRecording_AlwaysDerivableWhileActive_CovertUnrepresentable_D36()
    {
        var w = Setup();
        var s = CreateAttended(w, recording: "video", recordingRef: "recordings/s1.mp4");
        Assert.False(s.IsRecording); // requested: not capturing yet
        Assert.True(w.Sessions.AcceptSession(s.Id, "host", SessionAcceptOrigin.EndpointLocal));
        Assert.True(w.Sessions.StartSession(s.Id));
        // Active + Recording != none ⇒ IsRecording, from the record
        // alone — the presence layer can never be told "not
        // recording" about a capturing session.
        Assert.True(w.Sessions.GetSession(s.Id)!.IsRecording);
        Assert.True(w.Sessions.PauseSession(s.Id, "ctrl"));
        Assert.True(w.Sessions.GetSession(s.Id)!.IsRecording); // paused still exposes it
        Assert.True(w.Sessions.SetRecording(s.Id, "none", null, "host"));
        Assert.False(w.Sessions.GetSession(s.Id)!.IsRecording);
        Assert.Null(w.Sessions.GetSession(s.Id)!.RecordingRef); // none clears the ref
        Assert.True(w.Sessions.SetRecording(s.Id, "replay", null, "host"));
        Assert.True(w.Sessions.ResumeSession(s.Id, "ctrl"));
        Assert.True(w.Sessions.GetSession(s.Id)!.IsRecording); // replay form counts too
        Assert.True(w.Sessions.EndSession(s.Id, "host"));
        Assert.False(w.Sessions.GetSession(s.Id)!.IsRecording);
        Assert.False(w.Sessions.SetRecording(s.Id, "video", "recordings/x.mp4", "host")); // ended refuses
    }

    // ---- chat (Slice 3, model half) ------------------------------------------------------

    [Fact]
    public void Chat_ParticipantsOnly_EndedSessionRefuses_Slice3()
    {
        var w = Setup();
        var id = SessionInState(w, "active");
        Assert.NotNull(w.Sessions.SendChatMessage(id, "ctrl", "starting the update"));
        Assert.NotNull(w.Sessions.SendChatMessage(id, "host", "watching, go ahead"));
        // Non-participants and empty text refuse.
        Assert.Null(w.Sessions.SendChatMessage(id, "outsider", "let me in"));
        Assert.Null(w.Sessions.SendChatMessage(id, "ctrl", "  "));
        Assert.Equal(2, w.Sessions.ListChat(id).Count);
        Assert.Contains(w.Sessions.ListEvents(id), e => e.Kind == "chat_message");
        Assert.True(w.Sessions.EndSession(id, "host"));
        Assert.Null(w.Sessions.SendChatMessage(id, "ctrl", "still there?"));
        Assert.Equal(2, w.Sessions.ListChat(id).Count);
    }

    // ---- file jobs (Slice 3, model half) ---------------------------------------------------

    [Fact]
    public void FileJob_ProgressIsMonotonic_DoneRequiresFullBytes_Slice3()
    {
        var w = Setup();
        var id = SessionInState(w, "active");
        var job = w.Sessions.CreateFileJob(id, "to_host", "patch.msi", 100, "ctrl");
        Assert.NotNull(job);
        Assert.Equal("queued", job!.State);
        Assert.True(w.Sessions.SetFileJobState(job.Id, "active"));
        Assert.True(w.Sessions.UpdateFileProgress(job.Id, 40));
        // Backwards progress refuses and changes nothing.
        Assert.False(w.Sessions.UpdateFileProgress(job.Id, 30));
        Assert.Equal(40, w.Sessions.GetFileJob(job.Id)!.TransferredBytes);
        // Progress past the size refuses too.
        Assert.False(w.Sessions.UpdateFileProgress(job.Id, 101));
        Assert.Equal(40, w.Sessions.GetFileJob(job.Id)!.TransferredBytes);
        // Done at partial bytes refuses — state and bytes unchanged.
        Assert.False(w.Sessions.SetFileJobState(job.Id, "done"));
        Assert.Equal("active", w.Sessions.GetFileJob(job.Id)!.State);
        Assert.True(w.Sessions.UpdateFileProgress(job.Id, 100));
        Assert.True(w.Sessions.SetFileJobState(job.Id, "done"));
        // Terminal: no way back out, no more progress.
        Assert.False(w.Sessions.SetFileJobState(job.Id, "active"));
        Assert.False(w.Sessions.UpdateFileProgress(job.Id, 100));
    }

    [Fact]
    public void FileJob_SessionEndCascadeCancelsLiveJobs_Slice3()
    {
        var w = Setup();
        var id = SessionInState(w, "active");
        var queued = w.Sessions.CreateFileJob(id, "to_host", "a.bin", 10, "ctrl")!;
        var active = w.Sessions.CreateFileJob(id, "from_host", "b.bin", 10, "ctrl")!;
        Assert.True(w.Sessions.SetFileJobState(active.Id, "active"));
        var paused = w.Sessions.CreateFileJob(id, "to_host", "c.bin", 10, "ctrl")!;
        Assert.True(w.Sessions.SetFileJobState(paused.Id, "active"));
        Assert.True(w.Sessions.SetFileJobState(paused.Id, "paused"));
        var done = w.Sessions.CreateFileJob(id, "to_host", "d.bin", 4, "ctrl")!;
        Assert.True(w.Sessions.SetFileJobState(done.Id, "active"));
        Assert.True(w.Sessions.UpdateFileProgress(done.Id, 4));
        Assert.True(w.Sessions.SetFileJobState(done.Id, "done"));

        Assert.True(w.Sessions.EndSession(id, "host"));
        Assert.Equal("cancelled", w.Sessions.GetFileJob(queued.Id)!.State);
        Assert.Equal("cancelled", w.Sessions.GetFileJob(active.Id)!.State);
        Assert.Equal("cancelled", w.Sessions.GetFileJob(paused.Id)!.State);
        Assert.Equal("done", w.Sessions.GetFileJob(done.Id)!.State); // terminal jobs untouched
        Assert.Contains(w.Sessions.ListEvents(id), e => e.Kind == "file_job_cancelled");
        // No new jobs on an ended session.
        Assert.Null(w.Sessions.CreateFileJob(id, "to_host", "late.bin", 1, "ctrl"));
    }

    [Fact]
    public void FileJob_CreationGuards_Slice3()
    {
        var w = Setup();
        var id = SessionInState(w, "active");
        Assert.Null(w.Sessions.CreateFileJob(id, "sideways", "x.bin", 1, "ctrl"));
        Assert.Null(w.Sessions.CreateFileJob(id, "to_host", " ", 1, "ctrl"));
        Assert.Null(w.Sessions.CreateFileJob(id, "to_host", "x.bin", -1, "ctrl"));
        Assert.Null(w.Sessions.CreateFileJob("no-such-session", "to_host", "x.bin", 1, "ctrl"));
    }

    // ---- events: the replay source (D36 form 2) ----------------------------------------------

    [Fact]
    public void EventList_IsTheReplaySource_AppendOnlyInOrder_D36()
    {
        var w = Setup();
        var id = SessionInState(w, "paused");
        Assert.True(w.Sessions.ResumeSession(id, "ctrl"));
        Assert.True(w.Sessions.EndSession(id, "ctrl"));
        var kinds = w.Sessions.ListEvents(id).Select(e => e.Kind).ToList();
        // DS-P5-F19 (Wave 12): resume records "resumed", not a
        // second "started" — the pre-fix sequence asserted the
        // defect as correct.
        Assert.Equal(
            new[] { "created", "participant_added", "participant_added", "accepted", "started", "paused", "resumed", "ended" },
            kinds);
        // Timestamps never go backwards in the append-only list.
        var stamps = w.Sessions.ListEvents(id).Select(e => e.Utc).ToList();
        Assert.Equal(stamps.OrderBy(t => t).ToList(), stamps);
    }

    // ---- persistence (PairingService pattern) ---------------------------------------------------

    [Fact]
    public void Persistence_Roundtrip_PreservesTheWholeModel_Slice3()
    {
        var w = Setup();
        var s = CreateAttended(w, recording: "both", recordingRef: "recordings/s1.mp4");
        Assert.True(w.Sessions.AcceptSession(s.Id, "host", SessionAcceptOrigin.EndpointLocal));
        Assert.True(w.Sessions.AddParticipant(s.Id, "peer", "watcher", "ctrl"));
        Assert.True(w.Sessions.StartSession(s.Id));
        Assert.True(w.Sessions.GrantFloor(s.Id, "peer", "host"));
        Assert.NotNull(w.Sessions.SendChatMessage(s.Id, "ctrl", "hello"));
        var job = w.Sessions.CreateFileJob(s.Id, "from_host", "report.pdf", 10, "ctrl")!;
        Assert.True(w.Sessions.SetFileJobState(job.Id, "active"));
        Assert.True(w.Sessions.UpdateFileProgress(job.Id, 5));

        var restored = new SessionService(w.Roster, w.Enrollments);
        Assert.True(restored.ImportJson(w.Sessions.ExportJson()) > 0);
        var rs = restored.GetSession(s.Id)!;
        Assert.Equal("active", rs.State);
        Assert.Equal("both", rs.Recording);
        Assert.True(rs.IsRecording);
        Assert.Equal("host", rs.AcceptedByUserId);
        Assert.Equal(3, restored.ListParticipants(s.Id).Count);
        Assert.Equal("peer", Assert.Single(
            restored.ListParticipants(s.Id).Where(p => p.Floor == "holds")).UserId);
        Assert.Single(restored.ListChat(s.Id));
        var rjob = restored.GetFileJob(job.Id)!;
        Assert.Equal(5, rjob.TransferredBytes);
        Assert.Equal("active", rjob.State);
        Assert.Equal(w.Sessions.ListEvents(s.Id).Count, restored.ListEvents(s.Id).Count);
    }

    [Fact]
    public void Persistence_MalformedEntriesSkippedNeverFatal_Slice3()
    {
        var w = Setup();
        var restored = new SessionService(w.Roster, w.Enrollments);
        Assert.Equal(0, restored.ImportJson("this is not json"));
        Assert.Equal(0, restored.ImportJson(""));
        const string json = """
            {"Sessions":[
              {"Id":"s-bad","ScopeId":"company-1","HostDeviceId":"x","InitiatorUserId":"ctrl",
               "Kind":"attended","State":"bogus","StartedUtc":null,"EndedUtc":null,
               "TransportRung":"lan","Recording":"none","RecordingRef":null,
               "AcceptedByUserId":null,"EndReason":null},
              {"Id":"s-remote","ScopeId":"company-1","HostDeviceId":"x","InitiatorUserId":"ctrl",
               "Kind":"attended","State":"requested","StartedUtc":null,"EndedUtc":null,
               "TransportRung":"lan","Recording":"video","RecordingRef":"https://cloud.example.com/x.mp4",
               "AcceptedByUserId":null,"EndReason":null},
              {"Id":"s-good","ScopeId":"company-1","HostDeviceId":"x","InitiatorUserId":"ctrl",
               "Kind":"attended","State":"requested","StartedUtc":null,"EndedUtc":null,
               "TransportRung":"lan","Recording":"none","RecordingRef":null,
               "AcceptedByUserId":null,"EndReason":null}],
             "Participants":[
              {"SessionId":"s-good","UserId":"ctrl","Role":"controller","Floor":"holds"},
              {"SessionId":"s-good","UserId":"host","Role":"host","Floor":"holds"},
              {"SessionId":"s-ghost","UserId":"ctrl","Role":"controller","Floor":"watching"}],
             "Events":[],"Chat":[],"FileJobs":[]}
            """;
        restored.ImportJson(json);
        Assert.Null(restored.GetSession("s-bad"));    // unknown state: skipped
        Assert.Null(restored.GetSession("s-remote")); // remote recording ref: skipped (D36)
        Assert.NotNull(restored.GetSession("s-good"));
        // The one-holder invariant is repaired on import: first
        // holder keeps the floor, the second is demoted to watching.
        var holders = restored.ListParticipants("s-good").Where(p => p.Floor == "holds").ToList();
        Assert.Equal("ctrl", Assert.Single(holders).UserId);
    }

    [Fact]
    public void Changed_FiresOnMutation_SoTheHostCanPersist_Slice3()
    {
        var w = Setup();
        var fired = 0;
        w.Sessions.Changed += () => fired++;
        var s = CreateAttended(w);
        Assert.True(fired > 0);
        var afterCreate = fired;
        Assert.True(w.Sessions.AcceptSession(s.Id, "host", SessionAcceptOrigin.EndpointLocal));
        Assert.True(fired > afterCreate);
    }
}
