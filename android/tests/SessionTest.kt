import io.deskguest.app.enrollment.DeviceIdentity
import io.deskguest.app.enrollment.EnrollmentStore
import io.deskguest.app.roster.RosterStore
import io.deskguest.app.session.SessionStore
import java.io.File
import java.nio.file.Files

/**
 * JVM tests for Slice 3 (human session model). Every check cites
 * the decision or spec clause it enforces:
 * - Slice 3 SESSION: the closed state-transition set, with
 *   blocked -> ended ONLY (the 2026-11-17 STOP trap must be
 *   structurally impossible); illegal transitions change nothing
 * - Slice 3 CONSENT: attended cannot leave `requested` without a
 *   recorded host accept; unattended requires the initiator's
 *   `use` grant (Slice 2) at creation AND at start
 * - Slice 3 STOP: StopSession terminates from EVERY non-ended
 *   state, host-gated, reason host_stop
 * - D35 participants: the one-floor-holder property (exhaustive),
 *   atomic grant, host-act gating, AI floor eligibility (D9)
 * - Slice 3 OFFBOARDING HOOK (discharges Slice 2 D14's named
 *   requirement): removed/suspended users refuse or end sessions
 *   with participant_removed
 * - D36 events + recording: append-only event list (the replay
 *   source); recording flag + LOCAL-ONLY RecordingRef; IsRecording
 *   always derivable while active (covert recording
 *   unrepresentable)
 * - Slice 3 CHAT + FILE: participants only, ended sessions refuse;
 *   monotonic progress, done requires full bytes, session-end
 *   cascade cancels live jobs
 * - Slice 3 TRANSPORT: the rung must be in the host device's
 *   EffectiveTransports (Slice 2 resolution)
 * - Persistence: TSV roundtrip, corrupt lines skipped, no secret
 */
private var failures = 0

private fun check(name: String, condition: Boolean) {
    if (condition) println("PASS  $name")
    else {
        println("FAIL  $name")
        failures++
    }
}

private var clockNow = 1_700_000_000_000L
private fun tick(): Long {
    clockNow += 1_000L
    return clockNow
}

/** A fully wired world: company scope "co", admin1 (company
 *  admin), host1 (host user), user1/user2 (members of ug1, granted
 *  `use` on dg1), ai1 (paired by user1, member of ug1), dg1 with
 *  transport set [lan, hub, mesh], and one enrolled host device. */
private class World(dir: File, tag: String) {
    val enrollment = EnrollmentStore(File(dir, "$tag-enroll.tsv"))
    val roster = RosterStore(File(dir, "$tag-roster.tsv"), enrollment)
    val sessions: SessionStore
    val hostDeviceId: String

    init {
        roster.addScope(RosterStore.Scope("co", "company", "Acme Co"))
        roster.addUser(RosterStore.User("admin1", "co", "Admin One", "human"))
        roster.addCompanyAdmin("co", "admin1")
        roster.addUser(RosterStore.User("host1", "co", "Host User", "human"))
        roster.addUser(RosterStore.User("user1", "co", "User One", "human"))
        roster.addUser(RosterStore.User("user2", "co", "User Two", "human"))
        roster.addUser(RosterStore.User("user3", "co", "User Three", "human"))
        roster.addUser(RosterStore.User("ai1", "co", "Helper AI", "ai", pairedByUserId = "user1"))
        roster.addUserGroup(
            RosterStore.UserGroup("ug1", "co", "Techs", memberUserIds = setOf("user1", "user2", "ai1")),
            "admin1"
        )
        roster.addDeviceGroup(
            RosterStore.DeviceGroup("dg1", "co", "Fleet", listOf("lan", "hub", "mesh")), "admin1"
        )
        roster.addGrant(RosterStore.Grant("co", "ug1", "dg1", setOf("use")), "admin1")
        val identity = DeviceIdentity.generate()
        val code = enrollment.mint("company", "dg1", "Fleet")
        enrollment.redeem(
            code,
            EnrollmentStore.EnrollingDevice(identity.deviceId, identity.publicKeyBase64, "Host Device")
        )
        hostDeviceId = identity.deviceId
        sessions = SessionStore(File(dir, "$tag-sessions.tsv"), roster, enrollment) { tick() }
    }

    fun attended(id: String, initiator: String = "user1", rung: String = "lan"): Boolean =
        sessions.createSession(
            SessionStore.Session(
                id = id, scopeId = "co", hostDeviceId = hostDeviceId,
                initiatorUserId = initiator, kind = "attended", transportRung = rung
            ),
            hostUserId = "host1"
        )

    fun unattended(id: String, initiator: String = "user1", rung: String = "lan"): Boolean =
        sessions.createSession(
            SessionStore.Session(
                id = id, scopeId = "co", hostDeviceId = hostDeviceId,
                initiatorUserId = initiator, kind = "unattended", transportRung = rung
            ),
            hostUserId = "host1"
        )

    /** Drive a fresh attended session into [state] by legal moves.
     *  The host accept is always recorded first, so `requested`
     *  sessions in the transition matrix are startable. */
    fun inState(id: String, state: String): String {
        check("setup: create attended $id", attended(id))
        check("setup: accept $id", sessions.acceptSession(id, "host1", SessionStore.ACCEPT_ORIGIN_LOCAL_UI))
        when (state) {
            "requested" -> Unit
            "active", "paused", "blocked" -> {
                check("setup: start $id", sessions.startSession(id, "user1"))
                if (state == "paused") check("setup: pause $id", sessions.pauseSession(id, "user1"))
                if (state == "blocked") check("setup: block $id", sessions.blockSession(id, "user1"))
            }
            "ended" -> check("setup: end $id", sessions.endSession(id, "user1"))
            else -> error("unknown state $state")
        }
        check("setup: $id is in $state", sessions.session(id)?.state == state)
        return id
    }

    /** A live (active) attended session for an arbitrary initiator. */
    fun activeAttended(id: String, initiator: String): Boolean =
        attended(id, initiator) && sessions.acceptSession(id, "host1", SessionStore.ACCEPT_ORIGIN_LOCAL_UI) &&
            sessions.startSession(id, initiator) && sessions.session(id)?.state == "active"
}

fun main() {
    val dir = Files.createTempDirectory("deskguest-session-test").toFile()
    val states = listOf("requested", "active", "paused", "blocked", "ended")
    val legal: Map<String, Set<String>> = mapOf(
        "requested" to setOf("active", "ended"),
        "active" to setOf("paused", "blocked", "ended"),
        "paused" to setOf("active", "blocked", "ended"),
        "blocked" to setOf("ended"),
        "ended" to emptySet()
    )

    // ================= Creation validation =================
    run {
        val w = World(dir, "create")
        check("Slice 3 create: attended session lands in requested with host + initiator participants",
            w.attended("s1") && w.sessions.session("s1")?.state == "requested" &&
                w.sessions.participants("s1").map { it.userId to it.role } ==
                listOf("host1" to "host", "user1" to "controller"))
        check("Slice 3 create: created + participant_added events recorded with the initiator as actor",
            w.sessions.events("s1").map { it.type } ==
                listOf("created", "participant_added", "participant_added") &&
                w.sessions.events("s1").all { it.actorUserId == "user1" })
        check("Slice 3 create: duplicate id refused", !w.attended("s1"))
        check("Slice 3 create: unknown scope refused",
            !w.sessions.createSession(
                SessionStore.Session("sx", "nope", w.hostDeviceId, "user1", "attended", transportRung = "lan"),
                "host1"
            ))
        check("Slice 3 create: unknown host device refused",
            !w.sessions.createSession(
                SessionStore.Session("sx", "co", "no-device", "user1", "attended", transportRung = "lan"),
                "host1"
            ))
        check("Slice 3 create: unknown initiator refused", !w.attended("sx", initiator = "ghost"))
        check("Slice 3 create: cross-scope initiator refused (user of no scope)",
            !w.attended("sx", initiator = "adminX"))
        check("Slice 3 create: unknown host user refused",
            !w.sessions.createSession(
                SessionStore.Session("sx", "co", w.hostDeviceId, "user1", "attended", transportRung = "lan"),
                "ghost"
            ))
        check("Slice 3 create: an AI cannot be the host user (host is the person at the machine)",
            !w.sessions.createSession(
                SessionStore.Session("sx", "co", w.hostDeviceId, "user1", "attended", transportRung = "lan"),
                "ai1"
            ))
        check("Slice 3 create: unknown kind refused",
            !w.sessions.createSession(
                SessionStore.Session("sx", "co", w.hostDeviceId, "user1", "stealth", transportRung = "lan"),
                "host1"
            ))
        // D38 S3-AND F12: the old form of this check was a
        // disjunction that passed on outright refusal, leaving the
        // force-reset branch unproven. Assert the success path and
        // the forced fields separately.
        check("Slice 3 create: a caller-supplied active/accepted record is ACCEPTED as a create but force-reset",
            w.sessions.createSession(
                SessionStore.Session(
                    "sx", "co", w.hostDeviceId, "user1", "attended",
                    state = "active", transportRung = "lan", acceptBy = "host1"
                ), "host1"
            ))
        check("Slice 3 create: the minted session is in requested with NO accept and NO end stamp",
            w.sessions.session("sx")?.state == "requested" &&
                w.sessions.session("sx")?.acceptBy == null &&
                w.sessions.session("sx")?.endedUtc == null &&
                w.sessions.session("sx")?.endReason == null)
        check("Slice 3 transport: rung inside EffectiveTransports accepted (mesh in group set)",
            w.attended("s-mesh", rung = "mesh"))
        check("Slice 3 transport: rung OUTSIDE EffectiveTransports refused (tor not in group set)",
            !w.attended("s-tor", rung = "tor") && w.sessions.session("s-tor") == null)
        check("Slice 3 transport: a non-rung id refused", !w.attended("s-warp", rung = "warp"))
        check("setup: revoke the host device", w.enrollment.revoke(w.hostDeviceId))
        check("Slice 3 create: revoked host device refused", !w.attended("s-revoked"))
    }

    // ================= Closed transition set — exhaustive =================
    run {
        val w = World(dir, "matrix")
        var n = 0
        for (from in states) {
            for (to in states) {
                n++
                val id = "m$n"
                w.inState(id, from)
                val before = w.sessions.session(id)!!
                val eventsBefore = w.sessions.events(id).size
                val expectLegal = to in (legal[from] ?: emptySet())
                val result = w.sessions.transition(id, to, "user1")
                if (expectLegal) {
                    check("Slice 3 transitions: $from -> $to is legal and lands in $to",
                        result && w.sessions.session(id)?.state == to)
                } else {
                    val after = w.sessions.session(id)!!
                    check("Slice 3 transitions: $from -> $to REFUSED and changes nothing " +
                        "(state, endedUtc, endReason, event count identical)",
                        !result && after == before && w.sessions.events(id).size == eventsBefore)
                }
            }
        }
        check("Slice 3 transitions: the store's closed set is exactly the spec set (blocked -> ended ONLY)",
            SessionStore.TRANSITIONS == legal)
        check("Slice 3 transitions: an unknown target state refuses and changes nothing",
            run {
                val id = w.inState("m-unknown", "active")
                val before = w.sessions.session(id)
                !w.sessions.transition(id, "warp", "user1") && w.sessions.session(id) == before
            })
    }

    // ================= Consent gates =================
    run {
        val w = World(dir, "consent")
        check("setup: attended session created", w.attended("a1"))
        check("Slice 3 consent: attended CANNOT leave requested without a recorded host accept",
            !w.sessions.startSession("a1", "user1") && w.sessions.session("a1")?.state == "requested")
        check("Slice 3 consent: accept by a non-host participant refused",
            !w.sessions.acceptSession("a1", "user1", SessionStore.ACCEPT_ORIGIN_LOCAL_UI) && w.sessions.session("a1")?.acceptBy == null)
        check("Slice 3 consent: accept by a non-participant refused",
            !w.sessions.acceptSession("a1", "user2", SessionStore.ACCEPT_ORIGIN_LOCAL_UI))
        check("Slice 3 consent: host accept is recorded on the record AND as an event",
            w.sessions.acceptSession("a1", "host1", SessionStore.ACCEPT_ORIGIN_LOCAL_UI) &&
                w.sessions.session("a1")?.acceptBy == "host1" &&
                w.sessions.events("a1").any { it.type == "accepted" && it.actorUserId == "host1" })
        check("Slice 3 consent: a second accept is refused (accept is recorded once)",
            !w.sessions.acceptSession("a1", "host1", SessionStore.ACCEPT_ORIGIN_LOCAL_UI))
        check("Slice 3 consent: after the accept the attended session starts",
            w.sessions.startSession("a1", "user1") && w.sessions.session("a1")?.state == "active" &&
                w.sessions.events("a1").any { it.type == "started" })

        check("Slice 3 consent: unattended by a user WITHOUT the use grant is refused at creation",
            !w.unattended("u-nogrant", initiator = "user3") && w.sessions.session("u-nogrant") == null)
        check("Slice 3 consent: unattended by a granted user starts with NO accept at all",
            w.unattended("u1") && w.sessions.startSession("u1", "user1") &&
                w.sessions.session("u1")?.state == "active" && w.sessions.session("u1")?.acceptBy == null)
        check("Slice 3 consent: acceptSession on an unattended session is refused (no accept concept)",
            w.unattended("u2") && !w.sessions.acceptSession("u2", "host1", SessionStore.ACCEPT_ORIGIN_LOCAL_UI))
        check("setup: admin replaces the grant, dropping the use right",
            w.roster.addGrant(RosterStore.Grant("co", "ug1", "dg1", setOf("enroll")), "admin1"))
        check("Slice 3 consent: unattended start RE-CHECKS the grant at start — revoked grant refuses the start",
            !w.sessions.startSession("u2", "user1") && w.sessions.session("u2")?.state == "requested")
        check("setup: admin restores the use grant",
            w.roster.addGrant(RosterStore.Grant("co", "ug1", "dg1", setOf("use")), "admin1"))
        check("Slice 3 consent: with the grant restored the same session starts",
            w.sessions.startSession("u2", "user1"))
    }

    // ================= STOP — exhaustive =================
    run {
        val w = World(dir, "stop")
        for (from in listOf("requested", "active", "paused", "blocked")) {
            val id = w.inState("stop-$from", from)
            val ok = w.sessions.stopSession(id, "host1")
            val s = w.sessions.session(id)
            check("Slice 3 STOP: StopSession from $from terminates with reason host_stop",
                ok && s?.state == "ended" && s?.endReason == "host_stop" && s?.endedUtc != null)
            check("Slice 3 STOP: from $from the event tail is blocked/stopped/ended in order",
                w.sessions.events(id).takeLast(3).map { it.type } == listOf("blocked", "stopped", "ended") ||
                    (from == "blocked" &&
                        w.sessions.events(id).takeLast(2).map { it.type } == listOf("stopped", "ended")))
        }
        val endedId = w.inState("stop-ended", "ended")
        check("Slice 3 STOP: StopSession on an ended session refuses and changes nothing",
            !w.sessions.stopSession(endedId, "host1") &&
                w.sessions.session(endedId)?.endReason == "ended")
        val liveId = w.inState("stop-gate", "active")
        check("Slice 3 STOP: STOP by a non-host, non-admin participant is refused — session stays live",
            !w.sessions.stopSession(liveId, "user1") && w.sessions.session(liveId)?.state == "active")
        check("Slice 3 STOP: STOP by a company admin terminates",
            w.sessions.stopSession(liveId, "admin1") &&
                w.sessions.session(liveId)?.endReason == "host_stop")
    }

    // ================= Participants & floor (D35) — exhaustive =================
    run {
        val w = World(dir, "floor")
        val id = w.inState("f1", "active")
        check("D38/F7 add participant: in an ATTENDED session the initiator alone cannot widen the consented participant set",
            !w.sessions.addParticipant(id, "user1", "user2", "controller") &&
                w.sessions.participant(id, "user2") == null)
        check("D35 add participant by the host succeeds, entering as watcher-floored controller",
            w.sessions.addParticipant(id, "host1", "user2", "controller") &&
                w.sessions.participant(id, "user2")?.floor == "watching")
        check("D35 add participant: duplicate refused",
            !w.sessions.addParticipant(id, "host1", "user2", "controller"))
        check("D35 add participant: a second host refused",
            !w.sessions.addParticipant(id, "host1", "user3", "host"))
        check("D35 add participant: unknown user refused",
            !w.sessions.addParticipant(id, "host1", "ghost", "controller"))
        check("D35 add participant: by an unrelated non-host non-admin refused",
            !w.sessions.addParticipant(id, "user3", "ai1", "controller"))
        check("D35 add the AI participant by the host",
            w.sessions.addParticipant(id, "host1", "ai1", "controller"))
        check("D35 setup: three controllers + host present",
            w.sessions.participants(id).map { it.userId } == listOf("host1", "user1", "user2", "ai1"))

        // One-floor-holder, exhaustive: every ordered grant sequence
        // over every floor-eligible participant, invariant after each.
        val eligible = listOf("host1", "user1", "user2", "ai1")
        var sequenceOk = true
        for (first in eligible) {
            for (second in eligible) {
                if (!w.sessions.grantFloor(id, "host1", first)) sequenceOk = false
                var holders = w.sessions.participants(id).filter { it.floor == "holds" }
                if (holders.map { it.userId } != listOf(first)) sequenceOk = false
                if (!w.sessions.grantFloor(id, "host1", second)) sequenceOk = false
                holders = w.sessions.participants(id).filter { it.floor == "holds" }
                if (holders.map { it.userId } != listOf(second)) sequenceOk = false
            }
        }
        check("D35 one-floor-holder: EVERY ordered pair of grants leaves exactly the last grantee holding",
            sequenceOk)
        check("D35 grant floor records a floor_granted event per grant with the host as actor",
            w.sessions.events(id).count { it.type == "floor_granted" } == 32 &&
                w.sessions.events(id).filter { it.type == "floor_granted" }.all { it.actorUserId == "host1" })

        check("D35 host-act gating: a controller cannot grant the floor",
            !w.sessions.grantFloor(id, "user1", "user2"))
        check("D35 host-act gating: a company admin CAN grant the floor",
            w.sessions.grantFloor(id, "admin1", "user1"))
        check("D9/D35 an AI holding the floor gains NO host acts by holding it",
            w.sessions.grantFloor(id, "host1", "ai1") &&
                !w.sessions.grantFloor(id, "ai1", "user1") &&
                !w.sessions.removeParticipant(id, "ai1", "user2") &&
                !w.sessions.setWatchOnly(id, "ai1", "user2") &&
                !w.sessions.stopSession(id, "ai1"))
        check("D35 take floor back: floor returns to the host participant, exactly one holder",
            w.sessions.takeFloorBack(id, "host1") &&
                w.sessions.participants(id).filter { it.floor == "holds" }.map { it.userId } == listOf("host1") &&
                w.sessions.events(id).any { it.type == "floor_taken" })
        check("D35 set watch-only: role becomes watcher and a held floor is revoked in the same act",
            w.sessions.grantFloor(id, "host1", "user2") &&
                w.sessions.setWatchOnly(id, "host1", "user2") &&
                w.sessions.participant(id, "user2")?.role == "watcher" &&
                w.sessions.participant(id, "user2")?.floor == "watching" &&
                w.sessions.participants(id).none { it.floor == "holds" && it.userId == "user2" })
        check("D35 a watcher cannot be granted the floor",
            !w.sessions.grantFloor(id, "host1", "user2"))
        check("D35 the host participant cannot be set watch-only",
            !w.sessions.setWatchOnly(id, "host1", "host1"))
        check("D35 remove participant by a non-host refused",
            !w.sessions.removeParticipant(id, "user1", "ai1"))
        check("D35 remove the floor holder: floor is left UNHELD, nobody inherits it silently",
            w.sessions.grantFloor(id, "host1", "ai1") &&
                w.sessions.removeParticipant(id, "host1", "ai1") &&
                w.sessions.participant(id, "ai1") == null &&
                w.sessions.participants(id).none { it.floor == "holds" } &&
                w.sessions.events(id).any { it.type == "participant_removed" && it.actorUserId == "host1" })
        check("D35 the host participant cannot be removed",
            !w.sessions.removeParticipant(id, "admin1", "host1"))

        // Floor acts across states: meaningful in active/paused only.
        for (state in listOf("requested", "blocked", "ended")) {
            val sid = w.inState("floor-$state", state)
            check("D35 floor acts refuse in $state (grant + take-back)",
                !w.sessions.grantFloor(sid, "host1", "user1") &&
                    !w.sessions.takeFloorBack(sid, "host1"))
        }
        val pausedId = w.inState("floor-paused", "paused")
        check("D35 floor acts are meaningful in paused and work there",
            w.sessions.grantFloor(pausedId, "host1", "user1") &&
                w.sessions.participant(pausedId, "user1")?.floor == "holds")
    }

    // AI floor eligibility (D9): an AI without the use right cannot hold.
    run {
        val w = World(dir, "aifloor")
        w.roster.addUser(RosterStore.User("ai2", "co", "Ungranted AI", "ai", pairedByUserId = "user1"))
        val id = w.inState("af1", "active")
        check("setup: add the ungranted AI as participant",
            w.sessions.addParticipant(id, "host1", "ai2", "controller"))
        check("D9/D35 an AI that could NOT initiate (no use grant) cannot hold the floor",
            !w.sessions.grantFloor(id, "host1", "ai2") &&
                w.sessions.participant(id, "ai2")?.floor == "watching")
        check("setup: suspend ai1", w.roster.setUserSuspended("co", "ai1", true, "admin1"))
        check("setup: a suspended AI cannot even join as participant",
            !w.sessions.addParticipant(id, "host1", "ai1", "controller"))
    }

    // ================= Offboarding hook =================
    run {
        val w = World(dir, "offboard")
        w.roster.addUser(RosterStore.User("admin2", "co", "Admin Two", "human"))
        w.roster.addCompanyAdmin("co", "admin2", actorUserId = "admin1")

        val liveId = w.inState("ob-live", "active")
        check("setup: file job running on the live session",
            w.sessions.createFileJob(
                liveId, "user1",
                SessionStore.FileJob("job1", liveId, "to_host", "a.bin", 100)
            ) && w.sessions.updateFileProgress(liveId, "job1", 40, "user1"))
        // A second live session whose INITIATOR stays clean; user2
        // joins it as a mere participant (used below).
        check("setup: second live session initiated by user3",
            w.activeAttended("ob-participant", initiator = "user3"))
        check("setup: user2 joins as participant",
            w.sessions.addParticipant("ob-participant", "host1", "user2", "controller"))

        val removed = w.roster.removeUser("co", "user1", actorUserId = "admin1", stepUp = false)
        check("setup: D14 offboarding of user1 fires", removed.fired)
        check("Slice 3 offboarding: a removed user can NEVER initiate a new session",
            !w.attended("ob-new", initiator = "user1") && w.sessions.session("ob-new") == null)
        check("Slice 3 offboarding: enforceOffboarding ends the removed user's live session, participant_removed",
            w.sessions.enforceOffboarding(liveId) &&
                w.sessions.session(liveId)?.state == "ended" &&
                w.sessions.session(liveId)?.endReason == "participant_removed" &&
                w.sessions.events(liveId).any { it.type == "participant_removed" } &&
                w.sessions.events(liveId).any { it.type == "ended" })
        check("Slice 3 offboarding: the end cascade cancelled the removed user's live file job",
            w.sessions.fileJob(liveId, "job1")?.state == "cancelled")
        check("Slice 3 offboarding: enforceOffboarding on an ended session is a no-op false",
            !w.sessions.enforceOffboarding(liveId))

        // A removed PARTICIPANT (not the initiator) ends the session
        // on the next transition attempt — the transition re-reads.
        check("setup: user2 is offboarded",
            w.roster.removeUser("co", "user2", actorUserId = "admin1", stepUp = false).fired)
        val eventsBefore = w.sessions.events("ob-participant").size
        check("Slice 3 offboarding: a state transition RE-READS the roster — pause refused, session ended participant_removed",
            !w.sessions.pauseSession("ob-participant", "host1") &&
                w.sessions.session("ob-participant")?.state == "ended" &&
                w.sessions.session("ob-participant")?.endReason == "participant_removed" &&
                w.sessions.events("ob-participant").size > eventsBefore)

        // Suspended AI: cannot initiate, cannot stay in a session.
        // (user1's offboarding above already suspended ai1, its AI.)
        check("setup: ai1 is suspended (D14 suspended the removed user's AI)",
            w.roster.user("ai1")?.suspended == true)
        check("Slice 3 offboarding: a suspended AI can NEVER initiate",
            !w.unattended("ob-ai", initiator = "ai1") && w.sessions.session("ob-ai") == null)
        check("setup: fresh active session initiated by user3",
            w.activeAttended("ob-ai-live", initiator = "user3"))
        check("setup: ai1 unsuspended and added as participant",
            w.roster.setUserSuspended("co", "ai1", false, "admin1") &&
                w.sessions.addParticipant("ob-ai-live", "host1", "ai1", "controller"))
        check("setup: ai1 suspended again mid-session", w.roster.setUserSuspended("co", "ai1", true, "admin1"))
        check("Slice 3 offboarding: a session whose AI participant is suspended ends participant_removed",
            w.sessions.enforceOffboarding("ob-ai-live") &&
                w.sessions.session("ob-ai-live")?.endReason == "participant_removed")
        check("Slice 3 offboarding: a clean session is untouched by enforceOffboarding",
            w.activeAttended("ob-clean", initiator = "user3") &&
                !w.sessions.enforceOffboarding("ob-clean") &&
                w.sessions.session("ob-clean")?.state == "active")
    }

    // ================= Events + recording (D36) =================
    run {
        val w = World(dir, "recording")
        val id = w.inState("r1", "active")
        check("D36 a session with recording=none is not recording",
            w.sessions.session(id)?.recording == "none" && !w.sessions.isRecording(id))
        check("D36 the event list so far is the replay source: created/accepted/started in order, append-only",
            w.sessions.events(id).map { it.type } ==
                listOf("created", "participant_added", "participant_added", "accepted", "started"))
        val snapshot = w.sessions.events(id)
        check("D36 set recording to video with a LOCAL path takes visible effect immediately",
            w.sessions.setRecording(id, "host1", "video", "/storage/emulated/0/deskguest/session-r1.mp4") &&
                w.sessions.session(id)?.isRecording == true && w.sessions.isRecording(id))
        check("D36 remote RecordingRefs are refused and change nothing (https, http, s3, protocol-relative, ftp)",
            listOf(
                "https://cloud.example.com/r1.mp4", "http://example.com/r1.mp4",
                "s3://bucket/r1.mp4", "//cdn.example.com/r1.mp4", "ftp:files/r1.mp4"
            ).all { ref ->
                !w.sessions.setRecording(id, "host1", "video", ref) &&
                    w.sessions.session(id)?.recordingRef == "/storage/emulated/0/deskguest/session-r1.mp4"
            })
        check("D36 local uri forms are accepted (file:, content:, drive path)",
            w.sessions.setRecording(id, "host1", "video", "file:///storage/emulated/0/deskguest/r1.mp4") &&
                w.sessions.setRecording(id, "host1", "video", "content://media/external/video/42") &&
                w.sessions.setRecording(id, "host1", "both", "C:\\Recordings\\r1.mp4") &&
                w.sessions.session(id)?.recording == "both" && w.sessions.isRecording(id))
        check("D36 covert recording is unrepresentable: Session has NO stored boolean field that could hide recording " +
            "(isRecording is a derived property, absent from the stored fields)",
            SessionStore.Session::class.java.declaredFields.none { it.name == "isRecording" } &&
                w.sessions.session(id)?.isRecording == true)
        check("D36 recording=none clears the reference and the derived flag",
            w.sessions.setRecording(id, "host1", "none", null) &&
                w.sessions.session(id)?.recordingRef == null && !w.sessions.isRecording(id))
        check("D36 a remote ref is refused at CREATION too",
            !w.sessions.createSession(
                SessionStore.Session(
                    "r-bad", "co", w.hostDeviceId, "user1", "attended",
                    transportRung = "lan", recording = "video",
                    recordingRef = "https://cloud.example.com/x.mp4"
                ), "host1"
            ) && w.sessions.session("r-bad") == null)
        check("D38/F10 a session created with recording=video is NOT recording while still requested (pre-consent)",
            w.sessions.createSession(
                SessionStore.Session(
                    "r-good", "co", w.hostDeviceId, "user1", "attended",
                    transportRung = "lan", recording = "video", recordingRef = "/data/deskguest/r.mp4"
                ), "host1"
            ) && w.sessions.session("r-good")?.isRecording == false)
        check("D36/F10 after host accept + start, the same session IS recording (derived from state)",
            w.sessions.acceptSession("r-good", "host1", SessionStore.ACCEPT_ORIGIN_LOCAL_UI) &&
                w.sessions.startSession("r-good", "user1") &&
                w.sessions.session("r-good")?.isRecording == true)
        check("D36 events are append-only: earlier events are byte-identical after later acts",
            w.sessions.events(id).subList(0, snapshot.size) == snapshot)
        check("setup: restore video recording, then end the session",
            w.sessions.setRecording(id, "host1", "video", "/data/deskguest/r1.mp4") &&
                w.sessions.endSession(id, "host1"))
        check("D36 after the session ends it is no longer recording (derived from state)",
            w.sessions.session(id)?.recording == "video" && !w.sessions.isRecording(id))
        check("D36 recording cannot be changed on an ended session",
            !w.sessions.setRecording(id, "host1", "none", null))
    }

    // ================= Chat =================
    run {
        val w = World(dir, "chat")
        val id = w.inState("c1", "active")
        check("Slice 3 chat: a participant can send; message stored with sender + text",
            w.sessions.sendChat(id, "user1", "hello host") &&
                w.sessions.chatMessages(id).map { it.senderUserId to it.text } ==
                listOf("user1" to "hello host"))
        check("Slice 3 chat: a non-participant CANNOT send",
            !w.sessions.sendChat(id, "user2", "intruder") && w.sessions.chatMessages(id).size == 1)
        check("Slice 3 chat: blank text refused", !w.sessions.sendChat(id, "host1", "  "))
        check("Slice 3 chat: a chat marker event is recorded (marker carries no message text)",
            w.sessions.events(id).any { it.type == "chat" && !it.detail.contains("hello") })
        check("setup: user2 joins, chats, is removed",
            w.sessions.addParticipant(id, "host1", "user2", "controller") &&
                w.sessions.sendChat(id, "user2", "hi all") &&
                w.sessions.removeParticipant(id, "host1", "user2"))
        check("Slice 3 chat: a removed participant can no longer send",
            !w.sessions.sendChat(id, "user2", "still here?") && w.sessions.chatMessages(id).size == 2)
        val blockedId = w.inState("c-blocked", "blocked")
        check("Slice 3 chat: a blocked session refuses chat (its only outgoing edge is ended)",
            !w.sessions.sendChat(blockedId, "user1", "anyone?"))
        check("setup: end c1", w.sessions.endSession(id, "host1"))
        check("Slice 3 chat: messages to an ENDED session refuse",
            !w.sessions.sendChat(id, "user1", "after end") && w.sessions.chatMessages(id).size == 2)
    }

    // ================= File jobs =================
    run {
        val w = World(dir, "files")
        val id = w.inState("fj1", "active")
        check("Slice 3 file: job creation by a participant lands queued at zero bytes (caller cannot mint progress)",
            w.sessions.createFileJob(
                id, "user1",
                SessionStore.FileJob("j1", id, "to_host", "report.pdf", 100, transferredBytes = 55, state = "done")
            ) && w.sessions.fileJob(id, "j1")?.state == "queued" &&
                w.sessions.fileJob(id, "j1")?.transferredBytes == 0L)
        check("Slice 3 file: job creation by a non-participant refused",
            !w.sessions.createFileJob(id, "user3", SessionStore.FileJob("jx", id, "to_host", "x", 1)))
        check("Slice 3 file: bad direction / negative size / duplicate id refused",
            !w.sessions.createFileJob(id, "user1", SessionStore.FileJob("j2", id, "sideways", "x", 1)) &&
                !w.sessions.createFileJob(id, "user1", SessionStore.FileJob("j2", id, "to_host", "x", -1)) &&
                !w.sessions.createFileJob(id, "user1", SessionStore.FileJob("j1", id, "to_host", "x", 1)))
        check("Slice 3 file: progress advances and flips queued -> active",
            w.sessions.updateFileProgress(id, "j1", 40, "user1") &&
                w.sessions.fileJob(id, "j1")?.transferredBytes == 40L &&
                w.sessions.fileJob(id, "j1")?.state == "active")
        check("Slice 3 file: progress is MONOTONIC — a decrease refuses and changes nothing",
            !w.sessions.updateFileProgress(id, "j1", 39, "user1") &&
                w.sessions.fileJob(id, "j1")?.transferredBytes == 40L)
        check("Slice 3 file: progress beyond the size refuses",
            !w.sessions.updateFileProgress(id, "j1", 101, "user1") &&
                w.sessions.fileJob(id, "j1")?.transferredBytes == 40L)
        check("Slice 3 file: done REQUIRES full bytes — partial completion refused, state unchanged",
            !w.sessions.setFileJobState(id, "j1", "done", "user1") &&
                w.sessions.fileJob(id, "j1")?.state == "active")
        check("Slice 3 file: reaching full bytes does not auto-complete; the explicit done act then succeeds",
            w.sessions.updateFileProgress(id, "j1", 100, "user1") &&
                w.sessions.fileJob(id, "j1")?.state == "active" &&
                w.sessions.setFileJobState(id, "j1", "done", "user1") &&
                w.sessions.fileJob(id, "j1")?.state == "done")
        check("Slice 3 file: a done job is terminal (no progress, no state change)",
            !w.sessions.updateFileProgress(id, "j1", 100, "user1") &&
                !w.sessions.setFileJobState(id, "j1", "active", "user1"))
        check("Slice 3 file: a zero-byte job can complete (0 == 0)",
            w.sessions.createFileJob(id, "user1", SessionStore.FileJob("j0", id, "from_host", "empty", 0)) &&
                w.sessions.setFileJobState(id, "j0", "done", "user1"))
        check("setup: three live jobs in queued/active/paused for the cascade",
            w.sessions.createFileJob(id, "user1", SessionStore.FileJob("jq", id, "to_host", "q", 10)) &&
                w.sessions.createFileJob(id, "user1", SessionStore.FileJob("ja", id, "to_host", "a", 10)) &&
                w.sessions.updateFileProgress(id, "ja", 5, "user1") &&
                w.sessions.createFileJob(id, "user1", SessionStore.FileJob("jp", id, "from_host", "p", 10)) &&
                w.sessions.setFileJobState(id, "jp", "active", "user1") &&
                w.sessions.setFileJobState(id, "jp", "paused", "user1") &&
                w.sessions.createFileJob(id, "user1", SessionStore.FileJob("jf", id, "to_host", "f", 10)) &&
                w.sessions.setFileJobState(id, "jf", "failed", "user1"))
        check("setup: end the session", w.sessions.endSession(id, "host1"))
        check("Slice 3 file: session-end cascade forces queued/active/paused jobs to cancelled",
            w.sessions.fileJob(id, "jq")?.state == "cancelled" &&
                w.sessions.fileJob(id, "ja")?.state == "cancelled" &&
                w.sessions.fileJob(id, "jp")?.state == "cancelled")
        check("Slice 3 file: the cascade leaves terminal outcomes intact (done stays done, failed stays failed)",
            w.sessions.fileJob(id, "j1")?.state == "done" && w.sessions.fileJob(id, "jf")?.state == "failed")
        check("Slice 3 file: no new jobs, progress, or state changes on an ended session",
            !w.sessions.createFileJob(id, "user1", SessionStore.FileJob("jz", id, "to_host", "z", 1)) &&
                !w.sessions.updateFileProgress(id, "ja", 6, "user1") &&
                !w.sessions.setFileJobState(id, "ja", "active", "user1"))
    }

    // ================= Persistence =================
    run {
        val file = File(dir, "persist-sessions.tsv")
        val enrollment = EnrollmentStore(File(dir, "persist-enroll.tsv"))
        val roster = RosterStore(File(dir, "persist-roster.tsv"), enrollment)
        roster.addScope(RosterStore.Scope("co", "company", "Acme Co"))
        roster.addUser(RosterStore.User("admin1", "co", "Admin One", "human"))
        roster.addCompanyAdmin("co", "admin1")
        roster.addUser(RosterStore.User("host1", "co", "Host User", "human"))
        roster.addUser(RosterStore.User("user1", "co", "User One", "human"))
        roster.addUserGroup(
            RosterStore.UserGroup("ug1", "co", "Techs", memberUserIds = setOf("user1")), "admin1"
        )
        roster.addDeviceGroup(RosterStore.DeviceGroup("dg1", "co", "Fleet", listOf("lan", "hub")), "admin1")
        roster.addGrant(RosterStore.Grant("co", "ug1", "dg1", setOf("use")), "admin1")
        val identity = DeviceIdentity.generate()
        val code = enrollment.mint("company", "dg1", "Fleet")
        enrollment.redeem(
            code, EnrollmentStore.EnrollingDevice(identity.deviceId, identity.publicKeyBase64, "Host Device")
        )
        val store = SessionStore(file, roster, enrollment) { tick() }
        check("setup: build a rich session for the roundtrip",
            store.createSession(
                SessionStore.Session(
                    "p1", "co", identity.deviceId, "user1", "attended",
                    transportRung = "hub", recording = "video", recordingRef = "/data/deskguest/p1.mp4"
                ), "host1"
            ) && store.acceptSession("p1", "host1", SessionStore.ACCEPT_ORIGIN_LOCAL_UI) && store.startSession("p1", "user1") &&
                store.grantFloor("p1", "host1", "user1") &&
                store.sendChat("p1", "user1", "roundtrip chat") &&
                store.createFileJob("p1", "user1", SessionStore.FileJob("pj", "p1", "to_host", "f.bin", 10)) &&
                store.updateFileProgress("p1", "pj", 7, "user1"))
        val eventsBefore = store.events("p1")

        val reloaded = SessionStore(file, roster, enrollment) { tick() }
        check("persistence: session roundtrips incl. accept, rung, recording + local ref",
            reloaded.session("p1")?.state == "active" && reloaded.session("p1")?.acceptBy == "host1" &&
                reloaded.session("p1")?.acceptOrigin == SessionStore.ACCEPT_ORIGIN_LOCAL_UI &&
                reloaded.session("p1")?.transportRung == "hub" &&
                reloaded.session("p1")?.recording == "video" &&
                reloaded.session("p1")?.recordingRef == "/data/deskguest/p1.mp4" &&
                reloaded.session("p1")?.isRecording == true)
        check("persistence: participants + floor holder roundtrip",
            reloaded.participants("p1").firstOrNull { it.floor == "holds" }?.userId == "user1" &&
                reloaded.participants("p1").size == 2)
        check("persistence: the append-only event list roundtrips in order",
            reloaded.events("p1") == eventsBefore)
        check("persistence: chat roundtrips",
            reloaded.chatMessages("p1").map { it.text } == listOf("roundtrip chat"))
        check("persistence: file job roundtrips with progress",
            reloaded.fileJob("p1", "pj")?.transferredBytes == 7L &&
                reloaded.fileJob("p1", "pj")?.state == "active")
        check("persistence: the reloaded session still obeys the closed set (blocked -> active refused)",
            reloaded.blockSession("p1", "user1") && !reloaded.startSession("p1", "user1") &&
                reloaded.session("p1")?.state == "blocked")
        val eventsAfterBlock = reloaded.events("p1").size

        val onDisk = file.readText()
        check("persistence: the store contains no password/token/seed material",
            !onDisk.contains("password") && !onDisk.contains("token") && !onDisk.contains("seed"))

        file.appendText(
            "\ngarbage line with no tabs\nsession\ttoo\tfew\nparticipant\tx\tghost\tking\tholds\n" +
                "filejob\tj\ts\twarp\tn\t1\t0\tqueued\nevent\tnotanumber\ts\tcreated\ta\td\n"
        )
        val afterCorrupt = SessionStore(file, roster, enrollment) { tick() }
        check("persistence: corrupt lines are skipped, never fatal — records intact",
            afterCorrupt.session("p1")?.state == "blocked" &&
                afterCorrupt.participants("p1").size == 2 &&
                afterCorrupt.events("p1").size == eventsAfterBlock &&
                afterCorrupt.fileJob("p1", "pj") != null)
    }

    // ================= D38 reconciliation (S3-AND findings) =================
    run {
        val w = World(dir, "d38")

        // F1: initiator == host is refused — no self-accepted attended session.
        check("D38/F1 an initiator naming THEMSELVES as host is refused (attended)",
            !w.sessions.createSession(
                SessionStore.Session("self1", "co", w.hostDeviceId, "user1", "attended", transportRung = "lan"),
                hostUserId = "user1"
            ) && w.sessions.session("self1") == null)
        check("D38/F1 an initiator naming themselves as host is refused (unattended too)",
            !w.sessions.createSession(
                SessionStore.Session("self2", "co", w.hostDeviceId, "user1", "unattended", transportRung = "lan"),
                hostUserId = "user1"
            ))

        // F2: transitions authorize the actor.
        check("setup: attended d38-t created + accepted", w.attended("d38-t") && w.sessions.acceptSession("d38-t", "host1", SessionStore.ACCEPT_ORIGIN_LOCAL_UI))
        check("D38/F2 start by a NON-PARTICIPANT is refused, session stays requested",
            !w.sessions.startSession("d38-t", "user3") && w.sessions.session("d38-t")?.state == "requested")
        check("D38/F2 start by an arbitrary string is refused",
            !w.sessions.startSession("d38-t", "random-string"))
        check("setup: host starts d38-t", w.sessions.startSession("d38-t", "host1"))
        check("setup: user2 joins as WATCHER",
            w.sessions.addParticipant("d38-t", "host1", "user2", "watcher"))
        check("D38/F2 pause by a WATCHER is refused",
            !w.sessions.pauseSession("d38-t", "user2") && w.sessions.session("d38-t")?.state == "active")
        check("D38/F2 end by a non-participant is refused",
            !w.sessions.endSession("d38-t", "user3") && w.sessions.session("d38-t")?.state == "active")

        // F4: blocked refuses file + recording acts; file acts are authorized.
        check("setup: file job on d38-t",
            w.sessions.createFileJob("d38-t", "user1", SessionStore.FileJob("jf1", "d38-t", "to_host", "f.bin", 10)))
        check("D38/F4 file progress by a non-participant is refused",
            !w.sessions.updateFileProgress("d38-t", "jf1", 5, "user3") &&
                w.sessions.fileJob("d38-t", "jf1")?.transferredBytes == 0L)
        check("D38/F4 file progress by a watcher is refused",
            !w.sessions.updateFileProgress("d38-t", "jf1", 5, "user2"))
        check("setup: block d38-t", w.sessions.blockSession("d38-t", "host1"))
        check("D38/F4 file progress refuses in BLOCKED",
            !w.sessions.updateFileProgress("d38-t", "jf1", 5, "user1"))
        check("D38/F4 file state refuses in BLOCKED",
            !w.sessions.setFileJobState("d38-t", "jf1", "active", "user1"))
        check("D38/F4 recording refuses in BLOCKED",
            !w.sessions.setRecording("d38-t", "host1", "video", "/data/deskguest/x.mp4") &&
                w.sessions.session("d38-t")?.recording == "none")
        check("D38/F9 entering blocked CLEARS the floor (setup: floor was never held here, holder check on end below)",
            w.sessions.participants("d38-t").none { it.floor == "holds" })

        // F9: floor cleared on end.
        val f9 = w.inState("d38-f9", "active")
        check("D38/F9 floor held in active, cleared when the session ends",
            w.sessions.grantFloor(f9, "host1", "user1") &&
                w.sessions.participant(f9, "user1")?.floor == "holds" &&
                w.sessions.endSession(f9, "host1") &&
                w.sessions.participants(f9).none { it.floor == "holds" })

        // F7: recording is a host act in attended sessions.
        val f7 = w.inState("d38-f7", "active")
        check("D38/F7 a controller participant cannot toggle recording in an attended session",
            !w.sessions.setRecording(f7, "user1", "video", "/data/deskguest/x.mp4") &&
                w.sessions.session(f7)?.recording == "none")
        check("D38/F7 the host CAN set recording",
            w.sessions.setRecording(f7, "host1", "video", "/data/deskguest/x.mp4") &&
                w.sessions.session(f7)?.isRecording == true)
        check("D38/F10 pausing stops the derived recording signal (active-only derivation)",
            w.sessions.pauseSession(f7, "host1") && w.sessions.session(f7)?.isRecording == false)

        // F5: remote-ref forms.
        check("D38/F5 UNC paths, file://host and cloud content: providers are remote; local forms are not",
            SessionStore.isRemoteRef("\\\\server\\share\\r.mp4") &&
                SessionStore.isRemoteRef("file://nas.example.com/r.mp4") &&
                SessionStore.isRemoteRef("content://com.google.android.apps.docs.storage/r.mp4") &&
                !SessionStore.isRemoteRef("file:///storage/emulated/0/r.mp4") &&
                !SessionStore.isRemoteRef("file://localhost/storage/r.mp4") &&
                !SessionStore.isRemoteRef("content://media/external/video/42") &&
                !SessionStore.isRemoteRef("/data/deskguest/r.mp4") &&
                !SessionStore.isRemoteRef("C:\\Recordings\\r.mp4"))
        check("D38/F5 a UNC recording ref is refused at creation",
            !w.sessions.createSession(
                SessionStore.Session(
                    "unc1", "co", w.hostDeviceId, "user1", "attended",
                    transportRung = "lan", recording = "video", recordingRef = "\\\\server\\share\\r.mp4"
                ), "host1"
            ))

        // F12: ids with control characters refused; chat text round-trips exactly.
        check("D38/F12 a session id containing a tab is refused at creation",
            !w.sessions.createSession(
                SessionStore.Session("bad\tid", "co", w.hostDeviceId, "user1", "attended", transportRung = "lan"),
                "host1"
            ))
        check("setup: chat with tab + newline + backslash for the roundtrip",
            w.sessions.sendChat(f7, "user1", "a\tb\nc\\d"))
    }

    // F3: a participant offboarded mid-session ends it at the NEXT act of any kind.
    run {
        val w = World(dir, "d38-f3")
        w.roster.addUser(RosterStore.User("admin2", "co", "Admin Two", "human"))
        w.roster.addCompanyAdmin("co", "admin2", actorUserId = "admin1")
        val id = w.inState("f3-live", "active")
        check("setup: user2 joins f3-live", w.sessions.addParticipant(id, "host1", "user2", "controller"))
        check("setup: user2 is offboarded", w.roster.removeUser("co", "user2", "admin1", stepUp = false).fired)
        check("D38/F3 chat by a CLEAN participant still ends the session — a gone participant is found at the act",
            !w.sessions.sendChat(id, "user1", "anyone there?") &&
                w.sessions.session(id)?.state == "ended" &&
                w.sessions.session(id)?.endReason == "participant_removed")
        val id2 = w.inState("f3-live2", "active")
        check("setup: ai1 joins f3-live2 and is granted the floor",
            w.sessions.addParticipant(id2, "host1", "ai1", "controller") &&
                w.sessions.grantFloor(id2, "host1", "ai1"))
        check("setup: ai1 suspended mid-session (admin act)",
            w.roster.setUserSuspended("co", "ai1", true, "admin1"))
        check("D38/F3 the suspended AI floor-holder's session ends at the next floor act; the floor is gone",
            !w.sessions.grantFloor(id2, "host1", "user1") &&
                w.sessions.session(id2)?.state == "ended" &&
                w.sessions.participants(id2).none { it.floor == "holds" })
    }

    // F7 (unattended half): added controllers need the use right.
    run {
        val w = World(dir, "d38-f7u")
        check("setup: unattended session by user1, started",
            w.unattended("u-add") && w.sessions.startSession("u-add", "user1"))
        check("D38/F7 unattended: the initiator cannot add a controller who lacks the use right",
            !w.sessions.addParticipant("u-add", "user1", "user3", "controller"))
        check("D38/F7 unattended: the initiator CAN add a controller who holds the use right",
            w.sessions.addParticipant("u-add", "user1", "user2", "controller"))
        check("D38/F7 unattended: the initiator (not just the host) can set recording",
            w.sessions.setRecording("u-add", "user1", "video", "/data/deskguest/u.mp4"))
    }

    // F8: resume re-checks grant + device.
    run {
        val w = World(dir, "d38-f8")
        check("setup: unattended session started + paused",
            w.unattended("u-rev") && w.sessions.startSession("u-rev", "user1") &&
                w.sessions.pauseSession("u-rev", "user1"))
        check("setup: admin revokes the use grant",
            w.roster.addGrant(RosterStore.Grant("co", "ug1", "dg1", setOf("enroll")), "admin1"))
        check("D38/F8 resuming a paused unattended session whose grant was revoked ENDS it (grant_revoked)",
            !w.sessions.startSession("u-rev", "user1") &&
                w.sessions.session("u-rev")?.state == "ended" &&
                w.sessions.session("u-rev")?.endReason == "grant_revoked")
        check("setup: grant restored; fresh unattended session started + paused",
            w.roster.addGrant(RosterStore.Grant("co", "ug1", "dg1", setOf("use")), "admin1") &&
                w.unattended("u-dev") && w.sessions.startSession("u-dev", "user1") &&
                w.sessions.pauseSession("u-dev", "user1"))
        check("setup: host device revoked", w.enrollment.revoke(w.hostDeviceId))
        check("D38/F8 resuming against a REVOKED host device ends the session (device_revoked)",
            !w.sessions.startSession("u-dev", "user1") &&
                w.sessions.session("u-dev")?.state == "ended" &&
                w.sessions.session("u-dev")?.endReason == "device_revoked")
    }

    // F5/F9/F12 load-time behavior on hand-written files.
    run {
        val w = World(dir, "d38-load")
        val file = File(dir, "d38-load-sessions.tsv")
        file.writeText(
            listOf(
                "session\th1\tco\t${w.hostDeviceId}\tuser1\tattended\tactive\t1700000000000\t\tlan\tvideo\thttps://cloud.example.com/x.mp4\thost1\t",
                "participant\th1\thost1\thost\tholds",
                "participant\th1\tuser1\tcontroller\tholds",
                "chat\th1\tuser1\t1700000001000\ta\\tb\\nc\\\\d"
            ).joinToString("\n")
        )
        val loaded = SessionStore(file, w.roster, w.enrollment) { tick() }
        check("D38/F5 load() re-validates RecordingRef: a remote ref in the file is dropped",
            loaded.session("h1") != null && loaded.session("h1")?.recordingRef == null)
        check("D38/F9 load() keeps at most ONE floor holder per session",
            loaded.participants("h1").count { it.floor == "holds" } == 1 &&
                loaded.participants("h1").first { it.floor == "holds" }.userId == "host1")
        check("D38/F12 escaped chat text round-trips byte-identically (tab, newline, backslash)",
            loaded.chatMessages("h1").singleOrNull()?.text == "a\tb\nc\\d")
        check("D38/F6 no .tmp file is left behind by session saves",
            !File(dir, "d38-sessions.tsv.tmp").exists())
    }

    // ================= RULING 2026-11-19 — endpoint-local acceptance =================
    run {
        val w = World(dir, "ruling-accept")
        check("setup: attended session for the ruling checks", w.attended("acc1"))
        check("RULING accept: the host accepting via the INITIATING CHANNEL refuses — no accept recorded, session stays requested",
            !w.sessions.acceptSession("acc1", "host1", SessionStore.ACCEPT_ORIGIN_INITIATING_CHANNEL) &&
                w.sessions.session("acc1")?.acceptBy == null &&
                w.sessions.session("acc1")?.acceptOrigin == null &&
                w.sessions.session("acc1")?.state == "requested")
        check("RULING accept: the refused channel attempt is in the audit record as accept_refused (distinct from a local accept)",
            w.sessions.events("acc1").any {
                it.type == SessionStore.EVENT_ACCEPT_REFUSED && it.actorUserId == "host1"
            } && w.sessions.events("acc1").none { it.type == "accepted" })
        check("RULING accept: after a channel refusal the session still cannot start",
            !w.sessions.startSession("acc1", "user1") && w.sessions.session("acc1")?.state == "requested")
        check("RULING accept: an unknown origin refuses the same way",
            !w.sessions.acceptSession("acc1", "host1", "smoke-signal") &&
                w.sessions.session("acc1")?.acceptBy == null)
        check("RULING accept: the host accepting at the endpoint's LOCAL UI succeeds; record + event say 'at <device>, locally'",
            w.sessions.acceptSession("acc1", "host1", SessionStore.ACCEPT_ORIGIN_LOCAL_UI) &&
                w.sessions.session("acc1")?.acceptBy == "host1" &&
                w.sessions.session("acc1")?.acceptOrigin == SessionStore.ACCEPT_ORIGIN_LOCAL_UI &&
                w.sessions.events("acc1").any {
                    it.type == "accepted" && it.actorUserId == "host1" &&
                        it.detail.contains(w.hostDeviceId) && it.detail.contains("locally")
                })
        check("RULING accept: after the local accept the attended session starts",
            w.sessions.startSession("acc1", "user1") && w.sessions.session("acc1")?.state == "active")

        // A stored accept with no local origin (legacy 14-field line)
        // is repaired to unaccepted at load — consent cannot be
        // smuggled in through the file.
        val legacyFile = File(dir, "ruling-legacy-sessions.tsv")
        legacyFile.writeText(
            listOf(
                "session\tleg1\tco\t${w.hostDeviceId}\tuser1\tattended\trequested\t1700000000000\t\tlan\tnone\t\thost1\t",
                "participant\tleg1\thost1\thost\twatching",
                "participant\tleg1\tuser1\tcontroller\twatching"
            ).joinToString("\n")
        )
        val legacy = SessionStore(legacyFile, w.roster, w.enrollment) { tick() }
        check("RULING accept: a stored acceptBy with NO local origin loads as UNACCEPTED and cannot start",
            legacy.session("leg1") != null && legacy.session("leg1")?.acceptBy == null &&
                legacy.session("leg1")?.acceptOrigin == null &&
                !legacy.startSession("leg1", "user1") &&
                legacy.session("leg1")?.state == "requested")
        check("RULING accept: the repaired session accepts locally and starts",
            legacy.acceptSession("leg1", "host1", SessionStore.ACCEPT_ORIGIN_LOCAL_UI) &&
                legacy.startSession("leg1", "user1") && legacy.session("leg1")?.state == "active")
    }

    // RULING 2026-11-19 — one-user PERSONAL scope: the sole user is
    // both initiator and host; locality is the consent guarantee.
    run {
        val enrollment = EnrollmentStore(File(dir, "ruling-pers-enroll.tsv"))
        val roster = RosterStore(File(dir, "ruling-pers-roster.tsv"), enrollment)
        roster.addScope(RosterStore.Scope("me", "personal", "My Devices"))
        roster.addUser(RosterStore.User("owner", "me", "Owner", "human"))
        roster.addCompanyAdmin("me", "owner")
        roster.addUserGroup(
            RosterStore.UserGroup("ug-me", "me", "Mine", memberUserIds = setOf("owner")), "owner"
        )
        roster.addDeviceGroup(
            RosterStore.DeviceGroup("dg-me", "me", "Home Fleet", listOf("lan", "hub")), "owner"
        )
        roster.addGrant(RosterStore.Grant("me", "ug-me", "dg-me", setOf("use")), "owner")
        val identity = DeviceIdentity.generate()
        val code = enrollment.mint("personal", "dg-me", "Home Fleet")
        enrollment.redeem(
            code, EnrollmentStore.EnrollingDevice(identity.deviceId, identity.publicKeyBase64, "My Phone")
        )
        val sessions = SessionStore(File(dir, "ruling-pers-sessions.tsv"), roster, enrollment) { tick() }
        check("RULING personal: a one-user personal scope CAN create a self-session (initiator == host == sole owner)",
            sessions.createSession(
                SessionStore.Session(
                    "self-p", "me", identity.deviceId, "owner", "attended", transportRung = "lan"
                ),
                hostUserId = "owner"
            ) && sessions.session("self-p")?.state == "requested" &&
                sessions.participants("self-p").map { it.userId to it.role } == listOf("owner" to "host"))
        check("RULING personal: even in a personal scope, a CHANNEL accept refuses",
            !sessions.acceptSession("self-p", "owner", SessionStore.ACCEPT_ORIGIN_INITIATING_CHANNEL) &&
                sessions.session("self-p")?.acceptBy == null &&
                !sessions.startSession("self-p", "owner"))
        check("RULING personal: the same sole user accepting at the endpoint's LOCAL UI works and the session starts",
            sessions.acceptSession("self-p", "owner", SessionStore.ACCEPT_ORIGIN_LOCAL_UI) &&
                sessions.startSession("self-p", "owner") &&
                sessions.session("self-p")?.state == "active")
        check("RULING personal: the unattended path is unchanged — grant checked at creation, no accept involved",
            sessions.createSession(
                SessionStore.Session(
                    "self-u", "me", identity.deviceId, "owner", "unattended", transportRung = "lan"
                ),
                hostUserId = "owner"
            ) && sessions.startSession("self-u", "owner") &&
                sessions.session("self-u")?.acceptBy == null)
    }

    dir.deleteRecursively()
    println(if (failures == 0) "ALL SESSION TESTS PASSED" else "$failures SESSION TEST(S) FAILED")
    if (failures > 0) kotlin.system.exitProcess(1)
}
