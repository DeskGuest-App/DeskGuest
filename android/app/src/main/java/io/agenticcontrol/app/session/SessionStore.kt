package io.agenticcontrol.app.session

import io.agenticcontrol.app.enrollment.EnrollmentStore
import io.agenticcontrol.app.roster.RosterStore
import java.io.File

/**
 * Human session model (Slice 3): sessions as first-class records —
 * consent gates, participants + floor control (D35 model half),
 * the offboarding hook discharging Slice 2's named requirement,
 * the append-only event list that is the structured replay's data
 * source (D36 form 2), the video-recording flag + local storage
 * reference (D36 form 1), session chat, and file-transfer jobs.
 *
 * This is the MODEL layer: no media transport, no streaming.
 * Live surfaces DO read it (bd-and-core F12, 2026-11-22): the
 * platform session tools list it, and the presence layer renders
 * a non-hideable badge derived from a live record's recording /
 * blanked / input-blocked state (PlatformStores.liveSessionBadges
 * -> PresenceOverlay.sessionBadgeProvider). What remains unbuilt
 * is any media path itself — no frames, no call audio, no file
 * bytes move through this record, and nothing here claims they do.
 *
 * Discipline follows the established stores: every public entry
 * point is serialized on this store's monitor (@Synchronized);
 * persistence is one TSV file with type-tagged lines; corrupt
 * lines are skipped on load, never fatal; string fields are
 * TSV-sanitised; the file holds ids, names and state only — no
 * reusable password, token, seed, or any other secret (D22).
 *
 * State machine — a CLOSED set, enforced on every transition;
 * anything outside it refuses and changes nothing:
 *   requested -> active | ended
 *   active    -> paused | blocked | ended
 *   paused    -> active | blocked | ended
 *   blocked   -> ended            (ONLY — see below)
 *   ended     -> (terminal)
 * `blocked` has exactly one outgoing edge. The 2026-11-17 STOP
 * trap — a session left alive in `blocked` because the only UI
 * path out was itself blocked — is structurally impossible here:
 * from `blocked` the host's clear path IS ending the session, and
 * the model offers no other edge to get stuck on. Content acts
 * (floor, chat, file jobs, participant changes) also refuse in
 * `blocked`, so nothing can keep a blocked session busy.
 *
 * STOP: [stopSession] is a host-side act that works from EVERY
 * non-ended state: it records `blocked`, then `stopped`, then ends
 * the session with reason `host_stop`. There is no state in which
 * a session is alive but unstoppable.
 *
 * Endpoint-local acceptance (RULING 2026-11-19): an attended
 * session's accept is honored ONLY when it originates from the
 * endpoint host's local UI ([acceptSession]'s origin parameter);
 * accepts arriving over the initiating channel refuse in every
 * scope, and the event record says so. In a personal scope the
 * sole user may be both initiator and host — locality, not a
 * second person, is the consent guarantee there.
 *
 * Offboarding hook (Slice 2's named requirement, discharged):
 * creating a session, starting one, and every state transition
 * RE-READ the roster — the initiator and every participant are
 * checked against the roster's current user records AND its
 * offboarding event list. A removed or suspended user can never
 * initiate; if one is found on a live session the session is
 * ended with reason `participant_removed`. [enforceOffboarding]
 * exposes the same check as a direct hook for the layer that
 * watches roster events.
 *
 * Recording (D36): [Session.recording] is a flag on the record and
 * [Session.isRecording] is DERIVED from it — there is no separate
 * stored visibility boolean that could disagree, so an active
 * session with Recording != none always exposes that it is
 * recording; covert recording is unrepresentable. A
 * [Session.recordingRef] must be a local path/uri (plain path,
 * file: or content: uri); any remote-looking reference (another
 * scheme, a protocol-relative //host path) is refused.
 *
 * Lock order (D38 S3-AND F12): this store's monitor is the OUTER
 * lock. Methods here call into RosterStore / EnrollmentStore
 * (which take their own monitors) while holding it — session ->
 * roster/enrollment, NEVER the reverse. A roster-event watcher
 * must therefore invoke [enforceOffboarding] WITHOUT holding the
 * roster monitor, or the two stores can deadlock in opposite
 * lock order.
 */
class SessionStore(
    private val storeFile: File,
    private val rosterStore: RosterStore,
    private val enrollmentStore: EnrollmentStore,
    /** TOTAL POLICY CONTROL gates for the Block G surfaces
     *  (enterprise PolicyFeatures keys). Null = no policy loaded
     *  (the owner's own device — the same posture as the Windows
     *  store and SecondFactorStore's gate). They sit BEFORE the
     *  clock so every existing trailing-lambda call site keeps
     *  binding to clockMs. */
    private val featureGate: ((String, String) -> Boolean)? = null,
    private val featureRequired: ((String, String) -> Boolean)? = null,
    private val clockMs: () -> Long = { System.currentTimeMillis() }
) {

    /** SCOPE-AWARE gates (scopeId, featureKey): a policy bundle
     *  governs only its own scope (D38-G review F2). */
    private fun featureAllowed(scopeId: String, featureKey: String): Boolean =
        featureGate?.invoke(scopeId, featureKey) ?: true

    private fun featureIsRequired(scopeId: String, featureKey: String): Boolean =
        featureRequired?.invoke(scopeId, featureKey) ?: false

    // ---- records ----

    /** Slice 3 session record. [startedUtc] is the creation time;
     *  [endedUtc] is null until the session ends. [acceptBy] and
     *  [endReason] are model extensions the spec's consent/STOP
     *  clauses require to be recorded (accept as an event AND on
     *  the record; the end reason names host_stop /
     *  participant_removed / ended). */
    data class Session(
        val id: String,
        val scopeId: String,
        val hostDeviceId: String,
        val initiatorUserId: String,
        val kind: String,
        val state: String = STATE_REQUESTED,
        val startedUtc: Long = 0L,
        val endedUtc: Long? = null,
        val transportRung: String,
        val recording: String = RECORDING_NONE,
        val recordingRef: String? = null,
        val acceptBy: String? = null,
        val endReason: String? = null,
        /** RULING 2026-11-19 (endpoint-local acceptance): WHERE
         *  the accept happened — [ACCEPT_ORIGIN_LOCAL_UI] is the
         *  only origin an accept may carry. A stored accept with
         *  any other (or no) origin is not an accept: load()
         *  clears it and the start gate refuses it. */
        val acceptOrigin: String? = null,
        /** Block G session-surface flags (G-02/G-03/G-07). Each
         *  is a flag ON this record for the same reason recording
         *  is: the state must be derivable from the record itself,
         *  so the host screen cannot be blanked, local input
         *  blocked, or the stream watermarked without the record —
         *  and therefore the presence layer, which reads this
         *  record — saying so. All three clear on session end. */
        val blanked: Boolean = false,
        val inputBlocked: Boolean = false,
        val watermarked: Boolean = false
    ) {
        /** D36: derived, never stored — a session whose recording
         *  flag is set IS recording exactly while it is ACTIVE, and
         *  there is no field by which that could be hidden.
         *  D38 S3-AND F10: `requested` (not yet consented) and
         *  `blocked`/`paused` sessions are NOT recording — the flag
         *  on a requested session is a request to record, and the
         *  derived signal must not claim capture before the host
         *  has consented and the session is live. */
        val isRecording: Boolean
            get() = recording != RECORDING_NONE && state == STATE_ACTIVE
    }

    /** D35 model half: a participant of a session. At most one
     *  participant per session has [floor] == [FLOOR_HOLDS] at any
     *  moment (enforced atomically by [grantFloor]). */
    data class Participant(
        val sessionId: String,
        val userId: String,
        val role: String,
        val floor: String = FLOOR_WATCHING
    )

    /** One entry of a session's append-only event list — the
     *  structured replay's data source (D36 form 2). Events are
     *  never edited or removed by any API in this store. */
    data class SessionEvent(
        val atMs: Long,
        val sessionId: String,
        val type: String,
        val actorUserId: String,
        val detail: String
    )

    /** Session chat: senders must be participants of the session. */
    data class ChatMessage(
        val sessionId: String,
        val senderUserId: String,
        val utc: Long,
        val text: String
    )

    /** File-transfer job (model half). Progress is monotonic and
     *  `done` requires TransferredBytes == SizeBytes. */
    data class FileJob(
        val id: String,
        val sessionId: String,
        val direction: String,
        val name: String,
        val sizeBytes: Long,
        val transferredBytes: Long = 0L,
        val state: String = JOB_QUEUED
    )

    /** In-session voice/video call (Block G, G-05). The model
     *  carries the call's signaling state only — ringing | active
     *  | ended — between participants of ONE session; the media
     *  leg is a platform surface, never claimed by this record.
     *  A call lives and dies inside its session: the session-end
     *  and session-block cascades end it. */
    data class SessionCall(
        val id: String,
        val sessionId: String,
        val kind: String,
        val state: String = CALL_RINGING,
        val initiatorUserId: String,
        val startedUtc: Long,
        val answeredUtc: Long? = null,
        val endedUtc: Long? = null
    )

    // ---- state ----

    private val sessions = mutableListOf<Session>()
    private val participantsBySession = mutableMapOf<String, MutableList<Participant>>()
    private val eventList = mutableListOf<SessionEvent>()
    private val chatList = mutableListOf<ChatMessage>()
    private val jobs = mutableListOf<FileJob>()
    private val calls = mutableListOf<SessionCall>()

    init {
        load()
    }

    // ---- queries ----

    @Synchronized
    fun session(sessionId: String): Session? = sessions.firstOrNull { it.id == sessionId }

    @Synchronized
    fun sessionsInScope(scopeId: String): List<Session> = sessions.filter { it.scopeId == scopeId }

    @Synchronized
    fun participants(sessionId: String): List<Participant> =
        participantsBySession[sessionId]?.toList() ?: emptyList()

    @Synchronized
    fun participant(sessionId: String, userId: String): Participant? =
        participantsBySession[sessionId]?.firstOrNull { it.userId == userId }

    /** The session's append-only event list, in recorded order. */
    @Synchronized
    fun events(sessionId: String): List<SessionEvent> = eventList.filter { it.sessionId == sessionId }

    @Synchronized
    fun chatMessages(sessionId: String): List<ChatMessage> = chatList.filter { it.sessionId == sessionId }

    @Synchronized
    fun fileJobs(sessionId: String): List<FileJob> = jobs.filter { it.sessionId == sessionId }

    @Synchronized
    fun fileJob(sessionId: String, jobId: String): FileJob? =
        jobs.firstOrNull { it.sessionId == sessionId && it.id == jobId }

    /** Block G (G-05): the session's calls, in start order. */
    @Synchronized
    fun calls(sessionId: String): List<SessionCall> = calls.filter { it.sessionId == sessionId }

    /** The session's live (ringing/active) call, if any — at
     *  most one exists, enforced at start. */
    @Synchronized
    fun liveCall(sessionId: String): SessionCall? =
        calls.firstOrNull { it.sessionId == sessionId && (it.state == CALL_RINGING || it.state == CALL_ACTIVE) }

    /** D36: recording state derivable from the record at all times. */
    @Synchronized
    fun isRecording(sessionId: String): Boolean = session(sessionId)?.isRecording == true

    // ---- creation ----

    /**
     * Create a session in `requested`. The record's state /
     * endedUtc / acceptBy / endReason are forced to their initial
     * values — a caller cannot mint a session already active or
     * already accepted.
     *
     * Refuses (returns false, records nothing): blank or duplicate
     * id; unknown scope; host device unknown, revoked, or not a
     * member of a device group in this scope; [hostUserId] not a
     * human user of the scope, or suspended/removed; initiator not
     * a user of the scope, or removed/suspended (offboarding hook:
     * a removed user can NEVER initiate, a suspended AI can never
     * initiate); unknown kind or recording value; a remote-looking
     * recording reference; a transport rung outside the host
     * device's EffectiveTransports (Slice 2 resolution); and, for
     * `unattended`, an initiator without the `use` right on the
     * host's device group (checked again at activation).
     *
     * On success the host user joins as the `host` participant and
     * the initiator (when different) as a `controller`, both
     * watching; `created` + `participant_added` events are recorded.
     */
    @Synchronized
    fun createSession(session: Session, hostUserId: String): Boolean {
        if (session.id.isBlank() || sessions.any { it.id == session.id }) return false
        // D38 S3-AND F12: ids ride TSV lines — control characters in
        // an id are refused at creation rather than silently
        // rewritten on save (all other text is backslash-escaped).
        if (session.id.any { it == '\t' || it == '\n' || it == '\r' }) return false
        // D38 S3-AND F1: the host is the person AT the host device;
        // an initiator naming THEMSELVES as host could accept their
        // own attended session on someone else's device — refused
        // in company scopes. RULING 2026-11-19 exception: in a
        // PERSONAL scope the sole user legitimately initiates to
        // their own device (a one-user scope has no second person
        // to be the host); what protects that case is not a
        // second person but the endpoint-local acceptance rule —
        // the accept must still originate from the endpoint's own
        // local UI (see acceptSession), never the channel.
        // (Binding hostUserId to the device's owner record needs an
        // owner field Slice 1/2 do not carry — named as a spec gap
        // in the D38 reconciliation report.)
        val scopeRecord = rosterStore.scope(session.scopeId) ?: return false
        if (session.initiatorUserId == hostUserId &&
            scopeRecord.kind != RosterStore.SCOPE_PERSONAL
        ) return false
        val kind = session.kind.trim().lowercase()
        if (kind !in KINDS) return false
        val recording = session.recording.trim().lowercase()
        if (recording !in RECORDINGS) return false
        val ref = session.recordingRef?.takeIf { it.isNotBlank() }
        if (ref != null && isRemoteRef(ref)) return false
        if (recording == RECORDING_NONE && ref != null) return false

        val hostDevice = enrollmentStore.byId(session.hostDeviceId) ?: return false
        if (hostDevice.revoked) return false
        if (session.hostDeviceId !in rosterStore.deviceGroupMemberIds(session.scopeId, hostDevice.groupId)) {
            return false
        }
        val rung = session.transportRung.trim().lowercase()
        val effective = rosterStore.effectiveTransportsFor(session.scopeId, session.hostDeviceId)
            ?: return false
        if (rung !in effective) return false

        val hostUser = rosterStore.user(hostUserId) ?: return false
        if (hostUser.scopeId != session.scopeId || hostUser.kind != RosterStore.USER_HUMAN) return false
        if (isGone(session.scopeId, hostUserId)) return false
        val initiator = rosterStore.user(session.initiatorUserId) ?: return false
        if (initiator.scopeId != session.scopeId) return false
        if (isGone(session.scopeId, session.initiatorUserId)) return false
        if (kind == KIND_UNATTENDED &&
            !rosterStore.canUse(session.scopeId, session.initiatorUserId, hostDevice.groupId)
        ) return false

        val created = session.copy(
            kind = kind,
            state = STATE_REQUESTED,
            startedUtc = if (session.startedUtc > 0) session.startedUtc else clockMs(),
            endedUtc = null,
            transportRung = rung,
            recording = recording,
            recordingRef = if (recording == RECORDING_NONE) null else ref,
            acceptBy = null,
            endReason = null,
            acceptOrigin = null
        )
        sessions.add(created)
        val parts = participantsBySession.getOrPut(created.id) { mutableListOf() }
        parts.add(Participant(created.id, hostUserId, ROLE_HOST, FLOOR_WATCHING))
        recordEvent(created.id, EVENT_CREATED, created.initiatorUserId, "kind=$kind rung=$rung")
        recordEvent(created.id, EVENT_PARTICIPANT_ADDED, created.initiatorUserId, "user=$hostUserId role=$ROLE_HOST")
        if (session.initiatorUserId != hostUserId) {
            parts.add(Participant(created.id, session.initiatorUserId, ROLE_CONTROLLER, FLOOR_WATCHING))
            recordEvent(
                created.id, EVENT_PARTICIPANT_ADDED, created.initiatorUserId,
                "user=${session.initiatorUserId} role=$ROLE_CONTROLLER"
            )
        }
        save()
        return true
    }

    // ---- consent: attended accept ----

    /**
     * Record the host-side accept of an `attended` session.
     *
     * RULING 2026-11-19 — ENDPOINT-LOCAL ACCEPTANCE: acceptance is
     * an endpoint-local act, not a second-person act. This method
     * honors ONLY an accept whose [origin] is
     * [ACCEPT_ORIGIN_LOCAL_UI] — an event the endpoint host's own
     * software generated from a local interaction at that device.
     * An accept arriving over the initiating channel
     * ([ACCEPT_ORIGIN_INITIATING_CHANNEL], or any other origin)
     * REFUSES in every scope; a genuine host attempt via the
     * channel is recorded as an `accept_refused` event so the
     * audit trail distinguishes "accepted at <device>, locally"
     * (the `accepted` event's detail) from a mere "accepted by
     * <user>" claim arriving over the wire. There is deliberately
     * no overload without an origin: a caller that cannot name a
     * local origin cannot accept.
     *
     * Only the session's host participant can accept, only while
     * `requested`, only once. The accept is recorded on the record
     * ([Session.acceptBy] + [Session.acceptOrigin]) AND as an
     * `accepted` event. An attended session cannot leave
     * `requested` without a local accept (see [transition]). The
     * unattended path is unchanged: no accept exists there; the
     * `use` grant is checked at creation and re-checked at every
     * entry into `active`.
     */
    @Synchronized
    fun acceptSession(sessionId: String, acceptByUserId: String, origin: String): Boolean {
        val index = sessions.indexOfFirst { it.id == sessionId }
        if (index < 0) return false
        val session = sessions[index]
        if (session.kind != KIND_ATTENDED) return false
        if (session.state != STATE_REQUESTED) return false
        if (session.acceptBy != null) return false
        if (participant(sessionId, acceptByUserId)?.role != ROLE_HOST) return false
        if (isGone(session.scopeId, acceptByUserId)) return false
        if (endIfParticipantGone(session)) return false // D38 F3
        if (origin != ACCEPT_ORIGIN_LOCAL_UI) {
            recordEvent(
                sessionId, EVENT_ACCEPT_REFUSED, acceptByUserId,
                "accept via initiating channel refused (origin=$origin)"
            )
            save()
            return false
        }
        sessions[index] = session.copy(acceptBy = acceptByUserId, acceptOrigin = ACCEPT_ORIGIN_LOCAL_UI)
        // AF6(d): from this act the acceptor is THE host — any
        // other host-role row (a forgery the load arbitration
        // could not distinguish) demotes to watcher now, while
        // the genuine acceptor is proven present and local.
        participantsBySession[sessionId]?.let { parts ->
            for (i in parts.indices) {
                if (parts[i].role == ROLE_HOST && parts[i].userId != acceptByUserId)
                    parts[i] = parts[i].copy(role = ROLE_WATCHER)
            }
        }
        recordEvent(
            sessionId, EVENT_ACCEPTED, acceptByUserId,
            "accepted at ${session.hostDeviceId}, locally"
        )
        save()
        return true
    }

    // ---- state transitions ----

    /**
     * The one generic state-transition entry point. Enforces the
     * closed transition set; an illegal transition refuses and
     * changes NOTHING (no state change, no event, no timestamp).
     *
     * Before any non-ending transition the offboarding hook
     * re-reads the roster: if the initiator or any participant has
     * been removed/suspended, the requested transition is refused
     * and the session is ended with reason `participant_removed`
     * instead. Ending is always permitted by the set, so the hook
     * never fires on an explicit end.
     *
     * Gates on entering `active` from `requested` (the start):
     * attended requires a recorded host accept; unattended
     * re-checks the initiator's `use` right on the host's device
     * group against the roster at start time.
     */
    @Synchronized
    fun transition(sessionId: String, toState: String, actorUserId: String, reason: String? = null): Boolean {
        val index = sessions.indexOfFirst { it.id == sessionId }
        if (index < 0) return false
        val session = sessions[index]
        val target = toState.trim().lowercase()
        if (target !in STATES) return false
        if (target !in (TRANSITIONS[session.state] ?: emptySet())) return false
        // D38 S3-AND F2: the actor is AUTHORIZED, not just recorded.
        // The actor must be a live (not removed/suspended) host or
        // controller participant, or a company admin of the scope.
        // Watchers, non-participants, removed users and arbitrary
        // strings can drive nothing. Entering `active` is narrower
        // still: host participant, initiator, or company admin.
        if (isGone(session.scopeId, actorUserId)) return false
        val actorPart = participant(sessionId, actorUserId)
        val actorIsAdmin = rosterStore.isCompanyAdmin(session.scopeId, actorUserId)
        if (!actorIsAdmin && (actorPart == null || actorPart.role == ROLE_WATCHER)) return false
        if (target == STATE_ACTIVE && !actorIsAdmin &&
            actorPart?.role != ROLE_HOST && actorUserId != session.initiatorUserId
        ) return false
        if (target == STATE_ENDED) {
            endInternal(index, actorUserId, reason ?: REASON_ENDED)
            save()
            return true
        }
        val gone = goneParticipant(session)
        if (gone != null) {
            endInternal(index, gone, REASON_PARTICIPANT_REMOVED, goneUserId = gone)
            save()
            return false
        }
        if (target == STATE_ACTIVE) {
            // TOTAL POLICY CONTROL, required half (G-07): when
            // policy requires the watermark, a session may not
            // START unwatermarked (the flag is settable from
            // `requested` precisely so this gate can be met) —
            // and may not RESUME unwatermarked either (D38-G
            // review F8: the trap guards every entry into active
            // from a non-live state, exactly as on Windows).
            if ((session.state == STATE_REQUESTED || session.state == STATE_PAUSED) &&
                featureIsRequired(session.scopeId, io.agenticcontrol.app.enterprise.PolicyFeatures.WATERMARK) &&
                !session.watermarked
            ) return false
            // D38 S3-AND F8: EVERY entry into active re-checks the
            // authorization it runs under — not just the first start.
            val hostDevice = enrollmentStore.byId(session.hostDeviceId) ?: return false
            if (hostDevice.revoked) {
                endInternal(index, actorUserId, REASON_DEVICE_REVOKED)
                save()
                return false
            }
            val effective = rosterStore.effectiveTransportsFor(session.scopeId, session.hostDeviceId)
            if (effective == null || session.transportRung !in effective) return false
            if (session.kind == KIND_UNATTENDED &&
                !rosterStore.canUse(session.scopeId, session.initiatorUserId, hostDevice.groupId)
            ) {
                if (session.state == STATE_PAUSED) {
                    // A live session whose grant was revoked does
                    // not outlive its authorization.
                    endInternal(index, actorUserId, REASON_GRANT_REVOKED)
                    save()
                }
                return false
            }
            if (session.state == STATE_REQUESTED) {
                // RULING 2026-11-19: the start gate honors only an
                // ENDPOINT-LOCAL accept — an acceptBy with any other
                // (or no) recorded origin is not consent.
                if (session.kind == KIND_ATTENDED &&
                    (session.acceptBy == null || session.acceptOrigin != ACCEPT_ORIGIN_LOCAL_UI)
                ) return false
            }
        }
        sessions[index] = session.copy(state = target)
        if (target == STATE_BLOCKED) clearFloors(sessionId) // D38 F9
        when (target) {
            STATE_ACTIVE -> recordEvent(sessionId, EVENT_STARTED, actorUserId,
                if (session.state == STATE_PAUSED) "resumed" else "started")
            STATE_PAUSED -> recordEvent(sessionId, EVENT_PAUSED, actorUserId, "paused")
            STATE_BLOCKED -> recordEvent(sessionId, EVENT_BLOCKED, actorUserId, "blocked")
        }
        // G-03: the input block exists only while input flows
        // (active). Pausing releases it — the record never claims
        // a block over a frozen session.
        if (target == STATE_PAUSED && sessions[index].inputBlocked) {
            sessions[index] = sessions[index].copy(inputBlocked = false)
            recordEvent(sessionId, EVENT_INPUT_BLOCK_CLEARED, actorUserId, "input block released by pause")
        }
        // G-05: blocked is stopped-pending-end and no content
        // flows through it — a live call ends with the block.
        if (target == STATE_BLOCKED) endLiveCalls(sessionId, actorUserId, "call ended by session block")
        // AF8: blocked is not a live state for the G-02/G-03
        // surfaces either — the blank and the input block release
        // with the block, so the live record and the reloaded
        // record agree (the loader drops both for blocked).
        if (target == STATE_BLOCKED) {
            val cur = sessions[index]
            if (cur.blanked || cur.inputBlocked) {
                sessions[index] = cur.copy(blanked = false, inputBlocked = false)
                if (cur.blanked) recordEvent(sessionId, EVENT_BLANK_CLEARED, actorUserId,
                    "privacy blank released by session block")
                if (cur.inputBlocked) recordEvent(sessionId, EVENT_INPUT_BLOCK_CLEARED, actorUserId,
                    "input block released by session block")
            }
        }
        save()
        return true
    }

    /** Start = requested -> active (consent gates in [transition]). */
    @Synchronized
    fun startSession(sessionId: String, actorUserId: String): Boolean =
        transition(sessionId, STATE_ACTIVE, actorUserId)

    @Synchronized
    fun pauseSession(sessionId: String, actorUserId: String): Boolean =
        transition(sessionId, STATE_PAUSED, actorUserId)

    @Synchronized
    fun blockSession(sessionId: String, actorUserId: String): Boolean =
        transition(sessionId, STATE_BLOCKED, actorUserId)

    /** End from any non-ended state (the set permits ended from
     *  every live state, including blocked). */
    @Synchronized
    fun endSession(sessionId: String, actorUserId: String, reason: String = REASON_ENDED): Boolean =
        transition(sessionId, STATE_ENDED, actorUserId, reason)

    /**
     * STOP (host-side): from ANY state except `ended`, moves the
     * session through `blocked` and immediately to `ended` with
     * reason `host_stop`, recording blocked + stopped + ended
     * events in that order. The actor must be the session's host
     * participant or a company admin of the scope. STOP always
     * terminates — it is not subject to the offboarding hook or
     * any consent gate.
     */
    @Synchronized
    fun stopSession(sessionId: String, actorUserId: String): Boolean {
        val index = sessions.indexOfFirst { it.id == sessionId }
        if (index < 0) return false
        val session = sessions[index]
        if (session.state == STATE_ENDED) return false
        if (!isHostActor(session, actorUserId)) return false
        // D38 S3-AND F6: STOP must never be "ended in memory, alive
        // on disk". Snapshot first; if persistence fails, roll the
        // in-memory state back and let the failure surface.
        val sessionBefore = sessions[index]
        val jobsBefore = jobs.map { it.copy() }
        val callsBefore = calls.map { it.copy() }
        val partsBefore = participantsBySession[sessionId]?.map { it.copy() }
        val eventsBefore = eventList.size
        try {
            if (session.state != STATE_BLOCKED) {
                recordEvent(sessionId, EVENT_BLOCKED, actorUserId, "blocked by stop")
            }
            recordEvent(sessionId, EVENT_STOPPED, actorUserId, "host stop")
            endInternal(index, actorUserId, REASON_HOST_STOP, emitEndedEvent = true)
            save()
        } catch (e: Exception) {
            sessions[index] = sessionBefore
            jobs.clear(); jobs.addAll(jobsBefore)
            calls.clear(); calls.addAll(callsBefore)
            if (partsBefore != null) {
                participantsBySession[sessionId] = partsBefore.toMutableList()
            }
            while (eventList.size > eventsBefore) eventList.removeAt(eventList.size - 1)
            throw e
        }
        return true
    }

    /**
     * bd-and-rest F2 fix (2026-11-22): the LOCAL-origin STOP — the
     * person holding THIS device pressing STOP on its own screen.
     * STOP outranks every actor check by product law: it resolves
     * the session's host participant from the record itself and
     * stops as that host, so it can never come back refused because
     * a typed actor field was blank or wrong. False ONLY when the
     * session is unknown, already ended, or has no host participant
     * (a corrupt record — in which case there is no consent state
     * left to protect and the refusal is honest). Every other STOP
     * path ([stopSession]) keeps its host/admin gate unchanged.
     */
    @Synchronized
    fun stopLocalSession(sessionId: String): Boolean {
        val session = session(sessionId) ?: return false
        if (session.state == STATE_ENDED) return false
        val hostUserId = participantsBySession[sessionId]
            ?.firstOrNull { it.role == ROLE_HOST }?.userId ?: return false
        return stopSession(sessionId, hostUserId)
    }

    // ---- offboarding hook ----

    /**
     * Direct hook for the layer watching roster events: re-reads
     * the roster NOW; if the initiator or any participant of a
     * live session has been removed/suspended, ends the session
     * with reason `participant_removed` and returns true. Returns
     * false when the session is unknown, already ended, or clean.
     */
    @Synchronized
    fun enforceOffboarding(sessionId: String): Boolean {
        val index = sessions.indexOfFirst { it.id == sessionId }
        if (index < 0) return false
        val session = sessions[index]
        if (session.state == STATE_ENDED) return false
        val gone = goneParticipant(session) ?: return false
        endInternal(index, gone, REASON_PARTICIPANT_REMOVED, goneUserId = gone)
        save()
        return true
    }

    // ---- participants & floor (D35 model half) ----

    /**
     * Add a participant (floor always starts `watching` — the
     * floor is only ever taken via [grantFloor], atomically).
     * Actor must be the host participant, a company admin, or the
     * session initiator. Refused on ended/blocked sessions, for
     * duplicate participants, and for users who are unknown,
     * cross-scope, or removed/suspended.
     */
    @Synchronized
    fun addParticipant(sessionId: String, actorUserId: String, userId: String, role: String): Boolean {
        val session = session(sessionId) ?: return false
        if (session.state == STATE_ENDED || session.state == STATE_BLOCKED) return false
        if (endIfParticipantGone(session)) return false // D38 F3
        val normalizedRole = role.trim().lowercase()
        if (normalizedRole !in ROLES) return false
        if (normalizedRole == ROLE_HOST) return false // exactly one host, fixed at creation
        // D38 S3-AND F7: the host's accept covered the participant
        // set as it stood. In an ATTENDED session only a host actor
        // may change that set afterwards; in an UNATTENDED session
        // the initiator may add, but a new CONTROLLER must hold the
        // `use` right on the host's device group.
        if (session.kind == KIND_ATTENDED) {
            if (!isHostActor(session, actorUserId)) return false
        } else {
            if (!isHostActor(session, actorUserId) && actorUserId != session.initiatorUserId) return false
            if (normalizedRole == ROLE_CONTROLLER) {
                val groupId = enrollmentStore.byId(session.hostDeviceId)?.groupId ?: return false
                if (!rosterStore.canUse(session.scopeId, userId, groupId)) return false
            }
        }
        if (participant(sessionId, userId) != null) return false
        val user = rosterStore.user(userId) ?: return false
        if (user.scopeId != session.scopeId) return false
        if (isGone(session.scopeId, userId)) return false
        participantsBySession.getOrPut(sessionId) { mutableListOf() }
            .add(Participant(sessionId, userId, normalizedRole, FLOOR_WATCHING))
        recordEvent(sessionId, EVENT_PARTICIPANT_ADDED, actorUserId, "user=$userId role=$normalizedRole")
        save()
        return true
    }

    /**
     * Host act: remove a participant. The host participant cannot
     * be removed (a session without its host has no clear path —
     * end it instead). Removing the floor holder leaves the floor
     * unheld; nobody inherits it silently.
     */
    @Synchronized
    fun removeParticipant(sessionId: String, actorUserId: String, userId: String): Boolean {
        val session = session(sessionId) ?: return false
        if (session.state == STATE_ENDED || session.state == STATE_BLOCKED) return false
        if (endIfParticipantGone(session)) return false // D38 F3
        if (!isHostActor(session, actorUserId)) return false
        val parts = participantsBySession[sessionId] ?: return false
        val target = parts.firstOrNull { it.userId == userId } ?: return false
        if (target.role == ROLE_HOST) return false
        parts.remove(target)
        recordEvent(sessionId, EVENT_PARTICIPANT_REMOVED, actorUserId, "user=$userId removed by host act")
        save()
        return true
    }

    /**
     * Host act: grant the floor. ATOMIC under the store monitor:
     * every other participant is set `watching` and the target set
     * `holds` in the same step — there is no observable moment with
     * zero or two holders mid-grant, and never two holders after.
     *
     * The target must be a participant in `active`/`paused`, not a
     * watcher (watch-only cannot hold the floor), not
     * removed/suspended. An AI target must be one that could
     * initiate against this host (D9): it holds the `use` right on
     * the host's device group and is not suspended — and holding
     * the floor never gives an AI host acts (see [isHostActor]).
     */
    @Synchronized
    fun grantFloor(sessionId: String, actorUserId: String, targetUserId: String): Boolean {
        val session = session(sessionId) ?: return false
        if (session.state != STATE_ACTIVE && session.state != STATE_PAUSED) return false
        if (endIfParticipantGone(session)) return false // D38 F3: a gone holder's floor dies with the session
        if (!isHostActor(session, actorUserId)) return false
        val parts = participantsBySession[sessionId] ?: return false
        val target = parts.firstOrNull { it.userId == targetUserId } ?: return false
        if (target.role == ROLE_WATCHER) return false
        if (isGone(session.scopeId, targetUserId)) return false
        val targetUser = rosterStore.user(targetUserId) ?: return false
        if (targetUser.kind == RosterStore.USER_AI) {
            val groupId = enrollmentStore.byId(session.hostDeviceId)?.groupId ?: return false
            if (!rosterStore.canUse(session.scopeId, targetUserId, groupId)) return false
        }
        for (i in parts.indices) {
            parts[i] = parts[i].copy(
                floor = if (parts[i].userId == targetUserId) FLOOR_HOLDS else FLOOR_WATCHING
            )
        }
        recordEvent(sessionId, EVENT_FLOOR_GRANTED, actorUserId, "floor -> $targetUserId")
        save()
        return true
    }

    /** Host act: take the floor back to the host participant. */
    @Synchronized
    fun takeFloorBack(sessionId: String, actorUserId: String): Boolean {
        val session = session(sessionId) ?: return false
        if (session.state != STATE_ACTIVE && session.state != STATE_PAUSED) return false
        if (endIfParticipantGone(session)) return false // D38 F3
        if (!isHostActor(session, actorUserId)) return false
        val parts = participantsBySession[sessionId] ?: return false
        val host = parts.firstOrNull { it.role == ROLE_HOST } ?: return false
        for (i in parts.indices) {
            parts[i] = parts[i].copy(
                floor = if (parts[i].userId == host.userId) FLOOR_HOLDS else FLOOR_WATCHING
            )
        }
        recordEvent(sessionId, EVENT_FLOOR_TAKEN, actorUserId, "floor -> host ${host.userId}")
        save()
        return true
    }

    /** Host act: set a participant watch-only — role becomes
     *  `watcher` and any floor it held is revoked in the same step. */
    @Synchronized
    fun setWatchOnly(sessionId: String, actorUserId: String, targetUserId: String): Boolean {
        val session = session(sessionId) ?: return false
        if (session.state == STATE_ENDED || session.state == STATE_BLOCKED) return false
        if (endIfParticipantGone(session)) return false // D38 F3
        if (!isHostActor(session, actorUserId)) return false
        val parts = participantsBySession[sessionId] ?: return false
        val index = parts.indexOfFirst { it.userId == targetUserId }
        if (index < 0) return false
        if (parts[index].role == ROLE_HOST) return false
        parts[index] = parts[index].copy(role = ROLE_WATCHER, floor = FLOOR_WATCHING)
        recordEvent(sessionId, EVENT_WATCH_ONLY, actorUserId, "user=$targetUserId watch-only")
        save()
        return true
    }

    // ---- recording (D36) ----

    /**
     * Change the recording flag / reference on a live session.
     * Actor must be a participant or a company admin. A
     * remote-looking reference is refused and changes nothing;
     * setting `none` clears the reference. Because [isRecording]
     * is derived, this act takes visible effect immediately.
     */
    @Synchronized
    fun setRecording(sessionId: String, actorUserId: String, recording: String, recordingRef: String?): Boolean {
        val index = sessions.indexOfFirst { it.id == sessionId }
        if (index < 0) return false
        val session = sessions[index]
        // D38 S3-AND F4: blocked refuses recording changes too —
        // a blocked session's only outgoing edge is `ended`.
        if (session.state == STATE_ENDED || session.state == STATE_BLOCKED) return false
        if (endIfParticipantGone(session)) return false // D38 F3
        // D38 S3-AND F7: recording is the HOST's consent surface —
        // a host act (or, in an unattended session, the initiator).
        // A watcher or an AI participant cannot toggle it.
        if (!isHostActor(session, actorUserId) &&
            !(session.kind == KIND_UNATTENDED && actorUserId == session.initiatorUserId)
        ) return false
        val normalized = recording.trim().lowercase()
        if (normalized !in RECORDINGS) return false
        val ref = recordingRef?.takeIf { it.isNotBlank() }
        if (ref != null && isRemoteRef(ref)) return false
        sessions[index] = session.copy(
            recording = normalized,
            recordingRef = if (normalized == RECORDING_NONE) null else ref
        )
        recordEvent(sessionId, EVENT_RECORDING_SET, actorUserId, "recording=$normalized")
        save()
        return true
    }

    // ---- session surfaces (Block G: G-02 blank, G-03 input block, G-07 watermark) ----

    /** Who may ENABLE a session surface: a host actor, or the
     *  floor holder (the participant actually driving) while they
     *  are a live user of the scope — a removed/suspended holder's
     *  stale row confers nothing. Watchers, non-holder
     *  controllers, and outsiders never set surfaces that affect
     *  the person at the machine.
     *
     *  Block H (design 4 — per-act floor-grant re-check, mirroring
     *  the Windows CanEnableSurfaceLocked): a NON-host-side actor
     *  must ALSO currently hold the live `use` right on the host
     *  device's group (RosterStore.userHasRight — scope admins
     *  pass, including the personal-scope owner). The floor alone
     *  no longer suffices: a grant revoked mid-session stops the
     *  ex-holder's surface acts at the next act, not at the next
     *  session. Host-side actors are exempt — the person at the
     *  machine (and the scope's admins) need no grant to run
     *  their own session's surfaces. */
    private fun canEnableSurface(session: Session, actorUserId: String): Boolean {
        if (isHostActor(session, actorUserId)) return true
        if (isGone(session.scopeId, actorUserId)) return false
        // D38 Block H review F4 — D9 reconciled to the tunnel
        // store's recorded posture: an AI holds NO authority over
        // host-affecting surfaces (blank, input block, watermark),
        // not even as floor holder with a `use` grant. Driving a
        // session is one leash; changing what the person at the
        // machine sees and can touch is another, and the AI's
        // leash does not include it (SessionTunnels.kt, D9).
        if (rosterStore.user(actorUserId)?.kind == RosterStore.USER_AI) return false
        val holder = participantsBySession[session.id]?.firstOrNull { it.floor == FLOOR_HOLDS }
        if (holder?.userId != actorUserId) return false
        return holdsUseRightOnHost(session, actorUserId)
    }

    /** F4: the same D9 bar for calls — a non-host-side AI may
     *  neither start nor answer a call, whatever its grants. */
    private fun aiBarredFromCall(session: Session, actorUserId: String): Boolean {
        if (isHostActor(session, actorUserId)) return false
        return rosterStore.user(actorUserId)?.kind == RosterStore.USER_AI
    }

    /** The pre-Block-H enable shape, kept for CLEARING acts only:
     *  a host actor, or the live floor holder. Clearing is the
     *  host escape path (design 4): it is NOT subject to the
     *  per-act grant re-check, so losing a grant can never trap
     *  anyone behind a set surface. */
    private fun canClearSurface(session: Session, actorUserId: String): Boolean {
        if (isHostActor(session, actorUserId)) return true
        if (isGone(session.scopeId, actorUserId)) return false
        val holder = participantsBySession[session.id]?.firstOrNull { it.floor == FLOOR_HOLDS }
        return holder?.userId == actorUserId
    }

    /** D38 Block H review F2: the live `use`-right re-read,
     *  exposed for the tunnel store — opening a tunnel is a
     *  per-act drive and must re-check the same right the
     *  surface enables re-check. */
    @Synchronized
    fun holdsUseRightOnHost(sessionId: String, actorUserId: String): Boolean {
        val session = session(sessionId) ?: return false
        return holdsUseRightOnHost(session, actorUserId)
    }

    /** Block H (design 4): the live `use`-right re-read for a
     *  non-host-side actor against the host device's group.
     *  Callers hold the monitor. */
    private fun holdsUseRightOnHost(session: Session, actorUserId: String): Boolean {
        val groupId = enrollmentStore.byId(session.hostDeviceId)?.groupId ?: return false
        return rosterStore.userHasRight(session.scopeId, actorUserId, groupId, RosterStore.RIGHT_USE)
    }

    /**
     * G-02 — privacy blank. Bounds: the blank can never hide the
     * presence composition or STOP (the agent renders the blank
     * UNDER the presence windows; the flag is on this record,
     * which the presence layer reads), and the person at the
     * machine can always clear it — clearing is a host-side act
     * no state here can refuse while the session lives, and it is
     * NEVER policy-gated (policy cannot trap the person at the
     * machine behind a blank screen). Enabling requires a live
     * session (active or paused) and the policy gate
     * (TOTAL POLICY CONTROL, key `blank_screen`).
     */
    @Synchronized
    fun setBlanked(sessionId: String, actorUserId: String, blanked: Boolean): Boolean {
        val index = sessions.indexOfFirst { it.id == sessionId }
        if (index < 0) return false
        var session = sessions[index]
        if (session.state == STATE_ENDED) return false
        if (endIfParticipantGone(session)) return false
        session = sessions[index]
        if (blanked) {
            if (!featureAllowed(session.scopeId, io.agenticcontrol.app.enterprise.PolicyFeatures.BLANK_SCREEN)) return false
            if (session.state != STATE_ACTIVE && session.state != STATE_PAUSED) return false
            if (!canEnableSurface(session, actorUserId)) return false
            if (session.blanked) return true
            sessions[index] = session.copy(blanked = true)
            recordEvent(sessionId, EVENT_BLANK_SET, actorUserId,
                "host screen blanked for privacy (presence and STOP remain visible)")
        } else {
            if (!isHostActor(session, actorUserId) && !canClearSurface(session, actorUserId)) return false
            if (!session.blanked) return true
            sessions[index] = session.copy(blanked = false)
            recordEvent(sessionId, EVENT_BLANK_CLEARED, actorUserId, "privacy blank cleared")
        }
        save()
        return true
    }

    /**
     * G-03 — local input block. Same authorization shape as the
     * blank, with the harder bound: the flag is live-session-only
     * (active — a paused session's block is released by the pause
     * transition itself), and clearing is a host-side act that
     * always works while the session lives. Policy gates enabling
     * (key `input_block`), never clearing.
     */
    @Synchronized
    fun setInputBlocked(sessionId: String, actorUserId: String, blocked: Boolean): Boolean {
        val index = sessions.indexOfFirst { it.id == sessionId }
        if (index < 0) return false
        var session = sessions[index]
        if (session.state == STATE_ENDED) return false
        if (endIfParticipantGone(session)) return false
        session = sessions[index]
        if (blocked) {
            if (!featureAllowed(session.scopeId, io.agenticcontrol.app.enterprise.PolicyFeatures.INPUT_BLOCK)) return false
            if (session.state != STATE_ACTIVE) return false
            if (!canEnableSurface(session, actorUserId)) return false
            if (session.inputBlocked) return true
            sessions[index] = session.copy(inputBlocked = true)
            recordEvent(sessionId, EVENT_INPUT_BLOCK_SET, actorUserId,
                "host local input blocked (presence and STOP remain operable)")
        } else {
            if (!isHostActor(session, actorUserId) && !canClearSurface(session, actorUserId)) return false
            if (!session.inputBlocked) return true
            sessions[index] = session.copy(inputBlocked = false)
            recordEvent(sessionId, EVENT_INPUT_BLOCK_CLEARED, actorUserId, "input block released")
        }
        save()
        return true
    }

    /**
     * G-07 — stream/recording watermark. The watermark TEXT is
     * never caller-supplied ([watermarkText] derives it from this
     * record + the roster), so a caller cannot stamp someone
     * else's name into a recording. Settable from `requested`
     * (so a stream can start watermarked) through paused; refused
     * in blocked/ended. Clearing is host-actor only — and refused
     * outright while policy REQUIRES the watermark (key
     * `watermark`; the start gate in [transition] is the other
     * half). Policy gates enabling, via the constructor gate.
     */
    @Synchronized
    fun setWatermarked(sessionId: String, actorUserId: String, watermarked: Boolean): Boolean {
        val index = sessions.indexOfFirst { it.id == sessionId }
        if (index < 0) return false
        var session = sessions[index]
        if (session.state == STATE_ENDED || session.state == STATE_BLOCKED) return false
        if (endIfParticipantGone(session)) return false
        session = sessions[index]
        if (watermarked) {
            if (!featureAllowed(session.scopeId, io.agenticcontrol.app.enterprise.PolicyFeatures.WATERMARK)) return false
            // D38 Block H review F8: NO initiator exemption — the
            // doc's claim stands as written: watermark ENABLE
            // needs the live `use` re-check (canEnableSurface)
            // for every non-host-side actor, initiator included.
            if (!canEnableSurface(session, actorUserId)) return false
            if (session.watermarked) return true
            sessions[index] = session.copy(watermarked = true)
            recordEvent(sessionId, EVENT_WATERMARK_SET, actorUserId,
                "stream/recording watermark enabled (text derived from the session record)")
        } else {
            if (featureIsRequired(session.scopeId, io.agenticcontrol.app.enterprise.PolicyFeatures.WATERMARK)) return false
            if (!isHostActor(session, actorUserId)) return false
            if (!session.watermarked) return true
            sessions[index] = session.copy(watermarked = false)
            recordEvent(sessionId, EVENT_WATERMARK_CLEARED, actorUserId, "watermark cleared by a host-side actor")
        }
        save()
        return true
    }

    /** G-07: the derived watermark text for a session, or null
     *  when the session is not watermarked. Derived from the
     *  record + roster: the floor holder's name (else the
     *  initiator's), their id, the session's short id, the scope.
     *  An unknown user stamps their bare id — never an invented
     *  name. */
    @Synchronized
    fun watermarkText(sessionId: String): String? {
        val session = session(sessionId) ?: return null
        if (!session.watermarked) return null
        // The stamped name is a LIVE user's (D38-G review F8):
        // a suspended or removed holder's stale row supplies no
        // name — fall back to the initiator, then to a bare id.
        val holder = participantsBySession[session.id]?.firstOrNull { it.floor == FLOOR_HOLDS }
        val holderLive = holder?.userId?.let { rosterStore.user(it) }
            ?.takeIf { !it.suspended && it.scopeId == session.scopeId }
        val operatorId = holderLive?.id ?: session.initiatorUserId
        val name = rosterStore.user(operatorId)?.displayName?.takeIf { it.isNotBlank() } ?: operatorId
        return "$name ($operatorId) · session ${session.id.take(8)} · ${session.scopeId}"
    }

    // ---- in-session voice/video calls (Block G: G-05) ----

    /**
     * Start a voice/video call inside a live session. Null on
     * refusal: policy-disabled (key `voice_video`), unknown kind,
     * a session that is not active/paused, a caller who is not a
     * participant, or a session that already has a live call (one
     * call per session). The call starts `ringing` — media flows
     * only after the other side answers ([answerCall]); an
     * unanswered call carries nothing.
     */
    @Synchronized
    fun startCall(sessionId: String, initiatorUserId: String, kind: String): SessionCall? {
        val normalized = kind.trim().lowercase()
        if (normalized !in CALL_KINDS) return null
        val session = session(sessionId) ?: return null
        if (!featureAllowed(session.scopeId, io.agenticcontrol.app.enterprise.PolicyFeatures.VOICE_VIDEO)) return null
        if (endIfParticipantGone(session)) return null
        val current = session(sessionId) ?: return null
        if (current.state != STATE_ACTIVE && current.state != STATE_PAUSED) return null
        if (participant(sessionId, initiatorUserId) == null) return null
        // Block H (design 4): a non-host-side caller must ALSO
        // currently hold the live `use` right on the host device's
        // group — the per-act re-check the surface enables carry.
        // Host-side actors are exempt; ending a call is ungated.
        if (!isHostActor(current, initiatorUserId) &&
            !holdsUseRightOnHost(current, initiatorUserId)) return null
        if (aiBarredFromCall(current, initiatorUserId)) return null // F4: D9
        if (liveCall(sessionId) != null) return null
        val call = SessionCall(
            id = java.util.UUID.randomUUID().toString().replace("-", ""),
            sessionId = sessionId, kind = normalized, state = CALL_RINGING,
            initiatorUserId = initiatorUserId, startedUtc = clockMs()
        )
        calls.add(call)
        recordEvent(sessionId, EVENT_CALL_STARTED, initiatorUserId, "$normalized call started (ringing)")
        save()
        return call
    }

    /**
     * Answer a ringing call: media may start. The answerer must
     * be a participant OTHER than the caller, or a host actor
     * (the person at the machine picking up). The caller answering
     * their own call is refused — a call nobody else accepted
     * carries nothing, the same shape as session consent.
     */
    @Synchronized
    fun answerCall(callId: String, actorUserId: String): Boolean {
        val index = calls.indexOfFirst { it.id == callId }
        if (index < 0) return false
        val call = calls[index]
        val session = session(call.sessionId) ?: return false
        if (endIfParticipantGone(session)) return false
        val current = session(call.sessionId) ?: return false
        if (current.state != STATE_ACTIVE && current.state != STATE_PAUSED) return false
        if (call.state != CALL_RINGING) return false
        // The policy gate is re-consulted at answer time (AF7):
        // a feature disabled while the call rang answers nothing.
        if (!featureAllowed(current.scopeId, io.agenticcontrol.app.enterprise.PolicyFeatures.VOICE_VIDEO)) return false
        // The answerer is a PARTICIPANT other than the caller —
        // nobody else (D38-G review F11 / Android packet F12b).
        // The host participant is a participant, so the person
        // at the machine still picks up; a non-participant
        // company admin can no longer answer (join) a call that
        // is not theirs, and the caller can never answer their
        // own call on any path.
        if (actorUserId == call.initiatorUserId) return false
        if (participant(call.sessionId, actorUserId) == null) return false
        // Block H (design 4): a non-host-side answerer must ALSO
        // currently hold the live `use` right on the host device's
        // group. Host-side actors are exempt; ending a call is
        // ungated (the host escape principle).
        if (!isHostActor(current, actorUserId) &&
            !holdsUseRightOnHost(current, actorUserId)) return false
        if (aiBarredFromCall(current, actorUserId)) return false // F4: D9
        calls[index] = call.copy(state = CALL_ACTIVE, answeredUtc = clockMs())
        recordEvent(call.sessionId, EVENT_CALL_ANSWERED, actorUserId, "call answered")
        save()
        return true
    }

    /**
     * End a live call. Any participant may hang up, the caller
     * may cancel a ringing call, and a host actor may always end
     * it (the person at the machine is never trapped in a call).
     */
    @Synchronized
    fun endCall(callId: String, actorUserId: String): Boolean {
        val index = calls.indexOfFirst { it.id == callId }
        if (index < 0) return false
        val call = calls[index]
        if (call.state == CALL_ENDED) return false
        val session = session(call.sessionId) ?: return false
        if (participant(call.sessionId, actorUserId) == null && !isHostActor(session, actorUserId)) return false
        calls[index] = call.copy(state = CALL_ENDED, endedUtc = clockMs())
        recordEvent(call.sessionId, EVENT_CALL_ENDED, actorUserId, "call ended")
        save()
        return true
    }

    // ---- policy-change teardown sweep (Block H, design 5) ----

    /**
     * Tear down this scope's live policy-governed surfaces when
     * policy disables their feature: live calls end
     * (`voice_video`), the privacy blank clears (`blank_screen`),
     * the input block clears (`input_block`), the watermark
     * clears (`watermark`) — one recorded event per act, actor
     * `policy`. The wiring layer runs this when a new
     * PolicyEnforcer is installed/replaced: a feature that policy
     * just turned off does not linger on a live session until
     * the session happens to end. Ended sessions are untouched
     * (their flags already died with them); the consent floor
     * (presence, STOP, the audit events themselves) is NOT a
     * policy feature and is never swept. Returns the number of
     * teardown acts performed.
     */
    @Synchronized
    fun sweepPolicyTeardown(scopeId: String, featureDisabled: (String) -> Boolean): Int {
        val voiceVideoOff = featureDisabled(io.agenticcontrol.app.enterprise.PolicyFeatures.VOICE_VIDEO)
        val blankOff = featureDisabled(io.agenticcontrol.app.enterprise.PolicyFeatures.BLANK_SCREEN)
        val inputOff = featureDisabled(io.agenticcontrol.app.enterprise.PolicyFeatures.INPUT_BLOCK)
        val watermarkOff = featureDisabled(io.agenticcontrol.app.enterprise.PolicyFeatures.WATERMARK)
        if (!voiceVideoOff && !blankOff && !inputOff && !watermarkOff) return 0
        var acts = 0
        for (i in sessions.indices) {
            val s = sessions[i]
            if (s.scopeId != scopeId || s.state == STATE_ENDED) continue
            if (voiceVideoOff) {
                val live = calls.count {
                    it.sessionId == s.id && (it.state == CALL_RINGING || it.state == CALL_ACTIVE)
                }
                if (live > 0) {
                    endLiveCalls(s.id, "policy", "call ended by policy teardown (voice_video disabled)")
                    acts += live
                }
            }
            var cur = sessions[i]
            if (blankOff && cur.blanked) {
                cur = cur.copy(blanked = false)
                sessions[i] = cur
                recordEvent(s.id, EVENT_BLANK_CLEARED, "policy",
                    "privacy blank cleared by policy teardown (blank_screen disabled)")
                acts++
            }
            if (inputOff && cur.inputBlocked) {
                cur = cur.copy(inputBlocked = false)
                sessions[i] = cur
                recordEvent(s.id, EVENT_INPUT_BLOCK_CLEARED, "policy",
                    "input block cleared by policy teardown (input_block disabled)")
                acts++
            }
            if (watermarkOff && cur.watermarked) {
                cur = cur.copy(watermarked = false)
                sessions[i] = cur
                recordEvent(s.id, EVENT_WATERMARK_CLEARED, "policy",
                    "watermark cleared by policy teardown (watermark disabled)")
                acts++
            }
        }
        if (acts > 0) save()
        return acts
    }

    // ---- chat ----

    /**
     * Send a chat message. Senders must be participants; ended and
     * blocked sessions refuse (blocked's only outgoing edge is
     * `ended`). The message is stored and a chat marker event is
     * recorded (the marker carries no message text).
     */
    @Synchronized
    fun sendChat(sessionId: String, senderUserId: String, text: String): Boolean {
        val session = session(sessionId) ?: return false
        if (session.state == STATE_ENDED || session.state == STATE_BLOCKED) return false
        if (endIfParticipantGone(session)) return false // D38 F3
        if (text.isBlank()) return false
        if (participant(sessionId, senderUserId) == null) return false
        chatList.add(ChatMessage(sessionId, senderUserId, clockMs(), text))
        recordEvent(sessionId, EVENT_CHAT, senderUserId, "chat message (${text.length} chars)")
        save()
        return true
    }

    // ---- file jobs ----

    /**
     * Create a file job on a live (non-ended, non-blocked)
     * session. The job is forced to `queued` with zero bytes —
     * a caller cannot mint a job already progressed or done.
     * Actor must be a participant or a company admin.
     */
    @Synchronized
    fun createFileJob(sessionId: String, actorUserId: String, job: FileJob): Boolean {
        val session = session(sessionId) ?: return false
        if (session.state == STATE_ENDED || session.state == STATE_BLOCKED) return false
        if (endIfParticipantGone(session)) return false // D38 F3
        if (job.sessionId != sessionId) return false
        if (job.id.isBlank() || job.id.any { it == '\t' || it == '\n' || it == '\r' } ||
            jobs.any { it.sessionId == sessionId && it.id == job.id }) return false
        if (job.direction.trim().lowercase() !in DIRECTIONS) return false
        if (job.name.isBlank() || job.sizeBytes < 0) return false
        if (!canActOnFiles(session, actorUserId)) return false
        jobs.add(
            job.copy(
                direction = job.direction.trim().lowercase(),
                transferredBytes = 0L,
                state = JOB_QUEUED
            )
        )
        recordEvent(sessionId, EVENT_FILE_CREATED, actorUserId, "job=${job.id} ${job.name} ${job.sizeBytes}B")
        save()
        return true
    }

    /**
     * Advance a job's progress. Monotonic: a value below the
     * recorded progress refuses and changes nothing, as does a
     * value above the job's size. Terminal jobs refuse. Reaching
     * full size does NOT mark the job done by itself — completion
     * is the explicit [setFileJobState] act, which requires it.
     */
    @Synchronized
    fun updateFileProgress(sessionId: String, jobId: String, transferredBytes: Long, actorUserId: String): Boolean {
        val index = jobs.indexOfFirst { it.sessionId == sessionId && it.id == jobId }
        if (index < 0) return false
        val session = session(sessionId) ?: return false
        // D38 S3-AND F4: blocked refuses (its only edge is `ended`),
        // and the act is authorized — previously it took no actor
        // at all. Actor: a non-watcher participant or company admin.
        if (session.state == STATE_ENDED || session.state == STATE_BLOCKED) return false
        if (endIfParticipantGone(session)) return false // D38 F3
        if (!canActOnFiles(session, actorUserId)) return false
        val job = jobs[index]
        if (job.state in JOB_TERMINAL) return false
        if (transferredBytes < job.transferredBytes) return false // monotonic
        if (transferredBytes > job.sizeBytes) return false
        jobs[index] = job.copy(
            transferredBytes = transferredBytes,
            state = if (job.state == JOB_QUEUED && transferredBytes > 0) JOB_ACTIVE else job.state
        )
        save()
        return true
    }

    /**
     * Move a job between states. `done` REQUIRES
     * TransferredBytes == SizeBytes — refused otherwise, changing
     * nothing. Terminal states (done / failed / cancelled) never
     * leave — the SAME closed transition table as the standalone
     * jobs and the Windows store (AF11: one transfer discipline;
     * a retry is a NEW job, not a resurrection of a failed one).
     */
    @Synchronized
    fun setFileJobState(sessionId: String, jobId: String, toState: String, actorUserId: String): Boolean {
        val index = jobs.indexOfFirst { it.sessionId == sessionId && it.id == jobId }
        if (index < 0) return false
        val session = session(sessionId) ?: return false
        // D38 S3-AND F4: blocked refuses; the act is authorized
        // (previously it took no actor at all).
        if (session.state == STATE_ENDED || session.state == STATE_BLOCKED) return false
        if (endIfParticipantGone(session)) return false // D38 F3
        if (!canActOnFiles(session, actorUserId)) return false
        val job = jobs[index]
        val target = toState.trim().lowercase()
        if (target !in JOB_STATES) return false
        val legal = when (job.state to target) {
            JOB_QUEUED to JOB_ACTIVE, JOB_QUEUED to JOB_PAUSED,
            JOB_QUEUED to JOB_FAILED, JOB_QUEUED to JOB_CANCELLED,
            JOB_ACTIVE to JOB_PAUSED, JOB_ACTIVE to JOB_DONE,
            JOB_ACTIVE to JOB_FAILED, JOB_ACTIVE to JOB_CANCELLED,
            JOB_PAUSED to JOB_ACTIVE, JOB_PAUSED to JOB_DONE,
            JOB_PAUSED to JOB_FAILED, JOB_PAUSED to JOB_CANCELLED -> true
            // The one named exception to the shared table: a
            // ZERO-BYTE job has nothing to move, so queued→done
            // is its completion (Slice 3's pinned behavior). A
            // non-zero job may never skip the active state.
            JOB_QUEUED to JOB_DONE -> job.sizeBytes == 0L
            else -> false
        }
        if (!legal) return false
        if (target == JOB_DONE && job.transferredBytes != job.sizeBytes) return false
        jobs[index] = job.copy(state = target)
        recordEvent(sessionId, EVENT_FILE_STATE, actorUserId, "job=$jobId -> $target")
        save()
        return true
    }

    /** File-act gate (D38 S3-AND F4): a live, non-watcher
     *  participant or a company admin of the scope. Callers hold
     *  the monitor. */
    private fun canActOnFiles(session: Session, actorUserId: String): Boolean {
        if (isGone(session.scopeId, actorUserId)) return false
        if (rosterStore.isCompanyAdmin(session.scopeId, actorUserId)) return true
        val part = participant(session.id, actorUserId) ?: return false
        return part.role != ROLE_WATCHER
    }

    // ---- internals (callers hold the monitor) ----

    /** Host-act gate (D35): the actor is the session's host
     *  participant or a company admin of the scope. Holding the
     *  floor confers NOTHING here — an AI floor-holder is not a
     *  host participant and (D9) never a company admin. */
    private fun isHostActor(session: Session, actorUserId: String): Boolean {
        // D38 S3-AND F3: a removed/suspended host or admin has no
        // host acts, whatever the participant list or seat set says.
        if (isGone(session.scopeId, actorUserId)) return false
        val parts = participantsBySession[session.id] ?: emptyList()
        if (parts.any { it.role == ROLE_HOST && it.userId == actorUserId }) return true
        return rosterStore.isCompanyAdmin(session.scopeId, actorUserId)
    }

    /** Removed/suspended re-read against the roster: the user
     *  record is gone (removed — D14 deletes it), or suspended,
     *  or named as the subject of an offboarding event in this
     *  scope. Roster state is read fresh on every call. */
    private fun isGone(scopeId: String, userId: String): Boolean {
        val user = rosterStore.user(userId)
        if (user == null || user.scopeId != scopeId) return true
        if (user.suspended) return true
        return rosterStore.events().any {
            it.type == RosterStore.EVENT_USER_OFFBOARDED && it.scopeId == scopeId && it.subjectId == userId
        }
    }

    /** The first removed/suspended person on the session —
     *  initiator first, then participants — or null when clean. */
    private fun goneParticipant(session: Session): String? {
        if (isGone(session.scopeId, session.initiatorUserId)) return session.initiatorUserId
        val parts = participantsBySession[session.id] ?: emptyList()
        return parts.firstOrNull { isGone(session.scopeId, it.userId) }?.userId
    }

    /** Shared end path: stamp ended, cascade live file jobs to
     *  `cancelled` (done/failed/cancelled jobs keep their terminal
     *  state — their outcome already happened), record the
     *  participant_removed event when that is the cause, then the
     *  ended event. Callers hold the monitor and save. */
    private fun endInternal(
        index: Int,
        actorUserId: String,
        reason: String,
        goneUserId: String? = null,
        emitEndedEvent: Boolean = true
    ) {
        val session = sessions[index]
        if (goneUserId != null) {
            recordEvent(session.id, EVENT_PARTICIPANT_REMOVED, goneUserId, "user=$goneUserId participant_removed")
        }
        sessions[index] = session.copy(
            state = STATE_ENDED,
            endedUtc = clockMs(),
            endReason = reason,
            // Block G flags die with the session, on the record:
            // a blanked screen unblanks, blocked input releases,
            // and no ended session claims a watermark.
            blanked = false,
            inputBlocked = false,
            watermarked = false
        )
        clearFloors(session.id) // D38 S3-AND F9: an ended session holds no floor
        for (i in jobs.indices) {
            if (jobs[i].sessionId == session.id && jobs[i].state in JOB_CANCELLABLE) {
                jobs[i] = jobs[i].copy(state = JOB_CANCELLED)
            }
        }
        // G-05: a live call dies with its session, on the record.
        endLiveCalls(session.id, actorUserId, "call ended by session end")
        if (emitEndedEvent) {
            recordEvent(session.id, EVENT_ENDED, actorUserId, "ended reason=$reason")
        }
    }

    /** G-05 cascade: end every live (ringing/active) call on a
     *  session, one event per call. Callers hold the monitor and
     *  save. */
    private fun endLiveCalls(sessionId: String, actorUserId: String, detail: String) {
        for (i in calls.indices) {
            if (calls[i].sessionId == sessionId &&
                (calls[i].state == CALL_RINGING || calls[i].state == CALL_ACTIVE)
            ) {
                calls[i] = calls[i].copy(state = CALL_ENDED, endedUtc = clockMs())
                recordEvent(sessionId, EVENT_CALL_ENDED, actorUserId, detail)
            }
        }
    }

    private fun recordEvent(sessionId: String, type: String, actorUserId: String, detail: String) {
        eventList.add(SessionEvent(clockMs(), sessionId, type, actorUserId, detail))
        compactEvents(sessionId)
    }

    /**
     * bd-and-core F12 fix (2026-11-22): the event list is bounded
     * per session. The old list grew forever and every act rewrote
     * the whole TSV, so a long-lived session made each act slower
     * and the file bigger without limit. Now: at most
     * [MAX_EVENTS_PER_SESSION] events per session are retained;
     * when the cap is crossed the OLDEST events are dropped and a
     * single leading [EVENT_EVENTS_COMPACTED] marker records how
     * many were dropped in total — compaction is visible in the
     * record, never silent. Core lifecycle events at the tail
     * (ended/stopped) are never the ones dropped: drops take the
     * oldest non-marker events first, and the marker itself is
     * updated in place rather than duplicated.
     */
    private fun compactEvents(sessionId: String) {
        val mine = eventList.withIndex().filter { it.value.sessionId == sessionId }
        if (mine.size <= MAX_EVENTS_PER_SESSION) return
        var excess = mine.size - MAX_EVENTS_PER_SESSION
        val markerIdx = mine.firstOrNull { it.value.type == EVENT_EVENTS_COMPACTED }?.index
        var droppedSoFar = markerIdx?.let {
            eventList[it].detail.substringAfter("dropped=").substringBefore(" ").toIntOrNull() ?: 0
        } ?: 0
        val toRemove = mutableListOf<Int>()
        for ((idx, e) in mine) {
            if (excess <= 0) break
            if (idx == markerIdx) continue
            toRemove += idx
            droppedSoFar++
            excess--
        }
        // Remove from the back so indices stay valid.
        for (idx in toRemove.sortedDescending()) eventList.removeAt(idx)
        val marker = SessionEvent(
            clockMs(), sessionId, EVENT_EVENTS_COMPACTED, "system",
            "dropped=$droppedSoFar oldest events (per-session cap $MAX_EVENTS_PER_SESSION)"
        )
        if (markerIdx != null) {
            val adjusted = markerIdx - toRemove.count { it < markerIdx }
            eventList[adjusted] = marker
        } else {
            val firstIdx = eventList.indexOfFirst { it.sessionId == sessionId }
            eventList.add(if (firstIdx >= 0) firstIdx else eventList.size, marker)
        }
    }

    /** Append an event to a session's replay list (the transport
     *  layer's failover linkage: end + new-start, both ids named).
     *  False for an unknown session; the list stays append-only.
     *
     *  AF9: the CORE lifecycle/consent types (accepted, started,
     *  stopped, ended, blocked, and every other EVENT_* the store
     *  itself records) are NOT appendable through this door —
     *  they are the audit leg of the §7.10 consent floor, and a
     *  caller holding this store must not be able to forge them.
     *  Sibling legs append their own kinds (tunnel_*, wake_sent,
     *  terminal_*) plus the one shared linkage type,
     *  transport_failover. */
    @Synchronized
    fun appendEvent(sessionId: String, type: String, actorUserId: String, detail: String): Boolean {
        if (sessions.none { it.id == sessionId }) return false
        val normalized = type.trim().lowercase()
        if (normalized in CORE_EVENT_TYPES) return false
        recordEvent(sessionId, normalized, actorUserId, detail)
        save()
        return true
    }

    /** Public form of the host-actor rule (the session's host
     *  participant or a company admin of the scope — always a
     *  live user), for sibling stores (G-08 session tunnels) that
     *  must apply the SAME rule rather than a copy of it. */
    @Synchronized
    fun isHostActor(sessionId: String, actorUserId: String): Boolean {
        val session = session(sessionId) ?: return false
        return isHostActor(session, actorUserId)
    }

    /** D38 S3-AND F9: nobody holds the floor of a blocked or ended
     *  session. Callers hold the monitor. */
    private fun clearFloors(sessionId: String) {
        val parts = participantsBySession[sessionId] ?: return
        for (i in parts.indices) {
            if (parts[i].floor != FLOOR_WATCHING) {
                parts[i] = parts[i].copy(floor = FLOOR_WATCHING)
            }
        }
    }

    /**
     * D38 S3-AND F3: the offboarding re-read at the top of every
     * mutating entry point — not just transitions. If the initiator
     * or any participant has been removed/suspended, the session is
     * ended with reason `participant_removed` NOW (a removed user
     * never keeps chatting, transferring files, toggling recording,
     * or holding the floor until some later transition) and true is
     * returned; the caller must refuse its own act. Callers hold the
     * monitor.
     */
    private fun endIfParticipantGone(session: Session): Boolean {
        val gone = goneParticipant(session) ?: return false
        val index = sessions.indexOfFirst { it.id == session.id }
        if (index < 0) return false
        endInternal(index, gone, REASON_PARTICIPANT_REMOVED, goneUserId = gone)
        save()
        return true
    }

    // ---- persistence (PairingStore/EnrollmentStore/RosterStore style) ----

    private fun load() {
        if (!storeFile.exists()) return
        try {
            storeFile.readLines().forEach { line ->
                if (line.isBlank()) return@forEach
                val parts = line.split('\t')
                try {
                    when (parts.getOrNull(0)) {
                        "session" -> {
                            if (parts.size < 14) return@forEach
                            val kind = parts[5].trim().lowercase()
                            if (kind !in KINDS) return@forEach
                            val state = parts[6].trim().lowercase()
                            if (state !in STATES) return@forEach
                            val recording = parts[10].trim().lowercase()
                            if (recording !in RECORDINGS) return@forEach
                            if (sessions.any { it.id == parts[1] }) return@forEach
                            sessions.add(
                                Session(
                                    id = parts[1].tsvUnescape(), scopeId = parts[2].tsvUnescape(),
                                    hostDeviceId = parts[3].tsvUnescape(),
                                    initiatorUserId = parts[4].tsvUnescape(), kind = kind, state = state,
                                    startedUtc = parts[7].toLongOrNull() ?: return@forEach,
                                    endedUtc = parts[8].toLongOrNull(),
                                    transportRung = parts[9].tsvUnescape(), recording = recording,
                                    // D38 S3-AND F5: load re-validates —
                                    // a remote ref in the file is
                                    // dropped, never accepted back.
                                    recordingRef = parts[11].tsvUnescape()
                                        .takeIf { it.isNotBlank() && !isRemoteRef(it) },
                                    acceptBy = parts[12].tsvUnescape().takeIf { it.isNotBlank() },
                                    endReason = parts[13].tsvUnescape().takeIf { it.isNotBlank() },
                                    acceptOrigin = parts.getOrNull(14)?.tsvUnescape()
                                        ?.takeIf { it.isNotBlank() },
                                    // Block G flags on load: trusted
                                    // only as far as the state allows
                                    // (AF6: the blank is active/paused
                                    // only — a requested or blocked
                                    // session carries none; an input
                                    // block is active-only). A session
                                    // policy REQUIRES watermarked
                                    // loads watermarked even if the
                                    // file says otherwise (AF6b).
                                    blanked = parts.getOrNull(15) == "1" &&
                                        (state == STATE_ACTIVE || state == STATE_PAUSED),
                                    inputBlocked = parts.getOrNull(16) == "1" && state == STATE_ACTIVE,
                                    watermarked = (parts.getOrNull(17) == "1" && state != STATE_ENDED) ||
                                        (state != STATE_ENDED && featureIsRequired(
                                            parts[2].tsvUnescape(),
                                            io.agenticcontrol.app.enterprise.PolicyFeatures.WATERMARK))
                                )
                            )
                            // RULING 2026-11-19: a stored accept is
                            // honored only if it was endpoint-local.
                            // A legacy (14-field) line or a
                            // hand-edited line carrying an acceptBy
                            // with no local origin is repaired to
                            // UNACCEPTED — the session stays in
                            // `requested` until a real local accept.
                            val loadedIdx = sessions.size - 1
                            val loadedSession = sessions[loadedIdx]
                            if (loadedSession.acceptBy != null &&
                                loadedSession.acceptOrigin != ACCEPT_ORIGIN_LOCAL_UI
                            ) {
                                sessions[loadedIdx] = loadedSession.copy(
                                    acceptBy = null, acceptOrigin = null
                                )
                            }
                        }
                        "participant" -> {
                            if (parts.size < 5) return@forEach
                            val role = parts[3].trim().lowercase()
                            if (role !in ROLES) return@forEach
                            val floor = parts[4].trim().lowercase()
                            if (floor !in FLOORS) return@forEach
                            val list = participantsBySession.getOrPut(parts[1].tsvUnescape()) { mutableListOf() }
                            if (list.any { it.userId == parts[2].tsvUnescape() }) return@forEach
                            list.add(Participant(parts[1].tsvUnescape(), parts[2].tsvUnescape(), role, floor))
                        }
                        "event" -> {
                            if (parts.size < 6) return@forEach
                            eventList.add(
                                SessionEvent(
                                    atMs = parts[1].toLongOrNull() ?: return@forEach,
                                    sessionId = parts[2].tsvUnescape(), type = parts[3].tsvUnescape(),
                                    actorUserId = parts[4].tsvUnescape(), detail = parts[5].tsvUnescape()
                                )
                            )
                        }
                        "chat" -> {
                            if (parts.size < 5) return@forEach
                            chatList.add(
                                ChatMessage(
                                    sessionId = parts[1].tsvUnescape(), senderUserId = parts[2].tsvUnescape(),
                                    utc = parts[3].toLongOrNull() ?: return@forEach,
                                    text = parts[4].tsvUnescape()
                                )
                            )
                        }
                        "filejob" -> {
                            if (parts.size < 8) return@forEach
                            val direction = parts[3].trim().lowercase()
                            if (direction !in DIRECTIONS) return@forEach
                            val state = parts[7].trim().lowercase()
                            if (state !in JOB_STATES) return@forEach
                            if (jobs.any { it.sessionId == parts[2].tsvUnescape() && it.id == parts[1].tsvUnescape() }) return@forEach
                            // AF11: the session loader applies
                            // the same byte discipline the
                            // standalone loader claims — negative
                            // or over-size progress and a "done"
                            // without full bytes drop at the entry.
                            val jobSize = parts[5].toLongOrNull() ?: return@forEach
                            val jobDone = parts[6].toLongOrNull() ?: return@forEach
                            if (jobSize < 0 || jobDone < 0 || jobDone > jobSize) return@forEach
                            if (state == JOB_DONE && jobDone != jobSize) return@forEach
                            jobs.add(
                                FileJob(
                                    id = parts[1].tsvUnescape(), sessionId = parts[2].tsvUnescape(),
                                    direction = direction,
                                    name = parts[4].tsvUnescape(),
                                    sizeBytes = jobSize,
                                    transferredBytes = jobDone,
                                    state = state
                                )
                            )
                        }
                        "call" -> {
                            if (parts.size < 9) return@forEach
                            val kind = parts[3].trim().lowercase()
                            if (kind !in CALL_KINDS) return@forEach
                            val state = parts[4].trim().lowercase()
                            if (state !in CALL_STATES) return@forEach
                            if (calls.any { it.id == parts[1].tsvUnescape() }) return@forEach
                            calls.add(
                                SessionCall(
                                    id = parts[1].tsvUnescape(), sessionId = parts[2].tsvUnescape(),
                                    kind = kind, state = state,
                                    initiatorUserId = parts[5].tsvUnescape(),
                                    startedUtc = parts[6].toLongOrNull() ?: return@forEach,
                                    answeredUtc = parts[7].toLongOrNull(),
                                    endedUtc = parts[8].toLongOrNull()
                                )
                            )
                        }
                        else -> Unit // corrupt/unknown line: skip, never fatal
                    }
                } catch (_: Exception) {
                    // corrupt line: skip, never fatal
                }
            }
        } catch (_: Exception) {
            // unreadable store: start empty, never fatal
        }
        // AF5: a stored accept is honored only when the session's
        // own event list PROVES it — an "accepted" event by the
        // acceptBy user. A hand-edited acceptBy/acceptOrigin pair
        // with no such event is repaired to unaccepted; a live
        // ATTENDED session left unaccepted by the repair demotes
        // to requested (it was never consented to).
        for (i in sessions.indices) {
            var s0 = sessions[i]
            if (s0.acceptBy != null) {
                val proven = eventList.any {
                    it.sessionId == s0.id && it.type == EVENT_ACCEPTED && it.actorUserId == s0.acceptBy
                }
                if (!proven) s0 = s0.copy(acceptBy = null, acceptOrigin = null)
            }
            if (s0.kind == KIND_ATTENDED &&
                (s0.state == STATE_ACTIVE || s0.state == STATE_PAUSED) && s0.acceptBy == null
            ) {
                s0 = s0.copy(state = STATE_REQUESTED, blanked = false, inputBlocked = false)
            }
            sessions[i] = s0
        }
        // AF6(d): participant authority is re-validated at load.
        // The host role on Android is creation-bound (the host
        // participant row is written at createSession, before any
        // accept exists), so the repair arbitrates BETWEEN host
        // rows rather than against acceptBy alone: with several
        // host rows, the one matching the (verified) acceptBy —
        // else the first — is the host; every other host row is
        // forged and demotes to watcher. A single host row is
        // the session's designated host and stands. A watcher
        // never holds the floor.
        for (session in sessions) {
            val parts = participantsBySession[session.id] ?: continue
            val hostIdx = parts.indices.filter { parts[it].role == ROLE_HOST }
            val keepHost = when {
                hostIdx.size <= 1 -> hostIdx.firstOrNull()
                else -> hostIdx.firstOrNull { parts[it].userId == session.acceptBy } ?: hostIdx.first()
            }
            for (i in parts.indices) {
                var p = parts[i]
                if (p.role == ROLE_HOST && i != keepHost)
                    p = p.copy(role = ROLE_WATCHER)
                if (p.role == ROLE_WATCHER && p.floor == FLOOR_HOLDS)
                    p = p.copy(floor = FLOOR_WATCHING)
                parts[i] = p
            }
        }
        // D38 S3-AND F9: the one-holder invariant is enforced at
        // load too — a hand-edited file naming two holders keeps
        // only the first; the rest are demoted to watching.
        for ((_, parts) in participantsBySession) {
            var holderSeen = false
            for (i in parts.indices) {
                if (parts[i].floor == FLOOR_HOLDS) {
                    if (holderSeen) parts[i] = parts[i].copy(floor = FLOOR_WATCHING)
                    else holderSeen = true
                }
            }
        }
        // G-05 cascade invariant at load (extended, AF6c): no
        // live call on an ended, blocked, or merely-requested
        // session, none on a session that does not exist, at most
        // ONE live call per session, no "active" call that was
        // never answered, and no call whose initiator is not a
        // participant of the session.
        val liveCallSeen = HashSet<String>()
        for (i in calls.indices) {
            val call = calls[i]
            if (call.state == CALL_RINGING || call.state == CALL_ACTIVE) {
                val owner = sessions.firstOrNull { it.id == call.sessionId }
                val bad = owner == null || owner.state == STATE_ENDED ||
                    owner.state == STATE_BLOCKED || owner.state == STATE_REQUESTED ||
                    (call.state == CALL_ACTIVE && call.answeredUtc == null) ||
                    participantsBySession[call.sessionId]
                        ?.any { it.userId == call.initiatorUserId } != true ||
                    !liveCallSeen.add(call.sessionId)
                if (bad) {
                    calls[i] = call.copy(state = CALL_ENDED, endedUtc = call.endedUtc ?: call.startedUtc)
                }
            }
        }
    }

    private fun save() {
        val lines = mutableListOf<String>()
        sessions.forEach { s ->
            lines.add(
                listOf(
                    "session", s.id.tsvSafe(), s.scopeId.tsvSafe(), s.hostDeviceId.tsvSafe(),
                    s.initiatorUserId.tsvSafe(), s.kind, s.state, s.startedUtc.toString(),
                    s.endedUtc?.toString() ?: "", s.transportRung.tsvSafe(), s.recording,
                    (s.recordingRef ?: "").tsvSafe(), (s.acceptBy ?: "").tsvSafe(),
                    (s.endReason ?: "").tsvSafe(), (s.acceptOrigin ?: "").tsvSafe(),
                    if (s.blanked) "1" else "0", if (s.inputBlocked) "1" else "0",
                    if (s.watermarked) "1" else "0"
                ).joinToString("\t")
            )
        }
        participantsBySession.forEach { (sessionId, parts) ->
            parts.forEach { p ->
                lines.add(
                    listOf("participant", sessionId.tsvSafe(), p.userId.tsvSafe(), p.role, p.floor)
                        .joinToString("\t")
                )
            }
        }
        eventList.forEach { e ->
            lines.add(
                listOf(
                    "event", e.atMs.toString(), e.sessionId.tsvSafe(), e.type.tsvSafe(),
                    e.actorUserId.tsvSafe(), e.detail.tsvSafe()
                ).joinToString("\t")
            )
        }
        chatList.forEach { m ->
            lines.add(
                listOf("chat", m.sessionId.tsvSafe(), m.senderUserId.tsvSafe(), m.utc.toString(), m.text.tsvSafe())
                    .joinToString("\t")
            )
        }
        jobs.forEach { j ->
            lines.add(
                listOf(
                    "filejob", j.id.tsvSafe(), j.sessionId.tsvSafe(), j.direction,
                    j.name.tsvSafe(), j.sizeBytes.toString(), j.transferredBytes.toString(), j.state
                ).joinToString("\t")
            )
        }
        calls.forEach { c ->
            lines.add(
                listOf(
                    "call", c.id.tsvSafe(), c.sessionId.tsvSafe(), c.kind, c.state,
                    c.initiatorUserId.tsvSafe(), c.startedUtc.toString(),
                    c.answeredUtc?.toString() ?: "", c.endedUtc?.toString() ?: ""
                ).joinToString("\t")
            )
        }
        // D38 S3-AND F6: atomic replace only — tmp file, fsync,
        // rename. The old in-place fallback could truncate the
        // store on a crash mid-write (and load() would then start
        // empty, losing every session); a failed rename throws.
        val parent = storeFile.parentFile
        val bytes = lines.joinToString("\n").toByteArray(Charsets.UTF_8)
        if (parent != null) {
            val tmp = File(parent, storeFile.name + ".tmp")
            java.io.FileOutputStream(tmp).use { out ->
                out.write(bytes)
                out.fd.sync()
            }
            if (!tmp.renameTo(storeFile)) {
                tmp.delete()
                throw IllegalStateException("session store: atomic rename failed for ${storeFile.name}")
            }
        } else {
            java.io.FileOutputStream(storeFile).use { out ->
                out.write(bytes)
                out.fd.sync()
            }
        }
    }

    /**
     * D38 S3-AND F12: fields are backslash-ESCAPED, not lossily
     * rewritten — a tab, newline, or backslash in chat text, a
     * name, or an id round-trips byte-identically instead of
     * silently becoming spaces on save.
     */
    private fun String.tsvSafe(): String =
        replace("\\", "\\\\").replace("\t", "\\t").replace("\n", "\\n").replace("\r", "\\r")

    private fun String.tsvUnescape(): String {
        if (!contains('\\')) return this
        val out = StringBuilder(length)
        var i = 0
        while (i < length) {
            val c = this[i]
            if (c == '\\' && i + 1 < length) {
                when (this[i + 1]) {
                    't' -> out.append('\t')
                    'n' -> out.append('\n')
                    'r' -> out.append('\r')
                    '\\' -> out.append('\\')
                    else -> out.append(this[i + 1])
                }
                i += 2
            } else {
                out.append(c)
                i++
            }
        }
        return out.toString()
    }

    companion object {
        const val KIND_ATTENDED = "attended"
        const val KIND_UNATTENDED = "unattended"
        val KINDS = setOf(KIND_ATTENDED, KIND_UNATTENDED)

        const val STATE_REQUESTED = "requested"
        const val STATE_ACTIVE = "active"
        const val STATE_PAUSED = "paused"
        const val STATE_BLOCKED = "blocked"
        const val STATE_ENDED = "ended"
        val STATES = setOf(STATE_REQUESTED, STATE_ACTIVE, STATE_PAUSED, STATE_BLOCKED, STATE_ENDED)

        /** The closed transition set (Slice 3 spec). `blocked`
         *  maps to exactly {ended}: a blocked session can only
         *  end — the 2026-11-17 STOP trap is unrepresentable. */
        val TRANSITIONS: Map<String, Set<String>> = mapOf(
            STATE_REQUESTED to setOf(STATE_ACTIVE, STATE_ENDED),
            STATE_ACTIVE to setOf(STATE_PAUSED, STATE_BLOCKED, STATE_ENDED),
            STATE_PAUSED to setOf(STATE_ACTIVE, STATE_BLOCKED, STATE_ENDED),
            STATE_BLOCKED to setOf(STATE_ENDED),
            STATE_ENDED to emptySet()
        )

        const val ROLE_HOST = "host"
        const val ROLE_CONTROLLER = "controller"
        const val ROLE_WATCHER = "watcher"
        val ROLES = setOf(ROLE_HOST, ROLE_CONTROLLER, ROLE_WATCHER)

        const val FLOOR_HOLDS = "holds"
        const val FLOOR_WATCHING = "watching"
        val FLOORS = setOf(FLOOR_HOLDS, FLOOR_WATCHING)

        const val RECORDING_NONE = "none"
        const val RECORDING_VIDEO = "video"
        const val RECORDING_REPLAY = "replay"
        const val RECORDING_BOTH = "both"
        val RECORDINGS = setOf(RECORDING_NONE, RECORDING_VIDEO, RECORDING_REPLAY, RECORDING_BOTH)

        const val REASON_ENDED = "ended"
        const val REASON_TRANSPORT_FAILOVER = "transport_failover"
        const val REASON_HOST_STOP = "host_stop"
        const val REASON_PARTICIPANT_REMOVED = "participant_removed"
        const val REASON_DEVICE_REVOKED = "device_revoked"
        const val REASON_GRANT_REVOKED = "grant_revoked"

        /** RULING 2026-11-19: the only honored accept origin —
         *  the endpoint host's own local UI. */
        const val ACCEPT_ORIGIN_LOCAL_UI = "local_ui"
        /** An accept arriving over the initiating channel — never
         *  honored, in any scope (RULING 2026-11-19). */
        const val ACCEPT_ORIGIN_INITIATING_CHANNEL = "channel"

        /** bd-and-core F12: per-session retained-event cap; the
         *  compaction marker type (see compactEvents). */
        const val MAX_EVENTS_PER_SESSION = 500
        const val EVENT_EVENTS_COMPACTED = "events_compacted"

        const val EVENT_CREATED = "created"
        const val EVENT_ACCEPTED = "accepted"
        const val EVENT_ACCEPT_REFUSED = "accept_refused"
        const val EVENT_STARTED = "started"
        const val EVENT_FLOOR_GRANTED = "floor_granted"
        const val EVENT_FLOOR_TAKEN = "floor_taken"
        const val EVENT_PARTICIPANT_ADDED = "participant_added"
        const val EVENT_PARTICIPANT_REMOVED = "participant_removed"
        const val EVENT_PAUSED = "paused"
        const val EVENT_BLOCKED = "blocked"
        const val EVENT_STOPPED = "stopped"
        const val EVENT_ENDED = "ended"
        const val EVENT_WATCH_ONLY = "watch_only"
        const val EVENT_RECORDING_SET = "recording_set"
        const val EVENT_TRANSPORT_FAILOVER = "transport_failover"
        const val EVENT_CHAT = "chat"
        const val EVENT_FILE_CREATED = "file_created"
        const val EVENT_FILE_STATE = "file_state"
        const val EVENT_BLANK_SET = "blank_set"
        const val EVENT_BLANK_CLEARED = "blank_cleared"
        const val EVENT_INPUT_BLOCK_SET = "input_block_set"
        const val EVENT_INPUT_BLOCK_CLEARED = "input_block_cleared"
        const val EVENT_WATERMARK_SET = "watermark_set"
        const val EVENT_WATERMARK_CLEARED = "watermark_cleared"
        const val EVENT_CALL_STARTED = "call_started"
        const val EVENT_CALL_ANSWERED = "call_answered"
        const val EVENT_CALL_ENDED = "call_ended"

        /** Event types only the store itself may record: the
         *  public appendEvent door refuses them (AF9), so the
         *  consent/audit leg cannot be forged by a sibling store.
         *  EVENT_TRANSPORT_FAILOVER is deliberately absent — the
         *  transport layer appends it as linkage. */
        val CORE_EVENT_TYPES: Set<String> = setOf(
            EVENT_CREATED, EVENT_ACCEPTED, EVENT_ACCEPT_REFUSED, EVENT_STARTED,
            EVENT_FLOOR_GRANTED, EVENT_FLOOR_TAKEN, EVENT_PARTICIPANT_ADDED,
            EVENT_PARTICIPANT_REMOVED, EVENT_PAUSED, EVENT_BLOCKED, EVENT_STOPPED,
            EVENT_ENDED, EVENT_WATCH_ONLY, EVENT_RECORDING_SET, EVENT_CHAT,
            EVENT_FILE_CREATED, EVENT_FILE_STATE, EVENT_BLANK_SET, EVENT_BLANK_CLEARED,
            EVENT_INPUT_BLOCK_SET, EVENT_INPUT_BLOCK_CLEARED, EVENT_WATERMARK_SET,
            EVENT_WATERMARK_CLEARED, EVENT_CALL_STARTED, EVENT_CALL_ANSWERED,
            EVENT_CALL_ENDED
        )

        const val CALL_AUDIO = "audio"
        const val CALL_VIDEO = "video"
        val CALL_KINDS = setOf(CALL_AUDIO, CALL_VIDEO)

        const val CALL_RINGING = "ringing"
        const val CALL_ACTIVE = "active"
        const val CALL_ENDED = "ended"
        val CALL_STATES = setOf(CALL_RINGING, CALL_ACTIVE, CALL_ENDED)

        const val DIRECTION_TO_HOST = "to_host"
        const val DIRECTION_FROM_HOST = "from_host"
        val DIRECTIONS = setOf(DIRECTION_TO_HOST, DIRECTION_FROM_HOST)

        const val JOB_QUEUED = "queued"
        const val JOB_ACTIVE = "active"
        const val JOB_PAUSED = "paused"
        const val JOB_DONE = "done"
        const val JOB_FAILED = "failed"
        const val JOB_CANCELLED = "cancelled"
        val JOB_STATES = setOf(JOB_QUEUED, JOB_ACTIVE, JOB_PAUSED, JOB_DONE, JOB_FAILED, JOB_CANCELLED)
        private val JOB_TERMINAL = setOf(JOB_DONE, JOB_FAILED, JOB_CANCELLED)
        private val JOB_CANCELLABLE = setOf(JOB_QUEUED, JOB_ACTIVE, JOB_PAUSED)

        /** Schemes that name storage on the user's own device —
         *  the only uri schemes a RecordingRef may carry (D36:
         *  recording is stored locally, never a vendor cloud). */
        private val LOCAL_SCHEMES = setOf("file", "content")

        /** content: authorities that name ON-DEVICE media storage.
         *  D38 S3-AND F5: a content: uri is not automatically local
         *  — cloud document providers (Drive & friends) serve
         *  remote storage through content: uris, so only known
         *  on-device authorities pass. */
        private fun isLocalContentAuthority(authority: String): Boolean =
            authority == "media" ||
                authority.startsWith("com.android.providers.") ||
                authority == "com.android.externalstorage.documents"

        /**
         * True when [ref] is a remote reference. Allowlist-shaped
         * (D38 S3-AND F5): plain absolute/relative local paths
         * pass; file: uris pass only with an empty or localhost
         * authority; content: uris pass only from known on-device
         * authorities; a leading backslash (UNC \\server\share or
         * any backslash-rooted path), a protocol-relative //host
         * path, and every other scheme are remote.
         */
        fun isRemoteRef(ref: String): Boolean {
            val trimmed = ref.trim()
            if (trimmed.startsWith("//")) return true
            if (trimmed.startsWith("\\")) return true // UNC / backslash-rooted
            val schemeMatch = Regex("^([A-Za-z][A-Za-z0-9+.-]*):").find(trimmed) ?: return false
            val scheme = schemeMatch.groupValues[1].lowercase()
            if (scheme.length == 1) return false // drive letter, e.g. C:\recordings
            if (scheme !in LOCAL_SCHEMES) return true
            val rest = trimmed.substring(schemeMatch.value.length)
            if (scheme == "file" && rest.startsWith("//")) {
                val authority = rest.removePrefix("//").substringBefore('/').lowercase()
                return authority.isNotEmpty() && authority != "localhost"
            }
            if (scheme == "content") {
                val authority = rest.removePrefix("//").substringBefore('/').lowercase()
                return !isLocalContentAuthority(authority)
            }
            return false
        }
    }
}
