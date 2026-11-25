package io.agenticcontrol.app.server

import java.util.concurrent.atomic.AtomicLong

/**
 * Drive-session state (SPEC §7): a session is the bounded stretch in
 * which an agent may act. Presence (banner, glow, STOP) keys off this
 * state, and the audit log records against it. One session at a time;
 * starting a second while one runs is refused, never stacked.
 *
 * 0.4.0: the state machine gains PAUSED_BY_USER (physical
 * touch-to-yield: the owner grabbing the phone pauses the agent,
 * never silently), a monotonically increasing [generation] the
 * presence layer keys its window lifecycle to, the agent's current
 * intent line, and the fresh-snapshot rule — after the owner has had
 * the screen, the agent must look again before it may act.
 */
object SessionManager {

    enum class State { IDLE, ACTIVE, PAUSED_BY_USER }

    data class Session(
        val agentName: String,
        val startedAtMs: Long,
        val generation: Long,
        @Volatile var actions: Int = 0,
        @Volatile var lastAction: String = "",
        @Volatile var intent: String = "",
        /**
         * bd-and-core F4 fix (2026-11-22): the pairing that OPENED
         * this session (its bearer-token key, never logged). Drive
         * tools refuse any other pairing; end_session over the
         * channel is the owner pairing's alone (on-device STOP
         * stays universal). Null = a session opened without a
         * pairing context (host-side / legacy test paths), which
         * binds to no pairing and is checked by no pairing.
         */
        val pairingKey: String? = null
    )

    /** Bumped on every presence-relevant transition (start, pause,
     *  resume, end). Presence windows belong to exactly one
     *  generation; anything painted for an older one is swept. */
    val generation = AtomicLong(0)

    @Volatile
    private var current: Session? = null

    @Volatile
    var state: State = State.IDLE
        private set

    /** True after a resume until the agent takes a fresh snapshot:
     *  the screen may have changed under the owner's hands. */
    @Volatile
    private var freshSnapshotRequired = false

    @Volatile
    var lastAgentGestureAtMs: Long = 0
        private set

    val active: Session? get() = current
    val isActive: Boolean get() = current != null && state == State.ACTIVE
    val isPaused: Boolean get() = current != null && state == State.PAUSED_BY_USER
    val isOpen: Boolean get() = current != null
    val currentIntent: String get() = current?.intent ?: ""

    /** U4: why the session is budget-paused, when it is. Set only by
     *  [pauseByBudget]; cleared by resume/end/start. The pause state
     *  itself is PAUSED_BY_USER's machinery (presence pill + Resume)
     *  — a tripwire pause IS an owner-resume pause — but the reason
     *  is carried separately so refusals and the status surface can
     *  name the budget numbers instead of claiming the user touched
     *  the phone. */
    @Volatile
    var budgetPauseReason: String? = null
        private set

    /**
     * FR-122 (Android mirror of the Windows FR-121 fail-closed
     * adjudication, Lane W76): the presence Box names the SPECIFIC
     * driver, so a session with no driver name is a NAMED DEFECT,
     * never a generic rendering. [start] refuses a blank/whitespace
     * name outright — no session opens, no presence renders — and
     * the refusal is recorded here and emitted as a session event
     * under this name.
     */
    const val DEFECT_DRIVER_NAME_MISSING = "driver_name_missing"

    /** True when [name] cannot name a specific driver (null, blank,
     *  or whitespace only). Pure: the presence renderer guards on
     *  the same predicate SessionManager refuses on. */
    fun isDriverNameMissing(name: String?): Boolean = name.isNullOrBlank()

    /** The defect recorded by the most recent refused [start], or
     *  null when the last start attempt was not refused for a
     *  defect. Cleared by a successful start. */
    @Volatile
    var lastStartDefect: String? = null
        private set

    @Synchronized
    fun start(agentName: String, pairingKey: String? = null): Session? {
        // FR-122 fail-closed: an unnamed session start is refused
        // as the driver_name_missing defect (see above) — presence
        // must never render a generic or blank driver name.
        if (isDriverNameMissing(agentName)) {
            lastStartDefect = DEFECT_DRIVER_NAME_MISSING
            SessionEvents.emit(
                "session_start_refused",
                mapOf("defect" to DEFECT_DRIVER_NAME_MISSING)
            )
            return null
        }
        if (current != null) return null
        lastStartDefect = null
        val session = Session(
            agentName.trim(), System.currentTimeMillis(), generation.incrementAndGet(),
            pairingKey = pairingKey
        )
        // W12-DS P1-F14: publish state BEFORE current, and require
        // ACTIVE positively in driveRefusal — a concurrent drive
        // call must never observe a session whose state is not yet
        // ACTIVE.
        state = State.ACTIVE
        current = session
        freshSnapshotRequired = false
        budgetPauseReason = null
        // U4: fresh budget counters for the new session (null caps =
        // policy disabled the layer; dispatch then never counts).
        SessionBudget.capsProvider()?.let { SessionBudget.beginSession(session.generation, it) }
            ?: SessionBudget.disable()
        notifyChanged()
        SessionEvents.emit("session_started", mapOf("agent" to session.agentName))
        return session
    }

    @Synchronized
    fun end(): Session? {
        val ended = current
        current = null
        state = State.IDLE
        freshSnapshotRequired = false
        budgetPauseReason = null
        SessionBudget.endSession()
        if (ended != null) {
            generation.incrementAndGet()
            notifyChanged()
            SessionEvents.emit(
                "session_ended",
                mapOf("agent" to ended.agentName, "actions" to ended.actions)
            )
        }
        return ended
    }

    /**
     * The owner physically touched the screen: pause now. Pending
     * work is flushed by refusal — every drive call checks
     * [driveRefusal] before acting, so a paused session cannot act.
     * Returns true when this call actually paused a live session.
     */
    @Synchronized
    fun pauseByUser(): Boolean {
        if (current == null || state != State.ACTIVE) return false
        state = State.PAUSED_BY_USER
        generation.incrementAndGet()
        notifyChanged()
        SessionEvents.emit("paused_by_user", mapOf("agent" to current?.agentName))
        return true
    }

    /**
     * U4 tripwire act: a session budget cap (or the budget layer's
     * verdict) paused the session. Same pause state the owner's
     * touch produces — presence-visible, owner-resumed, never an
     * ending — with the budget reason recorded and emitted as a
     * "budget_tripwire" session event carrying the numbers.
     * Returns true when this call actually paused a live session.
     */
    @Synchronized
    fun pauseByBudget(reason: String): Boolean {
        if (current == null || state != State.ACTIVE) return false
        state = State.PAUSED_BY_USER
        budgetPauseReason = reason
        generation.incrementAndGet()
        notifyChanged()
        SessionEvents.emit(
            "budget_tripwire",
            mapOf("agent" to current?.agentName, "reason" to reason)
        )
        return true
    }

    /** The owner tapped Resume on the paused pill. */
    @Synchronized
    fun resume(): Boolean {
        if (current == null || state != State.PAUSED_BY_USER) return false
        state = State.ACTIVE
        budgetPauseReason = null
        SessionBudget.resume()
        freshSnapshotRequired = true
        generation.incrementAndGet()
        notifyChanged()
        SessionEvents.emit("session_resumed", mapOf("agent" to current?.agentName))
        return true
    }

    /** An on-device STOP (overlay button, home screen, QS tile) is
     *  ending the session: tell SSE clients it was the user, then end
     *  through the normal path (which emits session_ended). */
    // W12-DS P1-F9: synchronized + capture-once — the announced
    // session and the ended session are the same instance.
    @Synchronized
    fun stopByUser() {
        val session = current ?: return
        SessionEvents.emit("stopped_by_user", mapOf("agent" to session.agentName))
        end()
    }

    /** Physical-touch signal from the Android layer (overlay watcher
     *  or accessibility touch-interaction event). The Android layer
     *  applies its own agent-gesture guard before calling this. */
    fun onUserTouchSignal() {
        pauseByUser()
    }

    /** The agent stated what it is about to do (banner intent line). */
    fun setIntent(text: String) {
        val session = current ?: return
        val trimmed = text.trim().take(120)
        if (session.intent != trimmed) {
            session.intent = trimmed
            notifyChanged()
        }
    }

    // W12-DS P1-F18: synchronized increment (was a racy
    // read-modify-write on a volatile Int).
    @Synchronized
    fun noteAction(what: String) {
        current?.let {
            it.actions += 1
            it.lastAction = what
        }
    }

    /** The accessibility layer dispatches a gesture for the agent:
     *  stamps the time so a physical-touch signal arriving in the
     *  same instant is not mistaken for the owner taking over. */
    fun noteAgentGesture() {
        lastAgentGestureAtMs = System.currentTimeMillis()
    }

    /** A snapshot was just taken: the agent is looking at the screen
     *  as it is now, so the post-resume freshness rule is satisfied. */
    fun noteSnapshotTaken() {
        freshSnapshotRequired = false
    }

    /** W12-DS P1-F8: generation-keyed form — a snapshot that
     *  started before a pause/resume/new session (older
     *  generation) must NOT clear the fresh-snapshot requirement
     *  of the current generation. Async capture paths pass the
     *  generation captured when the snapshot started. */
    fun noteSnapshotTaken(genAtStart: Long) {
        if (generation.get() == genAtStart) freshSnapshotRequired = false
    }

    val needsFreshSnapshot: Boolean get() = freshSnapshotRequired

    /**
     * Why a drive tool must refuse right now, or null when it may
     * run. Checked by every drive tool before it acts: no session,
     * a paused session, and the post-resume stale screen all refuse
     * in plain words — nothing queues silently behind the owner.
     */
    /** W13 P1-F6: the no-arg form is the UNBOUND caller — it may
     *  drive only an unbound session. A session bound to a pairing
     *  refuses a caller that cannot name its key (the MCP choke
     *  point always passes the real key; host-side paths that carry
     *  no pairing get the refusal, not silent passage). */
    fun driveRefusal(): String? {
        val session = current
        if (session != null && session.pairingKey != null) {
            return "This drive session belongs to a pairing (${session.agentName}); " +
                "a caller without a pairing key cannot drive inside it."
        }
        return driveRefusal(null)
    }

    /**
     * As [driveRefusal], with the CALLING pairing's key (bd-and-core
     * F4): a session bound to a pairing refuses every other pairing,
     * so presence never names agent A while agent B drives. A null
     * caller key (host-side paths that carry no pairing) skips the
     * binding check; the MCP choke point always passes the real key.
     */
    fun driveRefusal(callerPairingKey: String?): String? {
        // Driving lockout (SPEC §7.7, BD-XCHECK owed item): the
        // Android layer installs a detector provider; while it
        // reports a driving state every drive tool refuses, while
        // voice-grade tools (notify_user — not a drive tool) remain.
        val drivingRefusal =
            io.agenticcontrol.app.safety.DrivingStateHolder.currentRefusal()
        val session = current
        return when {
            session == null -> "No drive session is open — call start_session first."
            // FR-122 fail-closed (defense in depth): a session that
            // somehow exists with no driver name is the
            // driver_name_missing defect — it never drives.
            isDriverNameMissing(session.agentName) ->
                "Refused ($DEFECT_DRIVER_NAME_MISSING): this session has no driver " +
                    "name, so drive tools refuse. Presence must name the specific " +
                    "driver; end the session and pair again with a named agent."
            // bd-and-core F2: while an approval prompt is up, no
            // drive tool runs — the agent cannot tap its own Approve.
            ApprovalPending.isPending -> ApprovalPending.REFUSAL
            session.pairingKey != null && callerPairingKey != null &&
                session.pairingKey != callerPairingKey ->
                "This drive session belongs to another pairing (${session.agentName}); " +
                    "your pairing cannot drive inside it. Presence names the session's owner."
            // bd-and-core F5: presence is a PRECONDITION for control.
            // When the Android layer's provider is installed, a
            // session whose STOP box is not attached for the current
            // generation refuses every drive tool — no glow, no box,
            // no STOP on screen means no driving, honestly named.
            // W12-DS P1-F19: providers read ONCE into locals and
            // invoked inside try/catch — a provider nulled or
            // throwing mid-teardown fails CLOSED, never NPEs.
            state == State.ACTIVE && !presenceStopOk() ->
                "Presence is not showing on the phone (the STOP box is not attached), " +
                    "so drive tools refuse. The user can check the overlay/accessibility " +
                    "state in the app; control resumes when presence is on screen."
            // W7 (§2 self-test): presence that failed its
            // draw-verify blocks driving — it is not decoration.
            state == State.ACTIVE && !presenceSelfTestOk() ->
                "Presence failed its self-test on the phone (the box, ring, or glow " +
                    "did not draw), so drive tools refuse until presence can be shown."
            // W12-DS P1-F14: positive ACTIVE requirement — any
            // non-ACTIVE, non-paused state refuses.
            state != State.ACTIVE && state != State.PAUSED_BY_USER ->
                "The session is not active (state=$state), so drive tools refuse."
            state == State.PAUSED_BY_USER && budgetPauseReason != null ->
                "PAUSED (budget tripwire): $budgetPauseReason. The session is paused until the user " +
                    "taps Resume on the phone (or STOP to end it). Do not retry drive tools until then."
            state == State.PAUSED_BY_USER ->
                "PAUSED: the user took over the phone. The session is paused until the user " +
                    "taps Resume on the phone (or STOP to end it). Do not retry drive tools until then."
            drivingRefusal != null -> drivingRefusal
            freshSnapshotRequired ->
                "The user had the phone and the screen may have changed. Take a fresh snapshot before acting."
            else -> null
        }
    }

    /** Why an observe tool must refuse right now, or null. Capture
     *  suspends entirely while the owner has taken over (takeover
     *  privacy): while paused, the agent does not watch. */
    /** W12-DS P1-F19 helpers: single local read of each volatile
     *  provider; absent provider = check does not apply (named seam
     *  in the provider KDocs); throwing provider = fail closed. */
    private fun presenceStopOk(): Boolean {
        val provider = presenceStopAttached ?: return true
        return try { provider.invoke(generation.get()) } catch (_: Exception) { false }
    }

    private fun presenceSelfTestOk(): Boolean {
        val provider = presenceSelfTestPassed ?: return true
        // W13 P1-F4 remainder closed: the provider is keyed by the
        // CURRENT generation — a self-test verdict earned for an
        // older generation's windows does not carry over.
        return try { provider.invoke(generation.get()) } catch (_: Exception) { false }
    }

    fun observeRefusal(): String? = when {
        // bd-and-core F2: capture suspends while an approval prompt
        // is up, so the agent cannot aim a tap at the prompt from a
        // fresh screenshot either.
        ApprovalPending.isPending -> ApprovalPending.REFUSAL
        // FR-122 fail-closed: an unnamed session (driver_name_missing
        // defect) is never watched either.
        current != null && isDriverNameMissing(current?.agentName) ->
            "Refused ($DEFECT_DRIVER_NAME_MISSING): this session has no driver " +
                "name, so capture refuses. End the session and pair again with " +
                "a named agent."
        current != null && state == State.PAUSED_BY_USER ->
            "PAUSED: the user took over the phone. Capture is suspended until the user taps Resume."
        // W12-DS P1-F3: capture during an ACTIVE session carries
        // the SAME presence precondition as driving — no watching
        // with no Box/Glow/STOP on screen.
        current != null && state == State.ACTIVE && !presenceStopOk() ->
            "Presence is not showing on the phone (the STOP box is not attached), so capture refuses."
        current != null && state == State.ACTIVE && !presenceSelfTestOk() ->
            "Presence failed its self-test on the phone, so capture refuses until presence can be shown."
        else -> null
    }

    /**
     * bd-and-core F5 seam: the Android presence layer installs this
     * provider (generation -> STOP box attached for that
     * generation?). Null in the JVM suite and wherever presence is
     * not hosted: the check then does not apply (named here, never
     * silently claimed). Installed by PresenceOverlay.watch.
     */
    @Volatile
    var presenceStopAttached: ((Long) -> Boolean)? = null

    /**
     * W7 seam (design record §2, presence self-test): the Android
     * presence layer installs this provider with the result of its
     * draw-verify (all three elements drawn + STOP present). When
     * installed and false, drive tools refuse — a session whose
     * presence cannot be drawn does not drive. Null in the JVM
     * suite and wherever presence is not hosted: the check then
     * does not apply (named here, never silently claimed).
     * Installed by PresenceOverlay.watch.
     */
    @Volatile
    var presenceSelfTestPassed: ((Long) -> Boolean)? = null

    /** The live session's owning pairing key, or null when no
     *  session is open or the session is unbound (bd-and-core F4). */
    val activePairingKey: String? get() = current?.pairingKey

    /**
     * bd-and-core F3 revalidation: a drive/shell action that slept
     * or blocked (glide, approval wait) re-checks BEFORE it acts.
     * Returns a refusal when the session ended, paused, was
     * replaced, or any drive refusal now applies — the in-flight
     * action must NOT land. [genAtEntry] is [generation] captured
     * when the tool call began.
     */
    fun refusalIfChangedSince(genAtEntry: Long, callerPairingKey: String? = null): String? {
        if (current == null) return "The session ended while the action was in flight — it was NOT performed."
        if (generation.get() != genAtEntry)
            return "The session changed while the action was in flight (STOP, pause, resume, or a new session) — the action was NOT performed. Take a fresh snapshot and re-check."
        return driveRefusal(callerPairingKey)
    }

    /** End the live session IF it belongs to [pairingKey]
     *  (bd-and-core F4: revoke / access downgrade hook). Returns
     *  true when a session was ended. */
    @Synchronized
    fun endIfOwnedBy(pairingKey: String): Boolean {
        val session = current ?: return false
        if (session.pairingKey != pairingKey) return false
        end()
        return true
    }

    /**
     * Change listeners. Presence registers here so the banner, glow
     * and STOP appear the moment a session opens and clear the moment
     * it ends — synchronously, in the session's own call stack —
     * instead of depending on a polling loop noticing the change. A
     * listener that throws must never break the session machinery.
     */
    private val listeners = mutableListOf<(Session?) -> Unit>()

    fun addListener(listener: (Session?) -> Unit) {
        synchronized(listeners) { listeners.add(listener) }
    }

    /** W13 P1-F13: listeners can be REMOVED (a prompt/overlay that
     *  registered for its lifetime must not be called forever), and
     *  a listener may ask for an immediate REPLAY of the current
     *  session so a late registrant converges without waiting for
     *  the next transition. */
    fun removeListener(listener: (Session?) -> Unit) {
        synchronized(listeners) { listeners.remove(listener) }
    }

    fun addListenerWithReplay(listener: (Session?) -> Unit) {
        addListener(listener)
        try { listener(current) } catch (_: Exception) { }
    }

    fun notifyChanged() {
        val session = current
        val snapshot: List<(Session?) -> Unit>
        synchronized(listeners) { snapshot = listeners.toList() }
        snapshot.forEach { listener ->
            try {
                listener(session)
            } catch (_: Exception) {
            }
        }
    }
}
