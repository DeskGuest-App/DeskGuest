package io.agenticcontrol.app.session

import io.agenticcontrol.app.roster.RosterStore

/**
 * The session terminal channel (Block F, Android mirror of the
 * Windows TerminalService): a shell that exists only INSIDE a live
 * session. Only the floor holder's keystrokes reach it — the host
 * included (a host who gave the floor away takes it back first);
 * a watcher never writes; an AI writes only when its pairing scope
 * carries the named `terminal` capability (default OFF, D9). Its
 * output is part of the session record (terminal_opened /
 * terminal_closed events), and it dies with the session.
 *
 * The platform shell sits behind [Sink] (Android's is the device
 * shell bridge; the JVM suite drives a fake).
 */
interface TerminalSink {
    fun start(terminalId: String)
    fun write(terminalId: String, text: String)
    fun close(terminalId: String)
}

data class TerminalInfo(
    val id: String,
    val sessionId: String,
    val openedByUserId: String,
    val openedUtcMs: Long,
    val isOpen: Boolean,
    val outputLines: Int
)

class TerminalService(
    private val sessions: SessionStore,
    private val roster: RosterStore,
    private val aiTerminalCapability: (scopeId: String, userId: String) -> Boolean = { _, _ -> false },
    private val sink: TerminalSink? = null,
    private val nowMs: () -> Long = { System.currentTimeMillis() }
) {
    private class State(
        val id: String,
        val sessionId: String,
        val openedBy: String,
        val openedUtcMs: Long,
        var closed: Boolean = false,
        val output: MutableList<String> = mutableListOf()
    )

    private val terminals = LinkedHashMap<String, State>()
    private var counter = 0

    @Synchronized
    fun open(sessionId: String, actorUserId: String): Pair<TerminalInfo?, String> {
        val session = sessions.session(sessionId)
            ?: return null to "terminal refused: no such session (a terminal exists only inside a session)"
        if (session.state != SessionStore.STATE_ACTIVE)
            return null to "terminal refused: session is ${session.state} (a terminal lives only in an active session)"
        val actor = sessions.participants(sessionId).firstOrNull { it.userId == actorUserId }
            ?: return null to "terminal refused: the opener is not a participant of this session"
        if (actor.role != SessionStore.ROLE_HOST && actor.floor != SessionStore.FLOOR_HOLDS)
            return null to "terminal refused: only the host or the floor holder may open the terminal"
        terminals.values.firstOrNull { it.sessionId == sessionId && !it.closed }?.let {
            return info(it) to "terminal already open on this session"
        }
        val state = State("term-${++counter}", sessionId, actorUserId, nowMs())
        terminals[state.id] = state
        try { sink?.start(state.id) } catch (_: Exception) { }
        sessions.appendEvent(sessionId, "terminal_opened", actorUserId,
            "terminal ${state.id} opened (output is part of the session record)")
        return info(state) to "terminal open"
    }

    @Synchronized
    fun write(terminalId: String, actorUserId: String, text: String): Pair<Boolean, String> {
        val state = terminals[terminalId]
        if (state == null || state.closed) return false to "write refused: no open terminal by that id"
        val session = sessions.session(state.sessionId)
        if (session == null || session.state != SessionStore.STATE_ACTIVE) {
            reap(state)
            return false to "write refused: the session is over — the terminal died with it"
        }
        val actor = sessions.participants(state.sessionId).firstOrNull { it.userId == actorUserId }
            ?: return false to "write refused: not a participant of this session"
        // Only the floor holder's keystrokes reach the terminal —
        // the host included: a host who has given the floor away
        // takes it back first (a host act), never types around it.
        if (actor.floor != SessionStore.FLOOR_HOLDS)
            return false to "write refused: only the floor holder's keystrokes reach the terminal"
        val user = roster.user(actorUserId)
        if (user != null && user.kind == "ai" && !aiTerminalCapability(session.scopeId, actorUserId))
            return false to "write refused: this AI's pairing does not carry the terminal capability (D9 — default OFF for AIs)"
        try { sink?.write(terminalId, text) } catch (_: Exception) { }
        sessions.appendEvent(state.sessionId, "terminal_input", actorUserId,
            "keystrokes delivered (${text.length} chars; content never recorded)")
        return true to "delivered"
    }

    @Synchronized
    fun appendOutput(terminalId: String, line: String): Boolean {
        val state = terminals[terminalId] ?: return false
        if (state.closed) return false
        state.output.add(line)
        return true
    }

    @Synchronized
    fun output(terminalId: String): List<String> =
        terminals[terminalId]?.output?.toList() ?: emptyList()

    @Synchronized
    fun close(terminalId: String, actorUserId: String): Pair<Boolean, String> {
        val state = terminals[terminalId]
        if (state == null || state.closed) return false to "no open terminal by that id"
        val actor = sessions.participants(state.sessionId).firstOrNull { it.userId == actorUserId }
        if (actor == null || (actor.role != SessionStore.ROLE_HOST && actor.floor != SessionStore.FLOOR_HOLDS))
            return false to "close refused: only the host or the floor holder closes the terminal"
        reap(state)
        sessions.appendEvent(state.sessionId, "terminal_closed", actorUserId, "terminal ${state.id} closed")
        return true to "terminal closed"
    }

    @Synchronized
    fun openTerminalFor(sessionId: String): TerminalInfo? {
        val session = sessions.session(sessionId)
        if (session == null || session.state != SessionStore.STATE_ACTIVE) return null
        return terminals.values.firstOrNull { it.sessionId == sessionId && !it.closed }?.let { info(it) }
    }

    @Synchronized
    fun reapEnded(): Int {
        var reaped = 0
        for (state in terminals.values) {
            if (state.closed) continue
            val session = sessions.session(state.sessionId)
            if (session == null || session.state == SessionStore.STATE_ENDED) {
                reap(state)
                sessions.appendEvent(state.sessionId, "terminal_closed", state.openedBy,
                    "terminal ${state.id} died with the session")
                reaped++
            }
        }
        return reaped
    }

    private fun reap(state: State) {
        state.closed = true
        try { sink?.close(state.id) } catch (_: Exception) { }
    }

    private fun info(state: State) = TerminalInfo(
        state.id, state.sessionId, state.openedBy, state.openedUtcMs, !state.closed, state.output.size)
}
