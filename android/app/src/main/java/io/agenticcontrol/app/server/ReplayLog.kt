package io.agenticcontrol.app.server

/**
 * Session replay data (SPEC §7.6, FEATURES §7) — BD-XCHECK owed
 * item, built 2026-11-22. The `session_replay_data` tool's source:
 * an append-only, bounded, in-memory record of the session events
 * this process has emitted (session start/pause/resume/end, budget
 * tripwires, approval outcomes, clipboard indicators), each with a
 * timestamp. It is fed by a SessionEvents listener installed once
 * by ControlService ([attach]); it never alters or deletes an entry
 * once recorded — when the bound is reached the OLDEST entries fall
 * off and the drop count is reported with the data, never silently.
 *
 * Honest limits: the record covers this process's lifetime only
 * (the durable evidence store remains the encrypted audit log,
 * which the owner exports in-app — §4.6); tool-call detail rides
 * the audit sink, not this log. Pure JVM — runs in the JVM suite.
 */
object ReplayLog {

    data class Entry(val atMs: Long, val state: String, val detail: Map<String, String>)

    const val MAX_ENTRIES = 2_000

    private val lock = Any()
    private val entries = mutableListOf<Entry>()
    private var dropped = 0

    @Volatile
    private var attached = false

    /** Install the SessionEvents listener (idempotent). */
    fun attach() {
        if (attached) return
        attached = true
        SessionEvents.addListener { event ->
            record(
                event.state,
                event.detail.mapValues { (_, v) -> v?.toString() ?: "" }
            )
        }
    }

    fun record(state: String, detail: Map<String, String> = emptyMap(), atMs: Long = System.currentTimeMillis()) {
        synchronized(lock) {
            entries.add(Entry(atMs, state, detail))
            while (entries.size > MAX_ENTRIES) {
                entries.removeAt(0)
                dropped++
            }
        }
    }

    fun snapshot(): List<Entry> = synchronized(lock) { entries.toList() }

    fun droppedCount(): Int = synchronized(lock) { dropped }

    /** Test-only reset. */
    fun clearForTest() {
        synchronized(lock) {
            entries.clear()
            dropped = 0
        }
    }
}
