package io.agenticcontrol.app.server

/**
 * U4 — Per-session agent budgets + tripwires, Android mirror of the
 * Windows SessionBudget (Acp.Shared/Policy/SessionBudget.cs). Same
 * classes, same policy keys, same named defaults, same semantics:
 *
 *  * caps are counted PER SESSION (SessionManager holds one session;
 *    counters begin at start() and die at end() — budgets reset per
 *    session by construction);
 *  * caps are TOTAL POLICY CONTROL settings (RMM-07 pattern): the
 *    toggle "rmm.session_budget.enabled" is registered in the
 *    Android FeatureToggleRegistry seed (Rmm07Policy.kt, default ON)
 *    and each cap is the plain settings key
 *    "session_budget.cap.<class>", resolved through [capsProvider].
 *    PLATFORM DIFFERENCE (recorded, U4): the Android MCP server has
 *    no live ManagementPolicyEngine instance wired into its dispatch
 *    path today (the Rmm07Policy engine is a model other lanes
 *    consume), so the provider defaults to the named code defaults;
 *    wiring a live engine only changes this one lambda;
 *  * a cap breach is a TRIPWIRE: the session PAUSES through the
 *    existing pause path (SessionManager.pauseByBudget — presence
 *    pill, session_paused refusals, owner taps Resume) with the
 *    reason and numbers in a "budget_tripwire" session event and the
 *    tool audit. Never a silent continue, never a hard kill.
 *
 * Egress is counted where measurable: egress-class calls count
 * pre-execution, and the byte length of what a successful
 * egress-class call returned counts post-execution in McpCore.
 */
object SessionBudget {

    object Classes {
        const val TOTAL = "total"
        const val INPUT = "input"
        const val DELETIONS = "deletions"
        const val SENDING = "sending"
        const val EGRESS_CALLS = "egress_calls"
        const val EGRESS_BYTES = "egress_bytes"
        val ALL = listOf(TOTAL, INPUT, DELETIONS, SENDING, EGRESS_CALLS, EGRESS_BYTES)
    }

    /** Per-class caps for one session; a cap of 0 forbids the class
     *  outright. Defaults identical to the Windows named defaults. */
    data class Caps(
        val total: Long = DEFAULT_TOTAL,
        val input: Long = DEFAULT_INPUT,
        val deletions: Long = DEFAULT_DELETIONS,
        val sending: Long = DEFAULT_SENDING,
        val egressCalls: Long = DEFAULT_EGRESS_CALLS,
        val egressBytes: Long = DEFAULT_EGRESS_BYTES
    ) {
        fun capFor(cls: String): Long = when (cls) {
            Classes.TOTAL -> total
            Classes.INPUT -> input
            Classes.DELETIONS -> deletions
            Classes.SENDING -> sending
            Classes.EGRESS_CALLS -> egressCalls
            Classes.EGRESS_BYTES -> egressBytes
            else -> Long.MAX_VALUE
        }

        companion object {
            const val DEFAULT_TOTAL = 1000L
            const val DEFAULT_INPUT = 600L
            const val DEFAULT_DELETIONS = 25L
            const val DEFAULT_SENDING = 20L
            const val DEFAULT_EGRESS_CALLS = 200L
            const val DEFAULT_EGRESS_BYTES = 256L * 1024 * 1024

            fun policyKeyFor(cls: String) = "session_budget.cap.$cls"

            /** Resolve caps from an effective-policy settings map:
             *  "session_budget.cap.<class>" overrides the default;
             *  unparsable/negative values are ignored (the default
             *  stands) — same rule as the Windows resolver. */
            fun fromSettings(settings: Map<String, String>): Caps {
                fun v(cls: String, def: Long): Long =
                    settings[policyKeyFor(cls)]?.toLongOrNull()?.takeIf { it >= 0 } ?: def
                return Caps(
                    total = v(Classes.TOTAL, DEFAULT_TOTAL),
                    input = v(Classes.INPUT, DEFAULT_INPUT),
                    deletions = v(Classes.DELETIONS, DEFAULT_DELETIONS),
                    sending = v(Classes.SENDING, DEFAULT_SENDING),
                    egressCalls = v(Classes.EGRESS_CALLS, DEFAULT_EGRESS_CALLS),
                    egressBytes = v(Classes.EGRESS_BYTES, DEFAULT_EGRESS_BYTES)
                )
            }
        }
    }

    /** The policy seam: returns the caps for a new session, or null
     *  when policy disables session budgets. Default = enabled with
     *  the named default caps. */
    @Volatile
    var capsProvider: () -> Caps? = { Caps() }

    sealed class Verdict {
        object Allow : Verdict()
        data class Deny(val reason: String) : Verdict()
        data class TripPause(val cls: String, val count: Long, val cap: Long, val reason: String) : Verdict()
    }

    private val inputTools = setOf(
        "tap", "tap_point", "swipe", "press", "type_text", "launch_app"
    )
    // Sending/egress membership is DataFlows' — one source of
    // truth. This file carried its own copies of both sets until
    // 2026-11-22, drifted with the same Windows-mirror names
    // (file_read, send_message, …); see DataFlow.kt's note.
    private val sendingTools get() = DataFlows.sendingTools
    private val egressTools get() = DataFlows.egressTools

    fun classesFor(toolName: String): List<String> {
        val classes = mutableListOf(Classes.TOTAL)
        if (toolName in inputTools) classes += Classes.INPUT
        if (toolName.contains("delete")) classes += Classes.DELETIONS
        if (toolName in sendingTools) classes += Classes.SENDING
        if (toolName in egressTools) classes += Classes.EGRESS_CALLS
        return classes
    }

    fun isEgress(toolName: String): Boolean = toolName in egressTools

    // One live session at a time (SessionManager's own rule), so one
    // counter set, keyed by the session generation it began under.
    private var generation: Long = -1
    private var caps: Caps = Caps()
    private val counts = mutableMapOf<String, Long>()
    private var tripped = false
    private var tripReason: String? = null

    /** False when policy disabled the layer for the live session:
     *  checks then Allow without counting (a disabled budget must
     *  never deny). Distinct from "enabled but no session", which
     *  denies — an uncounted control call is exactly what the layer
     *  exists to prevent. */
    private var enabled = false

    @Synchronized
    fun beginSession(sessionGeneration: Long, sessionCaps: Caps) {
        enabled = true
        generation = sessionGeneration
        caps = sessionCaps
        counts.clear()
        tripped = false
        tripReason = null
    }

    @Synchronized
    fun disable() {
        enabled = false
        generation = -1
        counts.clear()
        tripped = false
        tripReason = null
    }

    @Synchronized
    fun endSession() {
        generation = -1
        counts.clear()
        tripped = false
        tripReason = null
    }

    /** Pre-execution check-and-count for the live session (the
     *  counters' own begun-generation is the key: SessionManager's
     *  presence generation bumps on pause/resume, and the budget
     *  must survive those transitions — counts stand across a
     *  resume, exactly as on Windows). A call that would pass any
     *  of its classes' caps trips; once tripped, checks deny as
     *  paused until the owner resumes. */
    @Synchronized
    fun checkAndCount(classes: List<String>): Verdict {
        if (!enabled) return Verdict.Allow
        if (generation < 0)
            return Verdict.Deny("budget: no budget counters for this session — call start_session first")
        if (tripped) return Verdict.Deny("session_paused: $tripReason")
        for (cls in classes) {
            val next = (counts[cls] ?: 0L) + 1
            val cap = caps.capFor(cls)
            if (next > cap) {
                tripped = true
                tripReason = "budget tripwire: session cap for '$cls' reached ($next > $cap) — " +
                    "session paused; the owner resumes it from the phone"
                return Verdict.TripPause(cls, next, cap, tripReason!!)
            }
        }
        for (cls in classes) counts[cls] = (counts[cls] ?: 0L) + 1
        return Verdict.Allow
    }

    /** Post-execution egress accounting; a cumulative byte crossing
     *  trips the pause for everything after this call. */
    @Synchronized
    fun noteEgressBytes(bytes: Long): Verdict {
        if (bytes <= 0 || generation < 0 || tripped) return Verdict.Allow
        val next = (counts[Classes.EGRESS_BYTES] ?: 0L) + bytes
        counts[Classes.EGRESS_BYTES] = next
        val cap = caps.capFor(Classes.EGRESS_BYTES)
        if (next > cap) {
            tripped = true
            tripReason = "budget tripwire: session cap for '${Classes.EGRESS_BYTES}' reached ($next > $cap) — " +
                "session paused; the owner resumes it from the phone " +
                "(the call that crossed the byte cap had already returned its payload; the pause applies from the next call)"
            return Verdict.TripPause(Classes.EGRESS_BYTES, next, cap, tripReason!!)
        }
        return Verdict.Allow
    }

    @Synchronized
    fun resume() {
        tripped = false
        tripReason = null
    }

    val isTripped: Boolean
        @Synchronized get() = tripped

    @Synchronized
    fun snapshot(): Map<String, Any> = mapOf(
        "caps" to Classes.ALL.associateWith { caps.capFor(it) },
        "counts" to Classes.ALL.associateWith { counts[it] ?: 0L },
        "tripped" to tripped,
        "tripReason" to (tripReason ?: "")
    )
}
