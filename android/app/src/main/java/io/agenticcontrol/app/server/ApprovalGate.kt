package io.agenticcontrol.app.server

/**
 * Approval gates (0.4.0): the host-enforced "ask first" layer. Every
 * consequential action class has an owner-set policy — Auto (run),
 * Ask First (the phone shows Approve/Deny and the action waits), or
 * Blocked (refused outright). The agent cannot change these, cannot
 * see a way around them, and a deny or a 30-second timeout comes
 * back as a clean tool error. Pure policy here; persistence in
 * ApprovalSettings, the prompt UI in ApprovalOverlay.
 */
object ApprovalGate {

    enum class ActionClass(val label: String, val blurb: String) {
        LAUNCH_APP("Open an app", "Starting an app the agent names."),
        CLIPBOARD("Clipboard", "Reading or setting the clipboard."),
        SHELL("Shell commands", "Running a shell command over the wireless debugging channel."),
        SETTINGS_CHANGE("Change settings", "Writing a system setting (with read-back)."),
        PACKAGE_CHANGE("App changes", "Installing, removing, or changing apps."),
        FILE_WRITE("Write a file", "Writing a file into the app's agent-files folder."),
        // W10 (V3-F2): an action asked from Agent chat (A17). The
        // blurb is the chat truth: the ask came from chat, and the
        // gate — never chat — is what approves.
        CHAT_REQUEST("Act from Agent chat", "Your AI asked from Agent chat to act. Approving here lets it use its ordinary tools; chat itself cannot approve.")
    }

    enum class Policy(val label: String) {
        AUTO("Auto"), ASK_FIRST("Ask first"), BLOCKED("Blocked")
    }

    enum class Decision { ALLOW, ASK, DENY }

    fun decide(policy: Policy): Decision = when (policy) {
        Policy.AUTO -> Decision.ALLOW
        Policy.ASK_FIRST -> Decision.ASK
        Policy.BLOCKED -> Decision.DENY
    }

    /**
     * Shipped defaults: opening an app is low-risk and already
     * cap-gated, so it runs; everything that reads private data,
     * executes code, or changes the device asks first.
     */
    val DEFAULTS: Map<ActionClass, Policy> = mapOf(
        ActionClass.LAUNCH_APP to Policy.AUTO,
        ActionClass.CLIPBOARD to Policy.ASK_FIRST,
        ActionClass.SHELL to Policy.ASK_FIRST,
        ActionClass.SETTINGS_CHANGE to Policy.ASK_FIRST,
        ActionClass.PACKAGE_CHANGE to Policy.ASK_FIRST,
        ActionClass.FILE_WRITE to Policy.ASK_FIRST,
        ActionClass.CHAT_REQUEST to Policy.ASK_FIRST
    )

    fun defaultPolicy(actionClass: ActionClass): Policy =
        DEFAULTS[actionClass] ?: Policy.ASK_FIRST

    /** How long an approval prompt waits before it counts as a no. */
    const val TIMEOUT_MS = 30_000L
}

/**
 * The approval-pending latch (bd-and-core F2 fix, 2026-11-22):
 * while an Ask-First prompt is on screen, EVERY drive and observe
 * tool refuses and capture suspends — the HTTP server runs calls
 * concurrently, so without this latch a second call from the same
 * agent could tap the prompt's Approve button with a dispatched
 * gesture and approve its own gated action. The latch is set by
 * ApprovalOverlay for exactly the prompt's lifetime. The Approve
 * tap guard is the second leg: a tap landing within
 * [TOUCH_GUARD_MS] of the agent's last dispatched gesture is not a
 * human decision and is ignored (the prompt stays up for the
 * human; the timeout still counts it as a no).
 */
object ApprovalPending {
    // W12-DS P2-F1 fix: the latch was a single boolean, so two
    // concurrent Ask-First prompts shared one flag and the first
    // prompt's finally cleared it while the second prompt was
    // still on screen. The latch is now a REFCOUNT: pending while
    // depth > 0; every begin() must be balanced by exactly one
    // end(), and end() never drives the depth below zero.
    private val depth = java.util.concurrent.atomic.AtomicInteger(0)

    val isPending: Boolean get() = depth.get() > 0

    /** Current latch depth (test/diagnostic surface). */
    fun pendingDepth(): Int = depth.get()

    fun begin() { depth.incrementAndGet() }
    fun end() { depth.updateAndGet { if (it > 0) it - 1 else 0 } }

    const val TOUCH_GUARD_MS = 1_500L

    /** True when an Approve tap at [nowMs] may count as the
     *  human's: strictly outside the guard window after the last
     *  agent-dispatched gesture. */
    fun approveTapAllowed(nowMs: Long, lastAgentGestureAtMs: Long): Boolean =
        nowMs - lastAgentGestureAtMs > TOUCH_GUARD_MS

    /** The refusal every tool returns while a prompt is up. */
    const val REFUSAL =
        "An approval prompt is on the phone's screen right now. All tools pause until " +
            "the user answers it — an agent cannot act (or approve its own prompt) meanwhile."
}
