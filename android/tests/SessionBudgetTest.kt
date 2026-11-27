import io.deskguest.app.server.SessionBudget
import io.deskguest.app.server.SessionManager

/**
 * U4 regression tests (Android mirror): per-session budgets +
 * tripwires. Cap classes, trip-pauses-session (not kill), deny as
 * paused, per-session reset, egress byte accounting, policy-key
 * resolution, and the McpCore-facing pause surface on
 * SessionManager (pauseByBudget / budget-aware drive refusal /
 * owner resume clearing the trip).
 */
private var failures = 0

private fun check(name: String, condition: Boolean) {
    if (condition) println("PASS  $name")
    else {
        println("FAIL  $name")
        failures++
    }
}

private fun tinyCaps(
    total: Long = 100, input: Long = 100, deletions: Long = 100,
    sending: Long = 100, egressCalls: Long = 100, egressBytes: Long = Long.MAX_VALUE
) = SessionBudget.Caps(total, input, deletions, sending, egressCalls, egressBytes)

fun main() {
    SessionManager.end()
    SessionBudget.capsProvider = { SessionBudget.Caps() }

    // --- classifier ---
    check("classifier: tap is input", SessionBudget.Classes.INPUT in SessionBudget.classesFor("tap"))
    check("classifier: type_text is input", SessionBudget.Classes.INPUT in SessionBudget.classesFor("type_text"))
    check("classifier: file_delete is deletions", SessionBudget.Classes.DELETIONS in SessionBudget.classesFor("file_delete"))
    check("classifier: screenshot is egress", SessionBudget.Classes.EGRESS_CALLS in SessionBudget.classesFor("screenshot"))
    check("classifier: clipboard_get is egress", SessionBudget.Classes.EGRESS_CALLS in SessionBudget.classesFor("clipboard_get"))
    check("classifier: device_info is egress (its result carries device data out)",
        SessionBudget.classesFor("device_info") ==
            listOf(SessionBudget.Classes.TOTAL, SessionBudget.Classes.EGRESS_CALLS))

    // --- policy-key resolution ---
    val resolved = SessionBudget.Caps.fromSettings(mapOf(
        "session_budget.cap.deletions" to "3",
        "session_budget.cap.input" to "not-a-number",
        "session_budget.cap.sending" to "-5"
    ))
    check("policy: deletions cap resolves", resolved.deletions == 3L)
    check("policy: unparsable ignored, default stands", resolved.input == SessionBudget.Caps.DEFAULT_INPUT)
    check("policy: negative ignored, default stands", resolved.sending == SessionBudget.Caps.DEFAULT_SENDING)

    // --- counter: cap hit trips with class + numbers ---
    SessionBudget.beginSession(1, tinyCaps(deletions = 2))
    val del = listOf(SessionBudget.Classes.TOTAL, SessionBudget.Classes.DELETIONS)
    check("count 1 allowed", SessionBudget.checkAndCount(del) is SessionBudget.Verdict.Allow)
    check("count 2 allowed", SessionBudget.checkAndCount(del) is SessionBudget.Verdict.Allow)
    val trip = SessionBudget.checkAndCount(del)
    check("count 3 trips", trip is SessionBudget.Verdict.TripPause)
    if (trip is SessionBudget.Verdict.TripPause) {
        check("trip names the class", trip.cls == SessionBudget.Classes.DELETIONS)
        check("trip carries numbers", trip.count == 3L && trip.cap == 2L)
        check("trip reason says paused", trip.reason.contains("paused"))
    }
    val after = SessionBudget.checkAndCount(del)
    check("after trip: denies as paused",
        after is SessionBudget.Verdict.Deny && after.reason.contains("session_paused"))
    SessionBudget.resume()
    check("resume: counts stand, trips again",
        SessionBudget.checkAndCount(del) is SessionBudget.Verdict.TripPause)
    SessionBudget.endSession()

    // --- reset per session ---
    SessionBudget.beginSession(2, tinyCaps(total = 1))
    check("new session: first call allowed",
        SessionBudget.checkAndCount(listOf(SessionBudget.Classes.TOTAL)) is SessionBudget.Verdict.Allow)
    check("snapshot counts are per-session",
        (SessionBudget.snapshot()["counts"] as Map<*, *>)[SessionBudget.Classes.TOTAL] == 1L)
    SessionBudget.endSession()

    // --- disabled layer never denies ---
    SessionBudget.disable()
    check("disabled: allows without counting",
        SessionBudget.checkAndCount(del) is SessionBudget.Verdict.Allow)

    // --- egress bytes ---
    SessionBudget.beginSession(3, tinyCaps(egressBytes = 10))
    check("egress 6 of 10 allowed", SessionBudget.noteEgressBytes(6) is SessionBudget.Verdict.Allow)
    val byteTrip = SessionBudget.noteEgressBytes(6)
    check("egress 12 of 10 trips", byteTrip is SessionBudget.Verdict.TripPause)
    if (byteTrip is SessionBudget.Verdict.TripPause) {
        check("byte trip names egress_bytes", byteTrip.cls == SessionBudget.Classes.EGRESS_BYTES)
        check("byte trip admits the crossing call returned", byteTrip.reason.contains("already returned"))
    }
    SessionBudget.endSession()

    // --- SessionManager integration: tripwire pause surface ---
    SessionBudget.capsProvider = { tinyCaps(input = 1) }
    val session = SessionManager.start("Budget Agent")
    check("session starts", session != null && SessionManager.isActive)
    val tap = listOf(SessionBudget.Classes.TOTAL, SessionBudget.Classes.INPUT)
    check("first tap allowed", SessionBudget.checkAndCount(tap) is SessionBudget.Verdict.Allow)
    val tapTrip = SessionBudget.checkAndCount(tap)
    check("second tap trips", tapTrip is SessionBudget.Verdict.TripPause)
    if (tapTrip is SessionBudget.Verdict.TripPause) {
        check("pauseByBudget pauses the live session", SessionManager.pauseByBudget(tapTrip.reason))
    }
    check("session is paused, not ended", SessionManager.isPaused && SessionManager.isOpen)
    check("budget reason is recorded", SessionManager.budgetPauseReason?.contains("budget tripwire") == true)
    check("drive refusal names the budget pause",
        SessionManager.driveRefusal()?.contains("budget tripwire") == true)
    check("owner resume clears the pause", SessionManager.resume())
    check("after resume: reason cleared", SessionManager.budgetPauseReason == null)
    check("after resume: budget trip cleared", !SessionBudget.isTripped)
    SessionManager.end()
    check("end clears budget counters",
        (SessionBudget.snapshot()["counts"] as Map<*, *>)[SessionBudget.Classes.TOTAL] == 0L)
    SessionBudget.capsProvider = { SessionBudget.Caps() }

    println(if (failures == 0) "SessionBudgetTest: ALL PASS" else "SessionBudgetTest: $failures FAILURES")
    if (failures > 0) kotlin.system.exitProcess(1)
}
