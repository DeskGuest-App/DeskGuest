import io.agenticcontrol.app.server.SessionEvents
import io.agenticcontrol.app.server.SessionManager

/**
 * JVM tests for the 0.4.0 session state machine: pause-by-user,
 * resume with the fresh-snapshot rule, generation monotonicity, and
 * the refusal texts the drive/observe gates rely on.
 */
private var failures = 0

private fun check(name: String, condition: Boolean) {
    if (condition) println("PASS  $name")
    else {
        println("FAIL  $name")
        failures++
    }
}

fun main() {
    // Clean slate (the object is a singleton across this JVM).
    SessionManager.end()

    check("idle: no session", SessionManager.active == null && !SessionManager.isOpen)
    check(
        "idle: drive refused with the start_session words",
        SessionManager.driveRefusal()?.contains("start_session") == true
    )
    check("idle: observe allowed", SessionManager.observeRefusal() == null)
    check("idle: pause is a no-op", !SessionManager.pauseByUser())
    check("idle: resume is a no-op", !SessionManager.resume())

    val gen0 = SessionManager.generation.get()
    val session = SessionManager.start("Test Agent")
    check("start opens a session", session != null && SessionManager.isActive)
    check("start bumps the generation", SessionManager.generation.get() > gen0)
    check("second start refused, never stacked", SessionManager.start("Other") == null)
    check("active: drive allowed", SessionManager.driveRefusal() == null)

    SessionManager.setIntent("Opening Settings")
    check("intent recorded", SessionManager.currentIntent == "Opening Settings")
    SessionManager.setIntent("x".repeat(500))
    check("intent is length-capped", SessionManager.currentIntent.length == 120)

    // Touch-to-yield.
    val genActive = SessionManager.generation.get()
    check("user touch pauses", SessionManager.pauseByUser())
    check("paused state", SessionManager.isPaused && !SessionManager.isActive)
    check("pause bumps the generation", SessionManager.generation.get() > genActive)
    check(
        "paused: drive refused as PAUSED",
        SessionManager.driveRefusal()?.startsWith("PAUSED") == true
    )
    check(
        "paused: observe refused too (takeover privacy)",
        SessionManager.observeRefusal()?.startsWith("PAUSED") == true
    )
    check("double pause is a no-op", !SessionManager.pauseByUser())

    // Resume forces a fresh snapshot before any drive action.
    check("resume works from paused", SessionManager.resume())
    check("resumed: active again", SessionManager.isActive)
    check(
        "resumed: drive refused until a fresh snapshot",
        SessionManager.driveRefusal()?.contains("fresh snapshot") == true
    )
    check("resumed: observe allowed", SessionManager.observeRefusal() == null)
    SessionManager.noteSnapshotTaken()
    check("fresh snapshot clears the rule", SessionManager.driveRefusal() == null)

    // Session events fire for the SSE stream.
    val seen = mutableListOf<String>()
    val listener: (SessionEvents.Event) -> Unit = { seen.add(it.state) }
    SessionEvents.addListener(listener)
    SessionManager.pauseByUser()
    SessionManager.resume()
    SessionManager.stopByUser()
    SessionEvents.removeListener(listener)
    check(
        "events: paused, resumed, stopped_by_user, ended",
        seen == listOf("paused_by_user", "session_resumed", "stopped_by_user", "session_ended")
    )
    check("stopByUser ends the session", SessionManager.active == null)

    // The event JSON is a session_state notification.
    SessionManager.start("Json Agent")
    val json = SessionEvents.toJson(SessionEvents.Event("paused_by_user"))
    check("event json names the method", json.contains("notifications/session_state"))
    check("event json carries the state", json.contains("paused_by_user"))
    check("event json names the agent", json.contains("Json Agent"))
    SessionManager.end()
    check("end returns to idle", SessionManager.state == SessionManager.State.IDLE)

    println(if (failures == 0) "ALL SESSION TESTS PASSED" else "$failures SESSION TEST(S) FAILED")
    if (failures > 0) kotlin.system.exitProcess(1)
}
