import io.agenticcontrol.app.notify.NotificationCache
import io.agenticcontrol.app.safety.DrivingLockout
import io.agenticcontrol.app.safety.DrivingStateHolder
import io.agenticcontrol.app.safety.InvisibleAppBlocklist
import io.agenticcontrol.app.safety.InvisibleAppRules
import io.agenticcontrol.app.server.FileScope
import io.agenticcontrol.app.server.ReplayLog
import io.agenticcontrol.app.server.SessionManager
import java.io.File

/**
 * BD-XCHECK owed items (2026-11-22): invisible-apps blocklist,
 * driving lockout, and the pure cores behind the owed tools
 * (notifications cache, replay log, file scope). Fails loudly:
 * any failed check throws and the suite exits non-zero.
 */
private var checks = 0

private fun check(cond: Boolean, label: String) {
    checks++
    if (!cond) throw AssertionError("XCHECK-OWED FAIL: $label")
}

fun main() {
    // ---- Invisible apps ----
    check(InvisibleAppRules.normalize(" Com.Example.Bank ") == "com.example.bank", "normalize lowercases/trims")
    check(InvisibleAppRules.normalize("bank") == null, "single segment refused")
    check(InvisibleAppRules.normalize("com.example..bank") == null, "empty segment refused")
    check(InvisibleAppRules.normalize("") == null, "empty refused")
    check(InvisibleAppRules.normalize(null) == null, "null refused")
    val list = InvisibleAppBlocklist()
    check(!list.isBlocked("com.example.bank"), "empty list blocks nothing")
    check(list.mark("com.example.bank") == "com.example.bank", "mark returns normalized")
    check(list.isBlocked("COM.EXAMPLE.BANK"), "blocked match is case-insensitive via normalize")
    check(!list.isBlocked("com.example.other"), "unmarked app not blocked")
    check(!list.isBlocked("not a package"), "invalid name never blocked")
    check(list.mark("junk") == null, "invalid mark refused")
    val refusal = InvisibleAppRules.refusal()
    check(refusal.startsWith("blocked_by_user_rule"), "refusal carries the SPEC 7.5 code")
    check(!refusal.contains("com.example"), "refusal never names a package")
    val roundTrip = InvisibleAppBlocklist.decode(list.encode())
    check(roundTrip.isBlocked("com.example.bank"), "encode/decode round-trips")
    check(list.unmark("com.example.bank"), "unmark removes")
    check(!list.isBlocked("com.example.bank"), "unmarked no longer blocked")

    // ---- Driving lockout ----
    check(
        DrivingLockout.evaluate(DrivingLockout.Signals()) == DrivingLockout.State.NOT_DRIVING,
        "no signals = not driving"
    )
    check(
        DrivingLockout.evaluate(DrivingLockout.Signals(carMode = true)) == DrivingLockout.State.DRIVING,
        "car mode = driving"
    )
    check(
        DrivingLockout.evaluate(DrivingLockout.Signals(carBluetoothConnected = true)) ==
            DrivingLockout.State.DRIVING,
        "car bluetooth = driving"
    )
    check(
        DrivingLockout.driveRefusal(DrivingLockout.State.NOT_DRIVING, DrivingLockout.Signals()) == null,
        "not driving = no refusal"
    )
    val driveRefusal = DrivingLockout.driveRefusal(
        DrivingLockout.State.DRIVING, DrivingLockout.Signals(carMode = true)
    )
    check(driveRefusal != null && driveRefusal.contains("DRIVING LOCKOUT"), "driving refusal text")
    check(driveRefusal!!.contains("notify_user"), "refusal names the voice-grade exception")

    // SessionManager integration: provider installed -> drive tools
    // refuse; provider cleared -> normal no-session refusal returns.
    DrivingStateHolder.provider = {
        DrivingLockout.State.DRIVING to DrivingLockout.Signals(carBluetoothConnected = true)
    }
    SessionManager.start("XcheckOwedTest")
    val smRefusal = SessionManager.driveRefusal()
    check(smRefusal != null && smRefusal.contains("DRIVING LOCKOUT"), "SessionManager enforces the lockout")
    DrivingStateHolder.provider = null
    check(SessionManager.driveRefusal() == null, "no provider = drive allowed in a live session")
    SessionManager.end()
    check(
        SessionManager.driveRefusal()?.contains("No drive session") == true,
        "no-session refusal restored after end"
    )

    // ---- Notification cache ----
    NotificationCache.clear()
    check(NotificationCache.active().isEmpty(), "cache starts empty")
    NotificationCache.posted("k1", "com.example.mail", "Hi", "Body", 100L)
    NotificationCache.posted("k2", "com.example.chat", "Yo", "Text", 200L)
    check(NotificationCache.active().size == 2, "posted entries are active")
    NotificationCache.posted("k1", "com.example.mail", "Hi again", "Body2", 300L)
    check(NotificationCache.active().size == 2, "repost replaces, never duplicates")
    NotificationCache.removed("k1")
    check(NotificationCache.active().map { it.key } == listOf("k2"), "removal removes exactly that key")
    val longText = "x".repeat(NotificationCache.MAX_TEXT_CHARS + 50)
    NotificationCache.posted("k3", "com.example.long", "T", longText, 400L)
    check(
        NotificationCache.active().first { it.key == "k3" }.text.length == NotificationCache.MAX_TEXT_CHARS,
        "text is capped"
    )
    NotificationCache.clear()

    // ---- Replay log ----
    ReplayLog.clearForTest()
    ReplayLog.record("session_started", mapOf("agent" to "Test"))
    ReplayLog.record("session_ended", mapOf("actions" to "3"))
    val snap = ReplayLog.snapshot()
    check(snap.size == 2 && snap[0].state == "session_started", "replay keeps append order")
    check(snap[1].detail["actions"] == "3", "replay keeps detail")
    ReplayLog.clearForTest()
    repeat(ReplayLog.MAX_ENTRIES + 5) { i -> ReplayLog.record("e$i") }
    check(ReplayLog.snapshot().size == ReplayLog.MAX_ENTRIES, "replay is bounded")
    check(ReplayLog.droppedCount() == 5, "replay reports dropped-oldest honestly")
    check(ReplayLog.snapshot().first().state == "e5", "oldest fell off first")
    ReplayLog.clearForTest()

    // ---- File scope ----
    val root = File("/tmp/acp-agent-files-test")
    check(FileScope.resolve(root, "note.txt") != null, "plain name resolves")
    check(FileScope.resolve(root, "sub/note.txt") != null, "one subfolder resolves")
    check(FileScope.resolve(root, "../escape.txt") == null, "dotdot refused")
    check(FileScope.resolve(root, "sub/../../escape.txt") == null, "nested dotdot refused")
    check(FileScope.resolve(root, "/etc/passwd") == null, "absolute refused")
    check(FileScope.resolve(root, "a\\b.txt") == null, "backslash refused")
    check(FileScope.resolve(root, "") == null, "empty refused")
    check(FileScope.resolve(root, ".") == null, "root itself refused")
    check(FileScope.isPlainName("app.apk"), "plain apk name ok")
    check(!FileScope.isPlainName("../app.apk"), "plain name refuses traversal")

    println("XcheckOwedTest: ALL $checks CHECKS PASS")
}
