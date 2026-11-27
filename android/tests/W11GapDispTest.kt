import io.deskguest.app.access.AppCards
import io.deskguest.app.access.SnapshotStore
import io.deskguest.app.access.StructuredExtraction
import io.deskguest.app.notify.NotificationCache
import io.deskguest.app.notify.NotificationTriage
import io.deskguest.app.server.CrashReport
import io.deskguest.app.server.FindMyPhonePolicy
import io.deskguest.app.server.ReplayLog
import io.deskguest.app.server.ReplayTimeline

/**
 * Wave 11 Lane B — FEATURES gap disposition builds (2026-11-23):
 * structured extraction, crash-report parsing, app cards,
 * notification triage, find-my-phone policy, replay timeline.
 * Fails loudly: any failed check throws and the suite exits
 * non-zero.
 */
private var checks = 0

private fun check(cond: Boolean, label: String) {
    checks++
    if (!cond) throw AssertionError("W11-GAPDISP FAIL: $label")
}

private fun entry(
    ref: String, text: String, desc: String = "", cls: String = "android.widget.TextView",
    clickable: Boolean = false, editable: Boolean = false, password: Boolean = false
) = SnapshotStore.Entry(ref, text, desc, cls, 0, 0, 10, 10, clickable, editable, password)

fun main() {
    // ---- Structured extraction ----
    val result = StructuredExtraction.extract(
        listOf(
            entry("e1", "Balance", cls = "android.widget.TextView"),
            entry("e2", "Search", cls = "android.widget.EditText", editable = true),
            entry("e3", "", desc = "Settings", cls = "android.widget.ImageButton", clickable = true),
            entry("e4", "hunter2", cls = "android.widget.EditText", editable = true, password = true),
            entry("e5", "", cls = "android.widget.FrameLayout")
        )
    )
    check(result.fields.size == 4, "extract: labelled elements become fields")
    check(result.skippedUnlabelled == 1, "extract: unlabelled counted, not dropped silently")
    check(result.fields[0].kind == StructuredExtraction.KIND_TEXT, "extract: plain label is text")
    check(result.fields[1].kind == StructuredExtraction.KIND_INPUT, "extract: editable is input")
    check(result.fields[1].value == "Search", "extract: input carries its value")
    check(result.fields[2].kind == StructuredExtraction.KIND_ACTION, "extract: clickable is action")
    check(result.fields[2].label == "Settings", "extract: content-desc is the label when text empty")
    check(result.fields[3].value == SnapshotStore.REDACTED, "extract: password value is REDACTED, never content")
    val empty = StructuredExtraction.extract(listOf(entry("e1", "", cls = "android.view.View")))
    check(empty.fields.isEmpty() && empty.skippedUnlabelled == 1, "extract: canvas-like tree = zero fields, honestly")

    // ---- Crash report parsing ----
    val raw = "DeskGuest failure report\n" +
        "2026-11-20 09:41:07 — uncaught on main\n\n" +
        "java.lang.IllegalStateException: boom\n" +
        "\tat io.deskguest.app.Foo.bar(Foo.kt:12)\n" +
        "\tat io.deskguest.app.Foo.baz(Foo.kt:30)\n"
    val parsed = CrashReport.parse(raw)
    check(parsed != null, "crash: CrashTrap format parses")
    check(parsed!!.recordedAt == "2026-11-20 09:41:07", "crash: timestamp extracted")
    check(parsed.where == "uncaught on main", "crash: where extracted")
    check(parsed.exceptionLine.startsWith("java.lang.IllegalStateException"), "crash: exception line extracted")
    check(parsed.frameCount == 2, "crash: frames counted")
    check(CrashReport.parse(null) == null, "crash: null text = no report")
    check(CrashReport.parse("") == null, "crash: blank text = no report")
    check(CrashReport.parse("some other file\nwith lines") == null, "crash: foreign text refused, not guessed")

    // ---- App cards ----
    val cards = AppCards()
    check(cards.get("com.example.bank") == null, "cards: empty store has no card")
    check(cards.put(" Com.Example.Bank ", "Statements hide balances until tapped") == "com.example.bank", "cards: put normalizes key")
    check(cards.get("com.example.bank")!!.contains("Statements"), "cards: get returns note")
    check(cards.put("bank", "x") == null, "cards: single-segment key refused")
    check(cards.put("com.example.bank", "   ") == null, "cards: blank note refused")
    check(cards.put("com.example.bank", "x".repeat(AppCards.MAX_NOTE_CHARS + 1)) == null, "cards: over-cap note refused")
    check(cards.put("com.example.bank", "v2 note") == "com.example.bank", "cards: rewrite replaces whole")
    check(cards.get("com.example.bank") == "v2 note", "cards: replaced note is the whole note")
    val roundTrip = AppCards.decode(cards.encode())
    check(roundTrip != null && roundTrip.get("com.example.bank") == "v2 note", "cards: encode/decode round-trips")
    check(AppCards.decode("{not json") == null, "cards: corrupt file decodes to null, not empty")
    check(AppCards.decode(null) != null && AppCards.decode(null)!!.size() == 0, "cards: absent file = empty store")
    val full = AppCards()
    for (i in 0 until AppCards.MAX_CARDS) full.put("com.example.app$i", "note $i")
    check(full.put("com.example.one.more", "nope") == null, "cards: store cap refuses, never evicts silently")
    check(full.put("com.example.app0", "updated") == "com.example.app0", "cards: rewrite allowed at cap")
    check(cards.remove("com.example.bank"), "cards: remove works")
    check(cards.get("com.example.bank") == null, "cards: removed card gone")

    // ---- Notification triage ----
    fun notif(title: String, text: String) =
        NotificationCache.Entry("k", "com.example.app", title, text, 0L)
    check(
        NotificationTriage.judge(notif("Missed call", "From Sam")).urgency ==
            NotificationTriage.Urgency.URGENT,
        "triage: missed call is urgent"
    )
    check(
        NotificationTriage.judge(notif("Alarm", "7:00 AM")).rule == "alarm firing",
        "triage: alarm rule named"
    )
    check(
        NotificationTriage.judge(notif("Security alert", "New sign-in")).urgency ==
            NotificationTriage.Urgency.URGENT,
        "triage: security notice is urgent"
    )
    check(
        NotificationTriage.judge(notif("Payment failed", "Card declined")).urgency ==
            NotificationTriage.Urgency.URGENT,
        "triage: payment problem is urgent"
    )
    val routine = NotificationTriage.judge(notif("Newsletter", "Your weekly digest"))
    check(routine.urgency == NotificationTriage.Urgency.ROUTINE, "triage: ordinary mail is routine")
    check(routine.rule == "no urgent rule matched", "triage: routine verdict still names its basis")

    // ---- Find-my-phone policy ----
    check(FindMyPhonePolicy.ownerText("  I am  at\n the store ") == "I am at the store", "find: text flattened to one line")
    check(FindMyPhonePolicy.ownerText("") == FindMyPhonePolicy.DEFAULT_TEXT, "find: empty text gets the honest default")
    check(FindMyPhonePolicy.ownerText("x".repeat(FindMyPhonePolicy.MAX_TEXT_CHARS + 1)) == null, "find: over-cap text refused, not truncated")
    check(FindMyPhonePolicy.ringSeconds(0) == FindMyPhonePolicy.DEFAULT_RING_SECONDS, "find: default duration")
    check(FindMyPhonePolicy.ringSeconds(999) == FindMyPhonePolicy.MAX_RING_SECONDS, "find: duration capped")
    check(FindMyPhonePolicy.allowedNow(0L, 1_000L), "find: first ring allowed")
    check(!FindMyPhonePolicy.allowedNow(1_000L, 30_000L), "find: ring inside a minute refused")
    check(FindMyPhonePolicy.allowedNow(1_000L, 61_000L), "find: ring after a minute allowed")

    // ---- Replay timeline ----
    ReplayLog.clearForTest()
    val emptyLines = ReplayTimeline.render(ReplayLog.snapshot(), 0)
    check(emptyLines.first().contains("No session events"), "replay: empty state is honest")
    ReplayLog.record("session_started", mapOf("agent" to "Test"), atMs = 1_000L)
    ReplayLog.record("approval_granted", mapOf("class" to "shell"), atMs = 4_500L)
    val lines = ReplayTimeline.render(ReplayLog.snapshot(), 0)
    check(lines.size == 3, "replay: header + one line per event")
    check(lines[1].contains("session_started") && lines[1].contains("agent=Test"), "replay: event + detail rendered")
    check(lines[2].contains("+3s"), "replay: offset from first event rendered")
    val droppedLines = ReplayTimeline.render(ReplayLog.snapshot(), 7)
    check(droppedLines[0].contains("7 oldest"), "replay: dropped entries counted in header, never silent")
    ReplayLog.clearForTest()

    println("W11GapDispTest: $checks checks PASS")
}
