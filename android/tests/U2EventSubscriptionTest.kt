import io.deskguest.app.server.EventSubscriptions
import io.deskguest.app.server.SessionEvents

/**
 * U2 regression + destruction tests (Android): the event-kind
 * registry mirror, per-pairing subscription filters, the delivery
 * rule (subscribed kinds only; unsubscribed pairing receives
 * nothing), kind mapping for legacy session states, and the new
 * producers' kinds (screen_change / foreground_app / app_crash /
 * notification_posted). Cross-pairing origin scoping is a Windows
 * bus property; on Android the pairing key IS the subscription
 * identity, and the destruction leg here is that one pairing's
 * filter never delivers to another pairing's key.
 */
object U2EventSubscriptionTest {
    private var failures = 0
    private fun check(name: String, cond: Boolean) {
        if (cond) println("PASS $name") else { println("FAIL $name"); failures++ }
    }

    @JvmStatic
    fun main(args: Array<String>) {
        // Registry mirrors the Windows contract exactly.
        check(
            "registry kinds",
            SessionEvents.ALL_KINDS.containsAll(
                setOf(
                    "session", "approval", "screen_change",
                    "foreground_app", "app_crash", "notification_posted",
                    "clipboard_read" // U1 extension, mirrors Windows
                )
            )
        )
        check("legacy session state maps to session kind", SessionEvents.kindOf("session_started") == "session")
        check("legacy approval maps to approval kind", SessionEvents.kindOf("approval_required") == "approval")
        check("canonical kind maps to itself", SessionEvents.kindOf("app_crash") == "app_crash")

        // Subscribe / filter / deliver.
        val keyA = "token-a"; val keyB = "token-b"
        EventSubscriptions.clearPairing(keyA); EventSubscriptions.clearPairing(keyB)
        check("subscribe ok", EventSubscriptions.subscribe(keyA, listOf("session")) == null)
        check(
            "stream receives only subscribed kinds",
            EventSubscriptions.shouldDeliver(keyA, SessionEvents.Event("session_started")) &&
                !EventSubscriptions.shouldDeliver(keyA, SessionEvents.Event("approval_required"))
        )
        check(
            "unsubscribed pairing receives nothing",
            !EventSubscriptions.shouldDeliver(keyB, SessionEvents.Event("session_started"))
        )

        // Destruction: unknown kind refuses atomically.
        check("unknown kind refused", EventSubscriptions.subscribe(keyA, listOf("session", "wiretap")) != null)
        check("no partial subscription", EventSubscriptions.filterFor(keyA) == setOf("session"))

        // Destruction: cross-pairing — B's subscription never
        // delivers under A's key and vice versa.
        check("b subscribe crash", EventSubscriptions.subscribe(keyB, listOf("app_crash")) == null)
        check(
            "cross-pairing isolation",
            !EventSubscriptions.shouldDeliver(keyA, SessionEvents.Event("app_crash")) &&
                EventSubscriptions.shouldDeliver(keyB, SessionEvents.Event("app_crash"))
        )

        // Crash/screen/notification fixtures ride the bus filtered.
        val got = mutableListOf<SessionEvents.Event>()
        val listener: (SessionEvents.Event) -> Unit = { e ->
            if (EventSubscriptions.shouldDeliver(keyB, e)) got.add(e)
        }
        SessionEvents.addListener(listener)
        SessionEvents.emitKind("app_crash", mapOf("where" to "fixture"))
        SessionEvents.emitKind("screen_change", mapOf("package" to "com.example"))
        SessionEvents.emitKind("notification_posted", mapOf("package" to "com.example"))
        SessionEvents.emitKind("invented_kind", emptyMap())
        SessionEvents.removeListener(listener)
        check("fixtures filtered to subscribed kind", got.size == 1 && got[0].kind == "app_crash")
        check("event json carries kind", SessionEvents.toJson(got[0]).contains("\"kind\":\"app_crash\""))

        // Unsubscribe whole + clear.
        check("unsubscribe whole", EventSubscriptions.unsubscribe(keyB, null) == null)
        check("after unsubscribe nothing delivers", !EventSubscriptions.shouldDeliver(keyB, SessionEvents.Event("app_crash")))
        EventSubscriptions.clearPairing(keyA)
        check("clear pairing", EventSubscriptions.filterFor(keyA).isEmpty())

        if (failures > 0) { println("U2 ANDROID: $failures FAILURES"); kotlin.system.exitProcess(1) }
        println("U2 ANDROID: ALL PASS")
    }
}
