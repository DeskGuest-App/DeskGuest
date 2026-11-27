import io.deskguest.app.server.McpCore
import io.deskguest.app.server.PairingStore
import io.deskguest.app.server.SessionEvents
import io.deskguest.app.server.SessionManager
import java.io.File

/**
 * W80 / FR-122 — Android mirror of the Windows FR-121 fail-closed
 * adjudication (Lane W76): the presence Box names the SPECIFIC
 * driver, so no generic or blank driver name may ever render and an
 * unnamed session start is refused as the named defect
 * driver_name_missing.
 *
 * Reachability on the pre-fix tree (recorded in the lane log): both
 * production pairing flows beginPairing("") → Pairing.name = "";
 * agentName binds only from a non-blank clientInfo name; so
 * start_session could call SessionManager.start("") and the Box
 * rendered "%1$s is controlling your phone" with an empty name —
 * and a caller-less start fabricated the generic name "My AI".
 *
 * Args: [0] = android project dir.
 */
object W80Fr122Test {
    private var failures = 0
    private var passes = 0
    private fun check(name: String, ok: Boolean, detail: String = "") {
        if (ok) { passes++; println("PASS $name") }
        else { failures++; println("FAIL $name $detail") }
    }

    @JvmStatic
    fun main(args: Array<String>) {
        val root = File(args[0])
        val src = File(root, "app/src/main/java/io/deskguest/app")
        fun text(rel: String) = File(src, rel).readText()

        // ---- The predicate: what counts as a missing driver name ----
        check("predicate: null is missing", SessionManager.isDriverNameMissing(null))
        check("predicate: empty is missing", SessionManager.isDriverNameMissing(""))
        check("predicate: whitespace is missing", SessionManager.isDriverNameMissing("   "))
        check("predicate: a real name is present", !SessionManager.isDriverNameMissing("Axle"))
        check(
            "defect name is driver_name_missing",
            SessionManager.DEFECT_DRIVER_NAME_MISSING == "driver_name_missing"
        )

        // ---- SessionManager.start refuses unnamed starts, fail-closed ----
        SessionManager.end()
        val seen = mutableListOf<String>()
        val listener: (SessionEvents.Event) -> Unit = { seen.add(it.state) }
        SessionEvents.addListener(listener)
        val genBefore = SessionManager.generation.get()
        check("blank start refused", SessionManager.start("") == null)
        check("whitespace start refused", SessionManager.start("  ") == null)
        check("refused start opens no session", !SessionManager.isOpen && SessionManager.active == null)
        check("refused start leaves state IDLE", SessionManager.state == SessionManager.State.IDLE)
        check("refused start does not bump the generation", SessionManager.generation.get() == genBefore)
        check(
            "refusal recorded as the named defect",
            SessionManager.lastStartDefect == SessionManager.DEFECT_DRIVER_NAME_MISSING
        )
        check(
            "refusal emitted as session_start_refused",
            seen.count { it == "session_start_refused" } == 2
        )
        SessionEvents.removeListener(listener)

        // ---- A named start is unaffected; the defect clears ----
        val named = SessionManager.start("  Axle  ")
        check("named start opens a session", named != null && SessionManager.isActive)
        check("named start stores the trimmed specific name", named?.agentName == "Axle")
        check("successful start clears the defect record", SessionManager.lastStartDefect == null)
        check(
            "second start still refused as already-open, not as a defect",
            SessionManager.start("Other") == null && SessionManager.lastStartDefect == null
        )
        check("named session may drive (no defect refusal)", SessionManager.driveRefusal() == null)
        SessionManager.end()
        check("after end, a blank start is refused again", SessionManager.start("") == null)
        check("defect recorded again", SessionManager.lastStartDefect == SessionManager.DEFECT_DRIVER_NAME_MISSING)
        SessionManager.end()

        // ---- Pairing name chain: no generic default anywhere ----
        val dir = File(System.getProperty("java.io.tmpdir"), "w80-pairings-${System.nanoTime()}")
        dir.mkdirs()
        val store = PairingStore(File(dir, "pairings.tsv"))
        val code = store.beginPairing("")
        val pairing = store.redeem(code, PairingStore.DEFAULT_SCOPES)
        check("unnamed pairing redeems with an EMPTY name, not a generic",
            pairing != null && pairing.name == "" && pairing.agentName == "")
        val store2 = PairingStore(File(dir, "pairings2.tsv"))
        val pairing2 = store2.redeem(store2.beginPairing("Desk Mate"), PairingStore.DEFAULT_SCOPES)
        check("a given pairing name is carried verbatim", pairing2?.name == "Desk Mate")

        // ---- Caller display name: blanks propagate, never fabricate ----
        check("caller with no names has a blank display name",
            McpCore.Caller("", "").displayName == "")
        check("caller display name prefers the agent name",
            McpCore.Caller("Axle", "Pair").displayName == "Axle")
        check("caller display name falls back to the SPECIFIC pairing name",
            McpCore.Caller("", "Pair").displayName == "Pair")

        // ---- Source pins: the fabrication and the guards ----
        val access = text("server/AccessToolHost.kt")
        check("start_session: generic My AI fabrication abolished", !access.contains("\"My AI\""))
        check("start_session: refuses on the named defect",
            access.contains("DEFECT_DRIVER_NAME_MISSING") && access.contains("isDriverNameMissing(who)"))
        check("start_session: driver name comes from the caller display name",
            access.contains("caller?.displayName"))
        val sm = text("server/SessionManager.kt")
        check("SessionManager: defect constant + refusal in start",
            sm.contains("DEFECT_DRIVER_NAME_MISSING") && sm.contains("isDriverNameMissing(agentName)"))
        check("SessionManager: drive gate refuses an unnamed session",
            sm.contains("isDriverNameMissing(session.agentName)"))
        val pairings = text("server/PairingStore.kt")
        check("PairingStore: generic pending-name default abolished",
            !pairings.contains("pendingName: String = \"Agent\""))
        val overlay = text("presence/PresenceOverlay.kt")
        check("renderer guard: presence checks the driver name before the named box",
            overlay.indexOf("isDriverNameMissing(session.agentName)") in 0 until
                overlay.indexOf("buildBox(wctx, wm, session.agentName)"))
        check("renderer guard: defect box exists and names the defect string",
            overlay.contains("fun buildDefectBox") &&
                overlay.contains("R.string.presence_driver_name_missing"))
        check("renderer guard: defect box carries STOP via stopByUser",
            overlay.substringAfter("fun buildDefectBox").contains("SessionManager.stopByUser()"))
        check("renderer guard: named-box texts never overwrite the defect box",
            overlay.contains("if (SessionManager.isDriverNameMissing(session.agentName)) return"))
        val tile = text("tile/DeskGuestTileService.kt")
        check("QS tile: generic tile_default_agent fallback abolished",
            !tile.contains("tile_default_agent"))
        check("QS tile: blank driver name shows the defect line",
            tile.contains("R.string.presence_driver_name_missing"))
        val defaults = text("strings/ConsentStrings.kt")
        check("strings door: defect strings have built-in defaults",
            defaults.contains("\"presence_driver_name_missing\"") &&
                defaults.contains("\"presence_driver_name_missing_hint\""))
        val resXml = File(root, "app/src/main/res/values/strings.xml").readText()
        check("strings.xml: defect strings present",
            resXml.contains("name=\"presence_driver_name_missing\"") &&
                resXml.contains("name=\"presence_driver_name_missing_hint\""))

        println("W80 FR-122: $passes PASS, $failures FAIL")
        if (failures > 0) kotlin.system.exitProcess(1)
    }
}
