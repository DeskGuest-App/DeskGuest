import io.agenticcontrol.app.enrollment.DeviceIdentity
import io.agenticcontrol.app.enrollment.EnrollmentStore
import io.agenticcontrol.app.roster.RosterStore
import io.agenticcontrol.app.server.DataFlows
import io.agenticcontrol.app.server.McpCore
import io.agenticcontrol.app.server.SessionBudget
import io.agenticcontrol.app.server.PairingStore
import io.agenticcontrol.app.session.StandaloneTransferStore
import org.json.JSONObject
import java.io.File

/**
 * U5 regression tests (Android mirror): per-agent data-flow
 * transparency. Known payloads reconcile exactly; counters are
 * per-pairing and never merge; classification maps read/sent/
 * changed; audited calls without flow records show as gaps —
 * never as fabricated flows; transfer bytes land per device.
 *
 * Extended 2026-11-22 (Android DataFlows test lane) to prove the
 * same claims the Windows suite proves, at the real choke points:
 *  - exact byte reconciliation THROUGH McpCore dispatch (counted
 *    == UTF-8 bytes of the arguments JSON sent in and the reply
 *    body sent out, multi-byte payloads included; denials count);
 *  - Attack_NameCollision: two pairings carrying the SAME pairing
 *    name AND the SAME agent name never merge (the Android mirror
 *    of the Windows session-id collision — keying by display name
 *    was a live product bug, fixed by Pairing.id);
 *  - ended sessions / ended transfers / revoked pairings keep
 *    their totals (counters only ever grow within process life);
 *  - transfer bytes reconcile through the real
 *    StandaloneTransferStore progress path (deltas only; refused
 *    progress counts nothing);
 *  - every audit-gap shape surfaces as a named gap — counted >
 *    audited, uncorroborated, and the process-restart story
 *    (counters empty, persisted audit counts become a gap, never
 *    fabricated rows or estimated bytes).
 *
 * The in-memory-only limit itself (no persistence across a real
 * process restart) is DOCUMENTED in DataFlow.kt's header, not
 * asserted — a single JVM process cannot restart itself. What IS
 * asserted is its observable consequence, above.
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
    DataFlows.resetForTest()

    // --- classifier ---
    check("classifier: file_pull is read (egress)", DataFlows.classify("file_pull") == DataFlows.READ)
    check("classifier: screenshot is read (egress)", DataFlows.classify("screenshot") == DataFlows.READ)
    check("classifier: session_status is read (observe)", DataFlows.classify("session_status") == DataFlows.READ)
    check("classifier: sending set honestly empty on Android (no off-device senders)", DataFlows.sendingTools.isEmpty())
    check("classifier: tap is changed", DataFlows.classify("tap") == DataFlows.CHANGED)
    check("classifier: shell_exec is changed", DataFlows.classify("shell_exec") == DataFlows.CHANGED)

    // --- known payloads reconcile exactly ---
    DataFlows.noteCall("pair-a", "agent-a", "file_pull", 2, 10)
    DataFlows.noteCall("pair-a", "agent-a", "file_pull", 2, 5)
    DataFlows.noteCall("pair-a", "agent-a", "tap", 7, 3)
    val a = DataFlows.agentFlows().single { it.pairing == "pair-a" }
    check("totals: bytesIn 2+2+7 = 11", a.bytesIn == 11L)
    check("totals: bytesOut 10+5+3 = 18", a.bytesOut == 18L)
    val read = a.tools.single { it.tool == "file_pull" }
    check("per-tool: file_pull 2 calls, 4 in, 15 out", read.calls == 2L && read.bytesIn == 4L && read.bytesOut == 15L)
    check("by-class: read carries file_pull totals", a.byClass(DataFlows.READ)?.bytesOut == 15L)
    check("by-class: changed carries tap totals", a.byClass(DataFlows.CHANGED)?.calls == 1L)

    // --- negative bytes refused: counters only grow ---
    DataFlows.noteCall("pair-a", "agent-a", "file_pull", -100, -100)
    check("negative bytes refused", DataFlows.agentFlows().single { it.pairing == "pair-a" }.bytesIn == 11L)

    // --- W1 destruction hardening (2026-11-22): blank identities
    // mint no anonymous rows — a "" pairing/device/direction must
    // never appear in any flow view or gap report ---
    DataFlows.noteCall("", "ghost", "file_pull", 5, 5)
    DataFlows.noteCall("  ", "ghost", "file_pull", 5, 5)
    DataFlows.noteAudited("")
    DataFlows.noteDestination("", "nowhere")
    DataFlows.noteTransfer("", "to_device", 100)
    DataFlows.noteTransfer("dev-x", "", 100)
    check("blank pairing mints no flow row",
        DataFlows.agentFlows().none { it.pairing.isBlank() })
    check("blank pairing mints no audited count",
        !DataFlows.auditedCounts().containsKey("") && !DataFlows.auditedCounts().containsKey("  "))
    check("blank transfer identities mint no transfer row",
        DataFlows.transferFlows().none { it.deviceId.isBlank() || it.direction.isBlank() })

    // --- per-pairing isolation: two pairings never merge ---
    DataFlows.noteCall("pair-b", "agent-b", "file_pull", 2, 7)
    val flows = DataFlows.agentFlows()
    check("two agents present", flows.size == 2)
    check("pair-a bytesOut unchanged by pair-b", flows.single { it.pairing == "pair-a" }.bytesOut == 18L)
    check("pair-b has only its own bytes", flows.single { it.pairing == "pair-b" }.bytesOut == 7L)

    // --- transfers: bytes per target device, delta-counted ---
    DataFlows.noteTransfer("dev-9", "to_device", 400)
    DataFlows.noteTransfer("dev-9", "to_device", 150)
    DataFlows.noteTransfer("dev-9", "to_device", 0) // no movement, no count
    val transfer = DataFlows.transferFlows().single()
    check("transfer totals 400+150 = 550 for dev-9", transfer.bytes == 550L && transfer.deviceId == "dev-9")

    // --- corroborated report: audited counts match, no gaps ---
    DataFlows.noteAudited("pair-a"); DataFlows.noteAudited("pair-a"); DataFlows.noteAudited("pair-a")
    DataFlows.noteAudited("pair-b")
    val clean = DataFlows.report()
    check("corroborated report has no gaps", clean.gaps.isEmpty())

    // --- gaps show as gaps: audited calls with no flow record ---
    val gapped = DataFlows.report(mapOf("pair-a" to 3L, "pair-b" to 1L, "ghost" to 4L))
    check("ghost pairing gets NO fabricated agent row", gapped.agents.none { it.pairing == "ghost" })
    check("ghost gap names the missing count", gapped.gaps.any { it.contains("ghost") && it.contains("4 audited tool call(s) have no flow record") })
    check("ghost gap says NOT estimated", gapped.gaps.any { it.contains("NOT estimated") })
    check("real agents' totals untouched by the gap", gapped.agents.single { it.pairing == "pair-a" }.bytesOut == 18L)

    // --- partial gap counts only the missing calls ---
    val partial = DataFlows.report(mapOf("pair-a" to 5L, "pair-b" to 1L))
    check("partial gap counts exactly the missing 2", partial.gaps.any { it.contains("pair-a") && it.contains("2 audited tool call(s) have no flow record") })

    // --- summary lines carry the fields the detail surface shows ---
    val lines = DataFlows.summaryLines(mapOf("pair-a" to 3L, "pair-b" to 1L))
    check("summary names agent-a with volumes", lines.any { it.contains("agent-a") && it.contains("out 18 B") })
    check("summary names the transfer destination", lines.any { it.contains("dev-9") && it.contains("550 B") })

    DataFlows.resetForTest()
    check("empty state reports honestly", DataFlows.summaryLines(emptyMap()).single() == "No data flows recorded yet.")

    // --- gap shape: counted MORE than audited (flows exist the
    // audit view did not supply) ---
    DataFlows.resetForTest()
    DataFlows.noteCall("pair-c", "agent-c", "tap", 3, 4)
    DataFlows.noteCall("pair-c", "agent-c", "tap", 3, 4)
    val over = DataFlows.report(mapOf("pair-c" to 1L))
    check("counted>audited gap names the extra call",
        over.gaps.any { it.contains("pair-c") && it.contains("count 1 more call(s) than the audit") })
    check("counted>audited keeps the counted totals (no trim to audit)",
        over.agents.single { it.pairing == "pair-c" }.bytesOut == 8L)

    // --- gap shape: flows with NO audited counts supplied at all
    // show as uncorroborated, never silently trusted ---
    val uncorroborated = DataFlows.report(emptyMap())
    check("uncorroborated gap names the pairing",
        uncorroborated.gaps.any { it.contains("pair-c") && it.contains("uncorroborated") })
    check("uncorroborated flows still shown from counters",
        uncorroborated.agents.single { it.pairing == "pair-c" }.calls == 2L)

    // --- ended sessions keep totals: session boundaries are just
    // calls; nothing resets when a session ends, and a second
    // session for the same pairing accumulates onto the first ---
    DataFlows.resetForTest()
    DataFlows.noteCall("pair-s", "agent-s", "start_session", 5, 20)
    DataFlows.noteCall("pair-s", "agent-s", "file_pull", 10, 500)
    DataFlows.noteCall("pair-s", "agent-s", "end_session", 5, 20)
    val afterFirst = DataFlows.agentFlows().single { it.pairing == "pair-s" }
    check("totals survive the first session ending",
        afterFirst.bytesIn == 20L && afterFirst.bytesOut == 540L && afterFirst.calls == 3L)
    DataFlows.noteCall("pair-s", "agent-s", "start_session", 5, 20)
    DataFlows.noteCall("pair-s", "agent-s", "file_pull", 10, 250)
    DataFlows.noteCall("pair-s", "agent-s", "end_session", 5, 20)
    val afterSecond = DataFlows.agentFlows().single { it.pairing == "pair-s" }
    check("second session accumulates onto the first (no reset)",
        afterSecond.bytesIn == 40L && afterSecond.bytesOut == 830L && afterSecond.calls == 6L)

    // --- process-restart story: counters start empty (fresh
    // process) while the persisted audit still holds counts —
    // the report must show exactly a gap, no rows, no bytes ---
    DataFlows.resetForTest()
    val restarted = DataFlows.report(mapOf("pair-a" to 9L))
    check("restart: no agent rows fabricated from the audit", restarted.agents.isEmpty())
    check("restart: gap names all 9 pre-restart calls",
        restarted.gaps.any { it.contains("pair-a") && it.contains("9 audited tool call(s) have no flow record") })
    check("restart: gap says bytes NOT estimated",
        restarted.gaps.any { it.contains("NOT estimated") })

    classifierInventory()
    dispatchReconciliation()
    nameCollisionAttack()
    transferPathReconciliation()

    if (failures > 0) {
        println("DataFlowTest: $failures FAILURES")
        kotlin.system.exitProcess(1)
    }
    println("DataFlowTest: ALL PASS")
}

/** The whole defined-tool inventory with its expected class —
 *  the anti-drift tripwire added with the 2026-11-22 classifier
 *  reconciliation. Every tool defined on this host (44 ToolDefs −
 *  the 3 chat tools, accounted on the ledger's separate chat leg, +
 *  BgToolCatalogue's 8 with device_info counted once = 48;
 *  decomposition corrected 2026-11-23, W18-C) appears here
 *  exactly once; adding a tool without classifying it here fails
 *  the suite, and every name in DataFlows' three sets must exist
 *  in this inventory. SessionBudget reads the same sets, so its
 *  classes are pinned against them too. */
private fun classifierInventory() {
    val expected = mapOf(
        // observe scope (15) — all read
        "device_info" to DataFlows.READ, "session_status" to DataFlows.READ,
        "current_app" to DataFlows.READ, "snapshot" to DataFlows.READ,
        "screenshot" to DataFlows.READ, "annotated_screenshot" to DataFlows.READ,
        "wait_for" to DataFlows.READ, "clipboard_get" to DataFlows.READ,
        "camera_capture" to DataFlows.READ, "notifications_read" to DataFlows.READ,
        "notify_user" to DataFlows.READ, "platform_sessions" to DataFlows.READ,
        "platform_session_status" to DataFlows.READ,
        "events_subscribe" to DataFlows.READ, "events_unsubscribe" to DataFlows.READ,
        // W11-B (2026-11-23): the gap-disposition tools
        "structured_extract" to DataFlows.READ, "crash_report_read" to DataFlows.READ,
        "app_card_read" to DataFlows.READ,
        // shell/admin readers — results carry device data out (6)
        "file_list" to DataFlows.READ, "file_pull" to DataFlows.READ,
        "settings_get" to DataFlows.READ, "logcat_read" to DataFlows.READ,
        "package_info" to DataFlows.READ, "session_replay_data" to DataFlows.READ,
        // background catalogue, non-mutating (4 more; device_info above)
        "storage_report" to DataFlows.READ, "log_bundle_collect" to DataFlows.READ,
        "network_probe" to DataFlows.READ, "access_snapshot" to DataFlows.READ,
        // drive scope (9) — all changed; start/end_session included:
        // opening/closing a session acts on the device, it is not a read
        "start_session" to DataFlows.CHANGED, "end_session" to DataFlows.CHANGED,
        "tap" to DataFlows.CHANGED, "tap_point" to DataFlows.CHANGED,
        "swipe" to DataFlows.CHANGED, "press" to DataFlows.CHANGED,
        "type_text" to DataFlows.CHANGED, "launch_app" to DataFlows.CHANGED,
        "clipboard_set" to DataFlows.CHANGED,
        "app_card_write" to DataFlows.CHANGED, "find_my_phone" to DataFlows.CHANGED,
        // shell actors (6)
        "shell_exec" to DataFlows.CHANGED, "settings_put" to DataFlows.CHANGED,
        "grant_permission" to DataFlows.CHANGED, "install_package" to DataFlows.CHANGED,
        "reboot_device" to DataFlows.CHANGED, "file_push" to DataFlows.CHANGED,
        // background catalogue, mutating (3)
        "app_cache_clear" to DataFlows.CHANGED, "service_restart" to DataFlows.CHANGED,
        "policy_reapply" to DataFlows.CHANGED
    )
    check("inventory: 48 distinct defined tools pinned", expected.size == 48)
    for ((tool, cls) in expected) {
        check("inventory: $tool classifies $cls", DataFlows.classify(tool) == cls)
    }
    check("inventory: no defined tool classifies sent on Android",
        expected.keys.none { DataFlows.classify(it) == DataFlows.SENT })
    for (setName in listOf("egress", "sending", "observe")) {
        val set = when (setName) {
            "egress" -> DataFlows.egressTools
            "sending" -> DataFlows.sendingTools
            else -> DataFlows.observeTools
        }
        check("inventory: every ${setName}Tools name is a defined tool",
            set.all { it in expected.keys })
    }
    check("budget: file_pull is egress (shared sets)", SessionBudget.isEgress("file_pull"))
    check("budget: phantom file_read is not egress", !SessionBudget.isEgress("file_read"))
    check("budget: screenshot counts toward egress calls",
        SessionBudget.Classes.EGRESS_CALLS in SessionBudget.classesFor("screenshot"))
    check("budget: no SENDING class for a phantom sender",
        SessionBudget.Classes.SENDING !in SessionBudget.classesFor("send_message"))
    check("budget: phantom input name 'click' earns no INPUT class",
        SessionBudget.Classes.INPUT !in SessionBudget.classesFor("click"))
}

// ------------------------------------------------------------------
// Choke-point sections (2026-11-22): the claims below run through
// the REAL dispatch / transfer code, not the counter API alone.
// ------------------------------------------------------------------

private fun utf8(s: String): Long = s.toByteArray(Charsets.UTF_8).size.toLong()

/** The production in-byte measure, restated independently: UTF-8
 *  size of the arguments object of this raw request body. */
private fun expectedArgsBytes(rawBody: String): Long {
    val args = JSONObject(rawBody).getJSONObject("params").optJSONObject("arguments")
    return utf8(args?.toString() ?: "")
}

private fun dispatchHost(): McpCore.ToolHost = object : McpCore.ToolHost {
    override fun tools(): List<McpCore.ToolDef> = listOf(
        McpCore.ToolDef(
            "device_info", "fake device info", "observe",
            JSONObject().put("type", "object"),
            run = { "{\"model\":\"TéstPhoné→✓\"}" }
        ),
        McpCore.ToolDef(
            "tap", "fake drive tool", "drive",
            JSONObject().put("type", "object"),
            run = { "tapped" }
        )
    )
}

private fun pairToken(core: McpCore, store: PairingStore, pairingName: String, agentName: String?): String {
    var sessionId: String? = null
    if (agentName != null) {
        val init = core.handle(
            """{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"clientInfo":{"name":"$agentName","version":"1.0"}}}""",
            null
        )
        sessionId = init.sessionId
    }
    val code = store.beginPairing(pairingName)
    val paired = core.handle(
        """{"jsonrpc":"2.0","id":2,"method":"pair","params":{"code":"$code"}}""", null, sessionId
    )
    return JSONObject(paired.body!!).getJSONObject("result").getString("token")
}

private fun callRaw(core: McpCore, token: String, rawBody: String): McpCore.Reply =
    core.handle(rawBody, token)

/** Exact byte reconciliation at the McpCore dispatch choke point. */
private fun dispatchReconciliation() {
    DataFlows.resetForTest()
    val dir = File(System.getProperty("java.io.tmpdir"), "acp-dataflow-" + System.nanoTime())
    dir.mkdirs()
    val store = PairingStore(File(dir, "pairings.tsv"))
    val core = McpCore(store, dispatchHost())
    val token = pairToken(core, store, "Recon AI", null)
    val pairing = store.pairingForToken(token)!!
    check("dispatch: pairing id is not its display name", pairing.id != pairing.name)
    check("dispatch: pairing id is stable across store reload",
        PairingStore(File(dir, "pairings.tsv")).pairingForToken(token)?.id == pairing.id)

    // Call 1: a successful observe call whose arguments AND result
    // carry multi-byte UTF-8 — byte counts must be UTF-8 sizes,
    // not character counts.
    val body1 = """{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"device_info","arguments":{"note":"héllo→✓","n":42}}}"""
    val reply1 = callRaw(core, token, body1)
    val in1 = expectedArgsBytes(body1)
    val out1 = utf8(reply1.body!!)
    check("dispatch: fixture really is multi-byte (bytes > chars)",
        in1 > JSONObject(body1).getJSONObject("params").getJSONObject("arguments").toString().length)
    var flow = DataFlows.agentFlows().single()
    check("dispatch: counted under the pairing id, never the name", flow.pairing == pairing.id)
    check("dispatch: bytesIn == exact argument bytes", flow.bytesIn == in1)
    check("dispatch: bytesOut == exact reply bytes", flow.bytesOut == out1)
    check("dispatch: one call counted", flow.calls == 1L)
    val toolRow = flow.tools.single { it.tool == "device_info" }
    check("dispatch: per-tool row reconciles", toolRow.bytesIn == in1 && toolRow.bytesOut == out1)
    check("dispatch: device_info classified read", toolRow.flowClass == DataFlows.READ)

    // Call 2: a capability-denied call. Its bytes crossed and the
    // audit counts it, so the counters must count it too.
    val body2 = """{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"tap","arguments":{"x":1,"y":2}}}"""
    val reply2 = callRaw(core, token, body2)
    check("dispatch: tap really was denied",
        JSONObject(reply2.body!!).getJSONObject("result").getBoolean("isError"))
    val in2 = expectedArgsBytes(body2)
    val out2 = utf8(reply2.body!!)
    flow = DataFlows.agentFlows().single()
    check("dispatch: denied call counted (in)", flow.bytesIn == in1 + in2)
    check("dispatch: denied call counted (out)", flow.bytesOut == out1 + out2)
    check("dispatch: audited mirror matches counted calls",
        DataFlows.auditedCounts()[pairing.id] == 2L)
    check("dispatch: corroborated report has no gaps", DataFlows.report().gaps.isEmpty())

    // Call 3: an unknown tool. Dispatch counts it (bytes crossed)
    // but handleToolsCall returns before the audit hook — the
    // report must surface that as a counted>audited GAP, not hide
    // it and not trim the counted bytes.
    val body3 = """{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"nope_tool","arguments":{}}}"""
    val reply3 = callRaw(core, token, body3)
    val in3 = expectedArgsBytes(body3)
    val out3 = utf8(reply3.body!!)
    flow = DataFlows.agentFlows().single()
    check("dispatch: unknown-tool call counted",
        flow.bytesIn == in1 + in2 + in3 && flow.bytesOut == out1 + out2 + out3 && flow.calls == 3L)
    val rep = DataFlows.report()
    check("dispatch: unaudited counted call surfaces as a gap",
        rep.gaps.any { it.contains(pairing.id) && it.contains("count 1 more call(s) than the audit") })
    check("dispatch: gap does not trim counted bytes",
        rep.agents.single().bytesOut == out1 + out2 + out3)

    // Revoking the pairing ends its access — never its totals.
    store.revoke(token)
    check("dispatch: revoked pairing keeps its flow totals",
        DataFlows.agentFlows().singleOrNull()?.bytesOut == out1 + out2 + out3)
}

/** DESTRUCTION: two pairings with identical display name AND
 *  identical agent name must never merge. Before the Pairing.id
 *  fix, DataFlows keyed by pairing.name and this folded both
 *  pairings into one row. */
private fun nameCollisionAttack() {
    DataFlows.resetForTest()
    val dir = File(System.getProperty("java.io.tmpdir"), "acp-dataflow-twin-" + System.nanoTime())
    dir.mkdirs()
    val store = PairingStore(File(dir, "pairings.tsv"))
    val core = McpCore(store, dispatchHost())
    val tokenA = pairToken(core, store, "Twin AI", "TwinAgent")
    val tokenB = pairToken(core, store, "Twin AI", "TwinAgent")
    val pA = store.pairingForToken(tokenA)!!
    val pB = store.pairingForToken(tokenB)!!
    check("Attack_NameCollision: twins share pairing name", pA.name == pB.name)
    check("Attack_NameCollision: twins share agent name", pA.agentName == pB.agentName)
    check("Attack_NameCollision: twins have distinct tokens", pA.token != pB.token)
    check("Attack_NameCollision: twins have distinct pairing ids", pA.id != pB.id)

    val bodyA = """{"jsonrpc":"2.0","id":20,"method":"tools/call","params":{"name":"device_info","arguments":{"who":"a"}}}"""
    val replyA = callRaw(core, tokenA, bodyA)
    val bodyB = """{"jsonrpc":"2.0","id":21,"method":"tools/call","params":{"name":"device_info","arguments":{"who":"bb","pad":"xxxxxxxxxxxxxxxxxxxx"}}}"""
    val replyB = callRaw(core, tokenB, bodyB)
    DataFlows.noteDestination(pA.id, "dev-only-a")

    val flows = DataFlows.agentFlows()
    check("Attack_NameCollision: two flow rows, never one merged row", flows.size == 2)
    val rowA = flows.single { it.pairing == pA.id }
    val rowB = flows.single { it.pairing == pB.id }
    check("Attack_NameCollision: A's bytes are exactly A's",
        rowA.bytesIn == expectedArgsBytes(bodyA) && rowA.bytesOut == utf8(replyA.body!!))
    check("Attack_NameCollision: B's bytes are exactly B's",
        rowB.bytesIn == expectedArgsBytes(bodyB) && rowB.bytesOut == utf8(replyB.body!!))
    check("Attack_NameCollision: A's destination never lands on B",
        rowA.destinations == listOf("dev-only-a") && rowB.destinations.isEmpty())
    check("Attack_NameCollision: audited counts stay per-pairing",
        DataFlows.auditedCounts()[pA.id] == 1L && DataFlows.auditedCounts()[pB.id] == 1L)
    check("Attack_NameCollision: report cross-check clean for both twins",
        DataFlows.report().gaps.isEmpty())
}

/** Transfer bytes through the real StandaloneTransferStore
 *  progress path: deltas reconcile exactly, refused progress
 *  counts nothing, an ended (done) job keeps its totals. */
private fun transferPathReconciliation() {
    DataFlows.resetForTest()
    val dir = File(System.getProperty("java.io.tmpdir"), "acp-dataflow-xfer-" + System.nanoTime())
    dir.mkdirs()
    val enrollment = EnrollmentStore(File(dir, "enroll.tsv"))
    val roster = RosterStore(File(dir, "roster.tsv"), enrollment)
    roster.addScope(RosterStore.Scope("co", "company", "Acme Co"))
    roster.addUser(RosterStore.User("admin1", "co", "Admin One", "human"))
    roster.addCompanyAdmin("co", "admin1")
    roster.addUser(RosterStore.User("user1", "co", "User One", "human"))
    roster.addUserGroup(
        RosterStore.UserGroup("ug1", "co", "Techs", memberUserIds = setOf("user1")), "admin1"
    )
    roster.addDeviceGroup(
        RosterStore.DeviceGroup("dg1", "co", "Fleet", listOf("lan", "hub", "mesh")), "admin1"
    )
    roster.addGrant(RosterStore.Grant("co", "ug1", "dg1", setOf("use")), "admin1")
    val identity = DeviceIdentity.generate()
    val code = enrollment.mint("company", "dg1", "Fleet")
    enrollment.redeem(
        code, EnrollmentStore.EnrollingDevice(identity.deviceId, identity.publicKeyBase64, "Host Device")
    )

    val svc = StandaloneTransferStore(roster, enrollment, null, null) { System.currentTimeMillis() }
    val job = svc.createJob("co", identity.deviceId, "user1", "to_host", "report.pdf", 1000)
    check("transfer path: job created", job != null)
    svc.setJobState(job!!.id, "active", "user1")
    check("transfer path: progress 400 accepted", svc.updateProgress(job.id, 400, "user1"))
    check("transfer path: progress 650 accepted", svc.updateProgress(job.id, 650, "user1"))
    var xfer = DataFlows.transferFlows().single()
    check("transfer path: counted == moved (650, deltas only)",
        xfer.bytes == 650L && xfer.deviceId == identity.deviceId && xfer.direction == "to_host")
    check("transfer path: regressive progress refused", !svc.updateProgress(job.id, 600, "user1"))
    check("transfer path: over-size progress refused", !svc.updateProgress(job.id, 1200, "user1"))
    check("transfer path: non-initiator progress refused", !svc.updateProgress(job.id, 700, "admin1"))
    xfer = DataFlows.transferFlows().single()
    check("transfer path: refused progress counted nothing", xfer.bytes == 650L)
    check("transfer path: final progress accepted", svc.updateProgress(job.id, 1000, "user1"))
    check("transfer path: job completes", svc.setJobState(job.id, "done", "user1"))
    check("transfer path: ended job refuses further progress", !svc.updateProgress(job.id, 1000, "user1"))
    check("transfer path: ended transfer keeps its total (1000)",
        DataFlows.transferFlows().single().bytes == 1000L)
}
