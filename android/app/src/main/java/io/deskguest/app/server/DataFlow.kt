package io.deskguest.app.server

/**
 * U5 — Per-agent data-flow transparency (Android mirror of the
 * Windows DataFlow ledger/report in DeskGuest.Shared/Sessions/DataFlow.cs).
 *
 * Until this lane, nothing on the phone counted bytes or
 * destinations per pairing/agent: the audit log records tool calls,
 * not data volumes. This object is the flow-accounting layer:
 *
 *  * Counters are fed at the dispatch choke point that already sees
 *    the traffic (McpCore.handle for tools/call: request argument
 *    bytes in, response content bytes out, per pairing + tool,
 *    classified read/sent/changed) and at the standalone-transfer
 *    progress path (bytes moved per target device).
 *  * ZERO TELEMETRY law: counters live in process memory on the
 *    owner's phone. Nothing here opens a socket, phones home, or
 *    collects anything beyond the byte counts of traffic the
 *    product already carries. The report is a READ-ONLY derivation;
 *    the audit (§7.10, append-only) gains no edit path through it.
 *  * Per-pairing isolation is structural: counters are keyed by
 *    the pairing's unique id ([io.deskguest.app.server
 *    .PairingStore.Pairing.id]) and aggregated strictly per key —
 *    two pairings' flows never merge. The key must NEVER be a
 *    display name: pairing names and agent names are not unique
 *    (two pairings can carry both identically), and keying by
 *    name folded two pairings into one record — the Android
 *    mirror of the Windows ledger session-id collision, found
 *    and fixed 2026-11-22 (regression: DataFlowTest
 *    Attack_NameCollision_TwoPairingsSameName_NeverMerge).
 *  * GAPS SHOW AS GAPS: [report] cross-checks audited call counts
 *    per pairing (supplied by the caller from the audit records
 *    that already exist) against the counted calls. Audited calls
 *    with no flow record are named as a gap with their count —
 *    their bytes are unknown and are NEVER estimated or folded
 *    into an agent's totals.
 *
 * Lifetime note (honest limit): unlike the Windows ledger, these
 * counters are in-memory — they cover the current process life.
 * Totals for a pairing accumulate across its sessions within that
 * life and are never reset by a session ending; a process restart
 * starts them from zero, and the gap cross-check against the
 * (persisted) audit will say exactly that.
 */
object DataFlows {

    const val READ = "read"
    const val SENT = "sent"
    const val CHANGED = "changed"
    val CLASSES = listOf(READ, SENT, CHANGED)

    // The three sets name THIS host's tools — reconciled 2026-11-22
    // against the real definitions (decomposition corrected
    // 2026-11-23, W18-C: 44 ToolDefs across the server/wiring hosts
    // − the 3 chat tools, which the ledger accounts on its separate
    // chat leg rather than here, + 7 bg-only names from
    // BgToolCatalogue's 8 — its 8th, device_info, is already a
    // ToolDef — = the 48 pinned in DataFlowTest). Before that they were
    // carried over from the Windows mirror and named tools Android
    // never had (file_read, send_message, session_start, ping, …):
    // 14 of 22 entries pointed at no tool on this host, real
    // readers (file_pull, logcat_read, the bg reports) classified
    // as changed, and the SENT class could never fire. The
    // inventory check in DataFlowTest now pins every defined
    // tool's class so the sets cannot drift silently again, and
    // SessionBudget reads these same sets — one source of truth.

    /** Tools whose result carries device data out to the agent. */
    val egressTools = setOf(
        "device_info", "session_status", "current_app", "snapshot", "screenshot",
        "annotated_screenshot", "wait_for", "clipboard_get", "camera_capture",
        "notifications_read", "platform_sessions", "platform_session_status",
        "events_subscribe",
        "structured_extract", "crash_report_read", "app_card_read",
        "file_list", "file_pull", "settings_get", "logcat_read", "package_info",
        "session_replay_data",
        "storage_report", "log_bundle_collect", "network_probe", "access_snapshot"
    )

    /** Tools that send a message off this device to a third party.
     *  Android has none today — the class exists for report parity
     *  with the Windows ledger; an empty set is the honest state,
     *  not a gap to fill with names from another host. */
    val sendingTools = emptySet<String>()

    /** Every tool defined with scope "observe" on this host. */
    val observeTools = setOf(
        "device_info", "session_status", "current_app", "snapshot", "screenshot",
        "annotated_screenshot", "wait_for", "clipboard_get", "camera_capture",
        "notifications_read", "notify_user", "platform_sessions", "platform_session_status",
        "events_subscribe", "events_unsubscribe",
        "structured_extract", "crash_report_read", "app_card_read"
    )

    /** Classify one tool call: egress (its result carries device
     *  data out) or observe-scope → read; the sending set → sent;
     *  everything else acted on the device → changed. */
    fun classify(tool: String): String = when {
        tool in egressTools || tool in observeTools -> READ
        tool in sendingTools -> SENT
        else -> CHANGED
    }

    data class ToolFlow(
        val tool: String, val flowClass: String,
        var calls: Long = 0, var bytesIn: Long = 0, var bytesOut: Long = 0
    )

    data class AgentFlow(
        val pairing: String, val agentName: String,
        val tools: List<ToolFlow>, val destinations: List<String>
    ) {
        val bytesIn: Long get() = tools.sumOf { it.bytesIn }
        val bytesOut: Long get() = tools.sumOf { it.bytesOut }
        val calls: Long get() = tools.sumOf { it.calls }
        fun byClass(flowClass: String): ToolFlow? =
            tools.filter { it.flowClass == flowClass }.takeIf { it.isNotEmpty() }?.let { rows ->
                ToolFlow("class:$flowClass", flowClass,
                    rows.sumOf { it.calls }, rows.sumOf { it.bytesIn }, rows.sumOf { it.bytesOut })
            }
    }

    data class TransferFlow(val deviceId: String, val direction: String, var bytes: Long = 0)

    data class Report(val agents: List<AgentFlow>, val transfers: List<TransferFlow>, val gaps: List<String>)

    // W7 item 4 (design record §4 A4): delivered-frame accounting.
    // Sent counts DELIVERED frames, not calls — fed only from the
    // dispatch path when a frame tool's result was actually
    // delivered (FrameAccounting.frameDelivered). Chat messages to
    // an off-device agent (A17/[R4]) count as Sent under the
    // pairing, outside any session.
    private val framesByPairing = mutableMapOf<String, Long>()
    private val chatSentByPairing = mutableMapOf<String, Long>()

    /** Count one DELIVERED frame for [pairingId]. */
    fun noteDeliveredFrame(pairingId: String) {
        if (pairingId.isBlank()) return
        synchronized(lock) { framesByPairing[pairingId] = (framesByPairing[pairingId] ?: 0) + 1 }
    }

    /** Count one chat message sent to an off-device agent (A17). */
    fun noteChatMessageSent(pairingId: String) {
        if (pairingId.isBlank()) return
        synchronized(lock) { chatSentByPairing[pairingId] = (chatSentByPairing[pairingId] ?: 0) + 1 }
    }

    fun framesDelivered(pairingId: String): Long =
        synchronized(lock) { framesByPairing[pairingId] ?: 0 }

    fun chatSentCount(pairingId: String): Long =
        synchronized(lock) { chatSentByPairing[pairingId] ?: 0 }

    fun totalFramesDelivered(): Long = synchronized(lock) { framesByPairing.values.sum() }
    fun totalChatSent(): Long = synchronized(lock) { chatSentByPairing.values.sum() }

    private val lock = Any()
    private val auditedByPairing = mutableMapOf<String, Long>()
    private val toolsByPairing = mutableMapOf<String, MutableMap<String, ToolFlow>>()
    private val agentNameByPairing = mutableMapOf<String, String>()
    private val destinationsByPairing = mutableMapOf<String, MutableSet<String>>()
    private val transfersByKey = mutableMapOf<String, TransferFlow>()

    /** Count one dispatched call. [pairingId] is the pairing's
     *  unique id (Pairing.id) — never a display name (see header).
     *  Negative byte counts are refused — a counter only ever grows. */
    fun noteCall(pairingId: String, agentName: String, tool: String, bytesIn: Long, bytesOut: Long) {
        // W1 destruction hardening (2026-11-22): a blank pairing id
        // would mint an anonymous "" flow row that no pairing owns
        // and the report would present as an agent — refused, like
        // negative bytes. The choke point always supplies a real
        // Pairing.id, so no legitimate call is affected.
        if (pairingId.isBlank() || bytesIn < 0 || bytesOut < 0) return
        synchronized(lock) {
            if (agentName.isNotBlank()) agentNameByPairing[pairingId] = agentName
            val tools = toolsByPairing.getOrPut(pairingId) { mutableMapOf() }
            val row = tools.getOrPut(tool) { ToolFlow(tool, classify(tool)) }
            row.calls++
            row.bytesIn += bytesIn
            row.bytesOut += bytesOut
        }
    }

    /** Mirror one audited tool call (fed from McpCore's existing
     *  audit hook — the same calls the audit log records, counted
     *  in-process so the owner surface can cross-check without a
     *  new collection). */
    fun noteAudited(pairingId: String) {
        if (pairingId.isBlank()) return
        synchronized(lock) { auditedByPairing[pairingId] = (auditedByPairing[pairingId] ?: 0) + 1 }
    }

    /** The audited tool-call counts this process has mirrored. */
    fun auditedCounts(): Map<String, Long> = synchronized(lock) { auditedByPairing.toMap() }

    /** Count bytes moved by a standalone transfer toward a target
     *  device (the destination the owner can see). */
    fun noteTransfer(deviceId: String, direction: String, deltaBytes: Long) {
        if (deltaBytes <= 0 || deviceId.isBlank() || direction.isBlank()) return
        synchronized(lock) {
            val key = "$deviceId|$direction"
            val row = transfersByKey.getOrPut(key) { TransferFlow(deviceId, direction) }
            row.bytes += deltaBytes
        }
    }

    fun noteDestination(pairingId: String, destination: String) {
        if (pairingId.isBlank() || destination.isBlank()) return
        synchronized(lock) { destinationsByPairing.getOrPut(pairingId) { mutableSetOf() }.add(destination) }
    }

    /** Snapshot of every pairing's flows, sorted by pairing name. */
    fun agentFlows(): List<AgentFlow> = synchronized(lock) {
        toolsByPairing.entries.sortedBy { it.key }.map { (pairing, tools) ->
            AgentFlow(
                pairing = pairing,
                agentName = agentNameByPairing[pairing] ?: "",
                tools = tools.values.map { it.copy() }.sortedBy { it.tool },
                destinations = destinationsByPairing[pairing]?.sorted() ?: emptyList()
            )
        }
    }

    fun transferFlows(): List<TransferFlow> = synchronized(lock) {
        transfersByKey.values.map { it.copy() }.sortedBy { it.deviceId }
    }

    /**
     * The owner-visible view, cross-checked against the audit.
     * [auditedCallsByPairing] comes from the audit records the
     * product already keeps (pairing name → tool_call count).
     * Discrepancies become named gaps; nothing is fabricated.
     */
    fun report(auditedCallsByPairing: Map<String, Long> = auditedCounts()): Report {
        val agents = agentFlows()
        val gaps = mutableListOf<String>()
        val countedByPairing = agents.associate { it.pairing to it.calls }
        for ((pairing, audited) in auditedCallsByPairing.entries.sortedBy { it.key }) {
            val counted = countedByPairing[pairing] ?: 0
            if (audited > counted) {
                gaps.add(
                    "$pairing: ${audited - counted} audited tool call(s) have no flow record " +
                        "(they predate flow accounting or ran before this process started) — shown as a gap; " +
                        "their byte volumes are unknown and are NOT estimated or included in any total."
                )
            } else if (counted > audited) {
                gaps.add(
                    "$pairing: flow counters count ${counted - audited} more call(s) than the audit supplied " +
                        "to this view — flows are shown from the counters; the audit remains the authority " +
                        "for what was attempted."
                )
            }
        }
        for (agent in agents) {
            if (agent.pairing !in auditedCallsByPairing) {
                gaps.add(
                    "${agent.pairing}: flow counters exist but no audited tool calls were supplied to this " +
                        "view — the cross-check could not run for this agent, so its flows are shown uncorroborated."
                )
            }
        }
        return Report(agents, transferFlows(), gaps)
    }

    /** Plain-language lines for the Sessions detail surface
     *  (fields only — no new screen). */
    fun summaryLines(auditedCallsByPairing: Map<String, Long> = auditedCounts()): List<String> {
        val report = report(auditedCallsByPairing)
        val lines = mutableListOf<String>()
        for (agent in report.agents) {
            val name = agent.agentName.ifBlank { agent.pairing }
            lines.add("$name — in ${agent.bytesIn} B, out ${agent.bytesOut} B, ${agent.calls} call(s)")
            for (cls in CLASSES) {
                agent.byClass(cls)?.let { c ->
                    lines.add("  $cls: ${c.calls} call(s), in ${c.bytesIn} B, out ${c.bytesOut} B")
                }
            }
            if (agent.destinations.isNotEmpty()) {
                lines.add("  destinations: ${agent.destinations.joinToString(", ")}")
            }
            val frames = framesDelivered(agent.pairing)
            if (frames > 0) {
                lines.add("  sent: $frames delivered screen(s) counted at the frame source")
            }
            val chat = chatSentCount(agent.pairing)
            if (chat > 0) {
                lines.add("  sent: $chat chat message(s) sent from Agent chat")
            }
        }
        for (t in report.transfers) {
            lines.add("transfer → ${t.deviceId} (${t.direction}): ${t.bytes} B")
        }
        for (gap in report.gaps) lines.add("gap: $gap")
        if (lines.isEmpty()) lines.add("No data flows recorded yet.")
        return lines
    }

    /** Test-only reset (the production surface has no reset: totals
     *  only ever grow within the process life). */
    fun resetForTest() {
        synchronized(lock) {
            framesByPairing.clear()
            chatSentByPairing.clear()
            auditedByPairing.clear()
            toolsByPairing.clear()
            agentNameByPairing.clear()
            destinationsByPairing.clear()
            transfersByKey.clear()
        }
    }
}
