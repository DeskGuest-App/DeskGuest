package io.agenticcontrol.app.server

import org.json.JSONArray
import org.json.JSONObject

/**
 * The MCP protocol core (SPEC §6): JSON-RPC dispatch for initialize,
 * tools/list and tools/call, with the pairing handshake as a first-class
 * method. Pure protocol logic — Android specifics live behind [ToolHost],
 * so this class runs unchanged in the JVM test suite.
 *
 * Transport note: this implements the request/response subset of MCP
 * streamable HTTP. Server-initiated streaming (SSE) is not part of S1;
 * every tool here answers synchronously and honestly.
 */
class McpCore(
    private val pairingStore: PairingStore,
    private val toolHost: ToolHost,
    private val serverVersion: String = "0.1.0",
    /**
     * RMM-03 gate (Lane B1), scoped by bd-and-core F1 (2026-11-22):
     * the gate governs HUB/RMM-ORIGINATED calls — a tools/call that
     * CARRIES a signed-command envelope ("_signed_command") must
     * verify before anything executes: shell_exec executes ONLY as
     * the envelope's payload; other tools require a
     * background_action envelope whose payload names the tool
     * ("tool=<name>"). A call carrying NO envelope is a locally
     * code-paired call and runs under the pairing + capability +
     * approval gates alone — the pre-fix shape (gate applies to
     * every call, over an empty ring on a fresh personal install)
     * made a locally paired agent unable to call even end_session.
     * end_session is exempt unconditionally: closing a session is a
     * safety action and an envelope can neither be required for it
     * nor block it. Null gate = the pre-RMM-03 posture, which the
     * wiring layer must name as UNWIRED, never as coverage.
     */
    private val commandGate: io.agenticcontrol.app.rmmspine.SignedCommandGate? = null,
    /**
     * Lane INT (2026-11-21): the wiring layer's honest refinement
     * of the WIRED state — e.g. a gate built over an EMPTY ring is
     * present-but-refusing, and this text says so instead of
     * claiming key coverage that does not exist. Null keeps the
     * original WIRED wording. Never consulted when no gate is
     * wired: an absent gate is always named UNWIRED.
     */
    private val commandGateStateDetail: String? = null,
    private val clockMs: () -> Long = { System.currentTimeMillis() }
) {

    /** Named gate posture for surfaces that report RMM-03 state. */
    val commandGateState: String
        get() = when {
            commandGate == null -> "UNWIRED: no customer command key ring is provisioned on this host — tools run under pairing + capability + approval gates only; signed-command coverage is NOT claimed"
            commandGateStateDetail != null -> commandGateStateDetail
            else -> "WIRED: calls carrying a signed-command envelope verify against the customer key before executing (RMM-03); locally code-paired calls without an envelope run under pairing + capability + approval gates (bd-and-core F1)"
        }

    init {
        toolHost.attach(this)
    }
    /**
     * A tool the host can run. [scope] gates who may call it. [run]
     * returns plain text; [runContent], when set, returns the full MCP
     * content array instead (used by the screenshot tool for images).
     */
    data class ToolDef(
        val name: String,
        val description: String,
        val scope: String,
        val inputSchema: JSONObject,
        val run: (JSONObject) -> String,
        val runContent: ((JSONObject) -> JSONArray)? = null
    )

    /**
     * Who is calling, handed to every tool run: the pairing's bound
     * agent identity (clientInfo from initialize, via the store) with
     * the pairing's display name as fallback. Presence and status use
     * this so the phone names the actual connected agent.
     */
    data class Caller(val agentName: String, val pairingName: String) {
        /** The name to show the user: the agent's real name when known. */
        val displayName: String get() = agentName.ifBlank { pairingName }
    }

    /** The caller of the request currently being handled (per-thread). */
    val currentCaller = ThreadLocal<Caller>()

    /** U2: the calling pairing's key (its bearer token) for the
     *  request currently being handled. Event tools key the
     *  pairing's subscription by this — a tool can only ever touch
     *  its own pairing's filter. Never logged or emitted. */
    val currentPairingKey = ThreadLocal<String?>()

    /** U2: resolve a bearer token to its pairing (the SSE layer
     *  keys the stream's subscription filter by the token). */
    fun pairingForToken(bearerToken: String?): PairingStore.Pairing? =
        pairingStore.pairingForToken(bearerToken)

    interface ToolHost {
        fun tools(): List<ToolDef>

        /** Set by the core before it serves tools, so hosts can read
         *  per-request state (the caller) from the owning core. */
        fun attach(core: McpCore) {}
    }

    /** Outcome of handling one request body. */
    data class Reply(val httpStatus: Int, val body: String?, val sessionId: String? = null)

    /** The identity an agent presents in initialize (MCP clientInfo). */
    data class ClientInfo(val name: String, val version: String)

    private var issuedSession: String? = null

    /** clientInfo by issued session id (bd-and-core F8/F10,
     *  2026-11-22): BOUNDED (64 entries, least-recently-used
     *  evicted — the old map grew one entry per unauthenticated
     *  initialize, forever) and with NO global fallback: pair
     *  resolves identity ONLY from the session id this connection
     *  was issued at initialize, so one client's self-reported name
     *  can never be bound to another client's pairing. */
    private val sessionClients: MutableMap<String, ClientInfo> =
        java.util.Collections.synchronizedMap(
            object : LinkedHashMap<String, ClientInfo>(16, 0.75f, true) {
                override fun removeEldestEntry(
                    eldest: MutableMap.MutableEntry<String, ClientInfo>?
                ): Boolean = size > MAX_SESSION_CLIENTS
            }
        )

    /** True when [bearerToken] resolves to a live pairing. The SSE
     *  event stream checks this before it opens (0.4.0). */
    fun isAuthorized(bearerToken: String?): Boolean =
        pairingStore.pairingForToken(bearerToken) != null

    /**
     * W98 / S09(b): the audit hook for connection-path enforcement
     * refusals at this core's choke points. ControlService wires it
     * to the AuditStore as kind "pairing_connection" (the W97 audit
     * kind). Null in tests: refusals then only refuse.
     */
    @Volatile
    var connectionAuditSink: ((name: String, ok: Boolean, detail: String) -> Unit)? = null

    private fun fireConnectionAudit(name: String, ok: Boolean, detail: String) {
        try {
            connectionAuditSink?.invoke(name, ok, detail)
        } catch (_: Exception) {
        }
    }

    /**
     * W98 / S09(b): the connection-path gate at the authentication
     * choke point (the W97 McpHandler.PathAllowed shape). A null
     * [arrivalPath] means this is not a network arrival (an
     * in-process caller, or a JVM-suite call) — there is no path
     * to police and the gate passes. A real arrival the pairing's
     * setting excludes is REFUSED: the refusal is audited, the
     * current-path label does NOT move, and the setting never
     * widens. An allowed arrival notes the path (the label's only
     * source). Returns the refusal Reply, or null to proceed.
     */
    private fun pathRefusal(id: Any?, pairing: PairingStore.Pairing, arrivalPath: String?): Reply? {
        if (arrivalPath == null) return null
        if (!ConnectionPath.allows(pairing.connection, arrivalPath)) {
            fireConnectionAudit(
                pairing.name, false,
                ConnectionPath.refusalDetail(pairing.connection, arrivalPath)
            )
            return Reply(
                401,
                errorBody(id, -32001, "Unauthorized: this pairing may not connect over this path")
            )
        }
        pairingStore.noteConnection(pairing.token, arrivalPath)
        return null
    }

    /**
     * W98 / S09(b): the SSE leg's path check (McpHttpServer calls
     * this before opening a stream): same rule as [pathRefusal] —
     * a null arrival is not a network arrival; an excluded arrival
     * is refused and audited; an allowed one notes the path.
     */
    fun isPathAllowed(bearerToken: String?, arrivalPath: String?): Boolean {
        if (arrivalPath == null) return true
        val pairing = pairingStore.pairingForToken(bearerToken) ?: return false
        if (!ConnectionPath.allows(pairing.connection, arrivalPath)) {
            fireConnectionAudit(
                pairing.name, false,
                ConnectionPath.refusalDetail(pairing.connection, arrivalPath)
            )
            return false
        }
        pairingStore.noteConnection(pairing.token, arrivalPath)
        return true
    }

    /**
     * Handle one JSON-RPC request. [bearerToken] is the Authorization
     * header value already stripped of its "Bearer " prefix, or null.
     */
    fun handle(rawBody: String, bearerToken: String?): Reply = handle(rawBody, bearerToken, null)

    /**
     * As [handle], with the request's Mcp-Session-Id header (or null)
     * so the clientInfo captured at initialize can be found again at
     * pair time.
     */
    fun handle(rawBody: String, bearerToken: String?, sessionId: String?): Reply =
        handle(rawBody, bearerToken, sessionId, null)

    /**
     * W98 / S09(b): as [handle], with the path this request ARRIVED
     * over ([ConnectionPath.PATH_MESH] / [ConnectionPath.PATH_LOOPBACK]
     * as classified by the listener that accepted it in
     * McpHttpServer), or null when the call is not a network arrival.
     * Pairing-bearing methods enforce the pairing's connection-path
     * setting at the choke point (see [pathRefusal]); the pair door
     * enforces the mint-bound setting before the code is consumed.
     */
    fun handle(rawBody: String, bearerToken: String?, sessionId: String?, arrivalPath: String?): Reply {
        val request = try {
            JSONObject(rawBody)
        } catch (e: Exception) {
            return jsonRpcError(null, -32700, "Parse error: body is not valid JSON")
        }
        val id = if (request.has("id")) request.get("id") else null
        val method = request.optString("method", "")
        val params = request.optJSONObject("params") ?: JSONObject()

        // Notifications carry no id and expect no reply.
        if (id == null) return Reply(202, null)

        return when (method) {
            "initialize" -> handleInitialize(id, params)
            "ping" -> {
                // W98: ping carries no auth of its own, but when it
                // DOES present a live pairing's token it is that
                // pairing connecting — the path gate applies (this
                // is the request W97's live proof used).
                val pairing = pairingStore.pairingForToken(bearerToken)
                if (pairing != null) {
                    pathRefusal(id, pairing, arrivalPath)?.let { return it }
                }
                Reply(200, result(id, JSONObject()))
            }
            "pair" -> handlePair(id, params, sessionId, arrivalPath)
            "tools/list" -> {
                val pairing = pairingStore.pairingForToken(bearerToken)
                    ?: return Reply(401, errorBody(id, -32001, "Unauthorized: pair first, then send your bearer token"))
                pathRefusal(id, pairing, arrivalPath)?.let { return it }
                handleToolsList(id, pairing)
            }
            "tools/call" -> {
                val pairing = pairingStore.pairingForToken(bearerToken)
                    ?: return Reply(401, errorBody(id, -32001, "Unauthorized: pair first, then send your bearer token"))
                pathRefusal(id, pairing, arrivalPath)?.let { return it }
                val reply = handleToolsCall(id, params, pairing)
                // U5 data-flow accounting at the dispatch choke
                // point: the argument bytes this pairing sent in and
                // the response bytes that flowed back, per tool.
                // Every outcome counts (denials included — their
                // bytes crossed, and the audit counts them, so the
                // report's cross-check reconciles). Accounting never
                // breaks a call.
                try {
                    val argsBytes = (params.optJSONObject("arguments")?.toString() ?: "")
                        .toByteArray(Charsets.UTF_8).size.toLong()
                    val outBytes = (reply.body ?: "").toByteArray(Charsets.UTF_8).size.toLong()
                    DataFlows.noteCall(
                        pairing.id, pairing.agentName.ifBlank { pairing.name },
                        params.optString("name", ""), argsBytes, outBytes
                    )
                    // W7 item 4 (§4 A4): Sent counts DELIVERED
                    // frames, not calls — a frame tool whose result
                    // was delivered (HTTP 200, no isError content)
                    // counts exactly one delivered frame here, at
                    // the dispatch source that saw the delivery.
                    val toolName = params.optString("name", "")
                    val delivered = reply.httpStatus == 200 &&
                        !(reply.body ?: "").contains("\"isError\":true") &&
                        !(reply.body ?: "").contains("\"isError\": true")
                    if (io.agenticcontrol.app.design.FrameAccounting
                            .frameDelivered(toolName, !delivered)
                    ) {
                        DataFlows.noteDeliveredFrame(pairing.id)
                    }
                } catch (_: Exception) {
                }
                reply
            }
            else -> jsonRpcError(id, -32601, "Method not found: $method")
        }
    }

    private fun handleInitialize(id: Any?, params: JSONObject): Reply {
        val session = java.util.UUID.randomUUID().toString()
        issuedSession = session
        // Remember who is connecting (SPEC §5.2): the name the agent
        // gives here is bound to its pairing at pair time and shown in
        // the app as the proof of connection.
        val clientInfo = params.optJSONObject("clientInfo")
        val info = ClientInfo(
            name = clientInfo?.optString("name", "") ?: "",
            version = clientInfo?.optString("version", "") ?: ""
        )
        sessionClients[session] = info
        val result = JSONObject()
            .put("protocolVersion", PROTOCOL_VERSION)
            .put("capabilities", JSONObject().put("tools", JSONObject()))
            .put(
                "serverInfo", JSONObject()
                    .put("name", "agentic-control-platform")
                    .put("version", serverVersion)
            )
            .put(
                "instructions",
                "This is an DeskGuest host on the user's phone. " +
                    "Pair first (method: pair, with the one-time code the user reads from the app), " +
                    "then call tools with your bearer token. Presence and consent rules are enforced " +
                    "by the host, never by the agent."
            )
        return Reply(200, result(id, result), sessionId = session)
    }

    private fun handlePair(id: Any?, params: JSONObject, sessionId: String?, arrivalPath: String? = null): Reply {
        val code = params.optString("code", "")
        if (code.isBlank()) return jsonRpcError(id, -32602, "Missing pairing code")
        // W98 / S09(b): the pair door enforces the mint-bound
        // connection setting BEFORE the code is redeemed (W97's
        // exchange-door shape): an arrival over an excluded path is
        // refused WITHOUT consuming the code and WITHOUT counting
        // toward the brute-force brake — the code stays alive for
        // its allowed path. The refusal is audited.
        if (arrivalPath != null) {
            val pending = pairingStore.pendingConnectionSetting()
            if (!ConnectionPath.allows(pending, arrivalPath)) {
                fireConnectionAudit(
                    pairingStore.pendingPairingName(), false,
                    "pairing_exchange_refused_by_path: " +
                        ConnectionPath.refusalDetail(pending, arrivalPath)
                )
                return jsonRpcError(
                    id, -32003,
                    "Pairing refused: this pairing may not connect over this path"
                )
            }
        }
        var pairing = pairingStore.redeem(code, PairingStore.DEFAULT_SCOPES)
            ?: return jsonRpcError(id, -32002, "Pairing code not accepted (wrong, expired, or already used)")
        // W98: the redemption IS this pairing's first authenticated
        // arrival — it sets the current-path label.
        if (arrivalPath != null) pairingStore.noteConnection(pairing.token, arrivalPath)
        // Bind the clientInfo THIS session presented at initialize,
        // so the pairing carries the agent's real name from now on.
        // bd-and-core F10: no session id (or an unknown one) binds
        // NOTHING — the old lastClientInfo fallback let the most
        // recent unauthenticated initialize name every pairing.
        // The bound name is sanitized: control characters stripped,
        // capped at 40 chars — it becomes the presence title and the
        // approval-prompt subject, so it stays display-safe.
        val info = sessionId?.let { sessionClients[it] }
        if (info != null && info.name.isNotBlank()) {
            val safeName = info.name.filter { !it.isISOControl() }.trim().take(MAX_AGENT_NAME_CHARS)
            val safeVersion = info.version.filter { !it.isISOControl() }.trim().take(MAX_AGENT_NAME_CHARS)
            if (safeName.isNotBlank()) {
                pairing = pairingStore.bindAgentInfo(pairing.token, safeName, safeVersion) ?: pairing
            }
        }
        val result = JSONObject()
            .put("token", pairing.token)
            .put("name", pairing.name)
            .put("scopes", JSONArray(pairing.scopes.toList()))
            .put("access", pairing.access)
            .put("capabilities", JSONArray(pairing.caps.toList()))
        if (pairing.agentName.isNotBlank()) result.put("agentName", pairing.agentName)
        if (pairing.agentVersion.isNotBlank()) result.put("agentVersion", pairing.agentVersion)
        return Reply(200, result(id, result))
    }

    private fun handleToolsList(id: Any?, pairing: PairingStore.Pairing): Reply {
        val tools = JSONArray()
        toolHost.tools()
            .filter { it.scope in pairing.scopes || it.scope == "none" }
            .forEach { tool ->
                tools.put(
                    JSONObject()
                        .put("name", tool.name)
                        .put("description", tool.description)
                        .put("inputSchema", tool.inputSchema)
                )
            }
        return Reply(200, result(id, JSONObject().put("tools", tools)))
    }

    private fun handleToolsCall(id: Any?, params: JSONObject, pairing: PairingStore.Pairing): Reply {
        val name = params.optString("name", "")
        val args = params.optJSONObject("arguments") ?: JSONObject()
        val tool = toolHost.tools().firstOrNull { it.name == name }
            ?: return Reply(
                200, result(
                    id, JSONObject()
                        .put("content", JSONArray().put(textContent("Unknown tool: $name")))
                        .put("isError", true)
                )
            )
        // Capability gate (SPEC §5.3): the access level the user set
        // for this pairing decides what it may do, whatever its scopes
        // say. The refusal names the missing capability in plain words.
        capabilityRefusal(name, pairing)?.let { reason ->
            audit(pairing, name, false, reason)
            return Reply(
                200, result(
                    id, JSONObject()
                        .put("content", JSONArray().put(textContent(reason)))
                        .put("isError", true)
                )
            )
        }
        // bd-and-core F2: while an approval prompt is on screen,
        // every call but end_session refuses at the choke point —
        // tools that check neither driveRefusal nor observeRefusal
        // are covered here too, so the agent cannot act (or aim a
        // tap at its own prompt) through any surface.
        if (name != "end_session" && ApprovalPending.isPending) {
            audit(pairing, name, false, ApprovalPending.REFUSAL)
            return Reply(
                200, result(
                    id, JSONObject()
                        .put("content", JSONArray().put(textContent(ApprovalPending.REFUSAL)))
                        .put("isError", true)
                )
            )
        }
        // bd-and-core F4: session binding at the choke point. A
        // session opened by one pairing is that pairing's: other
        // pairings may read status (device_info / session_status /
        // event subscription) but may not drive, observe, or end
        // it. On-device STOP is not a tools/call and stays
        // universal. Unbound sessions (host-side starts) bind to
        // no pairing and skip this check.
        if (SessionManager.isOpen) {
            val ownerKey = SessionManager.activePairingKey
            if (ownerKey != null && ownerKey != pairing.token) {
                val reason = when (name) {
                    "end_session" ->
                        "This session belongs to another pairing; only the pairing that " +
                            "opened it can end it over the channel (the on-device STOP always can)."
                    in SESSION_STATUS_TOOLS -> null
                    else ->
                        "A drive session belonging to another pairing is open; this pairing " +
                            "cannot act inside it. Presence names the session's owner."
                }
                if (reason != null) {
                    audit(pairing, name, false, reason)
                    return Reply(
                        200, result(
                            id, JSONObject()
                                .put("content", JSONArray().put(textContent(reason)))
                                .put("isError", true)
                        )
                    )
                }
            }
        }
        // RMM-03 signed-command gate (bd-and-core F1 scoping): in
        // front of execution, after the pairing/capability/scope
        // gates — for calls that CARRY an envelope, and never for
        // end_session. A call with no envelope is a locally
        // code-paired call and proceeds under the local gates.
        // Refusals are audited by the gate itself (chained) and
        // here (tool audit).
        var effectiveArgs = args
        if (commandGate != null && name != "end_session" && args.has("_signed_command")) {
            val envJson = args.optJSONObject("_signed_command")
            val envelope = io.agenticcontrol.app.rmmspine.SignedCommandEnvelope.fromJson(envJson)
            val isShell = name == "shell_exec"
            val expectedClass = if (isShell) io.agenticcontrol.app.rmmspine.SignedCommandClasses.SHELL_EXEC
                else io.agenticcontrol.app.rmmspine.SignedCommandClasses.BACKGROUND_ACTION
            val expectedPayload = if (isShell) null else "tool=$name".toByteArray(Charsets.UTF_8)
            val verdict = commandGate.authorize(envelope, clockMs(), expectedClass, expectedPayload)
            if (!verdict.allowed) {
                val reason = "Signed command refused (RMM-03): ${verdict.reason}"
                audit(pairing, name, false, reason)
                return Reply(
                    200, result(
                        id, JSONObject()
                            .put("content", JSONArray().put(textContent(reason)))
                            .put("isError", true)
                    )
                )
            }
            if (isShell) {
                // The command that runs is the VERIFIED envelope
                // payload — the unsigned tool argument never runs.
                val payloadText = String(verdict.payload!!, Charsets.UTF_8)
                effectiveArgs = JSONObject(args.toString()).put("command", payloadText)
            }
        }
        if (tool.scope != "none" && tool.scope !in pairing.scopes) {
            return Reply(
                200, result(
                    id, JSONObject()
                        .put(
                            "content",
                            JSONArray().put(textContent("Tool '$name' needs scope '${tool.scope}', which this pairing does not hold"))
                        )
                        .put("isError", true)
                )
            )
        }
        // U4 budget leg: at the dispatch choke point, after the
        // capability/signed-command/scope gates, before execution.
        // Session lifecycle + status tools are never counted or
        // blocked (a paused session must stay stoppable and its
        // budget state readable). Only calls inside a live session
        // count — budgets are per session.
        if (name !in BUDGET_EXEMPT_TOOLS && SessionManager.isOpen) {
            if (SessionManager.isPaused && SessionManager.budgetPauseReason != null) {
                val reason = "session_paused: ${SessionManager.budgetPauseReason}"
                audit(pairing, name, false, reason)
                return Reply(
                    200, result(
                        id, JSONObject()
                            .put("content", JSONArray().put(textContent(reason)))
                            .put("isError", true)
                    )
                )
            }
            when (val verdict = SessionBudget.checkAndCount(SessionBudget.classesFor(name))) {
                is SessionBudget.Verdict.TripPause -> {
                    SessionManager.pauseByBudget(verdict.reason)
                    audit(pairing, name, false,
                        "budget_tripwire: class=${verdict.cls} count=${verdict.count} cap=${verdict.cap}")
                    return Reply(
                        200, result(
                            id, JSONObject()
                                .put("content", JSONArray().put(textContent(verdict.reason)))
                                .put("isError", true)
                        )
                    )
                }
                is SessionBudget.Verdict.Deny -> {
                    audit(pairing, name, false, verdict.reason)
                    return Reply(
                        200, result(
                            id, JSONObject()
                                .put("content", JSONArray().put(textContent(verdict.reason)))
                                .put("isError", true)
                        )
                    )
                }
                SessionBudget.Verdict.Allow -> {}
            }
        }
        currentCaller.set(Caller(pairing.agentName, pairing.name))
        currentPairingKey.set(pairing.token)
        return try {
            var content = tool.runContent?.invoke(effectiveArgs)
                ?: JSONArray().put(textContent(tool.run(effectiveArgs)))
            // U4 egress accounting: the bytes this successful
            // egress-class call actually returned. A byte-cap
            // crossing pauses the session for everything after it;
            // this call's payload already returned (the tripwire
            // event + audit carry the numbers).
            if (SessionManager.isOpen && SessionBudget.isEgress(name)) {
                val bytes = content.toString().toByteArray(Charsets.UTF_8).size.toLong()
                val trip = SessionBudget.noteEgressBytes(bytes)
                if (trip is SessionBudget.Verdict.TripPause) {
                    SessionManager.pauseByBudget(trip.reason)
                    audit(pairing, name, true,
                        "budget_tripwire: class=${trip.cls} count=${trip.count} cap=${trip.cap}")
                }
            }
            // The status tools name the connected agent when it is
            // known (SPEC §5.2): the name tag is the proof of connection.
            if (tool.runContent == null && name in AGENT_NAMED_TOOLS && pairing.agentName.isNotBlank()) {
                content = withAgentName(content, pairing)
            }
            audit(pairing, name, true, AuditLog.summarize(name, args))
            Reply(
                200, result(
                    id, JSONObject()
                        .put("content", content)
                        .put("isError", false)
                )
            )
        } catch (e: Exception) {
            audit(pairing, name, false, "failed: ${e.message}")
            Reply(
                200, result(
                    id, JSONObject()
                        .put("content", JSONArray().put(textContent("Tool '$name' failed: ${e.message}")))
                        .put("isError", true)
                )
            )
        }
    }

    /**
     * The audit hook (0.4.0): ControlService points this at the
     * encrypted audit log. Every tools/call outcome is recorded with
     * a redacted summary (AuditLog.summarize — never raw arguments).
     * Null in tests and whenever the log is unavailable: auditing
     * must never break a tool call.
     */
    @Volatile
    var auditSink: ((agent: String, tool: String, ok: Boolean, detail: String) -> Unit)? = null

    private fun audit(pairing: PairingStore.Pairing, tool: String, ok: Boolean, detail: String) {
        // U5: mirror the audited call into the data-flow cross-check
        // counts (same calls the audit records — no new collection).
        try {
            DataFlows.noteAudited(pairing.id)
        } catch (_: Exception) {
        }
        try {
            auditSink?.invoke(
                pairing.agentName.ifBlank { pairing.name }, tool, ok, detail
            )
        } catch (_: Exception) {
        }
    }

    /**
     * The capability [toolName] needs, or null when a valid pairing may
     * always call it. start_session is special-cased in
     * [capabilityRefusal]: it needs any one of the drive capabilities.
     * end_session is always allowed — closing a session is a safety
     * action, never gated (the scope check still applies).
     */
    private fun requiredCap(toolName: String): String? = when (toolName) {
        // W8 item 1: chat tools need no capability — chat confers
        // none (Addendum A: messaging is not a session).
        "device_info", "session_status", "end_session", "events_subscribe", "events_unsubscribe",
        "chat_read", "chat_post", "chat_ask" -> null
        "snapshot", "screenshot", "current_app", "annotated_screenshot", "wait_for",
        "clipboard_get", "package_info" -> PairingStore.CAP_SEE
        "tap", "tap_point", "swipe" -> PairingStore.CAP_TAP
        "type_text", "clipboard_set" -> PairingStore.CAP_TYPE
        "press", "open_app", "launch_app", "start_app" -> PairingStore.CAP_APPS
        "shell_exec" -> PairingStore.CAP_SHELL
        "settings_get", "settings_put" -> PairingStore.CAP_SETTINGS
        else -> null // unknown tools are refused by the unknown-tool path
    }

    /** A plain refusal reason if [pairing] lacks what [toolName] needs, else null. */
    private fun capabilityRefusal(toolName: String, pairing: PairingStore.Pairing): String? {
        if (toolName == "start_session") {
            if (pairing.caps.none { it in PairingStore.DRIVE_CAPS }) {
                return "Tool 'start_session' needs a drive capability (tap, type, or apps), " +
                    "which this pairing does not hold. The user can raise the access level in the app."
            }
            return null
        }
        val cap = requiredCap(toolName) ?: return null
        if (cap in pairing.caps) return null
        return "Tool '$toolName' needs the '$cap' capability, which this pairing does not hold. " +
            "The user can raise the access level in the app."
    }

    /** Add the pairing's agent name to a status tool's JSON text result. */
    private fun withAgentName(content: JSONArray, pairing: PairingStore.Pairing): JSONArray {
        return try {
            val first = content.optJSONObject(0) ?: return content
            if (first.optString("type") != "text") return content
            val parsed = try {
                JSONObject(first.optString("text", ""))
            } catch (e: Exception) {
                return content
            }
            parsed.put("agentName", pairing.agentName)
            if (pairing.agentVersion.isNotBlank()) parsed.put("agentVersion", pairing.agentVersion)
            first.put("text", parsed.toString(2))
            content
        } catch (e: Exception) {
            content
        }
    }

    private fun textContent(text: String): JSONObject =
        JSONObject().put("type", "text").put("text", text)

    private fun result(id: Any?, result: JSONObject): String =
        JSONObject().put("jsonrpc", "2.0").put("id", id).put("result", result).toString()

    private fun errorBody(id: Any?, code: Int, message: String): String =
        JSONObject().put("jsonrpc", "2.0").put("id", id)
            .put("error", JSONObject().put("code", code).put("message", message)).toString()

    private fun jsonRpcError(id: Any?, code: Int, message: String): Reply =
        Reply(200, errorBody(id, code, message))

    companion object {
        const val PROTOCOL_VERSION = "2025-03-26"
        /** bd-and-core F8: bound on remembered initialize identities. */
        const val MAX_SESSION_CLIENTS = 64
        /** bd-and-core F10: bound on a bound agent name/version. */
        const val MAX_AGENT_NAME_CHARS = 40
        /** bd-and-core F4: tools a non-owner pairing may still call
         *  while another pairing's session is open (status only). */
        private val SESSION_STATUS_TOOLS =
            setOf(
                "device_info", "session_status", "events_subscribe", "events_unsubscribe",
                // W8 item 1: chat is not part of any session, so a
                // session owned by another pairing never blocks it.
                "chat_read", "chat_post", "chat_ask"
            )
        /** Tools whose JSON results carry the connected agent's name. */
        private val AGENT_NAMED_TOOLS = setOf("device_info", "session_status")

        /** U4: tools the budget leg never counts or blocks —
         *  session lifecycle (a paused session stays stoppable)
         *  and the status surfaces that SHOW the budget state. */
        private val BUDGET_EXEMPT_TOOLS = setOf("start_session", "end_session", "session_status", "device_info", "events_subscribe", "events_unsubscribe", "chat_read", "chat_post", "chat_ask")
    }
}
