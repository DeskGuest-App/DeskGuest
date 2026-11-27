package io.deskguest.app.wiring

import io.deskguest.app.server.McpCore
import org.json.JSONArray
import org.json.JSONObject

/**
 * The MCP surface for Slice 3 sessions (Block A wiring): a paired
 * agent reads the SAME SessionStore the app's sessions screen reads
 * (both go through the one PlatformStores instance behind
 * [storesProvider]), so a session visible in the app is the same
 * session the agent sees — same id, same state, same floor holder,
 * same derived recording state.
 *
 * Read-only BY DESIGN. There is deliberately:
 * - no accept tool: acceptance is endpoint-local (RULING
 *   2026-11-19) — a channel accept is refused by the store, and
 *   this surface does not offer the attempt;
 * - no stop/transition tool: Slice 3 session control acts are
 *   host-side acts in the app. (The agent-session end_session tool
 *   on the phone hosts is a different session kind and unchanged.)
 *
 * The provider is invoked per call, never at construction: opening
 * the stores (and, deeper, the identity) must stay off the
 * ControlService startup path. Pure JVM — runs in the JVM suite.
 */
class PlatformToolHost(
    /**
     * bd-and-core F11 fix (2026-11-22): the roster scopes the
     * CALLING pairing may see, resolved from its pairing key.
     * Null (the default) = no caller context — direct host-side /
     * JVM-suite use, unfiltered, exactly as before. ControlService
     * always supplies the resolver: an unbound pairing resolves to
     * the personal scope(s) only, a bound pairing to its bound
     * scopes, an unknown token to none. A session outside the
     * caller's scopes is ABSENT from list output and an honest
     * "no such session" from status — its participants and event
     * history never cross the scope wall.
     * (Parameter order: storesProvider stays LAST so existing
     * trailing-lambda constructions — PlatformToolHost { stores } —
     * keep binding to it.)
     */
    private val callerScopes: ((pairingKey: String?) -> Set<String>)? = null,
    private val storesProvider: () -> PlatformStores?
) : McpCore.ToolHost {

    @Volatile
    private var core: McpCore? = null

    override fun attach(core: McpCore) {
        this.core = core
    }

    /** The scopes the current caller may see, or null when this
     *  host runs without a caller-scope resolver. */
    private fun visibleScopes(): Set<String>? =
        callerScopes?.invoke(core?.currentPairingKey?.get())

    private fun visible(scopeId: String): Boolean =
        visibleScopes()?.let { scopeId in it } ?: true

    override fun tools(): List<McpCore.ToolDef> = listOf(
        McpCore.ToolDef(
            name = "platform_sessions",
            description = "The human remote sessions (Slice 3 model) on this device: id, scope, " +
                "host device, initiator, kind, state, transport, recording state, and floor holder. " +
                "This is the same session list the app shows. Read-only.",
            scope = "observe",
            inputSchema = JSONObject().put("type", "object").put("properties", JSONObject()),
            run = { listSessions() }
        ),
        McpCore.ToolDef(
            name = "platform_session_status",
            description = "One human remote session in full: state, participants with roles and " +
                "floor, the derived recording state, and its event history. Read-only.",
            scope = "observe",
            inputSchema = JSONObject().put("type", "object")
                .put(
                    "properties", JSONObject().put(
                        "session_id",
                        JSONObject().put("type", "string").put("description", "The session id from platform_sessions")
                    )
                )
                .put("required", JSONArray().put("session_id")),
            run = { args -> sessionStatus(args) }
        )
    )

    private fun stores(): PlatformStores? = try {
        storesProvider()
    } catch (_: Exception) {
        null
    }

    private fun sessionJson(stores: PlatformStores, sessionId: String): JSONObject? {
        val detail = stores.sessionDetail(sessionId) ?: return null
        val s = detail.session
        return JSONObject()
            .put("id", s.id)
            .put("scopeId", s.scopeId)
            .put("hostDeviceId", s.hostDeviceId)
            .put("initiatorUserId", s.initiatorUserId)
            .put("kind", s.kind)
            .put("state", s.state)
            .put("transportRung", s.transportRung)
            .put("recording", s.recording)
            .put("isRecording", detail.isRecording)
            .put("floorHolderUserId", detail.floorHolderUserId ?: JSONObject.NULL)
            .put("endReason", s.endReason ?: JSONObject.NULL)
    }

    private fun listSessions(): String {
        val stores = stores()
            ?: return JSONObject().put("error", "platform stores are not open").toString()
        val array = JSONArray()
        stores.allSessions().forEach { s ->
            // bd-and-core F11: out-of-scope sessions are absent,
            // not listed-and-redacted.
            if (visible(s.scopeId)) sessionJson(stores, s.id)?.let { array.put(it) }
        }
        return JSONObject().put("sessions", array).toString(2)
    }

    private fun sessionStatus(args: JSONObject): String {
        val stores = stores()
            ?: return JSONObject().put("error", "platform stores are not open").toString()
        val sessionId = args.optString("session_id", "")
        val detail = stores.sessionDetail(sessionId)
            // bd-and-core F11: an out-of-scope session reads as no
            // such session — participants and events stay host-side.
            ?.takeIf { visible(it.session.scopeId) }
            ?: return JSONObject().put("error", "no such session: $sessionId").toString()
        val base = sessionJson(stores, sessionId) ?: return JSONObject().put("error", "no such session: $sessionId").toString()
        val parts = JSONArray()
        detail.participants.forEach { p ->
            parts.put(
                JSONObject()
                    .put("userId", p.userId)
                    .put("role", p.role)
                    .put("floor", p.floor)
            )
        }
        base.put("participants", parts)
        val events = JSONArray()
        detail.events.forEach { e ->
            events.put(
                JSONObject()
                    .put("atMs", e.atMs)
                    .put("type", e.type)
                    .put("actorUserId", e.actorUserId)
                    .put("detail", e.detail)
            )
        }
        base.put("events", events)
        return base.toString(2)
    }
}
