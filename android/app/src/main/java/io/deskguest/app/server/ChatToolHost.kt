package io.deskguest.app.server

import io.deskguest.app.chat.AgentChatStore
import io.deskguest.app.design.AgentChatModel
import io.deskguest.app.strings.ConsentStrings
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * W8 item 1 — Agent chat transport (Addendum A: the same agent is
 * "equally reachable in its own app"). The minimal honest
 * transport on the EXISTING architecture: the pairing's MCP
 * channel is the channel an agent already has to this device, so
 * chat rides it as tools the paired agent calls in its own app
 * context, authenticated by its own bearer token and bound to its
 * OWN pairing only (the calling pairing is read from McpCore's
 * per-request thread-locals — a tool can only ever touch its own
 * pairing's thread, the EventToolHost rule).
 *
 *  - chat_read: the owner→agent delivery leg. Returns this
 *    pairing's thread messages after the caller's cursor plus the
 *    next cursor, both from ONE store snapshot (W10, V3-F7).
 *    Delivery is pull-based: this architecture has no
 *    server-initiated push leg for message bodies (McpCore is
 *    request/response; the SSE stream carries event kinds, never
 *    bodies), and the tool description says so rather than
 *    implying push.
 *  - chat_post: the agent→device leg. Appends an agent message
 *    to the same thread file the owner reads in
 *    AgentChatActivity, and emits a metadata-only session event.
 *    Rate-capped per pairing (W10, V3-F7).
 *  - chat_ask (W10, V3-F2): the A17 ask card. The agent asks from
 *    chat to act; the ask routes through the ordinary approval
 *    gate on the phone with the chat origin line (fromChat=true)
 *    via the injected [gateAsker] — ControlService wires it to
 *    ApprovalOverlay. Chat cannot approve: the gate's answer is
 *    the owner's, given on the phone, and approval executes
 *    nothing by itself — the agent still acts only through its
 *    ordinary gated tools afterwards.
 *
 * Scope (W10, V3-F2): all three tools declare scope "none" —
 * McpCore's scope-free value — because chat is capability-free:
 * McpCore already exempts them from capability, budget and
 * session-owner gates, and the declared scope now says the same
 * (the old "observe" declaration silently required the pairing
 * to hold the observe scope, contradicting the claim).
 *
 * Chat is not a session: these tools start nothing and grant
 * nothing. Audit stays metadata-only: McpCore's audit summarises
 * tool calls without raw arguments, and the store's audit event
 * carries pairing / direction / length / time — never a body.
 * Unpairing ends the thread: the pairing lookup fails (the token
 * is gone) AND MainActivity's unpair removes the thread file, so
 * every leg refuses/empties for a dead pairing.
 */
class ChatToolHost(
    private val chatDir: File,
    private val pairingStore: PairingStore,
    /** W10: the gate the chat_ask tool raises, injected so the
     *  JVM fixture can stand in for ApprovalOverlay. Null in
     *  contexts with no UI (the ask then refuses by name). */
    private val gateAsker: ((summary: String, payload: String, agentName: String) -> Boolean)? = null
) : McpCore.ToolHost {

    private var core: McpCore? = null

    override fun attach(core: McpCore) {
        this.core = core
    }

    override fun tools(): List<McpCore.ToolDef> = listOf(
        McpCore.ToolDef(
            name = "chat_read",
            description = "Read messages your user sent you in Agent chat on this phone. " +
                "Returns this pairing's thread messages after 'after_seq' (omit or 0 for all) " +
                "with their sequence numbers and the next cursor to pass next time. " +
                "Delivery is pull-based: call this to receive; nothing is pushed to you. " +
                "Chat is not a session — reading starts nothing and grants nothing.",
            scope = "none",
            inputSchema = JSONObject()
                .put("type", "object")
                .put(
                    "properties", JSONObject().put(
                        "after_seq",
                        JSONObject().put("type", "integer")
                            .put("description", "Return only messages after this sequence number.")
                    )
                ),
            run = { args -> read(args) }
        ),
        McpCore.ToolDef(
            name = "chat_post",
            description = "Post a message to your user in Agent chat on this phone. " +
                "The message lands in the same thread the user reads in the app. " +
                "Chat is not a session and cannot approve anything: to act, the user " +
                "still goes through the on-device approval gate.",
            scope = "none",
            inputSchema = JSONObject()
                .put("type", "object")
                .put(
                    "properties", JSONObject().put(
                        "body",
                        JSONObject().put("type", "string")
                            .put("description", "The message text (max $MAX_BODY_CHARS characters).")
                    )
                )
                .put("required", JSONArray().put("body")),
            run = { args -> post(args) }
        ),
        McpCore.ToolDef(
            name = "chat_ask",
            description = "Ask your user, from Agent chat, for approval to act. " +
                AgentChatModel.askCardLine() + " " +
                "The ask opens the ordinary approval gate on the phone, marked as asked " +
                "from Agent chat; the user answers there — nothing in chat can approve it, " +
                "and approval by itself performs no action: afterwards you act only " +
                "through your ordinary gated tools. Returns whether the user approved.",
            scope = "none",
            inputSchema = JSONObject()
                .put("type", "object")
                .put(
                    "properties", JSONObject().put(
                        "request",
                        JSONObject().put("type", "string")
                            .put(
                                "description",
                                "What you want to do, in plain words (max $MAX_BODY_CHARS characters). " +
                                    "Shown to the user verbatim in the approval gate."
                            )
                    )
                )
                .put("required", JSONArray().put("request")),
            run = { args -> ask(args) }
        )
    )

    /** The calling pairing, resolved from this request's token —
     *  never from an argument. Null once unpaired (thread ended). */
    private fun callingPairing(): PairingStore.Pairing? {
        val token = core?.currentPairingKey?.get() ?: return null
        return pairingStore.pairingForToken(token)
    }

    private fun read(args: JSONObject): String {
        val pairing = callingPairing()
            ?: return "Agent chat is unavailable: this pairing has ended, so its thread is closed."
        val afterSeq = if (args.has("after_seq")) args.optLong("after_seq", 0L) else 0L
        if (afterSeq < 0) return "chat_read refused: after_seq cannot be negative."
        // ONE snapshot: messages and cursor from the same load, so
        // a concurrent append can never be skipped by the cursor.
        val (messages, cursor) = AgentChatStore.snapshotAfter(chatDir, pairing.id, afterSeq)
        val arr = JSONArray()
        for (s in messages) {
            arr.put(
                JSONObject()
                    .put("seq", s.seq)
                    .put("atMs", s.message.atMs)
                    .put("direction", s.message.direction)
                    .put("body", s.message.body)
            )
        }
        return JSONObject()
            .put("pairing", pairing.id)
            .put("messages", arr)
            .put("next_cursor", cursor)
            .toString()
    }

    private fun post(args: JSONObject): String {
        val pairing = callingPairing()
            ?: return "Agent chat is unavailable: this pairing has ended, so its thread is closed."
        val body = args.optString("body", "").trim()
        if (body.isBlank()) return "chat_post refused: the message body is empty."
        if (body.length > MAX_BODY_CHARS) {
            return "chat_post refused: the message is ${body.length} characters; the limit is $MAX_BODY_CHARS."
        }
        if (!postRateAllows(pairing.id, System.currentTimeMillis())) {
            return "chat_post refused: too many messages in the last minute " +
                "(the cap is ${AgentChatModel.CHAT_POST_RATE_MAX} per minute per pairing). " +
                "Wait, then post again."
        }
        val atMs = System.currentTimeMillis()
        val stored = AgentChatStore.appendSequenced(
            chatDir, pairing.id, AgentChatStore.DIR_AGENT, body, atMs,
            agentOffDevice = true
        )
        // W13 P1-F7: the store's tombstone dropped it — the thread
        // ended under this call (unpair raced the post).
        if (stored.seq < 0) {
            return "Agent chat is unavailable: this pairing has ended, so its thread is closed."
        }
        // Metadata only — the body never enters an event/audit path.
        SessionEvents.emit(
            "chat_message_received",
            AgentChatStore.auditEvent(pairing.id, AgentChatStore.DIR_AGENT, body.length, atMs)
        )
        return JSONObject()
            .put("posted", true)
            .put("pairing", pairing.id)
            .put("seq", stored.seq)
            .put("chars", body.length)
            .toString()
    }

    /** The A17 ask: route the request through the ordinary gate
     *  with the chat origin. The gate is the owner's surface; this
     *  tool only reports its answer. */
    private fun ask(args: JSONObject): String {
        val pairing = callingPairing()
            ?: return "Agent chat is unavailable: this pairing has ended, so its thread is closed."
        val request = args.optString("request", "").trim()
        if (request.isBlank()) return "chat_ask refused: the request is empty."
        if (request.length > MAX_BODY_CHARS) {
            return "chat_ask refused: the request is ${request.length} characters; the limit is $MAX_BODY_CHARS."
        }
        val asker = gateAsker
            ?: return "chat_ask unavailable: no approval gate is wired on this device, so the ask cannot be shown to the user."
        // FR-123: a chat caller with no name is presented to the
        // gate plainly as an unnamed caller (the U8 wording, read
        // from the pure defaults — this host has no Context) —
        // never a fabricated generic name, never a blank.
        val agentName = pairing.agentName.ifBlank { pairing.name }
            .ifBlank { ConsentStrings.unnamedCallerLabel() }
        val approved = asker("Act on a request from Agent chat", request, agentName)
        SessionEvents.emit(
            "chat_ask_resolved",
            mapOf("pairing" to pairing.id, "approved" to approved)
        )
        return JSONObject()
            .put("approved", approved)
            .put(
                "note",
                if (approved) {
                    "The user approved at the approval gate on the phone. Approval performs " +
                        "no action by itself — proceed through your ordinary gated tools."
                } else {
                    "The user did not approve (denied, timed out, or the gate could not be shown)."
                }
            )
            .toString()
    }

    // ---- W10 (V3-F7): per-pairing post rate cap ----
    private val postTimes = mutableMapOf<String, ArrayDeque<Long>>()

    @Synchronized
    private fun postRateAllows(pairingId: String, nowMs: Long): Boolean {
        val times = postTimes.getOrPut(pairingId) { ArrayDeque() }
        while (!times.isEmpty() && nowMs - times.first() >= AgentChatModel.CHAT_POST_RATE_WINDOW_MS) {
            times.removeFirst()
        }
        if (times.size >= AgentChatModel.CHAT_POST_RATE_MAX) return false
        times.addLast(nowMs)
        return true
    }

    companion object {
        const val MAX_BODY_CHARS = 4000
    }
}
