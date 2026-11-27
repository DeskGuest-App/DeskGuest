package io.deskguest.app.server

import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Session-state events (0.4.0): the push channel behind the MCP SSE
 * stream. SessionManager and the approval gate emit here; the HTTP
 * server's event streams subscribe. Keeping the bus separate from
 * the transport means the state machine stays testable on the JVM
 * and the SSE layer is a pure consumer.
 *
 * Event states: session_started, paused_by_user, session_resumed,
 * stopped_by_user, session_ended, approval_required,
 * approval_resolved.
 *
 * U2: every event also carries a canonical KIND from the shared
 * registry (mirrors DeskGuest.Shared AgentEventKinds on Windows):
 * session, approval, screen_change, foreground_app, app_crash,
 * notification_posted. Legacy states map to kinds in [kindOf];
 * producers of the new facts (accessibility service, CrashTrap)
 * emit kinds directly via [emitKind].
 */
object SessionEvents {

    const val KIND_SESSION = "session"
    const val KIND_APPROVAL = "approval"
    const val KIND_SCREEN_CHANGE = "screen_change"
    const val KIND_FOREGROUND_APP = "foreground_app"
    const val KIND_APP_CRASH = "app_crash"
    const val KIND_NOTIFICATION_POSTED = "notification_posted"

    /** U1 per-read indicator kind — mirrors the Windows registry,
     *  which carries clipboard_read beside the six census kinds. */
    const val KIND_CLIPBOARD_READ = "clipboard_read"

    val ALL_KINDS: Set<String> = setOf(
        KIND_SESSION, KIND_APPROVAL, KIND_SCREEN_CHANGE,
        KIND_FOREGROUND_APP, KIND_APP_CRASH, KIND_NOTIFICATION_POSTED,
        KIND_CLIPBOARD_READ
    )

    fun kindOf(state: String): String = when (state) {
        KIND_SESSION, KIND_APPROVAL, KIND_SCREEN_CHANGE,
        KIND_FOREGROUND_APP, KIND_APP_CRASH, KIND_NOTIFICATION_POSTED,
        KIND_CLIPBOARD_READ -> state
        "approval_required", "approval_resolved" -> KIND_APPROVAL
        else -> KIND_SESSION // every legacy session-state emit
    }

    data class Event(
        val state: String,
        val detail: Map<String, Any?> = emptyMap(),
        val kind: String = kindOf(state),
        /** W5 (bd-supp-eventsub F7): monotonic per-bus sequence,
         *  assigned by [emit]; 0 means "not emitted through the bus"
         *  (a hand-built event). Carried in the JSON and as the SSE
         *  `id:` line so a reconnecting client can name its place. */
        val seq: Long = 0
    )

    private val listeners = CopyOnWriteArrayList<(Event) -> Unit>()
    private val sequence = java.util.concurrent.atomic.AtomicLong(0)

    /** Bounded replay ring (F7): the last [RING_CAPACITY] emitted
     *  events, for Last-Event-ID resume. A resume older than the
     *  ring returns what the ring holds; the sequence jump tells
     *  the client a gap happened — loss is detectable, never silent. */
    const val RING_CAPACITY = 128
    private val ring = ArrayDeque<Event>()

    fun addListener(listener: (Event) -> Unit) {
        listeners.add(listener)
    }

    fun removeListener(listener: (Event) -> Unit) {
        listeners.remove(listener)
    }

    fun emit(state: String, detail: Map<String, Any?> = emptyMap()) {
        val event = Event(state, detail, seq = sequence.incrementAndGet())
        synchronized(ring) {
            ring.addLast(event)
            while (ring.size > RING_CAPACITY) ring.removeFirst()
        }
        listeners.forEach { listener ->
            try {
                listener(event)
            } catch (_: Exception) {
            }
        }
    }

    /** Events emitted after [afterSeq], oldest first (F7 resume). */
    fun eventsSince(afterSeq: Long): List<Event> =
        synchronized(ring) { ring.filter { it.seq > afterSeq } }

    /** U2: emit a canonical-kind fact (screen_change, app_crash…)
     *  whose state label is the kind itself. */
    fun emitKind(kind: String, detail: Map<String, Any?> = emptyMap()) {
        if (kind !in ALL_KINDS) return
        emit(kind, detail)
    }

    /** The JSON-RPC notification form an SSE client receives. */
    fun toJson(event: Event): String {
        val params = JSONObject()
            .put("state", event.state)
            .put("kind", event.kind)
            .put("seq", event.seq)
            .put("atMs", System.currentTimeMillis())
        event.detail.forEach { (k, v) -> if (v != null) params.put(k, v) }
        SessionManager.active?.let { session ->
            params.put("agent", session.agentName)
            params.put("actions", session.actions)
        }
        return JSONObject()
            .put("jsonrpc", "2.0")
            .put("method", "notifications/session_state")
            .put("params", params)
            .toString()
    }
}

/**
 * U2 — per-pairing event subscriptions (Android mirror of the
 * Windows EventSubscriptionStore). Keyed by the pairing's bearer
 * token (never emitted anywhere). A subscription is a KIND filter
 * enforced at stream time in McpHttpServer: an unsubscribed pairing
 * receives nothing, and subscribing never widens a pairing's
 * rights — the subscribe tools are observe-scoped and the stream
 * still requires the pairing's own token. Subscribing is not an
 * audit-evasion channel: subscribe/unsubscribe calls pass the
 * normal tools/call audit, and delivery never suppresses audit.
 */
object EventSubscriptions {

    /** W5 (bd-supp-eventsub F6): a subscription is a standing watch,
     *  so it EXPIRES — 24 h after the last subscribe call for the
     *  pairing; re-subscribing renews. Expired entries are dropped
     *  lazily on the delivery path and by [listAll]. */
    const val SUBSCRIPTION_TTL_MS: Long = 24L * 60 * 60 * 1000

    /** Test seam for the TTL; production uses the wall clock. */
    @Volatile
    var clockMs: () -> Long = { System.currentTimeMillis() }

    private val byPairing = java.util.concurrent.ConcurrentHashMap<String, MutableSet<String>>()
    private val expiresAtMs = java.util.concurrent.ConcurrentHashMap<String, Long>()

    /** W5 (F5): revoked pairing keys. Pairing tokens are 32 random
     *  bytes, minted once and never reused, so a tombstone can never
     *  block a legitimate future pairing — it only stops an in-flight
     *  subscribe that raced a revoke from resurrecting the entry. */
    private val tombstones = java.util.Collections.synchronizedSet(mutableSetOf<String>())

    /** F11: untrusted kind strings are echoed back truncated and
     *  stripped to alphanumerics/underscore — never in full. */
    private fun echoKind(kind: String): String =
        kind.filter { it.isLetterOrDigit() || it == '_' }.take(32)

    private fun liveSet(pairingKey: String): MutableSet<String>? {
        val set = byPairing[pairingKey] ?: return null
        val exp = expiresAtMs[pairingKey]
        if (exp != null && clockMs() > exp) {
            byPairing.remove(pairingKey)
            expiresAtMs.remove(pairingKey)
            return null
        }
        return set
    }

    /** Atomic subscribe: any unknown kind refuses the whole call. */
    fun subscribe(pairingKey: String, kinds: List<String>): String? {
        if (kinds.isEmpty()) return "kinds_required: name at least one event kind"
        if (pairingKey in tombstones) return "pairing_revoked: this pairing no longer exists"
        val unknown = kinds.firstOrNull { it !in SessionEvents.ALL_KINDS }
        if (unknown != null) return "unknown_event_kind: '${echoKind(unknown)}' is not an event kind; valid kinds: " +
            SessionEvents.ALL_KINDS.sorted().joinToString(", ")
        val set = byPairing.computeIfAbsent(pairingKey) {
            java.util.Collections.synchronizedSet(mutableSetOf())
        }
        // F5: re-check the tombstone under the set lock — a revoke
        // that landed while this call was in flight wins.
        synchronized(set) {
            if (pairingKey in tombstones) return "pairing_revoked: this pairing no longer exists"
            set.addAll(kinds)
        }
        expiresAtMs[pairingKey] = clockMs() + SUBSCRIPTION_TTL_MS
        return null
    }

    /** Unsubscribe; null/empty kinds drops the whole subscription. */
    fun unsubscribe(pairingKey: String, kinds: List<String>?): String? {
        if (!kinds.isNullOrEmpty()) {
            val unknown = kinds.firstOrNull { it !in SessionEvents.ALL_KINDS }
            if (unknown != null) return "unknown_event_kind: '${echoKind(unknown)}' is not an event kind"
            byPairing[pairingKey]?.let { set -> synchronized(set) { set.removeAll(kinds.toSet()) } }
        } else {
            byPairing.remove(pairingKey)
            expiresAtMs.remove(pairingKey)
        }
        return null
    }

    fun filterFor(pairingKey: String): Set<String> =
        liveSet(pairingKey)?.let { set -> synchronized(set) { set.toSet() } } ?: emptySet()

    /** F8: the hot-path membership check — no set copy. */
    fun isSubscribed(pairingKey: String, kind: String): Boolean {
        val set = liveSet(pairingKey) ?: return false
        return synchronized(set) { kind in set }
    }

    fun clearPairing(pairingKey: String) {
        byPairing.remove(pairingKey)
        expiresAtMs.remove(pairingKey)
    }

    /** W5 (F4/F10): revocation cleanup — drop the subscription AND
     *  tombstone the key so nothing resurrects it. Called by
     *  PairingStore.revoke, the one choke point every revoke flows
     *  through. */
    fun revokePairing(pairingKey: String) {
        clearPairing(pairingKey)
        tombstones.add(pairingKey)
    }

    fun isTombstoned(pairingKey: String): Boolean = pairingKey in tombstones

    /** F6: every live watch, for the consent/presence surface —
     *  which pairings are subscribed to which kinds, nothing hidden. */
    fun listAll(): Map<String, Set<String>> =
        byPairing.keys.toList().mapNotNull { key ->
            val kinds = filterFor(key)
            if (kinds.isEmpty()) null else key to kinds
        }.toMap()

    /** The delivery rule, pure: the event's kind must be in the
     *  pairing's own filter. */
    fun shouldDeliver(pairingKey: String, event: SessionEvents.Event): Boolean =
        isSubscribed(pairingKey, event.kind)

    /** W5 (F1): the scoped delivery rule the SSE layer uses — the
     *  pairing must ALSO hold Observe RIGHT NOW, checked live per
     *  event through [holdsObserveNow]. There is no fail-open form:
     *  a scope source that answers false (or a pairing that no
     *  longer resolves) stops delivery, whatever the filter says. */
    fun shouldDeliverScoped(
        pairingKey: String,
        event: SessionEvents.Event,
        holdsObserveNow: () -> Boolean
    ): Boolean = holdsObserveNow() && shouldDeliver(pairingKey, event)
}

/**
 * U2 — the events_subscribe / events_unsubscribe tools. The calling
 * pairing is read from McpCore's per-request pairing thread-local —
 * a tool can only ever touch its OWN pairing's filter.
 */
class EventToolHost : McpCore.ToolHost {

    private var core: McpCore? = null

    override fun attach(core: McpCore) {
        this.core = core
    }

    override fun tools(): List<McpCore.ToolDef> = listOf(
        McpCore.ToolDef(
            name = "events_subscribe",
            // W5 (bd-supp-eventsub F9): the kind list is BUILT from
            // the registry — the old hand-written list drifted and
            // hid clipboard_read. The schema enum comes from the
            // same source, so the two can never drift again.
            description = "Subscribe this pairing to agent event kinds (" +
                SessionEvents.ALL_KINDS.sorted().joinToString(", ") +
                "), delivered on the GET /mcp event stream. " +
                "A subscription only ever covers this pairing's own events, " +
                "expires after 24 hours, and ends if the pairing is revoked " +
                "or loses the observe scope.",
            scope = "observe",
            inputSchema = JSONObject()
                .put("type", "object")
                .put(
                    "properties", JSONObject().put(
                        "kinds",
                        JSONObject().put("type", "array").put(
                            "items",
                            JSONObject().put("type", "string")
                                .put("enum", JSONArray(SessionEvents.ALL_KINDS.sorted()))
                        )
                    )
                )
                .put("required", JSONArray().put("kinds")),
            run = { args -> subscribe(args) }
        ),
        McpCore.ToolDef(
            name = "events_unsubscribe",
            description = "Unsubscribe this pairing from event kinds; omit kinds to drop the whole subscription.",
            scope = "observe",
            inputSchema = JSONObject()
                .put("type", "object")
                .put(
                    "properties", JSONObject().put(
                        "kinds",
                        JSONObject().put("type", "array").put("items", JSONObject().put("type", "string"))
                    )
                ),
            run = { args -> unsubscribe(args) }
        )
    )

    private fun pairingKey(): String =
        core?.currentPairingKey?.get() ?: throw IllegalStateException("no pairing in scope for this call")

    /** F11: the kinds array is capped BEFORE materialising it —
     *  at most twice the registry size (duplicates tolerated). */
    private val kindsCap = SessionEvents.ALL_KINDS.size * 2

    private fun readKinds(args: JSONObject, required: Boolean): List<String>? {
        val arr = args.optJSONArray("kinds") ?: return if (required) null else emptyList()
        if (arr.length() > kindsCap) return null
        val out = mutableListOf<String>()
        for (i in 0 until arr.length()) out.add(arr.optString(i, ""))
        return out
    }

    private fun subscribe(args: JSONObject): String {
        val raw = args.optJSONArray("kinds")
        if (raw != null && raw.length() > kindsCap)
            return "too_many_kinds: at most $kindsCap kinds per call"
        val kinds = readKinds(args, required = true)
            ?: return "events_subscribe requires {kinds:[\"session\", ...]}"
        val key = pairingKey()
        EventSubscriptions.subscribe(key, kinds)?.let { return it }
        return JSONObject()
            .put("subscribed", JSONArray(EventSubscriptions.filterFor(key).sorted()))
            .put("stream", "GET /mcp with Accept: text/event-stream and this pairing's bearer token")
            .toString()
    }

    private fun unsubscribe(args: JSONObject): String {
        val raw = args.optJSONArray("kinds")
        if (raw != null && raw.length() > kindsCap)
            return "too_many_kinds: at most $kindsCap kinds per call"
        val kinds = readKinds(args, required = false)
        val key = pairingKey()
        EventSubscriptions.unsubscribe(key, kinds)?.let { return it }
        return JSONObject()
            .put("subscribed", JSONArray(EventSubscriptions.filterFor(key).sorted()))
            .toString()
    }
}
