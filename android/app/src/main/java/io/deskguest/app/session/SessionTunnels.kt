package io.deskguest.app.session

import io.deskguest.app.enterprise.PolicyFeatures
import io.deskguest.app.roster.RosterStore
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

/**
 * A TCP tunnel carried by a human session (Block G, G-08) — the
 * Android mirror of the Windows SessionTunnelService. A tunnel
 * here BELONGS to a session: it opens only inside a live
 * session, under the session's own authority (the floor holder
 * who is driving, or a host-side actor under the session store's
 * own rule), and it dies with the session — the per-act re-read
 * closes it on the spot if the session has ended or blocked, and
 * the wiring layer sweeps on session change. The record governs;
 * the platform byte mover is the mechanism it governs and may
 * only run tunnels this store has opened.
 */
data class SessionTunnel(
    val id: String,
    val sessionId: String,
    val targetHost: String,
    val targetPort: Int,
    val listenPort: Int,
    val state: String = STATE_OPEN,
    val openedByUserId: String,
    val openedUtcMs: Long,
    val closedUtcMs: Long? = null
) {
    companion object {
        const val STATE_OPEN = "open"
        const val STATE_CLOSED = "closed"
        val STATES = setOf(STATE_OPEN, STATE_CLOSED)
    }
}

data class SessionTunnelEvent(
    val atMs: Long,
    val kind: String,
    val tunnelId: String,
    val actorUserId: String?,
    val detail: String
)

class SessionTunnelStore(
    private val sessions: SessionStore,
    private val roster: RosterStore,
    private val featureGate: ((String, String) -> Boolean)? = null,
    /** Block H (design 3) — destination allowlist of "host:port"
     *  entries (host compared case-insensitively). Null = not
     *  configured: the pivot blocklist remains the control and
     *  the posture is unchanged. Non-null (EVEN EMPTY) = enforced:
     *  [open] refuses, and [importJson] restores-as-closed, any
     *  target not in the set. NOT the last parameter: the clock
     *  stays last so existing trailing-lambda call sites keep
     *  binding to it. */
    private val allowedTargets: Set<String>? = null,
    /** Change hook for wiring write-through persistence (AF10).
     *  NOT the last parameter: the clock stays last so existing
     *  trailing-lambda call sites keep binding to it. */
    private val onChanged: (() -> Unit)? = null,
    private val nowMillis: () -> Long = { System.currentTimeMillis() }
) {
    /** Allowlist entries normalized once: host lowercased, so
     *  membership is an exact "host:port" string test. */
    private val allowedTargetKeys: Set<String>? =
        allowedTargets?.map { normalizeTargetKey(it) }?.toSet()

    private fun targetAllowed(host: String, port: Int): Boolean {
        val keys = allowedTargetKeys ?: return true
        // D38 Block H review F9: match on the CANONICAL host
        // (trailing dot stripped, IP literals in canonical form),
        // and — when both the target and an allowlist entry
        // resolve — on the RESOLVED ADDRESSES, so a DNS name is
        // judged by where it points, not by its spelling. When
        // resolution is unavailable (offline, unresolvable name),
        // the canonical-name match stands.
        if ("${canonicalHost(host)}:$port" in keys) return true
        val targetAddrs = resolveAll(host)
        if (targetAddrs.isEmpty()) return false
        return keys.any { k ->
            val idx = k.lastIndexOf(':')
            idx > 0 && k.substring(idx + 1).toIntOrNull() == port &&
                resolveAll(k.substring(0, idx)).any { it in targetAddrs }
        }
    }
    private val tunnels = LinkedHashMap<String, SessionTunnel>()
    private val _events = ArrayList<SessionTunnelEvent>()
    val events: List<SessionTunnelEvent> get() = synchronized(this) { _events.toList() }

    /** SCOPE-AWARE gate (scopeId, featureKey) — D38-G review F2. */
    private fun featureAllowed(session: SessionStore.Session): Boolean =
        featureGate?.invoke(session.scopeId, PolicyFeatures.TCP_TUNNEL) ?: true

    @Synchronized
    private fun record(kind: String, tunnel: SessionTunnel, actor: String?, detail: String) {
        _events.add(SessionTunnelEvent(nowMillis(), kind, tunnel.id, actor, detail))
        onChanged?.invoke()
    }

    /** Who may open/close a tunnel on a session: the floor
     *  holder (a live, non-suspended participant — a stale holder
     *  row confers nothing) or a host actor under the session
     *  store's own rule. */
    private fun canDrive(session: SessionStore.Session, actorUserId: String?): Boolean {
        if (actorUserId.isNullOrBlank()) return false
        // An AI holds no tunnel authority (D9, D38-G review F9):
        // driving a session is one leash; opening a network path
        // off the endpoint is another, and the AI's leash does
        // not include it — not even as floor holder.
        val actor = roster.user(actorUserId)
        if (actor != null && actor.kind == RosterStore.USER_AI) return false
        if (sessions.isHostActor(session.id, actorUserId)) return true
        val holder = sessions.participants(session.id)
            .firstOrNull { it.floor == SessionStore.FLOOR_HOLDS } ?: return false
        if (holder.userId != actorUserId) return false
        val user = roster.user(actorUserId) ?: return false
        if (user.scopeId != session.scopeId || user.suspended) return false
        // D38 Block H review F2: the floor alone no longer
        // suffices — the holder must ALSO currently hold the live
        // `use` right on the host device's group, re-read at drive
        // time (the same per-act re-check SessionStore applies to
        // blank/input-block/watermark/calls). A grant revoked
        // mid-session stops tunnel opens — and imported 'open'
        // tunnels, which pass through this same check — at once.
        return sessions.holdsUseRightOnHost(session.id, actorUserId)
    }

    /** The session-liveness re-read, run before every act: a
     *  tunnel whose session is no longer active/paused is closed
     *  on the spot (recorded in both event lists) and the act
     *  refuses. Returns true when the sweep closed the tunnel. */
    @Synchronized
    private fun enforceSessionLive(tunnel: SessionTunnel): Boolean {
        if (tunnel.state == SessionTunnel.STATE_CLOSED) return false
        val session = sessions.session(tunnel.sessionId)
        if (session != null &&
            (session.state == SessionStore.STATE_ACTIVE || session.state == SessionStore.STATE_PAUSED)
        ) return false
        val closed = tunnel.copy(state = SessionTunnel.STATE_CLOSED, closedUtcMs = nowMillis())
        tunnels[tunnel.id] = closed
        record("tunnel_closed_session_gone", closed, null,
            "Tunnel closed: its session is no longer live.")
        if (session != null) {
            sessions.appendEvent(session.id, "tunnel_closed", "",
                "Session tunnel closed: session no longer live.")
        }
        return true
    }

    /**
     * Open a tunnel inside a live session. Null on refusal:
     * policy-disabled (key `tcp_tunnel`), an unknown or non-live
     * session, an actor who neither holds the floor nor is a host
     * actor, an invalid target host, a target port outside
     * 1–65535, a listen port that is neither 0 (the platform
     * assigns) nor 1024–65535, a listen port already open on this
     * session, or an identical open tunnel.
     */
    @Synchronized
    fun open(sessionId: String, actorUserId: String, targetHost: String,
             targetPort: Int, listenPort: Int): SessionTunnel? {
        if (!isValidTargetHost(targetHost)) return null
        if (isPivotTarget(targetHost)) return null
        if (!targetAllowed(targetHost, targetPort)) return null // design 3: allowlist, when configured
        if (targetPort !in 1..65535) return null
        if (listenPort != 0 && listenPort !in 1024..65535) return null
        val session0 = sessions.session(sessionId) ?: return null
        if (!featureAllowed(session0)) return null
        val session = session0
        if (session.state != SessionStore.STATE_ACTIVE && session.state != SessionStore.STATE_PAUSED)
            return null
        if (!canDrive(session, actorUserId)) return null
        val host = targetHost.trim()
        for (t in tunnels.values) {
            if (t.sessionId != session.id || t.state != SessionTunnel.STATE_OPEN) continue
            if (listenPort != 0 && t.listenPort == listenPort) return null
            if (t.listenPort == listenPort && t.targetHost.equals(host, ignoreCase = true) &&
                t.targetPort == targetPort) return null
        }
        val tunnel = SessionTunnel(
            UUID.randomUUID().toString().replace("-", ""), session.id, host,
            targetPort, listenPort, SessionTunnel.STATE_OPEN, actorUserId, nowMillis())
        tunnels[tunnel.id] = tunnel
        record("tunnel_opened", tunnel, actorUserId,
            "Tunnel opened: :$listenPort → $host:$targetPort in session ${session.id}.")
        sessions.appendEvent(session.id, "tunnel_opened", actorUserId,
            "TCP tunnel opened to $host:$targetPort (listen :$listenPort).")
        return tunnel
    }

    /**
     * Close a tunnel. The opener, the current floor holder, or a
     * host actor may close; an already-closed tunnel refuses. The
     * session-liveness re-read runs first.
     */
    @Synchronized
    fun close(tunnelId: String, actorUserId: String): Boolean {
        val tunnel = tunnels[tunnelId] ?: return false
        if (enforceSessionLive(tunnel)) return false
        val current = tunnels[tunnel.id] ?: return false
        if (current.state == SessionTunnel.STATE_CLOSED) return false
        val session = sessions.session(current.sessionId) ?: return false
        if (actorUserId != current.openedByUserId && !canDrive(session, actorUserId)) return false
        val closed = current.copy(state = SessionTunnel.STATE_CLOSED, closedUtcMs = nowMillis())
        tunnels[current.id] = closed
        record("tunnel_closed", closed, actorUserId, "Tunnel closed.")
        sessions.appendEvent(session.id, "tunnel_closed", actorUserId, "Session tunnel closed.")
        return true
    }

    /** Close every open tunnel on a session — the wiring layer's
     *  sweep when a session ends or blocks. Returns the number
     *  closed. */
    @Synchronized
    fun closeForSession(sessionId: String, actorUserId: String? = null): Int {
        var count = 0
        for (tunnel in tunnels.values.toList()) {
            if (tunnel.sessionId != sessionId || tunnel.state != SessionTunnel.STATE_OPEN) continue
            val closed = tunnel.copy(state = SessionTunnel.STATE_CLOSED, closedUtcMs = nowMillis())
            tunnels[tunnel.id] = closed
            record("tunnel_closed_session_end", closed, actorUserId,
                "Tunnel closed by session-end sweep.")
            count++
        }
        return count
    }

    /**
     * Block H (design 5) — policy-change teardown sweep: when
     * policy disables `tcp_tunnel`, close every OPEN tunnel whose
     * session belongs to [scopeId]. Recorded per tunnel, actor
     * `policy`, in both event lists. Returns the number closed.
     */
    @Synchronized
    fun sweepPolicyTeardown(scopeId: String, featureDisabled: (String) -> Boolean): Int {
        if (!featureDisabled(PolicyFeatures.TCP_TUNNEL)) return 0
        var count = 0
        for (tunnel in tunnels.values.toList()) {
            if (tunnel.state != SessionTunnel.STATE_OPEN) continue
            val session = sessions.session(tunnel.sessionId) ?: continue
            if (session.scopeId != scopeId) continue
            val closed = tunnel.copy(state = SessionTunnel.STATE_CLOSED, closedUtcMs = nowMillis())
            tunnels[tunnel.id] = closed
            record("tunnel_closed_policy_teardown", closed, "policy",
                "Tunnel closed by policy teardown (tcp_tunnel disabled).")
            sessions.appendEvent(session.id, "tunnel_closed", "policy",
                "Session tunnel closed by policy teardown (tcp_tunnel disabled).")
            count++
        }
        return count
    }

    /** Reads run the liveness sweep first (D38-G review F5):
     *  a tunnel over a dead session never REPORTS open, even if
     *  nobody has called close on it. */
    @Synchronized
    fun tunnel(tunnelId: String?): SessionTunnel? {
        if (tunnelId.isNullOrBlank()) return null
        val t = tunnels[tunnelId] ?: return null
        if (t.state == SessionTunnel.STATE_OPEN) enforceSessionLive(t)
        return tunnels[tunnelId]
    }

    @Synchronized
    fun tunnels(sessionId: String): List<SessionTunnel> {
        for (t in tunnels.values.toList())
            if (t.sessionId == sessionId && t.state == SessionTunnel.STATE_OPEN)
                enforceSessionLive(t)
        return tunnels.values.filter { it.sessionId == sessionId }
    }

    @Synchronized
    fun openTunnels(): List<SessionTunnel> {
        for (t in tunnels.values.toList())
            if (t.state == SessionTunnel.STATE_OPEN) enforceSessionLive(t)
        return tunnels.values.filter { it.state == SessionTunnel.STATE_OPEN }
    }

    // ---- persistence ----

    /** The event history exports WITH the tunnels (D38-G
     *  review F1: the acts are part of the record). The root is
     *  an object {tunnels, events}; import still accepts the
     *  pre-F1 bare array. */
    @Synchronized
    fun exportJson(): String {
        val arr = JSONArray()
        for (t in tunnels.values) arr.put(JSONObject()
            .put("id", t.id).put("sessionId", t.sessionId).put("targetHost", t.targetHost)
            .put("targetPort", t.targetPort).put("listenPort", t.listenPort)
            .put("state", t.state).put("openedByUserId", t.openedByUserId)
            .put("openedUtcMs", t.openedUtcMs)
            .put("closedUtcMs", t.closedUtcMs ?: JSONObject.NULL))
        val evArr = JSONArray()
        synchronized(this) {
            for (e in _events) evArr.put(JSONObject()
                .put("atMs", e.atMs).put("kind", e.kind).put("tunnelId", e.tunnelId)
                .put("actorUserId", e.actorUserId ?: JSONObject.NULL).put("detail", e.detail))
        }
        return JSONObject().put("tunnels", arr).put("events", evArr).toString()
    }

    /** Restore, re-validated: malformed entries drop; an "open"
     *  tunnel restores open ONLY if its session exists and is
     *  live in the session store right now — anything else
     *  restores closed (a restart leaves nothing live behind a
     *  record, the F11 rule applied to tunnels). */
    @Synchronized
    fun importJson(json: String): Int {
        val arr: JSONArray
        val evArr: JSONArray?
        try {
            val trimmed = json.trim()
            if (trimmed.startsWith("{")) {
                val root = JSONObject(trimmed)
                arr = root.optJSONArray("tunnels") ?: JSONArray()
                evArr = root.optJSONArray("events")
            } else {
                arr = JSONArray(trimmed)
                evArr = null
            }
        } catch (ex: Exception) { return 0 }
        if (evArr != null) {
            for (i in 0 until evArr.length()) {
                val dto = evArr.optJSONObject(i) ?: continue
                val kind = dto.optString("kind")
                val tunnelId = dto.optString("tunnelId")
                if (kind.isBlank() || tunnelId.isBlank()) continue
                _events.add(SessionTunnelEvent(dto.optLong("atMs"), kind, tunnelId,
                    if (dto.isNull("actorUserId")) null else dto.optString("actorUserId"),
                    dto.optString("detail")))
            }
        }
        var restored = 0
        for (i in 0 until arr.length()) {
            val dto = arr.optJSONObject(i) ?: continue
            val id = dto.optString("id")
            val sessionId = dto.optString("sessionId")
            val openedBy = dto.optString("openedByUserId")
            if (id.isBlank() || sessionId.isBlank() || openedBy.isBlank()) continue
            val host = dto.optString("targetHost")
            if (!isValidTargetHost(host)) continue
            if (isPivotTarget(host)) continue // F9: import enforces the pivot rule too
            val targetPort = dto.optInt("targetPort", -1)
            if (targetPort !in 1..65535) continue
            val listenPort = dto.optInt("listenPort", -1)
            if (listenPort != 0 && listenPort !in 1024..65535) continue
            var state = dto.optString("state").trim().lowercase()
            if (state !in SessionTunnel.STATES) continue
            if (tunnels.containsKey(id)) continue
            var closedUtc = if (dto.isNull("closedUtcMs")) null else dto.optLong("closedUtcMs")
            if (state == SessionTunnel.STATE_OPEN) {
                // Android packet F4: an imported OPEN tunnel must
                // pass the same authority the live open() demands
                // — a live session, an opener who could drive it
                // (host actor or live floor holder, never an AI),
                // the policy gate, and listen-port uniqueness
                // among open tunnels. Anything else restores
                // CLOSED: a hand-edited file plants nothing.
                val session = sessions.session(sessionId)
                val portClash = listenPort != 0 && tunnels.values.any {
                    it.sessionId == sessionId && it.state == SessionTunnel.STATE_OPEN &&
                        it.listenPort == listenPort
                }
                if (session == null ||
                    (session.state != SessionStore.STATE_ACTIVE && session.state != SessionStore.STATE_PAUSED) ||
                    !featureAllowed(session) || !canDrive(session, openedBy) || portClash ||
                    !targetAllowed(host, targetPort) // design 3: off-allowlist restores CLOSED
                ) {
                    state = SessionTunnel.STATE_CLOSED
                    if (closedUtc == null) closedUtc = nowMillis()
                }
            }
            if (state == SessionTunnel.STATE_CLOSED && closedUtc == null)
                closedUtc = dto.optLong("openedUtcMs")
            tunnels[id] = SessionTunnel(id, sessionId, host.trim(), targetPort, listenPort,
                state, openedBy, dto.optLong("openedUtcMs"), closedUtc)
            restored++
        }
        return restored
    }

    companion object {
        /** Normalize an allowlist entry to "host:port" with the
         *  host lowercased (design 3: host comparison is
         *  case-insensitive; the port is compared exactly). An
         *  entry with no port never matches a real target. */
        fun normalizeTargetKey(entry: String): String {
            val t = entry.trim()
            val idx = t.lastIndexOf(':')
            if (idx <= 0) return canonicalHost(t)
            return canonicalHost(t.substring(0, idx)) + ":" + t.substring(idx + 1).trim()
        }

        /** F9: canonical host form — trimmed, lowercased,
         *  trailing root dot stripped, IP literals (any spelling
         *  the parser accepts, incl. hex/octal IPv4 parts and
         *  IPv6-mapped forms) rewritten to their canonical
         *  address text. Non-literals keep their canonical name. */
        fun canonicalHost(host: String): String {
            var h = host.trim().lowercase()
            if (h.endsWith(".")) h = h.dropLast(1)
            parseIpLiteral(h)?.let { return it }
            return h
        }

        /** Resolve a host to its address set (canonical text);
         *  empty when it does not resolve. IP literals resolve
         *  to themselves without touching DNS. */
        fun resolveAll(host: String): Set<String> {
            parseIpLiteral(host.trim().lowercase().removeSuffix("."))?.let { return setOf(it) }
            return try {
                java.net.InetAddress.getAllByName(host.trim()).map { it.hostAddress }.toSet()
            } catch (ex: Exception) { emptySet() }
        }

        /** Parse an IP literal in any accepted spelling to its
         *  canonical text, or null when [h] is not an IP literal.
         *  IPv4 parts may be decimal, 0x-hex, or 0-octal, in
         *  dotted-quad or inet_aton short forms (127.1). IPv6
         *  (incl. ::ffff:a.b.c.d mapped forms) goes through
         *  InetAddress and comes back canonical. */
        fun parseIpLiteral(h: String): String? {
            if (h.contains(':')) {
                return try {
                    val a = java.net.InetAddress.getByName(h)
                    // getByName on a name with colons only succeeds
                    // for literals; require a digit/hex shape.
                    if (h.all { it.isDigit() || it in 'a'..'f' || it == ':' || it == '.' }) a.hostAddress else null
                } catch (ex: Exception) { null }
            }
            if (h.contains('.') || h.startsWith("0x")) {
                val parts = h.split('.')
                if (parts.size > 4) return null
                val nums = parts.map { p ->
                    when {
                        p.startsWith("0x") && p.length > 2 -> p.substring(2).toLongOrNull(16)
                        p.length > 1 && p.startsWith("0") && p.all { it in '0'..'7' } -> p.toLongOrNull(8)
                        p.isNotEmpty() && p.all { it.isDigit() } -> p.toLongOrNull(10)
                        else -> null
                    } ?: return null
                }
                // inet_aton shape rules: leading parts are single
                // bytes; the last part fills the remaining bytes.
                val bytes = ByteArray(4)
                for (i in 0 until nums.size - 1) {
                    if (nums[i] !in 0..255) return null
                    bytes[i] = nums[i].toByte()
                }
                val lastBits = (4 - (nums.size - 1)) * 8
                val last = nums.last()
                if (last < 0 || last >= (1L shl lastBits)) return null
                for (i in 0 until 4 - (nums.size - 1)) {
                    bytes[nums.size - 1 + i] = (last shr (8 * (3 - (nums.size - 1) - i))).toByte()
                }
                return bytes.joinToString(".") { (it.toInt() and 0xFF).toString() }
            }
            return null
        }

        /** A target is a DESTINATION: a non-empty host name or IP
         *  literal with no whitespace/control characters, never a
         *  wildcard bind address (0.0.0.0 / :: are listen
         *  addresses, not destinations — as targets they are
         *  configuration errors, refused rather than
         *  reinterpreted). */
        fun isValidTargetHost(host: String?): Boolean {
            if (host.isNullOrBlank()) return false
            val h = host.trim()
            if (h.length > 255) return false
            if (h.any { it.isWhitespace() || it.isISOControl() }) return false
            if (h == "0.0.0.0" || h == "::" || h == "*") return false
            return true
        }

        /** The endpoint's own loopback / link-local space is
         *  never a tunnel destination (D38-G review F9): a
         *  tunnel to it turns the endpoint into a pivot into
         *  its own services. */
        fun isPivotTarget(host: String?): Boolean {
            var h = (host ?: "").trim().lowercase()
            if (h.endsWith(".")) h = h.dropLast(1)
            if (h == "localhost") return true
            // F9: judge IP spellings by the ADDRESS they denote,
            // not the string — 0x7f.0.0.1, 127.1 and
            // ::ffff:127.0.0.1 are loopback too.
            val canon = parseIpLiteral(h) ?: return h.startsWith("fe80:")
            val b = canon.split('.').mapNotNull { it.toIntOrNull() }
            if (b.size == 4) {
                return b[0] == 127 || (b[0] == 169 && b[1] == 254)
            }
            // Canonical IPv6 text: loopback ::1 and link-local fe80::/10.
            return canon == "::1" || canon.startsWith("fe8") || canon.startsWith("fe9") ||
                canon.startsWith("fea") || canon.startsWith("feb")
        }
    }
}
