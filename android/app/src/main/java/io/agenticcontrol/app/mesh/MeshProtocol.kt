package io.agenticcontrol.app.mesh

import org.json.JSONObject

/**
 * The mesh companion protocol (0.4.0, stage 4) — the client side of
 * PLAN-WINDOWS W3. The Windows companion serves plain HTTP on the
 * tailnet:
 *
 *   GET  /mesh/state     -> the heartbeat JSON (see [CompanionState])
 *   GET  /mesh/preview   -> a JPEG of the desktop, when the state
 *                           says a preview is available
 *   POST /mesh/input     -> one input event JSON (see the builders)
 *   POST /mesh/handoff   -> ask the companion to hand control to the
 *                           agent ("Hand Off to Agent")
 *   POST /mesh/disconnect-> end the phone's spectate/drive link
 *   POST /mesh/heartbeat -> the phone's own heartbeat while the
 *                           device page is open
 *
 * The companion EXISTS (the Windows MeshService serves these
 * routes; the stale "does not exist yet" wording was corrected
 * 2026-11-22, bd-and-remote F2). Every state the client shows is
 * derived from real answers or their absence — "offline" is what
 * an unanswered poll means, never a guess.
 *
 * AUTHENTICATION STATE (bd-and-remote F2, named honestly): this
 * protocol is plain HTTP and carries NO proof of identity —
 * userId is a body field the companion's floor check trusts.
 * The Android-side mitigations in this build are target pinning
 * (the base URL must name a tailnet, loopback, or LAN address —
 * see MeshStore) and nothing more. Running the mesh protocol
 * over the authenticated v2 channel, or signing requests with
 * the device identity under a companion-issued nonce, requires
 * the companion to verify — that half is the Windows lane's
 * bd-win-core-3 F1 remainder, and until it lands this protocol
 * must only ever be pointed at a companion on the user's own
 * tailnet, which is the trust boundary it was designed for.
 */
/**
 * W6 Task 0 — mesh Authorization. The Windows companion's
 * MeshIdentityResolver gates every stream route on the Authorization
 * bearer: the pairing token resolves to the agent identity. The
 * Android mesh client therefore carries the pairing's bearer on
 * EVERY mesh/companion request. Rules, pinned by W6DesignTest:
 *  - the header value is exactly "Bearer <token>", token verbatim;
 *  - a null, blank, or whitespace-only token yields NO header —
 *    a token is never invented, trimmed into existence, or defaulted;
 *  - a token containing whitespace or control characters is refused
 *    outright (header-injection guard) and yields no header.
 * Pure + JVM-testable; MeshClient applies [headerValue] on all of
 * its request paths (plain request, full request, preview, frame).
 */
object MeshAuth {
    const val HEADER_NAME = "Authorization"

    fun headerValue(token: String?): String? {
        val t = token?.takeIf { it.isNotBlank() } ?: return null
        if (t.any { it.isWhitespace() || it.code < 0x20 || it.code == 0x7F }) return null
        // Surrounding whitespace means the stored value is malformed;
        // refuse rather than silently rewriting a credential.
        if (t != t.trim()) return null
        return "Bearer $t"
    }

    /** True when [token] would produce a header. */
    fun hasToken(token: String?): Boolean = headerValue(token) != null
}

object MeshProtocol {

    const val PATH_STATE = "/mesh/state"
    const val PATH_PREVIEW = "/mesh/preview"
    const val PATH_INPUT = "/mesh/input"
    const val PATH_HANDOFF = "/mesh/handoff"
    const val PATH_DISCONNECT = "/mesh/disconnect"
    const val PATH_HEARTBEAT = "/mesh/heartbeat"

    // Mesh contract v2 (Block D) — the real session stream.
    const val PATH_STREAM_START = "/mesh/stream/start"
    const val PATH_STREAM_STOP = "/mesh/stream/stop"
    const val PATH_STREAM_INFO = "/mesh/stream/info"
    const val PATH_STREAM_FRAME = "/mesh/stream/frame"
    const val PATH_STREAM_INPUT = "/mesh/stream/input"

    enum class State { IDLE, AI_DRIVING, HUMAN_MANUAL, HUMAN_SESSION, PAUSED_BY_USER, UNKNOWN }

    /**
     * One heartbeat from the companion. Unknown or missing fields
     * degrade to the defaults — a heartbeat we cannot read is an
     * UNKNOWN state, not an invented one.
     */
    data class CompanionState(
        val state: State = State.UNKNOWN,
        val deviceName: String = "",
        val agentName: String = "",
        val sessionSeconds: Long = 0,
        val actions: Int = 0,
        val intent: String = "",
        val previewAvailable: Boolean = false
    ) {
        companion object {
            fun parse(json: JSONObject): CompanionState {
                val raw = json.optString("state").uppercase()
                return CompanionState(
                    state = when (raw) {
                        "IDLE" -> State.IDLE
                        "AI_DRIVING" -> State.AI_DRIVING
                        "HUMAN_MANUAL" -> State.HUMAN_MANUAL
                        "HUMAN_SESSION" -> State.HUMAN_SESSION
                        "PAUSED_BY_USER" -> State.PAUSED_BY_USER
                        else -> State.UNKNOWN
                    },
                    deviceName = json.optString("device"),
                    agentName = json.optString("agent"),
                    sessionSeconds = json.optLong("sessionSeconds", 0),
                    actions = json.optInt("actions", 0),
                    intent = json.optString("intent"),
                    previewAvailable = json.optBoolean("preview", false)
                )
            }
        }
    }

    /** Relative pointer movement, normalized so 1.0 is a full
     *  trackpad-width of travel. */
    fun inputPointer(dx: Double, dy: Double): JSONObject = JSONObject()
        .put("type", "pointer")
        .put("dx", dx)
        .put("dy", dy)

    /** A mouse button event: action is down, up, or click. */
    fun inputButton(button: String, action: String): JSONObject = JSONObject()
        .put("type", "button")
        .put("button", button)
        .put("action", action)

    /** A named key or chord: win, alt_tab, enter, escape, ... */
    fun inputKey(key: String): JSONObject = JSONObject()
        .put("type", "key")
        .put("key", key)

    /** Typed text, sent as one event. */
    fun inputText(text: String): JSONObject = JSONObject()
        .put("type", "text")
        .put("text", text)

    /** The phone's heartbeat while its device page is open. */
    fun heartbeat(phoneName: String, watching: Boolean): JSONObject = JSONObject()
        .put("from", phoneName)
        .put("watching", watching)
        .put("at", System.currentTimeMillis())

    // ---- Mesh contract v2: the session stream (Block D) ----

    fun streamStart(sessionId: String, userId: String, monitor: Int): JSONObject = JSONObject()
        .put("sessionId", sessionId)
        .put("userId", userId)
        .put("monitor", monitor)

    fun streamStop(sessionId: String): JSONObject = JSONObject()
        .put("sessionId", sessionId)

    /** One stream input event, wrapped with the caller's session +
     *  participant identity. The companion's stream layer accepts it
     *  ONLY from the session's current floor holder; everyone else
     *  is refused with the reason in the reply. */
    fun streamInput(sessionId: String, userId: String, event: JSONObject): JSONObject = JSONObject()
        .put("sessionId", sessionId)
        .put("userId", userId)
        .put("event", event)

    /** Absolute pointer position inside the streamed monitor
     *  (stream input event kind "pointer_abs"). */
    fun inputPointerAbs(x: Int, y: Int): JSONObject = JSONObject()
        .put("type", "pointer_abs")
        .put("x", x)
        .put("y", y)

    /** Stream truth from /mesh/stream/info: session state, floor
     *  holder, roster, encoder facts — parsed defensively like the
     *  heartbeat: what we cannot read degrades, never invents. */
    data class StreamInfo(
        val ok: Boolean = false,
        val error: String = "",
        val streaming: Boolean = false,
        val sessionState: String = "",
        val floorHolderId: String? = null,
        val floorHolderName: String? = null,
        val width: Int = 0,
        val height: Int = 0,
        val monitor: Int = 0,
        val capture: String = "",
        val encoder: String = "",
        val hardware: Boolean = false,
        val framesEncoded: Long = 0,
        val roster: List<RosterEntry> = emptyList()
    ) {
        data class RosterEntry(
            val userId: String,
            val name: String,
            val role: String,
            val floor: String
        )

        companion object {
            fun parse(json: JSONObject): StreamInfo {
                if (!json.optBoolean("ok", false)) {
                    return StreamInfo(ok = false, error = json.optString("error"))
                }
                val floor = json.optJSONObject("floor")
                val rosterJson = json.optJSONArray("roster")
                val roster = mutableListOf<RosterEntry>()
                if (rosterJson != null) {
                    for (i in 0 until rosterJson.length()) {
                        val p = rosterJson.optJSONObject(i) ?: continue
                        roster += RosterEntry(
                            userId = p.optString("userId"),
                            name = p.optString("name"),
                            role = p.optString("role"),
                            floor = p.optString("floor")
                        )
                    }
                }
                return StreamInfo(
                    ok = true,
                    streaming = json.optBoolean("streaming", false),
                    sessionState = json.optString("sessionState"),
                    floorHolderId = floor?.optString("userId")?.takeIf { it.isNotEmpty() && it != "null" },
                    floorHolderName = floor?.optString("name")?.takeIf { it.isNotEmpty() && it != "null" },
                    width = json.optInt("width", 0),
                    height = json.optInt("height", 0),
                    monitor = json.optInt("monitor", 0),
                    capture = json.optString("capture"),
                    encoder = json.optString("encoder"),
                    hardware = json.optBoolean("hardware", false),
                    framesEncoded = json.optLong("framesEncoded", 0),
                    roster = roster
                )
            }
        }
    }

    /**
     * One ACPF v1 frame envelope (mesh contract v2 §stream): magic
     * "ACPF", u16 version, u16 header length, JSON header, then one
     * Annex B H.264 access unit. The parser is the Kotlin port of
     * the companion's own validator and is FAIL-CLOSED — the same
     * rules, so a malformed or hostile envelope dies here, before
     * anything reaches MediaCodec: bad magic/version, header out of
     * bounds, oversized or empty AU, non-Annex-B bytes, NAL type 0
     * or above 12, a keyframe without SPS+PPS+IDR (in order), or
     * absurd dimensions all reject. The keyframe flag is derived
     * from the NALs, never trusted from the header.
     */
    data class StreamFrame(
        val seq: Long,
        val ptsMs: Long,
        val captureMs: Long,
        val keyframe: Boolean,
        val width: Int,
        val height: Int,
        val monitor: Int,
        val encoder: String,
        val hardware: Boolean,
        val capture: String,
        val cursorX: Int,
        val cursorY: Int,
        val accessUnit: ByteArray
    ) {
        override fun equals(other: Any?): Boolean =
            other is StreamFrame && seq == other.seq && accessUnit.contentEquals(other.accessUnit)

        override fun hashCode(): Int = 31 * seq.hashCode() + accessUnit.contentHashCode()
    }

    object StreamFrames {
        const val MAX_HEADER_BYTES = 4096
        const val MAX_ACCESS_UNIT_BYTES = 8 * 1024 * 1024

        fun parse(bytes: ByteArray): StreamFrame? {
            if (bytes.size < 8) return null
            if (bytes[0] != 'A'.code.toByte() || bytes[1] != 'C'.code.toByte() ||
                bytes[2] != 'P'.code.toByte() || bytes[3] != 'F'.code.toByte()
            ) return null
            val version = (bytes[4].toInt() and 0xFF) or ((bytes[5].toInt() and 0xFF) shl 8)
            if (version != 1) return null
            val headerLen = (bytes[6].toInt() and 0xFF) or ((bytes[7].toInt() and 0xFF) shl 8)
            if (headerLen <= 0 || headerLen > MAX_HEADER_BYTES) return null
            if (bytes.size < 8 + headerLen + 4) return null
            val header = try {
                JSONObject(String(bytes, 8, headerLen, Charsets.UTF_8))
            } catch (e: Exception) {
                return null
            }
            val au = bytes.copyOfRange(8 + headerLen, bytes.size)
            if (au.isEmpty() || au.size > MAX_ACCESS_UNIT_BYTES) return null
            val keyframe = validateAccessUnit(au, header.optBoolean("keyframe", false)) ?: return null
            val width = header.optInt("width", 0)
            val height = header.optInt("height", 0)
            if (width <= 0 || height <= 0 || width > 16384 || height > 16384) return null
            if (header.optString("codec") != "h264") return null
            return StreamFrame(
                seq = header.optLong("seq", 0),
                ptsMs = header.optLong("ptsMs", 0),
                captureMs = header.optLong("captureMs", 0),
                keyframe = keyframe,
                width = width,
                height = height,
                monitor = header.optInt("monitor", 0),
                encoder = header.optString("encoder"),
                hardware = header.optBoolean("hardware", false),
                capture = header.optString("capture"),
                cursorX = header.optInt("cursorX", -1),
                cursorY = header.optInt("cursorY", -1),
                accessUnit = au
            )
        }

        /** True when the AU is a keyframe per its own NALs; null
         *  when the AU is invalid at all. */
        fun validateAccessUnit(au: ByteArray, claimedKeyframe: Boolean): Boolean? {
            val types = nalTypes(au) ?: return null
            val isKeyframe = 5 in types
            if (isKeyframe != claimedKeyframe) return null
            if (isKeyframe) {
                val sps = types.indexOf(7)
                val pps = types.indexOf(8)
                val idr = types.indexOf(5)
                if (sps < 0 || pps < 0 || sps > idr || pps > idr) return null
            }
            return isKeyframe
        }

        /** NAL unit types in order, or null when the bytes are not
         *  well-formed Annex B. */
        fun nalTypes(au: ByteArray): List<Int>? {
            if (au.size < 4) return null
            val types = mutableListOf<Int>()
            var i = 0
            var nalStart = -1
            fun emit(from: Int, to: Int): Boolean {
                if (to - from < 1) return false
                val b = au[from].toInt() and 0xFF
                if (b and 0x80 != 0) return false
                val type = b and 0x1F
                if (type == 0 || type > 12) return false
                types += type
                return true
            }
            while (i + 2 < au.size) {
                if (au[i].toInt() == 0 && au[i + 1].toInt() == 0 &&
                    (au[i + 2].toInt() == 1 || (i + 3 < au.size && au[i + 2].toInt() == 0 && au[i + 3].toInt() == 1))
                ) {
                    val scLen = if (au[i + 2].toInt() == 1) 3 else 4
                    if (nalStart >= 0) {
                        if (!emit(nalStart, i)) return null
                    } else if (i != 0) return null
                    nalStart = i + scLen
                    i += scLen
                } else i++
            }
            if (nalStart < 0) return null
            if (!emit(nalStart, au.size)) return null
            return types
        }
    }
}

/**
 * Base-URL shape policy for the mesh companion (bd-and-remote F2).
 * Lives beside the protocol (pure, JVM-compiled) so the suite can
 * pin it; MeshStore delegates here.
 */
object MeshUrlPolicy {
    fun isAcceptableBaseUrl(raw: String?): Boolean {
        val url = raw?.trim()?.trimEnd('/') ?: return false
        val rest = when {
            url.startsWith("http://") -> url.substring(7)
            url.startsWith("https://") -> url.substring(8)
            else -> return false
        }
        if (rest.isEmpty() || rest.contains('/') || rest.contains('@') || rest.contains(' ')) return false
        val host = hostPart(rest) ?: return false
        if (isTailnetAddress(host)) return true
        if (host.equals("localhost", ignoreCase = true)) return true
        val literal = parseLiteralIp(host) ?: return false
        if (literal.size == 16) return literal.all { it == 0.toByte() } || (literal[15] == 1.toByte() && literal.copyOfRange(0, 15).all { it == 0.toByte() })
        val o = literal.map { it.toInt() and 0xFF }
        return o[0] == 127 || (o[0] == 10) || (o[0] == 172 && o[1] in 16..31) || (o[0] == 192 && o[1] == 168)
    }

    // Self-contained copies of the MeshAddress / parseLiteralIp
    // rules (transport layer): MeshProtocol compiles in an earlier
    // chunk than the transport package, and a URL-shape policy must
    // not grow a layering dependency. The rules are identical:
    // tailnet = 100.64/10 or fd7a:115c:a1e0::/48.
    private fun hostPart(address: String): String? {
        val a = address.trim()
        if (a.isEmpty()) return null
        if (a.startsWith("[")) {
            val close = a.indexOf(']')
            if (close < 0) return null
            return a.substring(1, close)
        }
        val firstColon = a.indexOf(':')
        if (firstColon < 0) return a
        return if (a.indexOf(':', firstColon + 1) < 0) a.substring(0, firstColon) else a
    }

    private fun isTailnetAddress(host: String): Boolean {
        if (host.contains(':')) {
            val g = host.lowercase().split(':')
            return g.size >= 3 && g[0] == "fd7a" && g[1] == "115c" && g[2] == "a1e0"
        }
        val parts = host.split('.')
        if (parts.size != 4) return false
        val o = parts.map { it.toIntOrNull() ?: return false }
        if (o.any { it !in 0..255 }) return false
        return o[0] == 100 && o[1] in 64..127
    }

    private fun parseLiteralIp(host: String): ByteArray? {
        if (host.contains(':')) {
            val halves = host.split("::", limit = 2)
            fun groups(part: String): List<Int>? {
                if (part.isEmpty()) return emptyList()
                return part.split(':').map { g ->
                    if (g.isEmpty() || g.length > 4) return null
                    g.toIntOrNull(16) ?: return null
                }
            }
            val left = groups(halves[0]) ?: return null
            val right = if (halves.size == 2) (groups(halves[1]) ?: return null) else emptyList()
            val total = left.size + right.size
            if (halves.size == 2) { if (total > 7) return null } else if (total != 8) return null
            val full = left + List(8 - total) { 0 } + right
            val out = ByteArray(16)
            for (i in 0 until 8) { out[i * 2] = (full[i] shr 8).toByte(); out[i * 2 + 1] = full[i].toByte() }
            return out
        }
        val parts = host.split('.')
        if (parts.size != 4) return null
        val out = ByteArray(4)
        for (i in 0 until 4) {
            val v = parts[i].toIntOrNull() ?: return null
            if (v !in 0..255 || parts[i] != v.toString()) return null
            out[i] = v.toByte()
        }
        return out
    }
}
