package io.agenticcontrol.app.mesh

import android.content.Context
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

/** Where the Windows companion lives, as the user configured it. */
object MeshStore {
    private const val PREFS = "mesh"

    /** bd-and-remote F2 fix: the mesh protocol is unauthenticated
     *  plain HTTP (see MeshProtocol's authentication note), so the
     *  base URL is pinned by SHAPE: http/https to a tailnet
     *  (100.64/10 or the Tailscale ULA), loopback, or RFC1918 LAN
     *  host, with an optional port. A public-internet host is
     *  refused — the companion lives on the user's own tailnet or
     *  LAN, and a mistyped or hostile URL must not be able to
     *  redirect input events (and the userIds they carry) to a
     *  stranger's server. Pure + JVM-testable. */
    fun isAcceptableBaseUrl(raw: String?): Boolean = MeshUrlPolicy.isAcceptableBaseUrl(raw)

    fun baseUrl(context: Context): String? =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getString("base_url", null)?.trimEnd('/')?.takeIf { it.isNotBlank() && isAcceptableBaseUrl(it) }

    fun saveBaseUrl(context: Context, baseUrl: String) {
        // A refused shape is never stored: the field keeps its
        // previous (acceptable) value instead of the hostile one.
        if (!isAcceptableBaseUrl(baseUrl)) return
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString("base_url", baseUrl.trim().trimEnd('/'))
            .apply()
    }

    fun clear(context: Context) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().clear().apply()
    }

    /** W6 Task 0: the pairing bearer this client presents to the
     *  companion (stored in the same mesh prefs the base URL lives
     *  in). Null when unpaired — MeshClient then sends no
     *  Authorization header at all, never an invented one. */
    fun bearerToken(context: Context): String? =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getString("bearer_token", null)?.takeIf { it.isNotBlank() }

    fun saveBearerToken(context: Context, token: String) {
        if (!MeshAuth.hasToken(token)) return
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString("bearer_token", token)
            .apply()
    }
}

/**
 * The HTTP client for the mesh companion protocol (0.4.0). Every
 * call is blocking and meant for a background thread; failures come
 * back as null/false — the device page turns two missed polls into
 * the honest "companion offline" state.
 */
class MeshClient(
    private val baseUrl: String,
    /** W6 Task 0: supplies the pairing's bearer token at request
     *  time (so a re-pair or revoke takes effect on the next call).
     *  Null/blank → no Authorization header is sent. */
    private val bearerToken: () -> String? = { null }
) {

    @Volatile
    var lastRoundTripMs: Long = -1
        private set

    /** Applies the Authorization header iff a usable pairing token
     *  exists (see MeshAuth). Called on EVERY request path. */
    private fun HttpURLConnection.authorize() {
        MeshAuth.headerValue(bearerToken())?.let {
            setRequestProperty(MeshAuth.HEADER_NAME, it)
        }
    }

    fun fetchState(): MeshProtocol.CompanionState? {
        val started = System.nanoTime()
        val text = request("GET", MeshProtocol.PATH_STATE, null) ?: return null
        lastRoundTripMs = (System.nanoTime() - started) / 1_000_000
        return try {
            MeshProtocol.CompanionState.parse(JSONObject(text))
        } catch (e: Exception) {
            null
        }
    }

    /** The desktop preview JPEG, or null when there is none. */
    fun fetchPreview(): ByteArray? {
        val url = URL(baseUrl + MeshProtocol.PATH_PREVIEW)
        val conn = (url.openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = 3_000
            readTimeout = 5_000
            authorize()
        }
        return try {
            if (conn.responseCode != 200) {
                null
            } else {
                conn.inputStream.use { it.readBytes() }
            }
        } catch (e: Exception) {
            null
        } finally {
            conn.disconnect()
        }
    }

    fun postInput(event: JSONObject): Boolean =
        request("POST", MeshProtocol.PATH_INPUT, event.toString()) != null

    fun postHandoff(): Boolean =
        request("POST", MeshProtocol.PATH_HANDOFF, JSONObject().toString()) != null

    fun postDisconnect(): Boolean =
        request("POST", MeshProtocol.PATH_DISCONNECT, JSONObject().toString()) != null

    fun postHeartbeat(phoneName: String, watching: Boolean): Boolean =
        request(
            "POST", MeshProtocol.PATH_HEARTBEAT,
            MeshProtocol.heartbeat(phoneName, watching).toString()
        ) != null

    /** A stream call's full outcome: HTTP status + body. The stream
     *  layer's refusals (403 not the floor holder, 409 session not
     *  active, 404 no such session) are information the viewer shows
     *  verbatim — they must not collapse into a bare failure. */
    data class StreamReply(val status: Int, val body: String) {
        val ok: Boolean get() = status in 200..299
        val error: String
            get() = try {
                JSONObject(body).optString("error").ifEmpty { "HTTP $status" }
            } catch (e: Exception) {
                "HTTP $status"
            }
    }

    fun streamStart(sessionId: String, userId: String, monitor: Int): StreamReply =
        requestFull("POST", MeshProtocol.PATH_STREAM_START,
            MeshProtocol.streamStart(sessionId, userId, monitor).toString())

    fun streamStop(sessionId: String): StreamReply =
        requestFull("POST", MeshProtocol.PATH_STREAM_STOP,
            MeshProtocol.streamStop(sessionId).toString())

    fun streamInfo(sessionId: String): MeshProtocol.StreamInfo? {
        val reply = requestFull("GET",
            MeshProtocol.PATH_STREAM_INFO + "?sessionId=" + java.net.URLEncoder.encode(sessionId, "UTF-8"), null)
        if (!reply.ok) return null
        return try {
            MeshProtocol.StreamInfo.parse(JSONObject(reply.body))
        } catch (e: Exception) {
            null
        }
    }

    /** The next frame envelope after [afterSeq]: 200 with ACPF
     *  bytes (parsed fail-closed), 204 when nothing newer exists,
     *  anything else as a refusal reply. */
    sealed class FrameResult {
        data class Frame(val frame: MeshProtocol.StreamFrame) : FrameResult()
        object NoNewer : FrameResult()
        data class Refused(val reply: StreamReply) : FrameResult()
        object Invalid : FrameResult()
    }

    fun streamFrame(sessionId: String, afterSeq: Long): FrameResult {
        val url = URL(baseUrl + MeshProtocol.PATH_STREAM_FRAME +
            "?sessionId=" + java.net.URLEncoder.encode(sessionId, "UTF-8") + "&after=" + afterSeq)
        val conn = (url.openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = 3_000
            readTimeout = 5_000
            authorize()
        }
        return try {
            when (conn.responseCode) {
                204 -> FrameResult.NoNewer
                200 -> {
                    val bytes = conn.inputStream.use { it.readBytes() }
                    val frame = MeshProtocol.StreamFrames.parse(bytes)
                    if (frame != null) FrameResult.Frame(frame) else FrameResult.Invalid
                }
                else -> FrameResult.Refused(
                    StreamReply(conn.responseCode,
                        try { conn.errorStream?.readBytes()?.toString(Charsets.UTF_8) ?: "" } catch (e: Exception) { "" })
                )
            }
        } catch (e: Exception) {
            FrameResult.Refused(StreamReply(-1, ""))
        } finally {
            conn.disconnect()
        }
    }

    fun streamInput(sessionId: String, userId: String, event: JSONObject): StreamReply =
        requestFull("POST", MeshProtocol.PATH_STREAM_INPUT,
            MeshProtocol.streamInput(sessionId, userId, event).toString())

    private fun requestFull(method: String, path: String, body: String?): StreamReply {
        val conn = (URL(baseUrl + path).openConnection() as HttpURLConnection).apply {
            requestMethod = method
            connectTimeout = 3_000
            readTimeout = 5_000
            authorize()
            if (body != null) {
                doOutput = true
                setRequestProperty("Content-Type", "application/json")
            }
        }
        return try {
            if (body != null) {
                conn.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
            }
            val code = conn.responseCode
            val text = try {
                val stream = if (code in 200..299) conn.inputStream else conn.errorStream
                stream?.readBytes()?.toString(Charsets.UTF_8) ?: ""
            } catch (e: Exception) {
                ""
            }
            StreamReply(code, text)
        } catch (e: Exception) {
            StreamReply(-1, "")
        } finally {
            conn.disconnect()
        }
    }

    private fun request(method: String, path: String, body: String?): String? {
        val conn = (URL(baseUrl + path).openConnection() as HttpURLConnection).apply {
            requestMethod = method
            connectTimeout = 3_000
            readTimeout = 5_000
            authorize()
            if (body != null) {
                doOutput = true
                setRequestProperty("Content-Type", "application/json")
            }
        }
        return try {
            if (body != null) {
                conn.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
            }
            if (conn.responseCode !in 200..299) {
                null
            } else {
                conn.inputStream.use { it.readBytes().toString(Charsets.UTF_8) }
            }
        } catch (e: Exception) {
            null
        } finally {
            conn.disconnect()
        }
    }
}
