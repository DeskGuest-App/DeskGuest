package io.agenticcontrol.app.cameraview

import java.security.MessageDigest

/**
 * RMM-11 EXTENSION (Android mirror) — camera viewing, operator side.
 * Mirrors Windows Acp.Shared/NetworkDiscovery/CameraViewing.cs.
 * Model layer only: ONVIF/RTSP gate chain + classification + URI guard
 * + hash-chained audit. Rendering reuses the existing StreamViewer
 * (Block D H.264 SurfaceView) where it honestly fits: an RTSP source
 * is handed to that renderer as a stream source; this layer builds
 * no second video stack and claims no live camera proof.
 *
 * Gate chain, re-read per view, in order: roster `view` right (live,
 * via [ViewRights]) -> TOTAL POLICY CONTROL toggle -> capability
 * (cloud-locked = inventory-only WITH the manufacturer's reason) ->
 * URI re-validation at view time. Every view and every refusal is
 * hash-chained. Refused-STOP flood bound (Completion ruling a):
 * repeated refused attempts from the same actor+camera inside a
 * rolling window collapse into counted aggregate chain entries;
 * the total count stays recoverable from the chain.
 */
object CameraViewPolicy {
    @Volatile var enabled: Boolean = false // rmm.camera_viewing.enabled, seeded OFF
    @Volatile var audioEnabled: Boolean = false // rmm.camera_viewing.audio.enabled
    /** bd-and-rmm F2: a bound ManagementPolicyEngine governs
     *  through PolicyGate; the local var is the unbound fallback. */
    fun isEnabled(): Boolean =
        io.agenticcontrol.app.rmmspine.PolicyGate.enabledFor("rmm.camera_viewing.enabled", enabled)
}

fun interface ViewRights {
    /** Live check: suspension / scope / D9-AI-scoping enforced by the roster. */
    fun hasViewRight(scopeId: String, userId: String, deviceGroupId: String): Boolean
}

data class CameraRecord(
    val assetId: String, val scopeId: String, val deviceGroupId: String,
    val address: String, val make: String = "", val model: String = "",
    val viewCapability: String, // "onvif" | "rtsp" | "inventory_only"
    val inventoryReason: String? = null,
    val streamUri: String? = null
)

object CloudCameraClassifier {
    private val CLOUD = mapOf(
        "ring" to "Ring", "nest" to "Google Nest", "wyze" to "Wyze",
        "blink" to "Blink", "arlo" to "Arlo"
    )
    fun capabilityFor(make: String, hasOnvif: Boolean, hasRtsp: Boolean): Pair<String, String?> {
        if (hasOnvif) return "onvif" to null
        if (hasRtsp) return "rtsp" to null // capability evidence outranks brand
        val brand = CLOUD.entries.firstOrNull { make.lowercase().contains(it.key) }?.value
        return if (brand != null) "inventory_only" to
            "Cloud-locked consumer camera ($brand): no local ONVIF/RTSP stream is offered; video is reachable only in the manufacturer's cloud app. Inventory-only by the manufacturer's design."
        else "inventory_only" to "Camera did not advertise ONVIF or RTSP during discovery. Inventory-only."
    }
}

object RtspUriGuard {
    private val PORTS = setOf(554, 8554, 10554)
    /** SSRF line: rtsp only; IP-literal host EXACTLY the registered
     *  address; allowed ports only; no userinfo/query/fragment;
     *  traversal checked on the RAW string (DG-RCAM-06 lesson). */
    fun validate(rawUri: String, registeredAddress: String): String? {
        if (rawUri.contains("..") || rawUri.contains("%2e", true) || rawUri.contains("\\")) return "uri traversal refused"
        if (!rawUri.startsWith("rtsp://")) return "scheme must be rtsp"
        val rest = rawUri.removePrefix("rtsp://")
        if (rest.contains("@")) return "userinfo refused"
        if (rest.contains("?") || rest.contains("#")) return "query/fragment refused"
        val hostPort = rest.substringBefore("/")
        val host = hostPort.substringBefore(":")
        val port = hostPort.substringAfter(":", "554").toIntOrNull() ?: return "bad port"
        if (port !in PORTS) return "port not allowed: $port"
        if (host != registeredAddress) return "host does not match the camera's registered address"
        if (!host.matches(Regex("""\d+\.\d+\.\d+\.\d+"""))) return "host must be an IP literal"
        return null
    }
}

/** bd-and-rest F5 fix: the shared-audit bridge. The RMM services
 *  (Backup / Deploy / MobileOperator / VendorPass / CameraView)
 *  each keep their own hash-chained [ChainedAudit]; when the
 *  platform layer installs a [sink] (PlatformStores wires it to
 *  the app's encrypted AuditStore via MainActivity), every append
 *  ALSO forwards (type, detail) to that shared, exportable log —
 *  so an RMM act no longer lives only in a process-local chain
 *  that dies with the process. Uninstalled (JVM suites, surfaces
 *  that never composed the stores): appends stay local, as before. */
object SharedAuditBridge {
    @Volatile var sink: ((String, String) -> Unit)? = null
}

class ChainedAudit(private val clockMs: () -> Long = { System.currentTimeMillis() }) {
    data class Entry(val seq: Int, val atMs: Long, val type: String, val detail: String, val prevHash: String, val hash: String)
    private val entries = mutableListOf<Entry>()
    @Synchronized fun append(type: String, detail: String): Entry {
        val prev = entries.lastOrNull()?.hash ?: "GENESIS"
        val at = clockMs(); val seq = entries.size
        val body = bodyOf(seq, at, type, detail, prev)
        val hash = MessageDigest.getInstance("SHA-256").digest(body.toByteArray()).joinToString("") { "%02x".format(it) }
        val entry = Entry(seq, at, type, detail, prev, hash).also { entries.add(it) }
        try { SharedAuditBridge.sink?.invoke(type, detail) } catch (_: Exception) { /* the bridge never breaks an append */ }
        return entry
    }
    @Synchronized fun entries(): List<Entry> = entries.toList()
    @Synchronized fun verify(): Boolean {
        var prev = "GENESIS"
        for ((i, e) in entries.withIndex()) {
            if (e.seq != i || e.prevHash != prev) return false
            val hash = MessageDigest.getInstance("SHA-256").digest(bodyOf(e.seq, e.atMs, e.type, e.detail, e.prevHash).toByteArray()).joinToString("") { "%02x".format(it) }
            if (hash != e.hash) return false; prev = e.hash
        }
        return true
    }

    companion object {
        /** bd-and-rmm F12: fields are escaped before joining —
         *  the old raw '|' join let a detail containing '|' forge
         *  field boundaries in the canonical body. Escaping is
         *  applied identically at append and verify. */
        fun esc(s: String): String = s.replace("\\", "\\\\").replace("|", "\\|")
        fun bodyOf(seq: Int, at: Long, type: String, detail: String, prev: String): String =
            "$seq|$at|${esc(type)}|${esc(detail)}|$prev"
    }
}

class CameraViewService(
    private val rights: ViewRights,
    val audit: ChainedAudit = ChainedAudit(),
    private val clockMs: () -> Long = { System.currentTimeMillis() }
) {
    data class ViewSession(
        val id: String, val cameraId: String, val viewerId: String, val startedMs: Long, val audio: Boolean,
        /** bd-and-rmm F11: the camera + scope the view was gated
         *  against, kept so tick() can RE-gate the live view. The
         *  old session forgot both, so a right revoked mid-view
         *  could never be enforced. */
        val cam: CameraRecord? = null, val scopeId: String = ""
    )
    private val live = mutableMapOf<String, ViewSession>()
    private var nextId = 1
    // Flood bound: key actor|camera -> (windowStartMs, pendingCount, firstLogged)
    private val flood = mutableMapOf<String, Triple<Long, Int, Boolean>>()
    companion object {
        const val FLOOD_WINDOW_MS = 60_000L
        /** bd-and-rmm F11: the flood map is capped — keys are built
         *  from caller-supplied ids and grew without bound. */
        const val MAX_FLOOD_KEYS = 256
    }

    @Synchronized
    fun requestView(cam: CameraRecord, scopeId: String, viewerId: String, includeAudio: Boolean = false): Result<ViewSession> {
        fun refuse(reason: String): Result<ViewSession> {
            audit.append("camera_view_refused", "camera=${cam.assetId} viewer=$viewerId reason=$reason"); return Result.failure(IllegalStateException(reason))
        }
        if (!rights.hasViewRight(scopeId, viewerId, cam.deviceGroupId)) return refuse("no roster view right")
        if (!CameraViewPolicy.isEnabled()) return refuse("policy rmm.camera_viewing.enabled is OFF")
        if (cam.viewCapability == "inventory_only") return refuse(cam.inventoryReason ?: "inventory-only camera")
        val uri = cam.streamUri ?: return refuse("no stream URI registered")
        RtspUriGuard.validate(uri, cam.address)?.let { return refuse(it) }
        if (includeAudio && !CameraViewPolicy.audioEnabled) return refuse("audio requested but rmm.camera_viewing.audio.enabled is OFF (no silent downgrade)")
        val s = ViewSession("view-${nextId++}", cam.assetId, viewerId, clockMs(), includeAudio, cam, scopeId)
        audit.append("camera_view_started", "camera=${cam.assetId} viewer=$viewerId audio=$includeAudio") // chained BEFORE any sink is touched
        live[s.id] = s; return Result.success(s)
    }

    @Synchronized
    fun endView(id: String, actorId: String): Boolean {
        val s = live[id] ?: run { recordRefusedStop(actorId, id); return false }
        if (s.viewerId != actorId) { recordRefusedStop(actorId, id); return false }
        live.remove(id)
        audit.append("camera_view_ended", "camera=${s.cameraId} viewer=$actorId durationSeconds=${(clockMs() - s.startedMs) / 1000}")
        return true
    }

    /** Bounded refused-STOP accounting: first in-window attempt is an
     *  individual entry; later ones accumulate and flush as ONE
     *  counted aggregate entry at window close. Nothing is dropped. */
    /**
     * bd-and-rmm F11 fix: the standing enforcer for LIVE views.
     * A view was gated once at request time and never again — a
     * suspended viewer, a flipped policy, or a camera reclassified
     * inventory-only kept streaming until the viewer chose to stop.
     * tick() re-runs the gate chain per live view and ends failures
     * with the cause chained. It also flushes + evicts expired
     * flood windows, so aggregates no longer wait for a recurrence
     * of the same key to reach the chain.
     */
    @Synchronized
    fun tick() {
        for (s in live.values.toList()) {
            val cam = s.cam ?: continue
            val cause = when {
                !rights.hasViewRight(s.scopeId, s.viewerId, cam.deviceGroupId) -> "right_revoked"
                !CameraViewPolicy.isEnabled() -> "policy_off"
                cam.viewCapability == "inventory_only" -> "camera_reclassified_inventory_only"
                s.audio && !CameraViewPolicy.audioEnabled -> "audio_policy_off"
                else -> null
            }
            if (cause != null) {
                live.remove(s.id)
                audit.append("camera_view_ended", "camera=${s.cameraId} viewer=${s.viewerId} cause=$cause durationSeconds=${(clockMs() - s.startedMs) / 1000}")
            }
        }
        val now = clockMs()
        val expired = flood.entries.filter { now - it.value.first >= FLOOD_WINDOW_MS }
        for ((key, v) in expired) {
            if (v.second > 0) {
                val (actor, target) = key.split("|", limit = 2)
                audit.append("camera_stop_refused_aggregate", "actor=$actor target=$target count=${v.second}")
            }
            flood.remove(key)
        }
    }

    @Synchronized
    fun recordRefusedStop(actorId: String, target: String) {
        val key = "$actorId|$target"; val now = clockMs()
        if (key !in flood && flood.size >= MAX_FLOOD_KEYS) {
            // Evict the oldest window (flushing its count first).
            val oldest = flood.entries.minByOrNull { it.value.first }
            if (oldest != null) {
                if (oldest.value.second > 0) {
                    val (a, t) = oldest.key.split("|", limit = 2)
                    audit.append("camera_stop_refused_aggregate", "actor=$a target=$t count=${oldest.value.second}")
                }
                flood.remove(oldest.key)
            }
        }
        val cur = flood[key]
        if (cur == null || now - cur.first >= FLOOD_WINDOW_MS) {
            if (cur != null && cur.second > 0) audit.append("camera_stop_refused_aggregate", "actor=$actorId target=$target count=${cur.second}")
            flood[key] = Triple(now, 0, true)
            audit.append("camera_stop_refused", "actor=$actorId target=$target")
        } else flood[key] = Triple(cur.first, cur.second + 1, true)
    }
    @Synchronized fun flushFloodAggregates() {
        for ((key, v) in flood) if (v.second > 0) {
            val (actor, target) = key.split("|", limit = 2)
            audit.append("camera_stop_refused_aggregate", "actor=$actor target=$target count=${v.second}")
        }
        flood.clear()
    }
    @Synchronized fun liveViews(): List<ViewSession> = live.values.toList()
}
