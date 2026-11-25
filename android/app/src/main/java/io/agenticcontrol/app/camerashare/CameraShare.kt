package io.agenticcontrol.app.camerashare

import io.agenticcontrol.app.cameraview.ChainedAudit

/**
 * RMM-22 (Android host) — camera-share "see the rack". Mirrors
 * Windows Acp.Shared/CameraShare/CameraShare.cs. The phone IS the
 * camera. Five integration points, per the assessment of record:
 *  (1) Owner-only initiation surface. There is NO inbound start:
 *      [requestShareFromWatcher] exists only to refuse + audit.
 *  (2) Presence rendering contract: [presence] derives watcher-named
 *      waiting/watching/ended state; STOP is inside the contract
 *      (stopAvailable is true in every live state, by construction).
 *  (3) Pipeline: CameraX -> Annex B access units -> ACPF envelope ->
 *      [submitFrame]; frames only while sharing; waiting frames are
 *      DROPPED, never buffered. Frame bytes are never retained —
 *      the record holds counts only; there is no retention path.
 *  (4) Transport sink delivers to the named watcher ONLY;
 *      annotations render as overlay; torch binds to the host torch.
 *  (5) Lifecycle hooks: [watcherDisconnect], [ownerNavigatedAway],
 *      [tick] (timeout / suspension / policy flip end the share).
 * The Android host binds CameraX + the real transport behind
 * [CameraShareSink]; this file is the governed contract those
 * bindings plug into (model layer, JVM-proven).
 */
object CameraSharePolicy {
    @Volatile var enabled: Boolean = true // rmm.camera_share.enabled, registry-seeded ON
    /** bd-and-rmm F2: a bound ManagementPolicyEngine governs
     *  through PolicyGate; the local var is the unbound fallback. */
    fun isEnabled(): Boolean =
        io.agenticcontrol.app.rmmspine.PolicyGate.enabledFor("rmm.camera_share.enabled", enabled)
    @Volatile var voiceEnabled: Boolean = false // rmm.camera_share.voice.enabled, fail-closed when unset
    @Volatile var maxDurationMinutes: Long = 60
    const val ABSOLUTE_MAX_MINUTES = 480L // 8h hard clamp
}

fun interface AcpfValidator { fun isValidEnvelope(frame: ByteArray): Boolean }
interface CameraShareSink {
    fun open(shareId: String, watcherId: String)
    fun deliverFrame(shareId: String, watcherId: String, frame: ByteArray)
    fun deliverAnnotation(shareId: String, x: Int, y: Int)
    fun setTorch(shareId: String, on: Boolean)
    fun close(shareId: String, cause: String)
}
interface PartyDirectory {
    fun isLiveHuman(scopeId: String, userId: String): Boolean
    fun isLiveAi(scopeId: String, userId: String): Boolean
    fun displayName(userId: String): String
    fun phoneFiled(scopeId: String, phoneDeviceId: String): Boolean
    /** bd-and-rmm F6: does [ownerId] actually OWN [phoneDeviceId]
     *  in [scopeId]? Initiation used to check only that the phone
     *  was filed SOMEWHERE in the scope — any live human could
     *  start a share of somebody else's phone. */
    fun isPhoneOwner(scopeId: String, ownerId: String, phoneDeviceId: String): Boolean
}

data class AiShareGrant(val ownerId: String, val aiId: String, val phoneId: String, val expiresMs: Long)

class CameraShareService(
    private val parties: PartyDirectory,
    private val sink: CameraShareSink,
    private val acpf: AcpfValidator,
    val audit: ChainedAudit = ChainedAudit(),
    private val clockMs: () -> Long = { System.currentTimeMillis() }
) {
    data class Share(
        val id: String, val scopeId: String, val ownerId: String, val phoneId: String,
        val watcherId: String, val startedMs: Long,
        var state: String = "waiting", // waiting | sharing | ended
        var frameCount: Long = 0, var annotationCount: Long = 0,
        var voice: Boolean = false, var torch: Boolean = false,
        val recording: String = "none" // constant: a recording share is unrepresentable
    ) { val isRecording: Boolean get() = false }

    data class Presence(
        val watcherId: String, val watcherName: String, val state: String,
        val isBeingWatched: Boolean, val voice: Boolean, val torch: Boolean,
        val stopAvailable: Boolean, val bannerText: String
    )

    private val shares = mutableMapOf<String, Share>()
    private val grants = mutableListOf<AiShareGrant>()
    private var nextId = 1

    @Synchronized
    fun grantAiWatcher(ownerId: String, scopeId: String, aiId: String, phoneId: String, ttlMinutes: Long): Boolean {
        if (!parties.isLiveHuman(scopeId, ownerId) || !parties.isLiveAi(scopeId, aiId)) return false
        if (ttlMinutes <= 0) return false
        val ttl = minOf(ttlMinutes, CameraSharePolicy.ABSOLUTE_MAX_MINUTES)
        grants.removeAll { it.ownerId == ownerId && it.aiId == aiId && it.phoneId == phoneId }
        grants.add(AiShareGrant(ownerId, aiId, phoneId, clockMs() + ttl * 60_000))
        audit.append("camera_share_ai_grant", "owner=$ownerId ai=$aiId phone=$phoneId ttlMin=$ttl"); return true
    }
    @Synchronized
    fun revokeAiGrant(ownerId: String, aiId: String, phoneId: String) {
        grants.removeAll { it.ownerId == ownerId && it.aiId == aiId && it.phoneId == phoneId }
        shares.values.firstOrNull { it.state != "ended" && it.watcherId == aiId && it.phoneId == phoneId }?.let { end(it, "ai_grant_revoked") }
        audit.append("camera_share_ai_grant_revoked", "owner=$ownerId ai=$aiId phone=$phoneId")
    }

    /** (1) The ONLY mint. Owner = the phone's own human owner. */
    @Synchronized
    fun initiateShare(scopeId: String, ownerId: String, phoneId: String, watcherId: String): Result<Share> {
        fun refuse(r: String): Result<Share> { audit.append("camera_share_refused", "owner=$ownerId watcher=$watcherId reason=$r"); return Result.failure(IllegalStateException(r)) }
        if (!CameraSharePolicy.isEnabled()) return refuse("policy rmm.camera_share.enabled is OFF")
        if (!parties.isLiveHuman(scopeId, ownerId)) return refuse("owner must be a live human (an AI can never initiate or consent)")
        // bd-and-rmm F6: the initiator must own THIS phone.
        if (!parties.isPhoneOwner(scopeId, ownerId, phoneId)) return refuse("initiator does not own this phone — a share can only be started by the phone's owner")
        if (ownerId == watcherId) return refuse("self-watch refused")
        if (!parties.phoneFiled(scopeId, phoneId)) return refuse("phone is not filed in a device group of the scope")
        val watcherHuman = parties.isLiveHuman(scopeId, watcherId)
        if (!watcherHuman) {
            if (!parties.isLiveAi(scopeId, watcherId)) return refuse("watcher is not a live member of the scope")
            val g = grants.firstOrNull { it.ownerId == ownerId && it.aiId == watcherId && it.phoneId == phoneId }
            if (g == null || g.expiresMs <= clockMs()) return refuse("AI watcher requires a live explicit grant (default denied)")
        }
        if (shares.values.any { it.phoneId == phoneId && it.state != "ended" }) return refuse("one live share per phone")
        val s = Share("share-${nextId++}", scopeId, ownerId, phoneId, watcherId, clockMs())
        audit.append("camera_share_started", "share=${s.id} owner=$ownerId watcher=$watcherId") // audit-first, before sink opens
        try { sink.open(s.id, watcherId) } catch (e: Exception) {
            audit.append("camera_share_failed", "share=${s.id} reason=sink open failed"); return Result.failure(e)
        }
        shares[s.id] = s; return Result.success(s)
    }

    /** Named refusal surface: a watcher can NEVER start a share. */
    @Synchronized
    fun requestShareFromWatcher(watcherId: String, phoneId: String): Result<Share> {
        audit.append("camera_share_inbound_start_refused", "watcher=$watcherId phone=$phoneId")
        return Result.failure(IllegalStateException("watchers cannot start a camera share; only the phone owner initiates"))
    }

    @Synchronized
    fun watcherJoin(shareId: String, watcherId: String): Boolean {
        val s = shares[shareId] ?: return false
        if (s.watcherId != watcherId || s.state != "waiting") return false
        s.state = "sharing"; audit.append("camera_share_watcher_joined", "share=$shareId watcher=$watcherId"); return true
    }

    /** (3) Frames only while sharing; waiting frames dropped, never buffered, never retained. */
    @Synchronized
    fun submitFrame(shareId: String, fromId: String, frame: ByteArray): Boolean {
        val s = shares[shareId] ?: return false
        if (s.ownerId != fromId || s.state != "sharing") return false
        if (!acpf.isValidEnvelope(frame)) return false
        sink.deliverFrame(shareId, s.watcherId, frame) // handed to the named watcher only, then discarded
        s.frameCount++; return true
    }

    @Synchronized
    fun sendAnnotation(shareId: String, fromId: String, x: Int, y: Int): Boolean {
        val s = shares[shareId] ?: return false
        if (s.watcherId != fromId || s.state != "sharing") return false
        if (x !in 0..1000 || y !in 0..1000) return false
        sink.deliverAnnotation(shareId, x, y); s.annotationCount++; return true
    }

    @Synchronized
    fun setVoice(shareId: String, actorId: String, on: Boolean): Boolean {
        val s = shares[shareId] ?: return false; if (s.state == "ended") return false
        if (on && (s.ownerId != actorId || !CameraSharePolicy.voiceEnabled)) {
            audit.append("camera_share_voice_refused", "share=$shareId actor=$actorId"); return false
        }
        if (!on && actorId != s.ownerId && actorId != s.watcherId) return false
        s.voice = on; return true
    }
    @Synchronized
    fun setTorch(shareId: String, actorId: String, on: Boolean): Boolean {
        val s = shares[shareId] ?: return false
        if (s.ownerId != actorId || s.state == "ended") return false
        s.torch = on; sink.setTorch(shareId, on); return true
    }
    @Synchronized
    fun requestTorch(shareId: String, actorId: String): Boolean {
        val s = shares[shareId] ?: return false
        if (s.watcherId != actorId || s.state == "ended") return false
        audit.append("camera_share_torch_requested", "share=$shareId watcher=$actorId"); return true // changes no state
    }

    /** (2) Presence contract, derived from the record alone. */
    @Synchronized
    fun presence(shareId: String): Presence? {
        val s = shares[shareId] ?: return null
        val name = parties.displayName(s.watcherId)
        val banner = when (s.state) {
            "sharing" -> "$name is watching your camera"
            "waiting" -> "Waiting for $name to join your camera share"
            else -> "Camera share ended"
        }
        return Presence(s.watcherId, name, s.state, s.state == "sharing", s.voice, s.torch,
            stopAvailable = s.state != "ended", bannerText = banner)
    }

    @Synchronized fun stopShare(shareId: String, actorId: String): Boolean {
        val s = shares[shareId] ?: return false
        if (s.ownerId != actorId) { audit.append("camera_share_stop_refused", "share=$shareId actor=$actorId reason=owner only"); return false }
        if (s.state == "ended") return false; end(s, "owner_stop"); return true
    }
    @Synchronized fun watcherDisconnect(shareId: String) { shares[shareId]?.takeIf { it.state != "ended" }?.let { end(it, "watcher_disconnect") } }
    @Synchronized fun ownerNavigatedAway(shareId: String) { shares[shareId]?.takeIf { it.state != "ended" }?.let { end(it, "owner_navigated_away") } }

    /** (5) Standing enforcer. bd-and-rmm F6 fix: the enforcer now
     *  re-validates EVERY party on every tick — the owner must
     *  still be a live HUMAN (the old code accepted the owner
     *  having become a live AI, inverting the consent model), a
     *  human watcher must still be a live human, and an AI watcher
     *  must still hold an unexpired grant (revocation already ends
     *  shares in revokeAiGrant; expiry did not). */
    @Synchronized
    fun tick() {
        val maxMin = minOf(CameraSharePolicy.maxDurationMinutes, CameraSharePolicy.ABSOLUTE_MAX_MINUTES)
        for (s in shares.values.filter { it.state != "ended" }) {
            val aiGrant = grants.firstOrNull { it.ownerId == s.ownerId && it.aiId == s.watcherId && it.phoneId == s.phoneId }
            when {
                !CameraSharePolicy.isEnabled() -> end(s, "policy_off")
                clockMs() - s.startedMs >= maxMin * 60_000 -> end(s, "timeout")
                !parties.isLiveHuman(s.scopeId, s.ownerId) -> end(s, "owner_gone")
                parties.isLiveHuman(s.scopeId, s.watcherId) -> Unit // human watcher still live: share stands
                parties.isLiveAi(s.scopeId, s.watcherId) && aiGrant != null && aiGrant.expiresMs > clockMs() -> Unit // AI watcher under a live grant
                parties.isLiveAi(s.scopeId, s.watcherId) -> end(s, "ai_grant_expired")
                else -> end(s, "watcher_gone")
            }
            if (s.state != "ended" && !parties.phoneFiled(s.scopeId, s.phoneId)) end(s, "phone_unfiled")
        }
    }
    private fun end(s: Share, cause: String) {
        s.state = "ended"; sink.close(s.id, cause)
        audit.append("camera_share_ended", "share=${s.id} cause=$cause durationSeconds=${(clockMs() - s.startedMs) / 1000} frames=${s.frameCount}")
    }
    @Synchronized fun share(id: String): Share? = shares[id]
    @Synchronized fun tryEnableRecording(shareId: String): Boolean {
        audit.append("camera_share_recording_refused", "share=$shareId reason=live-only; recording is structurally absent")
        return false
    }
}
