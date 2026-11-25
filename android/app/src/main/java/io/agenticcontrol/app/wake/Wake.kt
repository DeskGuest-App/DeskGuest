package io.agenticcontrol.app.wake

import io.agenticcontrol.app.enrollment.EnrollmentStore
import io.agenticcontrol.app.enterprise.PolicyFeatures
import io.agenticcontrol.app.roster.RosterStore
import io.agenticcontrol.app.session.SessionStore
import org.json.JSONArray
import org.json.JSONObject
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress

/**
 * Wake-on-LAN as a session capability (Block G, G-01) — the
 * Android mirror of the Windows WakeService. A wake target is a
 * network fact about a device, recorded deliberately — never
 * guessed, never harvested from the LAN: a device with no
 * registered target cannot be woken, full stop.
 *
 * The phone-as-waker half of the census §13 pattern lives here:
 * this store runs on the operator's phone (or any enrolled
 * device) and sends the packet over the LAN it is on. Waking a
 * fully asleep phone from anywhere remains exception X-05 — this
 * store wakes OTHER machines; nothing here claims otherwise.
 */
object MagicPacket {
    const val PACKET_LENGTH = 102
    const val WAKE_PORT = 9

    /** Strict MAC parse: exactly 6 hex octets, colon- or
     *  dash-separated. Returns the 6 bytes, or null. */
    fun parseMac(mac: String?): ByteArray? {
        if (mac.isNullOrBlank()) return null
        val parts = mac.trim().split(':', '-')
        if (parts.size != 6) return null
        val bytes = ByteArray(6)
        for (i in 0 until 6) {
            if (parts[i].length != 2) return null
            bytes[i] = parts[i].toIntOrNull(16)?.toByte() ?: return null
        }
        return bytes
    }

    /** Canonical text form: uppercase, colon-separated. */
    fun normalizeMac(bytes: ByteArray): String =
        bytes.joinToString(":") { "%02X".format(it) }

    /** A wake target is one machine's NIC: the broadcast address
     *  and a multicast address are not wakeable targets. */
    fun isWakeableMac(bytes: ByteArray): Boolean =
        bytes.size == 6 &&
            (bytes[0].toInt() and 0x01) == 0 &&
            !bytes.all { it == 0xFF.toByte() } &&
            !bytes.all { it == 0.toByte() }

    fun build(macBytes: ByteArray): ByteArray {
        require(macBytes.size == 6) { "MAC must be 6 octets" }
        val packet = ByteArray(PACKET_LENGTH)
        for (i in 0 until 6) packet[i] = 0xFF.toByte()
        for (r in 0 until 16) macBytes.copyInto(packet, 6 + r * 6)
        return packet
    }

    fun build(mac: String): ByteArray =
        build(parseMac(mac) ?: throw IllegalArgumentException("unparseable MAC address"))
}

/** The packet's exit door. The production implementation is a
 *  UDP broadcast; tests substitute a recorder. */
fun interface WakeSender {
    fun send(packet: ByteArray, broadcastAddress: String, port: Int)
}

/** Production sender: one UDP datagram, broadcast enabled. */
class UdpWakeSender : WakeSender {
    override fun send(packet: ByteArray, broadcastAddress: String, port: Int) {
        DatagramSocket().use { socket ->
            socket.broadcast = true
            val address = InetAddress.getByName(broadcastAddress)
            socket.send(DatagramPacket(packet, packet.size, address, port))
        }
    }
}

/** A registered wake target: an enrolled device + the MAC of the
 *  NIC to wake + the broadcast address of its LAN segment. */
data class WakeTarget(
    val deviceId: String,
    val macAddress: String,
    val broadcastAddress: String,
    val registeredByUserId: String?,
    val registeredUtcMs: Long,
    val lastWakeUtcMs: Long? = null
)

data class WakeEvent(
    val atMs: Long,
    val kind: String,
    val deviceId: String,
    val actorUserId: String?,
    val detail: String
)

class WakeStore(
    private val roster: RosterStore,
    private val enrollment: EnrollmentStore,
    private val sender: WakeSender,
    private val featureGate: ((String, String) -> Boolean)? = null,
    /** This device's own id, when the wiring knows it: the
     *  null-actor (trusted in-process) registration path is
     *  bounded to it (AF12a). Null provider = the path is CLOSED
     *  and registration requires a live company admin, exactly
     *  the Windows rule. */
    private val localDeviceId: (() -> String?)? = null,
    /** Change hook the wiring layer uses for write-through
     *  persistence (AF10). Invoked after every recorded act.
     *  NOT the last parameter: the clock stays last so existing
     *  trailing-lambda call sites keep binding to it. */
    private val onChanged: (() -> Unit)? = null,
    private val nowMillis: () -> Long = { System.currentTimeMillis() }
) {
    private val targets = LinkedHashMap<String, WakeTarget>()
    private val _events = ArrayList<WakeEvent>()
    val events: List<WakeEvent> get() = synchronized(this) { _events.toList() }

    /** SCOPE-AWARE gate (scopeId, featureKey) — D38-G review F2. */
    private fun featureAllowed(scopeId: String): Boolean =
        featureGate?.invoke(scopeId, PolicyFeatures.WAKE_ON_LAN) ?: true

    private fun device(deviceId: String?) = enrollment.byId(deviceId ?: "")

    private fun scopeOf(device: EnrollmentStore.EnrolledDevice): String? =
        roster.deviceGroup(device.groupId)?.scopeId

    @Synchronized
    private fun record(kind: String, deviceId: String, actor: String?, detail: String) {
        _events.add(WakeEvent(nowMillis(), kind, deviceId, actor, detail))
        onChanged?.invoke()
    }

    private fun isLiveAdmin(scopeId: String, userId: String): Boolean {
        val user = roster.user(userId) ?: return false
        return user.scopeId == scopeId && user.kind == RosterStore.USER_HUMAN &&
            !user.suspended && roster.isCompanyAdmin(scopeId, userId)
    }

    /**
     * Register (or replace) a device's wake target. The actor
     * must be a live company admin of the device's scope, or null
     * — the trusted in-process path, by which a device's own host
     * registers the MACs it can read from its own NICs. AF12a:
     * the null path is bounded to THIS device (the wiring's
     * localDeviceId) — a null actor can no longer register a MAC
     * for any enrolled device, and with no local id wired the
     * path is closed entirely. A remote caller can never
     * register a target: the registry is what stands between
     * "any paired agent" and "wake any MAC on the LAN".
     */
    @Synchronized
    fun registerTarget(deviceId: String, macAddress: String, broadcastAddress: String,
                       actorUserId: String?): Boolean {
        val mac = MagicPacket.parseMac(macAddress)
        if (mac == null || !MagicPacket.isWakeableMac(mac)) return false
        if (!isIpv4(broadcastAddress)) return false
        val device = device(deviceId) ?: return false
        if (device.revoked) return false
        val scopeId = scopeOf(device) ?: return false
        if (actorUserId != null && !isLiveAdmin(scopeId, actorUserId)) return false
        if (actorUserId == null && localDeviceId?.invoke() != device.deviceId) return false
        val normalized = MagicPacket.normalizeMac(mac)
        val old = targets[device.deviceId]
        targets[device.deviceId] = WakeTarget(
            device.deviceId, normalized, broadcastAddress.trim(),
            actorUserId, nowMillis(), old?.lastWakeUtcMs)
        record("wake_target_registered", device.deviceId, actorUserId,
            "Wake target registered: $normalized via ${broadcastAddress.trim()}.")
        return true
    }

    @Synchronized
    fun unregisterTarget(deviceId: String, actorUserId: String?): Boolean {
        val device = device(deviceId) ?: return false
        val scopeId = scopeOf(device) ?: return false
        if (actorUserId != null && !isLiveAdmin(scopeId, actorUserId)) return false
        if (actorUserId == null && localDeviceId?.invoke() != device.deviceId) return false
        if (targets.remove(device.deviceId) == null) return false
        record("wake_target_removed", device.deviceId, actorUserId, "Wake target removed.")
        return true
    }

    @Synchronized
    fun target(deviceId: String): WakeTarget? = targets[deviceId]

    @Synchronized
    fun targets(): List<WakeTarget> = targets.values.toList()

    /**
     * Send the wake. Gates, in order: the policy toggle; a
     * registered target; the device still enrolled and unrevoked
     * (re-read at send time — a device revoked since registration
     * is never woken); the actor a live user of the device's
     * scope holding the "use" grant on the device's group (waking
     * is an act on the machine, authorized exactly like starting
     * an unattended session on it).
     */
    fun sendWake(deviceId: String, actorUserId: String): Pair<Boolean, String> {
        // Phase 1 (under the lock): resolve and gate, with the
        // DEVICE's scope (F2). Phase 2: the network send runs
        // OUTSIDE the lock (D38-G review F12) — a slow network
        // never stalls the store. Phase 3 (under the lock):
        // record the outcome.
        val prepared: Triple<WakeTarget, String, String>
        synchronized(this) {
            val device = device(deviceId) ?: return false to "unknown device"
            if (device.revoked) return false to "device is revoked — never woken"
            val target = targets[device.deviceId] ?: return false to "no wake target registered for this device"
            val scopeId = scopeOf(device) ?: return false to "device is not filed in any scope"
            if (!featureAllowed(scopeId))
                return false to "wake-on-LAN is disabled by policy for this scope"
            val actor = roster.user(actorUserId)
            if (actor == null || actor.scopeId != scopeId || actor.suspended)
                return false to "actor is not a live user of the device's scope"
            if (!roster.canUse(scopeId, actor.id, device.groupId))
                return false to "actor holds no 'use' grant on the device's group"
            prepared = Triple(target, device.deviceId, actor.id)
        }
        val (target, deviceKey, actorId) = prepared
        val packet = MagicPacket.build(target.macAddress)
        try {
            sender.send(packet, target.broadcastAddress, MagicPacket.WAKE_PORT)
        } catch (ex: Exception) {
            return false to "wake send failed: ${ex.javaClass.simpleName}"
        }
        synchronized(this) {
            targets[deviceKey]?.let { targets[deviceKey] = it.copy(lastWakeUtcMs = nowMillis()) }
            record("wake_sent", deviceKey, actorId,
                "Magic packet sent for ${target.macAddress} via ${target.broadcastAddress}:${MagicPacket.WAKE_PORT}.")
        }
        return true to "magic packet sent for ${target.macAddress}"
    }

    /**
     * The session form: wake the host of a REQUESTED session,
     * then the normal connect flow proceeds. The actor must be
     * the session's initiator or one of its participants; the
     * wake lands on the session's event list as well as in this
     * store's own events.
     */
    fun sendWakeForSession(sessions: SessionStore, sessionId: String,
                           actorUserId: String): Pair<Boolean, String> {
        // bd-and-remote F12(a) fix (2026-11-22): NOT @Synchronized.
        // The D38-G F12 rule is that the network send runs outside
        // the lock; this wrapper was @Synchronized and called
        // sendWake inside it, so the UDP send happened under this
        // store's monitor after all. The session checks are reads
        // against SessionStore (its own monitor); the send itself
        // goes through sendWake's phased locking.
        val session = sessions.session(sessionId) ?: return false to "unknown session"
        if (session.state != SessionStore.STATE_REQUESTED)
            return false to "session is ${session.state} — wake precedes connect and applies only to a requested session"
        val isInitiator = session.initiatorUserId == actorUserId
        val isParticipant = sessions.participants(sessionId).any { it.userId == actorUserId }
        if (!isInitiator && !isParticipant) return false to "actor is not part of this session"
        val device = device(session.hostDeviceId)
        if (device != null) {
            val scopeId = scopeOf(device)
            if (scopeId != null && scopeId != session.scopeId)
                return false to "host device is not filed in the session's scope (D8)"
        }
        val result = sendWake(session.hostDeviceId, actorUserId)
        if (result.first) {
            sessions.appendEvent(sessionId, "wake_sent", actorUserId,
                "Target woken for this session (wake-on-LAN).")
        }
        return result
    }

    // ---- persistence ----

    /** Serialize the registry + its event history (D38-G
     *  review F1). MACs are network facts, not secrets; nothing
     *  else lives in this store. Root {targets, events}; import
     *  accepts the pre-F1 bare array. */
    @Synchronized
    fun exportJson(): String {
        val arr = JSONArray()
        for (t in targets.values) arr.put(JSONObject()
            .put("deviceId", t.deviceId).put("macAddress", t.macAddress)
            .put("broadcastAddress", t.broadcastAddress)
            .put("registeredByUserId", t.registeredByUserId ?: JSONObject.NULL)
            .put("registeredUtcMs", t.registeredUtcMs)
            .put("lastWakeUtcMs", t.lastWakeUtcMs ?: JSONObject.NULL))
        val evArr = JSONArray()
        synchronized(this) {
            for (e in _events) evArr.put(JSONObject()
                .put("atMs", e.atMs).put("kind", e.kind).put("deviceId", e.deviceId)
                .put("actorUserId", e.actorUserId ?: JSONObject.NULL).put("detail", e.detail))
        }
        return JSONObject().put("targets", arr).put("events", evArr).toString()
    }

    /** Restore, re-validated: targets for unknown or revoked
     *  devices are dropped, MACs and broadcast addresses are
     *  re-parsed strictly, duplicates collapse to the first. */
    @Synchronized
    fun importJson(json: String): Int {
        val arr: JSONArray
        val evArr: JSONArray?
        try {
            val trimmed = json.trim()
            if (trimmed.startsWith("{")) {
                val root = JSONObject(trimmed)
                arr = root.optJSONArray("targets") ?: JSONArray()
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
                val devId = dto.optString("deviceId")
                if (kind.isBlank() || devId.isBlank()) continue
                _events.add(WakeEvent(dto.optLong("atMs"), kind, devId,
                    if (dto.isNull("actorUserId")) null else dto.optString("actorUserId"),
                    dto.optString("detail")))
            }
        }
        var restored = 0
        for (i in 0 until arr.length()) {
            val dto = arr.optJSONObject(i) ?: continue
            val deviceId = dto.optString("deviceId")
            if (deviceId.isBlank()) continue
            val device = device(deviceId) ?: continue
            if (device.revoked) continue
            if (targets.containsKey(device.deviceId)) continue
            val mac = MagicPacket.parseMac(dto.optString("macAddress")) ?: continue
            if (!MagicPacket.isWakeableMac(mac)) continue
            val broadcast = dto.optString("broadcastAddress")
            if (!isIpv4(broadcast)) continue
            targets[device.deviceId] = WakeTarget(
                device.deviceId, MagicPacket.normalizeMac(mac), broadcast.trim(),
                dto.optString("registeredByUserId").takeIf { !dto.isNull("registeredByUserId") },
                dto.optLong("registeredUtcMs"),
                if (dto.isNull("lastWakeUtcMs")) null else dto.optLong("lastWakeUtcMs"))
            restored++
        }
        return restored
    }

    companion object {
        /** Dotted-quad IPv4 only (the broadcast address of a LAN
         *  segment — IPv6 has no broadcast and no WoL form here). */
        fun isIpv4(text: String?): Boolean {
            val parts = (text ?: return false).trim().split('.')
            if (parts.size != 4) return false
            return parts.all { p ->
                p.isNotEmpty() && p.length <= 3 && p.all { it.isDigit() } &&
                    (p.toIntOrNull() ?: 256) in 0..255
            }
        }
    }
}
