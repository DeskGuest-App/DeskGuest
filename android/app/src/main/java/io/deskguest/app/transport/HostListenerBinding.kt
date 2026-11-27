package io.deskguest.app.transport

import io.deskguest.app.enrollment.EnrollmentStore
import io.deskguest.app.session.SessionStore
import java.net.InetAddress
import java.util.UUID

/**
 * Host-listener production binding (W4, closing the bd-and-remote
 * F5 remainder): what [LanHostListener] hands an authenticated
 * channel to once the v2 handshake + AEAD channel are up, and the
 * lifecycle owner that starts/stops the listener with the control
 * channel (ControlService).
 *
 * Wire protocol over the AEAD channel (line-based, like the bare
 * listener's PING/PONG shape it extends):
 *   PING                                  -> PONG
 *   ENROLL <code> <deviceId> <keyB64> <display name...>
 *       -> ENROLLED <deviceId> <scope> <groupId> <enrollerId|-> <enrollerKeyB64|-> <sas|->
 *       -> REFUSED enroll_rejected
 *   SESSION <scopeId> <initiator> <hostUser> <kind> [recording]
 *       -> PENDING <sessionId>   (consent pending — see below)
 *       -> REFUSED session_refused
 *   STATUS                                -> STATE <state>
 *   STOP <actorUserId>                    -> STOPPED | REFUSED stop_refused
 *   STOPLOCAL                             -> REFUSED stoplocal_removed
 *       (W14 P3-F14b: the verb is REMOVED — a channel peer holds no
 *       local-stop verb. It is refused by name, the session is NOT
 *       stopped, and the channel stays open. The on-device local
 *       STOP — SessionStore.stopLocalSession via the endpoint's own
 *       UI — is not a wire verb and is unchanged.)
 *   anything else                         -> ERR unknown
 *
 * Consent law (endpoint-local acceptance, RULING 2026-11-19):
 * a network accept NEVER self-accepts. A SESSION verb creates the
 * SessionStore record in `requested` and nothing more — the record
 * leaves `requested` only through the endpoint's own local UI
 * (PlatformStores.acceptLocal, the Sessions screen) and the store's
 * start gates. This binding holds NO accept path: there is no verb
 * for it, and the channel serves no drive capability at all — only
 * PING / STATUS / STOP — so presence attaching (below) can never
 * be preceded by a capability on this channel.
 *
 * Presence: [presenceAttach] fires the moment a session record
 * exists (BEFORE the PENDING reply is written, so presence is up
 * before the peer learns the session id), and [presenceDetach]
 * fires exactly once when the binding ends that session's channel,
 * whatever the exit path. ControlService wires these to the
 * presence/session-event layer; the JVM suite wires recorders.
 *
 * Identity: the peer's DEVICE is proven by the v2 handshake (the
 * listener only calls [serve] with a proven, enrolled device id).
 * The SESSION verb's user ids are roster claims, validated by the
 * SessionStore itself at creation (both users must be live members
 * of the scope, the host a human, this device a group member, the
 * rung in its effective transports, unattended initiators holding
 * `use`) — a lying claim creates nothing.
 *
 * ENROLL rides the existing EnrollmentStore (single-use codes,
 * burn counter, DeviceId<->key binding, SAS via the U9 response) —
 * [EnrollmentStore.redeemWithResponse]. A replayed code is refused
 * by the store (the code is consumed by the first redeem) and the
 * reply names it; nothing here mints a second path around it.
 */
class HostSessionBinding(
    private val sessions: SessionStore,
    private val enrollment: EnrollmentStore,
    private val ownDeviceId: () -> String,
    private val enrollerName: () -> String = { "" },
    private val presenceAttach: (sessionId: String, peerDeviceId: String) -> Unit = { _, _ -> },
    private val presenceDetach: (sessionId: String) -> Unit = {},
    private val idFactory: () -> String = { "hs-" + UUID.randomUUID().toString().replace("-", "").take(16) }
) {

    /** Serve one authenticated channel until it closes or its
     *  session ends. Called by the listener on its own thread. */
    fun serve(peerDeviceId: String, channel: SocketStreams) {
        while (true) {
            val line = LanProtocol.readLine(channel.input) ?: return
            when {
                line == "PING" -> LanProtocol.writeLine(channel.output, "PONG")
                line.startsWith("ENROLL ") -> serveEnroll(line, channel)
                line.startsWith("SESSION ") -> {
                    serveSession(peerDeviceId, line, channel)
                    return
                }
                else -> LanProtocol.writeLine(channel.output, "ERR unknown")
            }
        }
    }

    private fun serveEnroll(line: String, channel: SocketStreams) {
        val parts = line.split(' ')
        // ENROLL <code> <deviceId> <keyB64> <display name...>
        if (parts.size < 5) {
            LanProtocol.writeLine(channel.output, "REFUSED enroll_malformed")
            return
        }
        val displayName = parts.drop(4).joinToString(" ")
        val (enrolled, response) = enrollment.redeemWithResponse(
            parts[1],
            EnrollmentStore.EnrollingDevice(parts[2], parts[3], displayName),
            enrollerName()
        )
        if (enrolled == null || response == null) {
            // Single-use: a replayed (or wrong/expired/burned) code
            // lands here — the store consumed the real one already.
            LanProtocol.writeLine(channel.output, "REFUSED enroll_rejected")
            return
        }
        val enrollerId = response.enrollerDeviceId.ifBlank { "-" }
        val enrollerKey = response.enrollerPublicKeyBase64 ?: "-"
        val sas = enrollment.byId(enrolled.deviceId)?.sas?.ifBlank { "-" } ?: "-"
        LanProtocol.writeLine(channel.output,
            "ENROLLED ${enrolled.deviceId} ${enrolled.scope} ${enrolled.groupId} $enrollerId $enrollerKey $sas")
    }

    private fun serveSession(peerDeviceId: String, line: String, channel: SocketStreams) {
        val parts = line.split(' ')
        // SESSION <scopeId> <initiatorUserId> <hostUserId> <kind> [recording]
        if (parts.size < 5) {
            LanProtocol.writeLine(channel.output, "REFUSED session_malformed")
            return
        }
        val scopeId = parts[1]
        val initiatorUserId = parts[2]
        val hostUserId = parts[3]
        val kind = parts[4]
        val recording = parts.getOrNull(5) ?: SessionStore.RECORDING_NONE
        // W14 P3-F2 (W13-P3-F2 spec): when the handshake-proven peer
        // device carries an ownerUserId, the SESSION initiator must
        // BE that owner — a peer presenting for another user is
        // refused before any record is created. An unbound (empty)
        // owner — every legacy record — imposes no check here; the
        // SessionStore's own scope/member validation still applies.
        val boundOwner = enrollment.byId(peerDeviceId)?.ownerUserId?.trim().orEmpty()
        if (boundOwner.isNotEmpty() && boundOwner != initiatorUserId) {
            LanProtocol.writeLine(channel.output, "REFUSED owner_mismatch")
            return
        }
        val sessionId = idFactory()
        val created = sessions.createSession(
            SessionStore.Session(
                id = sessionId, scopeId = scopeId, hostDeviceId = ownDeviceId(),
                initiatorUserId = initiatorUserId, kind = kind,
                transportRung = "lan", recording = recording
            ), hostUserId
        )
        if (!created) {
            LanProtocol.writeLine(channel.output, "REFUSED session_refused")
            return
        }
        try {
            // Presence BEFORE the peer learns the session id, and
            // before any capability could exist on this channel.
            // W13 P3-F16: the attach is INSIDE the try — previously
            // it sat before it, so a throwing attach (or a failed
            // PENDING write path that bypassed the block) leaked
            // the session record with no detach/end behind it.
            presenceAttach(sessionId, peerDeviceId)
            LanProtocol.writeLine(channel.output, "PENDING $sessionId")
            sessionLoop(sessionId, hostUserId, channel)
        } finally {
            // Whatever ended the loop — STOP, peer vanishing, the
            // session ending locally — the record must not outlive
            // its channel: end it (host actor; from `blocked` the
            // local STOP path is the one that always works), then
            // drop presence exactly once.
            val state = sessions.session(sessionId)?.state
            if (state != null && state != SessionStore.STATE_ENDED) {
                if (!sessions.endSession(sessionId, hostUserId)) {
                    sessions.stopLocalSession(sessionId)
                }
            }
            presenceDetach(sessionId)
        }
    }

    private fun sessionLoop(sessionId: String, hostUserId: String, channel: SocketStreams) {
        while (true) {
            // W13 P3-F17: the store state is checked EVERY turn,
            // not only when the peer asks STATUS — a session ended
            // locally (owner STOP, offboarding) closes its channel
            // promptly instead of serving PINGs for a dead record.
            val liveState = sessions.session(sessionId)?.state
            if (liveState == null || liveState == SessionStore.STATE_ENDED) return
            val line = LanProtocol.readLine(channel.input) ?: return
            when {
                line == "PING" -> LanProtocol.writeLine(channel.output, "PONG")
                line == "STATUS" -> {
                    val state = sessions.session(sessionId)?.state ?: SessionStore.STATE_ENDED
                    LanProtocol.writeLine(channel.output, "STATE $state")
                    if (state == SessionStore.STATE_ENDED) return
                }
                line == "STOPLOCAL" -> {
                    // W14 P3-F14b: verb REMOVED in this protocol
                    // revision — refused by name, session NOT
                    // stopped, channel stays open. A peer must use
                    // STOP <hostUserId> (host-gated) or the person
                    // at the device uses the on-device STOP.
                    LanProtocol.writeLine(channel.output, "REFUSED stoplocal_removed")
                }
                line.startsWith("STOP ") -> {
                    val actor = line.substring(5).trim()
                    // W13 P3-F14: the STOP actor must be THIS
                    // session's host user — a wire-supplied stranger
                    // id no longer stops a session it does not host.
                    // (W14 P3-F14b removed the STOPLOCAL verb above.)
                    val ok = actor.isNotEmpty() && actor == hostUserId && sessions.stopSession(sessionId, actor)
                    LanProtocol.writeLine(channel.output, if (ok) "STOPPED" else "REFUSED stop_refused")
                    if (ok) return
                }
                else -> LanProtocol.writeLine(channel.output, "ERR unknown")
            }
        }
    }
}

/**
 * Lifecycle owner for the production host listener: ControlService
 * starts it with the control channel and stops it on destroy. The
 * bind address is the caller's explicit choice (the listener itself
 * refuses a wildcard bind by name) — ControlService passes the
 * tailnet address, the same posture as the MCP server's bind set.
 */
class HostListenerService(
    private val binding: HostSessionBinding,
    private val enrollments: EnrollmentStore,
    private val hostIdentity: io.deskguest.app.enrollment.DeviceIdentity
) {
    private var listener: LanHostListener? = null

    @Volatile
    var isRunning: Boolean = false
        private set

    @Synchronized
    fun start(bindAddress: InetAddress, port: Int = LanProtocol.DEFAULT_PORT): Boolean {
        if (listener != null) return true
        val created = LanHostListener(enrollments, hostIdentity) { peer, channel ->
            binding.serve(peer, channel)
        }
        return try {
            created.start(bindAddress, port)
            listener = created
            isRunning = true
            true
        } catch (e: Exception) {
            false
        }
    }

    @Synchronized
    fun stop() {
        listener?.stop()
        listener = null
        isRunning = false
    }

    /** The bound port while running (0 when the OS picked one). */
    val port: Int get() = listener?.port ?: 0
    val acceptedSessions: Int get() = listener?.acceptedSessions ?: 0
    val refusedHandshakes: Int get() = listener?.refusedHandshakes ?: 0
}
