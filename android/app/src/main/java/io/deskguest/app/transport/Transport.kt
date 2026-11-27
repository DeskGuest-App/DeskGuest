package io.deskguest.app.transport

import io.deskguest.app.enrollment.DeviceIdentity
import io.deskguest.app.enrollment.EnrollmentStore
import io.deskguest.app.roster.RosterStore
import io.deskguest.app.session.SessionStore
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import java.util.UUID

/**
 * Block C transport core — Android half, shared semantics with the
 * Windows DeskGuest.Shared.Transport layer (D19/D20/D29/D31/D32).
 *
 * - The `lan` rung carries DeskGuest's own session protocol over a direct
 *   socket, authenticated by proof of possession of the Slice 1
 *   device key (challenge → sign → verify against the enrolled
 *   public key). There is no unauthenticated mode.
 * - Connect-by-address rides the same `lan` rung with a hand-entered
 *   address (D19: the fallback when discovery cannot see across
 *   segments).
 * - The failover engine is rung-agnostic: it walks the group's
 *   ordered set as resolved by Slice 2, and hub/mesh/ipv6/ownpath/
 *   tor plug in behind [TransportRung] without engine changes.
 *   Non-primary rungs stay dormant (no listeners, no traffic) until
 *   the engine walks to them. A dead rung's session ENDS and a new
 *   session re-establishes on the next rung — a reconnect, linked
 *   by events, never a pretend-seamless stream.
 * - Local discovery announces ONLY a hash of the device id, a
 *   display name, and an enrollment state (D19/D20). It is not a
 *   network scan, and it grants no trust: a discovered device is
 *   never controllable from discovery.
 */

data class TransportTarget(val deviceId: String, val address: String? = null)

data class TransportConnectResult(
    val ok: Boolean, val detail: String, val stream: SocketStreams? = null,
    /** W13 P3-F3: the host device id the v2 handshake PROVED (null
     *  for test doubles / non-authenticated rungs). The session
     *  manager refuses to stamp a session with a caller-claimed
     *  host id that differs from the proven one. */
    val provenDeviceId: String? = null
)

/** A connected, authenticated channel (the socket-free shape lets
 *  the JVM suite drive the protocol over in-memory pipes). */
class SocketStreams(val input: InputStream, val output: OutputStream, private val closer: () -> Unit = {}) {
    fun close() { try { closer() } catch (_: Exception) {} }
}

interface TransportRung {
    val id: String
    val isDormant: Boolean get() = connectAttempts == 0
    val connectAttempts: Int
    fun connect(target: TransportTarget): TransportConnectResult
}

/** A rung whose session connects are authenticated by the local
 *  device identity's proof of possession (the LanProtocol v2
 *  handshake). The engine dispatches session connects to
 *  [connectSession] for these rungs — lan, hub and mesh all ride
 *  the same admission: an enrolled key, or no session. The
 *  enrollment store is a required input: the client verifies the
 *  HOST against its enrolled key before signing anything, so a
 *  rung without the store cannot run the handshake at all. */
interface AuthenticatedRung : TransportRung {
    fun connectSession(target: TransportTarget, identity: DeviceIdentity, enrollments: EnrollmentStore?): TransportConnectResult
}

/** The DeskGuest session protocol over a direct socket (the `lan` rung),
 *  wire protocol v2 (bd-and-remote F1 fix, 2026-11-22 — the Android
 *  parity implementation of the Windows DeskGuest.Shared v2, whose lane
 *  left this as the named remainder). The v1 handshake was one-way
 *  and relayable: only the client signed, the signature covered
 *  only Domain|deviceId|nonce, and the stream afterwards was
 *  plaintext — a spoofed host could relay a real host's challenge,
 *  harvest the client's signature, and replay it to the real host.
 *  V2 is mutually authenticated and encrypted, byte-for-byte the
 *  Windows form:
 *   1. Host → CHAL2: host nonce, host DeviceId, host ephemeral
 *      X25519 key, host Ed25519 signature over all three. The
 *      client verifies it against the host's ENROLLED key and the
 *      expected host DeviceId before signing anything.
 *   2. Client → HELLO2: client nonce, client ephemeral key, and
 *      the client's signature over the FULL transcript (both ids,
 *      both nonces, both ephemeral keys).
 *   3. Host → OK2: the host's signature over the transcript hash.
 *   4. Both sides derive per-direction AES-256-GCM keys via
 *      HKDF-SHA256 from the X25519 shared secret + transcript
 *      hash; all later traffic travels in AEAD frames
 *      ([LanSecureChannel]).
 *  There is no unauthenticated or plaintext mode. */
object LanProtocol {
    const val DOMAIN = "deskguest-transport-v1"
    const val DOMAIN_V2 = "deskguest-transport-v2"
    const val DEFAULT_PORT = 47621
    const val MAX_LINE_BYTES = 8192

    /** Legacy v1 proof message — retained ONLY so pre-v2 history
     *  can be read. No product code signs or verifies it any more. */
    fun proofMessage(deviceId: String, nonceBase64: String): ByteArray =
        "$DOMAIN|$deviceId|$nonceBase64".toByteArray(Charsets.UTF_8)

    fun hostProofMessage(hostDeviceId: String, hostNonceBase64: String, hostEphemeralBase64: String): ByteArray =
        "$DOMAIN_V2|host|$hostDeviceId|$hostNonceBase64|$hostEphemeralBase64".toByteArray(Charsets.UTF_8)

    fun clientProofMessage(clientDeviceId: String, hostDeviceId: String, hostNonceBase64: String,
                           clientNonceBase64: String, hostEphemeralBase64: String, clientEphemeralBase64: String): ByteArray =
        "$DOMAIN_V2|client|$clientDeviceId|$hostDeviceId|$hostNonceBase64|$clientNonceBase64|$hostEphemeralBase64|$clientEphemeralBase64"
            .toByteArray(Charsets.UTF_8)

    fun confirmMessage(transcriptHashHex: String): ByteArray =
        "$DOMAIN_V2|confirm|$transcriptHashHex".toByteArray(Charsets.UTF_8)

    fun transcriptHash(hostDeviceId: String, hostNonce: String, hostEphB64: String,
                       clientDeviceId: String, clientNonce: String, clientEphB64: String): String =
        MessageDigest.getInstance("SHA-256").digest(
            "$DOMAIN_V2|transcript|$hostDeviceId|$hostNonce|$hostEphB64|$clientDeviceId|$clientNonce|$clientEphB64"
                .toByteArray(Charsets.UTF_8)
        ).joinToString("") { "%02x".format(it) }

    fun readLine(input: InputStream): String? {
        // bd-and-remote F8 fix: bytes accumulate in a
        // ByteArrayOutputStream, not a MutableList<Byte> (which
        // boxed every byte of every line).
        val buffer = java.io.ByteArrayOutputStream()
        while (buffer.size() <= MAX_LINE_BYTES) {
            val b = input.read()
            if (b < 0) return if (buffer.size() == 0) null else buffer.toByteArray().toString(Charsets.UTF_8)
            if (b == '\n'.code) return buffer.toByteArray().toString(Charsets.UTF_8).trimEnd('\r')
            buffer.write(b)
        }
        return null // over-long line: fail closed
    }

    fun writeLine(output: OutputStream, line: String) {
        output.write((line + "\n").toByteArray(Charsets.UTF_8))
        output.flush()
    }

    /** Why a client handshake ended (CONV-F3 diagnostic honesty,
     *  mirrored): a peer that never issued an DeskGuest challenge is NOT
     *  a host refusing our proof. */
    enum class ClientOutcome { CONNECTED, HOST_REFUSED, NO_CHALLENGE, HOST_AUTH_FAILED }

    data class ClientResult(val outcome: ClientOutcome, val channel: SocketStreams? = null, val provenHostDeviceId: String? = null)

    private fun b64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)
    private fun unb64(text: String): ByteArray? = try { Base64.getDecoder().decode(text) } catch (_: Exception) { null }

    private fun hexBytes(hex: String): ByteArray =
        ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    private fun deriveChannel(streams: SocketStreams, ownEphScalar: ByteArray, peerEph: ByteArray,
                              transcriptHashHex: String, isHost: Boolean): SocketStreams? {
        val shared = WireGuardConfigGenerator.x25519(ownEphScalar, peerEph)
        if (shared.all { it == 0.toByte() }) return null // contributory check: refuse a null shared secret
        val okm = io.deskguest.app.adb.Hkdf.sha256(
            shared, hexBytes(transcriptHashHex), "$DOMAIN_V2|session-keys".toByteArray(Charsets.UTF_8), 64)
        val sendKey = if (isHost) okm.copyOfRange(32, 64) else okm.copyOfRange(0, 32)
        val receiveKey = if (isHost) okm.copyOfRange(0, 32) else okm.copyOfRange(32, 64)
        // W12-DS P3-F8: the secure wrapper carries the RAW
        // streams' closer — closing the channel closes the socket.
        return LanSecureChannel(streams.input, streams.output, sendKey, receiveKey) { streams.close() }.streams
    }

    /** Client half of v2: verify the host FIRST (enrolled key +
     *  expected DeviceId), then sign the full transcript and
     *  derive the AEAD channel. The client never signs for a host
     *  it has not authenticated — the v1 relay is dead by
     *  construction. */
    fun clientHandshakeDetailed(streams: SocketStreams, identity: DeviceIdentity,
                                enrollments: EnrollmentStore, expectedHostDeviceId: String?): ClientResult {
        val challenge = readLine(streams.input) ?: return ClientResult(ClientOutcome.NO_CHALLENGE)
        if (!challenge.startsWith("CHAL2 ")) return ClientResult(ClientOutcome.NO_CHALLENGE)
        val parts = challenge.split(' ')
        if (parts.size != 5) return ClientResult(ClientOutcome.NO_CHALLENGE)
        val hostNonce = parts[1]; val hostDeviceId = parts[2]; val hostEphB64 = parts[3]; val hostSigB64 = parts[4]
        if (hostNonce.length < 16 || hostNonce.length > 128) return ClientResult(ClientOutcome.NO_CHALLENGE)
        if (!expectedHostDeviceId.isNullOrBlank() && !expectedHostDeviceId.equals(hostDeviceId, ignoreCase = true))
            return ClientResult(ClientOutcome.HOST_AUTH_FAILED)
        val hostEph = unb64(hostEphB64) ?: return ClientResult(ClientOutcome.HOST_AUTH_FAILED)
        if (hostEph.size != 32) return ClientResult(ClientOutcome.HOST_AUTH_FAILED)
        val hostSig = unb64(hostSigB64) ?: return ClientResult(ClientOutcome.HOST_AUTH_FAILED)
        if (!enrollments.verifyEnrolledSignature(hostDeviceId, hostProofMessage(hostDeviceId, hostNonce, hostEphB64), hostSig))
            return ClientResult(ClientOutcome.HOST_AUTH_FAILED)

        val random = SecureRandom()
        val clientNonce = b64(ByteArray(32).also { random.nextBytes(it) })
        val clientEphScalar = ByteArray(32).also { random.nextBytes(it) }
        val base = ByteArray(32); base[0] = 9
        val clientEphB64 = b64(WireGuardConfigGenerator.x25519(clientEphScalar, base))
        val clientSig = identity.sign(clientProofMessage(
            identity.deviceId, hostDeviceId, hostNonce, clientNonce, hostEphB64, clientEphB64))
        writeLine(streams.output, "HELLO2 ${identity.deviceId} $clientNonce $clientEphB64 ${b64(clientSig)}")
        val verdict = readLine(streams.input)
        if (verdict == null || !verdict.startsWith("OK2 ")) return ClientResult(ClientOutcome.HOST_REFUSED)
        val transcript = transcriptHash(hostDeviceId, hostNonce, hostEphB64, identity.deviceId, clientNonce, clientEphB64)
        val confirmSig = unb64(verdict.substring(4).trim()) ?: return ClientResult(ClientOutcome.HOST_AUTH_FAILED)
        if (!enrollments.verifyEnrolledSignature(hostDeviceId, confirmMessage(transcript), confirmSig))
            return ClientResult(ClientOutcome.HOST_AUTH_FAILED)
        val channel = deriveChannel(streams, clientEphScalar, hostEph, transcript, isHost = false)
            ?: return ClientResult(ClientOutcome.HOST_AUTH_FAILED)
        return ClientResult(ClientOutcome.CONNECTED, channel, hostDeviceId)
    }

    /** Bool convenience over the detailed client handshake. NOTE:
     *  on success the AEAD channel is DISCARDED — session callers
     *  use [clientHandshakeDetailed] and keep the channel. */
    fun clientHandshake(streams: SocketStreams, identity: DeviceIdentity,
                        enrollments: EnrollmentStore, expectedHostDeviceId: String? = null): Boolean =
        clientHandshakeDetailed(streams, identity, enrollments, expectedHostDeviceId).outcome == ClientOutcome.CONNECTED

    /** Host half of v2: prove OUR identity first (the host signs
     *  its challenge with its own device key), then verify the
     *  client's transcript-bound proof against the enrolled key.
     *  Returns (proven device id, AEAD channel), or null —
     *  unauthenticated, unknown, revoked, spoofed and relaying
     *  peers all land there. */
    fun hostHandshake(streams: SocketStreams, enrollments: EnrollmentStore,
                      hostIdentity: DeviceIdentity): Pair<String, SocketStreams>? {
        val random = SecureRandom()
        val hostNonce = b64(ByteArray(32).also { random.nextBytes(it) })
        val hostEphScalar = ByteArray(32).also { random.nextBytes(it) }
        val base = ByteArray(32); base[0] = 9
        val hostEphB64 = b64(WireGuardConfigGenerator.x25519(hostEphScalar, base))
        val hostSig = hostIdentity.sign(hostProofMessage(hostIdentity.deviceId, hostNonce, hostEphB64))
        writeLine(streams.output, "CHAL2 $hostNonce ${hostIdentity.deviceId} $hostEphB64 ${b64(hostSig)}")
        val hello = readLine(streams.input) ?: return null
        val parts = hello.split(' ')
        if (parts.size != 5 || parts[0] != "HELLO2") { refuse(streams); return null }
        val deviceId = parts[1]; val clientNonce = parts[2]; val clientEphB64 = parts[3]
        val clientEph = unb64(clientEphB64) ?: run { refuse(streams); return null }
        if (clientEph.size != 32) { refuse(streams); return null }
        val clientSig = unb64(parts[4]) ?: run { refuse(streams); return null }
        if (!enrollments.verifyEnrolledSignature(deviceId,
                clientProofMessage(deviceId, hostIdentity.deviceId, hostNonce, clientNonce, hostEphB64, clientEphB64),
                clientSig)) { refuse(streams); return null }
        val transcript = transcriptHash(hostIdentity.deviceId, hostNonce, hostEphB64, deviceId, clientNonce, clientEphB64)
        val channel = deriveChannel(streams, hostEphScalar, clientEph, transcript, isHost = true)
            ?: run { refuse(streams); return null }
        val confirmSig = hostIdentity.sign(confirmMessage(transcript))
        writeLine(streams.output, "OK2 ${b64(confirmSig)}")
        val device = enrollments.byId(deviceId)
        return (device?.deviceId ?: deviceId) to channel
    }

    private fun refuse(streams: SocketStreams) {
        try { writeLine(streams.output, "REFUSE") } catch (_: Exception) { /* peer already gone */ }
    }
}

/** The AEAD session channel (bd-and-remote F1): AES-256-GCM frames
 *  over the raw stream, byte-identical to the Windows
 *  LanSecureChannel. Wire shape per frame: [4-byte big-endian
 *  ciphertext length][12-byte nonce][ciphertext + 16-byte tag].
 *  Nonces are counter-based per direction (sequence as a
 *  little-endian int64 in nonce bytes 4..11, matching the Windows
 *  BitConverter layout); each frame's AAD is its own sequence
 *  number, so reordered, replayed or truncated frames fail
 *  authentication and kill the channel. Writes buffer until flush
 *  (one frame per flush, chunked at 64 KiB); a tampered frame
 *  throws on read — never indistinguishable from a polite close. */
class LanSecureChannel(
    private val innerIn: InputStream,
    private val innerOut: OutputStream,
    private val sendKey: ByteArray,
    private val receiveKey: ByteArray,
    // W12-DS P3-F8: underlying closer (the raw socket's), invoked
    // when the secure streams close — was `{ }`, leaking sockets.
    private val onClose: () -> Unit = {}
) {
    private var sendSeq = 0L
    private var receiveSeq = 0L
    private val writeBuffer = java.io.ByteArrayOutputStream()
    private var readPlain = ByteArray(0)
    private var readPos = 0
    @Volatile private var dead = false

    val streams: SocketStreams = SocketStreams(secureInput(), secureOutput()) {
        try { innerOut.flush() } catch (_: Exception) {}
        onClose()
    }

    private fun nonceFor(seq: Long): ByteArray {
        val nonce = ByteArray(12)
        for (i in 0 until 8) nonce[4 + i] = (seq shr (8 * i)).toByte()
        return nonce
    }

    private fun aadFor(seq: Long): ByteArray = "deskguest-transport-v2|frame|$seq".toByteArray(Charsets.UTF_8)

    private fun secureOutput(): OutputStream = object : OutputStream() {
        override fun write(b: Int) { writeBuffer.write(b) }
        override fun write(b: ByteArray, off: Int, len: Int) { writeBuffer.write(b, off, len) }
        override fun flush() {
            if (dead) throw java.io.IOException("secure channel is dead (authentication failure or close)")
            if (writeBuffer.size() == 0) return
            val plain = writeBuffer.toByteArray(); writeBuffer.reset()
            var at = 0
            while (at < plain.size) {
                val chunk = plain.copyOfRange(at, minOf(at + MAX_FRAME_PLAINTEXT, plain.size))
                val seq = ++sendSeq
                val nonce = nonceFor(seq)
                val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(javax.crypto.Cipher.ENCRYPT_MODE,
                    javax.crypto.spec.SecretKeySpec(sendKey, "AES"),
                    javax.crypto.spec.GCMParameterSpec(128, nonce))
                cipher.updateAAD(aadFor(seq))
                val sealed = cipher.doFinal(chunk) // ciphertext || tag
                val header = ByteArray(4)
                val len = sealed.size
                header[0] = (len shr 24).toByte(); header[1] = (len shr 16).toByte()
                header[2] = (len shr 8).toByte(); header[3] = len.toByte()
                innerOut.write(header); innerOut.write(nonce); innerOut.write(sealed)
                at += chunk.size
            }
            innerOut.flush()
        }
        override fun close() { try { flush() } catch (_: Exception) {} }
    }

    private fun secureInput(): InputStream = object : InputStream() {
        override fun read(): Int {
            val one = ByteArray(1)
            val n = read(one, 0, 1)
            return if (n < 0) -1 else one[0].toInt() and 0xFF
        }
        override fun read(b: ByteArray, off: Int, len: Int): Int {
            if (dead) throw java.io.IOException("secure channel authentication failure: the channel is dead")
            if (len == 0) return 0
            if (readPos >= readPlain.size && !fill()) return -1
            val n = minOf(len, readPlain.size - readPos)
            System.arraycopy(readPlain, readPos, b, off, n)
            readPos += n
            return n
        }
    }

    /** False ONLY for a clean EOF exactly at a frame boundary. */
    private fun fill(): Boolean {
        val header = ByteArray(4)
        val headerRead = readUpTo(header)
        if (headerRead == 0) return false
        if (headerRead < 4) throw deadError("partial frame header — the channel is dead")
        val len = ((header[0].toInt() and 0xFF) shl 24) or ((header[1].toInt() and 0xFF) shl 16) or
            ((header[2].toInt() and 0xFF) shl 8) or (header[3].toInt() and 0xFF)
        // W12-DS P3-F19: len == 16 is an EMPTY plaintext frame —
        // it would make read() return 0 for len > 0, violating
        // the InputStream contract. Reject it as a dead channel.
        if (len <= 16 || len > MAX_FRAME_PLAINTEXT + 16)
            throw deadError("frame length $len is impossible — the channel is dead")
        val rest = ByteArray(12 + len)
        if (readUpTo(rest) < rest.size) throw deadError("frame truncated mid-body — the channel is dead")
        val seq = ++receiveSeq
        val nonce = rest.copyOfRange(0, 12)
        if (!nonce.contentEquals(nonceFor(seq)))
            throw deadError("frame nonce out of sequence (replay or reorder) — the channel is dead")
        val sealed = rest.copyOfRange(12, rest.size)
        val plain = try {
            val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(javax.crypto.Cipher.DECRYPT_MODE,
                javax.crypto.spec.SecretKeySpec(receiveKey, "AES"),
                javax.crypto.spec.GCMParameterSpec(128, nonce))
            cipher.updateAAD(aadFor(seq))
            cipher.doFinal(sealed)
        } catch (e: Exception) {
            throw deadError("frame authentication tag did not verify — the channel is dead")
        }
        readPlain = plain; readPos = 0
        return true
    }

    private fun deadError(why: String): java.io.IOException {
        dead = true
        return java.io.IOException("secure channel authentication failure: $why")
    }

    private fun readUpTo(buffer: ByteArray): Int {
        var read = 0
        while (read < buffer.size) {
            val n = innerIn.read(buffer, read, buffer.size - read)
            if (n < 0) break
            read += n
        }
        return read
    }

    companion object { const val MAX_FRAME_PLAINTEXT = 64 * 1024 }
}

/** The `lan` rung: direct TCP, [LanProtocol] over it. */
class LanRung : AuthenticatedRung {
    override val id: String = "lan"
    override var connectAttempts: Int = 0
        private set

    // W12-DS P3-F1 fix (BLOCKER): the old body stamped the target
    // with the LOCAL device id, so connectCore's expected-host
    // check (target != identity) always nulled out and ANY enrolled
    // device answering the hand-entered address was accepted as
    // the host — the MITM substitution the v2 handshake exists to
    // refuse. A bare address carries no expected-host identity, so
    // this entry point now refuses outright; callers must use
    // connectSession with a target whose deviceId is the intended
    // host's enrolled id.
    fun connectByAddress(address: String, identity: DeviceIdentity, enrollments: EnrollmentStore?): TransportConnectResult =
        TransportConnectResult(false, "lan: a hand-entered address alone cannot prove which host should answer — connect by the host's enrolled device id (connectSession), never by address alone")

    override fun connectSession(target: TransportTarget, identity: DeviceIdentity, enrollments: EnrollmentStore?): TransportConnectResult =
        connectCore(target, identity, enrollments)

    override fun connect(target: TransportTarget): TransportConnectResult =
        TransportConnectResult(false, "lan: a session connect requires the local device identity (connectSession)")

    private fun connectCore(target: TransportTarget, identity: DeviceIdentity, enrollments: EnrollmentStore?): TransportConnectResult {
        connectAttempts++
        if (enrollments == null)
            return TransportConnectResult(false, "lan: no enrollment store wired — the v2 handshake verifies the host against its enrolled key, so there is nothing to connect with")
        val address = target.address?.trim().orEmpty()
        if (address.isEmpty()) return TransportConnectResult(false, "lan: no address (not discovered, none entered)")
        val (host, port) = parseAddress(address) ?: return TransportConnectResult(false, "lan: bad address '$address'")
        val socket = Socket()
        return try {
            socket.connect(InetSocketAddress(host, port), 5000)
            // W13 P3-F5: the handshake runs under a socket deadline
            // (a peer that never speaks cannot hold this connect
            // forever); the deadline clears once the AEAD channel
            // is up, mirroring the host side.
            socket.soTimeout = LanHostListener.HANDSHAKE_TIMEOUT_MS
            val streams = SocketStreams(socket.getInputStream(), socket.getOutputStream()) { socket.close() }
            val expected = target.deviceId.takeIf { !it.equals(identity.deviceId, ignoreCase = true) }
            val result = LanProtocol.clientHandshakeDetailed(streams, identity, enrollments, expected)
            if (result.outcome == LanProtocol.ClientOutcome.CONNECTED) {
                try { socket.soTimeout = 0 } catch (_: Exception) { }
            }
            when (result.outcome) {
                LanProtocol.ClientOutcome.CONNECTED ->
                    TransportConnectResult(true, "lan: connected to $host:$port (mutually authenticated, AEAD channel)", result.channel, result.provenHostDeviceId)
                LanProtocol.ClientOutcome.HOST_REFUSED -> {
                    socket.close(); TransportConnectResult(false, "lan: host refused our proof of possession")
                }
                LanProtocol.ClientOutcome.NO_CHALLENGE -> {
                    socket.close(); TransportConnectResult(false, "lan: no DeskGuest challenge received — the peer did not speak the DeskGuest protocol")
                }
                LanProtocol.ClientOutcome.HOST_AUTH_FAILED -> {
                    socket.close(); TransportConnectResult(false, "lan: the peer claimed to be a host but could not prove it (unknown/revoked enrollment, wrong device, or bad signature) — nothing was signed for it")
                }
            }
        } catch (e: Exception) {
            try { socket.close() } catch (_: Exception) {}
            TransportConnectResult(false, "lan: ${e.javaClass.simpleName}")
        }
    }

    companion object {
        /** One shared endpoint parser (bd-and-remote F10 fix):
         *  "[v6]:port" strips the brackets; a BARE IPv6 literal
         *  (two or more colons) is a host with the default port —
         *  never split at its last colon; "host:port" and bare
         *  "host" keep the v1 shapes. */
        fun parseAddress(address: String): Pair<String, Int>? {
            val a = address.trim()
            if (a.isEmpty()) return null
            if (a.startsWith("[")) {
                val close = a.indexOf(']')
                if (close <= 1) return null
                val host = a.substring(1, close)
                val rest = a.substring(close + 1)
                if (rest.isEmpty()) return host to LanProtocol.DEFAULT_PORT
                if (!rest.startsWith(":")) return null
                val port = rest.substring(1).toIntOrNull() ?: return null
                if (port !in 1..65535) return null
                return host to port
            }
            if (a.count { it == ':' } >= 2) return a to LanProtocol.DEFAULT_PORT // bare IPv6 literal
            val idx = a.lastIndexOf(':')
            if (idx > 0) {
                val port = a.substring(idx + 1).toIntOrNull() ?: return null
                if (port !in 1..65535) return null
                return a.substring(0, idx) to port
            }
            return a to LanProtocol.DEFAULT_PORT
        }
    }
}

/** Host side of the `lan` rung. NOT listening until [start] —
 *  a configured-but-dormant rung has no listener (D29).
 *
 *  bd-and-remote F5/F8 fixes (2026-11-22): the handshake is v2 and
 *  needs THIS device's identity (the host proves itself first) —
 *  with no host identity wired the listener refuses every peer
 *  rather than running an unauthenticated shape. Pre-auth
 *  connections are bounded ([MAX_PREAUTH] concurrent, a
 *  [HANDSHAKE_TIMEOUT_MS] socket deadline that is cleared once
 *  the AEAD channel is up), counters are atomic, and a wildcard
 *  bind is refused by name — the caller names the interface.
 *  Post-handshake the channel carries the session line protocol
 *  (PING → PONG liveness; ERR unknown) OVER the AEAD channel.
 *  With a [channelHandler] wired (the production binding,
 *  HostListenerBinding.kt — W4), the handler owns the channel
 *  after the handshake instead: SessionStore/consent/presence/
 *  ENROLL. Without one the listener keeps the bare PING/PONG
 *  shape the transport suites pin. */
class LanHostListener(
    private val enrollments: EnrollmentStore,
    private val hostIdentity: DeviceIdentity? = null,
    private val channelHandler: ((peerDeviceId: String, channel: SocketStreams) -> Unit)? = null
) {
    @Volatile var isListening: Boolean = false
        private set
    private val acceptedCounter = java.util.concurrent.atomic.AtomicInteger(0)
    private val refusedCounter = java.util.concurrent.atomic.AtomicInteger(0)
    val acceptedSessions: Int get() = acceptedCounter.get()
    val refusedHandshakes: Int get() = refusedCounter.get()
    private val preAuth = java.util.concurrent.Semaphore(MAX_PREAUTH)
    // W13 P3-F4: the pre-auth permit is released the moment the
    // handshake completes; live sessions hold a SEPARATE, larger
    // session slot — 8 long-lived sessions no longer exhaust the
    // accept path for new handshakes.
    private val sessionSlots = java.util.concurrent.Semaphore(MAX_SESSIONS)
    // W13 P3-F13: accepted sockets are tracked so stop() closes
    // them all (previously stop() closed only the server socket
    // and live channels outlived the listener).
    private val acceptedSockets = java.util.Collections.synchronizedSet(mutableSetOf<Socket>())
    /** W13 P3-F12: why the accept loop died, when it died on its
     *  own (stop() is not a failure and does not set this). */
    @Volatile var acceptFailure: String? = null
        private set
    var port: Int = 0
        private set
    private var server: java.net.ServerSocket? = null
    private var thread: Thread? = null

    fun start(bindAddress: InetAddress, requestedPort: Int = LanProtocol.DEFAULT_PORT) {
        if (server != null) return
        require(!bindAddress.isAnyLocalAddress) {
            "lan host listener refuses a wildcard bind — name the interface address to listen on"
        }
        val srv = java.net.ServerSocket()
        srv.bind(InetSocketAddress(bindAddress, requestedPort))
        server = srv
        port = srv.localPort
        isListening = true
        thread = Thread {
            while (isListening) {
                try {
                    val client = srv.accept()
                    acceptedSockets.add(client)
                    if (!preAuth.tryAcquire()) {
                        refusedCounter.incrementAndGet()
                        acceptedSockets.remove(client)
                        try { client.close() } catch (_: Exception) {}
                        continue
                    }
                    Thread {
                        // handle() releases the pre-auth permit
                        // itself, exactly once, at handshake end.
                        handle(client)
                    }.apply { isDaemon = true }.start()
                } catch (e: Exception) {
                    // W13 P3-F12: an accept-loop death is VISIBLE —
                    // isListening drops and the cause is recorded,
                    // instead of a listener that claims to listen
                    // with no thread behind it. (stop() sets
                    // isListening=false first, so a stop-driven
                    // accept failure lands here with the flag
                    // already down and records nothing.)
                    if (isListening) {
                        isListening = false
                        acceptFailure = "accept loop died: ${e.javaClass.simpleName}: ${e.message}"
                    }
                    return@Thread
                }
            }
        }.apply { isDaemon = true; start() }
    }

    private fun handle(client: Socket) {
        var preAuthHeld = true
        var sessionHeld = false
        try {
        client.use {
            try {
                it.soTimeout = HANDSHAKE_TIMEOUT_MS
                val streams = SocketStreams(it.getInputStream(), it.getOutputStream())
                val identity = hostIdentity
                if (identity == null) { refusedCounter.incrementAndGet(); return }
                val proven = LanProtocol.hostHandshake(streams, enrollments, identity)
                if (proven == null) { refusedCounter.incrementAndGet(); return }
                acceptedCounter.incrementAndGet()
                // W13 P3-F4: handshake done — the pre-auth permit
                // goes back NOW; the live session holds a session
                // slot instead. No slot = refused, honestly.
                preAuth.release(); preAuthHeld = false
                if (!sessionSlots.tryAcquire()) { refusedCounter.incrementAndGet(); return }
                sessionHeld = true
                it.soTimeout = 0 // channel is up: the handshake deadline no longer applies
                val channel = proven.second
                val handler = channelHandler
                if (handler != null) {
                    handler(proven.first, channel)
                    return
                }
                while (true) {
                    val line = LanProtocol.readLine(channel.input) ?: return
                    LanProtocol.writeLine(channel.output, if (line == "PING") "PONG" else "ERR unknown")
                }
            } catch (_: Exception) { /* a dead peer ends its channel */ }
        }
        } finally {
            acceptedSockets.remove(client)
            if (preAuthHeld) preAuth.release()
            if (sessionHeld) sessionSlots.release()
        }
    }

    companion object {
        const val MAX_PREAUTH = 8
        const val MAX_SESSIONS = 64
        const val HANDSHAKE_TIMEOUT_MS = 5_000
    }

    fun stop() {
        isListening = false
        try { server?.close() } catch (_: Exception) {}
        server = null
        // W13 P3-F13: close every accepted socket still open.
        val snapshot = synchronized(acceptedSockets) { acceptedSockets.toList() }
        snapshot.forEach { try { it.close() } catch (_: Exception) {} }
    }
}

/** A rung that does exactly what a test tells it to — the engine's
 *  rung-agnosticism proof (mirrors the Windows StubRung). */
class StubRung(
    override val id: String,
    private val behavior: (TransportTarget) -> TransportConnectResult
) : TransportRung {
    override var connectAttempts: Int = 0
        private set
    override fun connect(target: TransportTarget): TransportConnectResult {
        connectAttempts++
        return behavior(target)
    }
    companion object {
        fun failing(id: String) = StubRung(id) { TransportConnectResult(false, "$id: forced failure (test double)") }
        fun succeeding(id: String) = StubRung(id) {
            TransportConnectResult(true, "$id: connected (test double)",
                SocketStreams(java.io.ByteArrayInputStream(ByteArray(0)), java.io.ByteArrayOutputStream()))
        }
    }
}

data class TransportEvent(
    val kind: String, val rung: String?, val detail: String,
    val fromSessionId: String? = null, val toSessionId: String? = null
)

/** The auto failover engine (D29/D32), Android form. */
class TransportSessionManager(
    private val roster: RosterStore,
    private val sessions: SessionStore,
    rungs: List<TransportRung>,
    private val identity: DeviceIdentity? = null,
    private val enrollments: EnrollmentStore? = null,
    private val idFactory: () -> String = { UUID.randomUUID().toString().replace("-", "") }
) {
    private val rungsById = rungs.associateBy { it.id.lowercase() }
    private val liveLinks = mutableMapOf<String, LiveLink>()
    private val eventList = mutableListOf<TransportEvent>()

    private data class LiveLink(
        val rung: String, val target: TransportTarget, val scopeId: String, val hostDeviceId: String,
        val initiatorUserId: String, val hostUserId: String, val kind: String, val recording: String,
        val streams: SocketStreams?, val orderedRungs: List<String>
    )

    @Synchronized fun events(): List<TransportEvent> = eventList.toList()
    @Synchronized fun getRung(id: String): TransportRung? = rungsById[id.lowercase()]

    private fun record(kind: String, rung: String?, detail: String, from: String? = null, to: String? = null) {
        synchronized(this) { eventList.add(TransportEvent(kind, rung, detail, from, to)) }
    }

    /** Resolve the ordered rung list a start may walk. A manual
     *  pin narrows WITHIN the resolved set; a pin outside the set
     *  refuses the whole resolution (never a silent widening). */
    @Synchronized
    fun resolveOrder(scopeId: String, hostDeviceId: String, manualPins: List<String>? = null): List<String>? {
        val effective = roster.effectiveTransportsFor(scopeId, hostDeviceId)
        if (effective.isNullOrEmpty()) return null
        if (manualPins != null) {
            val pins = manualPins.map { it.trim().lowercase() }.filter { it.isNotEmpty() }
            if (pins.isEmpty()) return null
            if (!pins.all { p -> effective.any { it.equals(p, ignoreCase = true) } }) return null
            return effective.filter { e -> pins.any { it.equals(e, ignoreCase = true) } }
        }
        return effective
    }

    // W13 P3-F5 (manager half): NOT @Synchronized across the rung
    // walk — a slow connect on one rung no longer blocks every
    // other session operation behind the manager monitor. Shared
    // state (liveLinks, eventList) is guarded by short synchronized
    // blocks; resolveOrder/record synchronize internally.
    fun startSession(
        scopeId: String, hostDeviceId: String, initiatorUserId: String, hostUserId: String,
        kind: String, targets: Map<String, TransportTarget>,
        recording: String = SessionStore.RECORDING_NONE, manualPins: List<String>? = null
    ): SessionStore.Session? {
        val order = resolveOrder(scopeId, hostDeviceId, manualPins)
        if (order == null) {
            record("start_refused", null, "No effective transports (or a manual pin outside the group's set).")
            return null
        }
        for (rungId in order) {
            val rung = rungsById[rungId.lowercase()]
            if (rung == null) {
                record("rung_unavailable", rungId, "Rung is in the group's set but no implementation is registered in this build.")
                continue
            }
            val target = targets[rungId] ?: TransportTarget(hostDeviceId)
            val result = if (rung is AuthenticatedRung && identity != null) rung.connectSession(target, identity, enrollments)
                         else rung.connect(target)
            if (!result.ok) { record("attempt_failed", rungId, result.detail); result.stream?.close(); continue }
            // W13 P3-F3: when the rung PROVED a host identity, the
            // session record is stamped only if the proof matches
            // the caller's claimed host — a proven-different host
            // refuses this rung, never a silently mis-stamped record.
            val proven = result.provenDeviceId
            if (proven != null && !proven.equals(hostDeviceId, ignoreCase = true)) {
                record("host_identity_mismatch", rungId,
                    "The rung proved host '$proven' but the caller asked for '$hostDeviceId' — refused.")
                result.stream?.close(); continue
            }
            val sessionId = idFactory()
            val created = sessions.createSession(
                SessionStore.Session(
                    id = sessionId, scopeId = scopeId, hostDeviceId = hostDeviceId,
                    initiatorUserId = initiatorUserId, kind = kind, transportRung = rungId,
                    recording = recording
                ), hostUserId
            )
            if (!created || !sessions.startSession(sessionId, initiatorUserId)) {
                record("start_gate_refused", rungId, "Slice 3 start gates refused this rung's session (consent/grant/offboarding).")
                result.stream?.close()
                if (created) sessions.endSession(sessionId, initiatorUserId)
                continue
            }
            synchronized(this) {
                liveLinks[sessionId] = LiveLink(rungId, target, scopeId, hostDeviceId, initiatorUserId,
                    hostUserId, kind, recording, result.stream, order)
            }
            // W13 P3-F9: engine-started sessions now SPEAK the
            // session line the host binding waits for — SESSION
            // <scope> <initiator> <hostUser> <kind> [recording] —
            // as the first line on the channel, so a host binding
            // serving this channel sees the same verb shape the
            // wire protocol documents. A failed write is recorded,
            // never hidden (the session record stands; the peer's
            // consent flow is the host's own).
            val stream = result.stream
            if (stream != null) {
                try {
                    LanProtocol.writeLine(stream.output,
                        "SESSION $scopeId $initiatorUserId $hostUserId $kind $recording")
                } catch (e: Exception) {
                    record("session_line_failed", rungId,
                        "The SESSION line could not be written: ${e.javaClass.simpleName}.", to = sessionId)
                }
            }
            record("session_started", rungId, "Session started over $rungId.", to = sessionId)
            return sessions.session(sessionId)
        }
        record("start_failed", null, "Every rung in the resolved order failed.")
        return null
    }

    /** Re-establish a live session whose rung died, on the NEXT
     *  rung in its resolved order. The old session ends with
     *  reason transport_failover first — end + new-start, linked.
     *  Null when no next rung exists: the floor holds, failover
     *  never leaves the session's resolved set. */
    @Synchronized
    fun reestablish(sessionId: String, targets: Map<String, TransportTarget>): SessionStore.Session? {
        val link = liveLinks[sessionId] ?: return null
        val current = sessions.session(sessionId)
        if (current == null || current.state == SessionStore.STATE_ENDED) {
            // W12-DS P3-F11: close the stream before dropping the link.
            try { link.streams?.close() } catch (_: Exception) {}
            liveLinks.remove(sessionId); return null
        }
        val idx = link.orderedRungs.indexOfFirst { it.equals(link.rung, ignoreCase = true) }
        // W12-DS P3-F21: rung no longer in the ordered set (idx -1)
        // must NOT retry the full list including the rung that just
        // died — treat as exhausted (the branch below ends cleanly).
        val remaining = if (idx < 0) emptyList() else link.orderedRungs.drop(idx + 1)
        if (remaining.isEmpty()) {
            // bd-and-remote F9 fix (2026-11-22): the event text
            // always SAID "the session ends rather than leaving its
            // set", but the code returned null and left the session
            // live in the store with its dead stream in place —
            // consent and presence kept showing a session with no
            // transport. Now the code does what the record says:
            // close the link, drop it, and END the session with the
            // transport-failover reason so presence clears.
            record("failover_exhausted", link.rung, "No next rung in the resolved set — the session ends rather than leaving its set.", from = sessionId)
            link.streams?.close()
            liveLinks.remove(sessionId)
            sessions.endSession(sessionId, link.initiatorUserId, SessionStore.REASON_TRANSPORT_FAILOVER)
            return null
        }
        // W13 P3-F10: end the old session FIRST, while its link
        // and stream are still intact — the old order dropped the
        // link before endSession was attempted, so a refused end
        // stranded a live session with no link to fail over from.
        if (!sessions.endSession(sessionId, link.initiatorUserId, SessionStore.REASON_TRANSPORT_FAILOVER)) {
            record("failover_refused", link.rung, "The old session could not be ended for failover.", from = sessionId)
            return null
        }
        link.streams?.close()
        liveLinks.remove(sessionId)
        val next = startSession(link.scopeId, link.hostDeviceId, link.initiatorUserId, link.hostUserId,
            link.kind, targets, link.recording, manualPins = remaining)
        if (next == null) {
            record("failover_failed", link.rung, "Re-establishment failed on every remaining rung.", from = sessionId)
            return null
        }
        record("session_reestablished", next.transportRung,
            "Reconnected on ${next.transportRung} after ${link.rung} died. This is a reconnect: session $sessionId ended (transport_failover); session ${next.id} started.",
            from = sessionId, to = next.id)
        sessions.appendEvent(next.id, SessionStore.EVENT_TRANSPORT_FAILOVER, link.initiatorUserId,
            "Re-established after rung '${link.rung}' died; previous session $sessionId ended (transport_failover). A reconnect, not a seamless continuation.")
        return next
    }

    @Synchronized
    fun forgetLink(sessionId: String) {
        liveLinks.remove(sessionId)?.streams?.close()
    }
}

// ---- local discovery (D19/D20) ----------------------------------------------

/** A discovery announcement: device-id HASH, display name,
 *  enrollment state — and nothing else. */
data class DiscoveryAnnouncement(val deviceIdHash: String, val displayName: String, val enrollmentState: String) {
    fun encode(): String =
        "$MAGIC|$deviceIdHash|$enrollmentState|${Base64.getEncoder().encodeToString(displayName.toByteArray(Charsets.UTF_8))}"

    companion object {
        const val MAGIC = "DESKGUEST1"
        const val STATE_ENROLLED = "enrolled"
        const val STATE_AVAILABLE = "available"

        fun hashDeviceId(deviceId: String): String =
            MessageDigest.getInstance("SHA-256").digest(deviceId.toByteArray(Charsets.UTF_8))
                .joinToString("") { "%02x".format(it) }

        fun sanitizeName(name: String?): String? {
            val t = name?.trim() ?: return null
            if (t.isEmpty() || t.length > 64) return null
            if (t.any { it.isISOControl() || it == '|' }) return null
            return t
        }

        fun forDevice(deviceId: String, displayName: String, enrolled: Boolean): DiscoveryAnnouncement? {
            val name = sanitizeName(displayName) ?: return null
            if (deviceId.isBlank()) return null
            return DiscoveryAnnouncement(hashDeviceId(deviceId), name, if (enrolled) STATE_ENROLLED else STATE_AVAILABLE)
        }

        /** Strict parse: any defect refuses the whole datagram. */
        fun decode(datagram: String?): DiscoveryAnnouncement? {
            if (datagram == null) return null
            val parts = datagram.trim().split('|')
            if (parts.size != 4 || parts[0] != MAGIC) return null
            val hash = parts[1]
            if (hash.length != 64 || hash.any { it !in '0'..'9' && it !in 'a'..'f' }) return null
            if (parts[2] != STATE_ENROLLED && parts[2] != STATE_AVAILABLE) return null
            val name = try {
                Base64.getDecoder().decode(parts[3]).toString(Charsets.UTF_8)
            } catch (_: Exception) { return null }
            if (sanitizeName(name) != name) return null
            return DiscoveryAnnouncement(hash, name, parts[2])
        }
    }
}

/** A discovered device. [isControllable] is ALWAYS false:
 *  discovery is an introduction, never a grant (D19/D20). */
data class DiscoveredDevice(val announcement: DiscoveryAnnouncement, val isKnownPeer: Boolean) {
    val availableToEnroll: Boolean get() = !isKnownPeer
    val isControllable: Boolean get() = false
}

/** Announcement + browse over UDP. Same-network only by
 *  construction; browse is a bounded window, not a scan. */
class DiscoveryService(
    knownDeviceIds: Collection<String> = emptyList(),
    /** W13 P3-F20: a LIVE provider of known device ids, consulted
     *  on every classify — the construction-time snapshot missed
     *  devices enrolled after the service was built, so a freshly
     *  enrolled peer classified as "available to enroll" forever.
     *  The snapshot remains as the floor; the provider unions in. */
    private val knownProvider: (() -> Collection<String>)? = null
) {
    private val knownHashes = knownDeviceIds.map { DiscoveryAnnouncement.hashDeviceId(it) }.toSet()

    fun classify(announcement: DiscoveryAnnouncement): DiscoveredDevice {
        val live = knownProvider?.invoke()
            ?.map { DiscoveryAnnouncement.hashDeviceId(it) }?.toSet() ?: emptySet()
        return DiscoveredDevice(announcement, announcement.deviceIdHash in knownHashes || announcement.deviceIdHash in live)
    }

    fun parseDatagram(data: ByteArray): DiscoveredDevice? =
        DiscoveryAnnouncement.decode(data.toString(Charsets.UTF_8))?.let { classify(it) }

    fun announce(announcement: DiscoveryAnnouncement, targetHost: String = "255.255.255.255", port: Int = DEFAULT_PORT) {
        DatagramSocket().use { socket ->
            socket.broadcast = true
            val bytes = announcement.encode().toByteArray(Charsets.UTF_8)
            socket.send(DatagramPacket(bytes, bytes.size, InetAddress.getByName(targetHost), port))
        }
    }

    fun browse(windowMs: Long, port: Int = DEFAULT_PORT): List<DiscoveredDevice> {
        val found = LinkedHashMap<String, DiscoveredDevice>()
        DatagramSocket(null).use { socket ->
            socket.reuseAddress = true
            socket.bind(InetSocketAddress(port))
            socket.soTimeout = 200
            val deadline = System.currentTimeMillis() + windowMs
            val buffer = ByteArray(2048)
            while (System.currentTimeMillis() < deadline) {
                try {
                    val packet = DatagramPacket(buffer, buffer.size)
                    socket.receive(packet)
                    val device = parseDatagram(packet.data.copyOf(packet.length)) ?: continue
                    found[device.announcement.deviceIdHash] = device
                } catch (_: java.net.SocketTimeoutException) { /* keep listening until the deadline */ }
            }
        }
        return found.values.toList()
    }

    companion object { const val DEFAULT_PORT = 47622 }
}
