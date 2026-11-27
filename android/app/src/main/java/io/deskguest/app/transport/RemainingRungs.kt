package io.deskguest.app.transport

import io.deskguest.app.enrollment.DeviceIdentity
import java.math.BigInteger
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.Socket
import java.security.MessageDigest
import java.util.Base64

/**
 * Block F remaining rungs (Android mirror of the Windows
 * DeskGuest.Shared transport): `ipv6`, `ownpath`, `tor`. Same honesty
 * rules as the Windows half: classification never pretends, configs
 * are serializer-made and re-validated at use time, and an
 * unconfigured rung refuses in words.
 */

/** Honest IPv6 reachability classification: only global unicast
 *  (2000::/3) is a direct session target. */
object Ipv6Reachability {
    fun classify(host: String?): Pair<Boolean, String> {
        if (host == null) return false to "ipv6: target is not an IPv6 address"
        val ip = try { InetAddress.getByName(host.trim()) } catch (_: Exception) {
            return false to "ipv6: target is not an IPv6 address"
        }
        val bytes = ip.address
        if (bytes.size != 16) return false to "ipv6: target is not an IPv6 address"
        if (ip.isLoopbackAddress) return false to "ipv6: loopback is not a direct session target"
        val b0 = bytes[0].toInt() and 0xFF
        val b1 = bytes[1].toInt() and 0xFF
        val b2 = bytes[2].toInt() and 0xFF
        val b3 = bytes[3].toInt() and 0xFF
        fun docRange() = b0 == 0x20 && b1 == 0x01 && b2 == 0x0D && b3 == 0xB8
        if ((b0 and 0xE0) != 0x20) {
            if (b0 == 0xFE && (b1 and 0xC0) == 0x80) return false to "ipv6: link-local address (fe80::/10) is not globally reachable"
            if ((b0 and 0xFE) == 0xFC) return false to "ipv6: unique-local address (fc00::/7) is not globally reachable"
            if (b0 == 0xFF) return false to "ipv6: multicast is not a session target"
            if (docRange()) return false to "ipv6: documentation range (2001:db8::/32) is not reachable"
            return false to "ipv6: address is outside the global unicast range (2000::/3)"
        }
        if (docRange()) return false to "ipv6: documentation range (2001:db8::/32) is not reachable"
        return true to "ipv6: global unicast target"
    }

    /** This device's own global IPv6 presence, from the OS
     *  interface list — no probing traffic is sent to learn it. */
    fun localHasGlobalIpv6(): Boolean {
        try {
            val interfaces = NetworkInterface.getNetworkInterfaces() ?: return false
            for (ni in interfaces) {
                if (!ni.isUp || ni.isLoopback) continue
                for (addr in ni.inetAddresses) {
                    if (classify(addr.hostAddress).first) return true
                }
            }
        } catch (_: Exception) { /* unreadable interfaces = not present */ }
        return false
    }
}

/** The `ipv6` rung: direct IPv6 where BOTH ends have it. */
class Ipv6Rung(private val localHasGlobal: () -> Boolean = { Ipv6Reachability.localHasGlobalIpv6() }) : AuthenticatedRung {
    override val id: String = "ipv6"
    override var connectAttempts: Int = 0
        private set

    override fun connect(target: TransportTarget): TransportConnectResult =
        TransportConnectResult(false, "ipv6: a session connect requires the local device identity (connectSession)")

    override fun connectSession(target: TransportTarget, identity: DeviceIdentity, enrollments: io.deskguest.app.enrollment.EnrollmentStore?): TransportConnectResult {
        connectAttempts++
        if (enrollments == null) return TransportConnectResult(false, "ipv6: no enrollment store wired — the v2 handshake verifies the host against its enrolled key")
        val address = target.address?.trim().orEmpty()
        if (address.isEmpty()) return TransportConnectResult(false, "ipv6: no address (target must carry the peer's global IPv6 address)")
        val (host, port) = LanRung.parseAddress(address)
            ?: return TransportConnectResult(false, "ipv6: bad address '$address'")
        val cls = Ipv6Reachability.classify(host)
        if (!cls.first) return TransportConnectResult(false, cls.second)
        if (!localHasGlobal()) return TransportConnectResult(false, "ipv6: this device has no global IPv6 address — the rung cannot carry a session from here")
        val socket = Socket()
        return try {
            socket.connect(InetSocketAddress(host, port), 5000)
            val streams = SocketStreams(socket.getInputStream(), socket.getOutputStream()) { socket.close() }
            val expected = target.deviceId.takeIf { !it.equals(identity.deviceId, ignoreCase = true) }
            val result = LanProtocol.clientHandshakeDetailed(streams, identity, enrollments, expected)
            if (result.outcome != LanProtocol.ClientOutcome.CONNECTED) {
                socket.close()
                TransportConnectResult(false, "ipv6: ${handshakeDetail(result.outcome)}")
            } else {
                TransportConnectResult(true, "ipv6: connected to [$host]:$port (mutually authenticated, AEAD channel)", result.channel)
            }
        } catch (e: Exception) {
            try { socket.close() } catch (_: Exception) {}
            TransportConnectResult(false, "ipv6: ${e.javaClass.simpleName}")
        }
    }
}

/** T5 own-path validation (OP-01…OP-04): safe names, WireGuard key
 *  shape, literal tunnel addresses, host:port endpoints. */
object OwnPathValidation {
    fun isSafeName(name: String?): Boolean {
        if (name == null) return false
        val trimmed = name.trim()
        if (trimmed != name || trimmed.isEmpty() || trimmed.length > 48) return false
        if (name.all { it == '.' }) return false // "." / ".." are path shapes, never names
        return name.all { it.isLetterOrDigit() || it in " ._-" }
    }

    fun isWireGuardKey(base64: String?): Boolean {
        if (base64 == null || base64.length != 44 || !base64.endsWith("=")) return false
        return try { Base64.getDecoder().decode(base64).size == 32 } catch (_: Exception) { false }
    }

    fun isTunnelAddress(address: String?): Boolean {
        if (address == null) return false
        return try { InetAddress.getByName(address.trim()); true } catch (_: Exception) { false }
    }

    fun parseEndpoint(endpoint: String?): Pair<String, Int>? {
        if (endpoint == null) return null
        val text = endpoint.trim()
        val host: String
        val portText: String
        if (text.startsWith("[")) {
            val close = text.indexOf(']')
            if (close < 0 || close + 1 >= text.length || text[close + 1] != ':') return null
            host = text.substring(1, close)
            portText = text.substring(close + 2)
            try { if (InetAddress.getByName(host).address.size != 16) return null } catch (_: Exception) { return null }
        } else {
            val idx = text.lastIndexOf(':')
            if (idx <= 0) return null
            host = text.substring(0, idx)
            portText = text.substring(idx + 1)
            if (host.isEmpty() || host.length > 253) return null
            if (!host.all { it.isLetterOrDigit() || it in ".-" }) return null
            if (host.startsWith(".") || host.startsWith("-") || host.contains("..")) return null
            for (label in host.split('.')) {
                if (label.isEmpty() || label.length > 63 || label.startsWith("-") || label.endsWith("-")) return null
            }
        }
        val port = portText.toIntOrNull() ?: return null
        if (port !in 1..65535) return null
        return host to port
    }
}

data class OwnPathPeer(
    val deviceId: String,
    val displayName: String,
    val publicKey: String,
    val tunnelAddress: String,
    val endpoint: String,
    val presharedKey: String? = null
)

/** Serializer + validator for DeskGuest-generated WireGuard peer configs
 *  (T5). The private key is NEVER part of a peer config (WG-02). */
object WireGuardConfigGenerator {
    fun generatePeerConfig(peer: OwnPathPeer): String {
        if (!OwnPathValidation.isSafeName(peer.displayName))
            throw IllegalStateException("ownpath: peer name '${peer.displayName}' is not a safe config name — refused (OP-01)")
        if (!OwnPathValidation.isWireGuardKey(peer.publicKey))
            throw IllegalStateException("ownpath: peer public key is not a WireGuard key — refused")
        if (peer.presharedKey != null && !OwnPathValidation.isWireGuardKey(peer.presharedKey))
            throw IllegalStateException("ownpath: preshared key is not a WireGuard key — refused")
        if (!OwnPathValidation.isTunnelAddress(peer.tunnelAddress))
            throw IllegalStateException("ownpath: tunnel address is not a literal IP — refused")
        val (host, port) = OwnPathValidation.parseEndpoint(peer.endpoint)
            ?: throw IllegalStateException("ownpath: endpoint is not a valid host:port — refused")
        val ip = InetAddress.getByName(peer.tunnelAddress.trim())
        val isV6 = ip.address.size == 16
        val mask = if (isV6) 128 else 32
        val endpointText = if (isV6 && host.contains(':')) "[$host]:$port" else "$host:$port"
        val sb = StringBuilder()
        sb.appendLine("# DeskGuest own-path peer (generated; do not hand-edit — regenerate)")
        sb.appendLine("# Device: ${peer.deviceId}")
        sb.appendLine("# Name: ${peer.displayName}")
        sb.appendLine("[Peer]")
        sb.appendLine("PublicKey = ${peer.publicKey}")
        if (peer.presharedKey != null) sb.appendLine("PresharedKey = ${peer.presharedKey}")
        sb.appendLine("AllowedIPs = ${peer.tunnelAddress.trim()}/$mask")
        sb.appendLine("Endpoint = $endpointText")
        sb.appendLine("PersistentKeepalive = 25")
        return sb.toString()
    }

    private val forbiddenKeys = setOf("postup", "predown", "postdown", "preup", "table", "saveconfig", "dns")

    fun validateConfigText(text: String?): Pair<Boolean, String> {
        if (text.isNullOrBlank()) return false to "config is empty"
        for (raw in text.lines()) {
            val line = raw.trim()
            if (line.isEmpty() || line.startsWith("#")) continue
            val key = line.substringBefore('=').trim().lowercase()
            if (key in forbiddenKeys)
                return false to "config carries forbidden key '$key' (wg-quick hooks / SaveConfig / DNS side effects are refused, WG-01/WG-03/WG-04)"
        }
        return true to "config accepted"
    }

    /** RFC 7748 X25519 over BigInteger (validated against the
     *  RFC 7748 §6.1 vector in the test suite). */
    fun x25519(scalar32: ByteArray, u32: ByteArray): ByteArray {
        val k = scalar32.copyOf()
        k[0] = (k[0].toInt() and 248).toByte()
        k[31] = (k[31].toInt() and 127).toByte()
        k[31] = (k[31].toInt() or 64).toByte()
        val p = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19))
        fun decodeLE(bytes: ByteArray): BigInteger {
            val reversed = bytes.copyOf()
            reversed[31] = (reversed[31].toInt() and 0x7F).toByte()
            reversed.reverse()
            return BigInteger(1, reversed)
        }
        fun encodeLE(x: BigInteger): ByteArray {
            val out = ByteArray(32)
            var v = x.mod(p)
            for (i in 0 until 32) {
                out[i] = v.and(BigInteger.valueOf(0xFF)).toByte()
                v = v.shiftRight(8)
            }
            return out
        }
        val x1 = decodeLE(u32)
        var x2 = BigInteger.ONE
        var z2 = BigInteger.ZERO
        var x3 = x1
        var z3 = BigInteger.ONE
        var swap = 0
        val a24 = BigInteger.valueOf(121665)
        fun add(a: BigInteger, b: BigInteger) = a.add(b).mod(p)
        fun sub(a: BigInteger, b: BigInteger) = a.subtract(b).mod(p)
        fun mul(a: BigInteger, b: BigInteger) = a.multiply(b).mod(p)
        for (t in 254 downTo 0) {
            val bit = (k[t / 8].toInt() shr (t % 8)) and 1
            swap = swap xor bit
            if (swap == 1) {
                val tx = x2; x2 = x3; x3 = tx
                val tz = z2; z2 = z3; z3 = tz
            }
            swap = bit
            val a = add(x2, z2); val aa = mul(a, a)
            val b = sub(x2, z2); val bb = mul(b, b)
            val e = sub(aa, bb)
            val c = add(x3, z3); val d = sub(x3, z3)
            val da = mul(d, a); val cb = mul(c, b)
            x3 = mul(add(da, cb), add(da, cb))
            z3 = mul(x1, mul(sub(da, cb), sub(da, cb)))
            x2 = mul(aa, bb)
            z2 = mul(e, add(aa, mul(a24, e)))
        }
        if (swap == 1) {
            val tx = x2; x2 = x3; x3 = tx
            val tz = z2; z2 = z3; z3 = tz
        }
        return encodeLE(mul(x2, z2.modPow(p.subtract(BigInteger.TWO), p)))
    }

    fun generateKeyPair(): Pair<String, String> {
        val priv = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
        val base = ByteArray(32); base[0] = 9
        val pub = x25519(priv, base)
        return Base64.getEncoder().encodeToString(priv) to Base64.getEncoder().encodeToString(pub)
    }
}

data class OwnPathPeerSet(val peers: Map<String, OwnPathPeer>) {
    companion object { val EMPTY = OwnPathPeerSet(emptyMap()) }
}

/** The `ownpath` rung: DeskGuest-generated WireGuard is the data plane
 *  (the OS stack carries the tunnel); this rung connects to the
 *  peer's tunnel address and runs the enrollment handshake. The
 *  stored peer is re-validated at use time. */
class OwnPathRung(private val peers: () -> OwnPathPeerSet) : AuthenticatedRung {
    override val id: String = "ownpath"
    override var connectAttempts: Int = 0
        private set

    override fun connect(target: TransportTarget): TransportConnectResult =
        TransportConnectResult(false, "ownpath: a session connect requires the local device identity (connectSession)")

    override fun connectSession(target: TransportTarget, identity: DeviceIdentity, enrollments: io.deskguest.app.enrollment.EnrollmentStore?): TransportConnectResult {
        connectAttempts++
        if (enrollments == null) return TransportConnectResult(false, "ownpath: no enrollment store wired — the v2 handshake verifies the host against its enrolled key")
        val peer = peers().peers[target.deviceId]
            ?: return TransportConnectResult(false, "ownpath: no generated WireGuard config for this device — run own-path setup first")
        val config = try { WireGuardConfigGenerator.generatePeerConfig(peer) } catch (e: IllegalStateException) {
            return TransportConnectResult(false, "ownpath: stored peer config fails validation — ${e.message}")
        }
        val verdict = WireGuardConfigGenerator.validateConfigText(config)
        if (!verdict.first) return TransportConnectResult(false, "ownpath: ${verdict.second}")
        val tunnelHost = peer.tunnelAddress.trim()
        var port = LanProtocol.DEFAULT_PORT
        val address = target.address?.trim().orEmpty()
        if (address.isNotEmpty()) {
            val parsed = LanRung.parseAddress(address)
            if (parsed != null && parsed.first == tunnelHost) port = parsed.second
        }
        val socket = Socket()
        return try {
            socket.connect(InetSocketAddress(tunnelHost, port), 5000)
            val streams = SocketStreams(socket.getInputStream(), socket.getOutputStream()) { socket.close() }
            val expected = target.deviceId.takeIf { !it.equals(identity.deviceId, ignoreCase = true) }
            val result = LanProtocol.clientHandshakeDetailed(streams, identity, enrollments, expected)
            if (result.outcome != LanProtocol.ClientOutcome.CONNECTED) {
                socket.close()
                TransportConnectResult(false, "ownpath: ${handshakeDetail(result.outcome)}")
            } else {
                TransportConnectResult(true, "ownpath: connected over the WireGuard tunnel to $tunnelHost:$port (mutually authenticated, AEAD channel)", result.channel)
            }
        } catch (e: Exception) {
            try { socket.close() } catch (_: Exception) {}
            TransportConnectResult(false, "ownpath: ${e.javaClass.simpleName}")
        }
    }
}

/** DeskGuest's Tor configuration: the SOCKS endpoint of the DeskGuest-managed
 *  Tor client. Absent = the rung is unconfigured and refuses. */
data class TorConfig(val socksHost: String, val socksPort: Int) {
    companion object {
        const val LATENCY_LABEL = "Tor: high latency by design — expect a slow session; the cost of this rung is speed, not setup (D28)."
    }
}

/** The `tor` rung: SOCKS5 (RFC 1928, no-auth) through DeskGuest's
 *  configured Tor proxy, then the enrollment handshake. Tor's
 *  metadata properties are Tor's design, not DeskGuest's claim: the local
 *  Tor client (and the exit) see the destination — no stronger
 *  claim is made anywhere in the product. T6 audit status:
 *  unaudited. */
class TorRung(private val config: () -> TorConfig?) : AuthenticatedRung {
    override val id: String = "tor"
    override var connectAttempts: Int = 0
        private set

    override fun connect(target: TransportTarget): TransportConnectResult =
        TransportConnectResult(false, "tor: a session connect requires the local device identity (connectSession)")

    override fun connectSession(target: TransportTarget, identity: DeviceIdentity, enrollments: io.deskguest.app.enrollment.EnrollmentStore?): TransportConnectResult {
        connectAttempts++
        if (enrollments == null) return TransportConnectResult(false, "tor: no enrollment store wired — the v2 handshake verifies the host against its enrolled key")
        val cfg = config() ?: return TransportConnectResult(false, "tor: not configured — DeskGuest's Tor setup has not run on this device")
        val address = target.address?.trim().orEmpty()
        if (address.isEmpty()) return TransportConnectResult(false, "tor: no target address")
        val (host, port) = LanRung.parseAddress(address)
            ?: return TransportConnectResult(false, "tor: bad address '$address'")
        val socket = Socket()
        return try {
            socket.connect(InetSocketAddress(cfg.socksHost, cfg.socksPort), 10_000)
            socket.soTimeout = 30_000
            val streams = SocketStreams(socket.getInputStream(), socket.getOutputStream()) { socket.close() }
            if (!socks5Connect(streams, host, port)) {
                socket.close()
                return TransportConnectResult(false, "tor: the configured Tor proxy refused the connection")
            }
            val expected = target.deviceId.takeIf { !it.equals(identity.deviceId, ignoreCase = true) }
            val hs = LanProtocol.clientHandshakeDetailed(streams, identity, enrollments, expected)
            if (hs.outcome != LanProtocol.ClientOutcome.CONNECTED) {
                socket.close()
                TransportConnectResult(false, "tor: ${handshakeDetail(hs.outcome)}")
            } else {
                TransportConnectResult(true, "tor: connected to $host:$port via the configured Tor proxy (${TorConfig.LATENCY_LABEL}) (mutually authenticated, AEAD channel)", hs.channel)
            }
        } catch (e: Exception) {
            try { socket.close() } catch (_: Exception) {}
            TransportConnectResult(false, "tor: ${e.javaClass.simpleName}")
        }
    }

    private fun socks5Connect(streams: SocketStreams, host: String, port: Int): Boolean {
        val out = streams.output
        val input = streams.input
        out.write(byteArrayOf(5, 1, 0)); out.flush()
        val greeting = ByteArray(2)
        if (!readFully(input, greeting) || greeting[0].toInt() != 5 || greeting[1].toInt() != 0) return false
        val requestBytes = socks5RequestBytes(host, port) ?: return false
        out.write(requestBytes); out.flush()
        val head = ByteArray(4)
        if (!readFully(input, head) || head[0].toInt() != 5 || head[1].toInt() != 0) return false
        val skip = when (head[3].toInt()) {
            1 -> 4; 4 -> 16
            3 -> { val len = input.read(); if (len < 0) return false; len }
            else -> return false
        }
        val rest = ByteArray(skip + 2)
        return readFully(input, rest)
    }

    companion object {
        /** The SOCKS5 CONNECT request bytes for (host, port), or
         *  null for an over-long name. Pure and testable: the
         *  ATYP choice is where the F4 no-local-resolution rule
         *  lives. */
        fun socks5RequestBytes(host: String, port: Int): ByteArray? {
        val request = mutableListOf<Byte>(5, 1, 0)
        // bd-and-remote F4 fix: NEVER resolve the target locally —
        // InetAddress.getByName(host) sent the destination (and any
        // .onion name) to the system resolver outside Tor. Literal
        // IPs are parsed WITHOUT resolution (parseLiteralIp); every
        // other name travels as ATYP 3 and Tor resolves it.
        val ip = parseLiteralIp(host)
        if (ip != null && ip.size == 4) {
            request.add(1); ip.forEach { request.add(it) }
        } else if (ip != null && ip.size == 16) {
            request.add(4); ip.forEach { request.add(it) }
        } else {
            val name = host.toByteArray(Charsets.UTF_8)
            if (name.size > 255) return null
            request.add(3); request.add(name.size.toByte()); name.forEach { request.add(it) }
        }
        request.add(((port shr 8) and 0xFF).toByte()); request.add((port and 0xFF).toByte())
        return request.toByteArray()
        }
    }

    private fun readFully(input: java.io.InputStream, buffer: ByteArray): Boolean {
        var read = 0
        while (read < buffer.size) {
            val n = input.read(buffer, read, buffer.size - read)
            if (n < 0) return false
            read += n
        }
        return true
    }
}

fun handshakeDetail(outcome: LanProtocol.ClientOutcome): String = when (outcome) {
    LanProtocol.ClientOutcome.HOST_REFUSED -> "host refused our proof of possession"
    LanProtocol.ClientOutcome.NO_CHALLENGE -> "no DeskGuest challenge received — the peer did not speak the DeskGuest protocol"
    LanProtocol.ClientOutcome.HOST_AUTH_FAILED -> "the peer claimed to be a host but could not prove it — nothing was signed for it"
    LanProtocol.ClientOutcome.CONNECTED -> "connected"
}

/** Parse a literal IP address WITHOUT any DNS resolution: dotted
 *  IPv4, or an IPv6 literal validated group-by-group. Null for any
 *  name — names are never resolved by this parser. */
fun parseLiteralIp(host: String): ByteArray? {
    val h = host.trim().removeSurrounding("[", "]")
    if (h.contains(':')) {
        // IPv6 literal: expand :: and validate 1-8 hex groups.
        val halves = h.split("::")
        if (halves.size > 2) return null
        fun groups(part: String): List<Int>? {
            if (part.isEmpty()) return emptyList()
            val out = mutableListOf<Int>()
            for (g in part.split(':')) {
                if (g.isEmpty() || g.length > 4 || !g.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) return null
                out.add(g.toInt(16))
            }
            return out
        }
        val left = groups(halves[0]) ?: return null
        val right = if (halves.size == 2) groups(halves[1]) ?: return null else emptyList()
        if (halves.size == 1 && left.size != 8) return null
        if (halves.size == 2 && left.size + right.size >= 8) return null
        val full = left + List(8 - left.size - right.size) { 0 } + right
        val bytes = ByteArray(16)
        for (i in 0 until 8) { bytes[i * 2] = (full[i] shr 8).toByte(); bytes[i * 2 + 1] = full[i].toByte() }
        return bytes
    }
    val parts = h.split('.')
    if (parts.size != 4) return null
    val bytes = ByteArray(4)
    for (i in 0 until 4) {
        val p = parts[i]
        if (p.isEmpty() || p.length > 3 || !p.all { it.isDigit() }) return null
        val v = p.toIntOrNull() ?: return null
        if (v !in 0..255) return null
        bytes[i] = v.toByte()
    }
    return bytes
}

/** Shared hashing helper for the Block F mirrors. */
internal fun sha256Hex(bytes: ByteArray): String =
    MessageDigest.getInstance("SHA-256").digest(bytes)
        .joinToString("") { "%02x".format(it) }
