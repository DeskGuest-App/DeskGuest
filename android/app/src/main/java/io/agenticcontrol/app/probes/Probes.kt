package io.agenticcontrol.app.probes

import io.agenticcontrol.app.cameraview.ChainedAudit
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress

/**
 * RMM-11 (Android completion) — probe suite hosted on the phone:
 * SNMP polling, topology mapping, agentless checks. The phone's
 * unique value is reaching LANs only it is on. Honest priority:
 * correctness over breadth — a check that cannot run says so by
 * name instead of returning a fabricated pass. Probing is
 * policy-gated and audited; targets are validated (no loopback /
 * link-local / multicast probing of record — same refusal line as
 * the Windows register).
 */
object ProbesPolicy {
    @Volatile var enabled: Boolean = true // rmm.probes.enabled (registry-seeded ON, bd-and-rmm F2)
    @Volatile var snmpEnabled: Boolean = true
    @Volatile var topologyEnabled: Boolean = true
    /** bd-and-rmm F2: a bound ManagementPolicyEngine governs the
     *  master switch through PolicyGate; the local var is the
     *  unbound fallback. */
    fun isEnabled(): Boolean =
        io.agenticcontrol.app.rmmspine.PolicyGate.enabledFor("rmm.probes.enabled", enabled)
}

fun interface UdpTransport { fun exchange(address: String, port: Int, payload: ByteArray, timeoutMs: Int): ByteArray? }
/** Real transport (used on-device; JVM tests inject a fake). */
object RealUdpTransport : UdpTransport {
    override fun exchange(address: String, port: Int, payload: ByteArray, timeoutMs: Int): ByteArray? = try {
        DatagramSocket().use { s ->
            s.soTimeout = timeoutMs
            val addr = InetAddress.getByName(address)
            s.send(DatagramPacket(payload, payload.size, addr, port))
            val buf = ByteArray(4096); val p = DatagramPacket(buf, buf.size)
            s.receive(p); buf.copyOf(p.length)
        }
    } catch (e: Exception) { null }
}

object TargetGuard {
    /**
     * bd-and-rmm F5 fix (2026-11-22): the guard used to accept ANY
     * routable IPv4 — a hub-supplied target list could make the
     * phone probe the public internet or carrier CGNAT space. The
     * suite's honest scope is the LANs the phone is on: RFC1918
     * private addresses ONLY (10/8, 172.16/12, 192.168/16).
     * Everything else — loopback, link-local, multicast, public,
     * CGNAT/shared, documentation and unspecified ranges — refuses
     * by name.
     */
    fun refusal(address: String): String? {
        val parts = address.split(".").mapNotNull { it.toIntOrNull() }
        if (parts.size != 4 || parts.any { it !in 0..255 }) return "not an IPv4 literal"
        if (parts[0] == 127) return "loopback refused"
        if (parts[0] == 169 && parts[1] == 254) return "link-local refused"
        if (parts[0] in 224..239) return "multicast refused"
        if (address == "0.0.0.0" || address == "255.255.255.255") return "broadcast/unspecified refused"
        val privateLan = parts[0] == 10 ||
            (parts[0] == 172 && parts[1] in 16..31) ||
            (parts[0] == 192 && parts[1] == 168)
        if (!privateLan) return "non-LAN address refused (probes are LAN-scoped: RFC1918 only)"
        return null
    }
}

/**
 * SNMPv2c GET codec (BER).
 *
 * bd-and-rmm F4 rewrite (2026-11-22). The first codec was a toy:
 * single-byte lengths (any content over 127 bytes unencodable),
 * single-byte INTEGERs (request-ids over 127 corrupted),
 * two-byte-max OID sub-identifiers (any sub-id >= 16384 corrupted
 * the OID), request-id / error-status skipped without looking (a
 * spoofed or errored reply decoded as a value), and the commonest
 * device values — TimeTicks (0x43), Counter32 (0x41), Gauge32
 * (0x42), IpAddress (0x40), OID (0x06) — unrecognised, collapsing
 * to the same null as a timeout. This codec does BER properly:
 * long-form lengths, minimal two's-complement integers, base-128
 * OID sub-identifiers of any size, response request-id verified
 * against the request, error-status honoured by name, and every
 * value type decoded to text.
 */
object SnmpCodec {
    private fun encodeLength(n: Int): ByteArray = when {
        n < 0x80 -> byteArrayOf(n.toByte())
        n <= 0xFF -> byteArrayOf(0x81.toByte(), n.toByte())
        else -> byteArrayOf(0x82.toByte(), (n ushr 8).toByte(), n.toByte())
    }
    private fun tlv(tag: Int, v: ByteArray) = byteArrayOf(tag.toByte()) + encodeLength(v.size) + v
    private fun intTlv(v: Int): ByteArray {
        var bytes = ByteArray(4) { i -> (v ushr (24 - 8 * i)).toByte() }
        var start = 0
        while (start < 3) {
            val b0 = bytes[start].toInt() and 0xFF; val b1 = bytes[start + 1].toInt() and 0xFF
            val redundant = (b0 == 0x00 && b1 and 0x80 == 0) || (b0 == 0xFF && b1 and 0x80 != 0)
            if (!redundant) break
            start++
        }
        return tlv(0x02, bytes.copyOfRange(start, 4))
    }
    /** Base-128 OID body: first two arcs packed; each later arc a
     *  base-128 continuation chain of any magnitude. */
    fun encodeOidBody(oid: IntArray): ByteArray {
        val body = mutableListOf<Byte>((oid[0] * 40 + oid[1]).toByte())
        for (sub in oid.drop(2)) {
            var v = sub.toLong() and 0xFFFFFFFFL
            if (v == 0L) body.add(0)
            else {
                val groups = mutableListOf<Byte>()
                while (v > 0) { groups.add(0, (v and 0x7F).toByte()); v = v ushr 7 }
                for ((idx, g) in groups.withIndex()) body.add((if (idx < groups.size - 1) (g.toInt() or 0x80) else g.toInt()).toByte())
            }
        }
        return body.toByteArray()
    }
    fun decodeOidBody(body: ByteArray): IntArray? {
        if (body.isEmpty()) return null
        val first = body[0].toInt() and 0xFF
        val arcs = mutableListOf(first / 40, first % 40)
        var acc = 0L; var inArc = false
        for (b in body.drop(1)) {
            val x = b.toInt() and 0xFF
            acc = (acc shl 7) or (x and 0x7F).toLong(); inArc = true
            if (x and 0x80 == 0) { arcs += acc.toInt(); acc = 0; inArc = false }
        }
        return if (inArc) null else arcs.toIntArray()
    }
    fun encodeGet(community: String, requestId: Int, oid: IntArray): ByteArray {
        val varbind = tlv(0x30, tlv(0x06, encodeOidBody(oid)) + tlv(0x05, byteArrayOf()))
        val varbindList = tlv(0x30, varbind)
        val pdu = tlv(0xA0, intTlv(requestId) + intTlv(0) + intTlv(0) + varbindList)
        return tlv(0x30, intTlv(1) + tlv(0x04, community.toByteArray()) + pdu)
    }

    private class Reader(val buf: ByteArray) {
        var pos = 0
        fun readTlv(): Pair<Int, ByteArray>? {
            if (pos + 2 > buf.size) return null
            val tag = buf[pos].toInt() and 0xFF
            val lb = buf[pos + 1].toInt() and 0xFF
            var header = 2; val len: Int
            if (lb and 0x80 != 0) {
                val n = lb and 0x7F
                if (n == 0 || n > 2 || pos + 2 + n > buf.size) return null
                var l = 0; for (j in 0 until n) l = (l shl 8) or (buf[pos + 2 + j].toInt() and 0xFF)
                len = l; header = 2 + n
            } else len = lb
            if (pos + header + len > buf.size) return null
            val v = buf.copyOfRange(pos + header, pos + header + len); pos += header + len
            return tag to v
        }
    }
    private fun signedValue(b: ByteArray): Long {
        var v = 0L; for (x in b) v = (v shl 8) or (x.toInt() and 0xFF).toLong()
        if (b.isNotEmpty() && b[0].toInt() and 0x80 != 0) { var m = -1L; repeat(b.size) { m = m shl 8 }; v = v or m }
        return v
    }
    private fun unsignedValue(b: ByteArray): Long { var v = 0L; for (x in b) v = (v shl 8) or (x.toInt() and 0xFF).toLong(); return v }

    /**
     * Decode a GetResponse, verifying its request-id equals
     * [expectedRequestId] and honouring error-status. Returns
     * (value, error) — exactly one is non-null.
     */
    fun decodeResponse(response: ByteArray, expectedRequestId: Int): Pair<String?, String?> {
        fun bad(r: String) = Pair<String?, String?>(null, r)
        val top = Reader(response).readTlv() ?: return bad("malformed packet")
        if (top.first != 0x30) return bad("malformed packet (top tag)")
        val r = Reader(top.second)
        r.readTlv() ?: return bad("malformed packet (version)")
        r.readTlv() ?: return bad("malformed packet (community)")
        val pdu = r.readTlv() ?: return bad("malformed packet (PDU)")
        if (pdu.first != 0xA2) return bad("not a GetResponse PDU")
        val pr = Reader(pdu.second)
        val rid = pr.readTlv() ?: return bad("malformed PDU (request-id)")
        val ridValue = signedValue(rid.second)
        if (ridValue != expectedRequestId.toLong())
            return bad("request-id mismatch (got $ridValue, expected $expectedRequestId) — reply refused as spoofed or stale")
        val err = pr.readTlv() ?: return bad("malformed PDU (error-status)")
        val errStatus = signedValue(err.second)
        pr.readTlv() ?: return bad("malformed PDU (error-index)")
        if (errStatus != 0L) return bad("agent returned error-status $errStatus")
        val vbl = pr.readTlv() ?: return bad("malformed PDU (varbind list)")
        if (vbl.first != 0x30) return bad("malformed PDU (varbind list tag)")
        val vb = Reader(vbl.second).readTlv() ?: return bad("empty varbind list")
        if (vb.first != 0x30) return bad("malformed varbind")
        val br = Reader(vb.second)
        br.readTlv() ?: return bad("malformed varbind (OID)")
        val value = br.readTlv() ?: return bad("malformed varbind (value)")
        return when (value.first) {
            0x05 -> bad("agent returned no value for this OID (noSuchObject)")
            0x02 -> Pair(signedValue(value.second).toString(), null)
            0x04 -> Pair(String(value.second, Charsets.UTF_8), null)
            0x06 -> Pair(decodeOidBody(value.second)?.joinToString(".") ?: "undecodable OID value", null)
            0x40 -> if (value.second.size == 4) Pair(value.second.joinToString(".") { (it.toInt() and 0xFF).toString() }, null) else bad("malformed IpAddress value")
            0x41, 0x42, 0x43 -> Pair(unsignedValue(value.second).toString(), null) // Counter32 / Gauge32 / TimeTicks
            0x44 -> Pair(value.second.joinToString("") { "%02x".format(it) }, null) // Opaque
            else -> bad("unsupported value tag ${value.first}")
        }
    }

    /** Extract the first value as text; null on any malformation,
     *  error status, or no-value reply. Lenient companion to
     *  [decodeResponse] (no request-id check) for raw inspection. */
    fun decodeValue(response: ByteArray): String? = try {
        val top = Reader(response).readTlv() ?: null
        if (top == null || top.first != 0x30) null
        else {
            val r = Reader(top.second)
            r.readTlv(); r.readTlv()
            val pdu = r.readTlv()
            if (pdu == null || pdu.first != 0xA2) null
            else {
                val pr = Reader(pdu.second)
                val rid = pr.readTlv()
                if (rid == null) null else decodeResponse(response, signedValue(rid.second).toInt()).first
            }
        }
    } catch (e: Exception) { null }
}

data class SnmpResult(val address: String, val oid: String, val value: String?, val error: String?)
data class TopologyNode(val address: String, val kind: String, val evidence: String)
data class AgentlessResult(val address: String, val check: String, val outcome: String) // pass | fail | unavailable:<reason>

class ProbeService(
    private val udp: UdpTransport = RealUdpTransport,
    val audit: ChainedAudit = ChainedAudit()
) {
    private val reqId = java.util.concurrent.atomic.AtomicInteger(1)

    companion object {
        /** bd-and-rmm F5: a topology sweep is bounded — an
         *  unbounded hub-supplied list can no longer park the
         *  service for hours. */
        const val MAX_TOPOLOGY_TARGETS = 64
        const val TOPOLOGY_THREADS = 8
    }

    /**
     * One SNMP GET. [actor] names who ordered the probe in the
     * audit (bd-and-rmm F5 — the audit previously could not name
     * an actor at all); a blank actor is recorded as "unattributed",
     * never silently dropped.
     */
    fun snmpGet(address: String, community: String, oid: IntArray, oidText: String, actor: String = ""): SnmpResult {
        val who = actor.ifBlank { "unattributed" }
        if (!ProbesPolicy.isEnabled() || !ProbesPolicy.snmpEnabled) return SnmpResult(address, oidText, null, "policy OFF")
        TargetGuard.refusal(address)?.let { audit.append("probe_refused", "kind=snmp actor=$who target=$address reason=$it"); return SnmpResult(address, oidText, null, it) }
        if (community.isBlank()) return SnmpResult(address, oidText, null, "community required (never defaulted)")
        val id = reqId.getAndIncrement()
        val resp = udp.exchange(address, 161, SnmpCodec.encodeGet(community, id, oid), 1500)
            ?: run { audit.append("probe_snmp_timeout", "actor=$who target=$address oid=$oidText"); return SnmpResult(address, oidText, null, "no response (timeout)") }
        val (v, err) = SnmpCodec.decodeResponse(resp, id)
        audit.append("probe_snmp", "actor=$who target=$address oid=$oidText answered=${v != null}")
        return SnmpResult(address, oidText, v, err)
    }

    /**
     * Topology from evidence only: SNMP sysDescr classifies;
     * silence classifies nothing. bd-and-rmm F5: the sweep is
     * BOUNDED (at most [MAX_TOPOLOGY_TARGETS] addresses; excess is
     * named in the audit, not silently dropped) and CONCURRENT —
     * the old sweep held the service monitor across sequential
     * 1.5s timeouts, so N dead addresses parked every other probe
     * for N x 1.5s.
     */
    fun mapTopology(addresses: List<String>, community: String, actor: String = ""): List<TopologyNode> {
        val who = actor.ifBlank { "unattributed" }
        if (!ProbesPolicy.isEnabled() || !ProbesPolicy.topologyEnabled) return emptyList()
        val sysDescr = intArrayOf(1, 3, 6, 1, 2, 1, 1, 1, 0)
        val capped = addresses.take(MAX_TOPOLOGY_TARGETS)
        val pool = java.util.concurrent.Executors.newFixedThreadPool(TOPOLOGY_THREADS)
        try {
            val futures = capped.map { a ->
                pool.submit<TopologyNode?> {
                    if (TargetGuard.refusal(a) != null) null
                    else {
                        val r = snmpGet(a, community, sysDescr, "sysDescr", who)
                        if (r.value == null) null else TopologyNode(a, classify(r.value), "snmp sysDescr")
                    }
                }
            }
            val out = futures.mapNotNull { it.get() }
            audit.append("probe_topology", "actor=$who scanned=${addresses.size} probed=${capped.size} classified=${out.size}" +
                if (addresses.size > capped.size) " truncated=${addresses.size - capped.size} (cap $MAX_TOPOLOGY_TARGETS)" else "")
            return out
        } finally {
            pool.shutdown()
        }
    }
    private fun classify(descr: String): String {
        val d = descr.lowercase()
        return when {
            "camera" in d || "onvif" in d -> "camera"
            "switch" in d || "router" in d || "gateway" in d -> "network"
            "printer" in d -> "printer"
            "linux" in d || "windows" in d || "darwin" in d -> "host"
            else -> "unknown"
        }
    }
    /**
     * Agentless checks: ping-equivalent is UDP/ICMP-limited on
     * Android — named unavailable, never faked. bd-and-rmm F4: a
     * check that cannot RUN (policy off, timeout, refused target)
     * reports unavailable:<reason>; "fail" is reserved for a device
     * that ANSWERED with no value — the old code reported policy
     * OFF as a device failure.
     */
    fun agentlessCheck(address: String, check: String, community: String = "", actor: String = ""): AgentlessResult {
        TargetGuard.refusal(address)?.let { return AgentlessResult(address, check, "unavailable:$it") }
        return when (check) {
            "snmp_uptime" -> {
                if (!ProbesPolicy.isEnabled() || !ProbesPolicy.snmpEnabled)
                    return AgentlessResult(address, check, "unavailable:policy OFF")
                val r = snmpGet(address, community, intArrayOf(1, 3, 6, 1, 2, 1, 1, 3, 0), "sysUpTime", actor)
                when {
                    r.value != null -> AgentlessResult(address, check, "pass")
                    r.error?.startsWith("no response") == true -> AgentlessResult(address, check, "unavailable:${r.error}")
                    r.error?.contains("refused") == true -> AgentlessResult(address, check, "unavailable:${r.error}")
                    else -> AgentlessResult(address, check, "fail")
                }
            }
            "icmp_ping" -> AgentlessResult(address, check, "unavailable:raw ICMP is not available to an Android app-tier probe; use snmp_uptime")
            else -> AgentlessResult(address, check, "unavailable:unknown check name")
        }
    }
}

