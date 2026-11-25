package io.agenticcontrol.app.transport

import io.agenticcontrol.app.enrollment.DeviceIdentity
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.util.UUID

/**
 * Block C part 3 — the `hub` and `mesh` rungs, Android mirror of
 * the Windows Acp.Shared transport layer.
 *
 * - `hub`: sessions over the ACP-managed Headscale mesh. Two gates
 *   stand in front of the socket: the target must be a tailnet
 *   address (100.64.0.0/10 — a LAN address is refused, never a
 *   silent downgrade), and the target device must be a LIVE member
 *   of the ACP hub registry (joined, not decommissioned, client at
 *   or above the floor). Past the gates, admission is the SAME
 *   LanProtocol enrollment handshake as the `lan` rung: mesh
 *   membership never equals ACP admission.
 * - `mesh`: sessions over the operator's own Tailscale tailnet.
 *   The rung admits nothing until the in-app setup
 *   ([MeshSetupFlow]) has completed — on Android that means the
 *   TS-03 carve-out path (operator-personal device only).
 *
 * The socket open is a constructor seam ([HubRung]'s connector)
 * because JVM-originated loopback connects are reset in the build
 * sandbox; production uses the real socket path, and the JVM suite
 * drives the identical gate + handshake code over in-memory pipes —
 * the same discipline TransportTest uses for LanProtocol.
 */

/** Tailnet address recognition: Tailscale IPv4 lives in
 *  100.64.0.0/10 (shared address space) — first octet 100, second
 *  64–127. Tailscale IPv6 lives in the fd7a:115c:a1e0::/48 ULA
 *  prefix (bd-and-remote F10 fix: hub/mesh were IPv4-only because
 *  the ULA prefix was never recognised). Anything else is not a
 *  mesh address. */
object MeshAddress {
    fun isTailnetAddress(address: String?): Boolean {
        val host = hostPart(address) ?: return false
        if (host.contains(':')) {
            val groups = host.lowercase().split(':')
            return groups.size >= 3 && groups[0] == "fd7a" && groups[1] == "115c" && groups[2] == "a1e0"
        }
        val parts = host.split('.')
        if (parts.size != 4) return false
        val octets = parts.map { it.toIntOrNull() ?: return false }
        if (octets.any { it !in 0..255 }) return false
        return octets[0] == 100 && octets[1] in 64..127
    }

    fun hostPart(address: String?): String? {
        var a = address?.trim().orEmpty()
        if (a.isEmpty()) return null
        if (a.startsWith("[")) {
            val end = a.indexOf(']')
            return if (end > 0) a.substring(1, end) else null
        }
        val idx = a.lastIndexOf(':')
        if (idx > 0 && a.indexOf(':') == idx) a = a.substring(0, idx)
        return a.ifEmpty { null }
    }
}

/** The Tailscale client version gate (T2): pin 1.104.7, floor
 *  ≥ 1.104.4 — the Tailworm range (TS-2026-014…017) is below the
 *  floor and is refused at setup and at hub join. */
object ClientVersionGate {
    const val PINNED_CLIENT_VERSION = "1.104.7"
    const val MIN_CLIENT_VERSION = "1.104.4"

    fun tryParse(version: String?): IntArray? {
        val v = version?.trim().orEmpty()
        if (v.isEmpty()) return null
        val parts = v.split('.')
        if (parts.size !in 2..4) return null
        val out = IntArray(4)
        for (i in parts.indices) {
            out[i] = parts[i].toIntOrNull()?.takeIf { it >= 0 } ?: return null
        }
        return out
    }

    fun compare(a: IntArray, b: IntArray): Int {
        for (i in 0 until 4) if (a[i] != b[i]) return if (a[i] < b[i]) -1 else 1
        return 0
    }

    /** Floor for admission: a parseable version at or above the floor. */
    fun meetsFloor(version: String?): Boolean {
        val v = tryParse(version) ?: return false
        val floor = tryParse(MIN_CLIENT_VERSION) ?: return false
        return compare(v, floor) >= 0
    }
}

/** ACP's registry of hub nodes — the ACP-side mirror of hub
 *  membership (the hub lane's HubNodeRegistry, Android form).
 *  Joining requires the client floor; decommissioning is
 *  immediate; deletion events from the hub reconcile in.
 *
 *  bd-and-remote F6 fix (2026-11-22): the registry persists when
 *  constructed with a [storeFile] (temp+rename JSON, the house
 *  style) and gains the [reconcile] entry point its doc always
 *  claimed — hub deletion events mark nodes deleted here. With no
 *  file it stays the in-memory form the JVM suite drives. The
 *  client version is still the caller's report at join (the hub's
 *  own node record is the authority — reading it needs the live
 *  Headscale client, a named remainder). */
class HubMembership(private val storeFile: java.io.File? = null) {
    data class Node(
        val deviceId: String, val nodeId: String, val clientVersion: String,
        val joinedAtMs: Long, val deleted: Boolean = false
    )

    private val nodes = mutableMapOf<String, Node>()
    private val eventList = mutableListOf<String>()

    @Volatile var lastJoinRefusal: String? = null
        private set

    init { load() }

    @Synchronized fun events(): List<String> = eventList.toList()

    @Synchronized fun get(deviceId: String): Node? = nodes[deviceId]

    @Synchronized fun isLiveMember(deviceId: String): Boolean =
        nodes[deviceId]?.let { !it.deleted } == true

    /** Hub deletion events reconcile in: every named node id that
     *  is not already deleted is marked deleted and the event is
     *  recorded. Returns how many nodes this call decommissioned. */
    @Synchronized fun reconcile(deletedNodeIds: Collection<String>): Int {
        var changed = 0
        for ((deviceId, node) in nodes.toList()) {
            if (node.nodeId in deletedNodeIds && !node.deleted) {
                nodes[deviceId] = node.copy(deleted = true)
                eventList.add("reconciled_deleted device=$deviceId node=${node.nodeId}")
                changed++
            }
        }
        if (changed > 0) save()
        return changed
    }

    private fun load() {
        val file = storeFile ?: return
        if (!file.exists()) return
        try {
            val root = org.json.JSONObject(file.readText())
            val arr = root.optJSONArray("nodes") ?: return
            for (i in 0 until arr.length()) {
                val o = arr.optJSONObject(i) ?: continue
                val deviceId = o.optString("deviceId"); if (deviceId.isBlank()) continue
                nodes[deviceId] = Node(deviceId, o.optString("nodeId"), o.optString("clientVersion"),
                    o.optLong("joinedAtMs"), o.optBoolean("deleted", false))
            }
        } catch (_: Exception) { /* corrupt registry file: start empty, never fatal */ }
    }

    private fun save() {
        val file = storeFile ?: return
        try {
            val arr = org.json.JSONArray()
            for (n in nodes.values) arr.put(org.json.JSONObject()
                .put("deviceId", n.deviceId).put("nodeId", n.nodeId)
                .put("clientVersion", n.clientVersion).put("joinedAtMs", n.joinedAtMs)
                .put("deleted", n.deleted))
            val parent = file.parentFile
            val bytes = org.json.JSONObject().put("nodes", arr).toString().toByteArray(Charsets.UTF_8)
            if (parent != null) {
                val tmp = java.io.File(parent, file.name + ".tmp")
                java.io.FileOutputStream(tmp).use { out -> out.write(bytes); out.fd.sync() }
                if (!tmp.renameTo(file)) { tmp.delete(); throw IllegalStateException("hub membership: atomic rename failed") }
            } else {
                java.io.FileOutputStream(file).use { out -> out.write(bytes); out.fd.sync() }
            }
        } catch (_: Exception) { /* persistence is best-effort beside the in-memory truth */ }
    }

    /** Join (or re-join) a device. Returns the node id, or null
     *  with [lastJoinRefusal] set — a client below the floor
     *  cannot join, full stop. */
    @Synchronized fun join(deviceId: String, clientVersion: String, nowMs: Long): String? {
        lastJoinRefusal = null
        if (!ClientVersionGate.meetsFloor(clientVersion)) {
            lastJoinRefusal =
                "hub: Tailscale client '$clientVersion' is below the required floor " +
                "${ClientVersionGate.MIN_CLIENT_VERSION} (T2: the Tailworm range is refused at join)."
            eventList.add("join_refused device=$deviceId client=$clientVersion reason=below_floor")
            return null
        }
        val existing = nodes[deviceId]
        val nodeId = existing?.nodeId ?: "node-" + UUID.randomUUID().toString().replace("-", "").substring(0, 12)
        nodes[deviceId] = Node(deviceId, nodeId, clientVersion, nowMs)
        eventList.add("joined device=$deviceId node=$nodeId client=$clientVersion")
        save()
        return nodeId
    }

    @Synchronized fun decommission(deviceId: String): Boolean {
        val node = nodes[deviceId] ?: return false
        nodes[deviceId] = node.copy(deleted = true)
        eventList.add("decommissioned device=$deviceId node=${node.nodeId}")
        save()
        return true
    }
}

/** Opens the byte channel to a peer — the production path is a
 *  real TCP socket; tests inject pipes (sandbox loopback limit). */
fun interface StreamConnector {
    fun open(host: String, port: Int): SocketStreams?
}

object SocketConnector : StreamConnector {
    override fun open(host: String, port: Int): SocketStreams? {
        val socket = Socket()
        return try {
            socket.connect(InetSocketAddress(host, port), 5000)
            SocketStreams(socket.getInputStream(), socket.getOutputStream()) { socket.close() }
        } catch (_: Exception) {
            try { socket.close() } catch (_: Exception) {}
            null
        }
    }
}

/** Shared connect core for the authenticated mesh rungs: gates
 *  first (in the caller's order), socket second, the enrollment
 *  handshake last — a peer that passes every gate still has to
 *  prove possession of an enrolled device key. */
internal fun authenticatedConnect(
    rungId: String,
    gateRefusal: String?,
    target: TransportTarget,
    identity: DeviceIdentity,
    enrollments: io.agenticcontrol.app.enrollment.EnrollmentStore?,
    connector: StreamConnector
): TransportConnectResult {
    if (gateRefusal != null) return TransportConnectResult(false, gateRefusal)
    if (enrollments == null)
        return TransportConnectResult(false, "$rungId: no enrollment store wired — the v2 handshake verifies the host against its enrolled key, so there is nothing to connect with")
    val address = target.address?.trim().orEmpty()
    if (address.isEmpty()) return TransportConnectResult(false, "$rungId: no address for the target device")
    val (host, port) = LanRung.parseAddress(address)
        ?: return TransportConnectResult(false, "$rungId: bad address '$address'")
    if (!MeshAddress.isTailnetAddress(host))
        return TransportConnectResult(false, "$rungId: '$host' is not a tailnet address (100.64.0.0/10 or the fd7a:115c:a1e0::/48 ULA); the $rungId rung never falls back to a LAN address")
    val streams = connector.open(host, port)
        ?: return TransportConnectResult(false, "$rungId: could not connect to $host:$port")
    val expected = target.deviceId.takeIf { !it.equals(identity.deviceId, ignoreCase = true) }
    val result = LanProtocol.clientHandshakeDetailed(streams, identity, enrollments, expected)
    if (result.outcome != LanProtocol.ClientOutcome.CONNECTED) {
        streams.close()
        return TransportConnectResult(false, when (result.outcome) {
            LanProtocol.ClientOutcome.HOST_REFUSED -> "$rungId: host refused our proof of possession"
            LanProtocol.ClientOutcome.NO_CHALLENGE -> "$rungId: no ACP challenge received — the peer did not speak the ACP protocol"
            else -> "$rungId: the peer claimed to be a host but could not prove it — nothing was signed for it"
        })
    }
    return TransportConnectResult(true, "$rungId: connected to $host:$port (mutually authenticated, AEAD channel)", result.channel)
}

/** The `hub` rung: ACP's own Headscale mesh. Membership is checked
 *  against [HubMembership] BEFORE any socket opens. */
class HubRung(
    private val membership: HubMembership,
    private val connector: StreamConnector = SocketConnector
) : AuthenticatedRung {
    override val id: String = "hub"
    override var connectAttempts: Int = 0
        private set

    override fun connect(target: TransportTarget): TransportConnectResult =
        TransportConnectResult(false, "hub: a session connect requires the local device identity (connectSession)")

    override fun connectSession(target: TransportTarget, identity: DeviceIdentity, enrollments: io.agenticcontrol.app.enrollment.EnrollmentStore?): TransportConnectResult {
        connectAttempts++
        val gate = when {
            target.address.isNullOrBlank() ->
                "hub: no hub address for the target device (its tailnet IP on the ACP hub)"
            !membership.isLiveMember(target.deviceId) ->
                "hub: target device ${target.deviceId} is not a live member of the ACP hub (never joined, or decommissioned)"
            else -> null
        }
        return authenticatedConnect(id, gate, target, identity, enrollments, connector)
    }
}

/** The `mesh` rung: the operator's own Tailscale tailnet. Admits
 *  nothing until [MeshSetupFlow] reports Ready — setup state is
 *  the gate, and on Android Ready is reachable only through the
 *  TS-03 operator-personal carve-out. */
class MeshRung(
    private val setupState: () -> MeshSetupState,
    private val connector: StreamConnector = SocketConnector
) : AuthenticatedRung {
    override val id: String = "mesh"
    override var connectAttempts: Int = 0
        private set

    override fun connect(target: TransportTarget): TransportConnectResult =
        TransportConnectResult(false, "mesh: a session connect requires the local device identity (connectSession)")

    override fun connectSession(target: TransportTarget, identity: DeviceIdentity, enrollments: io.agenticcontrol.app.enrollment.EnrollmentStore?): TransportConnectResult {
        connectAttempts++
        val state = setupState()
        val gate = when {
            state.stage != MeshSetupFlow.STAGE_READY ->
                "mesh: the Tailscale setup has not completed on this device (${state.stage}: ${state.detail})"
            target.address.isNullOrBlank() ->
                "mesh: no mesh address for the target device (its tailnet IP)"
            else -> null
        }
        return authenticatedConnect(id, gate, target, identity, enrollments, connector)
    }
}
