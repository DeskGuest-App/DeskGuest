import io.agenticcontrol.app.transport.AddressClass
import io.agenticcontrol.app.transport.ConnectionDoctor
import io.agenticcontrol.app.transport.DoctorFacts
import io.agenticcontrol.app.transport.NatClass
import io.agenticcontrol.app.transport.RungSnapshot
import io.agenticcontrol.app.transport.RungState

/** U6 connection doctor (Android mirror): NAT fixtures, per-rung
 *  honest states, D18 naming, destruction cases. No sockets anywhere
 *  — the doctor is pure classification over snapshot facts. */
private var failures = 0
private fun check(name: String, cond: Boolean) {
    if (cond) println("PASS $name") else { println("FAIL $name"); failures++ }
}
private fun rung(id: String, reg: Boolean = true, conf: Boolean = true, attempts: Int = 0,
                     detail: String? = null, ok: Boolean = false, bound: Boolean = false, phase: String? = null) =
        RungSnapshot(id, reg, conf, attempts, detail, ok, bound, phase, if (bound) "192.168.1.50" else null)

fun main() {
    // NAT fixtures
    check("nat public", ConnectionDoctor.classifyNat(listOf("203.0.113.9")) == NatClass.PUBLIC_DIRECT)
    check("nat private", ConnectionDoctor.classifyNat(listOf("192.168.1.50")) == NatClass.BEHIND_NAT)
    check("nat cgnat", ConnectionDoctor.classifyNat(listOf("100.80.1.2")) == NatClass.CARRIER_GRADE_NAT)
    check("nat tailnet not isp cgnat", ConnectionDoctor.classifyNat(
        listOf("192.168.1.50", "100.119.105.54"), tailnetAddresses = setOf("100.119.105.54")) == NatClass.BEHIND_NAT)
    check("nat double", ConnectionDoctor.classifyNat(listOf("192.168.1.50"), wanAddress = "10.0.0.2") == NatClass.DOUBLE_NAT)
    check("nat unknown", ConnectionDoctor.classifyNat(emptyList()) == NatClass.UNKNOWN)
    check("classify shapes", ConnectionDoctor.classifyAddress("192.168.1.50:47621") == AddressClass.PRIVATE_RFC1918 &&
        ConnectionDoctor.classifyAddress("not-an-address") == AddressClass.NOT_AN_ADDRESS &&
        ConnectionDoctor.classifyAddress("127.0.0.1") == AddressClass.LOOPBACK)

    // Rung states
    val bound = ConnectionDoctor.diagnose(DoctorFacts(listOf("192.168.1.50"), listOf(rung("lan", bound = true, phase = "Bound"))))
    check("bound reachable", bound.rungs[0].state == RungState.REACHABLE && bound.rungs[0].finding == null)
    val failed = ConnectionDoctor.diagnose(DoctorFacts(listOf("192.168.1.50"),
        listOf(rung("lan", attempts = 1, detail = "lan: no address (not discovered, none entered)"))))
    check("failed named reason+fix", failed.rungs[0].state == RungState.FAILED &&
        failed.rungs[0].finding!!.why.contains("no address", true) &&
        failed.rungs[0].finding!!.fix.contains("connect-by-address"))
    val states = ConnectionDoctor.diagnose(DoctorFacts(listOf("192.168.1.50"),
        listOf(rung("tor", reg = false), rung("ownpath", conf = false))))
    check("not-registered + not-configured", states.rungs[0].state == RungState.NOT_REGISTERED &&
        states.rungs[1].state == RungState.NOT_CONFIGURED)

    // Destruction: dead path reported healthy
    val dormant = ConnectionDoctor.diagnose(DoctorFacts(listOf("192.168.1.50"),
        listOf(rung("lan"), rung("mesh", phase = "NoAddress"))))
    check("dormant never reachable", dormant.rungs.all { it.state != RungState.REACHABLE } &&
        dormant.rungs[0].evidence.contains("unproven, not confirmed"))
    // Destruction: doctor as probe weapon — classifying a
    // third-party address records no attempt and changes nothing
    val snap = rung("lan")
    val weapon = ConnectionDoctor.diagnose(DoctorFacts(listOf("192.168.1.50"), listOf(snap), peerAddress = "203.0.113.200:47621"))
    check("third-party classification only", weapon.peerNat == NatClass.PUBLIC_DIRECT && snap.connectAttempts == 0)

    // D18
    val d18 = ConnectionDoctor.diagnose(DoctorFacts(listOf("100.80.1.2"),
        listOf(rung("lan", attempts = 1, detail = "lan: Timeout")), peerNat = NatClass.HOSTILE))
    check("d18 named", d18.isD18Corner && d18.summary.contains("D18") && d18.rungs[0].isD18Corner)
    val notD18 = ConnectionDoctor.diagnose(DoctorFacts(listOf("100.80.1.2"),
        listOf(rung("mesh", bound = true, phase = "Bound")), peerNat = NatClass.HOSTILE))
    check("d18 not named when reachable", !notD18.isD18Corner)
    val relay = ConnectionDoctor.diagnose(DoctorFacts(listOf("100.80.1.2"),
        listOf(rung("lan", attempts = 1, detail = "lan: Timeout")), peerNat = NatClass.CARRIER_GRADE_NAT, hasUserOwnedRelay = true))
    check("d18 not named with relay", !relay.isD18Corner)
    val lines = ConnectionDoctor.renderLines(d18)
    check("render names D18", lines.any { it.contains("D18") })

    if (failures > 0) { println("ConnectionDoctorTest: $failures FAILURES"); kotlin.system.exitProcess(1) }
    println("ConnectionDoctorTest: ALL PASS")
}
