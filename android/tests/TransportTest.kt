import io.deskguest.app.enrollment.DeviceIdentity
import io.deskguest.app.enrollment.EnrollmentStore
import io.deskguest.app.roster.RosterStore
import io.deskguest.app.session.SessionStore
import io.deskguest.app.transport.DiscoveryAnnouncement
import io.deskguest.app.transport.DiscoveryService
import io.deskguest.app.transport.LanProtocol
import io.deskguest.app.transport.SocketStreams
import io.deskguest.app.transport.StubRung
import io.deskguest.app.transport.TransportConnectResult
import io.deskguest.app.transport.TransportSessionManager
import io.deskguest.app.transport.TransportTarget
import java.io.File
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.nio.file.Files
import java.util.Base64

/**
 * JVM tests for Block C transport core (Android half):
 * D19/D20 local discovery + connect-by-address, D29/D32 the
 * rung-agnostic failover engine and group transport-set guards,
 * and the destruction battery for the lane (unauthenticated LAN
 * attempts, discovery spoofing, failover downgrade, dormant-rung
 * probes, set-editing bypass, reconnect loops).
 *
 * Socket note: JVM-originated loopback TCP connects are reset in
 * this sandbox (standing environment fact), so the handshake is
 * driven over in-memory pipes — the exact LanProtocol code the
 * LanRung/LanHostListener socket classes run. The Windows half
 * proves the same protocol over real sockets.
 */
private var failures = 0

private fun check(name: String, condition: Boolean) {
    if (condition) println("PASS  $name") else { println("FAIL  $name"); failures++ }
}

private var clockNow = 1_700_100_000_000L
private fun tick(): Long { clockNow += 1_000L; return clockNow }

private class TransportWorld(dir: File, tag: String, groupSet: List<String> = listOf("lan", "hub", "tor")) {
    val enrollment = EnrollmentStore(File(dir, "$tag-enroll.tsv"))
    val roster = RosterStore(File(dir, "$tag-roster.tsv"), enrollment)
    val sessions = SessionStore(File(dir, "$tag-sessions.tsv"), roster, enrollment) { tick() }
    val hostDeviceId: String
    val hostIdentity: DeviceIdentity
    val operatorIdentity: DeviceIdentity

    init {
        roster.addScope(RosterStore.Scope("co", "company", "Acme Co"))
        roster.addUser(RosterStore.User("admin1", "co", "Admin One", "human"))
        roster.addCompanyAdmin("co", "admin1")
        roster.addUser(RosterStore.User("host1", "co", "Host User", "human"))
        roster.addUser(RosterStore.User("user1", "co", "User One", "human"))
        roster.addUser(RosterStore.User("ai1", "co", "Helper AI", "ai", pairedByUserId = "user1"))
        roster.addUserGroup(
            RosterStore.UserGroup("ug1", "co", "Techs", memberUserIds = setOf("user1")), "admin1")
        roster.addDeviceGroup(RosterStore.DeviceGroup("dg1", "co", "Fleet", groupSet), "admin1")
        roster.addGrant(RosterStore.Grant("co", "ug1", "dg1", setOf("use")), "admin1")
        hostIdentity = DeviceIdentity.generate()
        enrollment.redeem(
            enrollment.mint("company", "dg1", "Fleet"),
            EnrollmentStore.EnrollingDevice(hostIdentity.deviceId, hostIdentity.publicKeyBase64, "Host Device"))
        hostDeviceId = hostIdentity.deviceId
        operatorIdentity = DeviceIdentity.generate()
        enrollment.redeem(
            enrollment.mint("company", "dg1", "Fleet"),
            EnrollmentStore.EnrollingDevice(operatorIdentity.deviceId, operatorIdentity.publicKeyBase64, "Operator Device"))
    }

    fun manager(vararg rungs: io.deskguest.app.transport.TransportRung, identity: DeviceIdentity? = null): TransportSessionManager {
        var n = 0
        // W3 lane B sibling repair (disclosed): the manager now takes
        // the enrollment store (transport v2 mutual authentication).
        return TransportSessionManager(roster, sessions, rungs.toList(), identity, enrollment) { "ts-${tagCounter()}-${n++}" }
    }
}

private var tagSeq = 0
private fun tagCounter(): Int = ++tagSeq

/** Run the host half of the handshake on a thread over pipes;
 *  returns the connected client streams + a result holder. */
private class PipeHandshake(val enrollments: EnrollmentStore, val hostIdentity: DeviceIdentity) {
    val clientToHostOut = PipedOutputStream()
    val clientToHostIn = PipedInputStream(clientToHostOut)
    val hostToClientOut = PipedOutputStream()
    val hostToClientIn = PipedInputStream(hostToClientOut)
    val client = SocketStreams(hostToClientIn, clientToHostOut)
    val host = SocketStreams(clientToHostIn, hostToClientOut)
    @Volatile var hostResult: String? = "PENDING"
    val thread = Thread {
        hostResult = try { LanProtocol.hostHandshake(host, enrollments, hostIdentity)?.first ?: "REFUSED" } catch (e: Exception) { "ERROR:${e.javaClass.simpleName}" }
    }.apply { isDaemon = true; start() }
}

fun main() {
    val dir = Files.createTempDirectory("deskguest-transport-test").toFile()

    // ---- failover engine: order + dormancy (D29/D32) ----
    run {
        val w = TransportWorld(dir, "order")
        val lan = StubRung.failing("lan"); val hub = StubRung.succeeding("hub"); val tor = StubRung.succeeding("tor")
        val mgr = w.manager(lan, hub, tor)
        val s = mgr.startSession("co", w.hostDeviceId, "user1", "host1", "unattended", emptyMap())
        check("D32 engine walks the group set in order; first success carries the session (rung=hub)",
            s != null && s.transportRung == "hub" && s.state == "active")
        check("D29 non-primary rungs stay dormant when an earlier rung carries (tor untouched)",
            tor.isDormant && tor.connectAttempts == 0)
    }
    run {
        val w = TransportWorld(dir, "pin")
        val lan = StubRung.succeeding("lan"); val tor = StubRung.succeeding("tor")
        val mgr = w.manager(lan, StubRung.succeeding("hub"), tor)
        val s = mgr.startSession("co", w.hostDeviceId, "user1", "host1", "unattended", emptyMap(), manualPins = listOf("tor"))
        check("D29/D32 manual pin attempts only the pin", s != null && s.transportRung == "tor" && lan.connectAttempts == 0)
        val refused = mgr.startSession("co", w.hostDeviceId, "user1", "host1", "unattended", emptyMap(), manualPins = listOf("ownpath"))
        check("D32 a manual pin outside the group's set is refused wholesale",
            refused == null && mgr.events().any { it.kind == "start_refused" })
    }

    // ---- failover re-establishment: end + new-start linkage (D29) ----
    run {
        val w = TransportWorld(dir, "failover")
        val mgr = w.manager(StubRung.succeeding("lan"), StubRung.succeeding("hub"), StubRung.succeeding("tor"))
        val first = mgr.startSession("co", w.hostDeviceId, "user1", "host1", "unattended", emptyMap())
        check("failover setup: session active on lan", first != null && first.transportRung == "lan")
        val next = mgr.reestablish(first!!.id, emptyMap())
        check("D29 re-establish: old session ENDS (transport_failover), new session starts on the next rung",
            next != null && next.id != first.id && next.transportRung == "hub" && next.state == "active" &&
                w.sessions.session(first.id)?.state == "ended" &&
                w.sessions.session(first.id)?.endReason == SessionStore.REASON_TRANSPORT_FAILOVER)
        check("D29 re-establish linkage is an event naming the previous session",
            w.sessions.events(next!!.id).any { it.type == SessionStore.EVENT_TRANSPORT_FAILOVER && it.detail.contains(first.id) } &&
                mgr.events().any { it.kind == "session_reestablished" && it.fromSessionId == first.id && it.toSessionId == next.id })
    }
    run {
        val w = TransportWorld(dir, "floor", listOf("lan"))
        val mgr = w.manager(StubRung.succeeding("lan"))
        val first = mgr.startSession("co", w.hostDeviceId, "user1", "host1", "unattended", emptyMap())
        val next = mgr.reestablish(first!!.id, emptyMap())
        // W3 lane B sibling repair (disclosed): bd-and-remote F9 —
        // the old check pinned the DEFECT (the event said "the
        // session ends" while the session stayed live). The fixed
        // behavior: exhaustion ENDS the session, reason recorded.
        check("D32 failover floor (F9): with no next rung the session ENDS (transport_failover) rather than dangling live outside its set",
            next == null && w.sessions.session(first.id)?.state == "ended" &&
                w.sessions.session(first.id)?.endReason == SessionStore.REASON_TRANSPORT_FAILOVER &&
                mgr.events().any { it.kind == "failover_exhausted" })
    }

    // ---- LAN handshake over pipes: the real protocol code ----
    run {
        val w = TransportWorld(dir, "hs")
        val pipe = PipeHandshake(w.enrollment, w.hostIdentity)
        val ok = LanProtocol.clientHandshake(pipe.client, w.operatorIdentity, w.enrollment, w.hostDeviceId)
        pipe.thread.join(3000)
        check("LAN handshake v2: mutual proof + AEAD channel established for an enrolled pair",
            ok && pipe.hostResult == w.operatorIdentity.deviceId)
    }

    // ---- destruction: unauthenticated + spoofed + revoked ----
    run {
        val w = TransportWorld(dir, "atk-unauth")
        val pipe = PipeHandshake(w.enrollment, w.hostIdentity)
        val chal = LanProtocol.readLine(pipe.client.input) // the host challenges first
        check("DESTRUCTION unauthenticated attempt is challenged before any verdict", chal?.startsWith("CHAL2 ") == true)
        LanProtocol.writeLine(pipe.client.output, "HELLO2 nobody AAAA")
        pipe.thread.join(3000)
        check("DESTRUCTION unauthenticated LAN attempt is refused and dropped",
            pipe.hostResult == "REFUSED")
    }
    run {
        val w = TransportWorld(dir, "atk-spoof")
        // Hostile announcer claims the victim's hash in discovery…
        val spoof = DiscoveryAnnouncement.forDevice(w.hostDeviceId, "Host Device", true)!!
        val svc = DiscoveryService(emptyList())
        check("DESTRUCTION discovery spoof buys only an 'available to enroll' listing, never control",
            svc.classify(spoof).availableToEnroll && !svc.classify(spoof).isControllable)
        // …then tries to BE the victim, signing with its own key.
        val attacker = DeviceIdentity.generate()
        val pipe = PipeHandshake(w.enrollment, w.hostIdentity)
        val chal = LanProtocol.readLine(pipe.client.input)!!
        val parts = chal.split(' ')
        val hostNonce = parts[2]
        val hostEph = parts[3]
        val b64 = Base64.getEncoder()
        val clientNonce = b64.encodeToString(ByteArray(32) { (it * 7 + 1).toByte() })
        val clientEph = b64.encodeToString(ByteArray(32) { (it * 3 + 2).toByte() })
        val forged = attacker.sign(LanProtocol.clientProofMessage(
            w.hostDeviceId, w.hostDeviceId, hostNonce, clientNonce, hostEph, clientEph))
        LanProtocol.writeLine(pipe.client.output,
            "HELLO2 ${w.hostDeviceId} $clientNonce $clientEph ${b64.encodeToString(forged)}")
        val verdict = LanProtocol.readLine(pipe.client.input)
        pipe.thread.join(3000)
        check("DESTRUCTION spoofed proof-of-possession (victim id, attacker key) is refused",
            verdict == "REFUSE" && pipe.hostResult == "REFUSED")
    }
    run {
        val w = TransportWorld(dir, "atk-revoked")
        check("setup: revoke the operator device", w.enrollment.revoke(w.operatorIdentity.deviceId))
        val pipe = PipeHandshake(w.enrollment, w.hostIdentity)
        val ok = LanProtocol.clientHandshake(pipe.client, w.operatorIdentity, w.enrollment, w.hostDeviceId)
        pipe.thread.join(3000)
        check("DESTRUCTION a revoked device's proof is refused", !ok && pipe.hostResult == "REFUSED")
    }
    run {
        val w = TransportWorld(dir, "atk-downgrade", listOf("lan", "hub"))
        val tor = StubRung.succeeding("tor")
        val mgr = w.manager(StubRung.failing("lan"), StubRung.failing("hub"), tor)
        val s = mgr.startSession("co", w.hostDeviceId, "user1", "host1", "unattended", emptyMap())
        check("DESTRUCTION failover downgrade: killing every in-set rung never fails over to an out-of-set rung",
            s == null && tor.connectAttempts == 0)
    }
    run {
        val w = TransportWorld(dir, "atk-loop")
        val mgr = w.manager(StubRung.succeeding("lan"), StubRung.succeeding("hub"), StubRung.succeeding("tor"))
        var cur = mgr.startSession("co", w.hostDeviceId, "user1", "host1", "unattended", emptyMap())!!
        repeat(2) { cur = mgr.reestablish(cur.id, emptyMap())!! }
        val exhausted = mgr.reestablish(cur.id, emptyMap())
        val again = mgr.reestablish(cur.id, emptyMap())
        // W3 lane B sibling repair (disclosed): bd-and-remote F9 —
        // exhaustion now ENDS the session (see the floor check);
        // a dead-end stays a dead-end because the ended session
        // has no live link to re-establish.
        check("DESTRUCTION reconnect loops terminate: a dead-end stays a dead-end, no resurrection loop",
            exhausted == null && again == null && w.sessions.session(cur.id)?.state == "ended")
    }

    // ---- group transport-set editing guards (D31/D32) ----
    run {
        val w = TransportWorld(dir, "setedit")
        check("D32 set change by a group admin lands and resolution follows",
            w.roster.setGroupTransports("co", "dg1", listOf("tor", "lan"), "admin1") &&
                w.roster.effectiveTransportsFor("co", w.hostDeviceId) == listOf("tor", "lan"))
        check("D31/D32 set change by a non-admin member is refused",
            !w.roster.setGroupTransports("co", "dg1", listOf("lan"), "user1"))
        check("D9/D32 set change by an AI is refused",
            !w.roster.setGroupTransports("co", "dg1", listOf("lan"), "ai1"))
        check("D32 set change naming an unknown rung is refused",
            !w.roster.setGroupTransports("co", "dg1", listOf("lan", "bogus"), "admin1"))
        check("D31 company ceiling caps the set after an admin widens it",
            w.roster.setCompanyCeiling("co", listOf("lan"), "admin1") &&
                w.roster.effectiveTransportsFor("co", w.hostDeviceId) == listOf("lan"))
    }

    // ---- discovery codec + classification (D19/D20) ----
    run {
        val a = DiscoveryAnnouncement.forDevice("device-abc", "Site PC", enrolled = true)!!
        val wire = a.encode()
        check("D19/D20 announcement carries only hash+name+state (the device id never broadcasts)",
            !wire.contains("device-abc") && DiscoveryAnnouncement.decode(wire) == a)
        check("D20 hostile datagrams refuse wholesale",
            DiscoveryAnnouncement.decode("DESKGUEST1|zzzz|enrolled|U2l0ZSBQQw==") == null &&
                DiscoveryAnnouncement.decode("XXXX|${"a".repeat(64)}|enrolled|U2l0ZSBQQw==") == null &&
                DiscoveryAnnouncement.decode("DESKGUEST1|${"a".repeat(64)}|controllable|U2l0ZSBQQw==") == null &&
                DiscoveryAnnouncement.decode("") == null && DiscoveryAnnouncement.decode(null) == null)
        val w = TransportWorld(dir, "disc")
        val svc = DiscoveryService(listOf(w.hostDeviceId))
        val known = svc.classify(DiscoveryAnnouncement.forDevice(w.hostDeviceId, "Host Device", true)!!)
        val stranger = svc.classify(DiscoveryAnnouncement.forDevice("other-device", "Spare", false)!!)
        check("D20 classification: known peer recognized by hash; unpaired is available-to-enroll only; neither is controllable",
            known.isKnownPeer && !known.availableToEnroll && !known.isControllable &&
                !stranger.isKnownPeer && stranger.availableToEnroll && !stranger.isControllable)
    }

    // ---- wiring facade (PlatformStores) ----
    run {
        val stores = io.deskguest.app.wiring.PlatformStores(File(dir, "facade"))
        val refused = stores.startTransportSession("nope", "no-device", "nobody", "nohost", "unattended")
        check("Wiring facade: a transport start against an empty store refuses honestly and records the engine event",
            refused == null && stores.transportEvents().any { it.kind == "start_refused" })
        check("Wiring facade: re-establishing an unknown session returns null, never a fabricated session",
            stores.reestablishTransportSession("no-such-session") == null)
    }
    run {
        val stores = io.deskguest.app.wiring.PlatformStores(File(dir, "facade-disc"))
        val own = stores.ownAnnouncement("Facade Phone")
        check("Wiring facade: own announcement carries this device's hash + name + available state (not yet enrolled)",
            own != null && own.deviceIdHash == DiscoveryAnnouncement.hashDeviceId(stores.ownDeviceId()) &&
                own.displayName == "Facade Phone" && own.enrollmentState == DiscoveryAnnouncement.STATE_AVAILABLE)
        check("Wiring facade: an unannounceable name (control characters) builds no announcement",
            stores.ownAnnouncement("bad\u0001name") == null)
        val svc = stores.discoveryService()
        val heard = svc.classify(DiscoveryAnnouncement.forDevice("some-unpaired-device", "Spare", false)!!)
        check("Wiring facade: discovery classification marks an unpaired device available-to-enroll and never controllable",
            heard.availableToEnroll && !heard.isControllable)
    }

    dir.deleteRecursively()
    println(if (failures == 0) "ALL TRANSPORT TESTS PASSED" else "$failures TRANSPORT TEST(S) FAILED")
    if (failures > 0) kotlin.system.exitProcess(1)
}
