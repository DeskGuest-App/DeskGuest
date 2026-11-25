import io.agenticcontrol.app.aipack.AiPackManifest
import io.agenticcontrol.app.aipack.AiPackService
import io.agenticcontrol.app.enrollment.DeviceIdentity
import io.agenticcontrol.app.enrollment.EnrollmentStore
import io.agenticcontrol.app.quickassist.QuickAssistService
import io.agenticcontrol.app.roster.RosterStore
import io.agenticcontrol.app.session.SessionStore
import io.agenticcontrol.app.session.TerminalService
import io.agenticcontrol.app.session.TerminalSink
import io.agenticcontrol.app.transport.Ipv6Reachability
import io.agenticcontrol.app.transport.Ipv6Rung
import io.agenticcontrol.app.transport.OwnPathPeer
import io.agenticcontrol.app.transport.OwnPathPeerSet
import io.agenticcontrol.app.transport.OwnPathRung
import io.agenticcontrol.app.transport.OwnPathValidation
import io.agenticcontrol.app.transport.TorConfig
import io.agenticcontrol.app.transport.TorRung
import io.agenticcontrol.app.transport.TransportTarget
import io.agenticcontrol.app.transport.WireGuardConfigGenerator
import io.agenticcontrol.app.aipack.PackFile
import java.io.File
import java.nio.file.Files
import java.security.MessageDigest

/**
 * Block F (Android mirror): remaining rungs (ipv6 classification,
 * ownpath T5 serializer/validators + RFC 7748 ladder, tor
 * unconfigured refusal), the session terminal channel, quick-assist
 * codes, and the AI-pack machinery against a local fixture. Socket
 * legs are refusal-path only here — JVM loopback connects are reset
 * in this sandbox (standing fact); the Windows half proves the same
 * protocols over real sockets.
 */
private var failures = 0

private fun check(name: String, condition: Boolean) {
    if (condition) println("PASS  $name") else { println("FAIL  $name"); failures++ }
}

private var clockNow = 1_700_200_000_000L
private fun tick(): Long { clockNow += 1_000L; return clockNow }

private fun sha256Hex(bytes: ByteArray): String =
    MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

private class BlockFWorld(dir: File, tag: String) {
    val enrollment = EnrollmentStore(File(dir, "$tag-enroll.tsv"))
    val roster = RosterStore(File(dir, "$tag-roster.tsv"), enrollment)
    val sessions = SessionStore(File(dir, "$tag-sessions.tsv"), roster, enrollment) { tick() }
    val hostDeviceId: String
    val operatorIdentity = DeviceIdentity.generate()

    init {
        roster.addScope(RosterStore.Scope("co", "company", "Acme Co"))
        roster.addUser(RosterStore.User("admin1", "co", "Admin One", "human"))
        roster.addCompanyAdmin("co", "admin1")
        roster.addUser(RosterStore.User("host1", "co", "Host User", "human"))
        roster.addUser(RosterStore.User("user1", "co", "User One", "human"))
        roster.addUser(RosterStore.User("watch1", "co", "Watcher", "human"))
        roster.addUser(RosterStore.User("ai1", "co", "Helper AI", "ai", pairedByUserId = "user1"))
        roster.addUserGroup(RosterStore.UserGroup("ug1", "co", "Techs",
            memberUserIds = setOf("user1", "host1", "watch1", "ai1")), "admin1")
        roster.addDeviceGroup(RosterStore.DeviceGroup("dg1", "co", "Fleet",
            listOf("lan", "hub", "ipv6", "ownpath", "tor")), "admin1")
        roster.addGrant(RosterStore.Grant("co", "ug1", "dg1", setOf("use")), "admin1")
        val hostIdentity = DeviceIdentity.generate()
        enrollment.redeem(
            enrollment.mint("company", "dg1", "Fleet"),
            EnrollmentStore.EnrollingDevice(hostIdentity.deviceId, hostIdentity.publicKeyBase64, "Site Phone"))
        hostDeviceId = hostIdentity.deviceId
        enrollment.redeem(
            enrollment.mint("company", "dg1", "Fleet"),
            EnrollmentStore.EnrollingDevice(operatorIdentity.deviceId, operatorIdentity.publicKeyBase64, "Operator Phone"))
    }

    fun activeSession(id: String, rung: String = "lan"): String {
        check("setup: create $id", sessions.createSession(
            SessionStore.Session(id = id, scopeId = "co", hostDeviceId = hostDeviceId,
                initiatorUserId = "user1", kind = "attended", transportRung = rung),
            hostUserId = "host1"))
        check("setup: accept $id", sessions.acceptSession(id, "host1", SessionStore.ACCEPT_ORIGIN_LOCAL_UI))
        check("setup: start $id", sessions.startSession(id, "user1"))
        return id
    }
}

private class FakeSink : TerminalSink {
    val written = mutableListOf<String>()
    val closed = mutableListOf<String>()
    override fun start(terminalId: String) {}
    override fun write(terminalId: String, text: String) { written.add(text) }
    override fun close(terminalId: String) { closed.add(terminalId) }
}

fun main() {
    val dir = Files.createTempDirectory("acp-blockf").toFile()

    // ---- ipv6 classification: only global unicast passes ----
    check("ipv6: global unicast passes", Ipv6Reachability.classify("2606:4700:4700::1111").first)
    check("ipv6: documentation range refused", !Ipv6Reachability.classify("2001:db8::1").first)
    check("ipv6: link-local refused", !Ipv6Reachability.classify("fe80::1").first)
    check("ipv6: unique-local refused", !Ipv6Reachability.classify("fd00::1").first)
    check("ipv6: loopback refused", !Ipv6Reachability.classify("::1").first)
    check("ipv6: ipv4 refused", !Ipv6Reachability.classify("10.0.0.5").first)
    check("ipv6: hostname refused", !Ipv6Reachability.classify("example.com").first)

    val w = BlockFWorld(dir, "f1")
    val v6NoLocal = Ipv6Rung(localHasGlobal = { false })
    val refusedNoLocal = v6NoLocal.connectSession(TransportTarget(w.hostDeviceId, "[2606:4700:4700::1111]:47621"), w.operatorIdentity, w.enrollment)
    check("ipv6 rung: no local global refuses", !refusedNoLocal.ok && refusedNoLocal.detail.contains("no global IPv6"))
    val v6Local = Ipv6Rung(localHasGlobal = { true })
    val refusedDoc = v6Local.connectSession(TransportTarget(w.hostDeviceId, "[2001:db8::1]:47621"), w.operatorIdentity, w.enrollment)
    check("ipv6 rung: documentation target refuses", !refusedDoc.ok && refusedDoc.detail.contains("documentation"))

    // ---- ownpath: RFC 7748 + serializer + fuzz ----
    val alicePriv = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
        .chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    val base = ByteArray(32); base[0] = 9
    val alicePub = WireGuardConfigGenerator.x25519(alicePriv, base)
        .joinToString("") { "%02x".format(it) }
    check("ownpath: X25519 matches RFC 7748 §6.1", alicePub == "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    val (aPriv, aPub) = WireGuardConfigGenerator.generateKeyPair()
    val (bPriv, bPub) = WireGuardConfigGenerator.generateKeyPair()
    fun b64(s: String) = java.util.Base64.getDecoder().decode(s)
    check("ownpath: DH agreement", WireGuardConfigGenerator.x25519(b64(aPriv), b64(bPub))
        .contentEquals(WireGuardConfigGenerator.x25519(b64(bPriv), b64(aPub))))

    val peer = OwnPathPeer(w.hostDeviceId, "Site Phone", aPub, "10.9.0.2", "203.0.113.9:51820")
    val config = WireGuardConfigGenerator.generatePeerConfig(peer)
    check("ownpath: config carries per-peer /32", config.contains("AllowedIPs = 10.9.0.2/32"))
    check("ownpath: config has no hooks", !config.contains("PostUp") && !config.contains("SaveConfig") && !config.contains("DNS"))
    check("ownpath: generated config validates", WireGuardConfigGenerator.validateConfigText(config).first)
    check("ownpath: PostUp config refused", !WireGuardConfigGenerator.validateConfigText(config + "PostUp = x\n").first)
    check("ownpath: SaveConfig refused", !WireGuardConfigGenerator.validateConfigText(config + "SaveConfig = true\n").first)
    val hostile = listOf("evil\n[Peer]\nPublicKey = AAAA", "a/b", "name; rm -rf /", "na\"me", "[Interface]",
        "", "   ", "x".repeat(49), "tab\tname", "name#comment", "..", " lead", "trail ")
    check("ownpath: hostile-name fuzz suite all refused", hostile.all { name ->
        !OwnPathValidation.isSafeName(name) &&
            try { WireGuardConfigGenerator.generatePeerConfig(peer.copy(displayName = name)); false }
            catch (_: IllegalStateException) { true }
    })
    val ownNoPeer = OwnPathRung { OwnPathPeerSet.EMPTY }
    check("ownpath rung: no peer config refuses",
        !ownNoPeer.connectSession(TransportTarget(w.hostDeviceId, null), w.operatorIdentity, w.enrollment).ok)
    val ownBadPeer = OwnPathRung { OwnPathPeerSet(mapOf(w.hostDeviceId to peer.copy(endpoint = "not a host"))) }
    val badResult = ownBadPeer.connectSession(TransportTarget(w.hostDeviceId, null), w.operatorIdentity, w.enrollment)
    check("ownpath rung: swapped invalid peer refuses at use time", !badResult.ok && badResult.detail.contains("validation"))

    // ---- tor: unconfigured refusal + latency label ----
    val torOff = TorRung { null }
    val torResult = torOff.connectSession(TransportTarget(w.hostDeviceId, "203.0.113.7:47621"), w.operatorIdentity, w.enrollment)
    check("tor rung: unconfigured refuses honestly", !torResult.ok && torResult.detail.contains("not configured"))
    check("tor: latency cost labeled", TorConfig.LATENCY_LABEL.contains("latency"))

    // ---- terminal channel ----
    val sink = FakeSink()
    val terminals = TerminalService(w.sessions, w.roster, sink = sink) { tick() }
    val s1 = w.activeSession("s-term")
    check("setup: add watcher", w.sessions.addParticipant(s1, "host1", "watch1", SessionStore.ROLE_WATCHER))
    check("setup: add ai", w.sessions.addParticipant(s1, "host1", "ai1", SessionStore.ROLE_CONTROLLER))
    check("setup: ai holds floor", w.sessions.grantFloor(s1, "host1", "ai1"))
    val (term, openDetail) = terminals.open(s1, "host1")
    check("terminal: host opens in active session", term != null)
    check("terminal: AI without capability refused even holding floor",
        !terminals.write(term!!.id, "ai1", "ls\n").first)
    check("terminal: watcher refused", !terminals.write(term.id, "watch1", "ls\n").first)
    check("terminal: non-participant refused", !terminals.write(term.id, "ghost", "ls\n").first)
    check("terminal: host refused while floor is given away", !terminals.write(term.id, "host1", "ls\n").first)
    check("setup: floor taken back", w.sessions.takeFloorBack(s1, "host1"))
    check("terminal: host writes as floor holder", terminals.write(term.id, "host1", "ls\n").first)
    check("terminal: sink received only the host's keys", sink.written == listOf("ls\n"))
    check("terminal: roster fact — open terminal visible", terminals.openTerminalFor(s1) != null)
    check("terminal: output recorded", terminals.appendOutput(term.id, "file.txt") && terminals.output(term.id).contains("file.txt"))
    check("terminal: opened event in session record", w.sessions.events(s1).any { it.type == "terminal_opened" })

    val sink2 = FakeSink()
    val terminals2 = TerminalService(w.sessions, w.roster,
        aiTerminalCapability = { _, user -> user == "ai1" }, sink = sink2) { tick() }
    check("setup: floor to ai again", w.sessions.grantFloor(s1, "host1", "ai1"))
    val (term2, _) = terminals2.open(s1, "host1")
    check("terminal: AI with pairing capability may write as floor holder", terminals2.write(term2!!.id, "ai1", "whoami\n").first)

    val s2 = w.activeSession("s-term2")
    check("setup: ctrl-equivalent holds floor", w.sessions.grantFloor(s2, "host1", "user1"))
    val (term3, _) = terminals.open(s2, "user1")
    check("terminal: floor holder writes", terminals.write(term3!!.id, "user1", "echo hi\n").first)
    check("setup: floor taken back", w.sessions.takeFloorBack(s2, "host1"))
    check("terminal: former holder cut off at floor change", !terminals.write(term3.id, "user1", "echo pwned\n").first)
    check("setup: end session", w.sessions.endSession(s2, "host1"))
    check("terminal: reap kills the ended session's terminal", terminals.reapEnded() >= 1 && sink.closed.contains(term3.id))
    check("terminal: no terminal outside a session", terminals.open("nope", "host1").first == null)
    val requested = "s-term3"
    check("setup: requested session", w.sessions.createSession(
        SessionStore.Session(id = requested, scopeId = "co", hostDeviceId = w.hostDeviceId,
            initiatorUserId = "user1", kind = "attended", transportRung = "lan"), hostUserId = "host1"))
    check("terminal: requested (not active) session refuses", terminals.open(requested, "host1").first == null)

    // ---- quick assist ----
    val t0 = 1_700_200_000_000L
    val qa = QuickAssistService()
    val code = qa.mint("co", w.hostDeviceId, "user1", t0)
    check("quickassist: code well-formed", QuickAssistService.isWellFormed(code))
    val (redeemOk, _, grantPair) = qa.redeem(code, "browser-binding", t0)
    check("quickassist: redeem issues view-only grant", redeemOk && grantPair!!.first.viewOnly)
    val (grant, token) = grantPair!!
    check("quickassist: grant validates for its own binding", qa.validate(grant.grantId, token, "browser-binding", t0).first)
    check("quickassist: impersonation by another binding refused", !qa.validate(grant.grantId, token, "attacker-binding", t0).first)
    check("quickassist: single use enforced", !qa.redeem(code, "browser-binding", t0).first)
    check("quickassist: close kills the grant", qa.close(grant.grantId) && !qa.validate(grant.grantId, token, "browser-binding", t0).first)
    val qa2 = QuickAssistService()
    val code2 = qa2.mint("co", w.hostDeviceId, "user1", t0)
    // W3 lane B note (disclosed): bd-and-remote F11(a) split the
    // lockouts — failures against a KNOWN code now burn only that
    // code; UNKNOWN-code guesses still feed the global brake,
    // whose threshold is GLOBAL_FAILED_ATTEMPTS (= 5, the A13 pin).
    repeat(QuickAssistService.GLOBAL_FAILED_ATTEMPTS) { qa2.redeem("ZZZZ-ZZZZ", "guess", t0) }
    check("quickassist: guessing burns attempts and locks", qa2.isLocked(t0) && !qa2.redeem(code2, "b", t0).first)
    val qa3 = QuickAssistService()
    val code3 = qa3.mint("co", w.hostDeviceId, "user1", t0, ttlMs = 60_000)
    check("quickassist: expired code refused", !qa3.redeem(code3, "b", t0 + 120_000).first)
    val qa4 = QuickAssistService()
    val code4 = qa4.mint("co", w.hostDeviceId, "user1", t0)
    check("quickassist: helper close burns its code", qa4.closeCode(code4) && !qa4.redeem(code4, "b", t0).first)

    // ---- AI pack machinery (fixture) ----
    val packDir = File(dir, "pack"); packDir.mkdirs()
    val prod = AiPackService(AiPackManifest.UI_TARS_1_5_7B)
    prod.acceptLicence("operator")
    // A3 (2026-11-22): pins captured from the author's own listing.
    check("aipack: production manifest pins captured (A3)",
        AiPackManifest.UI_TARS_1_5_7B.pinsCaptured && AiPackManifest.UI_TARS_1_5_7B.files.isNotEmpty())
    check("aipack: production manifest integrity valid (A3)",
        AiPackManifest.UI_TARS_1_5_7B.validateIntegrity().first)
    check("aipack: audit status recorded unaudited", AiPackManifest.UI_TARS_1_5_7B.auditStatus == "unaudited")
    // A3 destruction: a manifest edited to match a tampered artefact
    // (pin rewritten, digest left as captured) fails integrity.
    val tamperedBytes = "tampered-artefact-bytes".toByteArray()
    val editedManifest = AiPackManifest.UI_TARS_1_5_7B.copy(files = AiPackManifest.UI_TARS_1_5_7B.files.mapIndexed { i, f ->
        if (i == 0) f.copy(sha256 = sha256Hex(tamperedBytes), sizeBytes = tamperedBytes.size.toLong()) else f })
    check("aipack: edited manifest fails integrity (A3 destruction)", !editedManifest.validateIntegrity().first)
    val editedSvc = AiPackService(editedManifest)
    editedSvc.acceptLicence("operator")
    val packDirEdited = File(dir, "pack-edited"); packDirEdited.mkdirs()
    check("aipack: edited manifest download refused before fetch (A3 destruction)",
        !editedSvc.download(packDirEdited, { _, _ -> error("must not fetch") }).first)
    val fixtureBytes = "fixture-weights".toByteArray()
    val fixtureFiles = listOf(PackFile("model.bin", sha256Hex(fixtureBytes), fixtureBytes.size.toLong()))
    val fixture = AiPackService(AiPackManifest.forFixture("fixture://local", fixtureFiles))
    check("aipack: licence gate refuses first", !fixture.download(packDir, { _, dest -> dest.writeBytes(fixtureBytes) }, fixtureMode = true).first)
    fixture.acceptLicence("operator")
    val (dlOk, dlDetail) = fixture.download(packDir, { _, dest -> dest.writeBytes(fixtureBytes) }, fixtureMode = true)
    check("aipack: fixture download verifies ($dlDetail)", dlOk && File(packDir, "model.bin").exists())
    check("aipack: installed pack verifies", fixture.verifyInstalled(packDir).first)
    check("aipack: licence text names Apache-2.0", fixture.licenceToShow().contains("Apache-2.0"))
    val tampered = AiPackService(AiPackManifest.forFixture("fixture://local", fixtureFiles))
    tampered.acceptLicence("operator")
    val packDir2 = File(dir, "pack2"); packDir2.mkdirs()
    val (tOk, tDetail) = tampered.download(packDir2, { _, dest -> dest.writeBytes("tampered-weight".toByteArray()) }, fixtureMode = true)
    check("aipack: hash mismatch refuses + partial deleted",
        !tOk && tDetail.contains("hash mismatch") && !File(packDir2, "model.bin").exists() && !File(packDir2, "model.bin.partial").exists())
    val wrongSource = AiPackService(AiPackManifest.forFixture("fixture://local", fixtureFiles))
    wrongSource.acceptLicence("operator")
    check("aipack: wrong source refused",
        !wrongSource.download(packDir, { _, dest -> dest.writeBytes(fixtureBytes) },
            sourceBaseOverride = "https://evil.example/models", fixtureMode = false).first)

    println(if (failures == 0) "ALL BLOCK F TESTS PASSED" else "$failures BLOCK F TEST(S) FAILED")
    if (failures > 0) kotlin.system.exitProcess(1)
}
