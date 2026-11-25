import io.agenticcontrol.app.adb.AdbClient
import io.agenticcontrol.app.adb.AdbEndpoints
import io.agenticcontrol.app.adb.AdbKey
import io.agenticcontrol.app.adb.AdbPairing
import io.agenticcontrol.app.adb.AdbProtocol
import io.agenticcontrol.app.aipack.AiPackManifest
import io.agenticcontrol.app.aipack.AiPackService
import io.agenticcontrol.app.enrollment.DeviceIdentity
import io.agenticcontrol.app.enrollment.EnrollmentStore
import io.agenticcontrol.app.quickassist.QuickAssistService
import io.agenticcontrol.app.rmm.LicenceFindingKinds
import io.agenticcontrol.app.rmm.LicenceStates
import io.agenticcontrol.app.roster.RosterStore
import io.agenticcontrol.app.transport.AclBuilder
import io.agenticcontrol.app.transport.HubMembership
import io.agenticcontrol.app.transport.LanHostListener
import io.agenticcontrol.app.transport.LanProtocol
import io.agenticcontrol.app.transport.LanRung
import io.agenticcontrol.app.transport.LanSecureChannel
import io.agenticcontrol.app.transport.MeshAddress
import io.agenticcontrol.app.transport.MeshSetupFlow
import io.agenticcontrol.app.transport.MeshSetupState
import io.agenticcontrol.app.transport.SocketStreams
import io.agenticcontrol.app.transport.TorRung
import io.agenticcontrol.app.update.ManifestVerifier
import io.agenticcontrol.app.update.UpdateGuards
import io.agenticcontrol.app.wake.WakeStore
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.nio.file.Files
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.util.Base64
import org.json.JSONObject

/**
 * Wave 3 Lane B regression suite: bd-and-ui + bd-and-remote fixes
 * (2026-11-22). Every check names the finding it pins. Protocol
 * work runs over in-memory pipes (sandbox loopback rule); the ADB
 * transcript is a scripted fake adbd through AdbClient's transport
 * seam — the fake-adbd transcript test the bd-and-ui packet found
 * missing.
 */
private var failures = 0

private fun check(name: String, condition: Boolean) {
    if (condition) println("PASS  $name") else { println("FAIL  $name"); failures++ }
}

private class PipePair {
    val c2hOut = PipedOutputStream(); val c2hIn = PipedInputStream(c2hOut)
    val h2cOut = PipedOutputStream(); val h2cIn = PipedInputStream(h2cOut)
    val client = SocketStreams(h2cIn, c2hOut)
    val host = SocketStreams(c2hIn, h2cOut)
}

/** Enroll a device into a fresh store; returns its identity. */
private fun enrolled(store: EnrollmentStore, group: String = "dg1"): DeviceIdentity {
    val id = DeviceIdentity.generate()
    store.redeem(
        store.mint("company", group, "Fleet"),
        EnrollmentStore.EnrollingDevice(id.deviceId, id.publicKeyBase64, "Dev ${id.deviceId.take(4)}"))
    return id
}

fun main() {
    val dir = Files.createTempDirectory("acp-bdfix2").toFile()
    val b64 = Base64.getEncoder()

    // ============ bd-and-remote F1: transport v2 ============
    run {
        val store = EnrollmentStore(File(dir, "v2-enroll.tsv"))
        val hostId = enrolled(store)
        val clientId = enrolled(store)
        val pipe = PipePair()
        val hostThread = Thread {
            val established = LanProtocol.hostHandshake(pipe.host, store, hostId)
            if (established != null) {
                val line = LanProtocol.readLine(established.second.input)
                LanProtocol.writeLine(established.second.output, if (line == "PING") "PONG" else "ERR")
            }
        }.apply { isDaemon = true; start() }
        val result = LanProtocol.clientHandshakeDetailed(pipe.client, clientId, store, hostId.deviceId)
        check("F1 v2: mutually authenticated handshake connects", result.outcome == LanProtocol.ClientOutcome.CONNECTED)
        val channel = result.channel!!
        LanProtocol.writeLine(channel.output, "PING")
        check("F1 v2: AEAD channel carries traffic both ways", LanProtocol.readLine(channel.input) == "PONG")
        hostThread.join(2000)
    }
    run {
        // MITM substitution: a fake host claims the real host's id
        // but signs CHAL2 with its OWN (unenrolled-for-that-id) key.
        // The client must refuse BEFORE sending its proof.
        val store = EnrollmentStore(File(dir, "v2mitm-enroll.tsv"))
        val hostId = enrolled(store)
        val clientId = enrolled(store)
        val attacker = DeviceIdentity.generate()
        val pipe = PipePair()
        val fakeHost = Thread {
            val nonce = b64.encodeToString(ByteArray(32) { (it + 5).toByte() })
            val eph = b64.encodeToString(ByteArray(32) { (it + 9).toByte() })
            val sig = attacker.sign(LanProtocol.hostProofMessage(hostId.deviceId, nonce, eph))
            LanProtocol.writeLine(pipe.host.output,
                "CHAL2 ${hostId.deviceId} $nonce $eph ${b64.encodeToString(sig)}")
        }.apply { isDaemon = true; start() }
        val result = LanProtocol.clientHandshakeDetailed(pipe.client, clientId, store, hostId.deviceId)
        check("F1 destruction: substituted host key refused as HOST_AUTH_FAILED",
            result.outcome == LanProtocol.ClientOutcome.HOST_AUTH_FAILED)
        check("F1 destruction: client never sent its proof to the substitute",
            pipe.host.input.available() == 0)
        fakeHost.join(2000)
    }
    run {
        // Downgrade: a v1-only peer sends the old CHAL — no session.
        val store = EnrollmentStore(File(dir, "v2down-enroll.tsv"))
        val hostId = enrolled(store)
        val clientId = enrolled(store)
        val pipe = PipePair()
        Thread {
            LanProtocol.writeLine(pipe.host.output, "CHAL abc123")
            Thread.sleep(300)
        }.apply { isDaemon = true; start() }
        val result = LanProtocol.clientHandshakeDetailed(pipe.client, clientId, store, hostId.deviceId)
        check("F1 destruction: a v1 challenge is not a session (no downgrade)",
            result.outcome != LanProtocol.ClientOutcome.CONNECTED)
    }
    run {
        // AEAD frame shape + tamper death.
        val key = ByteArray(32) { (it * 11 + 3).toByte() }
        val out = ByteArrayOutputStream()
        val a = LanSecureChannel(ByteArrayInputStream(ByteArray(0)), out, key, key)
        LanProtocol.writeLine(a.streams.output, "hi")
        val frame = out.toByteArray()
        val declared = ((frame[0].toInt() and 0xFF) shl 24) or ((frame[1].toInt() and 0xFF) shl 16) or
            ((frame[2].toInt() and 0xFF) shl 8) or (frame[3].toInt() and 0xFF)
        check("F1 frame shape: [BE length = ct+16][12B nonce][ct+tag]",
            frame.size == 4 + 12 + 3 + 16 && declared == 3 + 16) // "hi\n" — writeLine adds the newline
        val b = LanSecureChannel(ByteArrayInputStream(frame), ByteArrayOutputStream(), key, key)
        check("F1 frame round-trips", LanProtocol.readLine(b.streams.input) == "hi")
        val tampered = frame.copyOf(); tampered[tampered.size - 1] = (tampered[tampered.size - 1] + 1).toByte()
        val c = LanSecureChannel(ByteArrayInputStream(tampered), ByteArrayOutputStream(), key, key)
        val threw = try { LanProtocol.readLine(c.streams.input); false } catch (e: Exception) { true }
        check("F1 destruction: a tampered frame kills the channel (throws, no plaintext)", threw)
    }
    run {
        // parseAddress (F10) + tailnet ULA (F6 limb).
        check("F10 parseAddress: bare IPv6 gets the default port, brackets stripped",
            LanRung.parseAddress("2001:db8::5") == ("2001:db8::5" to LanProtocol.DEFAULT_PORT))
        check("F10 parseAddress: bracketed IPv6 with port",
            LanRung.parseAddress("[2001:db8::5]:1234") == ("2001:db8::5" to 1234))
        check("F10 parseAddress: host:port and bare host unchanged",
            LanRung.parseAddress("192.168.1.9:47621") == ("192.168.1.9" to 47621) &&
                LanRung.parseAddress("desktop") == ("desktop" to LanProtocol.DEFAULT_PORT))
        check("F6 MeshAddress: Tailscale ULA is tailnet; random ULA is not",
            MeshAddress.isTailnetAddress("fd7a:115c:a1e0::42") && !MeshAddress.isTailnetAddress("fd00::1"))
        check("F8 LanHostListener refuses a wildcard bind",
            try {
                LanHostListener(EnrollmentStore(File(dir, "lh.tsv")), DeviceIdentity.generate())
                    .start(java.net.InetAddress.getByName("0.0.0.0"), 0); false
            } catch (e: IllegalArgumentException) { true })
    }

    // ============ bd-and-remote F2/F6: mesh + hub state ============
    run {
        check("F2 MeshStore accepts tailnet / loopback / RFC1918 companion addresses",
            io.agenticcontrol.app.mesh.MeshUrlPolicy.isAcceptableBaseUrl("http://100.64.0.7:8790") &&
                io.agenticcontrol.app.mesh.MeshUrlPolicy.isAcceptableBaseUrl("http://localhost:8790") &&
                io.agenticcontrol.app.mesh.MeshUrlPolicy.isAcceptableBaseUrl("http://192.168.1.20:8790"))
        check("F2 MeshStore refuses public / credentialed / path-bearing addresses",
            !io.agenticcontrol.app.mesh.MeshUrlPolicy.isAcceptableBaseUrl("http://203.0.113.9:8790") &&
                !io.agenticcontrol.app.mesh.MeshUrlPolicy.isAcceptableBaseUrl("http://user@100.64.0.7:8790") &&
                !io.agenticcontrol.app.mesh.MeshUrlPolicy.isAcceptableBaseUrl("ftp://100.64.0.7"))
        val file = File(dir, "hub.json")
        val m1 = HubMembership(file)
        val nodeId = m1.join("dev-a", "1.104.7", 1_000L)
        val m2 = HubMembership(file)
        check("F6 HubMembership persists across instances",
            nodeId != null && m2.get("dev-a")?.nodeId == nodeId && m2.isLiveMember("dev-a"))
        check("F6 HubMembership.reconcile marks controller-deleted nodes",
            m2.reconcile(listOf(nodeId!!)) == 1 && m2.get("dev-a")?.deleted == true &&
                HubMembership(file).get("dev-a")?.deleted == true)
        val mapping = io.agenticcontrol.app.transport.TailnetMapping(
            userGroups = mapOf("techs" to listOf("alice@example.com")),
            deviceGroups = mapOf("fleet" to "acp-fleet"),
            grants = listOf(io.agenticcontrol.app.transport.TailnetGrant("techs", "fleet", setOf("use"))))
        val acl = AclBuilder.build(mapping, 47621)
        val aclChanged = AclBuilder.build(mapping.copy(
            userGroups = mapOf("techs" to listOf("alice@example.com", "bob@example.com"))), 47621)
        check("F6 AclBuilder output is pretty-printed, so diff shows per-rule changes",
            acl.contains("\n") && acl.contains("group:techs") &&
                AclBuilder.diff(acl, aclChanged).contains("bob@example.com"))
        val seen = mutableListOf<MeshSetupState>()
        val flow = MeshSetupFlow(stateSink = { seen.add(it) })
        flow.runPreSignIn(io.agenticcontrol.app.transport.MeshPlatform.ANDROID,
            io.agenticcontrol.app.transport.MeshRole.OPERATOR,
            carveOutAcknowledged = true,
            clientVersion = io.agenticcontrol.app.transport.ClientVersionGate.PINNED_CLIENT_VERSION)
        check("F6 MeshSetupFlow reports transitions to its sink",
            seen.isNotEmpty() && seen.last() == flow.state &&
                flow.state.stage == MeshSetupFlow.STAGE_AWAITING_SIGN_IN)
        val restoredState = MeshSetupState(MeshSetupFlow.STAGE_AWAITING_SIGN_IN, "restored")
        val restored = MeshSetupFlow(restored = restoredState)
        check("F6 MeshSetupFlow restores persisted state", restored.state == restoredState)
    }

    // ============ bd-and-remote F3: SAS quarantine ============
    run {
        val store = EnrollmentStore(File(dir, "sasq.tsv"))
        val enroller = DeviceIdentity.generate()
        store.localPublicKeyProvider = { enroller.publicKey }
        val dev = enrolled(store)
        val msg = "quarantine-probe".toByteArray()
        val sig = dev.sign(msg)
        check("F3 setup: enrolled signature verifies before any mismatch",
            store.verifyEnrolledSignature(dev.deviceId, msg, sig))
        store.reportSasMismatch(dev.deviceId)
        check("F3 mismatch quarantines admission (signature no longer verifies)",
            !store.verifyEnrolledSignature(dev.deviceId, msg, sig))
        check("F3 quarantine is NOT a revocation (device still enrolled, unconfirmed)",
            store.byId(dev.deviceId) != null && !store.byId(dev.deviceId)!!.revoked &&
                !store.byId(dev.deviceId)!!.sasConfirmed)
        check("F3 quarantine survives a reload", run {
            val reloaded = EnrollmentStore(File(dir, "sasq.tsv"))
            !reloaded.verifyEnrolledSignature(dev.deviceId, msg, sig)
        })
        store.confirmSas(dev.deviceId)
        check("F3 a fresh SAS confirmation lifts the quarantine",
            store.verifyEnrolledSignature(dev.deviceId, msg, sig))
    }

    // ============ bd-and-remote F4: Tor request bytes ============
    run {
        val domain = TorRung.socks5RequestBytes("abcdefghijklmnopqrst.onion", 443)!!
        check("F4 onion names go as SOCKS domain form (ATYP 3), never DNS-resolved",
            domain[3] == 3.toByte() && domain[4] == 26.toByte())
        val v4 = TorRung.socks5RequestBytes("192.0.2.7", 80)!!
        check("F4 literal IPv4 goes as ATYP 1", v4[3] == 1.toByte() && v4.size == 10)
        val v6 = TorRung.socks5RequestBytes("2001:db8::1", 80)!!
        check("F4 literal IPv6 goes as ATYP 4", v6[3] == 4.toByte() && v6.size == 22)
        check("F4 parseLiteralIp rejects names and junk",
            io.agenticcontrol.app.transport.parseLiteralIp("example.com") == null && io.agenticcontrol.app.transport.parseLiteralIp("999.1.1.1") == null &&
                io.agenticcontrol.app.transport.parseLiteralIp("1.2.3.4") != null)
    }

    // ============ bd-and-remote F7: AiPack streaming + licence record ============
    run {
        val svc = AiPackService(AiPackManifest.UI_TARS_1_5_7B)
        var sinkLine: String? = null
        svc.licenceSink = { sinkLine = it }
        svc.acceptLicence("operator-7", nowMs = 4242L)
        check("F7 licence acceptance records WHO and WHEN (was: userId ignored)",
            svc.licenceAcceptedBy == "operator-7" && svc.licenceAcceptedAtMs == 4242L &&
                sinkLine == "licence_accepted pack=${AiPackManifest.UI_TARS_1_5_7B.packId} by=operator-7 atMs=4242")
        val svc2 = AiPackService(AiPackManifest.UI_TARS_1_5_7B)
        check("F7 licence record restores; foreign/garbled records do not",
            svc2.restoreLicenceRecord(sinkLine) && svc2.licenceAcceptedBy == "operator-7" &&
                !AiPackService(AiPackManifest.UI_TARS_1_5_7B).restoreLicenceRecord("licence_accepted pack=other by=x atMs=1") &&
                !AiPackService(AiPackManifest.UI_TARS_1_5_7B).restoreLicenceRecord("nonsense"))
        val big = File(dir, "big.bin")
        val content = ByteArray(2 * 1024 * 1024) { (it % 251).toByte() }
        big.writeBytes(content)
        val expected = MessageDigest.getInstance("SHA-256").digest(content)
            .joinToString("") { "%02x".format(it) }
        check("F7 sha256FileHex streams and matches (2 MiB fixture)",
            AiPackService.sha256FileHex(big) == expected)
    }

    // ============ bd-and-remote F11: QuickAssist ============
    run {
        val t0 = 1_700_300_000_000L
        val qa = QuickAssistService()
        val codeA = qa.mint("co", "dev", "helper", t0)
        val codeB = qa.mint("co", "dev", "helper", t0)
        repeat(QuickAssistService.MAX_FAILED_ATTEMPTS_PER_CODE) { qa.redeem(codeA, "guess", t0) }
        val (okB, _, pairB) = qa.redeem(codeB, "real-binding", t0)
        check("F11(a) burning one code's attempts does NOT lock the helper globally",
            !qa.isLocked(t0) && okB)
        check("F11(b) grant lifetime runs from REDEMPTION, not from the code's expiry",
            pairB != null && pairB.first.expiresUtcMs == t0 + QuickAssistService.GRANT_TTL_MS)
        val grant = pairB!!.first
        check("F11(c) grant starts view-only; host step-up enables control and validate says so",
            grant.viewOnly && qa.validate(grant.grantId, pairB.second, "real-binding", t0).second.contains("view-only") &&
                qa.allowControl(grant.grantId, t0) &&
                qa.validate(grant.grantId, pairB.second, "real-binding", t0).second.contains("control"))
        val qaP = QuickAssistService()
        val old = qaP.mint("co", "dev", "helper", t0, ttlMs = 1_000)
        qaP.redeem(old, "b", t0)
        qaP.prune(t0 + QuickAssistService.GRANT_TTL_MS + 10_000)
        check("F11(d) prune evicts expired used codes and closed/expired grants",
            qaP.retainedCounts() == (0 to 0))
    }

    // ============ bd-and-remote F12: wake lock + roster rollback ============
    run {
        val enrollW = EnrollmentStore(File(dir, "wake-enroll.tsv"))
        val roster = RosterStore(File(dir, "wake-roster.tsv"), enrollW)
        roster.addScope(RosterStore.Scope("co", "company", "Acme"))
        roster.addUser(RosterStore.User("admin1", "co", "Admin", "human"))
        roster.addCompanyAdmin("co", "admin1")
        roster.addUser(RosterStore.User("user1", "co", "User", "human"))
        roster.addUserGroup(RosterStore.UserGroup("ug1", "co", "Techs", setOf("user1")), "admin1")
        roster.addDeviceGroup(RosterStore.DeviceGroup("dg1", "co", "Fleet", listOf("lan")), "admin1")
        roster.addGrant(RosterStore.Grant("co", "ug1", "dg1", setOf("use")), "admin1")
        val hostDev = enrolled(enrollW)
        val sessions = io.agenticcontrol.app.session.SessionStore(
            File(dir, "wake-sessions.tsv"), roster, enrollW) { 1_700_300_000_000L }
        var sentPackets = 0
        val wake = WakeStore(roster, enrollW,
            io.agenticcontrol.app.wake.WakeSender { _, _, _ -> sentPackets++ }, null) { 1_700_300_000_000L }
        check("F12 setup: admin registers the wake target",
            wake.registerTarget(hostDev.deviceId, "00:11:22:33:44:55", "192.168.1.255", "admin1"))
        sessions.createSession(
            io.agenticcontrol.app.session.SessionStore.Session(
                id = "s-w", scopeId = "co", hostDeviceId = hostDev.deviceId,
                initiatorUserId = "user1", kind = "unattended", transportRung = "lan"),
            hostUserId = "admin1")
        check("F12(a) sendWakeForSession still sends (behavior kept after de-synchronization)",
            wake.sendWakeForSession(sessions, "s-w", "user1").first && sentPackets == 1)
    }
    run {
        // Roster persistence failure must roll the mutation back.
        val badFile = File(dir, "missing-parent/roster.tsv")
        val roster = RosterStore(badFile, null)
        val okAdd = roster.addScope(RosterStore.Scope("co", "company", "Acme"))
        check("F12(b) a mutator whose save fails reports failure AND rolls back",
            !okAdd && roster.scope("co") == null)
    }

    // ============ bd-and-ui F1/F4/F9: ADB transcript ============
    run {
        val keyGen = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }
        val kp = keyGen.generateKeyPair()
        val identity = object : io.agenticcontrol.app.adb.AdbIdentity {
            override val rsaPublicKey = kp.public as java.security.interfaces.RSAPublicKey
            override fun signToken(token: ByteArray): ByteArray = AdbKey.signToken(kp.private, token)
            override fun sslContext(): javax.net.ssl.SSLContext =
                throw UnsupportedOperationException("fake transport upgrades in-memory")
        }
        val c2dOut = PipedOutputStream(); val c2dIn = PipedInputStream(c2dOut)
        val d2cOut = PipedOutputStream(); val d2cIn = PipedInputStream(d2cOut)
        var upgraded = false
        val seenByDevice = mutableListOf<Int>()
        val device = Thread {
            val devIn = c2dIn; val devOut = d2cOut
            fun rd(): AdbProtocol.Message? = AdbProtocol.readFrom(devIn)
            fun wr(m: AdbProtocol.Message) = AdbProtocol.writeTo(devOut, m)
            val cnxn1 = rd(); if (cnxn1 != null) seenByDevice.add(cnxn1.command)
            wr(AdbProtocol.Message(AdbProtocol.A_STLS, AdbProtocol.VERSION, 0, ByteArray(0)))
            val stls = rd(); if (stls != null) seenByDevice.add(stls.command)
            val cnxn2 = rd(); if (cnxn2 != null) seenByDevice.add(cnxn2.command)
            val token = ByteArray(20) { (it * 13 + 1).toByte() }
            wr(AdbProtocol.Message(AdbProtocol.A_AUTH, AdbProtocol.AUTH_TOKEN, 0, token))
            val auth1 = rd(); if (auth1 != null) seenByDevice.add(auth1.arg0)
            wr(AdbProtocol.Message(AdbProtocol.A_AUTH, AdbProtocol.AUTH_TOKEN, 0, token))
            val auth2 = rd(); if (auth2 != null) seenByDevice.add(auth2.arg0)
            wr(AdbProtocol.Message(AdbProtocol.A_CNXN, AdbProtocol.VERSION, AdbProtocol.MAX_PAYLOAD,
                "device::ro.product.name=Fake".toByteArray()))
            // shell stream: OPEN -> OKAY, WRTE x2 (split UTF-8), expect OKAYs, CLSE
            val open = rd()
            if (open != null) {
                seenByDevice.add(open.command)
                wr(AdbProtocol.Message(AdbProtocol.A_OKAY, 77, open.arg0, ByteArray(0)))
                val part1 = "héllo ".toByteArray(Charsets.UTF_8).copyOf(3) // splits the é
                val full = "héllo wörld".toByteArray(Charsets.UTF_8)
                val part2 = full.copyOfRange(3, full.size)
                wr(AdbProtocol.Message(AdbProtocol.A_WRTE, 77, open.arg0, part1))
                rd() // OKAY
                wr(AdbProtocol.Message(AdbProtocol.A_WRTE, 77, open.arg0, part2))
                rd() // OKAY
                wr(AdbProtocol.Message(AdbProtocol.A_CLSE, 77, open.arg0, ByteArray(0)))
                rd() // CLSE echo
            }
        }.apply { isDaemon = true; start() }
        val transport = object : AdbClient.Transport {
            override val input: InputStream = d2cIn
            override val output: OutputStream = c2dOut
            override var readTimeoutMs: Int = 0
            override fun upgradeToTls(): AdbClient.Transport { upgraded = true; return this }
            override fun close() {}
        }
        val client = AdbClient(identity)
        client.transportFactory = { _, _ -> transport }
        client.connect("127.0.0.1", 5555, useTls = true)
        check("F1 ADB: STLS upgrade happened mid-handshake (TLS layered AFTER CNXN)",
            upgraded && client.isConnected && client.deviceBanner.contains("Fake"))
        check("F4 ADB: AUTH sequence was signature-then-public-key (no TOKEN loop)",
            seenByDevice.count { it == AdbProtocol.AUTH_SIGNATURE } == 1 &&
                seenByDevice.count { it == AdbProtocol.AUTH_RSAPUBLICKEY } == 1)
        check("F1 ADB: device saw CNXN, STLS, CNXN in that order",
            seenByDevice.take(3) == listOf(AdbProtocol.A_CNXN, AdbProtocol.A_STLS, AdbProtocol.A_CNXN))
        val output = client.exec("echo hi")
        check("F9 ADB: exec decodes split multibyte UTF-8 correctly", output == "héllo wörld")
        client.close()
        device.join(2000)
        check("F3 ADB: plain connect to a non-loopback host is refused",
            try {
                val c2 = AdbClient(identity); c2.transportFactory = { _, _ -> transport }
                c2.connect("192.0.2.44", 5555, useTls = false); false
            } catch (e: AdbClient.AdbException) { e.message!!.contains("loopback") })
        check("F3 AdbEndpoints: only loopback/own addresses are candidates",
            AdbEndpoints.isOwnAddress("127.0.0.1", emptySet()) &&
                AdbEndpoints.isOwnAddress("192.168.1.5", setOf("192.168.1.5")) &&
                !AdbEndpoints.isOwnAddress("192.168.1.6", setOf("192.168.1.5")))
        val peerInfo = AdbPairing.peerInfoPayload(identity)
        check("F3 AdbPairing.parsePeerInfoKey returns the device's key (was: discarded)",
            AdbPairing.parsePeerInfoKey(peerInfo) == AdbKey.publicKeyString(kp.public as java.security.interfaces.RSAPublicKey) &&
                AdbPairing.parsePeerInfoKey(ByteArray(8192) { 1 }) == null)
    }

    // ============ bd-and-ui F8/F10: update guards + verifier ============
    run {
        check("F8 safeApkFileName: traversal/hostile names fall back to the fixed name",
            UpdateGuards.safeApkFileName("../../evil.apk") == UpdateGuards.FIXED_APK_NAME &&
                UpdateGuards.safeApkFileName("dir/app.apk") == UpdateGuards.FIXED_APK_NAME &&
                UpdateGuards.safeApkFileName("notes.txt") == UpdateGuards.FIXED_APK_NAME &&
                UpdateGuards.safeApkFileName("app-release.apk") == UpdateGuards.FIXED_APK_NAME) // W12-DS P8-F16: ONE fixed name, as the KDoc always stated
        check("F8 isHttpsUrl: only https passes",
            UpdateGuards.isHttpsUrl("https://example.com/a.apk") &&
                !UpdateGuards.isHttpsUrl("http://example.com/a.apk") && !UpdateGuards.isHttpsUrl(null))
        val capped = ByteArrayOutputStream()
        check("F8 copyCapped: over-cap aborts with -1; under-cap copies exactly",
            UpdateGuards.copyCapped(ByteArrayInputStream(ByteArray(100)), capped, 50) == -1L &&
                UpdateGuards.copyCapped(ByteArrayInputStream(ByteArray(40)), ByteArrayOutputStream(), 50) == 40L)
        check("F8 downloadCapBytes: an undeclared size earns no download",
            UpdateGuards.downloadCapBytes(0) == -1L && UpdateGuards.downloadCapBytes(1000) > 1000)
        check("F8 signerSetsEqual: set equality — a co-signed stranger fails",
            UpdateGuards.signerSetsEqual(listOf(byteArrayOf(1, 2)), listOf(byteArrayOf(1, 2))) &&
                !UpdateGuards.signerSetsEqual(listOf(byteArrayOf(1, 2)), listOf(byteArrayOf(1, 2), byteArrayOf(9))) &&
                !UpdateGuards.signerSetsEqual(emptyList(), listOf(byteArrayOf(1))))
        // Verifier: Long codes + package binding + expiry.
        val rsa = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        fun signedManifest(build: JSONObject.() -> Unit): JSONObject {
            val m = JSONObject(); m.build()
            val signer = Signature.getInstance("SHA256withRSA")
            signer.initSign(rsa.private); signer.update(ManifestVerifier.canonicalBytes(m))
            m.put("signature", Base64.getEncoder().encodeToString(signer.sign()))
            return m
        }
        val bigCode = 3_000_000_000L // above Int range: the old optInt truncated this
        val mBig = signedManifest { put("versionCode", bigCode) }
        check("F10 verifyNewer is Long-wide (3e9 versionCode compares correctly)",
            ManifestVerifier.verifyNewer(mBig, rsa.public, bigCode - 1) &&
                !ManifestVerifier.verifyNewer(mBig, rsa.public, bigCode))
        val mPkg = signedManifest { put("versionCode", 10); put("packageName", "com.other.app") }
        check("F10 a manifest bound to another package is refused",
            !ManifestVerifier.verifyNewer(mPkg, rsa.public, 1, expectedPackage = "io.agenticcontrol.app") &&
                ManifestVerifier.verifyNewer(mPkg, rsa.public, 1))
        val mExp = signedManifest { put("versionCode", 10); put("expiresAt", 1000L) }
        check("F10 an expired manifest is refused; the same one in its window passes",
            !ManifestVerifier.verifyNewer(mExp, rsa.public, 1, nowMs = 2000L) &&
                ManifestVerifier.verifyNewer(mExp, rsa.public, 1, nowMs = 500L))
    }

    // ============ parity mirror: licence states ============
    run {
        check("PARITY deficit/surplus canonical values match the Windows rename",
            LicenceStates.Deficit == "deficit" && LicenceStates.Surplus == "surplus")
        check("PARITY legacy constant names are aliases carrying the CORRECTED values",
            LicenceStates.OverLicensed == "deficit" && LicenceStates.UnderLicensed == "surplus" &&
                LicenceFindingKinds.KindOverLicensed == "deficit" && LicenceFindingKinds.KindUnderLicensed == "surplus")
        val counts = LicenceStates.exportCounts(listOf("compliant", "deficit", "deficit", "surplus", "unlicensed_unknown"))
        check("PARITY export counts emit deficit_lines (never over_licensed_lines)",
            counts["deficit_lines"] == 2 && counts["surplus_lines"] == 1 && counts["total_lines"] == 5 &&
                !counts.containsKey("over_licensed_lines"))
    }

    dir.deleteRecursively()
    println(if (failures == 0) "ALL BD-AND-FIX-2 TESTS PASSED" else "$failures BD-AND-FIX-2 TEST(S) FAILED")
    if (failures > 0) kotlin.system.exitProcess(1)
}
