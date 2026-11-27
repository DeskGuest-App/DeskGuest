import io.deskguest.app.backup.BackupPolicy
import io.deskguest.app.backup.BackupService
import io.deskguest.app.backup.SafTree
import io.deskguest.app.backup.StoreSource
import io.deskguest.app.cameraview.ChainedAudit
import io.deskguest.app.cameraview.SharedAuditBridge
import io.deskguest.app.deploy.ContentPack
import io.deskguest.app.deploy.DeployPolicy
import io.deskguest.app.deploy.DeployService
import io.deskguest.app.deploy.DeployUnit
import io.deskguest.app.deploy.InstallerHandoff
import io.deskguest.app.deploy.PayloadInstallerHandoff
import io.deskguest.app.deploy.SignatureVerifier
import io.deskguest.app.enrollment.DeviceIdentity
import io.deskguest.app.enrollment.EnrollPayload
import io.deskguest.app.enrollment.EnrollmentStore
import io.deskguest.app.mobileop.AlertLookup
import io.deskguest.app.mobileop.ClientKeySigner
import io.deskguest.app.mobileop.HubKeyVerifier
import io.deskguest.app.mobileop.MobileOperatorClient
import io.deskguest.app.mobileop.MobileOperatorPolicy
import io.deskguest.app.mobileop.RosterRights
import io.deskguest.app.roster.RosterStore
import io.deskguest.app.session.SessionStore
import io.deskguest.app.transport.HostListenerService
import io.deskguest.app.transport.HostSessionBinding
import io.deskguest.app.transport.LanProtocol
import io.deskguest.app.transport.SocketStreams
import io.deskguest.app.vendorpass.VendorPassPolicy
import io.deskguest.app.wiring.PlatformStores
import java.io.File
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.nio.file.Files
import java.security.MessageDigest
import java.util.Base64

/**
 * Wave 4 Lane B regression suite: bd-and-rest dispositions +
 * the host-listener production binding + PlatformStores hub-seam
 * wiring. Every check is a permanent pin for a fix landed this
 * wave (or for a rebuttal's evidence).
 */
private var failures = 0
private fun check(name: String, condition: Boolean) {
    if (condition) println("PASS  $name") else { println("FAIL  $name"); failures++ }
}
private fun sha(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }
private var clockNow = 1_700_200_000_000L
private fun tick(): Long { clockNow += 1_000L; return clockNow }

private class W4World(dir: File, tag: String) {
    val enrollment = EnrollmentStore(File(dir, "$tag-enroll.tsv"))
    val roster = RosterStore(File(dir, "$tag-roster.tsv"), enrollment)
    val sessions = SessionStore(File(dir, "$tag-sessions.tsv"), roster, enrollment) { tick() }
    val hostIdentity = DeviceIdentity.generate()
    val operatorIdentity = DeviceIdentity.generate()
    val hostDeviceId get() = hostIdentity.deviceId
    init {
        roster.addScope(RosterStore.Scope("co", "company", "Acme Co"))
        roster.addUser(RosterStore.User("admin1", "co", "Admin One", "human"))
        roster.addCompanyAdmin("co", "admin1")
        roster.addUser(RosterStore.User("host1", "co", "Host User", "human"))
        roster.addUser(RosterStore.User("user1", "co", "User One", "human"))
        roster.addUserGroup(RosterStore.UserGroup("ug1", "co", "Techs", memberUserIds = setOf("user1")), "admin1")
        roster.addDeviceGroup(RosterStore.DeviceGroup("dg1", "co", "Fleet", listOf("lan", "hub", "tor")), "admin1")
        roster.addGrant(RosterStore.Grant("co", "ug1", "dg1", setOf("use")), "admin1")
        enrollment.redeem(enrollment.mint("company", "dg1", "Fleet"),
            EnrollmentStore.EnrollingDevice(hostIdentity.deviceId, hostIdentity.publicKeyBase64, "Host Device"))
        enrollment.redeem(enrollment.mint("company", "dg1", "Fleet"),
            EnrollmentStore.EnrollingDevice(operatorIdentity.deviceId, operatorIdentity.publicKeyBase64, "Operator Device"))
    }
    fun attendedSession(id: String): Boolean =
        sessions.createSession(SessionStore.Session(id, "co", hostDeviceId, "user1", "attended", transportRung = "lan"), "host1")
}

/** Two pipe pairs + a host thread running handshake -> binding. */
private class BoundChannel(val world: W4World, val binding: HostSessionBinding) {
    val c2hOut = PipedOutputStream(); val c2hIn = PipedInputStream(c2hOut)
    val h2cOut = PipedOutputStream(); val h2cIn = PipedInputStream(h2cOut)
    val clientRaw = SocketStreams(h2cIn, c2hOut)
    val hostRaw = SocketStreams(c2hIn, h2cOut)
    @Volatile var hostError: String? = null
    val thread = Thread {
        try {
            val proven = LanProtocol.hostHandshake(hostRaw, world.enrollment, world.hostIdentity)
            if (proven == null) { hostError = "handshake refused"; return@Thread }
            binding.serve(proven.first, proven.second)
        } catch (e: Exception) { hostError = e.javaClass.simpleName }
    }.apply { isDaemon = true; start() }
    fun clientChannel(): SocketStreams =
        LanProtocol.clientHandshakeDetailed(clientRaw, world.operatorIdentity, world.enrollment, world.hostDeviceId).channel!!
}

fun main() {
    val dir = Files.createTempDirectory("deskguest-w4-test").toFile()

    // ---- F2: local STOP can never be refused over a typed actor ----
    run {
        val w = W4World(dir, "stop")
        check("F2 setup: attended session created", w.attendedSession("s-stop"))
        check("F2 typed-actor STOP with a wrong actor is refused (channel gate intact)",
            !w.sessions.stopSession("s-stop", "mallory"))
        check("F2 local STOP succeeds with no actor at all",
            w.sessions.stopLocalSession("s-stop") &&
                w.sessions.session("s-stop")?.state == SessionStore.STATE_ENDED &&
                w.sessions.session("s-stop")?.endReason == SessionStore.REASON_HOST_STOP)
        check("F2 local STOP on an ended session is honestly false", !w.sessions.stopLocalSession("s-stop"))
    }

    // ---- F4: backup restore / UUID ids / manifest HMAC ----
    run {
        BackupPolicy.enabled = true
        val key = "w4-manifest-key".toByteArray()
        val dest = object : SafTree {
            val files = mutableMapOf<String, ByteArray>()
            override fun granted() = true
            override fun write(n: String, b: ByteArray) = true.also { files[n] = b.copyOf() }
            override fun read(n: String) = files[n]
        }
        val svc = BackupService(StoreSource { mapOf("roster.tsv" to "data-v1".toByteArray()) }, ChainedAudit(), { tick() }, key, allowLegacyPlaintext = true) // W12-DS: legacy fixture opts in explicitly
        val m1 = svc.backup(dest).getOrThrow()
        val svc2 = BackupService(StoreSource { mapOf("roster.tsv" to "data-v1".toByteArray()) }, ChainedAudit(), { tick() }, key, allowLegacyPlaintext = true) // W12-DS: legacy fixture opts in explicitly
        val m2 = svc2.backup(dest).getOrThrow()
        check("F4 backup ids are unique across process restarts (no backup-1 overwrite)", m1.id != m2.id && m1.id != "backup-1")
        val target = object : SafTree {
            val files = mutableMapOf<String, ByteArray>()
            override fun granted() = true
            override fun write(n: String, b: ByteArray) = true.also { files[n] = b.copyOf() }
            override fun read(n: String) = files[n]
        }
        check("F4 restore writes back exactly what verify approved",
            svc.restore(dest, m1.id, target).isSuccess &&
                target.files["deskguest/roster.tsv"]?.toString(Charsets.UTF_8) == "data-v1")
        // Tamper: rewrite the file AND its manifest hash together.
        val entryName = "deskguest/roster.tsv"
        dest.files["${m1.id}/$entryName"] = "evil".toByteArray()
        val manifestKey = dest.files.keys.first { it.endsWith("manifest.txt") && it.startsWith(m1.id) }
        val lines = String(dest.files[manifestKey]!!, Charsets.UTF_8).lines().toMutableList()
        val idx = lines.indexOfFirst { it.startsWith("$entryName\t") }
        lines[idx] = "$entryName\t${sha("evil".toByteArray())}"
        dest.files[manifestKey] = lines.joinToString("\n").toByteArray()
        check("F4 DESTRUCTION file+hash rewritten together still refuses (manifest HMAC)",
            svc.verify(dest, m1.id).isFailure && svc.restore(dest, m1.id, target).isFailure)
        // Allow-list: a MAC-valid manifest naming a traversal entry.
        val evilLines = "deskguest/../evil\t${sha("x".toByteArray())}"
        val mac = javax.crypto.Mac.getInstance("HmacSHA256")
        mac.init(javax.crypto.spec.SecretKeySpec(key, "HmacSHA256"))
        val evilMac = mac.doFinal(evilLines.toByteArray()).joinToString("") { "%02x".format(it) }
        val evilSrc = object : SafTree {
            val files = mutableMapOf(
                "bk/manifest.txt" to "$evilLines\n#hmac\t$evilMac".toByteArray(),
                "bk/deskguest/../evil" to "x".toByteArray())
            override fun granted() = true
            override fun write(n: String, b: ByteArray) = true
            override fun read(n: String) = files[n]
        }
        val cleanTarget = object : SafTree {
            val files = mutableMapOf<String, ByteArray>()
            override fun granted() = true
            override fun write(n: String, b: ByteArray) = true.also { files[n] = b.copyOf() }
            override fun read(n: String) = files[n]
        }
        check("F4 DESTRUCTION traversal entry refuses the whole restore before any write",
            svc.restore(evilSrc, "bk", cleanTarget).isFailure && cleanTarget.files.isEmpty())
    }

    // ---- F5/F9: deploy profile honesty, payload handoff, pack sink; policy defaults ----
    run {
        check("F5 vendor-pass local policy defaults OFF", !VendorPassPolicy.enabled)
        check("F5 mobile-operator local policy defaults OFF", !MobileOperatorPolicy.enabled)
        check("F5 deploy local policy defaults OFF", !DeployPolicy.enabled)
        DeployPolicy.enabled = true
        var legacyHanded = false
        var payloadSeen: ByteArray? = null
        val sunk = mutableListOf<ContentPack>()
        val svc = DeployService(
            SignatureVerifier { _, s -> s == "sig" },
            InstallerHandoff { _, _ -> legacyHanded = true; true },
            ChainedAudit(),
            PayloadInstallerHandoff { _, _, payload -> payloadSeen = payload; true },
            { pack -> sunk.add(pack) })
        val payload = "apk-bytes".toByteArray()
        val unit = DeployUnit("app1", "apk", "2.0", sha(payload))
        check("F9 payload installer receives the verified bytes themselves",
            svc.deploy(unit, byteArrayOf(1), "sig", payload, true).isSuccess &&
                payloadSeen?.contentEquals(payload) == true && !legacyHanded)
        val profile = DeployUnit("prof1", "profile", "1.0", sha(payload))
        check("F9 DESTRUCTION 'profile' no longer claims applied — it refuses as unimplemented",
            svc.deploy(profile, byteArrayOf(1), "sig", payload, true).isFailure)
        val packPayload = "a\nb".toByteArray()
        val pack = DeployUnit("pack1", "content_pack", "1.0", sha(packPayload))
        check("F5 content pack installs AND persists through the sink",
            svc.deploy(pack, byteArrayOf(1), "sig", packPayload, false).isSuccess && sunk.map { it.id } == listOf("pack1"))
        DeployPolicy.enabled = false
    }

    // ---- F5: shared audit bridge ----
    run {
        val seen = mutableListOf<String>()
        SharedAuditBridge.sink = { type, _ -> seen.add(type) }
        val audit = ChainedAudit()
        audit.append("bridge_probe", "x")
        SharedAuditBridge.sink = null
        check("F5 ChainedAudit appends forward to the shared audit bridge when installed",
            seen == listOf("bridge_probe") && audit.verify())
    }

    // ---- F12: mobile operator canonical payload + queue cap ----
    run {
        MobileOperatorPolicy.enabled = true
        val signer = object : ClientKeySigner {
            override fun sign(p: ByteArray) = sha(p + "k".toByteArray())
            override fun verify(p: ByteArray, s: String) = s == sign(p)
        }
        val client = MobileOperatorClient("co", "boss",
            RosterRights { _, _, _ -> setOf("use", "admin") },
            HubKeyVerifier { _, s -> s == "hubsig" }, signer,
            AlertLookup { id -> if (id == "a1") "alert body" else null }, ChainedAudit())
        val ap = client.approve("content1", "hash1", "dg1")!!
        check("F12 approval verifies for its own scope+group", client.verifyApproval(ap))
        check("F12 DESTRUCTION approval replayed for another device group fails",
            !client.verifyApproval(ap.copy(deviceGroupId = "dg2")))
        check("F12 DESTRUCTION field-boundary forgery fails (length-prefixed payload)",
            !client.verifyApproval(ap.copy(contentId = "content1|hash1")))
        var lastOk = false
        repeat(MobileOperatorClient.MAX_QUEUED_NOTIFICATIONS) {
            lastOk = client.enqueue("hub_alert_lookup", alertId = "a1").isSuccess
        }
        check("F12 notification queue is capped — the 101st enqueue refuses",
            lastOk && client.enqueue("hub_alert_lookup", alertId = "a1").isFailure &&
                client.notifications().size == MobileOperatorClient.MAX_QUEUED_NOTIFICATIONS)
        MobileOperatorPolicy.enabled = false
    }

    // ---- F11: enroll payload binds the minter ----
    run {
        val minter = DeviceIdentity.generate()
        val code = EnrollmentStore.formatCode("ABCDE23456")
        val payload = EnrollPayload.build(code, "company", "dg1", minter.deviceId, minter.publicKeyBase64)
        val parsed = EnrollPayload.parse(payload)
        check("F11 payload carries the minter and the key fingerprints to the id",
            parsed != null && parsed.minterVerified && parsed.minterDeviceId == minter.deviceId)
        val stranger = DeviceIdentity.generate()
        val forgedPayload = payload.replace(
            java.net.URLEncoder.encode(minter.publicKeyBase64, "UTF-8"),
            java.net.URLEncoder.encode(stranger.publicKeyBase64, "UTF-8"))
        check("F11 DESTRUCTION forged payload (id of one device, key of another) parses to null",
            forgedPayload != payload && EnrollPayload.parse(forgedPayload) == null)
        val legacy = EnrollPayload.parse(EnrollPayload.build(code, "company", "dg1"))
        check("F11 legacy payload (no minter) still parses, minter honestly absent",
            legacy != null && legacy.minterDeviceId == null && !legacy.minterVerified)
        var threw = false
        try { EnrollPayload.build(code, "company", "dg1", minter.deviceId, stranger.publicKeyBase64) } catch (_: IllegalArgumentException) { threw = true }
        check("F11 inconsistent minter pair is a build-time error", threw)
    }

    // ---- TASK 2: host binding end-to-end over the v2 AEAD channel ----
    run {
        val w = W4World(dir, "bind")
        val presenceEvents = mutableListOf<String>()
        val binding = HostSessionBinding(w.sessions, w.enrollment,
            ownDeviceId = { w.hostDeviceId },
            presenceAttach = { sid, peer -> presenceEvents.add("attach:$sid:$peer") },
            presenceDetach = { sid -> presenceEvents.add("detach:$sid") },
            idFactory = { "hs-e2e" })
        val bound = BoundChannel(w, binding)
        val channel = bound.clientChannel()
        LanProtocol.writeLine(channel.output, "SESSION co user1 host1 attended")
        val pending = LanProtocol.readLine(channel.input)
        check("T2 network SESSION creates a consent-PENDING record (never self-accepted)",
            pending == "PENDING hs-e2e" &&
                w.sessions.session("hs-e2e")?.state == SessionStore.STATE_REQUESTED &&
                w.sessions.session("hs-e2e")?.acceptBy == null)
        check("T2 presence attached before the peer learned the session id",
            presenceEvents == listOf("attach:hs-e2e:${w.operatorIdentity.deviceId}"))
        LanProtocol.writeLine(channel.output, "TAP 100 200")
        check("T2 no drive capability exists on the channel pre-consent (unknown verb)",
            LanProtocol.readLine(channel.input) == "ERR unknown")
        LanProtocol.writeLine(channel.output, "ACCEPT")
        check("T2 there is no channel accept verb — consent is endpoint-local only",
            LanProtocol.readLine(channel.input) == "ERR unknown" &&
                w.sessions.session("hs-e2e")?.state == SessionStore.STATE_REQUESTED)
        check("T2 endpoint-local accept + start is the only path to active",
            w.sessions.acceptSession("hs-e2e", "host1", SessionStore.ACCEPT_ORIGIN_LOCAL_UI) &&
                w.sessions.startSession("hs-e2e", "host1"))
        LanProtocol.writeLine(channel.output, "STATUS")
        check("T2 STATUS reports the live state over the AEAD channel",
            LanProtocol.readLine(channel.input) == "STATE active")
        LanProtocol.writeLine(channel.output, "PING")
        check("T2 PING/PONG liveness rides the bound channel",
            LanProtocol.readLine(channel.input) == "PONG")
        LanProtocol.writeLine(channel.output, "STOP mallory")
        check("T2 channel STOP by a non-host actor is refused (store gate intact)",
            LanProtocol.readLine(channel.input) == "REFUSED stop_refused" &&
                w.sessions.session("hs-e2e")?.state == SessionStore.STATE_ACTIVE)
        LanProtocol.writeLine(channel.output, "STOP host1")
        val stopped = LanProtocol.readLine(channel.input)
        bound.thread.join(3000)
        check("T2 STOP teardown: host STOP ends the session (host_stop) and detaches presence",
            stopped == "STOPPED" &&
                w.sessions.session("hs-e2e")?.state == SessionStore.STATE_ENDED &&
                w.sessions.session("hs-e2e")?.endReason == SessionStore.REASON_HOST_STOP &&
                presenceEvents.last() == "detach:hs-e2e")
    }

    // ---- TASK 2: peer vanishing ends the session (no dangling record) ----
    run {
        val w = W4World(dir, "vanish")
        val detached = mutableListOf<String>()
        val binding = HostSessionBinding(w.sessions, w.enrollment,
            ownDeviceId = { w.hostDeviceId },
            presenceDetach = { detached.add(it) },
            idFactory = { "hs-vanish" })
        val bound = BoundChannel(w, binding)
        val channel = bound.clientChannel()
        LanProtocol.writeLine(channel.output, "SESSION co user1 host1 attended")
        check("T2 vanish setup: session pending", LanProtocol.readLine(channel.input) == "PENDING hs-vanish")
        bound.c2hOut.close() // the peer vanishes: its pipe hits EOF mid-session
        bound.thread.join(3000)
        check("T2 a vanished peer's session is ended and presence detached — nothing dangles",
            w.sessions.session("hs-vanish")?.state == SessionStore.STATE_ENDED && detached == listOf("hs-vanish"))
    }

    // ---- TASK 2: ENROLL verb — single-use, SAS-carrying, replay refused ----
    run {
        val w = W4World(dir, "enroll")
        val binding = HostSessionBinding(w.sessions, w.enrollment, ownDeviceId = { w.hostDeviceId })
        val c2hOut = PipedOutputStream(); val c2hIn = PipedInputStream(c2hOut)
        val h2cOut = PipedOutputStream(); val h2cIn = PipedInputStream(h2cOut)
        val client = SocketStreams(h2cIn, c2hOut)
        val host = SocketStreams(c2hIn, h2cOut)
        val t = Thread { binding.serve(w.operatorIdentity.deviceId, host) }.apply { isDaemon = true; start() }
        val code = w.enrollment.mint("company", "dg1", "Fleet")
        val newDevice = DeviceIdentity.generate()
        LanProtocol.writeLine(client.output,
            "ENROLL $code ${newDevice.deviceId} ${newDevice.publicKeyBase64} New Device")
        val reply = LanProtocol.readLine(client.input) ?: ""
        check("T2 ENROLL redeems through EnrollmentStore and returns the enrollment + SAS shape",
            reply.startsWith("ENROLLED ${newDevice.deviceId} company dg1") &&
                w.enrollment.byId(newDevice.deviceId) != null)
        LanProtocol.writeLine(client.output,
            "ENROLL $code ${DeviceIdentity.generate().deviceId} ${DeviceIdentity.generate().publicKeyBase64} Replay")
        check("T2 DESTRUCTION ENROLL replay of the consumed code is refused",
            LanProtocol.readLine(client.input) == "REFUSED enroll_rejected")
        c2hOut.close()
        t.join(3000)
    }

    // ---- TASK 2: listener lifecycle (bind + stop; real-socket data
    // plane is the named on-device remainder — sandbox loopback
    // connects are reset for JVM clients, see TransportTest note) ----
    run {
        val w = W4World(dir, "life")
        val binding = HostSessionBinding(w.sessions, w.enrollment, ownDeviceId = { w.hostDeviceId })
        val service = HostListenerService(binding, w.enrollment, w.hostIdentity)
        val loopback = java.net.InetAddress.getByName("127.0.0.1")
        check("T2 listener starts on an explicitly named interface and stops with the service",
            service.start(loopback, 0) && service.isRunning && service.port > 0)
        service.stop()
        check("T2 listener is down after stop", !service.isRunning)
        var wildcardRefused = false
        try {
            io.deskguest.app.transport.LanHostListener(w.enrollment, w.hostIdentity)
                .start(java.net.InetAddress.getByName("0.0.0.0"), 0)
        } catch (_: IllegalArgumentException) { wildcardRefused = true }
        check("T2 DESTRUCTION wildcard bind is refused by name", wildcardRefused)
    }

    // ---- TASK 3: PlatformStores hub seams are live ----
    run {
        val storesDir = File(dir, "stores-hub")
        val first = PlatformStores(storesDir)
        val nodeId = first.hubMembership.join(first.ownDeviceId(), "1.104.7", tick())
        check("T3 hub join lands through the wired PlatformStores seam", nodeId != null)
        val second = PlatformStores(storesDir)
        check("T3 hub membership PERSISTS across PlatformStores instances (storeFile wired)",
            second.hubMembership.isLiveMember(first.ownDeviceId()))
        check("T3 hub reconcile marks the node deleted and persists that too",
            second.hubMembership.reconcile(listOf(nodeId!!)) == 1 &&
                !PlatformStores(storesDir).hubMembership.isLiveMember(first.ownDeviceId()))
        val flowFirst = PlatformStores(storesDir)
        flowFirst.meshSetupFlow.runPreSignIn(
            io.deskguest.app.transport.MeshPlatform.ANDROID,
            io.deskguest.app.transport.MeshRole.OPERATOR,
            carveOutAcknowledged = true, clientVersion = "1.104.7")
        val stageBefore = flowFirst.meshSetupFlow.state.stage
        val flowSecond = PlatformStores(storesDir)
        check("T3 mesh setup state PERSISTS across instances (sink + restore wired)",
            stageBefore == io.deskguest.app.transport.MeshSetupFlow.STAGE_AWAITING_SIGN_IN &&
                flowSecond.meshSetupFlow.state.stage == stageBefore)
        check("T3 host listener is composed by PlatformStores (not yet running)",
            !flowSecond.hostListenerRunning && flowSecond.hostListener() != null)
        check("T3 RMM factories compose over the live stores",
            flowSecond.vendorPassService() != null && flowSecond.backupService() != null)
    }

    dir.deleteRecursively()
    println(if (failures == 0) "ALL BD-AND-FIX-3 TESTS PASSED" else "$failures BD-AND-FIX-3 TEST(S) FAILED")
    if (failures > 0) kotlin.system.exitProcess(1)
}
