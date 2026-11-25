import io.agenticcontrol.app.crypto.SecondFactorStore
import io.agenticcontrol.app.crypto.Totp
import io.agenticcontrol.app.enrollment.DeviceIdentity
import io.agenticcontrol.app.enrollment.EnrollmentStore
import io.agenticcontrol.app.enterprise.PolicyFeatures
import io.agenticcontrol.app.roster.RosterStore
import io.agenticcontrol.app.session.SessionStore
import io.agenticcontrol.app.session.SessionTunnelStore
import io.agenticcontrol.app.session.StandaloneJob
import io.agenticcontrol.app.session.StandaloneTransferStore
import io.agenticcontrol.app.wake.MagicPacket
import io.agenticcontrol.app.wake.WakeSender
import io.agenticcontrol.app.wake.WakeStore
import io.agenticcontrol.app.wiring.AesGcmSecretSealer
import java.io.File
import java.nio.file.Files
import javax.crypto.KeyGenerator

/**
 * JVM tests for Block G (Android mirrors): G-01 wake-on-LAN,
 * G-02/G-03/G-07 session surfaces, G-04 standalone transfers,
 * G-05 in-session calls, G-06 local second factor (first JVM
 * coverage — the store previously had none), G-08 session
 * tunnels, all under the TOTAL POLICY CONTROL feature gates.
 * Attack cases are named Attack_*.
 */
private var failures = 0

private fun check(name: String, condition: Boolean) {
    if (condition) println("PASS  $name")
    else {
        println("FAIL  $name")
        failures++
    }
}

private var clockNow = 1_700_000_000_000L
private fun tick(): Long {
    clockNow += 1_000L
    return clockNow
}

private class BlockGWorld(dir: File, tag: String) {
    val enrollment = EnrollmentStore(File(dir, "$tag-enroll.tsv"))
    val roster = RosterStore(File(dir, "$tag-roster.tsv"), enrollment)
    val disabled = mutableSetOf<String>()
    val required = mutableSetOf<String>()
    val sessions: SessionStore
    val hostDeviceId: String

    init {
        roster.addScope(RosterStore.Scope("co", "company", "Acme Co"))
        roster.addUser(RosterStore.User("admin1", "co", "Admin One", "human"))
        roster.addCompanyAdmin("co", "admin1")
        roster.addUser(RosterStore.User("host1", "co", "Host User", "human"))
        roster.addUser(RosterStore.User("user1", "co", "User One", "human"))
        roster.addUser(RosterStore.User("user2", "co", "User Two", "human"))
        roster.addUser(RosterStore.User("user3", "co", "User Three", "human"))
        roster.addUser(RosterStore.User("ai1", "co", "Helper AI", "ai", pairedByUserId = "user1"))
        roster.addUserGroup(
            RosterStore.UserGroup("ug1", "co", "Techs", memberUserIds = setOf("user1", "user2", "host1", "ai1")),
            "admin1"
        )
        roster.addDeviceGroup(
            RosterStore.DeviceGroup("dg1", "co", "Fleet", listOf("lan", "hub", "mesh")), "admin1"
        )
        roster.addGrant(RosterStore.Grant("co", "ug1", "dg1", setOf("use")), "admin1")
        val identity = DeviceIdentity.generate()
        val code = enrollment.mint("company", "dg1", "Fleet")
        enrollment.redeem(
            code,
            EnrollmentStore.EnrollingDevice(identity.deviceId, identity.publicKeyBase64, "Host Device")
        )
        hostDeviceId = identity.deviceId
        sessions = SessionStore(
            File(dir, "$tag-sessions.tsv"), roster, enrollment,
            featureGate = { _, key -> key !in disabled },
            featureRequired = { _, key -> key in required }
        ) { tick() }
    }

    fun active(id: String): String {
        check("setup: create $id", sessions.createSession(
            SessionStore.Session(id, "co", hostDeviceId, "user1", "attended", transportRung = "lan"),
            hostUserId = "host1"))
        check("setup: accept $id", sessions.acceptSession(id, "host1", SessionStore.ACCEPT_ORIGIN_LOCAL_UI))
        check("setup: start $id", sessions.startSession(id, "user1"))
        return id
    }
}

fun main() {
    val dir = Files.createTempDirectory("acp-blockg").toFile()
    val w = BlockGWorld(dir, "g")

    // ---- G-01 wake-on-LAN ----
    run {
        val mac = MagicPacket.parseMac("00:11:22:33:44:55")
        check("G01 packet: canonical MAC parses + normalizes",
            mac != null && MagicPacket.normalizeMac(mac) == "00:11:22:33:44:55")
        val packet = MagicPacket.build(mac!!)
        check("G01 packet: 102 bytes, 0xFF header, MAC x16",
            packet.size == 102 && packet.take(6).all { it == 0xFF.toByte() } &&
                (0 until 16).all { i -> packet.sliceArray(6 + i * 6 until 12 + i * 6).contentEquals(mac) })
        check("G01 packet: broadcast/multicast/zero never wakeable",
            !MagicPacket.isWakeableMac(MagicPacket.parseMac("FF:FF:FF:FF:FF:FF")!!) &&
                !MagicPacket.isWakeableMac(MagicPacket.parseMac("01:00:5E:00:00:01")!!) &&
                MagicPacket.parseMac("00:11:22:33:44") == null)

        val sent = mutableListOf<String>()
        val wake = WakeStore(w.roster, w.enrollment,
            WakeSender { _, addr, _ -> sent.add(addr) }, null) { tick() }
        check("G01 registry: plain user cannot register a target",
            !wake.registerTarget(w.hostDeviceId, "00:11:22:33:44:55", "192.168.1.255", "user1"))
        check("G01 registry: company admin registers",
            wake.registerTarget(w.hostDeviceId, "00:11:22:33:44:55", "192.168.1.255", "admin1"))
        check("G01 send: grant holder wakes, packet to registered broadcast",
            wake.sendWake(w.hostDeviceId, "user1").first && sent == listOf("192.168.1.255"))
        check("Attack_G01: user without the grant cannot wake",
            !wake.sendWake(w.hostDeviceId, "user3").first)
        check("G01 persistence: export/import round-trips, unwakeable edit drops",
            WakeStore(w.roster, w.enrollment, WakeSender { _, _, _ -> }, null) { tick() }
                .importJson(wake.exportJson()) == 1 &&
                WakeStore(w.roster, w.enrollment, WakeSender { _, _, _ -> }, null) { tick() }
                    .importJson(wake.exportJson().replace("00:11:22:33:44:55", "FF:FF:FF:FF:FF:FF")) == 0)
    }

    // ---- G-02 / G-03 / G-07 session surfaces ----
    run {
        val id = w.active("s-surfaces")
        check("G02 blank: outsider refused", !w.sessions.setBlanked(id, "user3", true))
        check("G02 blank: host sets + flag reads back",
            w.sessions.setBlanked(id, "host1", true) && w.sessions.session(id)?.blanked == true)
        check("G03 input block: host sets", w.sessions.setInputBlocked(id, "host1", true))
        check("G03 input block: pause releases it",
            w.sessions.pauseSession(id, "user1") && w.sessions.session(id)?.inputBlocked == false)
        check("G07 watermark: derived text names the acting user + session",
            w.sessions.setWatermarked(id, "host1", true) &&
                (w.sessions.watermarkText(id)?.contains("(user1)") == true ||
                    w.sessions.watermarkText(id)?.contains("(host1)") == true) &&
                (w.sessions.watermarkText(id)?.contains(id.take(8)) == true))
        check("G07 watermark: remote participant cannot clear",
            !w.sessions.setWatermarked(id, "user1", false))
        check("surfaces: end cascade clears all three",
            w.sessions.endSession(id, "user1") &&
                w.sessions.session(id)?.let { !it.blanked && !it.inputBlocked && !it.watermarked } == true)

        // Required-watermark trap: start refuses unwatermarked;
        // nobody clears while required.
        val id2 = "s-required"
        check("setup: create+accept required-watermark session",
            w.sessions.createSession(
                SessionStore.Session(id2, "co", w.hostDeviceId, "user1", "attended", transportRung = "lan"),
                hostUserId = "host1") &&
                w.sessions.acceptSession(id2, "host1", SessionStore.ACCEPT_ORIGIN_LOCAL_UI))
        w.required.add(PolicyFeatures.WATERMARK)
        check("G07 required: start refuses unwatermarked", !w.sessions.startSession(id2, "user1"))
        check("G07 required: watermark set by host, clear refused for everyone",
            w.sessions.setWatermarked(id2, "host1", true) && !w.sessions.setWatermarked(id2, "host1", false))
        check("G07 required: start now proceeds", w.sessions.startSession(id2, "user1"))
        w.required.clear()

        // Policy-disabled blank: enable refuses, clear never gated.
        val id3 = w.active("s-disabled")
        w.disabled.add(PolicyFeatures.BLANK_SCREEN)
        check("Attack_policy: disabled blank refuses to enable",
            !w.sessions.setBlanked(id3, "host1", true))
        w.disabled.clear()
        check("policy: re-enabled blank works again", w.sessions.setBlanked(id3, "host1", true))
        w.disabled.add(PolicyFeatures.BLANK_SCREEN)
        check("policy: clearing a set blank is never policy-gated",
            w.sessions.setBlanked(id3, "host1", false))
        w.disabled.clear()
    }

    // ---- G-05 calls ----
    run {
        val id = w.active("s-call")
        check("G05 call: non-participant cannot start", w.sessions.startCall(id, "user3", "video") == null)
        val call = w.sessions.startCall(id, "user1", "video")
        check("G05 call: participant starts, ringing", call != null && call.state == "ringing")
        check("G05 call: one live call per session", w.sessions.startCall(id, "host1", "audio") == null)
        check("G05 call: initiator cannot self-answer", !w.sessions.answerCall(call!!.id, "user1"))
        check("G05 call: other side answers",
            w.sessions.answerCall(call!!.id, "host1") && w.sessions.liveCall(id)?.state == "active")
        check("G05 call: session end kills the call",
            w.sessions.endSession(id, "user1") && w.sessions.liveCall(id) == null &&
                w.sessions.calls(id).single().state == "ended")
    }

    // ---- G-04 standalone transfers ----
    run {
        val svc = StandaloneTransferStore(w.roster, w.enrollment, null) { tick() }
        val job = svc.createJob("co", w.hostDeviceId, "user1", "to_host", "report.pdf", 100)
        check("G04 create: grant holder queues a job", job != null && job.state == StandaloneJob.JOB_QUEUED)
        check("G04 create: no grant, no job",
            svc.createJob("co", w.hostDeviceId, "user3", "to_host", "x.bin", 1) == null)
        check("G04 progress: monotonic, initiator-only",
            svc.updateProgress(job!!.id, 50, "user1") && !svc.updateProgress(job.id, 40, "user1") &&
                !svc.updateProgress(job.id, 60, "user2"))
        check("G04 done: requires full bytes through legal transitions",
            svc.setJobState(job.id, "active", "user1") && !svc.setJobState(job.id, "done", "user1") &&
                svc.updateProgress(job.id, 100, "user1") && svc.setJobState(job.id, "done", "user1"))

        val svc2 = StandaloneTransferStore(w.roster, w.enrollment, null) { tick() }
        val job2 = svc2.createJob("co", w.hostDeviceId, "user1", "from_host", "logs.zip", 10)
        check("setup: second job live", job2 != null && svc2.liveJobCount() == 1)
        w.roster.setUserSuspended("co", "user1", true, "admin1")
        check("Attack_G04: initiator suspended mid-flight — next act cancels the job",
            !svc2.updateProgress(job2!!.id, 5, "user1") &&
                svc2.job(job2.id)?.state == StandaloneJob.JOB_CANCELLED &&
                svc2.events.any { it.kind == "job_cancelled_authorization_lost" })
        w.roster.setUserSuspended("co", "user1", false, "admin1")
    }

    // ---- G-08 session tunnels ----
    run {
        val id = w.active("s-tunnel")
        val tunnels = SessionTunnelStore(w.sessions, w.roster, null) { tick() }
        check("G08 open: outsider refused", tunnels.open(id, "user3", "192.168.1.10", 8080, 18080) == null)
        check("Attack_G08: wildcard target is not a destination",
            tunnels.open(id, "host1", "0.0.0.0", 8080, 18080) == null)
        val t = tunnels.open(id, "host1", "192.168.1.10", 8080, 18080)
        check("G08 open: host opens inside the live session", t != null)
        check("G08 open: duplicate listen port refuses",
            tunnels.open(id, "host1", "192.168.1.11", 80, 18080) == null)
        check("G08 close: non-opener participant refused", !tunnels.close(t!!.id, "user2"))
        check("G08 dies with session: end + act sweeps it closed",
            w.sessions.endSession(id, "user1") && !tunnels.close(t.id, "host1") &&
                tunnels.tunnel(t.id)?.state == "closed")
    }

    // ---- G-06 second factor ----
    run {
        // RFC 4226 Appendix D vectors through the mirror's Totp.
        val secret = "12345678901234567890".toByteArray(Charsets.US_ASCII)
        check("G06 RFC4226 vectors",
            Totp.hotp(secret, 0) == "755224" && Totp.hotp(secret, 1) == "287082" &&
                Totp.hotp(secret, 2) == "359152")
        val keyGen = KeyGenerator.getInstance("AES").apply { init(256) }
        val sealer = AesGcmSecretSealer(keyGen.generateKey())
        val factors = SecondFactorStore(w.roster, sealer, null) { tick() }
        val begin = factors.beginTotpEnrollment("co", "user1")
        check("G06 enroll: begin issues a secret", begin != null)
        val decoded = io.agenticcontrol.app.crypto.Base32.decode(begin!!.first)
        val now = clockNow
        check("G06 enroll: pending verifies nothing",
            !factors.verifyTotp("co", "user1", Totp.at(decoded!!, now), now))
        check("G06 enroll: confirm proves possession",
            factors.confirmTotpEnrollment("co", "user1", Totp.at(decoded, now), now))
        check("Attack_G06: the confirming code is consumed — replay refuses",
            !factors.verifyTotp("co", "user1", Totp.at(decoded, now), now))
        val next = now + 30_000L
        check("G06 verify: the next step's code verifies",
            factors.verifyTotp("co", "user1", Totp.at(decoded, next), next))
        check("Attack_G06: an AI user holds no factor (D9)",
            factors.beginTotpEnrollment("co", "ai1") == null)
        check("G06 state: the confirmed factor reads active",
            factors.hasActiveTotp("co", "user1"))
    }

    // ---- D38-G review fix round (2026-11-20) ----
    run {
        val keyGen2 = KeyGenerator.getInstance("AES").apply { init(256) }
        val sealer2 = AesGcmSecretSealer(keyGen2.generateKey())

        // AF1/F4: re-enrollment over an ACTIVE factor is
        // possession-gated; the old factor survives until the
        // new one confirms.
        val f2 = SecondFactorStore(w.roster, sealer2, null) { tick() }
        val b1 = f2.beginTotpEnrollment("co", "user2")
        check("Fix_AF1 setup: enroll user2", b1 != null)
        val sec1 = io.agenticcontrol.app.crypto.Base32.decode(b1!!.first)!!
        val t0 = clockNow
        check("Fix_AF1 setup: confirm user2", f2.confirmTotpEnrollment("co", "user2", Totp.at(sec1, t0), t0))
        check("Fix_AF1: begin over active without a code refuses",
            f2.beginTotpEnrollment("co", "user2") == null)
        check("Fix_AF1: begin over active with a wrong code refuses",
            f2.beginTotpEnrollment("co", "user2", "xxxxxx", t0 + 30_000L) == null)
        check("Fix_AF1: the old factor still verifies (no downgrade window)",
            f2.verifyTotp("co", "user2", Totp.at(sec1, t0 + 30_000L), t0 + 30_000L))
        val b2 = f2.beginTotpEnrollment("co", "user2", Totp.at(sec1, t0 + 60_000L), t0 + 60_000L)
        check("Fix_AF1: begin WITH a current code proceeds", b2 != null)
        check("Fix_AF1: old factor STILL active until the new one confirms",
            f2.hasActiveTotp("co", "user2") &&
                f2.verifyTotp("co", "user2", Totp.at(sec1, t0 + 90_000L), t0 + 90_000L))
        val sec2 = io.agenticcontrol.app.crypto.Base32.decode(b2!!.first)!!
        check("Fix_AF1: confirm the new factor",
            f2.confirmTotpEnrollment("co", "user2", Totp.at(sec2, t0 + 120_000L), t0 + 120_000L))
        check("Fix_AF1: the old secret is dead after confirmation",
            !f2.verifyTotp("co", "user2", Totp.at(sec1, t0 + 150_000L), t0 + 150_000L))
        check("Fix_AF1: the new secret verifies",
            f2.verifyTotp("co", "user2", Totp.at(sec2, t0 + 150_000L), t0 + 150_000L))

        // AF10: an imported replay counter cannot roll back.
        val f3 = SecondFactorStore(w.roster, sealer2, null) { tick() }
        val b3 = f3.beginTotpEnrollment("co", "user3")
        val sec3 = io.agenticcontrol.app.crypto.Base32.decode(b3!!.first)!!
        val u0 = clockNow
        check("Fix_AF10 setup: confirm user3", f3.confirmTotpEnrollment("co", "user3", Totp.at(sec3, u0), u0))
        val usedCode = Totp.at(sec3, u0)
        val forged = f3.exportJson().replace(
            Regex("\"lastAcceptedStep\":-?\\d+"), "\"lastAcceptedStep\":-1")
        val f4 = SecondFactorStore(w.roster, sealer2, null) { tick() }
        f4.importJson(forged)
        check("Fix_AF10: the just-used code stays dead after a rolled-back import",
            !f4.verifyTotp("co", "user3", usedCode, u0))
        check("Fix_AF10: a future code still verifies (factor not bricked)",
            f4.verifyTotp("co", "user3", Totp.at(sec3, u0 + 120_000L), u0 + 120_000L))

        // AF4: an imported open tunnel must pass live authority.
        w.active("s-af4")
        val tun = SessionTunnelStore(w.sessions, w.roster, null) { tick() }
        val planted = "[" +
            "{\"id\":\"tp1\",\"sessionId\":\"s-af4\",\"targetHost\":\"192.168.1.10\"," +
            "\"targetPort\":8080,\"listenPort\":18080,\"state\":\"open\"," +
            "\"openedByUserId\":\"user3\",\"openedUtcMs\":1,\"closedUtcMs\":null}," +
            "{\"id\":\"tp2\",\"sessionId\":\"s-af4\",\"targetHost\":\"192.168.1.11\"," +
            "\"targetPort\":8080,\"listenPort\":18081,\"state\":\"open\"," +
            "\"openedByUserId\":\"host1\",\"openedUtcMs\":1,\"closedUtcMs\":null}]"
        tun.importJson(planted)
        check("Fix_AF4: a tunnel planted under a non-participant opener restores CLOSED",
            tun.tunnel("tp1")?.state == "closed")
        check("Fix_AF4: a tunnel under the genuine host opener restores open",
            tun.tunnel("tp2")?.state == "open")

        // AF7/F12b: answering is participant-only, whoever asks.
        w.active("s-af7")
        val call = w.sessions.startCall("s-af7", "user1", "audio")
        check("Fix_AF7 setup: call rings", call != null)
        check("Fix_AF12b: a non-participant company admin cannot answer someone else's call",
            !w.sessions.answerCall(call!!.id, "admin1"))
        check("Fix_AF12b: the host participant answers",
            w.sessions.answerCall(call.id, "host1"))
        check("Fix_AF7 cleanup: end the call", w.sessions.endCall(call.id, "user1"))
        val own = w.sessions.startCall("s-af7", "host1", "audio")
        check("Fix_AF11: the caller cannot answer their own call on the host path either",
            own != null && !w.sessions.answerCall(own.id, "host1"))
        check("Fix_AF11: the other participant answers it",
            w.sessions.answerCall(own!!.id, "user1"))

        // AF8: blocking a session releases the blank + input block.
        w.active("s-af8")
        check("Fix_AF8 setup: blank + block set",
            w.sessions.setBlanked("s-af8", "host1", true) &&
                w.sessions.setInputBlocked("s-af8", "host1", true))
        check("Fix_AF8 setup: session blocks", w.sessions.blockSession("s-af8", "host1"))
        val blockedSession = w.sessions.session("s-af8")
        check("Fix_AF8: blocked record carries neither flag (live == reloaded)",
            blockedSession != null && !blockedSession.blanked && !blockedSession.inputBlocked)

        // AF2 (read half): tunnel reads sweep a dead session's tunnels.
        w.active("s-af2")
        val tun2 = SessionTunnelStore(w.sessions, w.roster, null) { tick() }
        val t2 = tun2.open("s-af2", "host1", "192.168.1.10", 8080, 18080)
        check("Fix_AF2 setup: tunnel open", t2 != null)
        check("Fix_AF2 setup: session ends", w.sessions.endSession("s-af2", "user1"))
        check("Fix_AF2: openTunnels() reports nothing over the dead session (no close call made)",
            tun2.openTunnels().isEmpty() && tun2.tunnel(t2!!.id)?.state == "closed")

        // AF5: a stored accept with no proving event is repaired,
        // and the live attended session demotes to requested.
        val w5 = BlockGWorld(dir, "fx5")
        w5.active("s-fx5")
        val tsv = File(dir, "fx5-sessions.tsv").readLines()
        val forgedLines = tsv.filterNot { line ->
            val p = line.split('\t')
            p.getOrNull(0) == "event" && p.getOrNull(3) == "accepted"
        }
        File(dir, "fx5-forged.tsv").writeText(forgedLines.joinToString("\n"))
        val reloaded = SessionStore(File(dir, "fx5-forged.tsv"), w5.roster, w5.enrollment) { tick() }
        val sFx = reloaded.session("s-fx5")
        check("Fix_AF5: accept with no proving event is cleared",
            sFx != null && sFx.acceptBy == null)
        check("Fix_AF5: the unproven live attended session demotes to requested",
            sFx?.state == "requested")
    }

    dir.deleteRecursively()
    println(if (failures == 0) "ALL BLOCK G TESTS PASSED" else "$failures BLOCK G TEST(S) FAILED")
    if (failures > 0) kotlin.system.exitProcess(1)
}
