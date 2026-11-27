import io.deskguest.app.access.LiveTreeNode
import io.deskguest.app.access.LiveTreeSearch
import io.deskguest.app.access.SnapshotStore
import io.deskguest.app.adb.AdbPairing
import io.deskguest.app.aipack.AiPackManifest
import io.deskguest.app.aipack.AiPackService
import io.deskguest.app.aipack.PackFile
import io.deskguest.app.crypto.Base32
import io.deskguest.app.crypto.SecondFactorStore
import io.deskguest.app.crypto.Totp
import io.deskguest.app.enrollment.DeviceIdentity
import io.deskguest.app.enrollment.EnrollmentStore
import io.deskguest.app.enterprise.PolicyBundle
import io.deskguest.app.enterprise.PolicyEnforcer
import io.deskguest.app.enterprise.PolicyFeatures
import io.deskguest.app.mesh.MeshProtocol
import io.deskguest.app.quickassist.QuickAssistService
import io.deskguest.app.roster.RosterStore
import io.deskguest.app.crypto.AesGcmLineCipher
import io.deskguest.app.server.McpCore
import io.deskguest.app.server.PairingStore
import io.deskguest.app.server.SessionManager
import io.deskguest.app.session.SessionStore
import io.deskguest.app.session.SessionTunnelStore
import io.deskguest.app.session.StandaloneJob
import io.deskguest.app.session.StandaloneTransferStore
import io.deskguest.app.update.ManifestVerifier
import io.deskguest.app.wiring.AesGcmSecretSealer
import io.deskguest.app.wiring.PlatformStores
import io.deskguest.app.wiring.PlatformToolHost
import java.io.File
import java.math.BigInteger
import java.nio.file.Files
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.util.Base64
import javax.crypto.KeyGenerator
import org.json.JSONObject

/**
 * JVM tests for Block H (Android lane): designs 1–5 (factor
 * throttling, passkey challenge binding, tunnel destination
 * allowlist, per-act floor-grant re-check, policy-change
 * teardown sweeps) and the Block H Android destruction battery
 * (Attack_H*). Attack entries are recorded in
 * ~/workspace/windows-agent/DESTRUCTION-LEDGER.md, "Block H —
 * Android destruction" (DG-H-A##).
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

private class BlockHWorld(dir: File, tag: String) {
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

private fun ec32(v: BigInteger): ByteArray {
    val b = v.toByteArray()
    return when {
        b.size == 32 -> b
        b.size > 32 -> b.copyOfRange(b.size - 32, b.size)
        else -> ByteArray(32 - b.size) { 0 } + b
    }
}

private data class Ceremony(
    val credentialId: String, val authData: ByteArray, val clientData: String, val signature: ByteArray
)

/** The test credential id, in valid standard Base64 (as
 *  registerPasskey requires — it decodes the id at the door). */
private const val CRED_ID = "Y3JlZC1oMQ=="

/** Build a WebAuthn-shaped assertion for [challenge] under a fresh
 *  P-256 key; returns the ceremony plus the keypair (registered by
 *  the caller on first use). */
private fun ceremony(kp: java.security.KeyPair, challenge: String, rpId: String, signCount: Long): Ceremony {
    val rpHash = MessageDigest.getInstance("SHA-256").digest(rpId.toByteArray(Charsets.UTF_8))
    val counter = byteArrayOf(
        (signCount shr 24).toByte(), (signCount shr 16).toByte(),
        (signCount shr 8).toByte(), signCount.toByte()
    )
    val authData = rpHash + byteArrayOf(0x01) + counter
    val clientData = """{"type":"webauthn.get","challenge":"$challenge","origin":"https://$rpId","crossOrigin":false}"""
    val clientHash = MessageDigest.getInstance("SHA-256").digest(clientData.toByteArray(Charsets.UTF_8))
    val signer = Signature.getInstance("SHA256withECDSA")
    signer.initSign(kp.private)
    signer.update(authData + clientHash)
    return Ceremony(CRED_ID, authData, clientData, signer.sign())
}

private fun registerKey(factors: SecondFactorStore, kp: java.security.KeyPair, userId: String): Boolean {
    val pub = kp.public as ECPublicKey
    return factors.registerPasskey(
        "co", userId, CRED_ID,
        Base64.getEncoder().encodeToString(ec32(pub.w.affineX)),
        Base64.getEncoder().encodeToString(ec32(pub.w.affineY))
    )
}

fun main() {
    val dir = Files.createTempDirectory("deskguest-blockh").toFile()
    val w = BlockHWorld(dir, "h")
    val keyGen = KeyGenerator.getInstance("AES").apply { init(256) }
    val sealer = AesGcmSecretSealer(keyGen.generateKey())
    val t0 = 1_700_000_000_000L

    // ============ Design 1: factor attempt throttling (TOTP) ============
    run {
        var now = t0
        val f = SecondFactorStore(w.roster, sealer, null, null) { now }
        val begin = f.beginTotpEnrollment("co", "user1")
        check("H1 setup: enroll user1", begin != null)
        val secret = Base32.decode(begin!!.first)!!
        check("H1 setup: confirm user1", f.confirmTotpEnrollment("co", "user1", Totp.at(secret, now), now))
        // Four failures, then a success: the counter resets, no lockout.
        var t = now + 30_000L
        repeat(4) {
            check("H1: wrong code ${it + 1}/4 refuses", !f.verifyTotp("co", "user1", "xxxxxx", t))
            t += 30_000L
        }
        check("H1: correct code after 4 failures verifies (no lockout yet)",
            f.verifyTotp("co", "user1", Totp.at(secret, t), t))
        check("H1: no throttle event yet", f.events.none { it.kind == "factor_throttled" })
        // Five consecutive failures engage the lockout.
        t += 30_000L
        repeat(5) {
            check("H1: wrong code ${it + 1}/5 refuses", !f.verifyTotp("co", "user1", "xxxxxx", t))
            t += 30_000L
        }
        check("H1: throttle engagement is recorded",
            f.events.any { it.kind == "factor_throttled" && it.userId == "user1" })
        check("H1: the CORRECT code refuses during lockout (material never checked)",
            !f.verifyTotp("co", "user1", Totp.at(secret, t), t))
        val after = t + SecondFactorStore.THROTTLE_LOCKOUT_MS + 30_000L
        // F1 fix: the lockout runs on the STORE clock — expiry is
        // the store clock passing the lockout, not the caller
        // presenting a later timestamp.
        now = after
        check("H1: correct code verifies again after the lockout expires",
            f.verifyTotp("co", "user1", Totp.at(secret, after), after))
    }

    // Design 1: the throttle is shared across verify paths.
    run {
        var now = t0
        val f = SecondFactorStore(w.roster, sealer, null, null) { now }
        val b = f.beginTotpEnrollment("co", "user2")
        val secret = Base32.decode(b!!.first)!!
        check("H1 setup: confirm user2", f.confirmTotpEnrollment("co", "user2", Totp.at(secret, now), now))
        var t = now + 30_000L
        repeat(3) { check("H1 cross-path: verify failure ${it + 1}/3", !f.verifyTotp("co", "user2", "xxxxxx", t)); t += 30_000L }
        repeat(2) {
            check("H1 cross-path: re-enrollment wrong-code failure ${it + 1}/2",
                f.beginTotpEnrollment("co", "user2", "xxxxxx", t) == null)
            t += 30_000L
        }
        check("H1 cross-path: 3 verify + 2 re-enrollment failures engage the shared lockout",
            f.events.any { it.kind == "factor_throttled" && it.userId == "user2" } &&
                !f.verifyTotp("co", "user2", Totp.at(secret, t), t) &&
                f.beginTotpEnrollment("co", "user2", Totp.at(secret, t), t) == null)
    }

    // Design 1: confirm path is throttled too.
    run {
        var now = t0
        val f = SecondFactorStore(w.roster, sealer, null, null) { now }
        val b = f.beginTotpEnrollment("co", "user3")
        val secret = Base32.decode(b!!.first)!!
        repeat(5) { check("H1 confirm: wrong confirm ${it + 1}/5 refuses", !f.confirmTotpEnrollment("co", "user3", "xxxxxx", now)) }
        check("H1 confirm: the CORRECT confirm refuses during lockout",
            !f.confirmTotpEnrollment("co", "user3", Totp.at(secret, now), now))
        val after = now + SecondFactorStore.THROTTLE_LOCKOUT_MS + 30_000L
        now = after // F1 fix: advance the STORE clock past the lockout
        check("H1 confirm: correct confirm succeeds after lockout (fresh step)",
            f.confirmTotpEnrollment("co", "user3", Totp.at(secret, after), after))
    }

    // Design 1: persistence — counts persist, import max-merges,
    // an import never clears a live lockout.
    run {
        var now = t0
        val fa = SecondFactorStore(w.roster, sealer, null, null) { now }
        val b = fa.beginTotpEnrollment("co", "user1")
        val secret = Base32.decode(b!!.first)!!
        check("H1 persist setup: confirm", fa.confirmTotpEnrollment("co", "user1", Totp.at(secret, now), now))
        var t = now + 30_000L
        repeat(3) { check("H1 persist: failure ${it + 1}/3", !fa.verifyTotp("co", "user1", "xxxxxx", t)); t += 30_000L }
        val exported = fa.exportJson()
        check("H1 persist: throttle state is in the export", exported.contains("\"throttle\""))
        val fb = SecondFactorStore(w.roster, sealer, null, null) { now }
        fb.importJson(exported)
        repeat(2) { check("H1 persist: imported count + failure ${it + 1}/2", !fb.verifyTotp("co", "user1", "xxxxxx", t)); t += 30_000L }
        check("H1 persist: 3 exported + 2 fresh failures engage the lockout in the importing store",
            fb.events.any { it.kind == "factor_throttled" } &&
                !fb.verifyTotp("co", "user1", Totp.at(secret, t), t))
        // Max-merge: fa (3 failures, no lockout) imports fb's export
        // (lockout live) — fa must come under the lockout, never the
        // reverse.
        fa.importJson(fb.exportJson())
        check("H1 persist: importing a locked export locks the importer (max-merge)",
            !fa.verifyTotp("co", "user1", Totp.at(secret, t), t))
        // And a stale export (no lockout) can never clear it.
        val fc = SecondFactorStore(w.roster, sealer, null, null) { now }
        val bc = fc.beginTotpEnrollment("co", "user2")
        val secretC = Base32.decode(bc!!.first)!!
        check("H1 persist setup: confirm fc user2", fc.confirmTotpEnrollment("co", "user2", Totp.at(secretC, now), now))
        var tc = now + 30_000L
        repeat(5) { fc.verifyTotp("co", "user2", "xxxxxx", tc); tc += 30_000L }
        val stale = SecondFactorStore(w.roster, sealer, null, null) { now }.exportJson()
        fc.importJson(stale)
        check("H1 persist: a stale import never clears a live lockout",
            !fc.verifyTotp("co", "user2", Totp.at(secretC, tc), tc))
    }

    // ============ Design 2: passkey challenge binding ============
    run {
        var now = t0
        val f = SecondFactorStore(w.roster, sealer, null, null) { now }
        val kp = KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair()
        check("H2 setup: register passkey", registerKey(f, kp, "user1"))
        val rp = "example.com"
        // An assertion answering a challenge the store never issued refuses.
        val forged = ceremony(kp, "never-issued-challenge", rp, 1)
        check("H2: unissued challenge refuses",
            !f.verifyPasskeyAssertion("co", "user1", CRED_ID, forged.authData, forged.clientData,
                forged.signature, "never-issued-challenge", rp))
        // Issued challenge verifies exactly once.
        val ch1 = f.issuePasskeyChallenge("co", "user1")
        check("H2: challenge issued (base64url, 32 bytes)", ch1 != null && ch1.length == 43)
        val c1 = ceremony(kp, ch1!!, rp, 1)
        check("H2: assertion answering the issued challenge verifies",
            f.verifyPasskeyAssertion("co", "user1", CRED_ID, c1.authData, c1.clientData, c1.signature, ch1, rp))
        val replay = ceremony(kp, ch1, rp, 2)
        check("H2: replay against the consumed challenge refuses",
            !f.verifyPasskeyAssertion("co", "user1", CRED_ID, replay.authData, replay.clientData,
                replay.signature, ch1, rp))
        // Expiry: 300 s.
        val chE = f.issuePasskeyChallenge("co", "user1")!!
        now += SecondFactorStore.PASSKEY_CHALLENGE_TTL_MS + 1_000L
        val cE = ceremony(kp, chE, rp, 2)
        check("H2: an expired challenge refuses",
            !f.verifyPasskeyAssertion("co", "user1", CRED_ID, cE.authData, cE.clientData, cE.signature, chE, rp))
        // Ephemeral: export/import does not carry challenges.
        now = t0
        val chX = f.issuePasskeyChallenge("co", "user1")!!
        val f2 = SecondFactorStore(w.roster, sealer, null, null) { now }
        f2.importJson(f.exportJson())
        val cX = ceremony(kp, chX, rp, 2)
        check("H2: a challenge does not survive export/import (restart invalidates ceremonies)",
            !f2.verifyPasskeyAssertion("co", "user1", CRED_ID, cX.authData, cX.clientData, cX.signature, chX, rp))

        // Burn-on-attempt + supersession (fresh store: the shared
        // throttle would otherwise lock the sequence out by design).
        val fB = SecondFactorStore(w.roster, sealer, null, null) { now }
        check("H2 setup: register passkey (burn store)", registerKey(fB, kp, "user1"))
        val ch2 = fB.issuePasskeyChallenge("co", "user1")!!
        val good = ceremony(kp, ch2, rp, 1)
        val badSig = Ceremony(good.credentialId, good.authData, good.clientData, ByteArray(64) { 7 })
        check("H2: bad-signature attempt fails",
            !fB.verifyPasskeyAssertion("co", "user1", CRED_ID, badSig.authData, badSig.clientData,
                badSig.signature, ch2, rp))
        check("H2: the honest retry on the burned challenge refuses",
            !fB.verifyPasskeyAssertion("co", "user1", CRED_ID, good.authData, good.clientData,
                good.signature, ch2, rp))
        // One outstanding: issuing supersedes. The superseded
        // attempt still REACHES the challenge check, so it burns
        // the outstanding challenge too (burn-on-attempt) — the
        // honest chB ceremony dies with it and a fresh challenge
        // is needed.
        val chA = fB.issuePasskeyChallenge("co", "user1")!!
        val chB = fB.issuePasskeyChallenge("co", "user1")!!
        val cA = ceremony(kp, chA, rp, 1)
        check("H2: a superseded challenge refuses",
            !fB.verifyPasskeyAssertion("co", "user1", CRED_ID, cA.authData, cA.clientData, cA.signature, chA, rp))
        val cB = ceremony(kp, chB, rp, 1)
        check("H2: burn-on-attempt — the superseded attempt consumed the current challenge too",
            !fB.verifyPasskeyAssertion("co", "user1", CRED_ID, cB.authData, cB.clientData, cB.signature, chB, rp))
        val chC = fB.issuePasskeyChallenge("co", "user1")!!
        val cC = ceremony(kp, chC, rp, 1)
        check("H2: a freshly issued challenge verifies",
            fB.verifyPasskeyAssertion("co", "user1", CRED_ID, cC.authData, cC.clientData, cC.signature, chC, rp))

        // Passkey failures feed the shared throttle (design 1).
        now = t0
        val f3 = SecondFactorStore(w.roster, sealer, null, null) { now }
        check("H2 setup: register for throttle", registerKey(f3, kp, "user2"))
        repeat(5) { i ->
            val ch = f3.issuePasskeyChallenge("co", "user2")!!
            val cer = ceremony(kp, ch, rp, (i + 1).toLong())
            val bad = Ceremony(cer.credentialId, cer.authData, cer.clientData, ByteArray(64) { 3 })
            check("H2 throttle: bad assertion ${i + 1}/5 refuses",
                !f3.verifyPasskeyAssertion("co", "user2", CRED_ID, bad.authData, bad.clientData,
                    bad.signature, ch, rp))
        }
        now = t0 + 200_000L // still inside the lockout (300 s from t0)
        val chGood = f3.issuePasskeyChallenge("co", "user2")!!
        val cGood = ceremony(kp, chGood, rp, 6)
        check("H2 throttle: a fully valid assertion refuses during the passkey-earned lockout",
            !f3.verifyPasskeyAssertion("co", "user2", CRED_ID, cGood.authData, cGood.clientData,
                cGood.signature, chGood, rp))
        now = t0 + SecondFactorStore.THROTTLE_LOCKOUT_MS + 1_000L // lockout over; challenge (issued t0+200 s) still live
        check("H2 throttle: the lockout refusal did NOT burn the challenge — it verifies after expiry",
            f3.verifyPasskeyAssertion("co", "user2", CRED_ID, cGood.authData, cGood.clientData,
                cGood.signature, chGood, rp))
    }

    // ============ Design 3: tunnel destination allowlist ============
    run {
        val id = w.active("s-h3")
        val open = SessionTunnelStore(w.sessions, w.roster, null,
            allowedTargets = setOf("192.168.1.10:8080", "DB.Internal:5432")) { tick() }
        check("H3: allowlisted target opens", open.open(id, "host1", "192.168.1.10", 8080, 18080) != null)
        check("H3: host match is case-insensitive", open.open(id, "host1", "db.internal", 5432, 18081) != null)
        check("H3: off-list host refuses", open.open(id, "host1", "192.168.1.11", 8080, 18082) == null)
        check("H3: off-list port refuses", open.open(id, "host1", "192.168.1.10", 8081, 18083) == null)
        val empty = SessionTunnelStore(w.sessions, w.roster, null, allowedTargets = emptySet()) { tick() }
        check("H3: an EMPTY allowlist refuses everything (configured, not absent)",
            empty.open(id, "host1", "192.168.1.10", 8080, 18084) == null)
        val planted = "[" +
            "{\"id\":\"ta1\",\"sessionId\":\"$id\",\"targetHost\":\"192.168.1.99\",\"targetPort\":8080," +
            "\"listenPort\":18090,\"state\":\"open\",\"openedByUserId\":\"host1\",\"openedUtcMs\":1,\"closedUtcMs\":null}," +
            "{\"id\":\"ta2\",\"sessionId\":\"$id\",\"targetHost\":\"192.168.1.10\",\"targetPort\":8080," +
            "\"listenPort\":18091,\"state\":\"open\",\"openedByUserId\":\"host1\",\"openedUtcMs\":1,\"closedUtcMs\":null}]"
        val imp = SessionTunnelStore(w.sessions, w.roster, null,
            allowedTargets = setOf("192.168.1.10:8080")) { tick() }
        imp.importJson(planted)
        check("H3: an imported open tunnel to an off-list target restores CLOSED",
            imp.tunnel("ta1")?.state == "closed")
        check("H3: an imported open tunnel to an allowlisted target restores open",
            imp.tunnel("ta2")?.state == "open")
        w.sessions.endSession(id, "user1")
    }

    // ============ Design 4: per-act floor-grant re-check ============
    run {
        val id = w.active("s-h4")
        check("H4 setup: floor to user1", w.sessions.grantFloor(id, "host1", "user1"))
        check("H4: floor holder WITH the use grant enables the blank",
            w.sessions.setBlanked(id, "user1", true))
        check("H4 setup: grant revoked mid-session",
            w.roster.removeUserFromGroup("co", "ug1", "user1", "admin1"))
        check("H4: the ex-grant floor holder can no longer enable surfaces",
            !w.sessions.setInputBlocked(id, "user1", true) && !w.sessions.setBlanked(id, "user1", true))
        check("H4: CLEARING stays ungated — the ex-grant holder clears the blank",
            w.sessions.setBlanked(id, "user1", false))
        check("H4 setup: grant restored", w.roster.addUserToGroup("co", "ug1", "user1", "admin1"))
        check("H4: the re-granted holder enables again", w.sessions.setBlanked(id, "user1", true))
        check("H4 cleanup: clear blank", w.sessions.setBlanked(id, "host1", false))

        // A participant with NO grant at all: floor alone is not enough.
        check("H4 setup: user3 joins as controller",
            w.sessions.addParticipant(id, "host1", "user3", "controller"))
        check("H4 setup: floor to user3", w.sessions.grantFloor(id, "host1", "user3"))
        check("H4: floor holder without the use grant cannot enable the watermark",
            !w.sessions.setWatermarked(id, "user3", true))
        check("H4: floor holder without the use grant cannot start a call",
            w.sessions.startCall(id, "user3", "audio") == null)
        val hostCall = w.sessions.startCall(id, "host1", "audio")
        check("H4: host-side actor starts a call (exempt)", hostCall != null)
        check("H4: answer by a participant without the use grant refuses",
            !w.sessions.answerCall(hostCall!!.id, "user3"))
        check("H4: answer by a participant WITH the use grant succeeds",
            w.sessions.answerCall(hostCall.id, "user1"))
        check("H4: call END stays ungated — the grant-less participant hangs up",
            w.sessions.endCall(hostCall.id, "user3"))
        // Host-side exemption proven against a host with no grant.
        check("H4 setup: host's own grant removed",
            w.roster.removeUserFromGroup("co", "ug1", "host1", "admin1"))
        check("H4: the host participant enables surfaces with NO grant (host-side exempt)",
            w.sessions.setBlanked(id, "host1", true))
        check("H4 cleanup: restore host grant + clear",
            w.roster.addUserToGroup("co", "ug1", "host1", "admin1") &&
                w.sessions.setBlanked(id, "host1", false))
        w.sessions.endSession(id, "user1")
    }

    // ============ Design 5: policy-change teardown sweeps ============
    run {
        val id = w.active("s-h5")
        check("H5 setup: surfaces set",
            w.sessions.setBlanked(id, "host1", true) &&
                w.sessions.setInputBlocked(id, "host1", true) &&
                w.sessions.setWatermarked(id, "host1", true))
        val call = w.sessions.startCall(id, "user1", "video")
        check("H5 setup: call ringing", call != null)
        val tunnels = SessionTunnelStore(w.sessions, w.roster, null) { tick() }
        val tun = tunnels.open(id, "host1", "192.168.1.10", 8080, 18080)
        check("H5 setup: tunnel open", tun != null)
        val transfers = StandaloneTransferStore(w.roster, w.enrollment, null) { tick() }
        val job = transfers.createJob("co", w.hostDeviceId, "user1", "to_host", "report.pdf", 10)
        check("H5 setup: standalone job live", job != null)

        val partial = w.sessions.sweepPolicyTeardown("co") { it == PolicyFeatures.VOICE_VIDEO || it == PolicyFeatures.BLANK_SCREEN }
        val afterPartial = w.sessions.session(id)!!
        check("H5: partial sweep ends the call + clears the blank, leaves input + watermark",
            partial == 2 && w.sessions.liveCall(id) == null && !afterPartial.blanked &&
                afterPartial.inputBlocked && afterPartial.watermarked)
        check("H5: sweep acts are recorded with actor 'policy'",
            w.sessions.events(id).any { it.type == SessionStore.EVENT_BLANK_CLEARED && it.actorUserId == "policy" } &&
                w.sessions.events(id).any { it.type == SessionStore.EVENT_CALL_ENDED && it.actorUserId == "policy" })
        check("H5: tunnel sweep closes the scope's open tunnels",
            tunnels.sweepPolicyTeardown("co") { it == PolicyFeatures.TCP_TUNNEL } == 1 &&
                tunnels.tunnel(tun!!.id)?.state == "closed" &&
                tunnels.events.any { it.kind == "tunnel_closed_policy_teardown" && it.actorUserId == "policy" })
        check("H5: tunnel sweep for another scope closes nothing",
            tunnels.sweepPolicyTeardown("other") { true } == 0)
        check("H5: transfer sweep cancels the scope's live jobs, actor 'policy'",
            transfers.sweepPolicyTeardown("co") { it == PolicyFeatures.STANDALONE_FILE_TRANSFER } == 1 &&
                transfers.job(job!!.id)?.state == StandaloneJob.JOB_CANCELLED &&
                transfers.events.any { it.kind == "job_cancelled_policy_teardown" && it.actorUserId == "policy" })
        val rest = w.sessions.sweepPolicyTeardown("co") { true }
        val afterAll = w.sessions.session(id)!!
        check("H5: full sweep clears what remains (input + watermark)",
            rest == 2 && !afterAll.inputBlocked && !afterAll.watermarked)
        check("H5: a sweep with nothing disabled is a no-op",
            w.sessions.sweepPolicyTeardown("co") { false } == 0 &&
                tunnels.sweepPolicyTeardown("co") { false } == 0 &&
                transfers.sweepPolicyTeardown("co") { false } == 0)
        w.sessions.endSession(id, "user1")
    }

    // Design 5: the PlatformStores wiring — installing an enforcer sweeps.
    run {
        val stores = PlatformStores(File(dir, "ps"))
        stores.addScope("co", "company", "Acme Co")
        stores.addUser("co", "admin1", "Admin One", "human")
        stores.addCompanyAdmin("co", "admin1")
        stores.addUser("co", "host1", "Host User", "human")
        stores.addUser("co", "user1", "User One", "human")
        stores.addUserGroup("co", "ug1", "Techs", "admin1")
        stores.addUserToGroup("co", "ug1", "user1", "admin1")
        stores.addUserToGroup("co", "ug1", "host1", "admin1")
        stores.addDeviceGroup("co", "dg1", "Fleet", listOf("lan", "hub", "mesh"), "admin1")
        stores.addGrant("co", "ug1", "dg1", setOf("use"), "admin1")
        val code = stores.mintEnrollment("company", "dg1", "Fleet")
        val enrolled = stores.redeemOwn(code, "This Phone", "Admin One", "op-device")
        check("H5 wiring setup: device enrolled", enrolled != null)
        check("H5 wiring setup: session live + blanked",
            stores.createSession("ps1", "co", enrolled!!.deviceId, "user1", "host1", "attended", "lan") &&
                stores.acceptLocal("ps1", "host1") && stores.startSession("ps1", "user1") &&
                stores.sessions.setBlanked("ps1", "host1", true))
        fun bundle(scope: String, disabledFeatures: List<String>) = PolicyBundle(
            version = 2, scopeId = scope, transportCeiling = listOf("lan", "hub", "mesh"),
            transportMode = "auto", pinnedVersion = null, updateDeferUntilMillis = null,
            forbidAiPairings = false, disableRecording = false, unattendedTier = "standard",
            issuedMillis = t0, expiresMillis = t0 + 3_600_000L, signatureBase64 = "",
            disabledFeatures = disabledFeatures
        )
        stores.policyEnforcer = PolicyEnforcer(bundle("other", listOf(PolicyFeatures.BLANK_SCREEN)))
        check("H5 wiring: an enforcer for ANOTHER scope sweeps nothing here",
            stores.sessions.session("ps1")?.blanked == true)
        stores.policyEnforcer = PolicyEnforcer(bundle("co", listOf(PolicyFeatures.BLANK_SCREEN)))
        check("H5 wiring: installing the scope's enforcer tears down the disabled surface",
            stores.sessions.session("ps1")?.blanked == false)
        stores.endSession("ps1", "user1")
    }

    // ================================================================
    // DESTRUCTION BATTERY (item 6) — DG-H-A## in the ledger.
    // ================================================================

    // ---- DG-H-A01..A06: MCP protocol core ----
    run {
        val host = CountingHost()
        val storeFile = File(dir, "pairings-h.tsv")
        val store = PairingStore(storeFile)
        val core = McpCore(store, host)
        fun rpc(body: String, token: String? = null) = core.handle(body, token)
        fun callTool(token: String?, name: String) = rpc(
            """{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"$name","arguments":{}}}""", token)

        // A01: no token / garbage / near-miss tokens all refuse.
        check("Attack_H_A01: tools/list without a token -> 401",
            rpc("""{"jsonrpc":"2.0","id":1,"method":"tools/list"}""").httpStatus == 401)
        check("Attack_H_A01: tools/call with a garbage token -> 401",
            callTool("f".repeat(64), "device_info").httpStatus == 401)
        val token = pairViaCore(core, store)
        check("Attack_H_A01: prefix / extended / case-flipped tokens -> 401",
            rpc("""{"jsonrpc":"2.0","id":1,"method":"tools/list"}""", token.dropLast(1)).httpStatus == 401 &&
                rpc("""{"jsonrpc":"2.0","id":1,"method":"tools/list"}""", token + "00").httpStatus == 401 &&
                rpc("""{"jsonrpc":"2.0","id":1,"method":"tools/list"}""", token.uppercase()).httpStatus == 401)
        check("Attack_H_A01: the real token works", callTool(token, "device_info").httpStatus == 200 &&
            host.runs["device_info"] == 1)

        // A02: pair as a notification (no id) issues NOTHING and
        // does not consume the code.
        val code2 = store.beginPairing("Sneaky")
        val notif = rpc("""{"jsonrpc":"2.0","method":"pair","params":{"code":"$code2"}}""")
        check("Attack_H_A02: pair-by-notification gets 202, no body, no pairing",
            notif.httpStatus == 202 && notif.body == null && store.all().size == 1)
        check("Attack_H_A02: the code still redeems through the front door afterwards",
            rpc("""{"jsonrpc":"2.0","id":2,"method":"pair","params":{"code":"$code2"}}""")
                .body?.contains("\"token\"") == true)

        // A03: malformed + batch bodies — parse-level refusal,
        // zero side effects.
        val runsBefore = host.runs.values.sum()
        val pairingsBefore = store.all().size
        val malformed = listOf("", "[]", "{", "null",
            """[{"jsonrpc":"2.0","id":1,"method":"pair","params":{"code":"$code2"}}]""",
            """{"jsonrpc":"2.0","id":9,"method":123}""")
        var allAnswered = true
        for (body in malformed) {
            val r = try { rpc(body) } catch (e: Exception) { allAnswered = false; null }
            if (r == null || (r.httpStatus != 200 && r.httpStatus != 202)) allAnswered = false
        }
        check("Attack_H_A03: malformed/batch bodies answered without crashing", allAnswered)
        check("Attack_H_A03: the batch pair executed NOTHING (no pairing, no tool run)",
            store.all().size == pairingsBefore && host.runs.values.sum() == runsBefore)

        // A04: method confusion.
        check("Attack_H_A04: tools/call before pairing -> 401",
            callTool(null, "device_info").httpStatus == 401)
        val unknown = rpc("""{"jsonrpc":"2.0","id":3,"method":"admin/nuke"}""", token)
        check("Attack_H_A04: unknown method with a valid token -> -32601",
            unknown.body?.contains("-32601") == true)
        check("Attack_H_A04: initialize does not widen an observe pairing",
            rpc("""{"jsonrpc":"2.0","id":4,"method":"initialize","params":{}}""").httpStatus == 200 &&
                store.pairingForToken(token)?.scopes == setOf("observe"))

        // A05: scope escape — an observe pairing cannot run a
        // drive-scope tool even when no capability maps to it.
        val esc = callTool(token, "drive_thing")
        check("Attack_H_A05: drive-scope tool refused for an observe pairing, never run",
            esc.body?.contains("\"isError\":true") == true && host.runs["drive_thing"] == null)

        // A01b: revocation kills the token immediately.
        check("Attack_H_A01: revoked token -> 401 on the next call",
            store.revoke(token) && callTool(token, "device_info").httpStatus == 401)
    }

    // A06: scope/capability mismatch — scopes alone never suffice.
    run {
        val host = CountingHost()
        val store = PairingStore(File(dir, "pairings-h6.tsv"))
        val core = McpCore(store, host)
        val code = store.beginPairing("Wide Scopes")
        val pairing = store.redeem(code, PairingStore.ALL_SCOPES)
        check("Attack_H_A06 setup: pairing holds ALL scopes but only observe caps",
            pairing != null && pairing.caps == PairingStore.OBSERVE_CAPS)
        val shell = core.handle(
            """{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"shell_exec","arguments":{"command":"id"}}}""",
            pairing!!.token)
        check("Attack_H_A06: shell_exec refused on capability despite the shell scope, never run",
            shell.body?.contains("capability") == true && host.runs["shell_exec"] == null)
        val start = core.handle(
            """{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"start_session","arguments":{}}}""",
            pairing.token)
        check("Attack_H_A06: start_session refused without a drive capability, never run",
            start.body?.contains("\"isError\":true") == true && host.runs["start_session"] == null)
    }

    // ---- DG-H-A07: SessionManager lifecycle / STOP ----
    run {
        SessionManager.end()
        val gen0 = SessionManager.generation.get()
        val s = SessionManager.start("Attack AI")
        check("Attack_H_A07: session starts; a second start is refused, never stacked",
            s != null && SessionManager.start("Second AI") == null)
        check("Attack_H_A07: drive allowed while active", SessionManager.driveRefusal() == null)
        check("Attack_H_A07: touch-to-yield pauses and drive + capture both refuse",
            SessionManager.pauseByUser() && SessionManager.driveRefusal() != null &&
                SessionManager.observeRefusal() != null)
        check("Attack_H_A07: after resume, drive refuses until a FRESH snapshot is taken",
            SessionManager.resume() && SessionManager.driveRefusal() != null)
        SessionManager.noteSnapshotTaken()
        check("Attack_H_A07: fresh snapshot re-arms drive", SessionManager.driveRefusal() == null)
        SessionManager.pauseByUser()
        SessionManager.stopByUser()
        check("Attack_H_A07: STOP from paused ends the session and clears presence state",
            SessionManager.active == null && SessionManager.state == SessionManager.State.IDLE &&
                SessionManager.driveRefusal() != null)
        check("Attack_H_A07: no session leak — a new session can start immediately",
            SessionManager.start("Next AI") != null)
        check("Attack_H_A07: generation advanced monotonically through the lifecycle",
            SessionManager.generation.get() > gen0)
        SessionManager.end()
        check("Attack_H_A07: ending with no session is an honest null, not a phantom",
            SessionManager.end() == null && SessionManager.active == null)
    }

    // ---- DG-H-A08: the platform tool surface offers no control ----
    run {
        val host = PlatformToolHost { null }
        val names = host.tools().map { it.name }.toSet()
        check("Attack_H_A08: the platform surface is exactly the two read-only tools",
            names == setOf("platform_sessions", "platform_session_status"))
        check("Attack_H_A08: no accept/stop/start/transition tool exists to call",
            names.none { it.contains("accept") || it.contains("stop") || it.contains("start") })
        val out = host.tools().first { it.name == "platform_sessions" }.run(JSONObject())
        check("Attack_H_A08: with stores closed the tool answers an error, never fabricates",
            out.contains("not open"))
    }

    // ---- DG-H-A09: PairingStore hostile file (CRACKED + fixed) ----
    run {
        val hostile = File(dir, "pairings-hostile.tsv")
        val plantedToken = "aa".repeat(32)
        hostile.writeText(
            "Attacker\t$plantedToken\tobserve,drive,root,admin\t1700000000000\tEvil\t1\tfull\tsee,shell,evilcap,admin2")
        val store = PairingStore(hostile)
        val loaded = store.pairingForToken(plantedToken)
        check("Attack_H_A09: unknown caps in a hand-edited pairing file are DROPPED at load",
            loaded != null && loaded.caps == setOf("see", "shell"))
        check("Attack_H_A09: unknown scopes in a hand-edited pairing file are DROPPED at load",
            loaded != null && loaded.scopes == setOf("observe", "drive", "admin"))
        // A token wrapped under another key fails closed.
        val keyA = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
        val keyB = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
        val wrappedFile = File(dir, "pairings-wrapped.tsv")
        val storeA = PairingStore(wrappedFile, AesGcmLineCipher(keyA))
        val code = storeA.beginPairing("Wrapped")
        check("Attack_H_A09 setup: pairing saved wrapped", storeA.redeem(code, setOf("observe")) != null)
        check("Attack_H_A09: a store file wrapped under a lost key loads EMPTY (fail closed)",
            PairingStore(wrappedFile, AesGcmLineCipher(keyB)).all().isEmpty())
    }

    // ---- DG-H-A10: SnapshotStore stale refs + budgets ----
    run {
        val ss = SnapshotStore()
        fun entry(ref: String) = SnapshotStore.Entry(ref, "OK", "", "Button", 0, 0, 10, 10,
            clickable = true, editable = false)
        val id1 = ss.beginSnapshot()
        ss.put(entry("e1"))
        check("Attack_H_A10: a ref resolves inside its own snapshot", ss.resolve("e1", id1) != null)
        val id2 = ss.beginSnapshot()
        check("Attack_H_A10: refs from a dead snapshot never resolve (stale-ref refusal)",
            ss.resolve("e1", id1) == null && ss.resolve("e1", id2) == null)
        repeat(SnapshotStore.MAX_NODES + 50) { ss.put(entry("e${it + 1}")) }
        check("Attack_H_A10: a hostile tree is capped at the budget and the cut is LOUD",
            ss.size() == SnapshotStore.MAX_NODES && ss.lastTruncated)
    }

    // ---- DG-H-A11/A12: mesh protocol hostile payloads ----
    run {
        fun frame(header: JSONObject, au: ByteArray, version: Int = 1, magic: String = "DGSF"): ByteArray {
            val h = header.toString().toByteArray(Charsets.UTF_8)
            return magic.toByteArray(Charsets.US_ASCII) +
                byteArrayOf(version.toByte(), 0, (h.size and 0xFF).toByte(), (h.size shr 8).toByte()) + h + au
        }
        val sps = byteArrayOf(0, 0, 0, 1, 0x67, 0x42, 0x00, 0x1f)
        val pps = byteArrayOf(0, 0, 0, 1, 0x68, 0xce.toByte(), 0x38, 0x80.toByte())
        val idr = byteArrayOf(0, 0, 0, 1, 0x65, 0x88.toByte(), 0x84.toByte())
        val keyAu = sps + pps + idr
        val deltaAu = byteArrayOf(0, 0, 0, 1, 0x41, 0x9a.toByte())
        val hdr = { kf: Boolean -> JSONObject().put("seq", 7).put("keyframe", kf)
            .put("width", 640).put("height", 480).put("codec", "h264") }
        check("H_A11 control: a well-formed keyframe parses",
            MeshProtocol.StreamFrames.parse(frame(hdr(true), keyAu))?.keyframe == true)
        check("Attack_H_A11: bad magic refuses",
            MeshProtocol.StreamFrames.parse(frame(hdr(true), keyAu, magic = "XCPF")) == null)
        check("Attack_H_A11: version 2 refuses",
            MeshProtocol.StreamFrames.parse(frame(hdr(true), keyAu, version = 2)) == null)
        check("Attack_H_A11: empty access unit refuses",
            MeshProtocol.StreamFrames.parse(frame(hdr(true), ByteArray(0))) == null)
        check("Attack_H_A11: a delta AU claiming to be a keyframe refuses (flag derived, never trusted)",
            MeshProtocol.StreamFrames.parse(frame(hdr(true), deltaAu)) == null)
        check("Attack_H_A11: a keyframe AU claiming to be a delta refuses",
            MeshProtocol.StreamFrames.parse(frame(hdr(false), keyAu)) == null)
        check("Attack_H_A11: NAL type 0 refuses",
            MeshProtocol.StreamFrames.parse(frame(hdr(false),
                byteArrayOf(0, 0, 0, 1, 0x00, 0x55))) == null)
        check("Attack_H_A11: NAL type 13 refuses",
            MeshProtocol.StreamFrames.parse(frame(hdr(false),
                byteArrayOf(0, 0, 0, 1, 0x6d, 0x55))) == null)
        check("Attack_H_A11: a keyframe with SPS after the IDR refuses",
            MeshProtocol.StreamFrames.parse(frame(hdr(true), idr + pps + sps)) == null)
        check("Attack_H_A11: absurd dimensions refuse",
            MeshProtocol.StreamFrames.parse(frame(
                JSONObject().put("keyframe", true).put("width", 99999).put("height", 480)
                    .put("codec", "h264"), keyAu)) == null)
        check("Attack_H_A11: a non-h264 codec refuses",
            MeshProtocol.StreamFrames.parse(frame(
                JSONObject().put("keyframe", true).put("width", 640).put("height", 480)
                    .put("codec", "hevc"), keyAu)) == null)
        val whole = frame(hdr(true), keyAu)
        check("Attack_H_A11: a truncated frame refuses",
            MeshProtocol.StreamFrames.parse(whole.copyOf(whole.size / 2)) == null)
        // A12: spoofed companion state degrades, never invents.
        val spoof = MeshProtocol.CompanionState.parse(
            JSONObject("""{"state":"PWNED","device":"PC"}"""))
        check("Attack_H_A12: an unknown companion state parses as UNKNOWN, never as a trusted state",
            spoof.state == MeshProtocol.State.UNKNOWN)
        val junk = MeshProtocol.CompanionState.parse(
            JSONObject("""{"state":"AI_DRIVING","sessionSeconds":"abc","actions":"lots"}"""))
        check("Attack_H_A12: wrong-typed heartbeat fields degrade to defaults without throwing",
            junk.state == MeshProtocol.State.AI_DRIVING && junk.sessionSeconds == 0L && junk.actions == 0)
        check("Attack_H_A12: a stream-info refusal stays a refusal",
            !MeshProtocol.StreamInfo.parse(JSONObject("""{"ok":false,"error":"no"}""")).ok)
    }

    // ---- DG-H-A13: quick-assist brute force / replay / binding ----
    run {
        val qa = QuickAssistService()
        val now = 1_000_000L
        val code = qa.mint("co", "dev1", "user1", now, ttlMs = 30 * 60 * 1000L)
        val raw = code.replace("-", "")
        val wrong = (if (raw[0] == 'A') 'B' else 'A') + raw.substring(1)
        repeat(5) { check("Attack_H_A13: wrong code ${it + 1}/5 refuses", !qa.redeem(wrong, "browser-1", now).first) }
        check("Attack_H_A13: five failures lock the mint", qa.isLocked(now))
        check("Attack_H_A13: the CORRECT code refuses during lockout",
            !qa.redeem(code, "browser-1", now).first)
        val later = now + QuickAssistService.LOCKOUT_MS + 1
        val redeemed = qa.redeem(code, "browser-1", later)
        check("Attack_H_A13: the correct code redeems after the lockout", redeemed.first && redeemed.third != null)
        val (grant, grantToken) = redeemed.third!!
        check("Attack_H_A13: replay of the redeemed code refuses", !qa.redeem(code, "browser-1", later).first)
        check("Attack_H_A13: the grant validates for its own binding",
            qa.validate(grant.grantId, grantToken, "browser-1", later).first)
        check("Attack_H_A13: the grant refuses a different client binding (helper impersonation)",
            !qa.validate(grant.grantId, grantToken, "browser-2", later).first)
        check("Attack_H_A13: the grant refuses a wrong token",
            !qa.validate(grant.grantId, "00".repeat(24), "browser-1", later).first)
        check("Attack_H_A13: the grant refuses after expiry",
            !qa.validate(grant.grantId, grantToken, "browser-1", grant.expiresUtcMs + 1).first)
        check("Attack_H_A13: closing the grant kills it for everyone",
            qa.close(grant.grantId) && !qa.validate(grant.grantId, grantToken, "browser-1", later).first)
    }

    // ---- DG-H-A15: update manifest downgrade / tamper ----
    run {
        val rsa = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val manifest = JSONObject()
            .put("versionCode", 50).put("versionName", "0.5.0")
            .put("url", "https://example.com/app.apk")
        val signer = Signature.getInstance("SHA256withRSA")
        signer.initSign(rsa.private)
        signer.update(ManifestVerifier.canonicalBytes(manifest))
        manifest.put("signature", Base64.getEncoder().encodeToString(signer.sign()))
        check("H_A15 control: a correctly signed manifest verifies",
            ManifestVerifier.verify(manifest, rsa.public))
        check("Attack_H_A15: an equal versionCode is NOT newer (replayed release refused)",
            !ManifestVerifier.verifyNewer(manifest, rsa.public, 50))
        check("Attack_H_A15: a signed-but-older manifest is refused like a forged one",
            !ManifestVerifier.verifyNewer(manifest, rsa.public, 51))
        check("H_A15 control: a genuinely newer manifest passes",
            ManifestVerifier.verifyNewer(manifest, rsa.public, 49))
        val tampered = JSONObject(manifest.toString()).put("versionCode", 9999)
        check("Attack_H_A15: editing the body after signing kills the signature",
            !ManifestVerifier.verify(tampered, rsa.public))
        val unsigned = JSONObject().put("versionCode", 60)
        check("Attack_H_A15: an unsigned manifest never verifies",
            !ManifestVerifier.verify(unsigned, rsa.public))
        val wrongKey = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        check("Attack_H_A15: a signature from another key never verifies",
            !ManifestVerifier.verify(manifest, wrongKey.public))
    }

    // ---- DG-H-A16: AI pack download guards ----
    run {
        val payload = "model-bytes".toByteArray()
        val sha = MessageDigest.getInstance("SHA-256").digest(payload)
            .joinToString("") { "%02x".format(it) }
        val fixture = AiPackManifest.forFixture(
            "http://127.0.0.1/fixture", listOf(PackFile("model.bin", sha, payload.size.toLong())))
        val svc = AiPackService(fixture)
        check("Attack_H_A16: download before licence acceptance refuses",
            !svc.download(File(dir, "pack1"), { _, dest -> dest.writeBytes(payload) },
                "http://127.0.0.1/fixture", fixtureMode = true).first)
        svc.acceptLicence("user1")
        check("H_A16 control: the pinned fixture downloads and verifies",
            svc.download(File(dir, "pack1"), { _, dest -> dest.writeBytes(payload) },
                "http://127.0.0.1/fixture", fixtureMode = true).first &&
                svc.verifyInstalled(File(dir, "pack1")).first)
        val svc2 = AiPackService(fixture)
        svc2.acceptLicence("user1")
        val forged = "model-byteX".toByteArray() // same length, wrong bytes
        val res2 = svc2.download(File(dir, "pack2"), { _, dest -> dest.writeBytes(forged) },
            "http://127.0.0.1/fixture", fixtureMode = true)
        check("Attack_H_A16: a hash mismatch refuses with NO override and the partial is deleted",
            !res2.first && !File(dir, "pack2/model.bin.partial").exists() &&
                !File(dir, "pack2/model.bin").exists())
        val svc3 = AiPackService(AiPackManifest.UI_TARS_1_5_7B)
        svc3.acceptLicence("user1")
        check("Attack_H_A16: a source override against the production pack refuses",
            !svc3.download(File(dir, "pack3"), { _, _ -> }, "https://evil.example.com/x").first)
        var fetcherCalled = false
        val traversal = AiPackManifest.forFixture(
            "http://127.0.0.1/fixture", listOf(PackFile("../evil.bin", sha, payload.size.toLong())))
        val svc4 = AiPackService(traversal)
        svc4.acceptLicence("user1")
        val res4 = svc4.download(File(dir, "pack4"), { _, _ -> fetcherCalled = true },
            "http://127.0.0.1/fixture", fixtureMode = true)
        check("Attack_H_A16: a pack path escaping the pack folder refuses before any fetch",
            !res4.first && !fetcherCalled && !File(dir, "evil.bin").exists())
    }

    // ---- DG-H-A17: SecondFactor hostile imports ----
    run {
        var now = t0
        val f = SecondFactorStore(w.roster, sealer, null, null) { now }
        f.importJson("""{"events":[{"atMillis":1,"kind":"totp_verified","scopeId":"co","userId":"user1","detail":"planted"}]}""")
        check("Attack_H_A17: imported EVENTS alone mint no factor (the event list is a record, not authority)",
            !f.hasActiveTotp("co", "user1") && f.counts() == (0 to 0))
        val b = f.beginTotpEnrollment("co", "user1")
        val secret = Base32.decode(b!!.first)!!
        check("Attack_H_A17 setup: confirm", f.confirmTotpEnrollment("co", "user1", Totp.at(secret, now), now))
        f.importJson("""{"throttle":[{"scopeId":"co","userId":"user1","failures":-5,"lockoutUntilMillis":9999999999999}]}""")
        check("Attack_H_A17: a hostile import can RAISE a lockout (max-merge) — the correct code now refuses",
            !f.verifyTotp("co", "user1", Totp.at(secret, now + 30_000L), now + 30_000L))
    }

    // ---- DG-H-A18: enrollment code burn + replay ----
    run {
        val es = EnrollmentStore(File(dir, "enroll-atk.tsv"))
        val identity = DeviceIdentity.generate()
        val device = EnrollmentStore.EnrollingDevice(identity.deviceId, identity.publicKeyBase64, "Attack Device")
        fun mutate(code: String): String {
            val chars = code.toCharArray()
            val i = chars.indexOfFirst { it.isLetterOrDigit() }
            chars[i] = when (chars[i]) {
                'A' -> 'B'; '0' -> '1'; else -> 'A'
            }
            return String(chars)
        }
        val code1 = es.mint("company", "dg1", "Fleet")
        val wrong = mutate(code1)
        check("Attack_H_A18 setup: mutated code differs", wrong != code1)
        repeat(5) { check("Attack_H_A18: wrong redeem ${it + 1}/5 refuses", es.redeem(wrong, device) == null) }
        check("Attack_H_A18: five wrong guesses BURN the code — the correct code is dead too",
            es.redeem(code1, device) == null)
        val code2 = es.mint("company", "dg1", "Fleet")
        check("Attack_H_A18: a fresh code redeems", es.redeem(code2, device) != null)
        check("Attack_H_A18: replay of the consumed code refuses", es.redeem(code2, device) == null)
    }

    // ---- DG-H-A19: ADB pairing packet headers ----
    run {
        check("Attack_H_A19: a short header refuses",
            AdbPairing.parsePacketHeader(ByteArray(5)) == null)
        val badVersion = AdbPairing.packetHeader(AdbPairing.TYPE_PEER_INFO, 10)
        badVersion[0] = 2
        check("Attack_H_A19: a wrong-version header refuses",
            AdbPairing.parsePacketHeader(badVersion) == null)
        val good = AdbPairing.packetHeader(AdbPairing.TYPE_PEER_INFO, AdbPairing.PEER_INFO_SIZE)
        check("H_A19 control: a well-formed header round-trips",
            AdbPairing.parsePacketHeader(good) == (AdbPairing.TYPE_PEER_INFO to AdbPairing.PEER_INFO_SIZE))
        val huge = AdbPairing.packetHeader(AdbPairing.TYPE_SPAKE2_MSG, -1)
        check("Attack_H_A19: a 0xFFFFFFFF size surfaces negative — the reader's <0 / >64KiB guard refuses it before allocating",
            (AdbPairing.parsePacketHeader(huge)?.second ?: 0) < 0)
    }

    // ---- DG-H-A20: SessionStore hostile TSV ----
    run {
        val w20 = BlockHWorld(dir, "h20")
        val idA = w20.active("s-h20a")
        val call = w20.sessions.startCall(idA, "user1", "audio")
        check("Attack_H_A20 setup: call ringing + session ended", call != null &&
            w20.sessions.endSession(idA, "user1"))
        val idB = w20.active("s-h20b")
        check("Attack_H_A20 setup: floor to user1", w20.sessions.grantFloor(idB, "host1", "user1"))
        val file = File(dir, "h20-sessions.tsv")
        file.appendText("\ncall\tc-forge\t$idA\taudio\tringing\tuser1\t1000\t\t")
        file.appendText("\nparticipant\t$idB\tuser2\tcontroller\tholds")
        val reloaded = SessionStore(file, w20.roster, w20.enrollment) { tick() }
        check("Attack_H_A20: a live call planted on an ENDED session loads ENDED",
            reloaded.calls(idA).firstOrNull { it.id == "c-forge" }?.state == "ended")
        val holders = reloaded.participants(idB).filter { it.floor == SessionStore.FLOOR_HOLDS }
        check("Attack_H_A20: two planted floor holders load as exactly ONE (the first)",
            holders.size == 1 && holders.single().userId == "user1")
    }

    // ================================================================
    // D38 CROSS-REVIEW FIX REGRESSIONS (packet df7da191, F1–F10).
    // ================================================================

    // ---- FIX-F1: the throttle runs on the STORE clock ----
    run {
        var now = t0
        val f = SecondFactorStore(w.roster, sealer, null, null) { now }
        val b = f.beginTotpEnrollment("co", "user2")
        val secret = Base32.decode(b!!.first)!!
        check("FIX-F1 setup: confirm", f.confirmTotpEnrollment("co", "user2", Totp.at(secret, now), now))
        var t = now + 30_000L
        repeat(5) { f.verifyTotp("co", "user2", "xxxxxx", t); t += 30_000L }
        check("FIX-F1 setup: lockout engaged", f.events.any { it.kind == "factor_throttled" && it.userId == "user2" })
        // The attack from the finding: present the CORRECT code
        // stamped far in the future. The store clock has not
        // moved, so the lockout still refuses it.
        val future = now + 100 * SecondFactorStore.THROTTLE_LOCKOUT_MS
        check("FIX-F1: a future-stamped correct code does NOT bypass the lockout",
            !f.verifyTotp("co", "user2", Totp.at(secret, future), future))
        now += SecondFactorStore.THROTTLE_LOCKOUT_MS + 30_000L
        check("FIX-F1: the same code verifies once the STORE clock passes the lockout",
            f.verifyTotp("co", "user2", Totp.at(secret, now), now))
    }

    // ---- FIX-F3: imported lockouts bounded; admin recovery clears ----
    run {
        var now = t0
        val f = SecondFactorStore(w.roster, sealer, null, null) { now }
        val b = f.beginTotpEnrollment("co", "user3")
        val secret = Base32.decode(b!!.first)!!
        check("FIX-F3 setup: confirm", f.confirmTotpEnrollment("co", "user3", Totp.at(secret, now), now))
        f.importJson("""{"throttle":[{"scopeId":"co","userId":"user3","failures":99,"lockoutUntilMillis":9999999999999}]}""")
        check("FIX-F3: the clamped import still locks (inside one lockout period)",
            !f.verifyTotp("co", "user3", Totp.at(secret, now + 30_000L), now + 30_000L))
        now += SecondFactorStore.THROTTLE_LOCKOUT_MS + 30_000L
        check("FIX-F3: a year-2286 imported lockout expires after ONE lockout period (bounded)",
            f.verifyTotp("co", "user3", Totp.at(secret, now), now))
        // Engage a fresh lockout, then recover by admin.
        var t = now + 30_000L
        repeat(5) { f.verifyTotp("co", "user3", "xxxxxx", t); t += 30_000L }
        check("FIX-F3 setup: locked again", !f.verifyTotp("co", "user3", Totp.at(secret, t), t))
        check("FIX-F3: admin removal succeeds", f.removeTotpByAdmin("co", "user3", "admin1"))
        val b2 = f.beginTotpEnrollment("co", "user3")
        val secret2 = Base32.decode(b2!!.first)!!
        check("FIX-F3: re-enrollment CONFIRM is not throttled after admin recovery (throttle cleared)",
            f.confirmTotpEnrollment("co", "user3", Totp.at(secret2, now), now))
    }

    // ---- FIX-F2: tunnels re-check the live `use` right ----
    run {
        val w2 = BlockHWorld(dir, "hfix2")
        val id = w2.active("s-fix2")
        check("FIX-F2 setup: floor to user1", w2.sessions.grantFloor(id, "host1", "user1"))
        val tunnels = SessionTunnelStore(w2.sessions, w2.roster, null) { tick() }
        check("FIX-F2: floor holder WITH the grant opens a tunnel",
            tunnels.open(id, "user1", "192.168.1.10", 8080, 18080) != null)
        check("FIX-F2 setup: grant revoked mid-session",
            w2.roster.removeUserFromGroup("co", "ug1", "user1", "admin1"))
        check("FIX-F2: the revoked floor holder can no longer open a tunnel",
            tunnels.open(id, "user1", "192.168.1.11", 8080, 18081) == null)
        val planted = "[{\"id\":\"tf2\",\"sessionId\":\"$id\",\"targetHost\":\"192.168.1.12\",\"targetPort\":8080," +
            "\"listenPort\":18082,\"state\":\"open\",\"openedByUserId\":\"user1\",\"openedUtcMs\":1,\"closedUtcMs\":null}]"
        tunnels.importJson(planted)
        check("FIX-F2: an imported 'open' tunnel for the revoked holder restores CLOSED",
            tunnels.tunnel("tf2")?.state == "closed")
        check("FIX-F2 setup: grant restored", w2.roster.addUserToGroup("co", "ug1", "user1", "admin1"))
        check("FIX-F2: the re-granted holder opens again",
            tunnels.open(id, "user1", "192.168.1.11", 8080, 18081) != null)
        w2.sessions.endSession(id, "user1")
    }

    // ---- FIX-F4: D9 — an AI floor holder gets no host surfaces/calls ----
    run {
        val id = w.active("s-fix4")
        check("FIX-F4 setup: ai1 joins + takes the floor (AI holds `use` via ug1)",
            w.sessions.addParticipant(id, "host1", "ai1", "controller") &&
                w.sessions.grantFloor(id, "host1", "ai1"))
        check("FIX-F4: AI floor holder cannot blank the host screen",
            !w.sessions.setBlanked(id, "ai1", true))
        check("FIX-F4: AI floor holder cannot block the host's local input",
            !w.sessions.setInputBlocked(id, "ai1", true))
        check("FIX-F4: AI floor holder cannot enable the watermark",
            !w.sessions.setWatermarked(id, "ai1", true))
        check("FIX-F4: AI floor holder cannot start a call",
            w.sessions.startCall(id, "ai1", "audio") == null)
        val hostCall = w.sessions.startCall(id, "host1", "audio")
        check("FIX-F4 setup: host call ringing", hostCall != null)
        check("FIX-F4: AI cannot answer a call either",
            !w.sessions.answerCall(hostCall!!.id, "ai1"))
        check("FIX-F4 cleanup: host ends the call", w.sessions.endCall(hostCall.id, "host1"))
        w.sessions.endSession(id, "user1")
    }

    // ---- FIX-F5: userHasRight — owner-only personal shortcut, group in scope ----
    run {
        val r = RosterStore(File(dir, "fix5-roster.tsv"), EnrollmentStore(File(dir, "fix5-enroll.tsv")))
        r.addScope(RosterStore.Scope("pers", "personal", "Mine"))
        r.addUser(RosterStore.User("owner", "pers", "Owner", "human"))
        r.addUser(RosterStore.User("second", "pers", "Second Human", "human"))
        r.addCompanyAdmin("pers", "owner")
        r.addDeviceGroup(RosterStore.DeviceGroup("dg-p", "pers", "Home", listOf("lan")), "owner")
        check("FIX-F5: the personal-scope OWNER holds rights via the shortcut",
            r.userHasRight("pers", "owner", "dg-p", "use"))
        check("FIX-F5: a SECOND human in a personal scope holds nothing without a grant",
            !r.userHasRight("pers", "second", "dg-p", "use"))
        check("FIX-F5: even the owner gets nothing on a group outside the scope",
            !r.userHasRight("pers", "owner", "dg-elsewhere", "use"))
        check("FIX-F5: a company admin gets nothing on a foreign group id either",
            !w.roster.userHasRight("co", "admin1", "dg-elsewhere", "use"))
    }

    // ---- FIX-F6 / DG-H-A14: LiveTreeSearch residuals ----
    run {
        class FakeNode(
            override val text: String? = null,
            override val contentDescription: String? = null,
            override val isVisibleToUser: Boolean = true,
            val kids: List<FakeNode> = emptyList(),
            val onChildFetch: () -> Unit = {}
        ) : LiveTreeNode {
            override val childCount: Int get() = kids.size
            override fun child(index: Int): LiveTreeNode? { onChildFetch(); return kids[index] }
        }
        // (a) DFS candidate order matches the original recursive walk.
        val a1 = FakeNode(text = "L", contentDescription = "a1")
        val a = FakeNode(text = "L", contentDescription = "a", kids = listOf(a1))
        val bNode = FakeNode(text = "L", contentDescription = "b")
        val root = FakeNode(kids = listOf(a, bNode))
        check("FIX-F6a: candidates come back in depth-first (original) order",
            LiveTreeSearch.collectByLabel(root, "L").map { it.contentDescription } == listOf("a", "a1", "b"))
        // (b) Invisible subtrees are pruned — neither collected nor visited.
        val ghost = FakeNode(text = "L", contentDescription = "ghost", isVisibleToUser = false,
            kids = listOf(FakeNode(text = "L", contentDescription = "ghost-child")))
        val real = FakeNode(text = "L", contentDescription = "real")
        val root2 = FakeNode(kids = listOf(ghost, real))
        check("FIX-F6b: an invisible label twin is never collected; its subtree is pruned",
            LiveTreeSearch.collectByLabel(root2, "L").map { it.contentDescription } == listOf("real"))
        // (c) A very wide node: child fetches stay within the budget.
        var fetches = 0
        val wide = FakeNode(kids = List(5_000) { FakeNode(text = "W") }, onChildFetch = { fetches++ })
        val found = LiveTreeSearch.collectByLabel(wide, "W", maxNodes = 100)
        check("FIX-F6c: a 5000-child node costs bounded fetches under a 100-node budget",
            fetches <= 100 && found.size <= 100)
        // Deep chain: iterative walk survives depths recursion could not.
        // The intent is the ITERATIVE walk at 50k depth, so the node
        // budget is raised explicitly to cover the 50,001-node tree —
        // under the DEFAULT budget (MAX_NODES = 1500) the walk rightly
        // stops long before the labelled bottom (see FIX-F6d).
        var deep: FakeNode = FakeNode(text = "L", contentDescription = "bottom")
        repeat(50_000) { deep = FakeNode(kids = listOf(deep)) }
        check("FIX-F6: a 50k-deep tree is walked iteratively (no stack overflow) under an explicit node budget",
            LiveTreeSearch.collectByLabel(deep, "L", maxNodes = 60_000, maxDepth = 60_000).size == 1)
        // (d) The A14 defence stands: the SAME hostile chain under the
        // DEFAULT node budget is bounded — the walk stops at ~MAX_NODES
        // and the bottom label (node 50,001) is never reached.
        check("FIX-F6d: the default node budget still bounds a 50k-deep hostile tree",
            LiveTreeSearch.collectByLabel(deep, "L", maxDepth = 60_000).isEmpty())
        // (e) Deep AND wide hostile tree (~90k labelled nodes) under a
        // small explicit budget: results and child fetches stay bounded.
        var hwFetches = 0
        val hwChains = List(300) {
            var chain: FakeNode = FakeNode(text = "L", onChildFetch = { hwFetches++ })
            repeat(299) { chain = FakeNode(text = "L", kids = listOf(chain), onChildFetch = { hwFetches++ }) }
            chain
        }
        val hwRoot = FakeNode(kids = hwChains, onChildFetch = { hwFetches++ })
        val hwFound = LiveTreeSearch.collectByLabel(hwRoot, "L", maxNodes = 400, maxDepth = 60_000)
        check("FIX-F6e: a deep+wide hostile tree stays bounded in results and fetches under a 400-node budget",
            hwFound.size <= 400 && hwFetches <= 1000)
    }

    // ---- FIX-F7: PairingStore load/redeem validation symmetry ----
    run {
        val f7file = File(dir, "pairings-fix7.tsv")
        val s7 = PairingStore(f7file)
        val code7 = s7.beginPairing("Custom")
        val p7 = s7.redeem(code7, setOf("observe", "bogus-scope"))
        check("FIX-F7 setup: redeem drops unknown scopes at the door",
            p7 != null && p7.scopes == setOf("observe"))
        s7.setAccess(p7!!.token, "custom", emptySet())
        check("FIX-F7: a custom pairing saved with ZERO caps reloads with zero caps (no widening)",
            PairingStore(f7file).pairingForToken(p7.token)?.caps == emptySet<String>())
        val f7b = File(dir, "pairings-fix7b.tsv")
        f7b.writeText("Planted\t${"bb".repeat(32)}\tobserve\t1700000000000\tEvil\t1\tsuperuser\tsee")
        check("FIX-F7: an invented access level on disk loads as the observe floor",
            PairingStore(f7b).all().single().access == PairingStore.ACCESS_OBSERVE)
    }

    // ---- FIX-F8: watermark enable — no initiator exemption ----
    run {
        val id = w.active("s-fix8")
        check("FIX-F8 setup: floor to grant-less user3", w.sessions.grantFloor(id, "host1", "user3") ||
            (w.sessions.addParticipant(id, "host1", "user3", "controller") &&
                w.sessions.grantFloor(id, "host1", "user3")))
        check("FIX-F8: the session INITIATOR (not holder, not host) cannot enable the watermark",
            !w.sessions.setWatermarked(id, "user1", true))
        check("FIX-F8: the host actor still can", w.sessions.setWatermarked(id, "host1", true))
        w.sessions.endSession(id, "user1")
    }

    // ---- FIX-F9: pivot + allowlist judge addresses, not spellings ----
    run {
        check("FIX-F9: hex IPv4 loopback is a pivot target", SessionTunnelStore.isPivotTarget("0x7f.0.0.1"))
        check("FIX-F9: IPv6-mapped loopback is a pivot target", SessionTunnelStore.isPivotTarget("::ffff:127.0.0.1"))
        check("FIX-F9: inet_aton short-form loopback is a pivot target", SessionTunnelStore.isPivotTarget("127.1"))
        check("FIX-F9: localhost with a trailing dot is a pivot target", SessionTunnelStore.isPivotTarget("localhost."))
        check("FIX-F9: a LAN address is not a pivot target", !SessionTunnelStore.isPivotTarget("192.168.1.10"))
        val id = w.active("s-fix9")
        val dotted = SessionTunnelStore(w.sessions, w.roster, null,
            allowedTargets = setOf("192.168.1.10:8080")) { tick() }
        check("FIX-F9: a trailing-dot spelling of an allowlisted address opens",
            dotted.open(id, "host1", "192.168.1.10.", 8080, 18080) != null)
        val v6 = SessionTunnelStore(w.sessions, w.roster, null,
            allowedTargets = setOf("2001:0db8:0000:0000:0000:0000:0000:0001:443")) { tick() }
        check("FIX-F9: a compressed IPv6 spelling matches its expanded allowlist entry",
            v6.open(id, "host1", "2001:db8::1", 443, 18081) != null)
        w.sessions.endSession(id, "user1")
    }

    // ---- FIX-F10: teardown predicate is the gate predicate ----
    run {
        val stores = PlatformStores(File(dir, "ps10"))
        stores.addScope("co", "company", "Acme Co")
        stores.addUser("co", "admin1", "Admin One", "human")
        stores.addCompanyAdmin("co", "admin1")
        stores.addUser("co", "host1", "Host User", "human")
        stores.addUser("co", "user1", "User One", "human")
        stores.addUserGroup("co", "ug1", "Techs", "admin1")
        stores.addUserToGroup("co", "ug1", "user1", "admin1")
        stores.addUserToGroup("co", "ug1", "host1", "admin1")
        stores.addDeviceGroup("co", "dg1", "Fleet", listOf("lan", "hub", "mesh"), "admin1")
        stores.addGrant("co", "ug1", "dg1", setOf("use"), "admin1")
        val code = stores.mintEnrollment("company", "dg1", "Fleet")
        val enrolled = stores.redeemOwn(code, "This Phone", "Admin One", "op-device")
        check("FIX-F10 setup: session live + blanked",
            enrolled != null &&
                stores.createSession("ps10", "co", enrolled.deviceId, "user1", "host1", "attended", "lan") &&
                stores.acceptLocal("ps10", "host1") && stores.startSession("ps10", "user1") &&
                stores.sessions.setBlanked("ps10", "host1", true))
        fun bundle10(disabledFeatures: List<String>) = PolicyBundle(
            version = 2, scopeId = "co", transportCeiling = listOf("lan", "hub", "mesh"),
            transportMode = "auto", pinnedVersion = null, updateDeferUntilMillis = null,
            forbidAiPairings = false, disableRecording = false, unattendedTier = "standard",
            issuedMillis = t0, expiresMillis = t0 + 3_600_000L, signatureBase64 = "",
            disabledFeatures = disabledFeatures
        )
        stores.policyEnforcer = PolicyEnforcer(bundle10(emptyList()))
        check("FIX-F10: an enforcer disabling nothing sweeps nothing (gate and teardown agree: permitted)",
            stores.sessions.session("ps10")?.blanked == true)
        stores.policyEnforcer = PolicyEnforcer(bundle10(listOf(PolicyFeatures.BLANK_SCREEN)))
        check("FIX-F10: the disabling enforcer tears the blank down AND the gate now refuses it",
            stores.sessions.session("ps10")?.blanked == false &&
                !stores.sessions.setBlanked("ps10", "host1", true))
        // Racing installs settle on a consistent final state.
        val tA = Thread { repeat(25) { stores.policyEnforcer = PolicyEnforcer(bundle10(listOf(PolicyFeatures.BLANK_SCREEN))) } }
        val tB = Thread { repeat(25) { stores.policyEnforcer = PolicyEnforcer(bundle10(emptyList())) } }
        tA.start(); tB.start(); tA.join(); tB.join()
        stores.policyEnforcer = PolicyEnforcer(bundle10(listOf(PolicyFeatures.BLANK_SCREEN)))
        check("FIX-F10: after racing installs, a final install sweeps deterministically",
            stores.sessions.session("ps10")?.blanked == false)
        stores.endSession("ps10", "user1")
    }

    dir.deleteRecursively()
    println(if (failures == 0) "ALL BLOCK H TESTS PASSED" else "$failures BLOCK H TEST(S) FAILED")
    if (failures > 0) kotlin.system.exitProcess(1)
}

/** Counting tool host for the MCP destruction battery. */
private class CountingHost : McpCore.ToolHost {
    val runs = mutableMapOf<String, Int>()
    private fun def(name: String, scope: String) = McpCore.ToolDef(
        name, "destruction-test tool", scope, JSONObject().put("type", "object"),
        run = { runs[name] = (runs[name] ?: 0) + 1; "ran $name" }
    )
    override fun tools(): List<McpCore.ToolDef> = listOf(
        def("device_info", "observe"), def("start_session", "drive"),
        def("shell_exec", "shell"), def("drive_thing", "drive")
    )
}

/** Pair through McpCore's front door and return the bearer token. */
private fun pairViaCore(core: McpCore, store: PairingStore): String {
    val code = store.beginPairing("Attack AI")
    val reply = core.handle(
        """{"jsonrpc":"2.0","id":1,"method":"pair","params":{"code":"$code"}}""", null)
    return JSONObject(reply.body!!).getJSONObject("result").getString("token")
}
