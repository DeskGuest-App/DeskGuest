import io.deskguest.app.bgtools.B1SignedCommandVerifier
import io.deskguest.app.bgtools.BgToolExecutor
import io.deskguest.app.bgtools.BgToolService
import io.deskguest.app.bgtools.BgToolsPolicy
import io.deskguest.app.bgtools.SignedEnvelope
import io.deskguest.app.cameraview.ChainedAudit
import io.deskguest.app.enrollment.DeviceIdentity
import io.deskguest.app.rmmspine.CustomerCommandKeyRing
import io.deskguest.app.rmmspine.InMemoryReplayGuard
import io.deskguest.app.rmmspine.IsoTime
import io.deskguest.app.rmmspine.SignedCommandClasses
import io.deskguest.app.rmmspine.SignedCommandEnvelope
import io.deskguest.app.rmmspine.SignedCommandSigner
import io.deskguest.app.rmmspine.SignedCommandVerifier as B1Verifier

/** Lane INT (2026-11-21) — binding proof: B3's bgtools service runs
 *  against Lane B1's REAL RMM-03 verifier via B1SignedCommandVerifier.
 *  BgToolService is used exactly as LaneB3Test uses it (no caller
 *  changes); only the verifier instance differs. */
private var failures = 0
private var passes = 0
private fun check(name: String, cond: Boolean) {
    if (cond) { println("PASS  $name"); passes++ } else { println("FAIL  $name"); failures++ }
}

private val T0 = 1_800_000_000_000L

fun main() {
    val customer = DeviceIdentity.fromSeed(ByteArray(32) { 7 })
    val attacker = DeviceIdentity.fromSeed(ByteArray(32) { 99 })
    val ring = CustomerCommandKeyRing().apply { addCurrent(customer.publicKey) }
    val signer = SignedCommandSigner(customer)
    val b1Verifier = B1Verifier(ring, InMemoryReplayGuard())
    val clock = { T0 }
    val adapter = B1SignedCommandVerifier(b1Verifier, clock)
    val auditClock = { T0 }

    fun b3Env(b1: SignedCommandEnvelope): SignedEnvelope = SignedEnvelope(
        commandClass = "background_tool",
        nonce = b1.nonce,
        expiresMs = IsoTime.parse(b1.expiresUtc)!!,
        payloadHash = b1.payloadHash,
        signature = b1.signatureBase64,
        keyId = b1.keyId,
        issuedMs = IsoTime.parse(b1.issuedUtc)!!
    )
    fun svc(v: B1SignedCommandVerifier = adapter) =
        BgToolService(v, BgToolExecutor { t, _ -> "ran:$t" }, ChainedAudit(auditClock), clock)

    BgToolsPolicy.enabled = true
    val payload = "tool=device_info".toByteArray()

    run {
        val b1 = signer.sign(SignedCommandClasses.BACKGROUND_ACTION, payload, T0, 600_000, "int-n1")
        val r = svc().invoke("device_info", emptyMap(), b3Env(b1), payload)
        check("INT-BIND valid B1-signed envelope runs bgtool via real verifier", r.isSuccess && r.getOrThrow().state == "succeeded")
    }
    run {
        val b1 = signer.sign(SignedCommandClasses.BACKGROUND_ACTION, payload, T0, 600_000, "int-n2")
        val forged = b3Env(b1).copy(signature = java.util.Base64.getEncoder().encodeToString(ByteArray(64) { 1 }))
        check("INT-BIND forged signature refused by real verifier", svc().invoke("device_info", emptyMap(), forged, payload).isFailure)
    }
    run {
        val atkSigner = SignedCommandSigner(attacker)
        val b1 = atkSigner.sign(SignedCommandClasses.BACKGROUND_ACTION, payload, T0, 600_000, "int-n3")
        check("INT-BIND attacker-key envelope refused (unknown key id)", svc().invoke("device_info", emptyMap(), b3Env(b1), payload).isFailure)
    }
    run {
        val b1 = signer.sign(SignedCommandClasses.BACKGROUND_ACTION, payload, T0, 600_000, "int-n4")
        check("INT-BIND tampered payload refused (hash/payload binding)", svc().invoke("device_info", emptyMap(), b3Env(b1), "tool=wipe".toByteArray()).isFailure)
    }
    run {
        val b1 = signer.sign(SignedCommandClasses.BACKGROUND_ACTION, payload, T0 - 700_000, 600_000, "int-n5")
        check("INT-BIND expired B1 envelope refused", svc().invoke("device_info", emptyMap(), b3Env(b1), payload).isFailure)
    }
    run {
        // Replay across a FRESH BgToolService (its own nonce set is
        // empty): only B1's replay guard can refuse the second use.
        val b1 = signer.sign(SignedCommandClasses.BACKGROUND_ACTION, payload, T0, 600_000, "int-n6")
        val env = b3Env(b1)
        check("INT-BIND first presentation succeeds", svc().invoke("device_info", emptyMap(), env, payload).isSuccess)
        check("INT-BIND replay refused by B1 replay guard (fresh service)", svc().invoke("device_info", emptyMap(), env, payload).isFailure)
    }
    run {
        val b1 = signer.sign(SignedCommandClasses.SHELL_EXEC, payload, T0, 600_000, "int-n7")
        check("INT-BIND envelope signed for another class refused", svc().invoke("device_info", emptyMap(), b3Env(b1), payload).isFailure)
    }
    run {
        val toy = SignedEnvelope("background_tool", "int-n8", T0 + 60_000, "h", "good")
        check("INT-BIND toy envelope without B1 fields refused (fail closed)", svc().invoke("device_info", emptyMap(), toy, payload).isFailure)
    }

    println("LANEINT $passes passed, $failures failed")
    println(if (failures == 0) "LANEINT ALL PASS" else "LANEINT FAILURES PRESENT")
    if (failures > 0) kotlin.system.exitProcess(1)
}
