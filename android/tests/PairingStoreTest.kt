import io.agenticcontrol.app.crypto.AesGcmLineCipher
import io.agenticcontrol.app.server.PairingStore
import java.io.File
import java.nio.file.Files

/**
 * JVM tests for the 0.4.0 pairing-store hardening: tokens wrapped at
 * rest under AES-GCM, legacy plaintext stores migrating on load
 * without orphaning the pairing, constant-time verification still
 * exact, and the failure backoff present but bounded.
 */
private var failures = 0

private fun check(name: String, condition: Boolean) {
    if (condition) println("PASS  $name")
    else {
        println("FAIL  $name")
        failures++
    }
}

fun main() {
    val dir = Files.createTempDirectory("acp-pairing-test").toFile()
    val cipher = AesGcmLineCipher(AesGcmLineCipher.generateKey())

    // Round-trip under the cipher: the token on disk is wrapped.
    val file = File(dir, "pairings.tsv")
    val store = PairingStore(file, cipher)
    val code = store.beginPairing("Wrapped Agent")
    val pairing = store.redeem(code!!, setOf("mcp"))!!
    check("redeem works under the cipher", pairing.token.isNotBlank())
    val onDisk = file.readText()
    check("token is wrapped on disk", onDisk.contains("v1:"))
    check("plaintext token never touches disk", !onDisk.contains(pairing.token))
    val reloaded = PairingStore(file, cipher)
    check("wrapped store reloads", reloaded.pairingForToken(pairing.token)?.name == "Wrapped Agent")
    check("wrong token refused", reloaded.pairingForToken("not-the-token") == null)

    // A store written by an old version (plaintext token, 8 fields)
    // loads, keeps working, and is re-written wrapped — the existing
    // pairing is migrated, never orphaned.
    val legacyFile = File(dir, "legacy.tsv")
    val legacyToken = "legacy-token-0123456789abcdef"
    legacyFile.writeText(
        "Old Agent\t$legacyToken\tmcp\t1700000000000\tAgent A\t1.0\tfull\tsee,tap,type,apps,shell,settings"
    )
    val legacy = PairingStore(legacyFile, cipher)
    check("legacy pairing survives the upgrade", legacy.pairingForToken(legacyToken) != null)
    val migrated = legacyFile.readText()
    check("legacy store re-written wrapped", migrated.contains("v1:") && !migrated.contains(legacyToken))
    check(
        "migrated store still resolves",
        PairingStore(legacyFile, cipher).pairingForToken(legacyToken) != null
    )

    // The legacy 4-field format migrates the same way.
    val legacy4File = File(dir, "legacy4.tsv")
    val legacy4Token = "legacy4-token-0123456789"
    legacy4File.writeText("Four Field\t$legacy4Token\tmcp\t1700000000000")
    val legacy4 = PairingStore(legacy4File, cipher)
    check("4-field legacy pairing survives", legacy4.pairingForToken(legacy4Token) != null)
    check("4-field store re-written wrapped", !legacy4File.readText().contains(legacy4Token))

    // A wrapped token under the WRONG key fails closed: the pairing
    // is dropped, never half-read.
    val otherCipher = AesGcmLineCipher(AesGcmLineCipher.generateKey())
    val wrongKey = PairingStore(file, otherCipher)
    check("wrong key drops the pairing (fail closed)", wrongKey.pairingForToken(pairing.token) == null)

    // Failure backoff: a wrong guess makes the next redeem wait, but
    // the wait is the bounded 500 ms window, not a lockout.
    val timedFile = File(dir, "timed.tsv")
    val timed = PairingStore(timedFile, cipher)
    val liveCode = timed.beginPairing("Timed")!!
    check("wrong guess refused", timed.redeem("000000", setOf("mcp")) == null)
    val t0 = System.currentTimeMillis()
    val afterBackoff = timed.redeem(liveCode, setOf("mcp"))
    val waited = System.currentTimeMillis() - t0
    check("correct code still redeems after a failure", afterBackoff != null)
    check(
        "backoff waited a bounded time (0 < wait <= ~600ms, was ${waited}ms)",
        waited in 1..900
    )

    dir.deleteRecursively()
    println(if (failures == 0) "ALL PAIRING STORE TESTS PASSED" else "$failures PAIRING STORE TEST(S) FAILED")
    if (failures > 0) kotlin.system.exitProcess(1)
}
