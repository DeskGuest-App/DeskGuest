import io.deskguest.app.update.ManifestVerifier
import org.json.JSONObject
import java.io.File
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * Cross-implementation test (platform/update-channel-plan.md): a
 * manifest signed by the Python publisher must verify under the
 * Kotlin verifier the app ships, the canonical bytes must match byte
 * for byte, and a tampered manifest must fail.
 */
private var failures = 0

private fun check(name: String, condition: Boolean) {
    if (condition) println("PASS  $name")
    else {
        println("FAIL  $name")
        failures++
    }
}

fun main(args: Array<String>) {
    val dir = File(args.getOrElse(0) { "/tmp/deskguest-xcheck" })
    val manifest = JSONObject(File(dir, "manifest.json").readText())
    val expectedCanonical = File(dir, "canonical.txt").readBytes()

    val configDir = args.getOrElse(1) {
        System.getenv("HOME") + "/.config/deskguest"
    }
    val certFile = File(configDir, "cert.pem")
    val cf = CertificateFactory.getInstance("X.509")
    val cert = cf.generateCertificate(certFile.inputStream()) as X509Certificate

    val actualCanonical = ManifestVerifier.canonicalBytes(manifest)
    check(
        "canonical bytes match the publisher's",
        actualCanonical.contentEquals(expectedCanonical)
    )
    check("publisher-signed manifest verifies", ManifestVerifier.verify(manifest, cert.publicKey))

    val tampered = JSONObject(File(dir, "manifest.json").readText())
    tampered.put("versionCode", 99)
    check("tampered manifest refused", !ManifestVerifier.verify(tampered, cert.publicKey))

    val unsigned = JSONObject(File(dir, "manifest.json").readText())
    unsigned.remove("signature")
    check("unsigned manifest refused", !ManifestVerifier.verify(unsigned, cert.publicKey))

    // Monotonicity (0.4.0): the fixture is versionCode 3. A signed
    // manifest is an update only for a strictly older running app —
    // equal or older is refused inside the verifier itself.
    // W3 lane B sibling repair (disclosed): verifyNewer is
    // Long-wide since bd-and-ui F10 — read the fixture code as Long.
    val fixtureCode = manifest.optLong("versionCode", -1L)
    check("fixture carries a versionCode", fixtureCode > 0)
    check(
        "verifyNewer accepts a strictly older app",
        ManifestVerifier.verifyNewer(manifest, cert.publicKey, fixtureCode - 1)
    )
    check(
        "verifyNewer refuses the same version (no reinstall-by-replay)",
        !ManifestVerifier.verifyNewer(manifest, cert.publicKey, fixtureCode)
    )
    check(
        "verifyNewer refuses a downgrade",
        !ManifestVerifier.verifyNewer(manifest, cert.publicKey, fixtureCode + 5)
    )
    check(
        "verifyNewer still refuses a tampered manifest",
        !ManifestVerifier.verifyNewer(tampered, cert.publicKey, 0)
    )

    println(if (failures == 0) "ALL MANIFEST TESTS PASSED" else "$failures MANIFEST TEST(S) FAILED")
    if (failures > 0) kotlin.system.exitProcess(1)
}
