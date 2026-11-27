import io.deskguest.app.crypto.AesGcmLineCipher
import io.deskguest.app.enrollment.DeviceIdentity
import io.deskguest.app.enrollment.EnrollmentStore
import io.deskguest.app.enrollment.PairingSas
import java.io.File
import java.nio.file.Files
import java.util.Base64

/**
 * U9 — Pairing SAS tests. The shared vectors are IDENTICAL to the
 * C# suite (DeskGuest.Tests/SasTests.cs): same inputs, same strings —
 * that is what makes a human compare across platforms meaningful.
 */
private var failures = 0

private fun check(name: String, condition: Boolean) {
    if (condition) println("PASS  $name")
    else {
        println("FAIL  $name")
        failures++
    }
}

private fun seq(start: Int): ByteArray = ByteArray(32) { (start + it).toByte() }

fun main() {
    // ---- shared vectors (identical in the C# suite) ----
    val v1 = PairingSas.compute(seq(0), seq(32), "ABCDE23456")
    check("vector1 digits", v1?.digits == "108306")
    check("vector1 words", v1?.words == listOf("fad", "tal", "tak", "sar"))
    check("vector1 display", v1?.display == "108 306 \u00b7 fad tal tak sar")
    check("vector1 deterministic", PairingSas.compute(seq(0), seq(32), "ABCDE23456")?.display == v1?.display)

    val v2 = PairingSas.compute(ByteArray(32), ByteArray(32) { 0xFF.toByte() }, "ZZZZZ99999")
    check("vector2 digits", v2?.digits == "207511")
    check("vector2 words", v2?.words == listOf("mak", "fab", "dag", "lat"))
    check("vector2 display", v2?.display == "207 511 \u00b7 mak fab dag lat")

    check("word list is 256 distinct", PairingSas.WORDS.size == 256 && PairingSas.WORDS.distinct().size == 256)

    // ---- MITM fixtures: substituting either key changes the string ----
    val mitmResp = seq(32); mitmResp[0] = (mitmResp[0].toInt() xor 1).toByte()
    check("substituted responder key changes SAS",
        PairingSas.compute(seq(0), mitmResp, "ABCDE23456")?.display != v1?.display)
    val mitmInit = seq(0); mitmInit[31] = (mitmInit[31].toInt() xor 0x80).toByte()
    check("substituted initiator key changes SAS",
        PairingSas.compute(mitmInit, seq(32), "ABCDE23456")?.display != v1?.display)
    check("role order matters",
        PairingSas.compute(seq(32), seq(0), "ABCDE23456")?.display != v1?.display)
    check("transcript binds",
        PairingSas.compute(seq(0), seq(32), "ABCDE23457")?.display != v1?.display)

    // ---- fail-closed ----
    check("short key fails closed", PairingSas.compute(ByteArray(31), seq(32), "ABCDE23456") == null)
    check("null key fails closed", PairingSas.compute(seq(0), null, "ABCDE23456") == null)
    check("blank transcript fails closed", PairingSas.compute(seq(0), seq(32), "") == null)
    check("bad base64 fails closed", PairingSas.computeBase64("!!!", Base64.getEncoder().encodeToString(seq(32)), "ABCDE23456") == null)
    check("displaysMatch tolerant", PairingSas.displaysMatch("961 003 \u00b7 tat vav gat hab", "961003 tat  vav gat HAB"))
    check("displaysMatch rejects different", !PairingSas.displaysMatch("961 003 \u00b7 tat vav gat hab", "961 003 \u00b7 tat vav gat zek"))

    // ---- enrollment integration ----
    val dir = Files.createTempDirectory("deskguest-sas-test").toFile()
    val cipher = AesGcmLineCipher(AesGcmLineCipher.generateKey())
    val enroller = DeviceIdentity.generate()
    val enrolling = DeviceIdentity.generate()
    val storeFile = File(dir, "sas.tsv")
    val store = EnrollmentStore(storeFile, cipher)
    store.localPublicKeyProvider = { enroller.publicKey }
    val code = store.mint("personal", "home", "Home")
    val enrolled = store.redeem(
        code,
        EnrollmentStore.EnrollingDevice(enrolling.deviceId, enrolling.publicKeyBase64, "Phone")
    )
    check("redeem succeeds with SAS wired", enrolled != null)
    val expected = PairingSas.compute(
        enrolling.publicKey, enroller.publicKey,
        EnrollmentStore.normalizeCode(code)!!
    )?.display
    check("record carries the SAS both sides derive", enrolled?.sas == expected)
    check("record starts honestly unconfirmed",
        enrolled?.sasConfirmed == false && enrolled?.sasState == PairingSas.STATE_UNCONFIRMED)
    check("redeem audit-trailed as unconfirmed",
        store.sasAudit().any { it.deviceId == enrolling.deviceId && it.action == PairingSas.STATE_UNCONFIRMED })

    check("confirmSas flips state", store.confirmSas(enrolling.deviceId))
    check("confirmed state visible", store.all().single().sasConfirmed &&
        store.all().single().sasState == PairingSas.STATE_CONFIRMED)
    check("confirm audit-trailed", store.sasAudit().any { it.action == PairingSas.STATE_CONFIRMED })

    // Persistence: confirmed state + SAS + audit survive reload.
    val reloaded = EnrollmentStore(storeFile, cipher)
    check("SAS + confirmation survive reload",
        reloaded.all().single().sas == expected && reloaded.all().single().sasConfirmed)
    check("SAS audit survives reload", reloaded.sasAudit().size == store.sasAudit().size)

    check("mismatch report keeps unconfirmed + audits",
        reloaded.reportSasMismatch(enrolling.deviceId) &&
            !reloaded.all().single().sasConfirmed &&
            reloaded.sasAudit().any { it.action == "sas_mismatch_reported" })
    check("mismatch does not revoke or remove the pairing",
        reloaded.all().size == 1 && !reloaded.all().single().revoked)

    // No responder key wired: redeem still succeeds, SAS empty, confirm impossible — never faked.
    val bareFile = File(dir, "bare.tsv")
    val bare = EnrollmentStore(bareFile, cipher)
    val bareCode = bare.mint("local", "g", "G")
    val bareEnrolled = bare.redeem(
        bareCode,
        EnrollmentStore.EnrollingDevice(enrolling.deviceId, enrolling.publicKeyBase64, "Solo")
    )
    check("no-key redeem succeeds with empty SAS", bareEnrolled != null && bareEnrolled.sas == "")
    check("no-key record is unconfirmed", bareEnrolled?.sasConfirmed == false)
    check("confirm without SAS is refused", !bare.confirmSas(enrolling.deviceId))
    check("confirm unknown device is refused", !store.confirmSas("unknown"))

    // Legacy 9-field line loads with empty/unconfirmed SAS.
    val legacyId = DeviceIdentity.generate()
    val legacyFile = File(dir, "legacy.tsv")
    legacyFile.writeText(
        "device\t${legacyId.deviceId}\tLegacy\t${legacyId.publicKeyBase64}\tlocal\tg\tG\t1700000000000\t0"
    )
    val legacy = EnrollmentStore(legacyFile, cipher)
    check("legacy line loads empty + unconfirmed SAS",
        legacy.all().singleOrNull()?.let { it.sas == "" && !it.sasConfirmed } == true)

    dir.deleteRecursively()
    println(if (failures == 0) "ALL SAS TESTS PASSED" else "$failures SAS TEST(S) FAILED")
    if (failures > 0) kotlin.system.exitProcess(1)
}
