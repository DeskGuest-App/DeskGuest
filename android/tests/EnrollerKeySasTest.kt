import io.deskguest.app.crypto.AesGcmLineCipher
import io.deskguest.app.enrollment.DeviceIdentity
import io.deskguest.app.enrollment.EnrollmentStore
import io.deskguest.app.enrollment.PairingSas
import java.io.File
import java.nio.file.Files

/**
 * U9 follow-up — enroller public key transmitted in the enrollment
 * RESPONSE, verified enrollee-side against the committed fingerprint
 * (the enroller DeviceId held from the code/QR transcript) before
 * use. Mirrors the C# suite (DeskGuest.Tests/EnrollerKeySasTests.cs):
 * identical outcomes, identical SAS strings.
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
    val dir = Files.createTempDirectory("deskguest-enroller-key-test").toFile()
    val cipher = AesGcmLineCipher(AesGcmLineCipher.generateKey())
    val enroller = DeviceIdentity.generate()
    val enrollee = DeviceIdentity.generate()

    // ---- enroller side: redeem + response carries the key ----
    val enrollerFile = File(dir, "enroller.tsv")
    val enrollerStore = EnrollmentStore(enrollerFile, cipher)
    enrollerStore.localPublicKeyProvider = { enroller.publicKey }
    val code = enrollerStore.mint("personal", "home", "Home")
    val (enrolled, response) = enrollerStore.redeemWithResponse(
        code,
        EnrollmentStore.EnrollingDevice(enrollee.deviceId, enrollee.publicKeyBase64, "Phone"),
        "Enroller"
    )
    check("redeem succeeds", enrolled != null && response != null)
    check("response carries enroller key",
        response?.enrollerPublicKeyBase64 == enroller.publicKeyBase64)
    check("response enroller id is the key fingerprint",
        response?.enrollerDeviceId == enroller.deviceId &&
            response?.enrollerDeviceId == DeviceIdentity.deviceIdFor(enroller.publicKey))

    // ---- enrollee side: separate store, verifies + computes ----
    val enrolleeFile = File(dir, "enrollee.tsv")
    val enrolleeStore = EnrollmentStore(enrolleeFile, cipher)
    val applied = enrolleeStore.recordReceiptFromResponse(
        response, enroller.deviceId, enrollee.publicKeyBase64, code)
    check("honest response applied",
        applied.outcome == EnrollmentStore.EnrollmentResponseOutcome.APPLIED)
    check("enrollee SAS identical to enroller-side record",
        applied.receipt?.sas == enrolled?.sas && applied.receipt?.sas?.isNotBlank() == true)
    check("receipt starts honestly unconfirmed",
        applied.receipt?.sasConfirmed == false &&
            applied.receipt?.sasState == PairingSas.STATE_UNCONFIRMED)
    check("enrollee redeem audit-trailed as unconfirmed",
        enrolleeStore.sasAudit().any {
            it.deviceId == enroller.deviceId && it.action == PairingSas.STATE_UNCONFIRMED
        })

    // Persistence: receipt SAS survives reload on the enrollee side.
    val reloaded = EnrollmentStore(enrolleeFile, cipher)
    check("receipt SAS survives reload",
        reloaded.receipts().singleOrNull()?.sas == enrolled?.sas)

    // Enrollee-side local confirm + mismatch (its own human act).
    check("confirmReceiptSas flips state", reloaded.confirmReceiptSas(enroller.deviceId))
    check("receipt confirmed state visible",
        reloaded.receipts().single().sasConfirmed &&
            reloaded.receipts().single().sasState == PairingSas.STATE_CONFIRMED)
    check("receipt mismatch report keeps unconfirmed + audits",
        reloaded.reportReceiptSasMismatch(enroller.deviceId) &&
            !reloaded.receipts().single().sasConfirmed &&
            reloaded.sasAudit().any { it.action == "sas_mismatch_reported" })
    check("confirm unknown enroller refused", !reloaded.confirmReceiptSas("unknown"))

    // ---- destruction: substituted key vs committed fingerprint ----
    val mitm = DeviceIdentity.generate()
    val attacked = response!!.copy(enrollerPublicKeyBase64 = mitm.publicKeyBase64)
    val victimFile = File(dir, "victim.tsv")
    val victim = EnrollmentStore(victimFile, cipher)
    val refused = victim.recordReceiptFromResponse(
        attacked, enroller.deviceId, enrollee.publicKeyBase64, code)
    check("substituted key refused as mismatch",
        refused.outcome == EnrollmentStore.EnrollmentResponseOutcome.REFUSED_KEY_MISMATCH)
    check("substituted key produces NO receipt and NO SAS",
        refused.receipt == null && victim.receipts().isEmpty())
    check("substituted key audited",
        victim.sasAudit().any { it.action == PairingSas.AUDIT_ENROLLER_KEY_MISMATCH })

    // Attacker rewrites BOTH key and claimed id — still refused,
    // because the commitment is the HONEST enroller's fingerprint.
    val attacked2 = response.copy(
        enrollerDeviceId = mitm.deviceId,
        enrollerPublicKeyBase64 = mitm.publicKeyBase64
    )
    val refused2 = victim.recordReceiptFromResponse(
        attacked2, enroller.deviceId, enrollee.publicKeyBase64, code)
    check("self-consistent MITM response still refused vs honest commitment",
        refused2.outcome == EnrollmentStore.EnrollmentResponseOutcome.REFUSED_KEY_MISMATCH &&
            victim.receipts().isEmpty())

    // No commitment held: the key is not trusted blindly.
    val refused3 = victim.recordReceiptFromResponse(
        response, null, enrollee.publicKeyBase64, code)
    check("no commitment held refuses the key",
        refused3.outcome == EnrollmentStore.EnrollmentResponseOutcome.REFUSED_KEY_MISMATCH)

    // Malformed keys: refused + audited, no receipt.
    val bad64 = victim.recordReceiptFromResponse(
        response.copy(enrollerPublicKeyBase64 = "!!!not-base64!!!"),
        enroller.deviceId, enrollee.publicKeyBase64, code)
    check("bad base64 key refused malformed",
        bad64.outcome == EnrollmentStore.EnrollmentResponseOutcome.REFUSED_MALFORMED)
    val shortKey = victim.recordReceiptFromResponse(
        response.copy(
            enrollerPublicKeyBase64 = java.util.Base64.getEncoder().encodeToString(ByteArray(16))),
        enroller.deviceId, enrollee.publicKeyBase64, code)
    check("short key refused malformed",
        shortKey.outcome == EnrollmentStore.EnrollmentResponseOutcome.REFUSED_MALFORMED)
    check("malformed keys audited, still no receipts",
        victim.receipts().isEmpty() &&
            victim.sasAudit().any { it.action == PairingSas.AUDIT_ENROLLER_KEY_MALFORMED })

    // ---- destruction: downgrade — strip the key to force no-SAS ----
    val legacy = response.copy(enrollerPublicKeyBase64 = null)
    val legacyFile = File(dir, "legacy-enrollee.tsv")
    val legacyStore = EnrollmentStore(legacyFile, cipher)
    val legacyResult = legacyStore.recordReceiptFromResponse(
        legacy, enroller.deviceId, enrollee.publicKeyBase64, code)
    check("stripped key is the visible legacy outcome",
        legacyResult.outcome == EnrollmentStore.EnrollmentResponseOutcome.LEGACY_NO_KEY)
    check("legacy receipt carries absent SAS, unconfirmed, never faked",
        legacyResult.receipt?.sas == "" && legacyResult.receipt?.hasSas == false &&
            legacyResult.receipt?.sasConfirmed == false)
    check("downgrade is audited, not silent",
        legacyStore.sasAudit().any { it.action == PairingSas.AUDIT_ABSENT_NO_ENROLLER_KEY })
    check("absent SAS can never be confirmed into existence",
        !legacyStore.confirmReceiptSas(enroller.deviceId))
    // The legacy receipt + its audit entry survive reload.
    val legacyReloaded = EnrollmentStore(legacyFile, cipher)
    check("legacy receipt + absent audit survive reload",
        legacyReloaded.receipts().singleOrNull()?.sas == "" &&
            legacyReloaded.sasAudit().any { it.action == PairingSas.AUDIT_ABSENT_NO_ENROLLER_KEY })

    // ---- destruction: replayed response ----
    // The human confirms locally, THEN the same honest response is
    // replayed at the enrollee: no duplicate receipt, no duplicate
    // audit, and the replay must NOT shadow/reset the confirmed
    // state with a fresh unconfirmed copy.
    val replayFile = File(dir, "replay-enrollee.tsv")
    val replayStore = EnrollmentStore(replayFile, cipher)
    val firstApplied = replayStore.recordReceiptFromResponse(
        response, enroller.deviceId, enrollee.publicKeyBase64, code)
    check("replay leg: first response applied",
        firstApplied.outcome == EnrollmentStore.EnrollmentResponseOutcome.APPLIED)
    check("replay leg: confirm before replay", replayStore.confirmReceiptSas(enroller.deviceId))
    val auditBeforeReplay = replayStore.sasAudit().size
    val replayed = replayStore.recordReceiptFromResponse(
        response, enroller.deviceId, enrollee.publicKeyBase64, code)
    check("replayed response still reports applied",
        replayed.outcome == EnrollmentStore.EnrollmentResponseOutcome.APPLIED)
    check("replayed response stores NO duplicate receipt",
        replayStore.receipts().size == 1)
    check("replayed response does NOT downgrade the confirmed state",
        replayStore.receipts().single().sasConfirmed)
    check("replayed response adds NO duplicate audit entry",
        replayStore.sasAudit().size == auditBeforeReplay)
    // Replayed LEGACY (stripped) response: also idempotent.
    val legacyReplay = legacyStore.recordReceiptFromResponse(
        legacy, enroller.deviceId, enrollee.publicKeyBase64, code)
    check("replayed legacy response stores NO duplicate receipt or audit",
        legacyReplay.outcome == EnrollmentStore.EnrollmentResponseOutcome.LEGACY_NO_KEY &&
            legacyStore.receipts().size == 1 &&
            legacyStore.sasAudit().count {
                it.action == PairingSas.AUDIT_ABSENT_NO_ENROLLER_KEY
            } == 1)

    // Unwired enroller (old build shape) builds a legacy response.
    val bareFile = File(dir, "bare.tsv")
    val bare = EnrollmentStore(bareFile, cipher)
    val bareCode = bare.mint("local", "g", "G")
    val (bareEnrolled, bareResponse) = bare.redeemWithResponse(
        bareCode,
        EnrollmentStore.EnrollingDevice(enrollee.deviceId, enrollee.publicKeyBase64, "Solo"),
        "Old Enroller"
    )
    check("unwired enroller redeems and builds a keyless response",
        bareEnrolled != null && bareResponse?.enrollerPublicKeyBase64 == null)

    dir.deleteRecursively()
    println(if (failures == 0) "ALL ENROLLER-KEY TESTS PASSED" else "$failures ENROLLER-KEY TEST(S) FAILED")
    if (failures > 0) kotlin.system.exitProcess(1)
}
