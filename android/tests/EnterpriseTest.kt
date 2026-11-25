import io.agenticcontrol.app.enrollment.DeviceIdentity
import io.agenticcontrol.app.enterprise.ChainedAuditLog
import io.agenticcontrol.app.enterprise.OperatorHistory
import io.agenticcontrol.app.enterprise.PolicyBundle
import io.agenticcontrol.app.enterprise.PolicyEnforcer
import io.agenticcontrol.app.enterprise.ScamFriction
import io.agenticcontrol.app.enterprise.SessionReceipt
import java.util.Base64

/**
 * Block E — enterprise pack, Android mirror (model layer).
 * Every check cites the directive it proves, mirroring the Windows
 * Acp.Tests EnterpriseTests semantics.
 */
private var failures = 0
private fun check(name: String, condition: Boolean) {
    if (condition) println("PASS  $name") else { println("FAIL  $name"); failures++ }
}

private const val T0 = 1_800_000_000_000L // fixed test instant (ms)
private const val DAY = 86_400_000L

fun main() {
    // DIR-25 / DIR-56 chained audit
    run {
        val log = ChainedAuditLog()
        log.append("session", "alice", "started", T0)
        val e2 = log.append("session", "alice", "earlier clock", T0 - 1000)
        check("DIR-56 Android backwards clock is flagged, sequence still orders", e2.clockSkewFlagged && e2.seq == 2L)
        val (ok, _) = log.verify()
        check("DIR-25 Android chained audit verifies intact", ok)
        val csv = log.exportCsv("admin1", T0 + 1000)
        check("DIR-23 Android export carries OK verdict and the export itself is audited",
            csv.contains("chainVerification=OK") && csv.contains("audit_export"))
    }

    // DIR-22 policy bundle: sign with a generated org identity, verify, enforce
    run {
        val org = DeviceIdentity.generate()
        val unsigned = PolicyBundle(
            version = 1, scopeId = "co1", transportCeiling = listOf("lan", "hub"), transportMode = "auto",
            pinnedVersion = "1.2.3", updateDeferUntilMillis = null, forbidAiPairings = true,
            disableRecording = false, unattendedTier = "business_hours",
            issuedMillis = T0, expiresMillis = T0 + 30 * DAY, signatureBase64 = ""
        )
        val sig = Base64.getEncoder().encodeToString(org.sign(unsigned.canonicalBody().toByteArray(Charsets.UTF_8)))
        val signed = unsigned.copy(signatureBase64 = sig)
        val (ok, _) = PolicyBundle.verify(signed, org.publicKey, T0 + DAY)
        check("DIR-22 Android verified bundle accepted", ok)
        val tampered = signed.copy(transportCeiling = listOf("lan", "hub", "tor"))
        check("DIR-22 Android tampered ceiling refused (fail closed)", !PolicyBundle.verify(tampered, org.publicKey, T0 + DAY).first)
        check("DIR-22 Android expired bundle refused", !PolicyBundle.verify(signed, org.publicKey, T0 + 31 * DAY).first)
        val enf = PolicyEnforcer(signed)
        check("DIR-22 Android pin refuses other versions", !enf.checkUpdate("1.2.4", T0).first && enf.checkUpdate("1.2.3", T0).first)
        check("DIR-22 Android ceiling refuses outside rungs", !enf.checkTransport("tor").first && enf.checkTransport("lan").first)
        check("DIR-65 Android AI-pairing prohibition enforced", !enf.checkAiPairing().first)
        val deferred = PolicyEnforcer(signed.copy(updateDeferUntilMillis = T0 + 7 * DAY))
        check("DIR-22 Android defer refuses until the date", !deferred.checkUpdate("1.2.3", T0 + DAY).first && deferred.checkUpdate("1.2.3", T0 + 8 * DAY).first)
        val manualBad = signed.copy(transportMode = "manual")
        check("DIR-22 Android manual policy must name exactly one rung", !PolicyBundle.verify(manualBad, org.publicKey, T0 + DAY).first)
    }

    // SCAM friction
    run {
        val fresh = OperatorHistory(0, 0, 0, null, false)
        val d = ScamFriction.evaluate("op-1", "Helper", fresh, T0 - 30 * DAY, T0, false)
        check("SCAM-01 Android first session view-only + 60s second consent", d.startsViewOnly && d.secondConsentRequired && d.secondConsentEarliestSeconds == 60)
        check("SCAM-04 Android presence label shows verification state", d.presenceLabel.startsWith("Unverified helper calling themselves"))
        val est = OperatorHistory(3, 0, 0, null, false)
        check("SCAM-15 Android established operator earns fast path", ScamFriction.evaluate("op-1", "Helper", est, T0 - 30 * DAY, T0, false).level == "established")
        val stopped = est.copy(lastStopMillis = T0 - 10 * 60 * 1000)
        check("SCAM-08 Android cooldown after STOP blocks fast path", ScamFriction.evaluate("op-1", "Helper", stopped, T0 - 30 * DAY, T0, false).warningRequired)
        check("SCAM-05 Android impersonation name triggers friction", ScamFriction.evaluate("op-1", "Microsoft Support", est, T0 - 30 * DAY, T0, false).warningRequired)
        check("SCAM-09 Android sensitive context pauses for non-established",
            ScamFriction.sensitiveContextPauses("banking", fresh) && !ScamFriction.sensitiveContextPauses("banking", est))
        check("SCAM-13 Android fresh install treated as first contact",
            ScamFriction.evaluate("op-1", "Helper", est, T0 - 3600_000, T0, false).startsViewOnly)
    }

    // HELP-09 receipt
    run {
        val receipt = SessionReceipt.generate("Sam", "2:14 PM", "2:37 PM", 23, 10, 13,
            emptyList(), emptyList(), wasRecorded = false, endReason = "you pressed STOP")
        check("HELP-09 Android receipt never omits categories", receipt.contains("No files were copied.") && receipt.contains("No programs were opened."))
        check("HELP-09 Android receipt states no recording plainly", receipt.contains("We did not record this session."))
    }

    if (failures > 0) { println("EnterpriseTest: $failures FAIL"); kotlin.system.exitProcess(1) }
    println("EnterpriseTest: all checks passed")
}
