using Acp.Shared.Enrollment;
using Acp.Shared.Security;

namespace Acp.Tests;

/// <summary>U9 follow-up — enroller public key transmitted in the
/// enrollment RESPONSE, verified enrollee-side against the committed
/// fingerprint (the enroller DeviceId held from the code/QR
/// transcript) before use. The Kotlin mirror
/// (tests/EnrollerKeySasTest.kt) asserts the identical outcomes and
/// the identical SAS strings.</summary>
public class EnrollerKeySasTests
{
    private static (EnrollmentService EnrollerSvc, DeviceIdentity Enroller, DeviceIdentity Enrollee) Setup()
    {
        var enroller = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var enrollee = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var svc = new EnrollmentService { LocalPublicKeyProvider = () => enroller.PublicKey };
        return (svc, enroller, enrollee);
    }

    private static (EnrollmentResponse Response, string Code, EnrolledDevice Enrolled) RedeemHonest(
        EnrollmentService svc, DeviceIdentity enrollee)
    {
        var code = svc.CreateEnrollmentCode("personal", "home", "Home");
        var (enrolled, response) = svc.RedeemWithResponse(code,
            new EnrollingDevice(enrollee.DeviceId, enrollee.PublicKeyBase64, "Phone"), "Enroller");
        return (response!, code, enrolled!);
    }

    [Fact]
    public void Response_CarriesEnrollerKey_WhoseFingerprintIsTheEnrollerDeviceId()
    {
        var (svc, enroller, enrollee) = Setup();
        var (response, _, _) = RedeemHonest(svc, enrollee);
        Assert.Equal(enroller.DeviceId, response.EnrollerDeviceId);
        Assert.Equal(enroller.PublicKeyBase64, response.EnrollerPublicKeyBase64);
        Assert.Equal(
            Ed25519.ComputeDeviceId(Convert.FromBase64String(response.EnrollerPublicKeyBase64!)),
            response.EnrollerDeviceId);
    }

    [Fact]
    public void Enrollee_ComputesIdenticalSas_FromVerifiedResponseKey()
    {
        var (svc, enroller, enrollee) = Setup();
        var (response, code, enrolled) = RedeemHonest(svc, enrollee);
        // Enrollee is a SEPARATE store: it never held the enroller key.
        var enrolleeSvc = new EnrollmentService();
        var result = enrolleeSvc.RecordReceiptFromResponse(
            response, enroller.DeviceId, enrollee.PublicKeyBase64, code);
        Assert.Equal(EnrollmentResponseOutcome.Applied, result.Outcome);
        Assert.NotNull(result.Receipt);
        // Identical string to the enroller-side record — the point of U9.
        Assert.Equal(enrolled.Sas, result.Receipt!.Sas);
        Assert.False(result.Receipt.SasConfirmed);
        Assert.Equal(PairingSas.StateUnconfirmed, result.Receipt.SasState);
        Assert.Contains(enrolleeSvc.ListSasAudit(),
            e => e.DeviceId == enroller.DeviceId && e.Action == PairingSas.StateUnconfirmed);
        // And it persists through export/import on the enrollee side.
        var restored = new EnrollmentService();
        restored.ImportJson(enrolleeSvc.ExportJson());
        Assert.Equal(enrolled.Sas, restored.ListReceipts().Single().Sas);
    }

    [Fact]
    public void Enrollee_CanConfirmReceiptSas_Locally_AndReportMismatch()
    {
        var (svc, enroller, enrollee) = Setup();
        var (response, code, _) = RedeemHonest(svc, enrollee);
        var enrolleeSvc = new EnrollmentService();
        enrolleeSvc.RecordReceiptFromResponse(response, enroller.DeviceId, enrollee.PublicKeyBase64, code);
        Assert.True(enrolleeSvc.ConfirmReceiptSas(enroller.DeviceId));
        Assert.True(enrolleeSvc.ListReceipts().Single().SasConfirmed);
        Assert.Equal(PairingSas.StateConfirmed, enrolleeSvc.ListReceipts().Single().SasState);
        Assert.True(enrolleeSvc.ReportReceiptSasMismatch(enroller.DeviceId));
        Assert.False(enrolleeSvc.ListReceipts().Single().SasConfirmed);
        Assert.Contains(enrolleeSvc.ListSasAudit(), e => e.Action == "sas_mismatch_reported");
        Assert.False(enrolleeSvc.ConfirmReceiptSas("unknown-enroller"));
    }

    // ---- destruction: substituted key vs the committed fingerprint ----

    [Fact]
    public void SubstitutedKeyInResponse_IsRefusedAndAudited_NoReceiptNoSas()
    {
        var (svc, enroller, enrollee) = Setup();
        var (response, code, _) = RedeemHonest(svc, enrollee);
        var mitm = new DeviceIdentity(new DevOnlyPassThroughProtector());
        // Attacker swaps its own key into the response (keeping the
        // honest enroller's claimed id — the classic MITM reveal).
        var attacked = response with { EnrollerPublicKeyBase64 = mitm.PublicKeyBase64 };
        var enrolleeSvc = new EnrollmentService();
        var result = enrolleeSvc.RecordReceiptFromResponse(
            attacked, enroller.DeviceId, enrollee.PublicKeyBase64, code);
        Assert.Equal(EnrollmentResponseOutcome.RefusedKeyMismatch, result.Outcome);
        Assert.Null(result.Receipt);
        Assert.Empty(enrolleeSvc.ListReceipts());
        Assert.Contains(enrolleeSvc.ListSasAudit(),
            e => e.Action == PairingSas.AuditEnrollerKeyMismatch);
    }

    [Fact]
    public void ResponseClaimingMitmId_ButVerifiedAgainstHonestCommitment_IsRefused()
    {
        var (svc, enroller, enrollee) = Setup();
        var (response, code, _) = RedeemHonest(svc, enrollee);
        var mitm = new DeviceIdentity(new DevOnlyPassThroughProtector());
        // Attacker rewrites BOTH the key and the claimed id to its
        // own — still refused, because the enrollee's commitment is
        // the HONEST enroller's fingerprint from the transcript.
        var attacked = response with
        {
            EnrollerDeviceId = mitm.DeviceId,
            EnrollerPublicKeyBase64 = mitm.PublicKeyBase64,
        };
        var enrolleeSvc = new EnrollmentService();
        var result = enrolleeSvc.RecordReceiptFromResponse(
            attacked, enroller.DeviceId, enrollee.PublicKeyBase64, code);
        Assert.Equal(EnrollmentResponseOutcome.RefusedKeyMismatch, result.Outcome);
        Assert.Empty(enrolleeSvc.ListReceipts());
    }

    [Fact]
    public void NoCommitmentHeld_KeyIsNotTrustedBlindly()
    {
        var (svc, enroller, enrollee) = Setup();
        var (response, code, _) = RedeemHonest(svc, enrollee);
        var enrolleeSvc = new EnrollmentService();
        var result = enrolleeSvc.RecordReceiptFromResponse(
            response, null, enrollee.PublicKeyBase64, code);
        Assert.Equal(EnrollmentResponseOutcome.RefusedKeyMismatch, result.Outcome);
        Assert.Empty(enrolleeSvc.ListReceipts());
        _ = enroller;
    }

    [Fact]
    public void MalformedKeyInResponse_IsRefusedAndAudited()
    {
        var (svc, enroller, enrollee) = Setup();
        var (response, code, _) = RedeemHonest(svc, enrollee);
        var enrolleeSvc = new EnrollmentService();
        var bad64 = enrolleeSvc.RecordReceiptFromResponse(
            response with { EnrollerPublicKeyBase64 = "!!!not-base64!!!" },
            enroller.DeviceId, enrollee.PublicKeyBase64, code);
        Assert.Equal(EnrollmentResponseOutcome.RefusedMalformed, bad64.Outcome);
        var shortKey = enrolleeSvc.RecordReceiptFromResponse(
            response with { EnrollerPublicKeyBase64 = Convert.ToBase64String(new byte[16]) },
            enroller.DeviceId, enrollee.PublicKeyBase64, code);
        Assert.Equal(EnrollmentResponseOutcome.RefusedMalformed, shortKey.Outcome);
        Assert.Empty(enrolleeSvc.ListReceipts());
        Assert.Contains(enrolleeSvc.ListSasAudit(),
            e => e.Action == PairingSas.AuditEnrollerKeyMalformed);
    }

    // ---- destruction: downgrade — strip the key to force no-SAS ----

    [Fact]
    public void StrippedKey_Downgrade_IsVisible_LegacyReceiptWithAbsentSasAudited()
    {
        var (svc, enroller, enrollee) = Setup();
        var (response, code, _) = RedeemHonest(svc, enrollee);
        // Same response an OLD enroller would send: no key at all.
        var legacy = response with { EnrollerPublicKeyBase64 = null };
        var enrolleeSvc = new EnrollmentService();
        var result = enrolleeSvc.RecordReceiptFromResponse(
            legacy, enroller.DeviceId, enrollee.PublicKeyBase64, code);
        Assert.Equal(EnrollmentResponseOutcome.LegacyNoKey, result.Outcome);
        Assert.NotNull(result.Receipt);
        Assert.Equal("", result.Receipt!.Sas);
        Assert.False(result.Receipt.HasSas);
        Assert.False(result.Receipt.SasConfirmed);
        // The downgrade is VISIBLE in the audit trail, not silent.
        Assert.Contains(enrolleeSvc.ListSasAudit(),
            e => e.Action == PairingSas.AuditAbsentNoEnrollerKey);
        // An absent SAS can never be confirmed into existence.
        Assert.False(enrolleeSvc.ConfirmReceiptSas(enroller.DeviceId));
    }

    [Fact]
    public void UnwiredEnroller_BuildsLegacyResponse_EnrolleeKeepsHonestAbsentSas()
    {
        // Enroller side with no local key wired = today's old build.
        var bare = new EnrollmentService();
        var enrollee = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var code = bare.CreateEnrollmentCode("local", "g", "G");
        var (enrolled, response) = bare.RedeemWithResponse(code,
            new EnrollingDevice(enrollee.DeviceId, enrollee.PublicKeyBase64, "Solo"), "Old Enroller");
        Assert.NotNull(enrolled);
        Assert.Null(response!.EnrollerPublicKeyBase64);
        var enrolleeSvc = new EnrollmentService();
        // Enrollee holds only a name-level id for the old enroller.
        var result = enrolleeSvc.RecordReceiptFromResponse(
            response with { EnrollerDeviceId = "legacy-enroller" },
            "legacy-enroller", enrollee.PublicKeyBase64, code);
        Assert.Equal(EnrollmentResponseOutcome.LegacyNoKey, result.Outcome);
        Assert.Equal("", result.Receipt!.Sas);
    }

    // ---- destruction: replayed response ----

    [Fact]
    public void ReplayedResponse_DoesNotDuplicateReceipt_OrDowngradeConfirmation()
    {
        var (svc, enroller, enrollee) = Setup();
        var (response, code, _) = RedeemHonest(svc, enrollee);
        var enrolleeSvc = new EnrollmentService();
        var first = enrolleeSvc.RecordReceiptFromResponse(
            response, enroller.DeviceId, enrollee.PublicKeyBase64, code);
        Assert.Equal(EnrollmentResponseOutcome.Applied, first.Outcome);
        // The human confirms locally, THEN the same response is
        // replayed (captured traffic re-sent at the enrollee).
        Assert.True(enrolleeSvc.ConfirmReceiptSas(enroller.DeviceId));
        var auditCount = enrolleeSvc.ListSasAudit().Count;
        var replay = enrolleeSvc.RecordReceiptFromResponse(
            response, enroller.DeviceId, enrollee.PublicKeyBase64, code);
        Assert.Equal(EnrollmentResponseOutcome.Applied, replay.Outcome);
        // No duplicate receipt, no duplicate audit entry, and the
        // replay must NOT shadow or reset the confirmed state with
        // a fresh unconfirmed copy.
        Assert.Single(enrolleeSvc.ListReceipts());
        Assert.True(enrolleeSvc.ListReceipts().Single().SasConfirmed);
        Assert.Equal(auditCount, enrolleeSvc.ListSasAudit().Count);
    }

    [Fact]
    public void ReplayedLegacyResponse_DoesNotDuplicateReceiptOrAudit()
    {
        var (svc, enroller, enrollee) = Setup();
        var (response, code, _) = RedeemHonest(svc, enrollee);
        var legacy = response with { EnrollerPublicKeyBase64 = null };
        var enrolleeSvc = new EnrollmentService();
        enrolleeSvc.RecordReceiptFromResponse(
            legacy, enroller.DeviceId, enrollee.PublicKeyBase64, code);
        var replay = enrolleeSvc.RecordReceiptFromResponse(
            legacy, enroller.DeviceId, enrollee.PublicKeyBase64, code);
        Assert.Equal(EnrollmentResponseOutcome.LegacyNoKey, replay.Outcome);
        Assert.Single(enrolleeSvc.ListReceipts());
        Assert.Single(enrolleeSvc.ListSasAudit(),
            e => e.Action == PairingSas.AuditAbsentNoEnrollerKey);
    }

    [Fact]
    public void StoredReceiptConfirmation_WithoutSas_DegradesOnImport_NeverFaked()
    {
        var svc = new EnrollmentService();
        svc.RecordReceipt(new EnrollmentReceipt("E", "enroller-x", "personal", "Home",
            DateTimeOffset.UtcNow, "", true)); // hand-forged: confirmed, no SAS
        var restored = new EnrollmentService();
        restored.ImportJson(svc.ExportJson());
        Assert.False(restored.ListReceipts().Single().SasConfirmed);
    }
}
