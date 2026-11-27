using DeskGuest.Shared.Enrollment;
using DeskGuest.Shared.Security;

namespace DeskGuest.Tests;

/// <summary>U9 — Pairing SAS (short authentication string).
/// Shared cross-platform vectors: the Kotlin suite
/// (tests/SasTest.kt) asserts the IDENTICAL strings for the
/// IDENTICAL inputs — that is what makes a human compare across a
/// Windows endpoint and an Android endpoint meaningful.</summary>
public class SasTests
{
    private static byte[] Seq(int start) => Enumerable.Range(start, 32).Select(i => (byte)i).ToArray();

    [Fact]
    public void Vector1_BothSidesDeriveIdenticalString()
    {
        var sas = PairingSas.Compute(Seq(0), Seq(32), "ABCDE23456");
        Assert.NotNull(sas);
        Assert.Equal("108306", sas!.Digits);
        Assert.Equal(new[] { "fad", "tal", "tak", "sar" }, sas.Words);
        Assert.Equal("108 306 \u00b7 fad tal tak sar", sas.Display);
        // Deterministic: recomputation is identical.
        Assert.Equal(sas.Display, PairingSas.Compute(Seq(0), Seq(32), "ABCDE23456")!.Display);
    }

    [Fact]
    public void Vector2_ZeroAndFFKeys()
    {
        var sas = PairingSas.Compute(new byte[32], Enumerable.Repeat((byte)0xFF, 32).ToArray(), "ZZZZZ99999");
        Assert.NotNull(sas);
        Assert.Equal("207511", sas!.Digits);
        Assert.Equal(new[] { "mak", "fab", "dag", "lat" }, sas.Words);
        Assert.Equal("207 511 \u00b7 mak fab dag lat", sas.Display);
    }

    [Fact]
    public void WordList_Is256DistinctWords()
    {
        Assert.Equal(256, PairingSas.WordList.Count);
        Assert.Equal(256, PairingSas.WordList.Distinct().Count());
    }

    [Fact]
    public void SubstitutedResponderKey_ChangesString_MITMFixture()
    {
        var honest = PairingSas.Compute(Seq(0), Seq(32), "ABCDE23456")!;
        var mitmKey = Seq(32); mitmKey[0] ^= 1;
        var attacked = PairingSas.Compute(Seq(0), mitmKey, "ABCDE23456")!;
        Assert.NotEqual(honest.Display, attacked.Display);
    }

    [Fact]
    public void SubstitutedInitiatorKey_ChangesString_MITMFixture()
    {
        var honest = PairingSas.Compute(Seq(0), Seq(32), "ABCDE23456")!;
        var mitmKey = Seq(0); mitmKey[31] ^= 0x80;
        var attacked = PairingSas.Compute(mitmKey, Seq(32), "ABCDE23456")!;
        Assert.NotEqual(honest.Display, attacked.Display);
    }

    [Fact]
    public void RoleOrderMatters_AndTranscriptBinds()
    {
        var a = PairingSas.Compute(Seq(0), Seq(32), "ABCDE23456")!;
        Assert.NotEqual(a.Display, PairingSas.Compute(Seq(32), Seq(0), "ABCDE23456")!.Display);
        Assert.NotEqual(a.Display, PairingSas.Compute(Seq(0), Seq(32), "ABCDE23457")!.Display);
    }

    [Fact]
    public void MalformedInputs_FailClosedNull()
    {
        Assert.Null(PairingSas.Compute(new byte[31], Seq(32), "ABCDE23456"));
        Assert.Null(PairingSas.Compute(Seq(0), null, "ABCDE23456"));
        Assert.Null(PairingSas.Compute(Seq(0), Seq(32), ""));
        Assert.Null(PairingSas.Compute(Seq(0), Seq(32), null));
        Assert.Null(PairingSas.ComputeBase64("!!!", Convert.ToBase64String(Seq(32)), "ABCDE23456"));
    }

    [Fact]
    public void DisplaysMatch_IsCaseAndWhitespaceTolerant()
    {
        Assert.True(PairingSas.DisplaysMatch("108 306 \u00b7 fad tal tak sar", "108306 fad  tal tak SAR"));
        Assert.False(PairingSas.DisplaysMatch("108 306 \u00b7 fad tal tak sar", "961 003 \u00b7 tat vav gat zek"));
        Assert.False(PairingSas.DisplaysMatch(null, "x"));
    }

    // ---- enrollment integration ----

    private static (EnrollmentService Service, DeviceIdentity Enroller, DeviceIdentity Enrolling) SetupWithKeys()
    {
        var enroller = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var enrolling = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var svc = new EnrollmentService { LocalPublicKeyProvider = () => enroller.PublicKey };
        return (svc, enroller, enrolling);
    }

    [Fact]
    public void Redeem_RecordCarriesSas_UnconfirmedHonestly()
    {
        var (svc, enroller, enrolling) = SetupWithKeys();
        var code = svc.CreateEnrollmentCode("personal", "home", "Home");
        var enrolled = svc.Redeem(code, new EnrollingDevice(enrolling.DeviceId, enrolling.PublicKeyBase64, "Phone"));
        Assert.NotNull(enrolled);
        // The stored SAS equals the pure computation over both keys + the normalized code.
        var expected = PairingSas.Compute(enrolling.PublicKey, enroller.PublicKey,
            EnrollmentService.NormalizeCode(code)!)!.Display;
        Assert.Equal(expected, enrolled!.Sas);
        Assert.False(enrolled.SasConfirmed);
        Assert.Equal(PairingSas.StateUnconfirmed, enrolled.SasState);
        Assert.Contains(svc.ListSasAudit(), e => e.DeviceId == enrolled.DeviceId && e.Action == PairingSas.StateUnconfirmed);
    }

    [Fact]
    public void ConfirmSas_EndpointLocalAct_FlipsState_AndPersists()
    {
        var (svc, _, enrolling) = SetupWithKeys();
        var enrolled = svc.Redeem(svc.CreateEnrollmentCode("personal", "home", "Home"),
            new EnrollingDevice(enrolling.DeviceId, enrolling.PublicKeyBase64, "Phone"))!;
        Assert.True(svc.ConfirmSas(enrolled.DeviceId));
        Assert.True(svc.List().Single().SasConfirmed);
        Assert.Equal(PairingSas.StateConfirmed, svc.List().Single().SasState);
        Assert.Contains(svc.ListSasAudit(), e => e.Action == PairingSas.StateConfirmed);

        var restored = new EnrollmentService();
        restored.ImportJson(svc.ExportJson());
        Assert.True(restored.List().Single().SasConfirmed);
        Assert.Equal(enrolled.Sas, restored.List().Single().Sas);
        Assert.Contains(restored.ListSasAudit(), e => e.Action == PairingSas.StateConfirmed);
    }

    [Fact]
    public void MismatchReport_KeepsUnconfirmed_AndIsAudited()
    {
        var (svc, _, enrolling) = SetupWithKeys();
        var enrolled = svc.Redeem(svc.CreateEnrollmentCode("personal", "home", "Home"),
            new EnrollingDevice(enrolling.DeviceId, enrolling.PublicKeyBase64, "Phone"))!;
        Assert.True(svc.ReportSasMismatch(enrolled.DeviceId));
        Assert.False(svc.List().Single().SasConfirmed);
        Assert.Contains(svc.ListSasAudit(), e => e.Action == "sas_mismatch_reported");
        // Pairing itself is untouched: still enrolled, not revoked.
        Assert.False(svc.List().Single().Revoked);
    }

    [Fact]
    public void ConfirmSas_UnknownDeviceOrNoSas_Fails()
    {
        var (svc, _, _) = SetupWithKeys();
        Assert.False(svc.ConfirmSas("unknown"));
        // No responder key wired: redeem succeeds, SAS empty, confirm impossible — never faked.
        var bare = new EnrollmentService();
        var id = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var enrolled = bare.Redeem(bare.CreateEnrollmentCode("local", "g", "G"),
            new EnrollingDevice(id.DeviceId, id.PublicKeyBase64, "Solo"))!;
        Assert.Equal("", enrolled.Sas);
        Assert.False(enrolled.SasConfirmed);
        Assert.False(bare.ConfirmSas(enrolled.DeviceId));
    }

    [Fact]
    public void MitmKeySubstitutionAtRedeem_ProducesDifferentSasThanHonestComputation()
    {
        var (svc, enroller, enrolling) = SetupWithKeys();
        var code = svc.CreateEnrollmentCode("personal", "home", "Home");
        var enrolled = svc.Redeem(code, new EnrollingDevice(enrolling.DeviceId, enrolling.PublicKeyBase64, "Phone"))!;
        var mitm = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var mitmSas = PairingSas.Compute(mitm.PublicKey, enroller.PublicKey,
            EnrollmentService.NormalizeCode(code)!)!.Display;
        Assert.NotEqual(mitmSas, enrolled.Sas);
    }
}
