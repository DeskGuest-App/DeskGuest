using System.Text;
using System.Text.RegularExpressions;
using DeskGuest.Shared.Enrollment;
using DeskGuest.Shared.Security;

namespace DeskGuest.Tests;

public class EnrollmentTests
{
    private static (EnrollmentService Service, DeviceIdentity Identity) Setup()
        => (new EnrollmentService(), new DeviceIdentity(new DevOnlyPassThroughProtector()));

    private static EnrollingDevice AsEnrolling(DeviceIdentity identity, string name = "Owner's Phone") =>
        new(identity.DeviceId, identity.PublicKeyBase64, name);

    [Fact]
    public void Mint_CodeFormat_IsFiveDashFive_FromAlphabet()
    {
        var (svc, _) = Setup();
        var code = svc.CreateEnrollmentCode("personal", "home", "Home");
        Assert.Matches(new Regex(@"^[A-HJKMNP-Z2-9]{5}-[A-HJKMNP-Z2-9]{5}$"), code);
        Assert.DoesNotContain("I", code);
        Assert.DoesNotContain("L", code);
        Assert.DoesNotContain("O", code);
        Assert.DoesNotContain("0", code);
        Assert.DoesNotContain("1", code);
    }

    [Fact]
    public void Redeem_BindsMintedScopeAndGroup()
    {
        var (svc, identity) = Setup();
        var code = svc.CreateEnrollmentCode("company", "company-a-fleet", "Company A Fleet");
        var enrolled = svc.Redeem(code, AsEnrolling(identity));
        Assert.NotNull(enrolled);
        Assert.Equal("company", enrolled!.Scope);
        Assert.Equal("company-a-fleet", enrolled.GroupId);
        Assert.Equal("Company A Fleet", enrolled.GroupName);
        Assert.Equal(identity.DeviceId, enrolled.DeviceId);
        Assert.False(enrolled.Revoked);
    }

    [Fact]
    public void Redeem_LocalScope_IsLocalPairing()
    {
        var (svc, identity) = Setup();
        var code = svc.CreateEnrollmentCode("local", "g1", "G1");
        Assert.Equal("local", svc.Redeem(code, AsEnrolling(identity))!.Scope);
    }

    [Fact]
    public void Mint_InvalidScope_Throws()
    {
        var (svc, _) = Setup();
        Assert.Throws<ArgumentException>(() => svc.CreateEnrollmentCode("galactic", "g", "G"));
    }

    [Fact]
    public void Redeem_IsCaseAndDashInsensitive()
    {
        var (svc, identity) = Setup();
        var code = svc.CreateEnrollmentCode("personal", "home", "Home");
        var presented = code.Replace("-", "").ToLowerInvariant();
        Assert.NotNull(svc.Redeem(presented, AsEnrolling(identity)));
    }

    [Fact]
    public void Redeem_CodeIsSingleUse()
    {
        var (svc, identity) = Setup();
        var other = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var code = svc.CreateEnrollmentCode("personal", "home", "Home");
        Assert.NotNull(svc.Redeem(code, AsEnrolling(identity)));
        Assert.Null(svc.Redeem(code, AsEnrolling(other)));
    }

    [Fact]
    public void Redeem_ExpiredCode_Fails()
    {
        var (svc, identity) = Setup();
        var code = svc.CreateEnrollmentCode("personal", "home", "Home", TimeSpan.FromSeconds(-5));
        Assert.Null(svc.Redeem(code, AsEnrolling(identity)));
    }

    [Fact]
    public void Redeem_UnknownOrMalformedCode_Fails()
    {
        var (svc, identity) = Setup();
        Assert.Null(svc.Redeem("AAAAA-AAAAA", AsEnrolling(identity)));
        Assert.Null(svc.Redeem("not a code", AsEnrolling(identity)));
        Assert.Null(svc.Redeem(null, AsEnrolling(identity)));
        Assert.Null(svc.Redeem("", AsEnrolling(identity)));
    }

    [Fact]
    public void Redeem_DeviceIdMismatchWithPublicKey_Fails_AndDoesNotConsume()
    {
        var (svc, identity) = Setup();
        var impostor = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var code = svc.CreateEnrollmentCode("personal", "home", "Home");
        // Claims the real identity's DeviceId but presents its own key.
        var lying = new EnrollingDevice(identity.DeviceId, impostor.PublicKeyBase64, "Liar");
        Assert.Null(svc.Redeem(code, lying));
        // Failed redeem does not consume: the honest device can still enroll.
        Assert.NotNull(svc.Redeem(code, AsEnrolling(identity)));
    }

    [Fact]
    public void Redeem_MalformedPublicKey_Fails()
    {
        var (svc, identity) = Setup();
        var code = svc.CreateEnrollmentCode("personal", "home", "Home");
        Assert.Null(svc.Redeem(code, new EnrollingDevice(identity.DeviceId, "!!!base64!!!", "X")));
        Assert.Null(svc.Redeem(code, new EnrollingDevice(identity.DeviceId,
            Convert.ToBase64String(new byte[16]), "X")));
    }

    [Fact]
    public void ListByGroup_FiltersRoster()
    {
        var (svc, a) = Setup();
        var b = new DeviceIdentity(new DevOnlyPassThroughProtector());
        svc.Redeem(svc.CreateEnrollmentCode("personal", "home", "Home"), AsEnrolling(a, "A"));
        svc.Redeem(svc.CreateEnrollmentCode("company", "work", "Work"), AsEnrolling(b, "B"));
        Assert.Equal(2, svc.List().Count);
        Assert.Single(svc.ListByGroup("home"));
        Assert.Equal("A", svc.ListByGroup("home")[0].DisplayName);
        Assert.Single(svc.ListByGroup("WORK")); // case-insensitive
        Assert.Empty(svc.ListByGroup("nope"));
    }

    [Fact]
    public void VerifyEnrolledSignature_Works_UntilRevoked()
    {
        var (svc, identity) = Setup();
        svc.Redeem(svc.CreateEnrollmentCode("personal", "home", "Home"), AsEnrolling(identity));
        var message = Encoding.UTF8.GetBytes("prove it");
        var sig = identity.Sign(message);
        Assert.True(svc.VerifyEnrolledSignature(identity.DeviceId, message, sig));
        Assert.True(svc.VerifyEnrolledSignature(identity.DeviceId, message, Convert.ToBase64String(sig)));

        Assert.True(svc.Revoke(identity.DeviceId));
        // Revocation takes effect immediately.
        Assert.False(svc.VerifyEnrolledSignature(identity.DeviceId, message, sig));
        Assert.True(svc.List().Single().Revoked);
    }

    [Fact]
    public void VerifyEnrolledSignature_UnknownTamperedOrMalformed_Fails()
    {
        var (svc, identity) = Setup();
        svc.Redeem(svc.CreateEnrollmentCode("personal", "home", "Home"), AsEnrolling(identity));
        var message = Encoding.UTF8.GetBytes("m");
        var sig = identity.Sign(message);
        Assert.False(svc.VerifyEnrolledSignature("unknown-device", message, sig));
        Assert.False(svc.VerifyEnrolledSignature(identity.DeviceId, Encoding.UTF8.GetBytes("other"), sig));
        Assert.False(svc.VerifyEnrolledSignature(identity.DeviceId, message, new byte[10]));
        Assert.False(svc.VerifyEnrolledSignature(identity.DeviceId, null, sig));
        Assert.False(svc.VerifyEnrolledSignature(null, message, sig));
        Assert.False(svc.Revoke("unknown-device"));
    }

    [Fact]
    public void Receipts_RecordAndList()
    {
        var (svc, _) = Setup();
        svc.RecordReceipt("Muse", "enroller-device-1", "personal", "Home",
            new DateTimeOffset(2026, 11, 17, 12, 0, 0, TimeSpan.Zero));
        var receipts = svc.ListReceipts();
        Assert.Single(receipts);
        Assert.Equal("Muse", receipts[0].EnrollerName);
        Assert.Equal("enroller-device-1", receipts[0].EnrollerDeviceId);
        Assert.Equal("personal", receipts[0].Scope);
        Assert.Equal("Home", receipts[0].GroupName);
    }

    [Fact]
    public void ExportImport_RoundTrip_PreservesRosterAndReceipts()
    {
        var (svc, identity) = Setup();
        svc.Redeem(svc.CreateEnrollmentCode("company", "company-a", "Company A"), AsEnrolling(identity));
        svc.RecordReceipt("Enroller", "enroller-9", "company", "Company A");
        var message = Encoding.UTF8.GetBytes("after restore");
        var sig = identity.Sign(message);

        var restored = new EnrollmentService();
        Assert.Equal(1, restored.ImportJson(svc.ExportJson()));
        var device = restored.List().Single();
        Assert.Equal(identity.DeviceId, device.DeviceId);
        Assert.Equal("company", device.Scope);
        Assert.Equal("company-a", device.GroupId);
        Assert.Single(restored.ListReceipts());
        Assert.True(restored.VerifyEnrolledSignature(identity.DeviceId, message, sig));
    }

    [Fact]
    public void ExportImport_PreservesRevocation()
    {
        var (svc, identity) = Setup();
        svc.Redeem(svc.CreateEnrollmentCode("personal", "home", "Home"), AsEnrolling(identity));
        svc.Revoke(identity.DeviceId);
        var restored = new EnrollmentService();
        restored.ImportJson(svc.ExportJson());
        var message = Encoding.UTF8.GetBytes("m");
        Assert.False(restored.VerifyEnrolledSignature(identity.DeviceId, message, identity.Sign(message)));
    }

    [Fact]
    public void Export_ContainsNoSeed_AndNoPendingCode()
    {
        var protector = new DevOnlyPassThroughProtector();
        var seed = Convert.FromHexString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        var identity = new DeviceIdentity(protector, seed);
        var svc = new EnrollmentService();
        var liveCode = svc.CreateEnrollmentCode("personal", "home", "Home");
        svc.Redeem(svc.CreateEnrollmentCode("personal", "home", "Home"), AsEnrolling(identity));
        var json = svc.ExportJson();
        Assert.DoesNotContain(Convert.ToHexString(seed), json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(Convert.ToBase64String(seed), json);
        Assert.DoesNotContain(EnrollmentService.NormalizeCode(liveCode)!, json);
        Assert.DoesNotContain(identity.ExportProtectedSeed(), json);
    }

    [Fact]
    public void Import_MalformedEntries_Skipped_NeverFatal()
    {
        var (svc, identity) = Setup();
        svc.Redeem(svc.CreateEnrollmentCode("personal", "home", "Home"), AsEnrolling(identity));
        var good = svc.ExportJson();
        // Inject a bogus device entry (bad key / mismatched fingerprint).
        var corrupt = good.Replace("\"Receipts\"",
            "\"Devices2\":[],\"Receipts\"").Replace("\"Devices\":[",
            "\"Devices\":[{\"DeviceId\":\"deadbeef\",\"DisplayName\":\"Bad\",\"PublicKeyBase64\":\"AAAA\",\"Scope\":\"personal\",\"GroupId\":\"home\",\"GroupName\":\"Home\",\"EnrolledUtc\":\"2026-11-17T00:00:00Z\",\"Revoked\":false},");
        var restored = new EnrollmentService();
        Assert.Equal(1, restored.ImportJson(corrupt));
        Assert.Single(restored.List());
        // Wholly malformed JSON restores nothing and does not throw.
        Assert.Equal(0, new EnrollmentService().ImportJson("{not json"));
        Assert.Equal(0, new EnrollmentService().ImportJson(""));
    }

    [Fact]
    public void TransportMode_ManualWithAllowedTransports_PersistsRoundTrip()
    {
        // D31: transport mode is decided at enrollment (bound at mint,
        // like scope/group) and survives export/import per device.
        var (svc, identity) = Setup();
        var code = svc.CreateEnrollmentCode("personal", "home", "Home",
            transportMode: "manual",
            allowedTransports: new[] { "tailscale", "lan", "loopback" });
        var enrolled = svc.Redeem(code, AsEnrolling(identity));
        Assert.NotNull(enrolled);
        Assert.Equal("manual", enrolled!.TransportMode);
        Assert.Equal(new HashSet<string> { "tailscale", "lan", "loopback" }, enrolled.AllowedTransports);

        var restored = new EnrollmentService();
        Assert.Equal(1, restored.ImportJson(svc.ExportJson()));
        var device = restored.List().Single();
        Assert.Equal("manual", device.TransportMode);
        Assert.Equal(new HashSet<string> { "tailscale", "lan", "loopback" }, device.AllowedTransports);
    }

    [Fact]
    public void TransportMode_DefaultsToInherit_AndImportFallsBackOnMalformed()
    {
        var (svc, identity) = Setup();
        var enrolled = svc.Redeem(svc.CreateEnrollmentCode("local", "g", "G"), AsEnrolling(identity));
        Assert.Equal("inherit", enrolled!.TransportMode);
        Assert.Empty(enrolled.AllowedTransports);

        // A stored record with a bogus mode / missing transports
        // imports with the defaults, never fatal (D31).
        var json = svc.ExportJson().Replace("\"TransportMode\":\"inherit\"", "\"TransportMode\":\"bogus\"");
        var restored = new EnrollmentService();
        Assert.Equal(1, restored.ImportJson(json));
        Assert.Equal("inherit", restored.List().Single().TransportMode);
    }

    [Fact]
    public void Changed_FiresOnRedeemRevokeAndReceipt()
    {
        var (svc, identity) = Setup();
        var fired = 0;
        svc.Changed += () => fired++;
        svc.Redeem(svc.CreateEnrollmentCode("personal", "home", "Home"), AsEnrolling(identity));
        svc.Revoke(identity.DeviceId);
        svc.RecordReceipt("E", "e-1", "personal", "Home");
        Assert.Equal(3, fired);
    }
}

public class EnrollPayloadTests
{
    [Fact]
    public void Qr_RoundTrip()
    {
        var svc = new EnrollmentService();
        var code = svc.CreateEnrollmentCode("personal", "home-group", "Home");
        var payload = EnrollPayload.Build(code, "personal", "home-group");
        Assert.StartsWith("deskguest://enroll/1?c=", payload);
        var parsed = EnrollPayload.Parse(payload);
        Assert.NotNull(parsed);
        Assert.Equal(EnrollmentService.NormalizeCode(code), parsed!.Code);
        Assert.Equal("personal", parsed.Scope);
        Assert.Equal("home-group", parsed.GroupId);
        // The parsed code redeems against the same service.
        var identity = new DeviceIdentity(new DevOnlyPassThroughProtector());
        Assert.NotNull(svc.Redeem(parsed.Code,
            new EnrollingDevice(identity.DeviceId, identity.PublicKeyBase64, "Phone")));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not a uri at all")]
    [InlineData("https://enroll/1?c=ABCDE23456")] // wrong scheme
    [InlineData("deskguest://other/1?c=ABCDE23456")] // wrong host
    [InlineData("deskguest://enroll/2?c=ABCDE23456")] // wrong version
    [InlineData("deskguest://enroll/1")] // missing code
    [InlineData("deskguest://enroll/1?s=personal&g=home")] // missing code
    [InlineData("deskguest://enroll/1?c=SHORT")] // code too short
    [InlineData("deskguest://enroll/1?c=IL0OIL0OIL")] // characters outside the alphabet
    [InlineData("deskguest://enroll/1?c=")] // empty code
    public void Qr_HostileInput_Rejected_NeverThrows(string? payload)
    {
        Assert.Null(EnrollPayload.Parse(payload));
        Assert.False(EnrollPayload.TryParse(payload, out var info));
        Assert.Null(info);
    }
}
