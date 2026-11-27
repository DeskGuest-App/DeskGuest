using System.Text;
using System.Text.Json;
using DeskGuest.Core;
using DeskGuest.Shared.Connection;
using DeskGuest.Shared.Enrollment;
using DeskGuest.Shared.Roster;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.Sessions;

namespace DeskGuest.Tests;

/// <summary>
/// DESTRUCTION GATE (project directive, 2026-11-18): hostile attacks on the
/// Slice 1–3 model layer — break it, corrupt its state, extract what
/// it protects, misuse it as a hostile actor or reckless user. Every
/// test here is a permanent regression entry in the D42 battery;
/// outcomes are recorded in ~/workspace/windows-agent/DESTRUCTION-LEDGER.md.
/// D38-* tests disposition the independent inspector's Slice 3
/// Windows findings F1–F12 (packet e5fbe100).
/// </summary>

// ---------------------------------------------------------------- Slice 1

public class DestructionEnrollmentTests
{
    private static (EnrollmentService Svc, DeviceIdentity Identity) Setup()
    {
        var svc = new EnrollmentService();
        return (svc, new DeviceIdentity(new DevOnlyPassThroughProtector()));
    }

    private static EnrollingDevice AsEnrolling(DeviceIdentity id, string name = "Device") =>
        new(id.DeviceId, id.PublicKeyBase64, name);

    [Fact]
    public void Destruction_Redeem_ReplayOfConsumedCode_Refused()
    {
        var (svc, identity) = Setup();
        var code = svc.CreateEnrollmentCode("company", "company-a", "Company A");
        Assert.NotNull(svc.Redeem(code, AsEnrolling(identity)));
        // Replay: the same code, even by the same device, is dead.
        Assert.Null(svc.Redeem(code, AsEnrolling(identity)));
        var other = new DeviceIdentity(new DevOnlyPassThroughProtector());
        Assert.Null(svc.Redeem(code, AsEnrolling(other)));
        Assert.Single(svc.List());
    }

    [Fact]
    public void Destruction_Redeem_AfterExpiry_Refused_AndCodeDead()
    {
        var (svc, identity) = Setup();
        var code = svc.CreateEnrollmentCode("company", "company-a", "Company A", TimeSpan.FromMilliseconds(-1000));
        Assert.Null(svc.Redeem(code, AsEnrolling(identity)));
        Assert.Empty(svc.List());
    }

    [Fact]
    public void Destruction_Redeem_BindingConfusion_KeyAIdWithKeyB_Refused()
    {
        var (svc, a) = Setup();
        var b = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var code = svc.CreateEnrollmentCode("company", "company-a", "Company A");
        // Present A's DeviceId with B's public key: fingerprint mismatch.
        Assert.Null(svc.Redeem(code, new EnrollingDevice(a.DeviceId, b.PublicKeyBase64, "Impostor")));
        // Present B's DeviceId with A's key: also mismatch.
        Assert.Null(svc.Redeem(code, new EnrollingDevice(b.DeviceId, a.PublicKeyBase64, "Impostor")));
        Assert.Empty(svc.List());
        // The code was NOT consumed by the failed impostor attempts:
        // the legitimate device can still redeem (availability).
        Assert.NotNull(svc.Redeem(code, AsEnrolling(a)));
    }

    [Fact]
    public void Destruction_Redeem_WrongGuesses_DoNotConsumeTheCode()
    {
        var (svc, identity) = Setup();
        var code = svc.CreateEnrollmentCode("company", "company-a", "Company A");
        var normalized = EnrollmentService.NormalizeCode(code)!;
        // 200 wrong guesses (deterministically different from the code).
        for (var i = 0; i < 200; i++)
        {
            var guess = EnrollmentService.FormatCode(
                new string(EnrollmentService.CodeAlphabet[i % EnrollmentService.CodeAlphabet.Length], 1) +
                new string(EnrollmentService.CodeAlphabet[(i / 7) % EnrollmentService.CodeAlphabet.Length], 9));
            if (EnrollmentService.NormalizeCode(guess) == normalized) continue;
            Assert.Null(svc.Redeem(guess, AsEnrolling(identity)));
        }
        // NOTE (ledger finding DG-S1-04): wrong guesses never burn the
        // code and there is no throttle in the model layer — recorded
        // as a spec finding; the availability half (legitimate redeem
        // still works after the barrage) is asserted here.
        Assert.NotNull(svc.Redeem(code, AsEnrolling(identity)));
    }

    [Fact]
    public void Destruction_VerifySignature_MalformedAndHostileInputs_AllRefused()
    {
        var (svc, identity) = Setup();
        svc.Redeem(svc.CreateEnrollmentCode("company", "company-a", "Company A"), AsEnrolling(identity));
        var msg = Encoding.UTF8.GetBytes("attested reading");
        var sig = identity.Sign(msg);
        Assert.True(svc.VerifyEnrolledSignature(identity.DeviceId, msg, sig));
        // Tampered message / tampered signature.
        Assert.False(svc.VerifyEnrolledSignature(identity.DeviceId, Encoding.UTF8.GetBytes("forged"), sig));
        var badSig = sig.ToArray(); badSig[10] ^= 0xFF;
        Assert.False(svc.VerifyEnrolledSignature(identity.DeviceId, msg, badSig));
        // Truncated / empty / oversized / random signatures.
        Assert.False(svc.VerifyEnrolledSignature(identity.DeviceId, msg, sig.Take(63).ToArray()));
        Assert.False(svc.VerifyEnrolledSignature(identity.DeviceId, msg, Array.Empty<byte>()));
        Assert.False(svc.VerifyEnrolledSignature(identity.DeviceId, msg, sig.Concat(new byte[] { 1 }).ToArray()));
        Assert.False(svc.VerifyEnrolledSignature(identity.DeviceId, msg, new byte[64]));
        // Unknown device, null inputs.
        Assert.False(svc.VerifyEnrolledSignature("deadbeef", msg, sig));
        Assert.False(svc.VerifyEnrolledSignature(null, msg, sig));
        Assert.False(svc.VerifyEnrolledSignature(identity.DeviceId, null, sig));
        Assert.False(svc.VerifyEnrolledSignature(identity.DeviceId, msg, (byte[]?)null));
        // A different enrolled device's key does not verify for this id.
        var other = new DeviceIdentity(new DevOnlyPassThroughProtector());
        svc.Redeem(svc.CreateEnrollmentCode("company", "company-a", "Company A"), AsEnrolling(other));
        Assert.False(svc.VerifyEnrolledSignature(other.DeviceId, msg, sig));
        // Revocation kills verification immediately.
        Assert.True(svc.Revoke(identity.DeviceId));
        Assert.False(svc.VerifyEnrolledSignature(identity.DeviceId, msg, sig));
    }

    [Fact]
    public void Destruction_Import_RevokedDevice_CannotBeResurrectedIntoLiveStore()
    {
        var (svc, identity) = Setup();
        svc.Redeem(svc.CreateEnrollmentCode("company", "company-a", "Company A"), AsEnrolling(identity));
        Assert.True(svc.Revoke(identity.DeviceId));
        // Hand-edited export: same device, Revoked flipped to false,
        // scope/group rewritten — imported into the LIVE store.
        var hostile = svc.ExportJson().Replace("\"Revoked\":true", "\"Revoked\":false");
        svc.ImportJson(hostile);
        var device = svc.List().Single();
        Assert.True(device.Revoked); // the live revocation stands
        var msg = Encoding.UTF8.GetBytes("m");
        Assert.False(svc.VerifyEnrolledSignature(identity.DeviceId, msg, identity.Sign(msg)));
    }

    [Fact]
    public void Destruction_Import_DuplicatesAndGarbage_NeverFatal_NeverDuplicated()
    {
        var (svc, identity) = Setup();
        svc.Redeem(svc.CreateEnrollmentCode("company", "company-a", "Company A"), AsEnrolling(identity));
        var good = svc.ExportJson();
        // Duplicate the device entry inside one payload + 2000 bogus rows.
        using var doc = JsonDocument.Parse(good);
        var deviceJson = doc.RootElement.GetProperty("Devices")[0].GetRawText();
        var bogus = string.Join(",", Enumerable.Range(0, 2000).Select(i =>
            $"{{\"DeviceId\":\"{i:x64}\",\"DisplayName\":\"B{i}\",\"PublicKeyBase64\":\"AAAA\",\"Scope\":\"company\",\"GroupId\":\"company-a\",\"GroupName\":\"Company A\",\"EnrolledUtc\":\"2026-11-17T00:00:00Z\",\"Revoked\":false}}"));
        var payload = $"{{\"Devices\":[{deviceJson},{deviceJson},{bogus}],\"Receipts\":[]}}";
        var restored = new EnrollmentService();
        restored.ImportJson(payload);
        Assert.Single(restored.List());
        Assert.Equal(identity.DeviceId, restored.List()[0].DeviceId);
        // Deeply nested / truncated / wrong-shape JSON: no throw, no state.
        Assert.Equal(0, new EnrollmentService().ImportJson(new string('[', 5000)));
        Assert.Equal(0, new EnrollmentService().ImportJson(good.Substring(0, good.Length / 2)));
        Assert.Equal(0, new EnrollmentService().ImportJson("[1,2,3]"));
        Assert.Equal(0, new EnrollmentService().ImportJson("null"));
    }

    private sealed class HashingProtector : ISecretProtector
    {
        public string Name => "hash-stub";
        public bool IsRealProtection => true;
        public string Protect(string plaintext) =>
            Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(plaintext)));
        public string Unprotect(string protectedText) => throw new NotSupportedException();
    }

    [Fact]
    public void Destruction_Identity_NoPublicSurfaceLeaksTheSeed()
    {
        var seed = Convert.FromHexString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        var identity = new DeviceIdentity(new HashingProtector(), seed);
        var seedHex = Convert.ToHexString(seed);
        var seedB64 = Convert.ToBase64String(seed);
        // JSON serialization of the identity object carries no seed.
        var json = JsonSerializer.Serialize(identity);
        Assert.DoesNotContain(seedHex, json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(seedB64, json);
        // The protected export hands material only to the protector:
        // with an irreversible protector nothing seed-shaped survives.
        var exported = identity.ExportProtectedSeed();
        Assert.DoesNotContain(seedHex, exported, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(seedB64, exported);
        // The public key is not the seed and signing does not expose it.
        Assert.NotEqual(seed, identity.PublicKey);
        Assert.Equal(64, identity.Sign(Encoding.UTF8.GetBytes("x")).Length);
    }

    [Fact]
    public void Destruction_Qr_PayloadScopeAndGroupHints_NeverOverrideMintBinding()
    {
        var (svc, identity) = Setup();
        var code = svc.CreateEnrollmentCode("personal", "home-group", "Home");
        var normalized = EnrollmentService.NormalizeCode(code)!;
        // Hostile payload: same code, but scope/group hints rewritten
        // to a company fleet group. The mint binding must win.
        var hostile = $"deskguest://enroll/1?c={normalized}&s=company&g=evil-fleet";
        var parsed = EnrollPayload.Parse(hostile);
        Assert.NotNull(parsed);
        var enrolled = svc.Redeem(parsed!.Code, AsEnrolling(identity));
        Assert.NotNull(enrolled);
        Assert.Equal("personal", enrolled!.Scope);
        Assert.Equal("home-group", enrolled.GroupId);
        // Parser survives a barrage of hostile shapes without throwing.
        foreach (var p in new[]
                 {
                     "deskguest://enroll@evil.example/1?c=" + normalized,
                     "deskguest://enroll/1?c=" + normalized + "#fragment",
                     "deskguest://enroll/1?c=" + new string('A', 100_000),
                     "deskguest://enroll/1?c=%41%42%43",
                     "DeskGuest://ENROLL/1?c=" + normalized.ToLowerInvariant(),
                     "deskguest://enroll/1?c=" + normalized + "&c=ZZZZZ22222",
                     "deskguest://enroll/%31?c=" + normalized,
                     "\u0000deskguest://enroll/1?c=" + normalized,
                 })
        {
            try { EnrollPayload.Parse(p); }
            catch (Exception ex) { Assert.Fail($"Parse threw on hostile input: {ex.GetType().Name}"); }
        }
    }
}

// ---------------------------------------------------------------- Slice 2

public class DestructionRosterTests
{
    private sealed class World
    {
        public required EnrollmentService Enrollments { get; init; }
        public required RosterService Roster { get; init; }
    }

    private static World Setup()
    {
        var enrollments = new EnrollmentService();
        var roster = new RosterService(enrollments);
        Assert.NotNull(roster.CreateScope("personal-1", "personal", "Personal"));
        Assert.NotNull(roster.CreateScope("company-1", "company", "Company A"));
        Assert.NotNull(roster.CreateUser("owner", "personal-1", "Owner", "human"));
        Assert.NotNull(roster.CreateUser("admin-a", "company-1", "Admin A", "human"));
        Assert.NotNull(roster.CreateUser("admin-b", "company-1", "Admin B", "human"));
        Assert.NotNull(roster.CreateUser("target", "company-1", "Target", "human"));
        Assert.NotNull(roster.CreateUser("member", "company-1", "Member", "human"));
        Assert.NotNull(roster.CreateUser("ai-1", "company-1", "Agent", "ai", pairedByUserId: "target"));
        Assert.True(roster.AddCompanyAdmin("company-1", "admin-a"));
        Assert.True(roster.AddCompanyAdmin("company-1", "admin-b"));
        Assert.NotNull(roster.CreateUserGroup("ug-1", "company-1", "Techs",
            new[] { "target", "member" }, new[] { "target" }));
        Assert.NotNull(roster.CreateDeviceGroup("dg-1", "company-1", "Fleet", new[] { "lan", "hub" }));
        Assert.NotNull(roster.AddGrant("company-1", "ug-1", "dg-1", new[] { "use", "enroll" }));
        return new World { Enrollments = enrollments, Roster = roster };
    }

    private static EnrolledDevice Enroll(World w, string name)
    {
        var identity = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var code = w.Enrollments.CreateEnrollmentCode("company", "dg-1", "Fleet");
        var device = w.Enrollments.Redeem(code, new EnrollingDevice(identity.DeviceId, identity.PublicKeyBase64, name));
        Assert.NotNull(device);
        return device!;
    }

    [Fact]
    public void Destruction_SuspendedCompanyAdmin_CannotOffboardOrStripAdmin()
    {
        var w = Setup();
        Assert.True(w.Roster.SetUserSuspended("company-1", "admin-b", true));
        // A suspended admin keeps the seat on paper but must hold NO power:
        // offboarding a user and stripping a fellow admin both refuse.
        Assert.Null(w.Roster.RemoveUser("company-1", "target", "admin-b", stepUp: true));
        Assert.NotNull(w.Roster.GetUser("company-1", "target"));
        Assert.False(w.Roster.RemoveCompanyAdmin("company-1", "admin-a", "admin-b", stepUp: true));
        Assert.True(w.Roster.IsCompanyAdmin("company-1", "admin-a"));
        // The live admin is unaffected and can still act.
        Assert.NotNull(w.Roster.RemoveUser("company-1", "target", "admin-a", stepUp: true));
    }

    [Fact]
    public void Destruction_Import_SuspendedUser_CannotEnterAsCompanyAdmin()
    {
        const string json = """
        {
          "Scopes": [{"Id":"company-1","Kind":"company","Name":"Company A","TransportCeiling":null}],
          "Users": [
            {"Id":"boss","ScopeId":"company-1","DisplayName":"Boss","Kind":"human","PairedByUserId":null,"Suspended":true},
            {"Id":"peer","ScopeId":"company-1","DisplayName":"Peer","Kind":"human","PairedByUserId":null,"Suspended":false}
          ],
          "CompanyAdmins": [
            {"ScopeId":"company-1","UserId":"boss"},
            {"ScopeId":"company-1","UserId":"peer"}
          ],
          "UserGroups": [], "DeviceGroups": [], "Grants": [], "Minted": [], "Events": []
        }
        """;
        var restored = new RosterService(new EnrollmentService());
        restored.ImportJson(json);
        // AddCompanyAdmin refuses a suspended user; import must not be
        // a side door around the same rule (D9/D13 consistency).
        Assert.False(restored.IsCompanyAdmin("company-1", "boss"));
        Assert.True(restored.IsCompanyAdmin("company-1", "peer"));
    }

    [Fact]
    public void Destruction_LastAdminGuard_EveryRemovalOrder_FailsToReachZero()
    {
        var w = Setup();
        // Order 1: strip B's seat (step-up), then try every route on A.
        Assert.True(w.Roster.RemoveCompanyAdmin("company-1", "admin-b", "admin-a", stepUp: true));
        Assert.Equal(1, w.Roster.CompanyAdmins("company-1").Count);
        Assert.False(w.Roster.RemoveCompanyAdmin("company-1", "admin-a", "admin-a"));
        Assert.Null(w.Roster.RemoveUser("company-1", "admin-a", "admin-a", stepUp: true));
        Assert.Equal(1, w.Roster.CompanyAdmins("company-1").Count);
        Assert.NotNull(w.Roster.GetUser("company-1", "admin-a"));
    }

    [Fact]
    public void Destruction_FellowAdminRemoval_WithoutStepUp_RefusedOnBothPaths()
    {
        var w = Setup();
        Assert.False(w.Roster.RemoveCompanyAdmin("company-1", "admin-b", "admin-a"));
        Assert.Null(w.Roster.RemoveUser("company-1", "admin-b", "admin-a"));
        Assert.True(w.Roster.IsCompanyAdmin("company-1", "admin-b"));
        Assert.NotNull(w.Roster.GetUser("company-1", "admin-b"));
        // With step-up the same acts succeed — the guard is the flag,
        // not a blanket refusal.
        Assert.True(w.Roster.RemoveCompanyAdmin("company-1", "admin-b", "admin-a", stepUp: true));
    }

    [Fact]
    public void Destruction_AiAdmin_EveryRoute_Refused()
    {
        var w = Setup();
        Assert.False(w.Roster.AddCompanyAdmin("company-1", "ai-1"));
        Assert.Null(w.Roster.CreateUserGroup("ug-ai", "company-1", "Bot Group",
            Array.Empty<string>(), new[] { "ai-1" }));
        Assert.NotNull(w.Roster.CreateUserGroup("ug-2", "company-1", "Second"));
        Assert.False(w.Roster.AddUserGroupAdmin("company-1", "ug-2", "ai-1", "admin-a"));
        Assert.False(w.Roster.UserHasRight("company-1", "ai-1", "dg-1", "admin"));
        Assert.False(w.Roster.HasAdminRight("company-1", "ai-1", deviceGroupId: "dg-1"));
        // Even holding the floor of rights via a grant, an AI never
        // gains structural power.
        Assert.NotNull(w.Roster.AddGrant("company-1", "ug-1", "dg-1", new[] { "use", "enroll", "admin" }));
        Assert.False(w.Roster.DeleteDeviceGroup("company-1", "dg-1", "ai-1"));
        Assert.False(w.Roster.DeleteUserGroup("company-1", "ug-1", "ai-1"));
    }

    [Fact]
    public void Destruction_Member_StructuralActs_AllRefused()
    {
        var w = Setup();
        var device = Enroll(w, "Member Target PC");
        Assert.False(w.Roster.DeleteUserGroup("company-1", "ug-1", "member"));
        Assert.False(w.Roster.DeleteDeviceGroup("company-1", "dg-1", "member"));
        Assert.False(w.Roster.DeleteDevice("company-1", device.DeviceId, "member"));
        Assert.False(w.Roster.RemoveGrant("company-1", "ug-1", "dg-1", "member"));
        Assert.False(w.Roster.SetGroupTransports("company-1", "dg-1", new[] { "tor" }, "member"));
        Assert.False(w.Roster.RemoveUserGroupMember("company-1", "ug-1", "target", "member"));
        Assert.False(w.Roster.AddUserGroupAdmin("company-1", "ug-1", "member", "member"));
        // Nothing moved.
        Assert.NotNull(w.Roster.GetUserGroup("company-1", "ug-1"));
        Assert.NotNull(w.Roster.GetDeviceGroup("company-1", "dg-1"));
        Assert.False(w.Enrollments.List().Single().Revoked);
        Assert.Equal(new[] { "lan", "hub" }, w.Roster.GetDeviceGroup("company-1", "dg-1")!.TransportSet);
    }

    [Fact]
    public void Destruction_CrossScope_Acts_Refused_TheWallCutsBothWays()
    {
        var w = Setup();
        // Company admin reaching into the personal scope.
        Assert.Null(w.Roster.RemoveUser("personal-1", "owner", "admin-a", stepUp: true));
        Assert.NotNull(w.Roster.GetUser("personal-1", "owner"));
        // A user id that lives in another scope is not removable here.
        Assert.Null(w.Roster.RemoveUser("company-1", "owner", "admin-a", stepUp: true));
        // Cross-scope AI ownership is refused at creation (D8/D9).
        Assert.Null(w.Roster.CreateUser("ai-x", "company-1", "X", "ai", pairedByUserId: "owner"));
        // Cross-scope grant is refused.
        Assert.NotNull(w.Roster.CreateUserGroup("ug-p", "personal-1", "Mine", new[] { "owner" }));
        Assert.Null(w.Roster.AddGrant("company-1", "ug-p", "dg-1", new[] { "use" }));
        // Operator rosters are scope-pure.
        var personal = w.Roster.OperatorRoster("personal-1")!;
        Assert.DoesNotContain(personal.Users, u => u.ScopeId == "company-1");
        var company = w.Roster.OperatorRoster("company-1")!;
        Assert.DoesNotContain(company.Users, u => u.ScopeId == "personal-1");
    }

    [Fact]
    public void Destruction_PinOutsideSet_EffectiveTransportsNeverWiden()
    {
        var w = Setup();
        var device = Enroll(w, "Pinned PC");
        // The guarded roster path rejects the outside pin outright (D32).
        Assert.False(w.Roster.UpdateDeviceTransportPolicy(device.DeviceId, "manual", new[] { "tor" }));
        // The raw Slice 1 update (trusted in-process API) CAN store an
        // outside pin — but resolution intersects with the group set,
        // so the device's effective transports never widen past it.
        Assert.True(w.Enrollments.TryUpdateTransports(device.DeviceId, "manual", new[] { "tor" }));
        var effective = w.Roster.EffectiveTransportsForDevice(device.DeviceId);
        Assert.NotNull(effective);
        Assert.DoesNotContain("tor", effective!);
        Assert.All(effective!, r => Assert.Contains(r, new[] { "lan", "hub" }));
    }

    [Fact]
    public void Destruction_Offboarding_CompletenessSweep_NoSurvivingAccess()
    {
        var w = Setup();
        var device = Enroll(w, "Target Minted PC");
        Assert.True(w.Roster.RecordMintedEnrollment("company-1", "target", device.DeviceId));
        var msg = Encoding.UTF8.GetBytes("proof");
        var identityDevice = w.Enrollments.List().Single();
        Assert.False(identityDevice.Revoked);

        var blast = w.Roster.RemoveUser("company-1", "target", "admin-a", stepUp: true);
        Assert.NotNull(blast);
        // User record gone; cannot be re-seated by any admin path.
        Assert.Null(w.Roster.GetUser("company-1", "target"));
        Assert.False(w.Roster.AddCompanyAdmin("company-1", "target"));
        // Group seats (member + admin) gone.
        var ug = w.Roster.GetUserGroup("company-1", "ug-1")!;
        Assert.DoesNotContain("target", ug.MemberUserIds);
        Assert.DoesNotContain("target", ug.AdminUserIds);
        // Minted enrollment revoked: the device is dead for signatures.
        Assert.True(w.Enrollments.List().Single().Revoked);
        // Owned AI suspended, not deleted (D14).
        var ai = w.Roster.GetUser("company-1", "ai-1");
        Assert.NotNull(ai);
        Assert.True(ai!.Suspended);
        // A second removal finds nothing to fire on.
        Assert.Null(w.Roster.RemoveUser("company-1", "target", "admin-a", stepUp: true));
        _ = msg;
    }

    [Fact]
    public void Destruction_Offboarding_PendingCodeMintedByRemovedUser_DiesWithThem()
    {
        var w = Setup();
        // Target mints an enrollment code for a future device (the
        // auth key they created, D14) but nobody redeems it yet.
        var identity = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var code = w.Enrollments.CreateEnrollmentCode("company", "dg-1", "Fleet",
            mintedByUserId: "target");
        Assert.NotNull(w.Roster.RemoveUser("company-1", "target", "admin-a", stepUp: true));
        // After offboarding the pending code must be dead: the removed
        // user cannot leave a live enrollment key behind.
        Assert.Null(w.Enrollments.Redeem(code,
            new EnrollingDevice(identity.DeviceId, identity.PublicKeyBase64, "Shadow Device")));
        Assert.Empty(w.Enrollments.List());
        // A code minted by a surviving user still redeems fine.
        var code2 = w.Enrollments.CreateEnrollmentCode("company", "dg-1", "Fleet",
            mintedByUserId: "admin-a");
        Assert.NotNull(w.Enrollments.Redeem(code2,
            new EnrollingDevice(identity.DeviceId, identity.PublicKeyBase64, "Legit Device")));
    }

    [Fact]
    public void Destruction_Import_DoubleImport_NoDuplicateGrantsOrMinted()
    {
        var w = Setup();
        var device = Enroll(w, "Dup PC");
        Assert.True(w.Roster.RecordMintedEnrollment("company-1", "target", device.DeviceId));
        var json = w.Roster.ExportJson();
        var restored = new RosterService(new EnrollmentService());
        restored.ImportJson(json);
        var grantsOnce = restored.ListGrants("company-1").Count;
        var mintedOnce = restored.ListMintedEnrollments("company-1").Count;
        // Restoring the same file again (operator error, crash loop)
        // must not multiply grants or minted attributions.
        restored.ImportJson(json);
        Assert.Equal(grantsOnce, restored.ListGrants("company-1").Count);
        Assert.Equal(mintedOnce, restored.ListMintedEnrollments("company-1").Count);
    }
}

// ---------------------------------------------------------------- Slice 3

public class DestructionSessionTests
{
    private sealed class World
    {
        public required EnrollmentService Enrollments { get; init; }
        public required RosterService Roster { get; init; }
        public required SessionService Sessions { get; init; }
        public required string DeviceId { get; init; }
    }

    private static World Setup()
    {
        var enrollments = new EnrollmentService();
        var roster = new RosterService(enrollments);
        Assert.NotNull(roster.CreateScope("personal-1", "personal", "Personal"));
        Assert.NotNull(roster.CreateScope("company-1", "company", "Company A"));
        Assert.NotNull(roster.CreateUser("owner", "personal-1", "Owner One", "human"));
        Assert.NotNull(roster.CreateUser("admin", "company-1", "Admin", "human"));
        Assert.True(roster.AddCompanyAdmin("company-1", "admin"));
        Assert.NotNull(roster.CreateUser("host", "company-1", "Host User", "human"));
        Assert.NotNull(roster.CreateUser("ctrl", "company-1", "Controller", "human"));
        Assert.NotNull(roster.CreateUser("peer", "company-1", "Peer", "human"));
        Assert.NotNull(roster.CreateUser("outsider", "company-1", "Outsider", "human"));
        Assert.NotNull(roster.CreateUser("ai-1", "company-1", "Agent One", "ai", pairedByUserId: "admin"));
        Assert.NotNull(roster.CreateUserGroup("ug-1", "company-1", "Techs",
            new[] { "ctrl", "host", "peer", "ai-1" }));
        Assert.NotNull(roster.CreateDeviceGroup("dg-1", "company-1", "Fleet", new[] { "lan", "hub" }));
        Assert.NotNull(roster.AddGrant("company-1", "ug-1", "dg-1", new[] { "use" }));

        var identity = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var code = enrollments.CreateEnrollmentCode("company", "dg-1", "Fleet");
        var device = enrollments.Redeem(code, new EnrollingDevice(identity.DeviceId, identity.PublicKeyBase64, "Site PC"));
        Assert.NotNull(device);
        return new World
        {
            Enrollments = enrollments,
            Roster = roster,
            Sessions = new SessionService(roster, enrollments),
            DeviceId = device!.DeviceId,
        };
    }

    private static Session CreateAttended(World w, string initiator = "ctrl")
    {
        var s = w.Sessions.CreateSession("company-1", w.DeviceId, initiator, "attended", "lan");
        Assert.NotNull(s);
        return s!;
    }

    private static string ActiveAttended(World w)
    {
        var s = CreateAttended(w);
        Assert.True(w.Sessions.AcceptSession(s.Id, "host", SessionAcceptOrigin.EndpointLocal));
        Assert.True(w.Sessions.StartSession(s.Id));
        return s.Id;
    }

    // ---- D38 F1: self-accept / AI accept -------------------------------------
    // REDEFINED by the 2026-11-19 endpoint-local ruling (DG-FIND-05):
    // the F1-era rule refused the initiator / participants outright,
    // which left a one-user personal scope with no valid acceptor at
    // all. The ruling makes ORIGIN the consent signal: an accept over
    // the initiating channel refuses for EVERYONE (the F1 hole, in
    // its exact original form), while an endpoint-local accept is
    // valid for any live human of the scope — initiator included.
    // These two tests now pin the channel half; the local half lives
    // in DestructionEndpointLocalAcceptanceTests below.

    [Fact]
    public void Destruction_D38_F1_InitiatorCannotAcceptOwnSession_OverInitiatingChannel()
    {
        var w = Setup();
        var s = CreateAttended(w);
        Assert.False(w.Sessions.AcceptSession(s.Id, "ctrl", SessionAcceptOrigin.InitiatingChannel)); // self-accept over the channel
        Assert.Null(w.Sessions.GetSession(s.Id)!.AcceptedByUserId);
        Assert.False(w.Sessions.StartSession(s.Id)); // consent gate still shut
        Assert.Equal("requested", w.Sessions.GetSession(s.Id)!.State);
    }

    [Fact]
    public void Destruction_D38_F1_AiCannotAccept_AndChannelAcceptsRefuse()
    {
        var w = Setup();
        var s = CreateAttended(w);
        // An AI accept is not consent on EITHER origin: no human at
        // the device consented, locally or otherwise.
        Assert.False(w.Sessions.AcceptSession(s.Id, "ai-1", SessionAcceptOrigin.EndpointLocal));
        Assert.False(w.Sessions.AcceptSession(s.Id, "ai-1", SessionAcceptOrigin.InitiatingChannel));
        Assert.True(w.Sessions.AddParticipant(s.Id, "peer", "watcher", "ctrl"));
        // Over the initiating channel NOBODY can accept — not a
        // participant, not the host user, not an admin: the channel
        // is the requester's side, and the request cannot approve
        // itself (the original F1 claim, preserved verbatim).
        Assert.False(w.Sessions.AcceptSession(s.Id, "peer", SessionAcceptOrigin.InitiatingChannel));
        Assert.False(w.Sessions.AcceptSession(s.Id, "host", SessionAcceptOrigin.InitiatingChannel));
        Assert.False(w.Sessions.AcceptSession(s.Id, "admin", SessionAcceptOrigin.InitiatingChannel));
        Assert.Null(w.Sessions.GetSession(s.Id)!.AcceptedByUserId);
        // The genuine endpoint-local host accept still works.
        Assert.True(w.Sessions.AcceptSession(s.Id, "host", SessionAcceptOrigin.EndpointLocal));
    }

    // ---- D38 F2: host authority via AddParticipant -----------------------------

    [Fact]
    public void Destruction_D38_F2_HostRoleCannotBeAssignedViaAddParticipant()
    {
        var w = Setup();
        var id = ActiveAttended(w);
        Assert.False(w.Sessions.AddParticipant(id, "peer", "host", "ctrl"));
        Assert.False(w.Sessions.AddParticipant(id, "ai-1", "host", "ctrl"));
        Assert.False(w.Sessions.AddParticipant(id, "peer", "host", "host"));
        // Neither gained host authority: STOP and floor acts refuse.
        Assert.False(w.Sessions.StopSession(id, "peer"));
        Assert.False(w.Sessions.GrantFloor(id, "ctrl", "peer"));
        Assert.Equal("active", w.Sessions.GetSession(id)!.State);
        // Exactly one host participant exists: the acceptor.
        var hosts = w.Sessions.ListParticipants(id).Where(p => p.Role == "host").ToList();
        Assert.Equal("host", Assert.Single(hosts).UserId);
    }

    // ---- D38 F3: unattended STOP trap -------------------------------------------

    [Fact]
    public void Destruction_D38_F3_UnattendedSession_IsStoppableWithoutCompanyAdmin()
    {
        var w = Setup();
        // Company scope, unattended: no acceptor, no host participant.
        var s = w.Sessions.CreateSession("company-1", w.DeviceId, "ctrl", "unattended", "lan");
        Assert.NotNull(s);
        Assert.True(w.Sessions.StartSession(s!.Id));
        // A live human of the scope at the host machine can STOP it —
        // a live session the host cannot clear must be impossible.
        Assert.True(w.Sessions.StopSession(s.Id, "host"));
        Assert.Equal("ended", w.Sessions.GetSession(s.Id)!.State);
        Assert.Equal("host_stop", w.Sessions.GetSession(s.Id)!.EndReason);
        // An AI can never wield STOP.
        var s2 = w.Sessions.CreateSession("company-1", w.DeviceId, "ctrl", "unattended", "lan");
        Assert.NotNull(s2);
        Assert.True(w.Sessions.StartSession(s2!.Id));
        Assert.False(w.Sessions.StopSession(s2.Id, "ai-1"));
        Assert.Equal("active", w.Sessions.GetSession(s2.Id)!.State);
    }

    [Fact]
    public void Destruction_D38_F3_UnattendedStop_PersonalScopeOwner()
    {
        var enrollments = new EnrollmentService();
        var roster = new RosterService(enrollments);
        Assert.NotNull(roster.CreateScope("personal-1", "personal", "Personal"));
        Assert.NotNull(roster.CreateUser("owner", "personal-1", "Owner One", "human"));
        Assert.NotNull(roster.CreateDeviceGroup("dg-p", "personal-1", "Home", new[] { "lan" }));
        var identity = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var code = enrollments.CreateEnrollmentCode("personal", "dg-p", "Home");
        var device = enrollments.Redeem(code, new EnrollingDevice(identity.DeviceId, identity.PublicKeyBase64, "Home PC"));
        Assert.NotNull(device);
        var sessions = new SessionService(roster, enrollments);
        var s = sessions.CreateSession("personal-1", device!.DeviceId, "owner", "unattended", "lan");
        Assert.NotNull(s);
        Assert.True(sessions.StartSession(s!.Id)); // owner holds every right in personal scope
        // No company admins exist in a personal scope — the owner at
        // the machine must still be able to STOP.
        Assert.True(sessions.StopSession(s.Id, "owner"));
        Assert.Equal("ended", sessions.GetSession(s.Id)!.State);
    }

    // ---- D38 F4: removed/suspended users keep acting ------------------------------

    [Fact]
    public void Destruction_D38_F4_RemovedParticipant_ContentActsEndTheSession()
    {
        var w = Setup();
        var id = ActiveAttended(w);
        Assert.True(w.Sessions.AddParticipant(id, "peer", "watcher", "ctrl"));
        Assert.NotNull(w.Roster.RemoveUser("company-1", "peer", "admin"));
        // The next content act re-reads offboarding: the session ends
        // with participant_removed and the act itself refuses.
        Assert.Null(w.Sessions.SendChatMessage(id, "ctrl", "anyone there?"));
        var s = w.Sessions.GetSession(id)!;
        Assert.Equal("ended", s.State);
        Assert.Equal("participant_removed", s.EndReason);
        // File acts on the corpse refuse too.
        Assert.Null(w.Sessions.CreateFileJob(id, "to_host", "x.bin", 1, "ctrl"));
    }

    [Fact]
    public void Destruction_D38_F4_RemovedAcceptor_LosesHostAuthority()
    {
        var w = Setup();
        var id = ActiveAttended(w);
        Assert.NotNull(w.Roster.RemoveUser("company-1", "host", "admin"));
        // The removed acceptor's host authority is dead with the user:
        // STOP by the dead identity refuses and changes nothing.
        Assert.False(w.Sessions.StopSession(id, "host"));
        Assert.Equal("active", w.Sessions.GetSession(id)!.State);
        // The next host act re-reads offboarding (D14): the session
        // ends with participant_removed instead of being driven by —
        // or for — a removed user.
        Assert.False(w.Sessions.GrantFloor(id, "ctrl", "host"));
        var s = w.Sessions.GetSession(id)!;
        Assert.Equal("ended", s.State);
        Assert.Equal("participant_removed", s.EndReason);
    }

    [Fact]
    public void Destruction_D38_F4_SuspendedAcceptor_LosesHostAuthority()
    {
        var w = Setup();
        var id = ActiveAttended(w);
        Assert.True(w.Roster.SetUserSuspended("company-1", "host", true));
        // The suspended acceptor cannot wield host acts; the attempt
        // re-reads offboarding and the session ends (D14).
        Assert.False(w.Sessions.GrantFloor(id, "ctrl", "host"));
        var s = w.Sessions.GetSession(id)!;
        Assert.Equal("ended", s.State);
        Assert.Equal("participant_removed", s.EndReason);
        Assert.False(w.Sessions.RemoveParticipant(id, "ctrl", "host"));
    }

    // ---- D38 F5: SetRecording authorization ----------------------------------------

    [Fact]
    public void Destruction_D38_F5_SetRecording_TurnOnRequiresHostSide()
    {
        var w = Setup();
        var id = ActiveAttended(w);
        // Controller, watcher participant, outsider, anonymous: none
        // may start recording a session the host accepted as "none".
        Assert.True(w.Sessions.AddParticipant(id, "peer", "watcher", "ctrl"));
        Assert.False(w.Sessions.SetRecording(id, "video", "recordings/x.mp4", "ctrl"));
        Assert.False(w.Sessions.SetRecording(id, "video", "recordings/x.mp4", "peer"));
        Assert.False(w.Sessions.SetRecording(id, "video", "recordings/x.mp4", "outsider"));
        Assert.False(w.Sessions.SetRecording(id, "video", "recordings/x.mp4", null));
        Assert.Equal("none", w.Sessions.GetSession(id)!.Recording);
        Assert.False(w.Sessions.GetSession(id)!.IsRecording);
        // Host-side can turn it on; a participant can always turn it OFF.
        Assert.True(w.Sessions.SetRecording(id, "video", "recordings/x.mp4", "host"));
        Assert.True(w.Sessions.GetSession(id)!.IsRecording);
        Assert.True(w.Sessions.SetRecording(id, "none", null, "ctrl"));
        Assert.False(w.Sessions.GetSession(id)!.IsRecording);
    }

    [Fact]
    public void Destruction_BlockedSession_ContentActsRefuse()
    {
        var w = Setup();
        var id = ActiveAttended(w);
        var job = w.Sessions.CreateFileJob(id, "to_host", "a.bin", 10, "ctrl")!;
        Assert.True(w.Sessions.BlockSession(id, "ctrl"));
        // A blocked session is stopped-pending-end: no chat, no new
        // jobs, no progress, no recording may flow through it.
        Assert.Null(w.Sessions.SendChatMessage(id, "ctrl", "still here"));
        Assert.Null(w.Sessions.CreateFileJob(id, "to_host", "b.bin", 1, "ctrl"));
        Assert.False(w.Sessions.UpdateFileProgress(job.Id, 5, "ctrl"));
        Assert.False(w.Sessions.SetRecording(id, "video", "recordings/x.mp4", "host"));
        // The one legal exit still works.
        Assert.True(w.Sessions.EndSession(id, "host"));
        Assert.Equal("cancelled", w.Sessions.GetFileJob(job.Id)!.State);
    }

    // ---- D38 F6: recording-ref scheme tricks -----------------------------------------

    [Theory]
    [InlineData("file://server/share/rec.mp4")]        // file URI, remote host = UNC
    [InlineData("file://192.168.1.5/share/rec.mp4")]   // file URI, remote IP host
    [InlineData("FiLe://EVIL/share/rec.mp4")]          // mixed-case scheme + host
    [InlineData("\\/server/share/rec.mp4")]            // mixed-separator UNC
    [InlineData("/\\server\\share\\rec.mp4")]          // mixed-separator UNC, flipped
    [InlineData("file://evil.example.com/rec.mp4")]
    public void Destruction_D38_F6_RemoteRecordingRef_SchemeTricks_Refused(string remoteRef)
    {
        Assert.True(SessionService.IsRemoteRecordingRef(remoteRef), remoteRef);
        var w = Setup();
        Assert.Null(w.Sessions.CreateSession("company-1", w.DeviceId, "ctrl",
            "attended", "lan", "video", remoteRef));
    }

    [Fact]
    public void Destruction_D38_F6_LocalhostFileUri_StaysLocal()
    {
        Assert.False(SessionService.IsRemoteRecordingRef("file://localhost/recordings/x.mp4"));
        Assert.False(SessionService.IsRemoteRecordingRef("file:///recordings/x.mp4"));
        Assert.False(SessionService.IsRemoteRecordingRef("file://LOCALHOST/recordings/x.mp4"));
    }

    // ---- D38 F7: import restores consent/state from untrusted input ---------------------

    [Fact]
    public void Destruction_D38_F7_Import_ActiveAttendedWithoutAccept_ForcedEnded()
    {
        var w = Setup();
        var sessions = new SessionService(w.Roster, w.Enrollments);
        var json = $$"""
            {"Sessions":[
              {"Id":"s-forged","ScopeId":"company-1","HostDeviceId":"{{w.DeviceId}}","InitiatorUserId":"ctrl",
               "Kind":"attended","State":"active","StartedUtc":"2026-11-17T00:00:00Z","EndedUtc":null,
               "TransportRung":"lan","Recording":"video","RecordingRef":"recordings/x.mp4",
               "AcceptedByUserId":null,"EndReason":null}],
             "Participants":[],"Events":[],"Chat":[],"FileJobs":[]}
            """;
        sessions.ImportJson(json);
        var s = sessions.GetSession("s-forged");
        Assert.NotNull(s);
        // A live attended session with no recorded host accept is
        // unrepresentable: import repairs it to ended, never active.
        Assert.Equal("ended", s!.State);
        Assert.Equal("import_repair", s.EndReason);
        Assert.False(s.IsRecording);
    }

    [Fact]
    public void Destruction_D38_F7_Import_SelfOrAiAccept_ClearedOrEnded()
    {
        var w = Setup();
        var sessions = new SessionService(w.Roster, w.Enrollments);
        var json = $$"""
            {"Sessions":[
              {"Id":"s-self","ScopeId":"company-1","HostDeviceId":"{{w.DeviceId}}","InitiatorUserId":"ctrl",
               "Kind":"attended","State":"requested","StartedUtc":null,"EndedUtc":null,
               "TransportRung":"lan","Recording":"none","RecordingRef":null,
               "AcceptedByUserId":"ctrl","EndReason":null},
              {"Id":"s-ai","ScopeId":"company-1","HostDeviceId":"{{w.DeviceId}}","InitiatorUserId":"ctrl",
               "Kind":"attended","State":"active","StartedUtc":"2026-11-17T00:00:00Z","EndedUtc":null,
               "TransportRung":"lan","Recording":"none","RecordingRef":null,
               "AcceptedByUserId":"ai-1","EndReason":null}],
             "Participants":[],"Events":[],"Chat":[],"FileJobs":[]}
            """;
        sessions.ImportJson(json);
        // Requested + self-accept: the forged accept is cleared, the
        // session falls back to honestly-unaccepted.
        var self = sessions.GetSession("s-self")!;
        Assert.Equal("requested", self.State);
        Assert.Null(self.AcceptedByUserId);
        Assert.False(sessions.StartSession("s-self"));
        // Active + AI accept: no valid consent ever existed — ended.
        Assert.Equal("ended", sessions.GetSession("s-ai")!.State);
    }

    [Fact]
    public void Destruction_D38_F7_Import_SuspendedFloorHolder_Demoted()
    {
        var w = Setup();
        Assert.True(w.Roster.SetUserSuspended("company-1", "peer", true));
        var sessions = new SessionService(w.Roster, w.Enrollments);
        var json = $$"""
            {"Sessions":[
              {"Id":"s-floor","ScopeId":"company-1","HostDeviceId":"{{w.DeviceId}}","InitiatorUserId":"ctrl",
               "Kind":"attended","State":"requested","StartedUtc":null,"EndedUtc":null,
               "TransportRung":"lan","Recording":"none","RecordingRef":null,
               "AcceptedByUserId":null,"EndReason":null}],
             "Participants":[
              {"SessionId":"s-floor","UserId":"peer","Role":"controller","Floor":"holds"},
              {"SessionId":"s-floor","UserId":"ghost","Role":"controller","Floor":"holds"}],
             "Events":[],"Chat":[],"FileJobs":[]}
            """;
        sessions.ImportJson(json);
        var participants = sessions.ListParticipants("s-floor");
        // Suspended holder demoted; unknown user dropped entirely.
        Assert.DoesNotContain(participants, p => p.Floor == "holds");
        Assert.DoesNotContain(participants, p => p.UserId == "ghost");
    }

    // ---- D38 F8: file-job acts ------------------------------------------------------------

    [Fact]
    public void Destruction_D38_F8_FileJobs_RequireLiveParticipantAndActiveSession()
    {
        var w = Setup();
        var s = CreateAttended(w); // requested: transfers cannot start pre-start
        Assert.Null(w.Sessions.CreateFileJob(s.Id, "to_host", "x.bin", 1, "ctrl"));
        Assert.True(w.Sessions.AcceptSession(s.Id, "host", SessionAcceptOrigin.EndpointLocal));
        Assert.True(w.Sessions.StartSession(s.Id));
        // Non-participant and anonymous actors cannot create jobs.
        Assert.Null(w.Sessions.CreateFileJob(s.Id, "to_host", "x.bin", 1, "outsider"));
        Assert.Null(w.Sessions.CreateFileJob(s.Id, "to_host", "x.bin", 1, null));
        var job = w.Sessions.CreateFileJob(s.Id, "to_host", "x.bin", 10, "ctrl");
        Assert.NotNull(job);
        // Progress/state acts by a non-participant refuse.
        Assert.True(w.Sessions.SetFileJobState(job!.Id, "active", "ctrl"));
        Assert.False(w.Sessions.UpdateFileProgress(job.Id, 5, "outsider"));
        Assert.False(w.Sessions.SetFileJobState(job.Id, "failed", "outsider"));
        Assert.Equal(0, w.Sessions.GetFileJob(job.Id)!.TransferredBytes);
        // Pausing the session freezes the job: no progress, no done.
        Assert.True(w.Sessions.PauseSession(s.Id, "ctrl"));
        Assert.False(w.Sessions.UpdateFileProgress(job.Id, 5, "ctrl"));
        Assert.True(w.Sessions.ResumeSession(s.Id, "ctrl"));
        Assert.True(w.Sessions.UpdateFileProgress(job.Id, 10, "ctrl"));
        Assert.True(w.Sessions.SetFileJobState(job.Id, "done", "ctrl"));
    }

    // ---- D38 F9: transition authorization ----------------------------------------------------

    [Fact]
    public void Destruction_D38_F9_NonParticipant_CannotDriveTransitions()
    {
        var w = Setup();
        var id = ActiveAttended(w);
        Assert.False(w.Sessions.PauseSession(id, "outsider"));
        Assert.Equal("active", w.Sessions.GetSession(id)!.State);
        Assert.True(w.Sessions.PauseSession(id, "host")); // host participant pauses
        // A non-participant cannot resume what the host paused, and a
        // stranger cannot end the session with a forged actor string.
        Assert.False(w.Sessions.ResumeSession(id, "outsider"));
        Assert.False(w.Sessions.ResumeSession(id, "ghost"));
        Assert.False(w.Sessions.EndSession(id, "outsider"));
        Assert.Equal("paused", w.Sessions.GetSession(id)!.State);
        Assert.True(w.Sessions.ResumeSession(id, "ctrl")); // participant resumes
        Assert.True(w.Sessions.EndSession(id, "ctrl"));
    }

    // ---- D38 F10: device revoked between create and start ---------------------------------------

    [Fact]
    public void Destruction_D38_F10_DeviceRevokedBetweenCreateAndStart_StartRefused()
    {
        var w = Setup();
        var s = CreateAttended(w);
        Assert.True(w.Sessions.AcceptSession(s.Id, "host", SessionAcceptOrigin.EndpointLocal));
        Assert.True(w.Enrollments.Revoke(w.DeviceId));
        Assert.False(w.Sessions.StartSession(s.Id));
        Assert.Equal("requested", w.Sessions.GetSession(s.Id)!.State);
        // Unattended path refuses too.
        var w2 = Setup();
        var u = w2.Sessions.CreateSession("company-1", w2.DeviceId, "ctrl", "unattended", "lan");
        Assert.NotNull(u);
        Assert.True(w2.Enrollments.Revoke(w2.DeviceId));
        Assert.False(w2.Sessions.StartSession(u!.Id));
        Assert.Equal("requested", w2.Sessions.GetSession(u.Id)!.State);
    }

    [Fact]
    public void Destruction_UnattendedGrantDroppedBetweenCreateAndStart_StartRefused()
    {
        var w = Setup();
        var s = w.Sessions.CreateSession("company-1", w.DeviceId, "ctrl", "unattended", "lan");
        Assert.NotNull(s);
        Assert.True(w.Roster.RemoveGrant("company-1", "ug-1", "dg-1", "admin"));
        Assert.False(w.Sessions.StartSession(s!.Id));
        Assert.Equal("requested", w.Sessions.GetSession(s.Id)!.State);
    }

    // ---- D38 F11 (model half): restart reconciliation ------------------------------------------------

    [Fact]
    public void Destruction_D38_F11_RestartReconciliation_EndsRestoredLiveSessions()
    {
        var w = Setup();
        var id = ActiveAttended(w);
        var job = w.Sessions.CreateFileJob(id, "to_host", "a.bin", 10, "ctrl")!;
        var restored = new SessionService(w.Roster, w.Enrollments);
        restored.ImportJson(w.Sessions.ExportJson());
        Assert.Equal("active", restored.GetSession(id)!.State); // as persisted
        // A Core restart leaves nothing live behind a restored session:
        // reconciliation ends it with the named reason, jobs cascade.
        Assert.Equal(1, restored.ReconcileAfterRestart());
        var s = restored.GetSession(id)!;
        Assert.Equal("ended", s.State);
        Assert.Equal("core_restart", s.EndReason);
        Assert.Equal("cancelled", restored.GetFileJob(job.Id)!.State);
        Assert.Equal(0, restored.ReconcileAfterRestart()); // idempotent
    }

    // ---- D38 F12: floor recipient liveness + import idempotence -----------------------------------------

    [Fact]
    public void Destruction_D38_F12_TakeFloorBack_SuspendedHost_Refused()
    {
        var w = Setup();
        var id = ActiveAttended(w);
        Assert.True(w.Sessions.GrantFloor(id, "ctrl", "host"));
        Assert.True(w.Roster.SetUserSuspended("company-1", "host", true));
        // The floor cannot be handed to a suspended host participant.
        Assert.False(w.Sessions.TakeFloorBack(id, "admin"));
        var holder = Assert.Single(w.Sessions.ListParticipants(id).Where(p => p.Floor == "holds"));
        Assert.Equal("ctrl", holder.UserId); // floor unmoved
    }

    [Fact]
    public void Destruction_D38_F12_DoubleImport_DoesNotDuplicateEventsOrChat()
    {
        var w = Setup();
        var id = ActiveAttended(w);
        Assert.NotNull(w.Sessions.SendChatMessage(id, "ctrl", "hello"));
        var json = w.Sessions.ExportJson();
        var events = w.Sessions.ListEvents(id).Count;
        var chat = w.Sessions.ListChat(id).Count;
        // Re-importing the same file into the same store (crash loop,
        // operator error) must not replay history a second time.
        w.Sessions.ImportJson(json);
        Assert.Equal(events, w.Sessions.ListEvents(id).Count);
        Assert.Equal(chat, w.Sessions.ListChat(id).Count);
        Assert.Equal(2, w.Sessions.ListParticipants(id).Count);
    }

    // ---- persistence corruption barrage (all stores, Slice 3 side) -----------------------------------------

    [Fact]
    public void Destruction_SessionsImport_CorruptBarrage_NeverThrowsNeverResurrects()
    {
        var w = Setup();
        var sessions = new SessionService(w.Roster, w.Enrollments);
        foreach (var junk in new[]
                 {
                     "", "null", "[]", "{}", "{not json",
                     "{\"Sessions\":null}",
                     "{\"Sessions\":[{\"Id\":\"x\"}]}",
                     "{\"Sessions\":[],\"Participants\":null,\"Events\":null,\"Chat\":null,\"FileJobs\":null}",
                 })
        {
            try { sessions.ImportJson(junk); }
            catch (Exception ex) { Assert.Fail($"ImportJson threw on corrupt input: {ex.GetType().Name}"); }
        }
        Assert.Empty(sessions.ListSessions());
    }
}

// ---------------------------------------------------------------- D38 reconciliation (S1-WIN / S2-WIN packets)

public class DestructionD38S1ReconciliationTests
{
    private static EnrollingDevice AsEnrolling(DeviceIdentity id, string name = "Device") =>
        new(id.DeviceId, id.PublicKeyBase64, name);

    private static byte[] IdentityKey() { var k = new byte[32]; k[0] = 0x01; return k; }

    [Fact]
    public void Destruction_D38S1_F2_IdentityPointKey_ForgedSignature_Refused()
    {
        // Public key 0x01||0x00*31 is the identity point. Pre-fix, the
        // forged signature (R = [1]B, S = 1) verifies for EVERY message
        // because [k]A is the identity: [S]B == R + [k]A holds trivially.
        var identityKey = new byte[32]; identityKey[0] = 0x01;
        var forged = new byte[64];
        Convert.FromHexString("5866666666666666666666666666666666666666666666666666666666666666")
            .CopyTo(forged, 0); // R = base point encoding ([1]B)
        forged[32] = 0x01; // S = 1
        var msg = Encoding.UTF8.GetBytes("transfer the fleet");
        Assert.False(Ed25519.Verify(identityKey, msg, forged));
        Assert.False(Ed25519.Verify(identityKey, Encoding.UTF8.GetBytes("anything else"), forged));
    }

    [Fact]
    public void Destruction_D38S1_F2_SmallOrderKeys_RedeemRefused_CodeNotConsumed()
    {
        var svc = new EnrollmentService();
        var badKeys = new[]
        {
            new byte[32], // all-zero encoding: order-4 point
            IdentityKey(), // identity point encoding
        };
        foreach (var badKey in badKeys)
        {
            var code = svc.CreateEnrollmentCode("company", "company-a", "Company A");
            var deviceId = Ed25519.ComputeDeviceId(badKey);
            Assert.Null(svc.Redeem(code,
                new EnrollingDevice(deviceId, Convert.ToBase64String(badKey), "Forged Device")));
            // The failed attempt must not consume the code.
            var legit = new DeviceIdentity(new DevOnlyPassThroughProtector());
            Assert.NotNull(svc.Redeem(code, AsEnrolling(legit)));
        }
    }

    [Fact]
    public async Task Destruction_D38S1_F3_CorruptIdentityFile_PreservedAndRotated_NotOverwritten()
    {
        var dir = TestUtil.TempDir();
        var identityPath = Path.Combine(dir, "device-identity.txt");
        File.WriteAllText(identityPath, "GARBAGE-NOT-A-PROTECTED-SEED");
        CoreOptions Options() => new()
        {
            DataDir = dir, Port = 18799, Protector = new DevOnlyPassThroughProtector(),
            Probe = new FakeProbe(), FactChecks = new FakeFactChecks(),
        };
        var runtime = new CoreRuntime(Options());
        // The corrupt original is preserved byte-for-byte, not destroyed.
        var preserved = Directory.GetFiles(dir, "device-identity.corrupt-*");
        Assert.Single(preserved);
        Assert.Equal("GARBAGE-NOT-A-PROTECTED-SEED", File.ReadAllText(preserved[0]));
        // A fresh identity was persisted atomically and is stable.
        Assert.True(DeviceIdentity.TryImportProtectedSeed(new DevOnlyPassThroughProtector(),
            File.ReadAllText(identityPath), out var restored));
        Assert.Equal(runtime.Identity.DeviceId, restored!.DeviceId);
        // W95 / FR-124 amendment: the second runtime is a RESTART,
        // so the first stops first — the single-instance guard
        // refuses a second LIVE Core on the same data dir (defect
        // D-W93-1's fix). The pin's substance is unchanged: the
        // rotated identity is stable across a restart.
        await runtime.StopAsync(default);
        await runtime.DisposeAsync();
        var runtime2 = new CoreRuntime(Options());
        Assert.Equal(runtime.Identity.DeviceId, runtime2.Identity.DeviceId);
        await runtime2.StopAsync(default);
        await runtime2.DisposeAsync();
        Assert.Single(Directory.GetFiles(dir, "device-identity.corrupt-*"));
        // The rotation reached the audit log (device id only, never seed).
        var auditText = File.ReadAllText(Path.Combine(dir, "audit", "audit.jsonl"));
        Assert.Contains("identity_rotated", auditText);
        Assert.Contains(runtime.Identity.DeviceId, auditText);
    }

    [Fact]
    public void Destruction_D38S1_F4_RecordReceipt_ConcurrentBarrage_ExportsAlwaysParse()
    {
        var svc = new EnrollmentService();
        var exports = 0;
        svc.Changed += () =>
        {
            // The persistence handler's view: every snapshot it is asked
            // to write must be one consistent, parseable export.
            using var doc = JsonDocument.Parse(svc.ExportJson());
            Interlocked.Increment(ref exports);
        };
        Parallel.For(0, 200, i =>
            svc.RecordReceipt($"Enroller {i}", $"enroller-{i}", "company", "Fleet"));
        Assert.Equal(200, svc.ListReceipts().Count);
        Assert.Equal(200, exports);
    }

    [Fact]
    public void Destruction_D38S1_F9_PublicKeyMutation_DoesNotAlterIdentity()
    {
        var identity = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var originalB64 = identity.PublicKeyBase64;
        var originalId = identity.DeviceId;
        var leaked = identity.PublicKey;
        leaked[0] ^= 0xFF; leaked[10] ^= 0xFF; // caller scribbles on the returned array
        Assert.Equal(originalB64, identity.PublicKeyBase64);
        Assert.Equal(originalId, identity.DeviceId);
        var msg = Encoding.UTF8.GetBytes("proof");
        Assert.True(Ed25519.Verify(Convert.FromBase64String(originalB64), msg, identity.Sign(msg)));
    }

    [Fact]
    public void Destruction_D38S1_F10_HugeTtl_DoesNotThrow()
    {
        var svc = new EnrollmentService();
        var identity = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var code = svc.CreateEnrollmentCode("company", "company-a", "Company A", TimeSpan.MaxValue);
        Assert.NotNull(svc.Redeem(code, AsEnrolling(identity)));
    }

    [Fact]
    public void Destruction_D38S1_F10_InjectedClock_ControlsExpiry()
    {
        var clock = new FakeClock();
        var svc = new EnrollmentService(clock);
        var identity = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var live = svc.CreateEnrollmentCode("company", "company-a", "Company A", TimeSpan.FromMinutes(10));
        Assert.NotNull(svc.Redeem(live, AsEnrolling(identity)));
        var dying = svc.CreateEnrollmentCode("company", "company-a", "Company A", TimeSpan.FromMinutes(10));
        clock.Advance(TimeSpan.FromMinutes(11));
        Assert.Null(svc.Redeem(dying, AsEnrolling(identity)));
    }

    [Fact]
    public void Destruction_D38S1_F12_DisplayName_HostileValues_Refused_CodeNotConsumed()
    {
        var svc = new EnrollmentService();
        var identity = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var code = svc.CreateEnrollmentCode("company", "company-a", "Company A");
        Assert.Null(svc.Redeem(code, AsEnrolling(identity, new string('x', 200))));
        Assert.Null(svc.Redeem(code, AsEnrolling(identity, "BadName")));
        Assert.Null(svc.Redeem(code, AsEnrolling(identity, "Evil‮Name")));
        Assert.NotNull(svc.Redeem(code, AsEnrolling(identity, "Honest Device")));
    }
}

public class DestructionD38S2ReconciliationTests
{
    private sealed class World
    {
        public required EnrollmentService Enrollments { get; init; }
        public required RosterService Roster { get; init; }
    }

    private static World Setup()
    {
        var enrollments = new EnrollmentService();
        var roster = new RosterService(enrollments);
        Assert.NotNull(roster.CreateScope("personal-1", "personal", "Personal"));
        Assert.NotNull(roster.CreateScope("company-1", "company", "Company A"));
        Assert.NotNull(roster.CreateScope("company-2", "company", "Other Co"));
        Assert.NotNull(roster.CreateUser("owner", "personal-1", "Owner", "human"));
        Assert.NotNull(roster.CreateUser("admin-a", "company-1", "Admin A", "human"));
        Assert.NotNull(roster.CreateUser("admin-b", "company-1", "Admin B", "human"));
        Assert.NotNull(roster.CreateUser("target", "company-1", "Target", "human"));
        Assert.NotNull(roster.CreateUser("member", "company-1", "Member", "human"));
        Assert.True(roster.AddCompanyAdmin("company-1", "admin-a"));
        Assert.True(roster.AddCompanyAdmin("company-1", "admin-b"));
        Assert.NotNull(roster.CreateUserGroup("ug-1", "company-1", "Techs",
            new[] { "target", "member" }, new[] { "target" }));
        Assert.NotNull(roster.CreateDeviceGroup("dg-1", "company-1", "Fleet", new[] { "lan", "hub" }));
        Assert.NotNull(roster.CreateDeviceGroup("dg-p", "personal-1", "Home", new[] { "lan" }));
        Assert.NotNull(roster.AddGrant("company-1", "ug-1", "dg-1", new[] { "use", "enroll" }));
        return new World { Enrollments = enrollments, Roster = roster };
    }

    private static EnrolledDevice Enroll(World w, string scope, string groupId, string groupName, string name)
    {
        var identity = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var code = w.Enrollments.CreateEnrollmentCode(scope, groupId, groupName);
        var device = w.Enrollments.Redeem(code, new EnrollingDevice(identity.DeviceId, identity.PublicKeyBase64, name));
        Assert.NotNull(device);
        return device!;
    }

    [Fact]
    public void Destruction_D38S2_F2_DeletedDeviceGroupId_CannotBeReusedToCaptureDevices()
    {
        var w = Setup();
        Assert.NotNull(w.Roster.CreateDeviceGroup("dg-x", "company-1", "Temp Fleet", new[] { "lan" }));
        var device = Enroll(w, "company", "dg-x", "Temp Fleet", "Orphan PC");
        Assert.True(w.Roster.DeleteDeviceGroup("company-1", "dg-x", "admin-a"));
        // Re-creating the id in ANY scope (or the same one) must refuse:
        // the orphaned enrollment still carries the bare id.
        Assert.Null(w.Roster.CreateDeviceGroup("dg-x", "company-2", "Capture Fleet"));
        Assert.Null(w.Roster.CreateDeviceGroup("dg-x", "company-1", "Capture Fleet"));
        Assert.DoesNotContain(w.Roster.OperatorRoster("company-2")!.Devices, d => d.DeviceId == device.DeviceId);
        // The tombstone survives persistence.
        var restored = new RosterService(new EnrollmentService());
        restored.ImportJson(w.Roster.ExportJson());
        Assert.Null(restored.CreateDeviceGroup("dg-x", "company-2", "Capture Fleet"));
    }

    [Fact]
    public void Destruction_D38S2_F3_DeleteDevice_UnknownGroup_FailsClosed()
    {
        var w = Setup();
        var device = Enroll(w, "company", "ghost-group", "Ghost", "Orphan PC");
        // No device group owns this device: no caller-supplied scope may
        // authorize its deletion (personal owner OR company admin).
        Assert.False(w.Roster.DeleteDevice("personal-1", device.DeviceId, "owner"));
        Assert.False(w.Roster.DeleteDevice("company-1", device.DeviceId, "admin-a"));
        Assert.False(w.Enrollments.List().Single().Revoked);
    }

    [Fact]
    public void Destruction_D38S2_F4_RecordMintedEnrollment_CrossScopeDevice_Refused()
    {
        var w = Setup();
        var personalDevice = Enroll(w, "personal", "dg-p", "Home", "Home PC");
        // A company user cannot claim attribution for a personal-scope
        // device — that attribution is what offboarding revokes by.
        Assert.False(w.Roster.RecordMintedEnrollment("company-1", "target", personalDevice.DeviceId));
        Assert.Empty(w.Roster.ListMintedEnrollments("company-1"));
        // Unknown devices are refused too (when an enrollment store exists).
        Assert.False(w.Roster.RecordMintedEnrollment("company-1", "target", "no-such-device"));
        // Same-scope attribution still works.
        var companyDevice = Enroll(w, "company", "dg-1", "Fleet", "Fleet PC");
        Assert.True(w.Roster.RecordMintedEnrollment("company-1", "target", companyDevice.DeviceId));
    }

    [Fact]
    public void Destruction_D38S2_F4_ForgedImportedAttribution_OffboardingCannotRevokeCrossScopeDevice()
    {
        var w = Setup();
        var personalDevice = Enroll(w, "personal", "dg-p", "Home", "Home PC");
        // Hand-forged roster file: company target "minted" the personal device.
        var json = $$"""
        {
          "Scopes": [{"Id":"company-1","Kind":"company","Name":"Company A","TransportCeiling":null}],
          "Users": [
            {"Id":"admin-a","ScopeId":"company-1","DisplayName":"Admin A","Kind":"human","PairedByUserId":null,"Suspended":false},
            {"Id":"target","ScopeId":"company-1","DisplayName":"Target","Kind":"human","PairedByUserId":null,"Suspended":false}
          ],
          "CompanyAdmins": [{"ScopeId":"company-1","UserId":"admin-a"}],
          "UserGroups": [], "DeviceGroups": [], "Grants": [],
          "Minted": [{"ScopeId":"company-1","MintedByUserId":"target","DeviceId":"{{personalDevice.DeviceId}}"}],
          "Events": []
        }
        """;
        var forged = new RosterService(w.Enrollments);
        forged.ImportJson(json);
        Assert.NotNull(forged.RemoveUser("company-1", "target", "admin-a", stepUp: true));
        Assert.False(w.Enrollments.List().Single(d => d.DeviceId == personalDevice.DeviceId).Revoked);
    }

    [Fact]
    public void Destruction_D38S2_F5_LastLiveAdminGuards_CountOnlyLiveAdmins()
    {
        var w = Setup();
        Assert.True(w.Roster.SetUserSuspended("company-1", "admin-b", true));
        // admin-b's seat exists on paper but is not live. admin-a is the
        // sole LIVE admin: neither removal path may strand the scope.
        Assert.False(w.Roster.RemoveCompanyAdmin("company-1", "admin-a", "admin-a", stepUp: true));
        Assert.Null(w.Roster.RemoveUser("company-1", "admin-a", "admin-a", stepUp: true));
        Assert.NotNull(w.Roster.GetUser("company-1", "admin-a"));
        Assert.True(w.Roster.IsCompanyAdmin("company-1", "admin-a"));
        // And the live admin can still work: unsuspend the peer.
        Assert.True(w.Roster.SetUserSuspended("company-1", "admin-b", false));
        Assert.True(w.Roster.RemoveCompanyAdmin("company-1", "admin-b", "admin-a", stepUp: true));
    }

    [Fact]
    public void Destruction_D38S2_F1_SuspendingSoleLiveAdmin_Refused_AndSuspensionIsEvented()
    {
        var w = Setup();
        Assert.NotNull(w.Roster.CreateUser("solo", "company-2", "Solo Admin", "human"));
        Assert.True(w.Roster.AddCompanyAdmin("company-2", "solo"));
        // Suspending the only live admin would lock the scope with no
        // step-up and (pre-fix) no event — the last-admin guard's twin.
        Assert.False(w.Roster.SetUserSuspended("company-2", "solo", true));
        Assert.False(w.Roster.GetUser("company-2", "solo")!.Suspended);
        // An ordinary suspension still works and is audit-shaped.
        Assert.True(w.Roster.SetUserSuspended("company-1", "member", true));
        Assert.Contains(w.Roster.ListEvents("company-1"),
            e => e.Kind == "user_suspended" && e.SubjectId == "member");
    }

    [Fact]
    public void Destruction_D38S2_F6_EndpointView_RevokedDevice_ReturnsNull()
    {
        var w = Setup();
        var device = Enroll(w, "company", "dg-1", "Fleet", "Fleet PC");
        Assert.NotNull(w.Roster.EndpointView(device.DeviceId));
        Assert.True(w.Enrollments.Revoke(device.DeviceId));
        Assert.Null(w.Roster.EndpointView(device.DeviceId));
    }

    [Fact]
    public void Destruction_D38S2_F7_ControlCharIdsRefused_AndPersonalScopeHasOneHuman()
    {
        var w = Setup();
        Assert.Null(w.Roster.CreateUser("bad\nid", "company-1", "Bad", "human"));
        Assert.Null(w.Roster.CreateScope("bad\nscope", "company", "Bad"));
        Assert.Null(w.Roster.CreateUserGroup("bad\ngroup", "company-1", "Bad"));
        Assert.Null(w.Roster.CreateDeviceGroup("bad\ngroup", "company-1", "Bad"));
        // Personal scope: the owner is the SOLE human (Slice 2 spec);
        // a second human would also be an admin there by IsScopeAdmin.
        Assert.Null(w.Roster.CreateUser("second-human", "personal-1", "Second", "human"));
        // An AI paired by the owner is not a second human user.
        Assert.NotNull(w.Roster.CreateUser("ai-p", "personal-1", "Helper", "ai", pairedByUserId: "owner"));
    }

    [Fact]
    public void Destruction_D38S2_F8_EmptyCeiling_Refused_NullStillClears()
    {
        var w = Setup();
        Assert.True(w.Roster.SetScopeTransportCeiling("company-1", new[] { "lan" }));
        // [] must not silently clear the cap into "all rungs allowed".
        Assert.False(w.Roster.SetScopeTransportCeiling("company-1", Array.Empty<string>()));
        Assert.Equal(new[] { "lan" }, w.Roster.GetScopeTransportCeiling("company-1"));
        Assert.True(w.Roster.SetScopeTransportCeiling("company-1", null));
        Assert.Null(w.Roster.GetScopeTransportCeiling("company-1"));
    }

    [Fact]
    public void Destruction_D38S2_F9_Import_AiBeforeOwner_Restored_AndGhostMintedDropped()
    {
        const string json = """
        {
          "Scopes": [{"Id":"company-1","Kind":"company","Name":"Company A","TransportCeiling":null}],
          "Users": [
            {"Id":"ai-1","ScopeId":"company-1","DisplayName":"Agent","Kind":"ai","PairedByUserId":"boss","Suspended":false},
            {"Id":"boss","ScopeId":"company-1","DisplayName":"Boss","Kind":"human","PairedByUserId":null,"Suspended":false}
          ],
          "CompanyAdmins": [{"ScopeId":"company-1","UserId":"boss"}],
          "UserGroups": [], "DeviceGroups": [], "Grants": [],
          "Minted": [
            {"ScopeId":"company-1","MintedByUserId":"ghost","DeviceId":"dev-ghost"},
            {"ScopeId":"company-1","MintedByUserId":"boss","DeviceId":"dev-real"}
          ],
          "Events": []
        }
        """;
        var restored = new RosterService(new EnrollmentService());
        restored.ImportJson(json);
        var ai = restored.GetUser("company-1", "ai-1");
        Assert.NotNull(ai);
        Assert.Equal("boss", ai!.PairedByUserId);
        var minted = restored.ListMintedEnrollments("company-1");
        Assert.Single(minted);
        Assert.Equal("dev-real", minted[0].DeviceId);
    }

    [Fact]
    public void Destruction_D38S2_F10_RemoveUser_WithoutEnrollmentStore_KeepsMintedEvidence()
    {
        var roster = new RosterService(); // no enrollment store wired
        Assert.NotNull(roster.CreateScope("company-1", "company", "Company A"));
        Assert.NotNull(roster.CreateUser("admin", "company-1", "Admin", "human"));
        Assert.NotNull(roster.CreateUser("target", "company-1", "Target", "human"));
        Assert.True(roster.AddCompanyAdmin("company-1", "admin"));
        Assert.True(roster.RecordMintedEnrollment("company-1", "target", "device-xyz"));
        var blast = roster.RemoveUser("company-1", "target", "admin", stepUp: true);
        Assert.NotNull(blast);
        // Nothing could be revoked (no store): the attribution must NOT
        // be deleted as if the revocation had fired.
        Assert.Single(roster.ListMintedEnrollments("company-1"));
    }

    [Fact]
    public void Destruction_D38S2_F12_ConcurrentTransportChanges_EffectiveNeverWidens()
    {
        var w = Setup();
        var device = Enroll(w, "company", "dg-1", "Fleet", "Race PC");
        Parallel.For(0, 200, i =>
        {
            switch (i % 3)
            {
                case 0: w.Roster.UpdateDeviceTransportPolicy(device.DeviceId, "manual", new[] { "hub" }); break;
                case 1: w.Roster.SetGroupTransports("company-1", "dg-1", new[] { "lan", "hub" }, "admin-a"); break;
                default: w.Roster.SetScopeTransportCeiling("company-1", new[] { "lan", "hub" }); break;
            }
        });
        var effective = w.Roster.EffectiveTransportsForDevice(device.DeviceId);
        Assert.NotNull(effective);
        Assert.All(effective!, r => Assert.Contains(r, new[] { "lan", "hub" }));
    }
}

// ---------------------------------------------------------------- Endpoint-local acceptance (RULINGS — 2026-11-19)

/// <summary>Endpoint-local acceptance (project ruling, 2026-11-19,
/// resolving DG-FIND-05): AcceptSession honors ONLY accept events
/// originating from the endpoint host's local UI; accepts over the
/// initiating channel refuse in EVERY scope; the unattended-grant
/// path is unchanged. Both directions are proven, in both scope
/// kinds, with identical structure.</summary>
public class DestructionEndpointLocalAcceptanceTests
{
    private sealed class World
    {
        public required EnrollmentService Enrollments { get; init; }
        public required RosterService Roster { get; init; }
        public required SessionService Sessions { get; init; }
        public required string CompanyDeviceId { get; init; }
        public required string PersonalDeviceId { get; init; }
    }

    private static World Setup()
    {
        var enrollments = new EnrollmentService();
        var roster = new RosterService(enrollments);
        Assert.NotNull(roster.CreateScope("personal-1", "personal", "Personal"));
        Assert.NotNull(roster.CreateScope("company-1", "company", "Company A"));
        Assert.NotNull(roster.CreateUser("owner", "personal-1", "Owner", "human"));
        Assert.NotNull(roster.CreateUser("admin", "company-1", "Admin", "human"));
        Assert.True(roster.AddCompanyAdmin("company-1", "admin"));
        Assert.NotNull(roster.CreateUser("host", "company-1", "Host User", "human"));
        Assert.NotNull(roster.CreateUser("ctrl", "company-1", "Controller", "human"));
        Assert.NotNull(roster.CreateUser("ai-1", "company-1", "Agent One", "ai", pairedByUserId: "admin"));
        Assert.NotNull(roster.CreateUserGroup("ug-1", "company-1", "Techs",
            new[] { "ctrl", "host", "ai-1" }));
        Assert.NotNull(roster.CreateDeviceGroup("dg-1", "company-1", "Fleet", new[] { "lan", "hub" }));
        Assert.NotNull(roster.CreateDeviceGroup("dg-p", "personal-1", "Home", new[] { "lan" }));
        Assert.NotNull(roster.AddGrant("company-1", "ug-1", "dg-1", new[] { "use" }));

        string Enroll(string scope, string groupId, string groupName, string name)
        {
            var identity = new DeviceIdentity(new DevOnlyPassThroughProtector());
            var code = enrollments.CreateEnrollmentCode(scope, groupId, groupName);
            var device = enrollments.Redeem(code,
                new EnrollingDevice(identity.DeviceId, identity.PublicKeyBase64, name));
            Assert.NotNull(device);
            return device!.DeviceId;
        }

        return new World
        {
            Enrollments = enrollments,
            Roster = roster,
            Sessions = new SessionService(roster, enrollments),
            CompanyDeviceId = Enroll("company", "dg-1", "Fleet", "Site PC"),
            PersonalDeviceId = Enroll("personal", "dg-p", "Home", "Home PC"),
        };
    }

    [Fact]
    public void EndpointLocal_PersonalScope_SoleUser_CanAcceptLocally_AndStart()
    {
        // (a) The DG-FIND-05 case itself: a one-user personal scope,
        // where the sole user is necessarily the initiator. Under the
        // F1-era rule no valid acceptor existed; under the ruling the
        // endpoint-local accept IS the consent.
        var w = Setup();
        var s = w.Sessions.CreateSession("personal-1", w.PersonalDeviceId, "owner", "attended", "lan");
        Assert.NotNull(s);
        Assert.True(w.Sessions.AcceptSession(s!.Id, "owner", SessionAcceptOrigin.EndpointLocal));
        var accepted = w.Sessions.GetSession(s.Id)!;
        Assert.Equal("owner", accepted.AcceptedByUserId);
        Assert.Equal(SessionService.AcceptOriginEndpointLocal, accepted.AcceptOrigin);
        // The audit/event record states the locality honestly:
        // "accepted at <device>, locally", not "accepted by <user>".
        var evt = w.Sessions.ListEvents(s.Id).Single(e => e.Kind == "accepted");
        Assert.Equal($"Accepted at {w.PersonalDeviceId}, locally.", evt.Detail);
        Assert.Equal("owner", evt.ActorUserId);
        // The acceptor is the host participant, and the session starts.
        Assert.Contains(w.Sessions.ListParticipants(s.Id),
            p => p.UserId == "owner" && p.Role == "host");
        Assert.True(w.Sessions.StartSession(s.Id));
        Assert.Equal("active", w.Sessions.GetSession(s.Id)!.State);
    }

    [Fact]
    public void EndpointLocal_ChannelAccept_RefusedInEveryScope()
    {
        // (b) The same accepts attempted over the initiating channel
        // refuse — personal and company alike, whoever sends them.
        var w = Setup();
        var personal = w.Sessions.CreateSession("personal-1", w.PersonalDeviceId, "owner", "attended", "lan");
        Assert.NotNull(personal);
        Assert.False(w.Sessions.AcceptSession(personal!.Id, "owner", SessionAcceptOrigin.InitiatingChannel));
        Assert.Null(w.Sessions.GetSession(personal.Id)!.AcceptedByUserId);
        Assert.False(w.Sessions.StartSession(personal.Id));

        var company = w.Sessions.CreateSession("company-1", w.CompanyDeviceId, "ctrl", "attended", "lan");
        Assert.NotNull(company);
        Assert.False(w.Sessions.AcceptSession(company!.Id, "ctrl", SessionAcceptOrigin.InitiatingChannel));
        Assert.False(w.Sessions.AcceptSession(company.Id, "host", SessionAcceptOrigin.InitiatingChannel));
        Assert.False(w.Sessions.AcceptSession(company.Id, "admin", SessionAcceptOrigin.InitiatingChannel));
        Assert.Null(w.Sessions.GetSession(company.Id)!.AcceptedByUserId);
        Assert.Equal("requested", w.Sessions.GetSession(company.Id)!.State);
    }

    [Fact]
    public void EndpointLocal_CompanyScope_LocalAccept_SameStructureAsPersonal()
    {
        // (c) Company scope behaves identically in structure: channel
        // refuses (proven above), endpoint-local accepts, origin is
        // recorded, the acceptor becomes the host participant.
        var w = Setup();
        var s = w.Sessions.CreateSession("company-1", w.CompanyDeviceId, "ctrl", "attended", "lan");
        Assert.NotNull(s);
        Assert.True(w.Sessions.AcceptSession(s!.Id, "host", SessionAcceptOrigin.EndpointLocal));
        var accepted = w.Sessions.GetSession(s.Id)!;
        Assert.Equal("host", accepted.AcceptedByUserId);
        Assert.Equal(SessionService.AcceptOriginEndpointLocal, accepted.AcceptOrigin);
        var evt = w.Sessions.ListEvents(s.Id).Single(e => e.Kind == "accepted");
        Assert.Equal($"Accepted at {w.CompanyDeviceId}, locally.", evt.Detail);
        Assert.Contains(w.Sessions.ListParticipants(s.Id),
            p => p.UserId == "host" && p.Role == "host");
        // Exactly one accept exists: a second local accept refuses.
        Assert.False(w.Sessions.AcceptSession(s.Id, "admin", SessionAcceptOrigin.EndpointLocal));
        Assert.True(w.Sessions.StartSession(s.Id));
    }

    [Fact]
    public void EndpointLocal_AiAndSuspendedHuman_CannotAcceptLocally()
    {
        // Locality is necessary, not sufficient: the acceptor must be
        // a live HUMAN of the scope. An AI has no presence at the
        // local UI; a suspended user consents to nothing.
        var w = Setup();
        var s = w.Sessions.CreateSession("company-1", w.CompanyDeviceId, "ctrl", "attended", "lan");
        Assert.NotNull(s);
        Assert.False(w.Sessions.AcceptSession(s!.Id, "ai-1", SessionAcceptOrigin.EndpointLocal));
        Assert.True(w.Roster.SetUserSuspended("company-1", "host", true));
        Assert.False(w.Sessions.AcceptSession(s.Id, "host", SessionAcceptOrigin.EndpointLocal));
        Assert.Null(w.Sessions.GetSession(s.Id)!.AcceptedByUserId);
    }

    [Fact]
    public void EndpointLocal_UnattendedGrantPath_Unchanged()
    {
        // The ruling leaves the unattended path exactly as it was:
        // no accept gate on either origin (AcceptSession refuses —
        // there is nothing to accept), and the initiator's `use`
        // grant is the consent, checked at start.
        var w = Setup();
        var s = w.Sessions.CreateSession("company-1", w.CompanyDeviceId, "ctrl", "unattended", "lan");
        Assert.NotNull(s);
        Assert.False(w.Sessions.AcceptSession(s!.Id, "host", SessionAcceptOrigin.EndpointLocal));
        Assert.False(w.Sessions.AcceptSession(s.Id, "host", SessionAcceptOrigin.InitiatingChannel));
        Assert.True(w.Sessions.StartSession(s.Id));
        Assert.Equal("active", w.Sessions.GetSession(s.Id)!.State);
    }

    [Fact]
    public void EndpointLocal_Import_ChannelAcceptNeverCounts_LocalSelfAcceptCounts()
    {
        // Import re-validation speaks the ruling's language: a stored
        // "initiating_channel" accept is no consent (live session
        // repaired to ended), while a stored "endpoint_local" accept
        // BY THE INITIATOR is valid consent (the personal-scope form).
        var w = Setup();
        var sessions = new SessionService(w.Roster, w.Enrollments);
        var json = $$"""
            {"Sessions":[
              {"Id":"s-channel","ScopeId":"company-1","HostDeviceId":"{{w.CompanyDeviceId}}","InitiatorUserId":"ctrl",
               "Kind":"attended","State":"active","StartedUtc":"2026-11-19T00:00:00Z","EndedUtc":null,
               "TransportRung":"lan","Recording":"none","RecordingRef":null,
               "AcceptedByUserId":"host","EndReason":null,"AcceptOrigin":"initiating_channel"},
              {"Id":"s-local-self","ScopeId":"personal-1","HostDeviceId":"{{w.PersonalDeviceId}}","InitiatorUserId":"owner",
               "Kind":"attended","State":"active","StartedUtc":"2026-11-19T00:00:00Z","EndedUtc":null,
               "TransportRung":"lan","Recording":"none","RecordingRef":null,
               "AcceptedByUserId":"owner","EndReason":null,"AcceptOrigin":"endpoint_local"}],
             "Participants":[],"Events":[],"Chat":[],"FileJobs":[]}
            """;
        sessions.ImportJson(json);
        var channel = sessions.GetSession("s-channel")!;
        Assert.Equal("ended", channel.State);
        Assert.Equal("import_repair", channel.EndReason);
        Assert.Null(channel.AcceptedByUserId);
        var local = sessions.GetSession("s-local-self")!;
        Assert.Equal("active", local.State);
        Assert.Equal("owner", local.AcceptedByUserId);
        Assert.Equal(SessionService.AcceptOriginEndpointLocal, local.AcceptOrigin);
    }
}

// ---------------------------------------------------------------- D38 reconciliation remainders (S1-WIN)

public class DestructionD38S1RemainderTests
{
    private static EnrollingDevice AsEnrolling(DeviceIdentity id, string name = "Device") =>
        new(id.DeviceId, id.PublicKeyBase64, name);

    [Fact]
    public void Destruction_D38S1_F1_RevokedDevice_CannotResurrectViaFreshCode()
    {
        var svc = new EnrollmentService();
        var identity = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var code1 = svc.CreateEnrollmentCode("company", "company-a", "Company A");
        Assert.NotNull(svc.Redeem(code1, AsEnrolling(identity)));
        Assert.True(svc.Revoke(identity.DeviceId));
        // A fresh code is not a resurrection path: the revoked record
        // stands, and the code is not consumed by the refused attempt.
        var code2 = svc.CreateEnrollmentCode("company", "company-a", "Company A");
        Assert.Null(svc.Redeem(code2, AsEnrolling(identity)));
        Assert.True(svc.List().Single().Revoked);
        var other = new DeviceIdentity(new DevOnlyPassThroughProtector());
        Assert.NotNull(svc.Redeem(code2, AsEnrolling(other)));
        // A LIVE device re-enrolling (DG-FIND-10's recorded behavior)
        // still works: mint-side possession of a fresh code is the
        // credential there.
        var code3 = svc.CreateEnrollmentCode("company", "company-a", "Company A");
        Assert.NotNull(svc.Redeem(code3, AsEnrolling(other)));
    }

    [Fact]
    public void Destruction_D38S1_F6_PassThroughProtectorInForce_IsAuditedNeverSilent()
    {
        var dir = TestUtil.TempDir();
        var runtime = new CoreRuntime(new CoreOptions
        {
            DataDir = dir, Port = 18799, Protector = new DevOnlyPassThroughProtector(),
            Probe = new FakeProbe(), FactChecks = new FakeFactChecks(),
        });
        Assert.NotNull(runtime.Identity);
        var auditText = File.ReadAllText(Path.Combine(dir, "audit", "audit.jsonl"));
        Assert.Contains("secret_protector_not_real_protection", auditText);
    }

    [Fact]
    public void Destruction_D38S1_F11_OversizedVerifyMessage_RefusedEvenWithValidSignature()
    {
        var svc = new EnrollmentService();
        var identity = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var code = svc.CreateEnrollmentCode("company", "company-a", "Company A");
        Assert.NotNull(svc.Redeem(code, AsEnrolling(identity)));
        var small = Encoding.UTF8.GetBytes("challenge");
        Assert.True(svc.VerifyEnrolledSignature(identity.DeviceId, small, identity.Sign(small)));
        // A valid signature over an oversized message still refuses:
        // the cap is on the work the host will do, not on validity.
        var huge = new byte[EnrollmentService.MaxVerifyMessageBytes + 1];
        Assert.False(svc.VerifyEnrolledSignature(identity.DeviceId, huge, identity.Sign(huge)));
    }
}
