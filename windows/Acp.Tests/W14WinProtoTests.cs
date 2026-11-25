using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Acp.Shared.Enrollment;
using Acp.Shared.Roster;
using Acp.Shared.Security;
using Acp.Shared.Transport;

namespace Acp.Tests;

/// <summary>
/// W14 Lane B (Windows protocol/interop) — permanent pins for:
///  1. sealAadV2 interop (P4-F17 mirror): Windows recovery opens
///     Android-sealed v2 contact copies; the v2 AAD bytes match
///     Android's RecoveryBlob.sealAadV2 formula exactly; legacy
///     unmarked slots keep the legacy AAD; renaming a v2 slot or
///     stripping its marker breaks the seal (no downgrade).
///  2. P3-F14b STOPLOCAL (Windows side): the wire verb is removed —
///     refused by name ("REFUSED stoplocal_removed"), nothing is
///     stopped, the channel stays open (the listener loop continues).
///  3. P3-F2 ownerUserId (Windows side): mint-carried trailing
///     field on EnrolledDevice, parse-tolerant persistence, and the
///     SESSION owner binding (SessionOwnerRefusal) wired into the
///     host listener's line replies.
/// Cross-platform fixture constants are the C20 contract: identity
/// seed 0x01..0x20, contact seed 0xA0..0xBF, contact name
/// "Xcheck Contact", passphrase "correct horse battery staple" —
/// identical in Android's RecoveryBlobTest.kt (xwrite/xread) and
/// the C# harness-c20 Program.cs.
/// </summary>
public sealed class W14WinProtoTests
{
    private const string Passphrase = "correct horse battery staple";

    private static byte[] FixtureSeed(byte start) =>
        Enumerable.Range(0, 32).Select(i => (byte)(start + i)).ToArray();

    private sealed record World(
        DeviceIdentity Identity,
        PairingService Pairings,
        RosterService Roster,
        ISecretProtector Protector);

    private static World BuildWorld()
    {
        var protector = new DevOnlyPassThroughProtector();
        var identity = new DeviceIdentity(protector);
        var pairings = new PairingService(protector);
        var code = pairings.CreatePairingCode("agent-one", TimeSpan.FromMinutes(5),
            new HashSet<string> { "look_only" });
        pairings.ExchangeCode(code, "agent-one");
        var roster = new RosterService();
        roster.CreateScope("personal-1", "personal", "Personal");
        roster.CreateUser("owner", "personal-1", "Owner", "human");
        return new World(identity, pairings, roster, protector);
    }

    private static (PairingService Pairings, RosterService Roster, DevOnlyPassThroughProtector Protector) EmptyTargets()
    {
        var protector = new DevOnlyPassThroughProtector();
        return (new PairingService(protector), new RosterService(), protector);
    }

    // ================= Task 1: sealAadV2 interop =================

    [Fact]
    public void SealAadV2_Bytes_MatchTheAndroidFormulaExactly()
    {
        // Android RecoveryBlob.kt sealAadV2:
        //   ("acp-recovery-seal-v2|" + b64(contactPublicKey) + "|" + contactName)
        //       .toByteArray(UTF_8)
        var contactSeed = FixtureSeed(0xA0);
        var contactPublic = Ed25519.DerivePublicKey(contactSeed);
        var aad = RecoveryBlobService.SealAadV2(contactPublic, "Xcheck Contact");
        Assert.Equal(
            "acp-recovery-seal-v2|" + Convert.ToBase64String(contactPublic) + "|Xcheck Contact",
            Encoding.UTF8.GetString(aad));
        // The v2 AAD must NOT equal the legacy AAD for the same key.
        var legacy = Encoding.UTF8.GetBytes("acp-recovery-seal|" + Convert.ToBase64String(contactPublic));
        Assert.NotEqual(legacy, aad);
    }

    [Fact]
    public void V2_Export_MarksTheSlot_AndTheNamedContactRestores()
    {
        var world = BuildWorld();
        var contactSeed = FixtureSeed(0xA0);
        var contact = new RecoveryContact("Contact One", Ed25519.DerivePublicKey(contactSeed));
        var export = RecoveryBlobService.Export(world.Identity, world.Protector,
            world.Pairings, world.Roster, Passphrase, new[] { contact });
        var blob = export.ContactBlobs[0].Blob;
        // The slot says so: sealAadV = 2 in the envelope JSON.
        var env = JsonNode.Parse(Encoding.UTF8.GetString(blob))!;
        Assert.Equal(2, env["sealed"]!["sealAadV"]!.GetValue<int>());
        Assert.Equal("Contact One", env["sealed"]!["contactName"]!.GetValue<string>());

        var (pairings, roster, protector) = EmptyTargets();
        var restored = RecoveryBlobService.RestoreFromContactCopy(blob,
            contactSeed, export.KeySheet, protector, pairings, roster, () => false);
        Assert.Equal(world.Identity.DeviceId, restored.DeviceId);
    }

    [Fact]
    public void V2_RenamingTheSlotsContactName_BreaksTheSeal()
    {
        var world = BuildWorld();
        var contactSeed = FixtureSeed(0xA0);
        var contact = new RecoveryContact("Contact One", Ed25519.DerivePublicKey(contactSeed));
        var export = RecoveryBlobService.Export(world.Identity, world.Protector,
            world.Pairings, world.Roster, Passphrase, new[] { contact });
        var env = JsonNode.Parse(Encoding.UTF8.GetString(export.ContactBlobs[0].Blob))!;
        env["sealed"]!["contactName"] = "Mallory";
        var tampered = Encoding.UTF8.GetBytes(env.ToJsonString());
        var (pairings, roster, protector) = EmptyTargets();
        var ex = Assert.Throws<RecoveryBlobException>(() =>
            RecoveryBlobService.RestoreFromContactCopy(tampered,
                contactSeed, export.KeySheet, protector, pairings, roster, () => false));
        Assert.Equal(RecoveryBlobException.ReasonCodes.SealedIntegrity, ex.ReasonCode);
        Assert.Empty(pairings.List());
    }

    [Fact]
    public void V2_StrippingTheMarker_DoesNotDowngradeToTheLegacyAad()
    {
        var world = BuildWorld();
        var contactSeed = FixtureSeed(0xA0);
        var contact = new RecoveryContact("Contact One", Ed25519.DerivePublicKey(contactSeed));
        var export = RecoveryBlobService.Export(world.Identity, world.Protector,
            world.Pairings, world.Roster, Passphrase, new[] { contact });
        var env = JsonNode.Parse(Encoding.UTF8.GetString(export.ContactBlobs[0].Blob))!;
        env["sealed"]!.AsObject().Remove("sealAadV");
        var stripped = Encoding.UTF8.GetBytes(env.ToJsonString());
        var (pairings, roster, protector) = EmptyTargets();
        var ex = Assert.Throws<RecoveryBlobException>(() =>
            RecoveryBlobService.RestoreFromContactCopy(stripped,
                contactSeed, export.KeySheet, protector, pairings, roster, () => false));
        Assert.Equal(RecoveryBlobException.ReasonCodes.SealedIntegrity, ex.ReasonCode);
        Assert.Empty(pairings.List());
    }

    [Fact]
    public void Legacy_UnmarkedSlot_SealedUnderTheLegacyAad_StillOpens()
    {
        // Build a genuine PRE-W13 contact copy: the primary blob's
        // recovery-key slot carries a recovery-wrapped blob key for
        // the same payload; re-seal those bytes to the contact
        // under the LEGACY AAD (public primitives only) and present
        // the slot with NO sealAadV marker. It must still open —
        // legacy slots keep the legacy AAD.
        var world = BuildWorld();
        var contactSeed = FixtureSeed(0xA0);
        var contactPublic = Ed25519.DerivePublicKey(contactSeed);
        var contact = new RecoveryContact("Contact One", contactPublic);
        var export = RecoveryBlobService.Export(world.Identity, world.Protector,
            world.Pairings, world.Roster, Passphrase, new[] { contact });

        var primary = JsonNode.Parse(Encoding.UTF8.GetString(export.PrimaryBlob))!;
        var recoveryWrapped = Convert.FromBase64String(primary["recoveryKey"]!["wrappedKey"]!.GetValue<string>());

        var ephemeralSeed = FixtureSeed(0x40);
        var ephemeralScalar = X25519.ScalarFromEd25519Seed(ephemeralSeed);
        var ephemeralPublic = X25519.Raw(ephemeralScalar, X25519.BasePointU);
        var shared = X25519.Raw(ephemeralScalar, X25519.PublicFromEd25519(contactPublic));
        var sealKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, shared, 32,
            salt: ephemeralPublic, info: Encoding.UTF8.GetBytes("acp-recovery-seal-v1"));
        var legacyAad = Encoding.UTF8.GetBytes("acp-recovery-seal|" + Convert.ToBase64String(contactPublic));
        var nonce = RandomNumberGenerator.GetBytes(12);
        var ct = new byte[recoveryWrapped.Length];
        var tag = new byte[16];
        using (var aes = new AesGcm(sealKey, 16))
            aes.Encrypt(nonce, recoveryWrapped, ct, tag, legacyAad);
        var sealedBytes = nonce.Concat(ct).Concat(tag).ToArray();

        var legacyEnv = new JsonObject
        {
            ["format"] = "acp-recovery-blob",
            ["version"] = 1,
            ["kind"] = "contact",
            ["deviceId"] = primary["deviceId"]!.GetValue<string>(),
            ["createdUtc"] = primary["createdUtc"]!.GetValue<string>(),
            ["payloadNonce"] = primary["payloadNonce"]!.GetValue<string>(),
            ["payloadCiphertext"] = primary["payloadCiphertext"]!.GetValue<string>(),
            ["passphrase"] = null,
            ["recoveryKey"] = null,
            ["sealed"] = new JsonObject
            {
                ["contactName"] = "Contact One",
                ["contactPublicKey"] = Convert.ToBase64String(contactPublic),
                ["ephemeralPublicKey"] = Convert.ToBase64String(ephemeralPublic),
                ["sealedWrappedKey"] = Convert.ToBase64String(sealedBytes),
                // NO sealAadV marker — the pre-W13 shape.
            },
        };
        var legacyBlob = Encoding.UTF8.GetBytes(legacyEnv.ToJsonString());
        var (pairings, roster, protector) = EmptyTargets();
        var restored = RecoveryBlobService.RestoreFromContactCopy(legacyBlob,
            contactSeed, export.KeySheet, protector, pairings, roster, () => false);
        Assert.Equal(world.Identity.DeviceId, restored.DeviceId);
        Assert.Equal(1, restored.PairingsRestored);
    }

    [Fact]
    public void CrossPlatformFixtureShape_WindowsExport_RestoresAsTheHarnessContract()
    {
        // The C20 xwrite fixture shape (identity seed 0x01..0x20,
        // contact seed 0xA0..0xBF, "Xcheck Contact"): a Windows
        // export in this shape is what Android's xread consumes.
        var protector = new DevOnlyPassThroughProtector();
        var identity = new DeviceIdentity(protector, FixtureSeed(0x01));
        var pairings = new PairingService(protector);
        var code = pairings.CreatePairingCode("xcheck-agent", TimeSpan.FromMinutes(5),
            new HashSet<string> { "look_only" });
        pairings.ExchangeCode(code, "xcheck-agent");
        var roster = new RosterService();
        roster.CreateScope("personal-1", "personal", "Personal");
        roster.CreateUser("owner", "personal-1", "Owner", "human");
        var contactSeed = FixtureSeed(0xA0);
        var contact = new RecoveryContact("Xcheck Contact", Ed25519.DerivePublicKey(contactSeed));
        var export = RecoveryBlobService.Export(identity, protector, pairings, roster,
            Passphrase, new[] { contact },
            clock: () => new DateTimeOffset(2026, 11, 22, 12, 0, 0, TimeSpan.Zero));
        var env = JsonNode.Parse(Encoding.UTF8.GetString(export.ContactBlobs[0].Blob))!;
        Assert.Equal(2, env["sealed"]!["sealAadV"]!.GetValue<int>());
        var (p2, r2, prot2) = EmptyTargets();
        var restored = RecoveryBlobService.RestoreFromContactCopy(export.ContactBlobs[0].Blob,
            contactSeed, export.KeySheet, prot2, p2, r2, () => false);
        Assert.Equal(identity.DeviceId, restored.DeviceId);
    }

    // ================= Task 2: STOPLOCAL removed =================

    [Fact]
    public void StopLocal_IsRefusedByName_AndIsNotAStop()
    {
        var reply = LanProtocol.SessionLineReply("STOPLOCAL");
        Assert.Equal("REFUSED stoplocal_removed", reply);
        Assert.NotEqual("STOPPED", reply);
    }

    [Fact]
    public void SessionLineReplies_PreserveThePreW14Posture()
    {
        Assert.Equal("PONG", LanProtocol.SessionLineReply("PING"));
        Assert.Equal("ERR unknown", LanProtocol.SessionLineReply("STATUS"));
        Assert.Equal("ERR unknown", LanProtocol.SessionLineReply("STOP host"));
        Assert.Equal("ERR unknown", LanProtocol.SessionLineReply("STOPLOCALX"));
        Assert.Equal("ERR unknown", LanProtocol.SessionLineReply("garbage"));
        Assert.Equal("ERR unknown", LanProtocol.SessionLineReply(null));
    }

    [Fact]
    public void SessionInitiatorOf_ParsesOnlyWellFormedSessionLines()
    {
        Assert.Equal("alice", LanProtocol.SessionInitiatorOf("SESSION scope-1 alice host-1 control"));
        Assert.Equal("alice", LanProtocol.SessionInitiatorOf("SESSION scope-1 alice host-1 control none"));
        Assert.Null(LanProtocol.SessionInitiatorOf("SESSION scope-1 alice"));
        Assert.Null(LanProtocol.SessionInitiatorOf("PING"));
        Assert.Null(LanProtocol.SessionInitiatorOf(null));
    }

    // ================= Task 3: ownerUserId =================

    private static (EnrollmentService Service, DeviceIdentity Identity) EnrollmentSetup()
        => (new EnrollmentService(), new DeviceIdentity(new DevOnlyPassThroughProtector()));

    private static EnrollingDevice AsEnrolling(DeviceIdentity identity) =>
        new(identity.DeviceId, identity.PublicKeyBase64, "Owner's Phone");

    [Fact]
    public void OwnerUserId_IsMintCarried_IntoTheEnrolledRecord()
    {
        var (svc, identity) = EnrollmentSetup();
        var code = svc.CreateEnrollmentCode("personal", "home", "Home", ownerUserId: "owner-1");
        var enrolled = svc.Redeem(code, AsEnrolling(identity));
        Assert.NotNull(enrolled);
        Assert.Equal("owner-1", enrolled!.OwnerUserId);
        Assert.Equal("owner-1", svc.ById(identity.DeviceId)!.OwnerUserId);
    }

    [Fact]
    public void OwnerUserId_AbsentAtMint_LoadsUnbound()
    {
        var (svc, identity) = EnrollmentSetup();
        var code = svc.CreateEnrollmentCode("personal", "home", "Home");
        var enrolled = svc.Redeem(code, AsEnrolling(identity));
        Assert.NotNull(enrolled);
        Assert.Equal("", enrolled!.OwnerUserId);
    }

    [Fact]
    public void OwnerUserId_RoundTripsThroughExportImport()
    {
        var (svc, identity) = EnrollmentSetup();
        var code = svc.CreateEnrollmentCode("personal", "home", "Home", ownerUserId: "owner-1");
        svc.Redeem(code, AsEnrolling(identity));
        var json = svc.ExportJson();
        Assert.Contains("\"OwnerUserId\":\"owner-1\"", json);
        var fresh = new EnrollmentService();
        Assert.Equal(1, fresh.ImportJson(json));
        Assert.Equal("owner-1", fresh.ById(identity.DeviceId)!.OwnerUserId);
    }

    [Fact]
    public void OwnerUserId_LegacyExportWithoutTheField_LoadsUnbound()
    {
        var (svc, identity) = EnrollmentSetup();
        var code = svc.CreateEnrollmentCode("personal", "home", "Home", ownerUserId: "owner-1");
        svc.Redeem(code, AsEnrolling(identity));
        // Strip the trailing field — the pre-W14 export shape.
        var node = JsonNode.Parse(svc.ExportJson())!;
        node["Devices"]![0]!.AsObject().Remove("OwnerUserId");
        var fresh = new EnrollmentService();
        Assert.Equal(1, fresh.ImportJson(node.ToJsonString()));
        Assert.Equal("", fresh.ById(identity.DeviceId)!.OwnerUserId);
        // Absent field = current behaviour: no owner check binds.
        Assert.Null(fresh.SessionOwnerRefusal(identity.DeviceId, "anyone"));
    }

    [Fact]
    public void SessionOwnerRefusal_BindsOnlyBoundDevices()
    {
        var (svc, identity) = EnrollmentSetup();
        var code = svc.CreateEnrollmentCode("personal", "home", "Home", ownerUserId: "owner-1");
        svc.Redeem(code, AsEnrolling(identity));
        Assert.Null(svc.SessionOwnerRefusal(identity.DeviceId, "owner-1"));
        Assert.Equal("owner_mismatch", svc.SessionOwnerRefusal(identity.DeviceId, "mallory"));
        Assert.Equal("owner_mismatch", svc.SessionOwnerRefusal(identity.DeviceId, ""));
        Assert.Equal("owner_mismatch", svc.SessionOwnerRefusal(identity.DeviceId, null));
        // Unknown device: no record, no binding (the handshake /
        // enrollment checks refuse unknown peers on their own).
        Assert.Null(svc.SessionOwnerRefusal("unknown-device", "mallory"));
    }

    [Fact]
    public void SessionLineReply_OwnerMismatch_IsRefusedByName_BeforeUnknownVerb()
    {
        const string line = "SESSION scope-1 mallory host-1 control";
        Assert.Equal("REFUSED owner_mismatch", LanProtocol.SessionLineReply(line, "owner_mismatch"));
        // An owner-clean SESSION keeps the listener's existing
        // posture — this listener serves no SESSION verb.
        Assert.Equal("ERR unknown", LanProtocol.SessionLineReply(line, null));
        Assert.Equal("ERR unknown", LanProtocol.SessionLineReply(line));
    }
}
