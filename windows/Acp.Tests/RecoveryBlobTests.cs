using System.Security.Cryptography;
using System.Text;
using Acp.Shared.Enrollment;
using Acp.Shared.Roster;
using Acp.Shared.Security;

namespace Acp.Tests;

/// <summary>
/// C20 — recovery blob (user-held encrypted artefact + optional sealed
/// contact copies; NO cloud, NO account, NO server). Covers the spec's
/// named tests — round-trip on the platform, wrong recovery credential
/// refuses, restore over a live identity refuses, a contact-sealed copy
/// cannot be opened by a non-named contact — plus the destruction set:
/// blob tampering, wrong passphrase, import-over-live-identity attack,
/// and a recovery contact trying to use a sealed copy alone.
/// </summary>
public sealed class RecoveryBlobTests
{
    private const string Passphrase = "correct horse battery staple";

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
        var exchange = pairings.ExchangeCode(code, "agent-one");
        Assert.NotNull(exchange);
        var roster = new RosterService();
        var scope = roster.CreateScope("personal-1", "personal", "Personal");
        Assert.NotNull(scope);
        var owner = roster.CreateUser("owner", "personal-1", "Owner", "human");
        Assert.NotNull(owner);
        var ai = roster.CreateUser("ai-1", "personal-1", "Agent One", "ai", pairedByUserId: "owner");
        Assert.NotNull(ai);
        return new World(identity, pairings, roster, protector);
    }

    private static (PairingService Pairings, RosterService Roster, DevOnlyPassThroughProtector Protector) EmptyTargets()
    {
        var protector = new DevOnlyPassThroughProtector();
        return (new PairingService(protector), new RosterService(), protector);
    }

    private static RecoveryExportResult ExportDefault(World world, IReadOnlyList<RecoveryContact>? contacts = null) =>
        RecoveryBlobService.Export(world.Identity, world.Protector, world.Pairings, world.Roster,
            Passphrase, contacts);

    // ---- key sheet -----------------------------------------------------

    [Fact]
    public void KeySheet_WordList_MatchesThePinnedSasList()
    {
        Assert.Equal(256, RecoveryBlobService.KeySheetWords.Length);
        Assert.Equal(256, RecoveryBlobService.KeySheetWords.Distinct().Count());
        Assert.Equal(PairingSas.WordList.ToArray(), RecoveryBlobService.KeySheetWords);
    }

    [Fact]
    public void KeySheet_RoundTrips_AndIsCaseAndSeparatorTolerant()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var sheet = RecoveryBlobService.KeySheetEncode(key);
        Assert.Equal(34, sheet.Split(' ').Length);
        Assert.Equal(key, RecoveryBlobService.KeySheetDecode(sheet));
        Assert.Equal(key, RecoveryBlobService.KeySheetDecode(sheet.ToUpperInvariant().Replace(' ', '-')));
        Assert.Equal(key, RecoveryBlobService.KeySheetDecode("  " + sheet.Replace(' ', '\n') + "  "));
    }

    [Fact]
    public void KeySheet_OneWrongWord_RefusesViaChecksum()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var words = RecoveryBlobService.KeySheetEncode(key).Split(' ').ToList();
        words[5] = words[5] == "bab" ? "bad" : "bab";
        Assert.Throws<RecoveryBlobException>(() => RecoveryBlobService.KeySheetDecode(string.Join(" ", words)));
        Assert.Throws<RecoveryBlobException>(() => RecoveryBlobService.KeySheetDecode("bab bab bab"));
        Assert.Throws<RecoveryBlobException>(() => RecoveryBlobService.KeySheetDecode(
            string.Join(" ", RecoveryBlobService.KeySheetEncode(key).Split(' ').Take(33))));
    }

    // ---- X25519 pin ------------------------------------------------------

    [Fact]
    public void X25519_MatchesRfc7748Vectors()
    {
        // RFC 7748 §5.2 test vectors. The expected outputs were
        // verified against an independent X25519 implementation
        // (Python `cryptography`) during the C20 build — never trust
        // a from-memory constant (CB-04 lesson).
        var scalar1 = Convert.FromHexString("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        var u1 = Convert.FromHexString("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        var expected1 = Convert.FromHexString("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
        Assert.Equal(expected1, X25519.Raw(scalar1, u1));

        var scalar2 = Convert.FromHexString("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
        var u2 = Convert.FromHexString("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
        var expected2 = Convert.FromHexString("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");
        Assert.Equal(expected2, X25519.Raw(scalar2, u2));
    }

    [Fact]
    public void X25519_Ed25519Agreement_BothSidesDeriveTheSameSecret()
    {
        var alice = Ed25519.GenerateKeyPair();
        var bob = Ed25519.GenerateKeyPair();
        var aliceShared = X25519.Raw(X25519.ScalarFromEd25519Seed(alice.Seed), X25519.PublicFromEd25519(bob.PublicKey));
        var bobShared = X25519.Raw(X25519.ScalarFromEd25519Seed(bob.Seed), X25519.PublicFromEd25519(alice.PublicKey));
        Assert.Equal(aliceShared, bobShared);
        Assert.False(aliceShared.All(b => b == 0));
    }

    // ---- export / round-trip ------------------------------------------------

    [Fact]
    public void RoundTrip_Passphrase_RestoresIdentityPairingsAndRoster()
    {
        var world = BuildWorld();
        var export = ExportDefault(world);
        Assert.Equal(world.Identity.DeviceId, export.DeviceId);
        Assert.Empty(export.ContactBlobs);

        var (pairings, roster, protector) = EmptyTargets();
        var restored = RecoveryBlobService.RestorePrimary(export.PrimaryBlob, Passphrase, null,
            protector, pairings, roster, () => false);
        Assert.Equal(world.Identity.DeviceId, restored.Identity.DeviceId);
        Assert.Equal(world.Identity.PublicKey, restored.Identity.PublicKey);
        Assert.Equal(1, restored.PairingsRestored);
        Assert.True(restored.RosterEntriesRestored > 0);
        Assert.Single(pairings.List());
        Assert.Equal("agent-one", pairings.List()[0].AgentName);
        Assert.NotNull(roster.GetUser("personal-1", "owner"));
        Assert.NotNull(roster.GetUser("personal-1", "ai-1"));
        // The restored identity is fully functional: it signs.
        var msg = Encoding.UTF8.GetBytes("post-restore signing check");
        Assert.True(Ed25519.Verify(world.Identity.PublicKey, msg, restored.Identity.Sign(msg)));
    }

    [Fact]
    public void RoundTrip_KeySheet_RestoresWithoutPassphrase()
    {
        var world = BuildWorld();
        var export = ExportDefault(world);
        var (pairings, roster, protector) = EmptyTargets();
        var restored = RecoveryBlobService.RestorePrimary(export.PrimaryBlob, null, export.KeySheet,
            protector, pairings, roster, () => false);
        Assert.Equal(world.Identity.DeviceId, restored.Identity.DeviceId);
        Assert.Equal(1, restored.PairingsRestored);
    }

    [Fact]
    public void Export_BlobContainsNoPlaintextSeedOrTokenMaterial()
    {
        var world = BuildWorld();
        var export = ExportDefault(world);
        var blobText = Encoding.UTF8.GetString(export.PrimaryBlob);
        var seedBase64 = world.Protector.Unprotect(world.Identity.ExportProtectedSeed());
        Assert.DoesNotContain(seedBase64, blobText);
        Assert.DoesNotContain(Convert.ToHexString(Convert.FromBase64String(seedBase64)), blobText, StringComparison.OrdinalIgnoreCase);
        // The pairing token hash lives in the pairing export — it must
        // not be readable in the blob either (payload is encrypted).
        var pairingJson = world.Pairings.ExportJson();
        var hashStart = pairingJson.IndexOf("\"TokenHash\":\"", StringComparison.Ordinal);
        if (hashStart >= 0)
        {
            var hash = pairingJson.Substring(hashStart + 13, 64);
            Assert.DoesNotContain(hash, blobText);
        }
    }

    [Fact]
    public void Export_ShortPassphrase_Refused()
    {
        var world = BuildWorld();
        Assert.Throws<RecoveryBlobException>(() =>
            RecoveryBlobService.Export(world.Identity, world.Protector, world.Pairings, world.Roster, "short"));
        Assert.Throws<RecoveryBlobException>(() =>
            RecoveryBlobService.Export(world.Identity, world.Protector, world.Pairings, world.Roster, ""));
    }

    [Fact]
    public void Inspect_ReadsMetadata_AndRefusesGarbage()
    {
        var world = BuildWorld();
        var contact = new RecoveryContact("Contact One", Ed25519.GenerateKeyPair().PublicKey);
        var export = ExportDefault(world, new[] { contact });
        var info = RecoveryBlobService.Inspect(export.PrimaryBlob);
        Assert.Equal(RecoveryBlobService.KindPrimary, info.Kind);
        Assert.Equal(world.Identity.DeviceId, info.DeviceId);
        Assert.Null(info.ContactName);
        var contactInfo = RecoveryBlobService.Inspect(export.ContactBlobs[0].Blob);
        Assert.Equal(RecoveryBlobService.KindContact, contactInfo.Kind);
        Assert.Equal("Contact One", contactInfo.ContactName);
        Assert.Throws<RecoveryBlobException>(() => RecoveryBlobService.Inspect(Encoding.UTF8.GetBytes("not a blob")));
        Assert.Throws<RecoveryBlobException>(() => RecoveryBlobService.Inspect(Array.Empty<byte>()));
    }

    // ---- destruction: wrong credentials ---------------------------------------

    [Fact]
    public void WrongPassphrase_Refuses_AndTargetsStayEmpty()
    {
        var world = BuildWorld();
        var export = ExportDefault(world);
        var (pairings, roster, protector) = EmptyTargets();
        // W10 / V2-C2: the refusal is asserted BY NAME (reason code),
        // not by exception type alone.
        var ex = Assert.Throws<RecoveryBlobException>(() =>
            RecoveryBlobService.RestorePrimary(export.PrimaryBlob, "wrong horse battery staple", null,
                protector, pairings, roster, () => false));
        Assert.Equal(RecoveryBlobException.ReasonCodes.PassphraseRefused, ex.ReasonCode);
        Assert.Empty(pairings.List());
        Assert.Empty(roster.ListScopes());
    }

    [Fact]
    public void WrongKeySheet_Refuses()
    {
        var world = BuildWorld();
        var export = ExportDefault(world);
        var otherSheet = RecoveryBlobService.KeySheetEncode(RandomNumberGenerator.GetBytes(32));
        var (pairings, roster, protector) = EmptyTargets();
        var ex = Assert.Throws<RecoveryBlobException>(() =>
            RecoveryBlobService.RestorePrimary(export.PrimaryBlob, null, otherSheet,
                protector, pairings, roster, () => false));
        Assert.Equal(RecoveryBlobException.ReasonCodes.KeySheetRefused, ex.ReasonCode);
        Assert.Empty(pairings.List());
    }

    [Fact]
    public void NoCredential_Refuses()
    {
        var world = BuildWorld();
        var export = ExportDefault(world);
        var (pairings, roster, protector) = EmptyTargets();
        Assert.Throws<RecoveryBlobException>(() =>
            RecoveryBlobService.RestorePrimary(export.PrimaryBlob, null, null,
                protector, pairings, roster, () => false));
    }

    // ---- destruction: tampering -------------------------------------------------

    [Fact]
    public void TamperedPayloadCiphertext_Refuses()
    {
        var world = BuildWorld();
        var export = ExportDefault(world);
        var tampered = TamperJson(export.PrimaryBlob, "payloadCiphertext");
        var (pairings, roster, protector) = EmptyTargets();
        var ex = Assert.Throws<RecoveryBlobException>(() =>
            RecoveryBlobService.RestorePrimary(tampered, Passphrase, null,
                protector, pairings, roster, () => false));
        Assert.Equal(RecoveryBlobException.ReasonCodes.PayloadIntegrity, ex.ReasonCode);
        Assert.Empty(pairings.List());
        Assert.Empty(roster.ListScopes());
    }

    [Fact]
    public void TamperedPassphraseSlot_Refuses()
    {
        var world = BuildWorld();
        var export = ExportDefault(world);
        var tampered = TamperJson(export.PrimaryBlob, "wrappedKey");
        var (pairings, roster, protector) = EmptyTargets();
        var ex = Assert.Throws<RecoveryBlobException>(() =>
            RecoveryBlobService.RestorePrimary(tampered, Passphrase, null,
                protector, pairings, roster, () => false));
        Assert.Equal(RecoveryBlobException.ReasonCodes.PassphraseRefused, ex.ReasonCode);
    }

    [Fact]
    public void TamperedDeviceBinding_Refuses()
    {
        var world = BuildWorld();
        var export = ExportDefault(world);
        // Swap the envelope deviceId for another valid-looking one: the
        // payload AAD + payload/envelope binding must catch it.
        var text = Encoding.UTF8.GetString(export.PrimaryBlob);
        var other = new DeviceIdentity(new DevOnlyPassThroughProtector()).DeviceId;
        var tampered = Encoding.UTF8.GetBytes(text.Replace(world.Identity.DeviceId, other));
        var (pairings, roster, protector) = EmptyTargets();
        // The envelope deviceId is the payload's AAD: swapping it
        // fails the GCM tag — refused BY NAME as payload integrity.
        var ex = Assert.Throws<RecoveryBlobException>(() =>
            RecoveryBlobService.RestorePrimary(tampered, Passphrase, null,
                protector, pairings, roster, () => false));
        Assert.Equal(RecoveryBlobException.ReasonCodes.PayloadIntegrity, ex.ReasonCode);
    }

    [Fact]
    public void TruncatedAndGarbageBlobs_Refuse()
    {
        var world = BuildWorld();
        var export = ExportDefault(world);
        var (pairings, roster, protector) = EmptyTargets();
        Assert.Throws<RecoveryBlobException>(() =>
            RecoveryBlobService.RestorePrimary(export.PrimaryBlob[..40], Passphrase, null,
                protector, pairings, roster, () => false));
        Assert.Throws<RecoveryBlobException>(() =>
            RecoveryBlobService.RestorePrimary(RandomNumberGenerator.GetBytes(512), Passphrase, null,
                protector, pairings, roster, () => false));
    }

    /// <summary>Flip one byte inside a base64 JSON field's DECODED
    /// bytes and re-encode. (W10: the pre-fix helper flipped a raw
    /// text character — System.Text.Json escapes '+' as \u002B, so
    /// the flip sometimes landed inside an escape sequence and the
    /// blob refused at JSON parse or base64 decode instead of at
    /// the integrity check the test names. Production refused BY
    /// NAME in every branch; the helper was the flake.)</summary>
    private static byte[] TamperJson(byte[] blob, string field)
    {
        var text = Encoding.UTF8.GetString(blob);
        string decoded;
        using (var doc = System.Text.Json.JsonDocument.Parse(text))
        {
            // Slot fields are nested (passphrase.wrappedKey,
            // sealed.sealedWrappedKey) — search the whole document.
            string? found = null;
            void Walk(System.Text.Json.JsonElement el)
            {
                if (found is not null) return;
                if (el.ValueKind == System.Text.Json.JsonValueKind.Object)
                {
                    foreach (var prop in el.EnumerateObject())
                    {
                        if (prop.Name == field && prop.Value.ValueKind == System.Text.Json.JsonValueKind.String)
                        { found = prop.Value.GetString(); return; }
                        Walk(prop.Value);
                        if (found is not null) return;
                    }
                }
                else if (el.ValueKind == System.Text.Json.JsonValueKind.Array)
                {
                    foreach (var item in el.EnumerateArray()) { Walk(item); if (found is not null) return; }
                }
            }
            Walk(doc.RootElement);
            Assert.True(found is not null, $"field {field} not found");
            decoded = found!;
        }
        var bytes = Convert.FromBase64String(decoded);
        bytes[3] ^= 0xFF;
        var reEncoded = Convert.ToBase64String(bytes);
        var marker = $"\"{field}\":\"";
        var idx = text.IndexOf(marker, StringComparison.Ordinal);
        Assert.True(idx >= 0, $"field {field} not found");
        var start = idx + marker.Length;
        var end = text.IndexOf('"', start);
        Assert.True(end > start, $"field {field} value span not found");
        return Encoding.UTF8.GetBytes(text[..start] + reEncoded + text[end..]);
    }

    // ---- destruction: import over a live identity --------------------------------

    [Fact]
    public void RestoreOverLiveIdentity_Refuses_AndLiveStateIsUndamaged()
    {
        var world = BuildWorld();
        var export = ExportDefault(world);

        // The "victim" device: a DIFFERENT live identity with its own pairing.
        var victim = BuildWorld();
        var pairingsBefore = victim.Pairings.ExportJson();
        var rosterBefore = victim.Roster.ExportJson();
        Assert.Throws<RecoveryBlobException>(() =>
            RecoveryBlobService.RestorePrimary(export.PrimaryBlob, Passphrase, null,
                victim.Protector, victim.Pairings, victim.Roster, () => true));
        // Live state byte-identical after the refused import.
        Assert.Equal(pairingsBefore, victim.Pairings.ExportJson());
        Assert.Equal(rosterBefore, victim.Roster.ExportJson());
    }

    [Fact]
    public void RestoreIntoNonEmptyPairingStore_Refuses_EvenWithoutLiveIdentityFlag()
    {
        var world = BuildWorld();
        var export = ExportDefault(world);
        var (pairings, roster, protector) = EmptyTargets();
        var code = pairings.CreatePairingCode("someone-else", TimeSpan.FromMinutes(5));
        pairings.ExchangeCode(code, "someone-else");
        Assert.Throws<RecoveryBlobException>(() =>
            RecoveryBlobService.RestorePrimary(export.PrimaryBlob, Passphrase, null,
                protector, pairings, roster, () => false));
        Assert.Single(pairings.List());
        Assert.Equal("someone-else", pairings.List()[0].AgentName);
    }

    // ---- sealed contact copies ------------------------------------------------------

    private static (RecoveryContact Contact, byte[] Seed) MakeContact(string name)
    {
        var kp = Ed25519.GenerateKeyPair();
        return (new RecoveryContact(name, kp.PublicKey), kp.Seed);
    }

    [Fact]
    public void ContactCopy_RoundTrips_WithContactKeyAndKeySheet()
    {
        var world = BuildWorld();
        var (contact, contactSeed) = MakeContact("Contact One");
        var export = ExportDefault(world, new[] { contact });
        Assert.Single(export.ContactBlobs);

        var (pairings, roster, protector) = EmptyTargets();
        var restored = RecoveryBlobService.RestoreFromContactCopy(export.ContactBlobs[0].Blob,
            contactSeed, export.KeySheet, protector, pairings, roster, () => false);
        Assert.Equal(world.Identity.DeviceId, restored.Identity.DeviceId);
        Assert.Equal(1, restored.PairingsRestored);
    }

    [Fact]
    public void ContactCopy_ContactAloneWithoutKeySheet_CannotRestore()
    {
        var world = BuildWorld();
        var (contact, contactSeed) = MakeContact("Contact One");
        var export = ExportDefault(world, new[] { contact });
        var blob = export.ContactBlobs[0].Blob;
        var (pairings, roster, protector) = EmptyTargets();
        // No sheet at all.
        Assert.Throws<RecoveryBlobException>(() =>
            RecoveryBlobService.RestoreFromContactCopy(blob, contactSeed, "",
                protector, pairings, roster, () => false));
        // A WRONG sheet (the contact guessing / another export's sheet).
        var wrongSheet = RecoveryBlobService.KeySheetEncode(RandomNumberGenerator.GetBytes(32));
        Assert.Throws<RecoveryBlobException>(() =>
            RecoveryBlobService.RestoreFromContactCopy(blob, contactSeed, wrongSheet,
                protector, pairings, roster, () => false));
        Assert.Empty(pairings.List());
        Assert.Empty(roster.ListScopes());
    }

    [Fact]
    public void ContactCopy_NonNamedContact_CannotOpen()
    {
        var world = BuildWorld();
        var (contact, _) = MakeContact("Contact One");
        var (_, strangerSeed) = MakeContact("Stranger");
        var export = ExportDefault(world, new[] { contact });
        var (pairings, roster, protector) = EmptyTargets();
        Assert.Throws<RecoveryBlobException>(() =>
            RecoveryBlobService.RestoreFromContactCopy(export.ContactBlobs[0].Blob,
                strangerSeed, export.KeySheet, protector, pairings, roster, () => false));
        Assert.Empty(pairings.List());
    }

    [Fact]
    public void ContactCopy_HolderCannotOpenWithPassphraseOrSheetAlone()
    {
        var world = BuildWorld();
        var (contact, _) = MakeContact("Contact One");
        var export = ExportDefault(world, new[] { contact });
        var blob = export.ContactBlobs[0].Blob;
        var (pairings, roster, protector) = EmptyTargets();
        // The holder knows the passphrase AND the key sheet — the
        // contact copy still refuses: it has no passphrase/recovery
        // slot, only the sealed slot.
        Assert.Throws<RecoveryBlobException>(() =>
            RecoveryBlobService.RestorePrimary(blob, Passphrase, export.KeySheet,
                protector, pairings, roster, () => false));
        Assert.Empty(pairings.List());
    }

    [Fact]
    public void ContactCopy_PrimaryBlobRefusedOnContactPath_AndViceVersa()
    {
        var world = BuildWorld();
        var (contact, contactSeed) = MakeContact("Contact One");
        var export = ExportDefault(world, new[] { contact });
        var (pairings, roster, protector) = EmptyTargets();
        Assert.Throws<RecoveryBlobException>(() =>
            RecoveryBlobService.RestoreFromContactCopy(export.PrimaryBlob,
                contactSeed, export.KeySheet, protector, pairings, roster, () => false));
    }

    [Fact]
    public void ContactCopy_TamperedSealedSlot_Refuses()
    {
        var world = BuildWorld();
        var (contact, contactSeed) = MakeContact("Contact One");
        var export = ExportDefault(world, new[] { contact });
        var tampered = TamperJson(export.ContactBlobs[0].Blob, "sealedWrappedKey");
        var (pairings, roster, protector) = EmptyTargets();
        var ex = Assert.Throws<RecoveryBlobException>(() =>
            RecoveryBlobService.RestoreFromContactCopy(tampered,
                contactSeed, export.KeySheet, protector, pairings, roster, () => false));
        Assert.Equal(RecoveryBlobException.ReasonCodes.SealedIntegrity, ex.ReasonCode);
        Assert.Empty(pairings.List());
    }

    [Fact]
    public void Export_SmallOrderContactKey_Refused()
    {
        var world = BuildWorld();
        // The Ed25519 identity encoding (point of order 1) is small-order.
        var smallOrder = new byte[32];
        smallOrder[0] = 1;
        if (Ed25519.IsSmallOrderPublicKey(smallOrder))
        {
            var bad = new RecoveryContact("Bad", smallOrder);
            Assert.Throws<RecoveryBlobException>(() => ExportDefault(world, new[] { bad }));
        }
    }
}
