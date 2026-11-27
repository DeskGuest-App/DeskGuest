using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DeskGuest.Shared.Roster;

namespace DeskGuest.Shared.Security;

// =====================================================================
// C20 — Recovery blob (UNION census #20, coordinator decision on
// record in log-union-verify.md): the recovery artefact is USER-HELD.
// The user exports a single encrypted file and keeps it where they
// choose. There is NO cloud default, NO DeskGuest account and NO
// server-side recovery — there is no server (D-series law). Optional
// sealed copies may be handed to user-named recovery contacts; a
// sealed copy is encrypted to the contact's enrolled Ed25519 key and
// the holder cannot read it — and even the named contact cannot use
// it alone: unsealing yields a recovery-key-wrapped blob key, so a
// restore from a contact copy ALSO needs the recovery key sheet.
//
// Artefact design:
//   payload  = { identity seed (base64), pairing store export,
//                roster export } — the seed leaves DeviceIdentity
//                ONLY through its ExportProtectedSeed seam; the
//                export peels the caller's own protector layer INSIDE
//                this service and stores the seed base64 inside the
//                encrypted payload, so the blob is machine-independent
//                (a DPAPI-bound seed could never restore onto a
//                replacement machine — the entire point of recovery).
//   blobKey  = fresh random 32 bytes per export; payload is
//              AES-256-GCM under it (tag = integrity proof).
//   primary blob key slots (either opens it):
//     * passphrase slot — blobKey wrapped under a PBKDF2-HMAC-SHA256
//       key (600k iterations, fresh salt) derived from a user-chosen
//       passphrase. DeskGuest never stores the passphrase.
//     * recovery-key slot — blobKey wrapped under a freshly generated
//       32-byte recovery key. The recovery key is shown ONCE as a
//       printable key sheet (34 words from the pinned SAS word list:
//       32 key words + 2 checksum words) and is NEVER stored by DeskGuest.
//   contact blob key slot (the only slot):
//     * sealed slot — the recovery-key-wrapped blobKey, itself sealed
//       to the contact's Ed25519 public key (X25519 via the birational
//       map, ephemeral keypair, HKDF-SHA256, AES-256-GCM).
//
// Restore discipline (fail-closed, verify-before-touch):
//   parse envelope → recover blobKey through the presented credential
//   → AES-GCM-decrypt the payload (tag failure = refuse) → validate
//   payload shape + device-id binding → ONLY THEN check the target
//   stores are empty (a live identity, any pairing, or any roster
//   scope refuses) → apply. A wrong passphrase, a wrong key sheet, a
//   tampered byte, or a non-named contact refuses BEFORE any live
//   state is touched, and the existing identity is never damaged by
//   a refused import.
// =====================================================================

/// <summary>A refusal of a recovery-blob operation. Always carries a
/// human-readable reason; never carries key material. W10 / V2-C2:
/// every refusal ALSO carries a machine-readable ReasonCode naming
/// WHICH check refused — the pre-fix tests could assert only the
/// exception type, so a refusal by the wrong check passed silently.</summary>
public sealed class RecoveryBlobException : Exception
{
    public RecoveryBlobException(string message, string? reasonCode = null) : base(message)
    {
        ReasonCode = reasonCode ?? ReasonCodes.Unspecified;
    }

    /// <summary>The named check that refused (see ReasonCodes).</summary>
    public string ReasonCode { get; }

    public static class ReasonCodes
    {
        public const string Unspecified = "unspecified";
        public const string RecoveryKeyLength = "recovery_key_length";
        public const string KeySheetEmpty = "key_sheet_empty";
        public const string KeySheetWordCount = "key_sheet_word_count";
        public const string KeySheetUnknownWord = "key_sheet_unknown_word";
        public const string KeySheetChecksum = "key_sheet_checksum";
        public const string PassphraseTooShort = "passphrase_too_short";
        public const string ContactNeedsName = "contact_needs_name";
        public const string ContactKeyMalformed = "contact_key_malformed";
        public const string ContactKeySmallOrder = "contact_key_small_order";
        public const string IdentitySeedUnreadable = "identity_seed_unreadable";
        public const string IdentitySeedMalformed = "identity_seed_malformed";
        public const string IdentitySeedLength = "identity_seed_length";
        public const string BlobTimestampMalformed = "blob_timestamp_malformed";
        public const string NotPrimaryBlob = "not_primary_blob";
        public const string NoPassphraseSlot = "no_passphrase_slot";
        public const string NoRecoveryKeySlot = "no_recovery_key_slot";
        public const string KeySheetRefused = "key_sheet_refused";
        public const string NoCredential = "no_credential";
        public const string NotContactCopy = "not_contact_copy";
        public const string ContactSeedLength = "contact_seed_length";
        public const string ContactSheetRequired = "contact_sheet_required";
        public const string PayloadIntegrity = "payload_integrity";
        public const string PayloadMalformed = "payload_malformed";
        public const string PayloadNotRecovery = "payload_not_recovery";
        public const string DeviceBindingMismatch = "device_binding_mismatch";
        public const string SeedDeviceMismatch = "seed_device_mismatch";
        public const string LiveIdentityExists = "live_identity_exists";
        public const string PairingStoreNotEmpty = "pairing_store_not_empty";
        public const string RosterStoreNotEmpty = "roster_store_not_empty";
        public const string EmptyBlob = "empty_blob";
        public const string NotABlob = "not_a_recovery_blob";
        public const string UnsupportedVersion = "unsupported_version";
        public const string UnknownKind = "unknown_kind";
        public const string IncompleteEnvelope = "incomplete_envelope";
        public const string SealedSlotMalformed = "sealed_slot_malformed";
        public const string NotNamedContact = "not_named_contact";
        public const string SealedIntegrity = "sealed_integrity";
        public const string DegenerateSharedSecret = "degenerate_shared_secret";
        public const string MalformedBase64 = "malformed_base64";
        public const string WrappedSlotMalformed = "wrapped_slot_malformed";
        public const string KeySlotIntegrity = "key_slot_integrity";
        public const string PassphraseSlotMalformed = "passphrase_slot_malformed";
        public const string PassphraseIterations = "passphrase_iterations_out_of_range";
        public const string PassphraseRefused = "passphrase_refused";
    }
}

/// <summary>A user-named recovery contact: a display name plus the
/// contact's enrolled Ed25519 public key (32 bytes). Sealing needs
/// only the public key; unsealing needs the contact's seed, which
/// never leaves the contact's own device.</summary>
public sealed record RecoveryContact(string Name, byte[] Ed25519PublicKey);

/// <summary>One export: the primary user-held blob, one sealed blob
/// per named contact, and the key sheet — shown ONCE at export time
/// and never stored by DeskGuest.</summary>
public sealed record RecoveryExportResult(
    byte[] PrimaryBlob,
    IReadOnlyList<(RecoveryContact Contact, byte[] Blob)> ContactBlobs,
    string KeySheet,
    string DeviceId);

/// <summary>A completed restore: the rebuilt identity plus the store
/// counts actually applied.</summary>
public sealed record RecoveryRestoreResult(
    DeviceIdentity Identity,
    int PairingsRestored,
    int RosterEntriesRestored,
    string DeviceId);

/// <summary>Public metadata readable from an unopened blob — kind,
/// device binding, contact name. No key material, no payload.</summary>
public sealed record RecoveryBlobInfo(
    string Kind,
    string DeviceId,
    DateTimeOffset CreatedUtc,
    string? ContactName);

public static class RecoveryBlobService
{
    public const string FormatTag = "deskguest-recovery-blob";
    public const int FormatVersion = 1;
    public const string KindPrimary = "primary";
    public const string KindContact = "contact";

    /// <summary>PBKDF2-HMAC-SHA256 iteration count for the passphrase
    /// slot (OWASP 2023 guidance for SHA-256).</summary>
    public const int PassphraseIterations = 600_000;

    /// <summary>Minimum passphrase length the export accepts.</summary>
    public const int MinPassphraseLength = 10;

    private const string PayloadFormatTag = "deskguest-recovery-payload";
    private const string SealInfo = "deskguest-recovery-seal-v1";

    // ---- envelope DTOs (private: the wire shape is ours to evolve) ----

    private sealed record PassphraseSlot(string Salt, int Iterations, string WrappedKey);
    private sealed record RecoveryKeySlot(string WrappedKey);
    private sealed record SealedSlot(
        string ContactName, string ContactPublicKey, string EphemeralPublicKey, string SealedWrappedKey,
        // W14 P4-F17 interop: the seal-AAD version marker Android's
        // W13-B seal writes ("sealAadV": 2). Null/absent = a pre-W13
        // legacy seal (name NOT bound in the AAD); 2 = the contact
        // NAME is bound in the AAD (see SealAadV2). Parse-tolerant:
        // old blobs carry no marker and load as legacy.
        int? SealAadV = null);
    private sealed record Envelope(
        string Format, int Version, string Kind, string DeviceId, string CreatedUtc,
        string PayloadNonce, string PayloadCiphertext,
        PassphraseSlot? Passphrase, RecoveryKeySlot? RecoveryKey, SealedSlot? Sealed);
    private sealed record Payload(
        string Format, int Version, string DeviceId, string CreatedUtc,
        string IdentitySeed, string Pairings, string Roster);

    private static readonly JsonSerializerOptions JsonOpts = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    // ---- key sheet ----------------------------------------------------

    /// <summary>
    /// The printable recovery key sheet: the 32 recovery-key bytes
    /// rendered as 32 words from the pinned SAS 256-word list (the
    /// SAME list as Enrollment/Sas on both platforms), plus 2 checksum
    /// words (the first 2 bytes of SHA-256 of the key) so a mistyped
    /// word is caught at entry, before any decryption attempt. 34
    /// words total. The sheet is the ONLY copy of the recovery key —
    /// DeskGuest never stores it.
    /// </summary>
    public static string KeySheetEncode(byte[] recoveryKey)
    {
        if (recoveryKey is null || recoveryKey.Length != 32)
            throw new RecoveryBlobException("a recovery key is exactly 32 bytes", RecoveryBlobException.ReasonCodes.RecoveryKeyLength);
        var words = new List<string>(34);
        foreach (var b in recoveryKey) words.Add(KeySheetWords[b]);
        var check = SHA256.HashData(recoveryKey);
        words.Add(KeySheetWords[check[0]]);
        words.Add(KeySheetWords[check[1]]);
        return string.Join(" ", words);
    }

    /// <summary>Decode a key sheet back to the 32-byte recovery key.
    /// Case-insensitive; words may be separated by spaces, dashes or
    /// newlines. Throws <see cref="RecoveryBlobException"/> on a wrong
    /// word count, an unknown word, or a checksum mismatch (a mistyped
    /// or wrong sheet) — before any blob is touched.</summary>
    public static byte[] KeySheetDecode(string keySheet)
    {
        if (string.IsNullOrWhiteSpace(keySheet))
            throw new RecoveryBlobException("the recovery key sheet is empty", RecoveryBlobException.ReasonCodes.KeySheetEmpty);
        var tokens = keySheet.ToLowerInvariant()
            .Split(new[] { ' ', '\t', '\r', '\n', '-' }, StringSplitOptions.RemoveEmptyEntries);
        if (tokens.Length != 34)
            throw new RecoveryBlobException($"a recovery key sheet is 34 words — this one has {tokens.Length}", RecoveryBlobException.ReasonCodes.KeySheetWordCount);
        var bytes = new byte[34];
        for (var i = 0; i < tokens.Length; i++)
        {
            var idx = Array.IndexOf(KeySheetWords, tokens[i]);
            if (idx < 0) throw new RecoveryBlobException($"key sheet word '{tokens[i]}' is not a recovery word", RecoveryBlobException.ReasonCodes.KeySheetUnknownWord);
            bytes[i] = (byte)idx;
        }
        var key = bytes[..32];
        var check = SHA256.HashData(key);
        if (check[0] != bytes[32] || check[1] != bytes[33])
            throw new RecoveryBlobException("key sheet checksum mismatch — a word is wrong or mistyped; refused before any decryption", RecoveryBlobException.ReasonCodes.KeySheetChecksum);
        return key;
    }

    /// <summary>The pinned 256-word list, GENERATED from the same
    /// onset × suffix pattern as the SAS list (Enrollment/Sas.cs and
    /// enrollment/Sas.kt carry it verbatim): 16 onsets × (12 a-suffixes
    /// + 4 e-suffixes). Generating it here from the pattern keeps the
    /// three copies provably identical — the tests pin the generated
    /// list against the SAS list itself.</summary>
    public static readonly string[] KeySheetWords = BuildWordList();

    private static string[] BuildWordList()
    {
        var onsets = new[] { "b", "d", "f", "g", "h", "j", "k", "l", "m", "n", "p", "r", "s", "t", "v", "z" };
        var suffixes = new[] { "ab", "ad", "ag", "ak", "al", "am", "an", "ap", "ar", "as", "at", "av", "eb", "ed", "eg", "ek" };
        var words = new string[256];
        var i = 0;
        foreach (var onset in onsets)
            foreach (var suffix in suffixes)
                words[i++] = onset + suffix;
        return words;
    }

    // ---- export ---------------------------------------------------------

    /// <summary>
    /// Export the recovery artefact set. <paramref name="identityProtector"/>
    /// must be the SAME protector the identity was constructed with —
    /// it is used only to peel the identity's own at-rest protection
    /// off the seed inside this call (see the header: the blob itself
    /// is the protection, and it must work on a replacement machine).
    /// Throws <see cref="RecoveryBlobException"/> on a missing/short
    /// passphrase or a malformed contact key.
    /// </summary>
    public static RecoveryExportResult Export(
        DeviceIdentity identity,
        ISecretProtector identityProtector,
        PairingService pairings,
        RosterService roster,
        string passphrase,
        IReadOnlyList<RecoveryContact>? contacts = null,
        Func<DateTimeOffset>? clock = null)
    {
        if (identity is null) throw new ArgumentNullException(nameof(identity));
        if (identityProtector is null) throw new ArgumentNullException(nameof(identityProtector));
        if (pairings is null) throw new ArgumentNullException(nameof(pairings));
        if (roster is null) throw new ArgumentNullException(nameof(roster));
        if (string.IsNullOrEmpty(passphrase) || passphrase.Length < MinPassphraseLength)
            throw new RecoveryBlobException($"the export passphrase must be at least {MinPassphraseLength} characters — it is the only thing standing between a found blob and this device's identity", RecoveryBlobException.ReasonCodes.PassphraseTooShort);
        contacts ??= Array.Empty<RecoveryContact>();
        foreach (var c in contacts)
        {
            if (string.IsNullOrWhiteSpace(c.Name))
                throw new RecoveryBlobException("a recovery contact needs a name", RecoveryBlobException.ReasonCodes.ContactNeedsName);
            if (c.Ed25519PublicKey is null || c.Ed25519PublicKey.Length != 32)
                throw new RecoveryBlobException($"recovery contact '{c.Name}' does not carry a 32-byte Ed25519 public key", RecoveryBlobException.ReasonCodes.ContactKeyMalformed);
            if (Ed25519.IsSmallOrderPublicKey(c.Ed25519PublicKey))
                throw new RecoveryBlobException($"recovery contact '{c.Name}' public key is a small-order point — sealing to it would produce a predictable shared secret; refused", RecoveryBlobException.ReasonCodes.ContactKeySmallOrder);
        }

        var now = (clock ?? (() => DateTimeOffset.UtcNow))().ToUniversalTime();

        // The seed's ONLY exit from DeviceIdentity is ExportProtectedSeed;
        // peel this device's own protector layer here, inside the export,
        // and let the blob's own encryption be the protection in transit.
        string seedBase64;
        try { seedBase64 = identityProtector.Unprotect(identity.ExportProtectedSeed()); }
        catch (Exception ex) { throw new RecoveryBlobException($"the identity seed could not be read through its protector: {ex.Message}", RecoveryBlobException.ReasonCodes.IdentitySeedUnreadable); }
        byte[] seed;
        try { seed = Convert.FromBase64String(seedBase64); }
        catch { throw new RecoveryBlobException("the identity seed did not decode — export refused", RecoveryBlobException.ReasonCodes.IdentitySeedMalformed); }
        if (seed.Length != 32) throw new RecoveryBlobException("the identity seed is not 32 bytes — export refused", RecoveryBlobException.ReasonCodes.IdentitySeedLength);

        var payload = new Payload(
            PayloadFormatTag, FormatVersion, identity.DeviceId, now.ToString("O"),
            Convert.ToBase64String(seed), pairings.ExportJson(), roster.ExportJson());
        CryptographicOperations.ZeroMemory(seed);
        var payloadBytes = JsonSerializer.SerializeToUtf8Bytes(payload, JsonOpts);

        var blobKey = RandomNumberGenerator.GetBytes(32);
        var recoveryKey = RandomNumberGenerator.GetBytes(32);
        try
        {
            var aad = Aad(identity.DeviceId);
            var (nonce, ciphertext) = AesGcmEncrypt(blobKey, payloadBytes, aad);

            var salt = RandomNumberGenerator.GetBytes(16);
            var kek = Rfc2898DeriveBytes.Pbkdf2(passphrase, salt, PassphraseIterations, HashAlgorithmName.SHA256, 32);
            byte[] wrappedByPassphrase, wrappedByRecovery;
            try { wrappedByPassphrase = WrapKey(kek, blobKey, "passphrase"); }
            finally { CryptographicOperations.ZeroMemory(kek); }
            wrappedByRecovery = WrapKey(recoveryKey, blobKey, "recovery-key");

            var envelope = new Envelope(
                FormatTag, FormatVersion, KindPrimary, identity.DeviceId, now.ToString("O"),
                Convert.ToBase64String(nonce), Convert.ToBase64String(ciphertext),
                new PassphraseSlot(Convert.ToBase64String(salt), PassphraseIterations, Convert.ToBase64String(wrappedByPassphrase)),
                new RecoveryKeySlot(Convert.ToBase64String(wrappedByRecovery)),
                Sealed: null);
            var primaryBlob = JsonSerializer.SerializeToUtf8Bytes(envelope, JsonOpts);

            var contactBlobs = new List<(RecoveryContact, byte[])>();
            foreach (var contact in contacts)
            {
                // Each contact blob is self-contained: same payload
                // ciphertext, its own recovery-key wrap, sealed to the
                // contact. The holder of this file can read NOTHING of
                // it: no passphrase slot, no recovery slot — only the
                // sealed slot, and unsealing still needs the key sheet.
                var recoveryWrapped = WrapKey(recoveryKey, blobKey, "recovery-key");
                var sealedSlot = SealToContact(contact, recoveryWrapped);
                var contactEnvelope = new Envelope(
                    FormatTag, FormatVersion, KindContact, identity.DeviceId, now.ToString("O"),
                    Convert.ToBase64String(nonce), Convert.ToBase64String(ciphertext),
                    Passphrase: null, RecoveryKey: null, sealedSlot);
                contactBlobs.Add((contact, JsonSerializer.SerializeToUtf8Bytes(contactEnvelope, JsonOpts)));
            }

            return new RecoveryExportResult(primaryBlob, contactBlobs, KeySheetEncode(recoveryKey), identity.DeviceId);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(blobKey);
            CryptographicOperations.ZeroMemory(recoveryKey);
        }
    }

    // ---- inspect ---------------------------------------------------------

    /// <summary>Read a blob's public metadata without opening it.
    /// Throws <see cref="RecoveryBlobException"/> on anything that is
    /// not a well-formed recovery envelope.</summary>
    public static RecoveryBlobInfo Inspect(byte[] blob)
    {
        var env = ParseEnvelope(blob);
        if (!DateTimeOffset.TryParse(env.CreatedUtc, out var created))
            throw new RecoveryBlobException("the blob's creation timestamp is malformed", RecoveryBlobException.ReasonCodes.BlobTimestampMalformed);
        return new RecoveryBlobInfo(env.Kind, env.DeviceId, created, env.Sealed?.ContactName);
    }

    // ---- restore ----------------------------------------------------------

    /// <summary>
    /// Restore from a PRIMARY blob using either the export passphrase
    /// or the recovery key sheet (passphrase wins when both are
    /// given). Verifies EVERYTHING before touching live state and
    /// refuses over a live identity / non-empty stores. See the class
    /// header for the full discipline.
    /// </summary>
    public static RecoveryRestoreResult RestorePrimary(
        byte[] blob,
        string? passphrase,
        string? keySheet,
        ISecretProtector targetProtector,
        PairingService targetPairings,
        RosterService targetRoster,
        Func<bool> liveIdentityExists)
    {
        var env = ParseEnvelope(blob);
        if (env.Kind != KindPrimary)
            throw new RecoveryBlobException("this is a sealed contact copy, not the primary blob — restore it with the named contact's key and the recovery key sheet", RecoveryBlobException.ReasonCodes.NotPrimaryBlob);
        byte[] blobKey;
        if (!string.IsNullOrEmpty(passphrase))
        {
            if (env.Passphrase is null) throw new RecoveryBlobException("this blob carries no passphrase slot", RecoveryBlobException.ReasonCodes.NoPassphraseSlot);
            blobKey = UnwrapWithPassphrase(env.Passphrase, passphrase);
        }
        else if (!string.IsNullOrWhiteSpace(keySheet))
        {
            if (env.RecoveryKey is null) throw new RecoveryBlobException("this blob carries no recovery-key slot", RecoveryBlobException.ReasonCodes.NoRecoveryKeySlot);
            var recoveryKey = KeySheetDecode(keySheet);
            try { blobKey = UnwrapKey(recoveryKey, Decode(env.RecoveryKey.WrappedKey), "recovery-key"); }
            catch (RecoveryBlobException) { throw new RecoveryBlobException("the recovery key sheet does not open this blob — wrong sheet, or the blob is corrupt; nothing was restored", RecoveryBlobException.ReasonCodes.KeySheetRefused); }
            finally { CryptographicOperations.ZeroMemory(recoveryKey); }
        }
        else
        {
            throw new RecoveryBlobException("a restore needs the export passphrase or the recovery key sheet", RecoveryBlobException.ReasonCodes.NoCredential);
        }
        try { return RestoreVerified(env, blobKey, targetProtector, targetPairings, targetRoster, liveIdentityExists); }
        finally { CryptographicOperations.ZeroMemory(blobKey); }
    }

    /// <summary>
    /// Restore from a SEALED CONTACT copy. Needs BOTH the named
    /// contact's identity seed (their private key — it never leaves
    /// their device; it is presented here on the restoring device by
    /// the contact) AND the recovery key sheet. The contact alone
    /// cannot restore: unsealing yields only a recovery-key-wrapped
    /// blob key. A seed belonging to any other key fails the seal's
    /// GCM tag and refuses.
    /// </summary>
    public static RecoveryRestoreResult RestoreFromContactCopy(
        byte[] blob,
        byte[] contactSeed,
        string keySheet,
        ISecretProtector targetProtector,
        PairingService targetPairings,
        RosterService targetRoster,
        Func<bool> liveIdentityExists)
    {
        var env = ParseEnvelope(blob);
        if (env.Kind != KindContact || env.Sealed is null)
            throw new RecoveryBlobException("this is not a sealed contact copy", RecoveryBlobException.ReasonCodes.NotContactCopy);
        if (contactSeed is null || contactSeed.Length != 32)
            throw new RecoveryBlobException("the contact's identity seed must be 32 bytes", RecoveryBlobException.ReasonCodes.ContactSeedLength);
        if (string.IsNullOrWhiteSpace(keySheet))
            throw new RecoveryBlobException("a contact-copy restore also needs the recovery key sheet — the contact's key alone is not enough, by design", RecoveryBlobException.ReasonCodes.ContactSheetRequired);

        var recoveryWrapped = UnsealFromContact(env.Sealed, contactSeed);
        var recoveryKey = KeySheetDecode(keySheet);
        byte[] blobKey;
        try { blobKey = UnwrapKey(recoveryKey, recoveryWrapped, "recovery-key"); }
        catch (RecoveryBlobException) { throw new RecoveryBlobException("the recovery key sheet does not match this contact copy — wrong sheet, or the copy is corrupt; nothing was restored", RecoveryBlobException.ReasonCodes.KeySheetRefused); }
        finally { CryptographicOperations.ZeroMemory(recoveryKey); }
        try { return RestoreVerified(env, blobKey, targetProtector, targetPairings, targetRoster, liveIdentityExists); }
        finally { CryptographicOperations.ZeroMemory(blobKey); }
    }

    /// <summary>Decrypt + validate the payload, check the target
    /// stores are empty, and only then apply. Every refusal before the
    /// apply step leaves live state byte-identical.</summary>
    private static RecoveryRestoreResult RestoreVerified(
        Envelope env, byte[] blobKey,
        ISecretProtector targetProtector, PairingService targetPairings, RosterService targetRoster,
        Func<bool> liveIdentityExists)
    {
        if (targetProtector is null) throw new ArgumentNullException(nameof(targetProtector));
        if (targetPairings is null) throw new ArgumentNullException(nameof(targetPairings));
        if (targetRoster is null) throw new ArgumentNullException(nameof(targetRoster));
        if (liveIdentityExists is null) throw new ArgumentNullException(nameof(liveIdentityExists));

        byte[] payloadBytes;
        try { payloadBytes = AesGcmDecrypt(blobKey, Decode(env.PayloadNonce), Decode(env.PayloadCiphertext), Aad(env.DeviceId)); }
        catch (Exception ex) when (ex is CryptographicException or FormatException)
        {
            throw new RecoveryBlobException("the blob failed its integrity check — it is corrupt or tampered with; nothing was restored", RecoveryBlobException.ReasonCodes.PayloadIntegrity);
        }
        Payload? payload;
        try { payload = JsonSerializer.Deserialize<Payload>(payloadBytes, JsonOpts); }
        catch { throw new RecoveryBlobException("the blob's payload is malformed; nothing was restored", RecoveryBlobException.ReasonCodes.PayloadMalformed); }
        if (payload is null || payload.Format != PayloadFormatTag || payload.Version != FormatVersion)
            throw new RecoveryBlobException("the blob's payload is not a recovery payload; nothing was restored", RecoveryBlobException.ReasonCodes.PayloadNotRecovery);
        if (!string.Equals(payload.DeviceId, env.DeviceId, StringComparison.Ordinal))
            throw new RecoveryBlobException("the blob's payload does not match its envelope device binding — substituted or tampered; nothing was restored", RecoveryBlobException.ReasonCodes.DeviceBindingMismatch);
        byte[] seed;
        try { seed = Convert.FromBase64String(payload.IdentitySeed); }
        catch { throw new RecoveryBlobException("the blob's identity seed is malformed; nothing was restored", RecoveryBlobException.ReasonCodes.IdentitySeedMalformed); }
        if (seed.Length != 32) throw new RecoveryBlobException("the blob's identity seed is not 32 bytes; nothing was restored", RecoveryBlobException.ReasonCodes.IdentitySeedLength);
        var restoredIdentity = new DeviceIdentity(targetProtector, seed);
        CryptographicOperations.ZeroMemory(seed);
        if (!string.Equals(restoredIdentity.DeviceId, env.DeviceId, StringComparison.Ordinal))
            throw new RecoveryBlobException("the blob's identity seed does not reproduce its device id — tampered; nothing was restored", RecoveryBlobException.ReasonCodes.SeedDeviceMismatch);

        // The empty-store gate: restore lands in EMPTY stores only.
        // Checked after full verification, before ANY mutation, so a
        // refused import can never damage the live identity.
        if (liveIdentityExists())
            throw new RecoveryBlobException("a live identity already exists on this device — restore refused (a recovery import never overwrites a live identity)", RecoveryBlobException.ReasonCodes.LiveIdentityExists);
        if (targetPairings.List().Count > 0)
            throw new RecoveryBlobException("the pairing store is not empty — restore refused (a recovery import lands in empty stores only)", RecoveryBlobException.ReasonCodes.PairingStoreNotEmpty);
        if (targetRoster.ListScopes().Count > 0)
            throw new RecoveryBlobException("the roster store is not empty — restore refused (a recovery import lands in empty stores only)", RecoveryBlobException.ReasonCodes.RosterStoreNotEmpty);

        var pairingsRestored = targetPairings.ImportJson(payload.Pairings);
        var rosterRestored = targetRoster.ImportJson(payload.Roster);
        return new RecoveryRestoreResult(restoredIdentity, pairingsRestored, rosterRestored, env.DeviceId);
    }

    // ---- envelope parsing ---------------------------------------------------

    private static Envelope ParseEnvelope(byte[] blob)
    {
        if (blob is null || blob.Length == 0)
            throw new RecoveryBlobException("the blob is empty", RecoveryBlobException.ReasonCodes.EmptyBlob);
        Envelope? env;
        try { env = JsonSerializer.Deserialize<Envelope>(blob, JsonOpts); }
        catch { throw new RecoveryBlobException("this file is not a recovery blob (unparseable)", RecoveryBlobException.ReasonCodes.NotABlob); }
        if (env is null || env.Format != FormatTag)
            throw new RecoveryBlobException("this file is not a recovery blob", RecoveryBlobException.ReasonCodes.NotABlob);
        if (env.Version != FormatVersion)
            throw new RecoveryBlobException($"recovery blob version {env.Version} is not supported by this build (expected {FormatVersion})", RecoveryBlobException.ReasonCodes.UnsupportedVersion);
        if (env.Kind is not (KindPrimary or KindContact))
            throw new RecoveryBlobException($"unknown recovery blob kind '{env.Kind}'", RecoveryBlobException.ReasonCodes.UnknownKind);
        if (string.IsNullOrWhiteSpace(env.DeviceId) || string.IsNullOrWhiteSpace(env.PayloadNonce) ||
            string.IsNullOrWhiteSpace(env.PayloadCiphertext))
            throw new RecoveryBlobException("the recovery blob envelope is incomplete", RecoveryBlobException.ReasonCodes.IncompleteEnvelope);
        return env;
    }

    // ---- sealing (Ed25519 → X25519 sealed box) -------------------------------

    private static SealedSlot SealToContact(RecoveryContact contact, byte[] recoveryWrappedKey)
    {
        var ephemeralSeed = RandomNumberGenerator.GetBytes(32);
        try
        {
            var ephemeralScalar = X25519.ScalarFromEd25519Seed(ephemeralSeed);
            var ephemeralPublic = X25519.Raw(ephemeralScalar, X25519.BasePointU);
            var contactU = X25519.PublicFromEd25519(contact.Ed25519PublicKey);
            var shared = X25519.Raw(ephemeralScalar, contactU);
            RejectZeroShared(shared);
            var sealKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, shared, 32, salt: ephemeralPublic, info: Encoding.UTF8.GetBytes(SealInfo));
            try
            {
                // W14 P4-F17 interop (mirrors Android W13-B): new
                // seals bind the contact NAME into the AAD
                // (sealAadV2) and say so (SealAadV = 2) — a renamed
                // slot no longer opens. Byte-compatible with
                // RecoveryBlob.kt sealToContact.
                var (nonce, ct) = AesGcmEncrypt(sealKey, recoveryWrappedKey, SealAadV2(contact.Ed25519PublicKey, contact.Name));
                return new SealedSlot(
                    contact.Name,
                    Convert.ToBase64String(contact.Ed25519PublicKey),
                    Convert.ToBase64String(ephemeralPublic),
                    Convert.ToBase64String(Concat(nonce, ct)),
                    SealAadV: 2);
            }
            finally { CryptographicOperations.ZeroMemory(sealKey); }
        }
        finally { CryptographicOperations.ZeroMemory(ephemeralSeed); }
    }

    private static byte[] UnsealFromContact(SealedSlot slot, byte[] contactSeed)
    {
        byte[] contactPublic, ephemeralPublic, sealedBytes;
        try
        {
            contactPublic = Convert.FromBase64String(slot.ContactPublicKey);
            ephemeralPublic = Convert.FromBase64String(slot.EphemeralPublicKey);
            sealedBytes = Convert.FromBase64String(slot.SealedWrappedKey);
        }
        catch { throw new RecoveryBlobException("the sealed slot is malformed; nothing was restored", RecoveryBlobException.ReasonCodes.SealedSlotMalformed); }
        if (contactPublic.Length != 32 || ephemeralPublic.Length != 32 || sealedBytes.Length <= 12 + 16)
            throw new RecoveryBlobException("the sealed slot is malformed; nothing was restored", RecoveryBlobException.ReasonCodes.SealedSlotMalformed);
        // The presented seed must belong to the NAMED contact: derive
        // its public key and bind to the slot before any DH.
        var presentedPublic = Ed25519.DerivePublicKey(contactSeed);
        if (!CryptographicOperations.FixedTimeEquals(presentedPublic, contactPublic))
            throw new RecoveryBlobException($"this copy is sealed to '{slot.ContactName}' — the presented key is not theirs; refused", RecoveryBlobException.ReasonCodes.NotNamedContact);
        var scalar = X25519.ScalarFromEd25519Seed(contactSeed);
        var shared = X25519.Raw(scalar, ephemeralPublic);
        RejectZeroShared(shared);
        var sealKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, shared, 32, salt: ephemeralPublic, info: Encoding.UTF8.GetBytes(SealInfo));
        try
        {
            // W14 P4-F17 interop (mirrors Android W13-B): v2 slots
            // verify against the name-bound AAD (the slot's own
            // contactName — renaming it breaks the seal, and
            // stripping the marker falls back to the legacy AAD,
            // which also breaks a v2 seal: no downgrade path);
            // unmarked slots are pre-W13 and verify against the
            // legacy AAD only.
            var aad = slot.SealAadV is >= 2
                ? SealAadV2(contactPublic, slot.ContactName)
                : SealAad(contactPublic);
            return AesGcmDecrypt(sealKey, sealedBytes[..12], sealedBytes[12..], aad);
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException)
        {
            throw new RecoveryBlobException("the sealed copy failed its integrity check — corrupt or tampered; nothing was restored", RecoveryBlobException.ReasonCodes.SealedIntegrity);
        }
        finally { CryptographicOperations.ZeroMemory(sealKey); }
    }

    private static void RejectZeroShared(byte[] shared)
    {
        if (shared.All(b => b == 0))
            throw new RecoveryBlobException("the key agreement produced a degenerate shared secret — refused (small-order peer key)", RecoveryBlobException.ReasonCodes.DegenerateSharedSecret);
    }

    private static byte[] SealAad(byte[] contactPublicKey) =>
        Encoding.UTF8.GetBytes("deskguest-recovery-seal|" + Convert.ToBase64String(contactPublicKey));

    /// <summary>W14 P4-F17 interop: the v2 seal AAD — the contact's
    /// display name is bound into the seal, so editing the slot's
    /// contactName (e.g. to redirect a restore) breaks verification.
    /// BYTE-COMPATIBLE with Android's RecoveryBlob.sealAadV2:
    /// UTF-8 of "deskguest-recovery-seal-v2|" + base64(contactPublicKey)
    /// + "|" + contactName. Public so the cross-platform fixture
    /// tests pin the exact bytes against the Android formula.</summary>
    public static byte[] SealAadV2(byte[] contactPublicKey, string contactName) =>
        Encoding.UTF8.GetBytes("deskguest-recovery-seal-v2|" + Convert.ToBase64String(contactPublicKey) + "|" + (contactName ?? ""));

    // ---- primitive helpers -----------------------------------------------------

    /// <summary>Payload AAD: binds the ciphertext to the format and
    /// the device — deliberately NOT to the envelope kind, because the
    /// primary and contact envelopes share one payload ciphertext
    /// (the kind is enforced by the slot checks on each path).</summary>
    private static byte[] Aad(string deviceId) =>
        Encoding.UTF8.GetBytes($"{FormatTag}|{FormatVersion}|{deviceId}");

    private static byte[] Decode(string base64)
    {
        try { return Convert.FromBase64String(base64); }
        catch { throw new RecoveryBlobException("the blob carries malformed base64 — corrupt; nothing was restored", RecoveryBlobException.ReasonCodes.MalformedBase64); }
    }

    private static byte[] Concat(byte[] a, byte[] b)
    {
        var outBytes = new byte[a.Length + b.Length];
        Buffer.BlockCopy(a, 0, outBytes, 0, a.Length);
        Buffer.BlockCopy(b, 0, outBytes, a.Length, b.Length);
        return outBytes;
    }

    private static (byte[] Nonce, byte[] CiphertextWithTag) AesGcmEncrypt(byte[] key, byte[] plaintext, byte[] aad)
    {
        var nonce = RandomNumberGenerator.GetBytes(12);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[16];
        using var aes = new AesGcm(key, 16);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);
        return (nonce, Concat(ciphertext, tag));
    }

    private static byte[] AesGcmDecrypt(byte[] key, byte[] nonce, byte[] ciphertextWithTag, byte[] aad)
    {
        if (nonce.Length != 12 || ciphertextWithTag.Length < 16)
            throw new CryptographicException("ciphertext too short");
        var ciphertext = ciphertextWithTag[..^16];
        var tag = ciphertextWithTag[^16..];
        var plaintext = new byte[ciphertext.Length];
        using var aes = new AesGcm(key, 16);
        aes.Decrypt(nonce, ciphertext, tag, plaintext, aad);
        return plaintext;
    }

    /// <summary>Wrap a 32-byte key under another 32-byte key:
    /// nonce(12) || AES-256-GCM(wrappingKey, key, AAD names the slot).</summary>
    private static byte[] WrapKey(byte[] wrappingKey, byte[] key, string slotName)
    {
        var (nonce, ct) = AesGcmEncrypt(wrappingKey, key, Encoding.UTF8.GetBytes("deskguest-recovery-wrap|" + slotName));
        return Concat(nonce, ct);
    }

    private static byte[] UnwrapKey(byte[] wrappingKey, byte[] wrapped, string slotName)
    {
        if (wrapped.Length != 12 + 32 + 16)
            throw new RecoveryBlobException("a wrapped key slot is malformed; nothing was restored", RecoveryBlobException.ReasonCodes.WrappedSlotMalformed);
        try { return AesGcmDecrypt(wrappingKey, wrapped[..12], wrapped[12..], Encoding.UTF8.GetBytes("deskguest-recovery-wrap|" + slotName)); }
        catch (CryptographicException)
        {
            throw new RecoveryBlobException("a key slot failed its integrity check — wrong credential or corrupt blob; nothing was restored", RecoveryBlobException.ReasonCodes.KeySlotIntegrity);
        }
    }

    private static byte[] UnwrapWithPassphrase(PassphraseSlot slot, string passphrase)
    {
        byte[] salt, wrapped;
        try
        {
            salt = Convert.FromBase64String(slot.Salt);
            wrapped = Convert.FromBase64String(slot.WrappedKey);
        }
        catch { throw new RecoveryBlobException("the passphrase slot is malformed; nothing was restored", RecoveryBlobException.ReasonCodes.PassphraseSlotMalformed); }
        if (slot.Iterations < 100_000 || slot.Iterations > 10_000_000)
            throw new RecoveryBlobException("the passphrase slot names an out-of-range iteration count — tampered; nothing was restored", RecoveryBlobException.ReasonCodes.PassphraseIterations);
        var kek = Rfc2898DeriveBytes.Pbkdf2(passphrase, salt, slot.Iterations, HashAlgorithmName.SHA256, 32);
        try { return UnwrapKey(kek, wrapped, "passphrase"); }
        catch (RecoveryBlobException)
        {
            throw new RecoveryBlobException("the passphrase does not open this blob — wrong passphrase, or the blob is corrupt; nothing was restored", RecoveryBlobException.ReasonCodes.PassphraseRefused);
        }
        finally { CryptographicOperations.ZeroMemory(kek); }
    }
}

/// <summary>
/// X25519 (RFC 7748) over the Montgomery form of Curve25519, reached
/// from Ed25519 keys through the standard birational map
/// u = (1+y)/(1−y). BigInteger arithmetic — correctness over speed;
/// this runs once per export/restore, never on a hot path. The raw
/// function is pinned against the RFC 7748 §5.2 test vector in the
/// test suite (both platforms).
/// </summary>
public static class X25519
{
    private static readonly BigInteger P = (BigInteger.One << 255) - 19;
    private static readonly BigInteger A24 = 121665;
    public static readonly byte[] BasePointU = new byte[32] { 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

    /// <summary>RFC 7748 X25519: scalar (32 bytes, clamped inside) ×
    /// u-coordinate (32 bytes) → 32-byte u-coordinate.</summary>
    public static byte[] Raw(ReadOnlySpan<byte> scalar, ReadOnlySpan<byte> uCoordinate)
    {
        if (scalar.Length != 32 || uCoordinate.Length != 32)
            throw new ArgumentException("X25519 inputs are 32 bytes.");
        var k = DecodeLittleEndian(scalar);
        k[0] &= 248; k[31] &= 127; k[31] |= 64;
        var scalarInt = LittleEndianToBigInteger(k);
        var x1 = LittleEndianToBigInteger(DecodeLittleEndian(uCoordinate));
        BigInteger x2 = 1, z2 = 0, x3 = x1, z3 = 1;
        var swap = 0;
        for (var t = 254; t >= 0; t--)
        {
            var bit = (int)((scalarInt >> t) & 1);
            swap ^= bit;
            if (swap == 1) { (x2, x3) = (x3, x2); (z2, z3) = (z3, z2); }
            swap = bit;
            var a = Mod(x2 + z2); var aa = Mod(a * a);
            var b = Mod(x2 - z2); var bb = Mod(b * b);
            var e = Mod(aa - bb);
            var c = Mod(x3 + z3); var d = Mod(x3 - z3);
            var da = Mod(d * a); var cb = Mod(c * b);
            x3 = Mod((da + cb) * (da + cb));
            z3 = Mod(x1 * Mod((da - cb) * (da - cb)));
            x2 = Mod(aa * bb);
            z2 = Mod(e * Mod(aa + Mod(A24 * e)));
        }
        if (swap == 1) { (x2, x3) = (x3, x2); (z2, z3) = (z3, z2); }
        var result = Mod(x2 * BigInteger.ModPow(z2, P - 2, P));
        return BigIntegerToLittleEndian(result, 32);
    }

    /// <summary>The X25519 scalar for an Ed25519 seed: the clamped
    /// first half of SHA-512(seed) — the same expansion Ed25519 signs
    /// with, so a contact's existing identity key doubles as their
    /// recovery-contact key. Returned UNclamped; <see cref="Raw"/>
    /// clamps.</summary>
    public static byte[] ScalarFromEd25519Seed(ReadOnlySpan<byte> seed)
    {
        if (seed.Length != 32) throw new ArgumentException("Ed25519 seed must be 32 bytes.", nameof(seed));
        var hash = SHA512.HashData(seed);
        return hash[..32];
    }

    /// <summary>Convert an Ed25519 public key to its Montgomery
    /// u-coordinate: u = (1+y)·(1−y)⁻¹ mod p, y from the encoded point
    /// (top bit is the x sign — masked off).</summary>
    public static byte[] PublicFromEd25519(ReadOnlySpan<byte> edPublicKey)
    {
        if (edPublicKey.Length != 32) throw new ArgumentException("Ed25519 public key must be 32 bytes.", nameof(edPublicKey));
        var yBytes = DecodeLittleEndian(edPublicKey);
        var y = LittleEndianToBigInteger(yBytes);
        var u = Mod((1 + y) * BigInteger.ModPow(Mod(1 - y), P - 2, P));
        return BigIntegerToLittleEndian(u, 32);
    }

    private static BigInteger Mod(BigInteger value)
    {
        var r = value % P;
        return r.Sign < 0 ? r + P : r;
    }

    /// <summary>Copy with the top bit of the last byte masked off
    /// (RFC 7748 §5: for X25519 the most significant bit of u is
    /// ignored; for Ed25519 encodings it is the x sign bit).</summary>
    private static byte[] DecodeLittleEndian(ReadOnlySpan<byte> bytes)
    {
        var copy = bytes.ToArray();
        copy[31] &= 127;
        return copy;
    }

    private static BigInteger LittleEndianToBigInteger(byte[] littleEndian)
    {
        var bigEndian = littleEndian.Reverse().ToArray();
        return new BigInteger(bigEndian, isUnsigned: true, isBigEndian: true);
    }

    private static byte[] BigIntegerToLittleEndian(BigInteger value, int length)
    {
        var bigEndian = value.ToByteArray(isUnsigned: true, isBigEndian: true);
        var outBytes = new byte[length];
        for (var i = 0; i < Math.Min(length, bigEndian.Length); i++)
            outBytes[i] = bigEndian[bigEndian.Length - 1 - i];
        return outBytes;
    }
}
