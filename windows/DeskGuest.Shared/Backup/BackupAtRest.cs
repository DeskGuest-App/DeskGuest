using System.Security.Cryptography;
using System.Text;
using DeskGuest.Shared.Security;

namespace DeskGuest.Shared.Backup;

// =====================================================================
// W10 / V2-C1 — backup encryption at rest for the Windows snapshot
// store. Before this, BackupSnapshotStore wrote chunks and
// manifests as PLAINTEXT: integrity rested on unkeyed SHA-256 and
// a catalogue chain any storage-side attacker can recompute (the
// named full-recompute residual), and backup CONTENT was readable
// by anyone with storage access. (The Android DGENC2 format is a
// different surface on a different platform; it never covered this
// store.)
//
// Format (per stored blob): "DGENCW1" magic (8 bytes) ||
// nonce (12) || AES-256-GCM ciphertext||tag. The GCM AAD binds
// every blob to its storage key ("chunks/<hash>" /
// "manifests/<id>.json"), so a sealed blob moved to another key —
// a chunk swap, a manifest swap — fails decryption BY NAME before
// any hash check runs. Content addressing is unchanged: a chunk's
// key remains the SHA-256 of its PLAINTEXT, so deduplication,
// read-back verification and the catalogue chain keep their exact
// pre-encryption meanings; only the stored bytes are sealed.
//
// Key discipline: the store takes a 32-byte data key at
// construction. The key's fingerprint (KeyId) is bound into the
// catalogue chain hash, so a catalogue written under one key
// cannot be re-anchored under another. A store configured WITH a
// key REFUSES plaintext blobs (no silent downgrade — the Android
// DGENC2 law, applied here): legacy plaintext backups are
// readable only by a store constructed without a key, which is a
// deliberate, visible operator act, never a fallback.
//
// Production key custody: LoadOrCreateKeyFile persists the data
// key ONLY as ISecretProtector-protected text (DPAPI in
// production — machine/owner-bound, the same custody as every
// other DeskGuest secret). The storage target itself never holds the
// key: a stolen backup tree yields sealed blobs and no key.
// =====================================================================
public static class BackupAtRest
{
    public static readonly byte[] Magic = Encoding.ASCII.GetBytes("DGENCW1");
    public const int KeyBytes = 32;
    private const int NonceBytes = 12;
    private const int TagBytes = 16;

    public static bool IsSealed(ReadOnlySpan<byte> stored) =>
        stored.Length >= Magic.Length && stored[..Magic.Length].SequenceEqual(Magic);

    /// <summary>The non-secret fingerprint of a data key, bound
    /// into catalogue hashes so keys cannot be swapped silently.</summary>
    public static string KeyId(byte[] key) => BackupHashing.Sha256Hex(key)[..16];

    private static byte[] Aad(string storageKey) =>
        Encoding.UTF8.GetBytes("deskguest-backup-at-rest-v1|" + storageKey);

    public static byte[] Seal(byte[] key, string storageKey, byte[] plaintext)
    {
        if (key is null || key.Length != KeyBytes)
            throw new ArgumentException($"a backup at-rest key is exactly {KeyBytes} bytes", nameof(key));
        var nonce = RandomNumberGenerator.GetBytes(NonceBytes);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagBytes];
        using var aes = new AesGcm(key, TagBytes);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, Aad(storageKey));
        var stored = new byte[Magic.Length + NonceBytes + ciphertext.Length + TagBytes];
        Magic.CopyTo(stored, 0);
        nonce.CopyTo(stored, Magic.Length);
        ciphertext.CopyTo(stored, Magic.Length + NonceBytes);
        tag.CopyTo(stored, Magic.Length + NonceBytes + ciphertext.Length);
        return stored;
    }

    /// <summary>Open one sealed blob. Every failure is a named
    /// refusal (InvalidOperationException): not sealed, truncated,
    /// or tag failure (wrong key / tampered / swapped blob).</summary>
    public static byte[] Open(byte[] key, string storageKey, byte[] stored)
    {
        if (key is null || key.Length != KeyBytes)
            throw new ArgumentException($"a backup at-rest key is exactly {KeyBytes} bytes", nameof(key));
        if (!IsSealed(stored))
            throw new InvalidOperationException(
                $"backup blob '{storageKey}' is NOT sealed while this store requires at-rest encryption — refused (no silent downgrade to plaintext backups)");
        if (stored.Length < Magic.Length + NonceBytes + TagBytes)
            throw new InvalidOperationException($"backup blob '{storageKey}' is truncated — refused");
        var nonce = stored.AsSpan(Magic.Length, NonceBytes).ToArray();
        var ciphertext = stored.AsSpan(Magic.Length + NonceBytes, stored.Length - Magic.Length - NonceBytes - TagBytes).ToArray();
        var tag = stored.AsSpan(stored.Length - TagBytes, TagBytes).ToArray();
        var plaintext = new byte[ciphertext.Length];
        try
        {
            using var aes = new AesGcm(key, TagBytes);
            aes.Decrypt(nonce, ciphertext, tag, plaintext, Aad(storageKey));
        }
        catch (CryptographicException)
        {
            throw new InvalidOperationException(
                $"backup blob '{storageKey}' failed at-rest decryption — wrong backup key, or the stored bytes were tampered with or swapped; refused");
        }
        return plaintext;
    }

    /// <summary>Load the store's data key from a key file, creating
    /// it on first use. The file holds ONLY protector-wrapped key
    /// material (never the raw key); a file that does not unprotect,
    /// or unwraps to the wrong length, refuses loudly rather than
    /// minting a replacement over an existing backup history.</summary>
    public static byte[] LoadOrCreateKeyFile(string path, ISecretProtector protector)
    {
        if (protector is null) throw new ArgumentNullException(nameof(protector));
        if (File.Exists(path))
        {
            byte[] key;
            try { key = Convert.FromBase64String(protector.Unprotect(File.ReadAllText(path).Trim())); }
            catch (Exception ex)
            {
                throw new InvalidOperationException(
                    $"backup key file '{path}' could not be unprotected ({ex.GetType().Name}) — refused: minting a new key would orphan every sealed backup", ex);
            }
            if (key.Length != KeyBytes)
                throw new InvalidOperationException(
                    $"backup key file '{path}' unwraps to {key.Length} bytes, not {KeyBytes} — refused");
            return key;
        }
        var fresh = RandomNumberGenerator.GetBytes(KeyBytes);
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, protector.Protect(Convert.ToBase64String(fresh)));
        File.Move(tmp, path, overwrite: false);
        return fresh;
    }
}
