using System.Security.Cryptography;

namespace Acp.Shared.Security;

/// <summary>
/// This device's long-term Ed25519 identity. The 32-byte seed is held
/// only in memory and leaves this class solely through
/// <see cref="ExportProtectedSeed"/>, protected by the injected
/// <see cref="ISecretProtector"/> (DPAPI in production) so Core can
/// persist it the same way pairing material is persisted. The raw
/// seed is never exposed, exported in plaintext, or logged.
///
/// DeviceId is the shared cross-platform fingerprint: lowercase hex
/// SHA-256 of the 32-byte public key.
/// </summary>
public sealed class DeviceIdentity
{
    private readonly byte[] _seed; // 32 bytes, never exposed
    private readonly byte[] _publicKey; // 32 bytes; only copies leave this class
    private readonly ISecretProtector _protector;

    public DeviceIdentity(ISecretProtector protector, byte[]? seed = null)
    {
        _protector = protector ?? throw new ArgumentNullException(nameof(protector));
        if (seed is null)
        {
            _seed = RandomNumberGenerator.GetBytes(32);
        }
        else
        {
            if (seed.Length != 32) throw new ArgumentException("Ed25519 seed must be 32 bytes.", nameof(seed));
            _seed = seed.ToArray();
        }
        _publicKey = Ed25519.DerivePublicKey(_seed);
        DeviceId = Ed25519.ComputeDeviceId(_publicKey);
    }

    /// <summary>Lowercase hex SHA-256 of the public key.</summary>
    public string DeviceId { get; }

    /// <summary>The 32-byte public key (a COPY; safe to share — a
    /// caller mutating the returned array cannot alter this identity,
    /// D38 S1-WIN F9).</summary>
    public byte[] PublicKey => _publicKey.ToArray();

    public string PublicKeyBase64 => Convert.ToBase64String(_publicKey);

    /// <summary>Sign a message with this identity's key.</summary>
    public byte[] Sign(ReadOnlySpan<byte> message) => Ed25519.Sign(_seed, message);

    /// <summary>The seed, protected for at-rest persistence. The
    /// plaintext fed to the protector is the seed's base64 form; the
    /// output contains neither the raw seed bytes, their hex, nor
    /// their base64 (with a real protector it is DPAPI ciphertext;
    /// with the dev pass-through it is base64-of-base64).</summary>
    public string ExportProtectedSeed() =>
        _protector.Protect(Convert.ToBase64String(_seed));

    /// <summary>Restore an identity from <see cref="ExportProtectedSeed"/>
    /// output. Throws on malformed input — the caller (Core) treats a
    /// corrupt identity store like a corrupt pairing store: not fatal
    /// to the process, but the stored value is not trusted.</summary>
    public static DeviceIdentity ImportProtectedSeed(ISecretProtector protector, string protectedSeed)
    {
        if (protector is null) throw new ArgumentNullException(nameof(protector));
        if (string.IsNullOrWhiteSpace(protectedSeed)) throw new ArgumentException("Protected seed is empty.", nameof(protectedSeed));
        var seed = Convert.FromBase64String(protector.Unprotect(protectedSeed));
        return new DeviceIdentity(protector, seed); // length validated by the ctor
    }

    /// <summary>Try-import variant for Core startup: false (never an
    /// exception) on any malformed/corrupt stored value.</summary>
    public static bool TryImportProtectedSeed(ISecretProtector protector, string? protectedSeed, out DeviceIdentity? identity)
    {
        identity = null;
        if (string.IsNullOrWhiteSpace(protectedSeed)) return false;
        try
        {
            identity = ImportProtectedSeed(protector, protectedSeed);
            return true;
        }
        catch
        {
            identity = null;
            return false;
        }
    }
}
