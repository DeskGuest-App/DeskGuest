using System.Text;
using System.Text.Json;
using Acp.Shared.Security;

namespace Acp.Shared.Ipc;

/// <summary>
/// W25: the Core's asymmetric identity for the Agent channel —
/// the fix for the round-5 FIX-INADEQUATE break on the
/// W22 token-channel hardening.
///
/// THE BREAK (round 5, Item 2): the per-boot token + expected-path
/// check authenticate "a process the console user runs", not the
/// Core. A fake Core running as the console user — who legitimately
/// holds ReadAndDelete on the token file — reads the token, launches
/// the REAL Agent with ACP_CORE_EXE pointing at itself, passes the
/// expected-path check against its own path, completes the HMAC
/// with the read token, and receives vault/gate/STOP traffic. The
/// token is a shared secret the endpoint user can read; a shared
/// secret can never distinguish the Core from that user.
///
/// THE FIX: the Core holds an Ed25519 IDENTITY KEYPAIR, distinct
/// from the device identity (that key enrolls this device with
/// peers; this key proves "the pipe host is the installed Core" to
/// the local Agent — different trust domain, different lifecycle).
///   * The PRIVATE seed lives only in the Core's data area
///     (core-identity.key, protector-wrapped like the device
///     identity store), under an ACL that grants SYSTEM +
///     Administrators and NO console-user principal (see
///     BuildKeyFileAclPlan). In the shipped service shape the Core
///     runs as SYSTEM, so the console user — and any process
///     running as them, fake Cores included — cannot read it.
///   * The Core SIGNS the handshake: HelloAck carries an Ed25519
///     signature over the Agent's fresh nonce (domain-separated,
///     see HandshakeMessage) alongside the existing HMAC.
///   * The Agent PINS the Core's public key from its install
///     record: core-identity.pub beside the Agent's own image —
///     the install directory, which a console-user process cannot
///     rewrite in the shipped shape (Program Files / install root
///     ACLs). The Agent verifies the signature against the PIN
///     ONLY. A public key arriving over the pipe is diagnostic
///     data, never trust input.
///   * Token + expected-path remain as additional factors. Neither
///     is the identity proof any more.
///
/// CONSOLE-HOST LIMIT — NAMED, NOT PAPERED OVER: in the Path B
/// console-host shape the Core runs AS the console user, so its
/// identity seed is necessarily readable by that same user (the
/// Core cannot hold a secret from its own account). A process
/// running as the console user can therefore read the seed, sign
/// as the Core, and pass every check in that shape. Same-user
/// impersonation is NOT excluded in the console-host shape; the
/// signature binds only in the shipped service shape (Core as
/// SYSTEM, seed ACL'd away from the console user). This is the
/// strongest posture the console-host shape admits, and it is
/// stated here so no future reader mistakes the dev shape's
/// posture for the product's.
///
/// W28 SUPERSESSION (round-6): the beside-image pin
/// described above was itself the break — the pin's location
/// follows the Agent's image, so a copied Agent reads an
/// attacker-planted pin. The Agent no longer reads ANY pin from
/// beside its image; the public key it verifies against comes
/// ONLY from the protected install trust record (InstallTrust:
/// %ProgramData%\ACP\trust\agent-trust-record.json, written by
/// the installer / SYSTEM Core, ACL'd away from console-user
/// write). The beside-image core-identity.pub is still published
/// by the Core for operator inspection — diagnostic material,
/// never a trust input. See InstallTrustRecord.cs.
/// </summary>
public sealed class CoreIdentityKey
{
    private readonly byte[] _seed; // 32 bytes, never exposed

    private CoreIdentityKey(byte[] seed)
    {
        if (seed.Length != 32) throw new ArgumentException("Ed25519 seed must be 32 bytes.", nameof(seed));
        _seed = seed.ToArray();
        PublicKey = Ed25519.DerivePublicKey(_seed);
    }

    /// <summary>The 32-byte public key (a copy).</summary>
    public byte[] PublicKey { get; }

    public string PublicKeyBase64 => Convert.ToBase64String(PublicKey);

    public static CoreIdentityKey Generate()
    {
        var (seed, _) = Ed25519.GenerateKeyPair();
        return new CoreIdentityKey(seed);
    }

    public static CoreIdentityKey FromSeed(byte[] seed) => new(seed);

    /// <summary>The seed's base64 form, for protector-wrapped
    /// persistence ONLY (the Core channel wraps this with its
    /// ISecretProtector before it touches disk, exactly like the
    /// device identity store). Never logged, never sent.</summary>
    public string ExportSeedBase64() => Convert.ToBase64String(_seed);

    public static CoreIdentityKey ImportSeedBase64(string base64) =>
        new(Convert.FromBase64String(base64));

    /// <summary>Sign the handshake for one connection: the
    /// Agent's fresh nonce, domain-separated so a Core identity
    /// signature can never be replayed as any other protocol's
    /// signature (and vice versa).</summary>
    public byte[] SignHandshake(string nonce) =>
        Ed25519.Sign(_seed, CoreIdentity.HandshakeMessage(nonce));

    public string SignHandshakeBase64(string nonce) =>
        Convert.ToBase64String(SignHandshake(nonce));
}

public static class CoreIdentity
{
    /// <summary>The Core's private identity store, in the Core
    /// data dir (protector-wrapped seed).</summary>
    public const string PrivateKeyFileName = "core-identity.key";

    /// <summary>The public pin file. On the Core side it is also
    /// written into the data dir for operator inspection; the copy
    /// the Agent TRUSTS is the one beside the Agent's own image
    /// (the install record).</summary>
    public const string PinFileName = "core-identity.pub";

    public const string AdministratorsSid = "S-1-5-32-544";

    /// <summary>Domain separation for the handshake signature.</summary>
    public static byte[] HandshakeMessage(string nonce) =>
        Encoding.UTF8.GetBytes("acp-core-identity:v1:" + nonce);

    /// <summary>The ACL plan for the private key file: SYSTEM +
    /// Administrators, full control, and NO other principal —
    /// in particular never the console user. This is the ACL
    /// that makes the signature bind in the service shape.</summary>
    public static IReadOnlyList<IpcTokenFileAclEntry> BuildKeyFileAclPlan() => new[]
    {
        new IpcTokenFileAclEntry(IpcTokenFile.SystemSid, "FullControl", IsSystem: true),
        new IpcTokenFileAclEntry(AdministratorsSid, "FullControl", IsSystem: true),
    };

    /// <summary>W43 (F1): the WRITER-AWARE plan. The strict plan
    /// above names no console-user principal — correct for the
    /// service shape, where the writer IS SYSTEM and already holds
    /// FullControl. In the console-host shape the writer is the
    /// console user, and the strict plan locks the Core out of its
    /// OWN store: a non-elevated console process cannot use the
    /// Administrators ACE, and ownership alone grants no read or
    /// write — the W42 live boot read its attempt-1 store as
    /// "corrupt" (the read was access-denied) and then failed to
    /// persist the replacement with UnauthorizedAccessException,
    /// rotating the identity every boot. When the writer is a
    /// non-SYSTEM, non-Administrators identity, the plan therefore
    /// adds THAT identity — and no other — with FullControl. This
    /// grants nothing the console-host shape does not already
    /// concede (see the named console-host limit in this file's
    /// header: the Core cannot hold a secret from its own
    /// account); it restores the writer's access to its own store
    /// while every other non-admin principal stays excluded.</summary>
    public static IReadOnlyList<IpcTokenFileAclEntry> BuildKeyFileAclPlan(string? writerSid)
    {
        var strict = BuildKeyFileAclPlan();
        if (string.IsNullOrWhiteSpace(writerSid)) return strict;
        var sid = writerSid.Trim();
        if (string.Equals(sid, IpcTokenFile.SystemSid, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(sid, AdministratorsSid, StringComparison.OrdinalIgnoreCase))
            return strict;
        if (strict.Any(e => string.Equals(e.Sid, sid, StringComparison.OrdinalIgnoreCase)))
            return strict;
        return strict.Concat(new[]
        {
            new IpcTokenFileAclEntry(sid, "FullControl", IsSystem: false),
        }).ToArray();
    }

    /// <summary>Verify a handshake signature against a PINNED
    /// public key. Fail-closed: malformed key/signature, a
    /// small-order key, or a bad signature all return false.</summary>
    public static bool VerifyHandshake(ReadOnlySpan<byte> pinnedPublicKey, string? nonce, string? signatureBase64)
    {
        if (string.IsNullOrWhiteSpace(nonce) || string.IsNullOrWhiteSpace(signatureBase64)) return false;
        byte[] signature;
        try { signature = Convert.FromBase64String(signatureBase64.Trim()); }
        catch { return false; }
        return Ed25519.Verify(pinnedPublicKey, HandshakeMessage(nonce), signature);
    }

    /// <summary>Build the HelloAck payload the Core sends: the
    /// identity signature over the nonce, plus the Core's public
    /// key FOR DIAGNOSTICS ONLY (an Agent that trusted this field
    /// would re-open the round-5 break — verification is against
    /// the install pin, see VerifyHelloAckProof).</summary>
    public static string BuildHelloAckProof(CoreIdentityKey identity, string nonce) =>
        JsonSerializer.Serialize(new
        {
            coreIdentitySig = identity.SignHandshakeBase64(nonce),
            corePublicKey = identity.PublicKeyBase64,
        });

    /// <summary>The AGENT side of the handshake proof, pure so the
    /// harness pins the exact decision the Session Agent makes:
    /// given the PINNED public key (from the install record), the
    /// nonce this connection generated, and the HelloAck payload,
    /// decide whether the pipe host proved it holds the Core
    /// identity key. Anything missing or malformed refuses. The
    /// payload's own corePublicKey field is deliberately never
    /// read here.</summary>
    public static bool VerifyHelloAckProof(byte[]? pinnedPublicKey, string? nonce, string? helloAckArgumentsJson)
    {
        if (pinnedPublicKey is null || pinnedPublicKey.Length != 32) return false;
        if (string.IsNullOrWhiteSpace(nonce) || string.IsNullOrWhiteSpace(helloAckArgumentsJson)) return false;
        string? signature = null;
        try
        {
            using var doc = JsonDocument.Parse(helloAckArgumentsJson);
            if (doc.RootElement.TryGetProperty("coreIdentitySig", out var sig) &&
                sig.ValueKind == JsonValueKind.String)
                signature = sig.GetString();
        }
        catch (JsonException) { return false; }
        return VerifyHandshake(pinnedPublicKey, nonce, signature);
    }

    /// <summary>The pin file's path beside an image (the Agent's
    /// own image, in production): the install record.</summary>
    public static string? PinPathBeside(string? imagePath)
    {
        if (string.IsNullOrWhiteSpace(imagePath) || !WindowsPath.IsFullyQualified(imagePath)) return null;
        var normalized = WindowsPath.Normalize(imagePath);
        var sep = normalized.LastIndexOf('\\');
        if (sep < 0)
        {
            // Off-Windows harness shape: the same "beside the image"
            // rule over the host's own separator.
            var dir = Path.GetDirectoryName(imagePath);
            return dir is null ? null : Path.Combine(dir, PinFileName);
        }
        return normalized[..sep] + "\\" + PinFileName;
    }

    /// <summary>Read + validate the pinned Core public key beside
    /// the Agent's image. ANY failure — absent, unreadable,
    /// malformed, wrong length, small-order — returns null, which
    /// the Agent treats as "no Core identity can be verified":
    /// fail closed (the Authenticated posture requires the proof).</summary>
    public static byte[]? TryReadPinnedPublicKey(string? agentImagePath)
    {
        var path = PinPathBeside(agentImagePath);
        if (path is null) return null;
        // PinPathBeside speaks Windows paths; on a Windows host that
        // IS the filesystem path. (The harness drives the parse +
        // validation through TryParsePinnedPublicKey directly.)
        try
        {
            if (!File.Exists(path)) return null;
            return TryParsePinnedPublicKey(File.ReadAllText(path));
        }
        catch { return null; }
    }

    /// <summary>Parse a pin file's content: base64 of exactly 32
    /// bytes, and not a small-order (forgeable) key.</summary>
    public static byte[]? TryParsePinnedPublicKey(string? content)
    {
        if (string.IsNullOrWhiteSpace(content)) return null;
        byte[] key;
        try { key = Convert.FromBase64String(content.Trim()); }
        catch { return null; }
        if (key.Length != 32) return null;
        if (Ed25519.IsSmallOrderPublicKey(key)) return null;
        return key;
    }
}
