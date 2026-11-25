using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Acp.Shared.Enterprise;

namespace Acp.Shared.Security;

// =====================================================================
// RMM-03 — Endpoint Takeover Prevention (signed commands).
//
// Every instruction the hub can issue that CHANGES an endpoint is
// signed with a CUSTOMER-HELD Ed25519 key; the endpoint verifies the
// signature against the customer's public key BEFORE executing and
// refuses unsigned or altered commands EVEN IF THE HUB IS
// COMPROMISED. A stolen hub therefore degrades to a denial of
// service, never to fleet-wide code execution.
//
// The private key is the customer's: it lives only inside a
// DeviceIdentity (seed never exposed; persistence is the existing
// ISecretProtector vault machinery, DPAPI in production). The
// endpoint holds PUBLIC keys only, in a CustomerCommandKeyRing that
// supports rotation: the outgoing key is retired with a grace
// deadline (the same shape as break-glass holder rotation — a use
// or rotation is explicit, audited, and never silent), after which
// it verifies nothing.
//
// Verification is fail-closed and total: unknown command class,
// unknown key id, expired envelope, future-dated envelope, payload
// hash mismatch, bad signature, and replayed nonce ALL refuse, and
// every refusal is a hash-chained audit event (SignedCommandGate).
// =====================================================================

/// <summary>The closed set of command classes RMM-03 signs. An
/// envelope naming a class outside this set refuses — an unknown
/// class is a field that changes meaning.</summary>
public static class SignedCommandClasses
{
    public const string ShellExec = "shell_exec";
    public const string ScriptExec = "script_exec";
    public const string Automation = "automation";
    public const string PackageDeploy = "package_deploy";
    public const string PatchDeploy = "patch_deploy";
    public const string PolicyDelivery = "policy_delivery";
    public const string SessionInitiation = "session_initiation";
    public const string UpdateStaging = "update_staging";
    /// <summary>RMM-10: a hub-initiated background-tool action. The
    /// payload names the tool ({"tool": …}); the background service
    /// executes exactly the signed tool, never the unsigned args.</summary>
    public const string BackgroundAction = "background_action";
    /// <summary>RMM-29: an OS imaging / provisioning run authorization.
    /// Imaging is the most destructive hub command class there is —
    /// it rides this signed envelope with no exceptions; the payload
    /// binds image id+version+content hash, target, and profile
    /// binding (see Acp.Shared.Provisioning).</summary>
    public const string Provisioning = "provisioning";

    public static readonly IReadOnlySet<string> All = new HashSet<string>
    {
        ShellExec, ScriptExec, Automation, PackageDeploy, PatchDeploy,
        PolicyDelivery, SessionInitiation, UpdateStaging, BackgroundAction,
        Provisioning,
    };
}

/// <summary>The signed-command envelope. The signature covers the
/// canonical body (version, class, key id, issued/expiry, nonce,
/// payload hash, AUDIENCE) — the payload itself is bound through its
/// SHA-256 hash, so any alteration of class, timing, nonce, key,
/// payload or target breaks the signature or the hash check.
///
/// D38 F1: the audience is the target endpoint's device id (or a
/// scope id for genuinely scope-wide classes). An envelope minted
/// for one endpoint verifies ONLY there: a captured envelope cannot
/// be replayed across the fleet by a compromised hub, which is what
/// keeps a stolen hub at "denial of service" instead of fleet-wide
/// code execution. An empty audience is a fleet-wide envelope and
/// refuses wherever an endpoint expects its own id.</summary>
public sealed record SignedCommandEnvelope(
    int Version,
    string CommandClass,
    string KeyId,
    DateTimeOffset IssuedUtc,
    DateTimeOffset ExpiresUtc,
    string Nonce,
    string PayloadHash,
    string PayloadBase64,
    string SignatureBase64,
    string Audience = "")
{
    public static string CanonicalBody(SignedCommandEnvelope e) => string.Join("|",
        "acp-signed-command-v1", e.Version, e.CommandClass, e.KeyId,
        e.IssuedUtc.ToString("O"), e.ExpiresUtc.ToString("O"), e.Nonce, e.PayloadHash,
        e.Audience ?? "");

    public static string HashPayload(ReadOnlySpan<byte> payload) =>
        Convert.ToHexString(SHA256.HashData(payload)).ToLowerInvariant();

    public string ToJson() => JsonSerializer.Serialize(this);

    public static SignedCommandEnvelope? FromJson(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try { return JsonSerializer.Deserialize<SignedCommandEnvelope>(json); }
        catch { return null; }
    }
}

/// <summary>One customer command key in the endpoint's ring. A
/// retired key carries the instant after which it verifies NOTHING —
/// rotation grace is bounded and explicit, never open-ended.</summary>
public sealed record CustomerCommandKey(string KeyId, byte[] PublicKey, DateTimeOffset? RetiredUntilUtc)
{
    public bool IsRetired(DateTimeOffset now) => RetiredUntilUtc is { } until && now > until;
    public bool IsRetiring => RetiredUntilUtc is not null;
}

/// <summary>The endpoint-side store of customer PUBLIC command keys.
/// Signing keys never live here. Rotation mirrors the break-glass
/// discipline: <see cref="Rotate"/> retires the current key with a
/// grace deadline and installs the new current key; there is exactly
/// one current (signing) key id at a time.</summary>
public sealed class CustomerCommandKeyRing
{
    private readonly Dictionary<string, CustomerCommandKey> _keys = new(StringComparer.Ordinal);
    private readonly object _gate = new();

    public string? CurrentKeyId { get; private set; }

    /// <summary>Key id derivation: "cust-" + the first 16 hex chars
    /// of the key's DeviceId (SHA-256 of the public key) — the same
    /// fingerprint the rest of ACP uses, so a key id can never be
    /// detached from the key it names.</summary>
    public static string KeyIdFor(ReadOnlySpan<byte> publicKey) =>
        "cust-" + Ed25519.ComputeDeviceId(publicKey)[..16];

    /// <summary>Grace a superseded current key keeps when a new
    /// current key is installed without an explicit Rotate: bounded
    /// (D38 F6 — a superseded key must never stay trusted forever).</summary>
    public static readonly TimeSpan SupersededKeyGrace = TimeSpan.FromHours(24);

    public CustomerCommandKey AddCurrent(byte[] publicKey)
    {
        if (publicKey.Length != 32) throw new ArgumentException("customer command public key must be 32 bytes", nameof(publicKey));
        var id = KeyIdFor(publicKey);
        lock (_gate)
        {
            // D38 F6: a RETIRED key can never be resurrected by
            // re-adding it as current — its RetiredUntilUtc is a
            // one-way door. Rotation to a fresh key is the only way
            // forward; this throws rather than silently widening
            // trust (the caller audits the refusal).
            if (_keys.TryGetValue(id, out var existing) && existing.RetiredUntilUtc is not null)
                throw new InvalidOperationException(
                    $"customer command key '{id}' is retired (until {existing.RetiredUntilUtc:O}) and cannot be re-installed as current — a retired key is never resurrected; rotate to a NEW key");
            // D38 F6: exactly one current key. Installing a new
            // current key retires the previous one with a bounded
            // grace deadline — it does not stay trusted indefinitely.
            if (CurrentKeyId is { } prev && prev != id && _keys.TryGetValue(prev, out var prevKey)
                && prevKey.RetiredUntilUtc is null)
                _keys[prev] = prevKey with { RetiredUntilUtc = DateTimeOffset.UtcNow + SupersededKeyGrace };
            var key = new CustomerCommandKey(id, publicKey.ToArray(), null);
            _keys[id] = key;
            CurrentKeyId = id;
            return key;
        }
    }

    /// <summary>Install a key that is ALREADY retired with its grace
    /// deadline (the persisted-ring load path: rotation happened
    /// earlier; the endpoint restores the state, it does not
    /// re-decide it). Re-adding a retired key keeps the EARLIER
    /// (more restrictive) deadline — a later load can never extend
    /// a retirement (D38 F6).</summary>
    public CustomerCommandKey AddRetired(byte[] publicKey, DateTimeOffset retiredUntilUtc)
    {
        if (publicKey.Length != 32) throw new ArgumentException("customer command public key must be 32 bytes", nameof(publicKey));
        var key = new CustomerCommandKey(KeyIdFor(publicKey), publicKey.ToArray(), retiredUntilUtc);
        lock (_gate)
        {
            if (_keys.TryGetValue(key.KeyId, out var existing) && existing.RetiredUntilUtc is { } earlier
                && earlier < retiredUntilUtc)
                key = key with { RetiredUntilUtc = earlier };
            _keys[key.KeyId] = key;
            if (CurrentKeyId == key.KeyId) CurrentKeyId = null;
            return key;
        }
    }

    /// <summary>Rotate: EVERY non-retired key except the incoming
    /// one is retired (verifies only until <paramref name="now"/> +
    /// <paramref name="grace"/>) and the new key becomes current —
    /// not just the key named by CurrentKeyId (D38 F6: a key made
    /// current earlier and superseded informally must not escape
    /// retirement). Consistent with the break-glass holder
    /// machinery: rotation is an explicit act; the caller (hub/Core
    /// surface) audits it. Rotating TO a retired key throws (see
    /// AddCurrent) — resurrection is not a rotation.</summary>
    public CustomerCommandKey Rotate(byte[] newPublicKey, DateTimeOffset now, TimeSpan grace)
    {
        if (newPublicKey.Length != 32) throw new ArgumentException("customer command public key must be 32 bytes", nameof(newPublicKey));
        var newId = KeyIdFor(newPublicKey);
        lock (_gate)
        {
            foreach (var id in _keys.Keys.ToList())
            {
                if (id == newId) continue;
                var k = _keys[id];
                if (k.RetiredUntilUtc is null)
                    _keys[id] = k with { RetiredUntilUtc = now + grace };
            }
        }
        return AddCurrent(newPublicKey);
    }

    public bool TryGet(string keyId, out CustomerCommandKey? key)
    {
        lock (_gate) return _keys.TryGetValue(keyId ?? "", out key);
    }

    public IReadOnlyList<CustomerCommandKey> Keys
    {
        get { lock (_gate) return _keys.Values.OrderBy(k => k.KeyId, StringComparer.Ordinal).ToList(); }
    }
}

/// <summary>Hub-side signer. Holds the customer's key as a
/// DeviceIdentity — the seed never leaves that class; persistence is
/// ExportProtectedSeed through the existing vault machinery. The
/// signer is the ONLY place envelopes are minted.</summary>
public sealed class SignedCommandSigner
{
    private readonly DeviceIdentity _customerKey;
    public string KeyId { get; }

    public SignedCommandSigner(DeviceIdentity customerKey)
    {
        _customerKey = customerKey ?? throw new ArgumentNullException(nameof(customerKey));
        KeyId = CustomerCommandKeyRing.KeyIdFor(customerKey.PublicKey);
    }

    /// <summary>The longest envelope lifetime the signer will mint
    /// and the verifier will accept (D38 F7). The brief's
    /// "minutes-scale TTL" was a convention; this makes it a check:
    /// no envelope — however validly signed — lives longer than
    /// this, so a captured envelope's replay window is bounded even
    /// on a device that has never seen its nonce.</summary>
    public static readonly TimeSpan MaxEnvelopeLifetime = TimeSpan.FromHours(4);

    public SignedCommandEnvelope Sign(string commandClass, ReadOnlySpan<byte> payload, DateTimeOffset now, TimeSpan ttl)
        => Sign(commandClass, payload, now, ttl, audience: "");

    /// <param name="audience">The target endpoint's device id (D38
    /// F1). The envelope verifies ONLY on that endpoint. Empty =
    /// unbound (verifies wherever no audience is expected; refuses
    /// on any endpoint that expects its own id).</param>
    public SignedCommandEnvelope Sign(string commandClass, ReadOnlySpan<byte> payload, DateTimeOffset now, TimeSpan ttl, string? audience)
    {
        if (!SignedCommandClasses.All.Contains(commandClass))
            throw new ArgumentException($"unknown signed-command class '{commandClass}'", nameof(commandClass));
        if (ttl <= TimeSpan.Zero) throw new ArgumentException("envelope ttl must be positive", nameof(ttl));
        if (ttl > MaxEnvelopeLifetime)
            throw new ArgumentException($"envelope ttl {ttl} exceeds the maximum envelope lifetime {MaxEnvelopeLifetime} — refused (D38 F7: envelope lifetime is bounded by check, not convention)", nameof(ttl));
        var unsigned = new SignedCommandEnvelope(
            Version: 1, CommandClass: commandClass, KeyId: KeyId,
            IssuedUtc: now, ExpiresUtc: now + ttl,
            Nonce: Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant(),
            PayloadHash: SignedCommandEnvelope.HashPayload(payload),
            PayloadBase64: Convert.ToBase64String(payload), SignatureBase64: "",
            Audience: (audience ?? "").Trim());
        var sig = _customerKey.Sign(Encoding.UTF8.GetBytes(SignedCommandEnvelope.CanonicalBody(unsigned)));
        return unsigned with { SignatureBase64 = Convert.ToBase64String(sig) };
    }
}

/// <summary>Replay protection: a nonce is single-use per key. Seen
/// nonces are kept until their envelope expires (plus a small
/// margin), then pruned — a replay after expiry is refused by the
/// expiry check anyway, so pruning cannot reopen a replay window.</summary>
public sealed class SignedCommandReplayGuard : IReplayGuard
{
    private readonly Dictionary<string, DateTimeOffset> _seen = new(); // keyId|nonce -> keep-until
    private readonly object _gate = new();

    public bool TryRegister(SignedCommandEnvelope e, DateTimeOffset now)
    {
        lock (_gate)
        {
            var stale = _seen.Where(kv => kv.Value < now).Select(kv => kv.Key).ToList();
            foreach (var s in stale) _seen.Remove(s);
            var id = e.KeyId + "|" + e.Nonce;
            if (_seen.ContainsKey(id)) return false;
            _seen[id] = e.ExpiresUtc.AddMinutes(5);
            return true;
        }
    }

    public int TrackedCount { get { lock (_gate) return _seen.Count; } }
}

public sealed record SignedCommandVerdict(bool Allowed, string Reason, byte[]? Payload = null);

/// <summary>Endpoint-side verifier. Pure and fail-closed: every
/// malformed, unknown, expired, altered or replayed input refuses
/// with a named reason; nothing throws.</summary>
public sealed class SignedCommandVerifier
{
    private readonly CustomerCommandKeyRing _ring;
    private readonly IReplayGuard _replay;
    private readonly string? _expectedAudience;

    public SignedCommandVerifier(CustomerCommandKeyRing ring, SignedCommandReplayGuard? replay = null)
        : this(ring, (IReplayGuard?)replay) { }

    /// <summary>Durability seam (RMM-02 precondition): Core wires
    /// the persisted guard (PersistedSignedCommandReplayGuard) so a
    /// replayed envelope refuses ACROSS restarts; the in-memory
    /// guard remains the default for tests and unwired hosts.</summary>
    /// <param name="expectedAudience">D38 F1: this endpoint's device
    /// id. When set, an envelope verifies only if its signed
    /// audience names THIS endpoint — a captured envelope cannot be
    /// replayed fleet-wide. Null = no audience expectation (unit
    /// rigs and unwired hosts; Core always sets it).</param>
    public SignedCommandVerifier(CustomerCommandKeyRing ring, IReplayGuard? replay, string? expectedAudience = null)
    {
        _ring = ring ?? throw new ArgumentNullException(nameof(ring));
        _replay = replay ?? new SignedCommandReplayGuard();
        _expectedAudience = string.IsNullOrWhiteSpace(expectedAudience) ? null : expectedAudience.Trim();
    }

    public SignedCommandVerdict Verify(SignedCommandEnvelope? e, DateTimeOffset now, string? expectedClass = null)
    {
        if (e is null) return new SignedCommandVerdict(false, "no signed-command envelope presented — refused (RMM-03: unsigned commands never execute)");
        if (e.Version != 1) return new SignedCommandVerdict(false, $"unknown envelope version {e.Version} — refused");
        if (!SignedCommandClasses.All.Contains(e.CommandClass ?? ""))
            return new SignedCommandVerdict(false, $"unknown command class '{e.CommandClass}' — refused");
        if (expectedClass is not null && e.CommandClass != expectedClass)
            return new SignedCommandVerdict(false, $"command class '{e.CommandClass}' does not match the '{expectedClass}' this path executes — refused");
        // D38 F1: audience binding. The audience is inside the
        // signed canonical body, so this is a routing check on
        // signed data: an envelope minted for another endpoint (or
        // for the fleet at large) refuses HERE, before it can run.
        if (_expectedAudience is not null
            && !string.Equals((e.Audience ?? "").Trim(), _expectedAudience, StringComparison.Ordinal))
            return new SignedCommandVerdict(false,
                $"envelope audience '{(string.IsNullOrWhiteSpace(e.Audience) ? "(none — fleet-wide)" : e.Audience)}' does not name this endpoint '{_expectedAudience}' — refused (a signed command runs only on the endpoint it was minted for)");
        if (string.IsNullOrWhiteSpace(e.Nonce)) return new SignedCommandVerdict(false, "envelope carries no nonce — refused (replay protection is not optional)");
        if (e.ExpiresUtc <= now) return new SignedCommandVerdict(false, "signed command expired — refused");
        if (e.IssuedUtc > now.AddMinutes(5)) return new SignedCommandVerdict(false, "signed command issued in the future — refused");
        if (e.ExpiresUtc <= e.IssuedUtc) return new SignedCommandVerdict(false, "envelope expiry precedes its issuance — refused");
        byte[] payload;
        try { payload = Convert.FromBase64String(e.PayloadBase64 ?? ""); }
        catch { return new SignedCommandVerdict(false, "payload is not valid base64 — refused"); }
        var actualHash = SignedCommandEnvelope.HashPayload(payload);
        if (!CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(actualHash),
                Encoding.ASCII.GetBytes((e.PayloadHash ?? "").ToLowerInvariant())))
            return new SignedCommandVerdict(false, "payload hash mismatch — the command was altered after signing — refused");
        if (!_ring.TryGet(e.KeyId ?? "", out var key) || key is null)
            return new SignedCommandVerdict(false, $"unknown signer key id '{e.KeyId}' — refused (key-id confusion never widens trust)");
        if (key.IsRetired(now))
            return new SignedCommandVerdict(false, $"signer key '{e.KeyId}' is retired past its grace deadline — refused (rotate per the key-rotation story)");
        // D38 F7: maximum envelope lifetime, checked on the SIGNED
        // issued/expiry pair — an envelope minted with a days- or
        // years-long TTL refuses no matter how fresh it looks.
        if (e.ExpiresUtc - e.IssuedUtc > SignedCommandSigner.MaxEnvelopeLifetime)
            return new SignedCommandVerdict(false,
                $"envelope lifetime {e.ExpiresUtc - e.IssuedUtc} exceeds the maximum {SignedCommandSigner.MaxEnvelopeLifetime} — refused (D38 F7: lifetime is bounded by check, not convention)");
        bool ok;
        try
        {
            ok = Ed25519.Verify(key.PublicKey, Encoding.UTF8.GetBytes(SignedCommandEnvelope.CanonicalBody(e)),
                Convert.FromBase64String(e.SignatureBase64 ?? ""));
        }
        catch { ok = false; }
        if (!ok) return new SignedCommandVerdict(false, "signature invalid — refused (fail closed; a compromised hub cannot forge the customer's key)");
        if (!_replay.TryRegister(e, now))
            return new SignedCommandVerdict(false, "nonce already seen — replayed command refused");
        return new SignedCommandVerdict(true, $"signed command verified (class {e.CommandClass}, key {e.KeyId})", payload);
    }
}

/// <summary>The verify-gate wired into endpoint command paths. Every
/// refusal — and every acceptance — is a hash-chained audit event in
/// the enterprise ledger (RMM-03 (c): refusals are audit events,
/// never silent).</summary>
public sealed class SignedCommandGate
{
    private readonly SignedCommandVerifier _verifier;
    private readonly ChainedAuditLog _audit;

    public SignedCommandGate(SignedCommandVerifier verifier, ChainedAuditLog audit)
    {
        _verifier = verifier ?? throw new ArgumentNullException(nameof(verifier));
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
    }

    public SignedCommandVerdict Authorize(SignedCommandEnvelope? envelope, DateTimeOffset now, string? expectedClass = null)
    {
        var verdict = _verifier.Verify(envelope, now, expectedClass);
        var cls = envelope?.CommandClass ?? "(none)";
        var kid = envelope?.KeyId ?? "(none)";
        if (verdict.Allowed)
            _audit.Append("signed_command_accepted", "signed-command-gate",
                $"class={cls} key={kid} nonce={envelope!.Nonce} audience={envelope.Audience}", now);
        else
            _audit.Append("signed_command_refused", "signed-command-gate",
                $"class={cls} key={kid} reason={verdict.Reason}", now);
        return verdict;
    }
}
