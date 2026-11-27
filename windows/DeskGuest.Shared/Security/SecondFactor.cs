using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.Roster;

namespace DeskGuest.Shared.Security;

// =====================================================================
// G-06 — Local second factor (census §3 "2FA / SSO" row; §5 table
// stakes "2FA (TOTP/passkey, local)"). The census $0-substitution
// for SMS/email OTP: a factor that lives on the device, needs no
// carrier, no vendor cloud, and no account.
//
// Two halves, honestly separated:
//  * TOTP (RFC 6238 over RFC 4226 HOTP, HMAC-SHA1) — fully built
//    and proven here against the RFCs' own test vectors.
//  * Passkeys (WebAuthn) — the ASSERTION VERIFICATION is built and
//    fixture-proven here (challenge, rpId hash, UP flag, signature
//    counter monotonicity). The capture legs (Windows Hello /
//    Android Credential Manager prompts that produce assertions,
//    and attestation at registration) are platform surfaces that
//    land at the device gates; this layer stores the credential
//    public keys those legs produce and verifies what they sign.
//
// Replay discipline: a TOTP step, once accepted, can never be
// accepted again for that enrollment — acceptance is monotonic in
// the step counter, so a code observed in transit is dead the
// moment it is used, and an older code can never follow a newer
// one. Passkey signature counters are monotonic the same way
// (WebAuthn's clone detection).
// =====================================================================

/// <summary>RFC 4648 base32 (the otpauth secret encoding).</summary>
public static class Base32
{
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    public static string Encode(byte[] data)
    {
        var sb = new StringBuilder((data.Length * 8 + 4) / 5);
        int buffer = 0, bits = 0;
        foreach (var b in data)
        {
            buffer = (buffer << 8) | b;
            bits += 8;
            while (bits >= 5)
            {
                bits -= 5;
                sb.Append(Alphabet[(buffer >> bits) & 0x1F]);
            }
        }
        if (bits > 0) sb.Append(Alphabet[(buffer << (5 - bits)) & 0x1F]);
        return sb.ToString();
    }

    /// <summary>Tolerant decode: case-insensitive, spaces and
    /// padding ignored. Null on any character outside the alphabet
    /// or an impossible length — never a partial secret.</summary>
    public static byte[]? Decode(string? text)
    {
        if (text is null) return null;
        var clean = new string(text.Where(c => !char.IsWhiteSpace(c) && c != '=').ToArray()).ToUpperInvariant();
        if (clean.Length == 0) return null;
        var bytes = new List<byte>();
        int buffer = 0, bits = 0;
        foreach (var c in clean)
        {
            var v = Alphabet.IndexOf(c);
            if (v < 0) return null;
            buffer = (buffer << 5) | v;
            bits += 5;
            if (bits >= 8)
            {
                bits -= 8;
                bytes.Add((byte)(buffer >> bits));
            }
        }
        return bytes.ToArray();
    }
}

/// <summary>RFC 4226 HOTP + RFC 6238 TOTP (HMAC-SHA1, 30-second
/// step, T0 = unix epoch — the otpauth defaults every authenticator
/// app implements).</summary>
public static class Totp
{
    public const int StepSeconds = 30;
    public const int Digits = 6;

    public static long CounterFor(DateTimeOffset at, int stepSeconds = StepSeconds) =>
        at.ToUnixTimeSeconds() / stepSeconds;

    public static string Hotp(byte[] secret, long counter, int digits = Digits)
    {
        var counterBytes = new byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(counterBytes, counter);
        var hash = HMACSHA1.HashData(secret, counterBytes);
        var offset = hash[^1] & 0x0F;
        var binary = ((hash[offset] & 0x7F) << 24) | ((hash[offset + 1] & 0xFF) << 16) |
                     ((hash[offset + 2] & 0xFF) << 8) | (hash[offset + 3] & 0xFF);
        var mod = 1;
        for (var i = 0; i < digits; i++) mod *= 10;
        return (binary % mod).ToString($"D{digits}");
    }

    public static string At(byte[] secret, DateTimeOffset at, int digits = Digits) =>
        Hotp(secret, CounterFor(at), digits);

    /// <summary>Find the step whose code matches, searching
    /// ±windowSteps around the current step (clock-skew tolerance).
    /// Returns the matched counter, or null. Comparison is
    /// constant-time over the code bytes.</summary>
    public static long? MatchStep(byte[] secret, string? code, DateTimeOffset at, int windowSteps = 1)
    {
        if (string.IsNullOrWhiteSpace(code)) return null;
        var presented = code.Trim();
        var center = CounterFor(at);
        for (var step = center - windowSteps; step <= center + windowSteps; step++)
        {
            var candidate = Hotp(secret, step);
            if (CryptographicOperations.FixedTimeEquals(
                    Encoding.ASCII.GetBytes(candidate), Encoding.ASCII.GetBytes(presented)))
                return step;
        }
        return null;
    }
}

/// <summary>A TOTP enrollment. The secret exists in the store ONLY
/// sealed (ISecretProtector — DPAPI on Windows); the base32 form is
/// shown exactly once, at Begin, to the enrolling user.</summary>
public sealed record TotpEnrollment(
    string ScopeId, string UserId, string SealedSecretBase64,
    string State,               // "pending" | "active"
    DateTimeOffset CreatedUtc,
    long LastAcceptedStep);     // replay guard: monotonic, -1 = none yet

/// <summary>A stored passkey credential: the public half the
/// platform registration leg produced. Verification needs nothing
/// else — the private key never leaves the authenticator.</summary>
public sealed record PasskeyCredential(
    string ScopeId, string UserId, string CredentialIdBase64,
    string PublicKeyXBase64, string PublicKeyYBase64,
    uint SignCount, DateTimeOffset CreatedUtc);

public sealed record SecondFactorEvent(
    DateTimeOffset Utc, string Kind, string ScopeId, string UserId, string Detail);

/// <summary>The local second-factor store + verifiers. Every act
/// re-reads roster liveness (a removed or suspended user verifies
/// nothing, enrolls nothing); an AI user holds no factor (a factor
/// is a human's possession proof — D9's leash means an AI's acts
/// are authorized by scope and grant, never by a fake possession).
/// The feature gate (TOTAL POLICY CONTROL, key
/// "local_second_factor") is consulted when wired: a policy that
/// disables the factor refuses enrollment AND verification.</summary>
public sealed class SecondFactorService
{
    private readonly RosterService _roster;
    private readonly ISecretProtector _protector;
    private readonly Func<string, string, PolicyVerdict>? _featureGate;
    private readonly Action<string, string?, string>? _auditSink;
    private readonly Dictionary<string, TotpEnrollment> _totp = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, TotpEnrollment> _pending = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, PasskeyCredential> _passkeys = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<SecondFactorEvent> _events = new();
    private readonly object _gate = new();

    // ---- attempt throttling (Block H — the D38 F10 remainder) --
    // Verify/confirm attempts were bounded only by the TOTP step
    // window and passkey cryptography: nothing slowed a guesser.
    // Now: MaxConsecutiveFailures consecutive MATERIAL failures
    // lock verification for LockoutSeconds. During lockout the
    // locked path refuses WITHOUT examining material (a lockout
    // that still checked codes would remain an oracle, and a
    // correct code presented mid-lockout is refused like any
    // other — the standard, explainable posture). A success
    // resets the counter. The state persists (export/import) and
    // an import can only ever make it MORE restrictive.
    //
    // Throttle keys are PER PATH (Block H D38 fix F12): the TOTP
    // paths (verify, confirm, re-enrollment possession check)
    // share one key per (scope, user); passkey verification is
    // keyed per (scope, user, CREDENTIAL). The original single
    // shared key let anyone who could reach the passkey verifier
    // lock the victim's TOTP too — credential ids are public
    // (they travel in allowCredentials), so a spray of garbage
    // assertions was a 300-second denial of the victim's every
    // factor. Path-scoped keys confine a lockout to the path —
    // and the credential — actually under attack.
    public const int MaxConsecutiveFailures = 5;
    public const int LockoutSeconds = 300;
    private readonly Dictionary<string, (int Failures, DateTimeOffset LockedUntil)> _throttle = new(StringComparer.OrdinalIgnoreCase);

    private static string TotpThrottleKey(string scopeId, string userId) => Key(scopeId, userId) + "\ntotp";
    private static string PasskeyThrottleKey(string scopeId, string userId, string credentialId) =>
        Key(scopeId, userId, credentialId) + "\npasskey";

    private bool ThrottledLocked(string key, DateTimeOffset now) =>
        _throttle.TryGetValue(key, out var t) && t.LockedUntil > now;

    private void NoteFailureLocked(string key, string scopeId, string userId, DateTimeOffset now)
    {
        var t = _throttle.TryGetValue(key, out var cur) ? cur : (0, DateTimeOffset.MinValue);
        var failures = t.Item1 + 1;
        if (failures >= MaxConsecutiveFailures)
        {
            _throttle[key] = (0, now.AddSeconds(LockoutSeconds));
            RecordLocked("factor_throttled", scopeId, userId,
                $"Second-factor verification locked for {LockoutSeconds}s after {MaxConsecutiveFailures} consecutive failed attempts.");
        }
        else _throttle[key] = (failures, t.Item2);
    }

    private void NoteSuccessLocked(string key) => _throttle.Remove(key);

    // ---- passkey challenge binding (Block H — the D38 F12
    // remainder) -----------------------------------------------
    // The ceremony caller used to issue challenges itself, so the
    // service verified an assertion against a challenge it had
    // never seen — a captured assertion could be replayed under
    // any fresh caller-issued ceremony. Challenges are now issued
    // BY THE SERVICE: one outstanding challenge per (scope, user),
    // 300 s to live, and any verify attempt that PRESENTS the
    // issued challenge consumes it (success or failure — a failed
    // ceremony never leaves a reusable challenge behind). A
    // mismatched presentation consumes nothing (F12).
    // Challenges are ephemeral by design: export/import does NOT
    // carry them, so a restart invalidates in-flight ceremonies
    // (the client simply begins again).
    public const int ChallengeSeconds = 300;
    private readonly Dictionary<string, (string Challenge, DateTimeOffset ExpiresUtc)> _challenges = new(StringComparer.OrdinalIgnoreCase);

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=');

    /// <summary>Issue the challenge for a passkey ceremony. Only
    /// a live human with the feature allowed gets one; issuing
    /// replaces any outstanding challenge for the user (one
    /// ceremony at a time). Residual (F12, named): a caller who
    /// can reach this method can replace a victim's in-flight
    /// challenge — an annoyance that fails that one ceremony
    /// PRELIMINARY (no lockout, nothing burned that the victim
    /// cannot re-issue), not a factor lockout; the ceremony host
    /// is in-process, and challenge issuance is not an MCP or IPC
    /// surface in this build.</summary>
    public string? IssuePasskeyChallenge(string scopeId, string userId, DateTimeOffset? now = null)
    {
        if (!FeatureAllowed(scopeId)) return null;
        lock (_gate)
        {
            if (!LiveHuman(scopeId, userId)) return null;
            var at = now ?? DateTimeOffset.UtcNow;
            var challenge = Base64Url(RandomNumberGenerator.GetBytes(32));
            _challenges[Key(scopeId, userId)] = (challenge, at.AddSeconds(ChallengeSeconds));
            RecordLocked("passkey_challenge_issued", scopeId, userId,
                "Passkey challenge issued by the service (single-use, 300 s).");
            return challenge;
        }
    }

    /// <param name="featureGate">TOTAL POLICY CONTROL gate,
    /// SCOPE-AWARE (scopeId, featureKey) — D38 review F2.</param>
    /// <param name="auditSink">Optional chained-audit sink
    /// (kind, actor, detail) — D38 review F1.</param>
    public SecondFactorService(RosterService roster, ISecretProtector protector,
        Func<string, string, PolicyVerdict>? featureGate = null,
        Action<string, string?, string>? auditSink = null)
    {
        _roster = roster ?? throw new ArgumentNullException(nameof(roster));
        _protector = protector ?? throw new ArgumentNullException(nameof(protector));
        _featureGate = featureGate;
        _auditSink = auditSink;
    }

    public event Action? Changed;
    public IReadOnlyList<SecondFactorEvent> Events { get { lock (_gate) return _events.ToList(); } }

    private static string Key(string scopeId, string userId) => $"{scopeId}\n{userId}";
    private static string Key(string scopeId, string userId, string credentialId) => $"{scopeId}\n{userId}\n{credentialId}";

    private bool LiveHuman(string scopeId, string? userId)
    {
        if (string.IsNullOrWhiteSpace(userId)) return false;
        var user = _roster.GetUser(scopeId, userId);
        return user is not null && user.Kind == "human" && !user.Suspended;
    }

    private bool FeatureAllowed(string scopeId) =>
        _featureGate?.Invoke(scopeId, PolicyFeatures.LocalSecondFactor).Allowed ?? true;

    private void RecordLocked(string kind, string scopeId, string userId, string detail)
    {
        _events.Add(new SecondFactorEvent(DateTimeOffset.UtcNow, kind, scopeId, userId, detail));
        _auditSink?.Invoke(kind, userId, detail);
        Changed?.Invoke();
    }

    // ---- TOTP enrollment ------------------------------------------------

    /// <summary>Begin enrollment: mint a fresh 160-bit secret,
    /// store it sealed + PENDING (in the pending store, apart
    /// from any active factor), and return the base32 secret and
    /// otpauth URI for the user's authenticator app. This is the
    /// only moment the secret is visible. A pending enrollment
    /// verifies NOTHING until Confirm proves possession.
    ///
    /// Re-enrollment over an ACTIVE factor (D38 review F4) is a
    /// possession-gated act, exactly like removal: the caller
    /// must present a currently valid code for the EXISTING
    /// factor (verified, and its step consumed). Without it,
    /// Begin refuses — a hijacked session cannot replace the
    /// victim's factor with the attacker's secret. And the old
    /// factor stays ACTIVE until the new one confirms: there is
    /// no window in which the user has no working factor
    /// (HasActiveTotp never dips false mid-re-enrollment). The
    /// code-free recovery path is the admin's (RemoveTotpByAdmin,
    /// then Begin).</summary>
    public (string Base32Secret, string OtpAuthUri)? BeginTotpEnrollment(string scopeId, string userId,
        string? currentCode = null, DateTimeOffset? now = null)
    {
        if (!FeatureAllowed(scopeId)) return null;
        lock (_gate)
        {
            if (!LiveHuman(scopeId, userId)) return null;
            var key = Key(scopeId, userId);
            var tkey = TotpThrottleKey(scopeId, userId);
            if (_totp.TryGetValue(key, out var active))
            {
                var at = now ?? DateTimeOffset.UtcNow;
                if (ThrottledLocked(tkey, at))
                {
                    RecordLocked("totp_reenrollment_refused", scopeId, userId,
                        "Re-enrollment refused: factor verification is throttled (too many failed attempts).");
                    return null;
                }
                var activeSecret = SecretOf(active);
                var step = activeSecret is null || currentCode is null
                    ? null
                    : Totp.MatchStep(activeSecret, currentCode, at);
                if (step is null || step.Value <= active.LastAcceptedStep)
                {
                    NoteFailureLocked(tkey, scopeId, userId, at);
                    RecordLocked("totp_reenrollment_refused", scopeId, userId,
                        "Re-enrollment over an active factor refused: no valid current code presented.");
                    return null;
                }
                NoteSuccessLocked(tkey);
                _totp[key] = active with { LastAcceptedStep = step.Value };
                RecordLocked("totp_reenrollment_authorized", scopeId, userId,
                    "Re-enrollment authorized by a current code from the existing factor (step consumed).");
            }
            var secret = RandomNumberGenerator.GetBytes(20);
            var base32 = Base32.Encode(secret);
            _pending[key] = new TotpEnrollment(
                scopeId, userId, _protector.Protect(base32), "pending", DateTimeOffset.UtcNow, -1);
            RecordLocked("totp_enrollment_begun", scopeId, userId,
                "TOTP enrollment begun (pending possession proof).");
            var label = Uri.EscapeDataString($"DeskGuest:{userId}");
            var uri = $"otpauth://totp/{label}?secret={base32}&issuer=DeskGuest&digits={Totp.Digits}&period={Totp.StepSeconds}";
            return (base32, uri);
        }
    }

    /// <summary>Confirm enrollment with a current code: possession
    /// proven → the pending enrollment goes ACTIVE (replacing any
    /// previous active factor at this single moment) and the
    /// confirming step is consumed (it can never be replayed as a
    /// verification).</summary>
    public bool ConfirmTotpEnrollment(string scopeId, string userId, string code, DateTimeOffset now)
    {
        if (!FeatureAllowed(scopeId)) return false;
        lock (_gate)
        {
            if (!LiveHuman(scopeId, userId)) return false;
            var key = Key(scopeId, userId);
            var tkey = TotpThrottleKey(scopeId, userId);
            if (!_pending.TryGetValue(key, out var e)) return false;
            if (ThrottledLocked(tkey, now)) return false;
            var secret = SecretOf(e);
            if (secret is null) return false;
            var step = Totp.MatchStep(secret, code, now);
            if (step is null) { NoteFailureLocked(tkey, scopeId, userId, now); return false; }
            NoteSuccessLocked(tkey);
            _pending.Remove(key);
            _totp[key] = e with { State = "active", LastAcceptedStep = step.Value };
            RecordLocked("totp_enrollment_confirmed", scopeId, userId, "TOTP enrollment confirmed and active.");
            return true;
        }
    }

    /// <summary>Verify a step-up code. Active enrollments only;
    /// the matched step must be NEWER than every previously
    /// accepted step (replay + out-of-order refusal); a successful
    /// verification consumes the step.</summary>
    public bool VerifyTotp(string scopeId, string userId, string code, DateTimeOffset now)
    {
        if (!FeatureAllowed(scopeId)) return false;
        lock (_gate)
        {
            if (!LiveHuman(scopeId, userId)) return false;
            if (!_totp.TryGetValue(Key(scopeId, userId), out var e) || e.State != "active") return false;
            if (ThrottledLocked(TotpThrottleKey(scopeId, userId), now)) return false;
            var secret = SecretOf(e);
            if (secret is null) return false;
            var step = Totp.MatchStep(secret, code, now);
            if (step is null || step.Value <= e.LastAcceptedStep)
            {
                NoteFailureLocked(TotpThrottleKey(scopeId, userId), scopeId, userId, now);
                return false; // replay / stale / wrong code
            }
            NoteSuccessLocked(TotpThrottleKey(scopeId, userId));
            _totp[Key(scopeId, userId)] = e with { LastAcceptedStep = step.Value };
            RecordLocked("totp_verified", scopeId, userId, "TOTP step-up verified.");
            return true;
        }
    }

    /// <summary>Self-removal: requires a currently valid code (which
    /// is consumed by the check) — possession proves the removal is
    /// the owner's act, not a session hijack's.</summary>
    public bool RemoveTotp(string scopeId, string userId, string code, DateTimeOffset now)
    {
        lock (_gate)
        {
            if (!_totp.ContainsKey(Key(scopeId, userId))) return false;
            if (!VerifyTotp(scopeId, userId, code, now)) return false;
            lock (_gate)
            {
                _totp.Remove(Key(scopeId, userId));
                RecordLocked("totp_removed", scopeId, userId, "TOTP factor removed by its owner (code-verified).");
            }
            return true;
        }
    }

    /// <summary>Admin removal (the lost-device recovery path): a
    /// live company admin of the scope may remove another user's
    /// factor without a code. The act is recorded with the admin as
    /// actor — recovery is possible, never silent.</summary>
    public bool RemoveTotpByAdmin(string scopeId, string targetUserId, string adminUserId)
    {
        lock (_gate)
        {
            if (!_roster.IsCompanyAdmin(scopeId, adminUserId) || !LiveHuman(scopeId, adminUserId)) return false;
            if (!_totp.Remove(Key(scopeId, targetUserId))) return false;
            RecordLocked("totp_removed_by_admin", scopeId, targetUserId,
                $"TOTP factor removed by company admin {adminUserId} (recovery path).");
            return true;
        }
    }

    public bool HasActiveTotp(string scopeId, string userId)
    {
        lock (_gate)
            return _totp.TryGetValue(Key(scopeId, userId), out var e) && e.State == "active";
    }

    /// <summary>Store counts for snapshot facts: active TOTP
    /// enrollments and registered passkeys. Counts only — never
    /// which users, never any factor material.</summary>
    public (int TotpActive, int Passkeys) Counts()
    {
        lock (_gate)
            return (_totp.Values.Count(e => e.State == "active"), _passkeys.Count);
    }

    private byte[]? SecretOf(TotpEnrollment e)
    {
        try { return Base32.Decode(_protector.Unprotect(e.SealedSecretBase64)); }
        catch { return null; }
    }

    // ---- Passkeys (WebAuthn assertion verification) ----------------------

    /// <summary>Store a credential the platform registration leg
    /// produced. The model validates shape only (a P-256 point that
    /// parses); attestation is the platform leg's job and is not
    /// claimed here.</summary>
    public bool RegisterPasskey(string scopeId, string userId, string credentialIdBase64,
        string publicKeyXBase64, string publicKeyYBase64)
    {
        if (!FeatureAllowed(scopeId)) return false;
        lock (_gate)
        {
            if (!LiveHuman(scopeId, userId)) return false;
            byte[] x, y;
            try
            {
                if (string.IsNullOrWhiteSpace(credentialIdBase64)) return false;
                Convert.FromBase64String(credentialIdBase64);
                x = Convert.FromBase64String(publicKeyXBase64);
                y = Convert.FromBase64String(publicKeyYBase64);
            }
            catch { return false; }
            if (x.Length != 32 || y.Length != 32) return false; // P-256 coordinates
            try
            {
                using var probe = ECDsa.Create(new ECParameters
                {
                    Curve = ECCurve.NamedCurves.nistP256,
                    Q = new ECPoint { X = x, Y = y },
                });
            }
            catch { return false; } // not a point on the curve
            _passkeys[Key(scopeId, userId, credentialIdBase64)] = new PasskeyCredential(
                scopeId, userId, credentialIdBase64, publicKeyXBase64, publicKeyYBase64, 0, DateTimeOffset.UtcNow);
            RecordLocked("passkey_registered", scopeId, userId, "Passkey credential registered (platform attestation leg).");
            return true;
        }
    }

    /// <summary>How a passkey attempt ended, for the throttle:
    /// only MATERIAL failures count toward the lockout — an
    /// attempt that presented the outstanding SERVICE-ISSUED
    /// challenge for a real credential (i.e. the caller held the
    /// ceremony) and then failed the cryptographic checks.
    /// Preliminary failures (unknown credential, dead user,
    /// malformed ceremony, and — Block H D38 fix F12 — a
    /// challenge that does not match the issued one) do not
    /// count and do not consume the challenge: credential ids
    /// are public, so counting unmatched-challenge garbage would
    /// let a stranger burn the victim's in-flight ceremony and
    /// lock their factor by spraying at it. The earlier comment
    /// here claimed exactly that safety while the code counted a
    /// challenge mismatch as material; the code now matches the
    /// claim.</summary>
    private enum PasskeyAttempt { Verified, FailedMaterial, FailedPreliminary }

    /// <summary>Verify a WebAuthn assertion (the get() ceremony):
    /// clientData type + challenge + origin host, authenticatorData
    /// rpIdHash + user-presence flag, signature over
    /// authData || SHA256(clientDataJson) under the stored P-256
    /// key, and signature-counter monotonicity (a counter that
    /// fails to advance when both sides track one is a cloned
    /// authenticator — refused and recorded). Any failure refuses;
    /// nothing about the failure is distinguishable to the caller
    /// beyond the recorded event kind.
    ///
    /// The challenge is SERVICE-ISSUED (Block H): it must be the
    /// outstanding challenge from IssuePasskeyChallenge for this
    /// user; presenting it consumes it, while a mismatched
    /// presentation neither consumes it nor counts toward the
    /// throttle (D38 fix F12) —
    /// <paramref name="expectedChallengeBase64Url"/> is now the
    /// caller's statement of which ceremony it ran, checked
    /// against the issued record like everything else.</summary>
    public bool VerifyPasskeyAssertion(string scopeId, string userId, string credentialIdBase64,
        byte[] authenticatorData, string clientDataJson, byte[] signature,
        string expectedChallengeBase64Url, string rpId, DateTimeOffset? now = null)
    {
        if (!FeatureAllowed(scopeId)) return false;
        lock (_gate)
        {
            var key = PasskeyThrottleKey(scopeId, userId, credentialIdBase64);
            var at = now ?? DateTimeOffset.UtcNow;
            if (ThrottledLocked(key, at)) return false;
            var attempt = VerifyPasskeyAssertionInner(scopeId, userId, credentialIdBase64,
                authenticatorData, clientDataJson, signature, expectedChallengeBase64Url, rpId, at);
            switch (attempt)
            {
                case PasskeyAttempt.Verified: NoteSuccessLocked(key); return true;
                case PasskeyAttempt.FailedMaterial: NoteFailureLocked(key, scopeId, userId, at); return false;
                default: return false;
            }
        }
    }

    private PasskeyAttempt VerifyPasskeyAssertionInner(string scopeId, string userId, string credentialIdBase64,
        byte[] authenticatorData, string clientDataJson, byte[] signature,
        string expectedChallengeBase64Url, string rpId, DateTimeOffset now)
    {
        lock (_gate)
        {
            if (!LiveHuman(scopeId, userId)) return PasskeyAttempt.FailedPreliminary;
            if (!_passkeys.TryGetValue(Key(scopeId, userId, credentialIdBase64), out var cred)) return PasskeyAttempt.FailedPreliminary;
            if (authenticatorData is null || authenticatorData.Length < 37 || signature is null) return PasskeyAttempt.FailedPreliminary;
            try
            {
                using var doc = JsonDocument.Parse(clientDataJson);
                var root = doc.RootElement;
                if (root.GetProperty("type").GetString() != "webauthn.get") return PasskeyAttempt.FailedPreliminary;
                // Challenge binding (Block H; DoS shape per D38
                // fix F12): the presented challenge must be the
                // outstanding SERVICE-ISSUED challenge for this
                // user, unexpired. A MISMATCH is preliminary: it
                // neither consumes the issued challenge nor counts
                // toward the lockout — the presenter demonstrably
                // does not hold this ceremony (a stranger spraying
                // garbage with a public credential id must not be
                // able to burn the victim's in-flight challenge).
                // A MATCH consumes the challenge on the spot —
                // success or failure, a challenge that was actually
                // presented never survives the attempt.
                var presented = root.GetProperty("challenge").GetString();
                var challengeKey = Key(scopeId, userId);
                var hasIssued = _challenges.TryGetValue(challengeKey, out var issued);
                if (!hasIssued || issued.ExpiresUtc <= now ||
                    presented is null ||
                    presented.Length != issued.Challenge.Length ||
                    !CryptographicOperations.FixedTimeEquals(
                        Encoding.ASCII.GetBytes(presented), Encoding.ASCII.GetBytes(issued.Challenge)) ||
                    !string.Equals(expectedChallengeBase64Url, issued.Challenge, StringComparison.Ordinal))
                    return PasskeyAttempt.FailedPreliminary;
                _challenges.Remove(challengeKey);
                var origin = root.GetProperty("origin").GetString() ?? "";
                if (!Uri.TryCreate(origin, UriKind.Absolute, out var originUri) ||
                    !string.Equals(originUri.Host, rpId, StringComparison.OrdinalIgnoreCase))
                    return PasskeyAttempt.FailedMaterial;
            }
            catch { return PasskeyAttempt.FailedPreliminary; }

            var expectedRpHash = SHA256.HashData(Encoding.UTF8.GetBytes(rpId));
            if (!CryptographicOperations.FixedTimeEquals(expectedRpHash, authenticatorData.AsSpan(0, 32)))
                return PasskeyAttempt.FailedMaterial;
            var flags = authenticatorData[32];
            if ((flags & 0x01) == 0) return PasskeyAttempt.FailedMaterial; // user presence bit must be set
            var signCount = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(authenticatorData.AsSpan(33, 4));
            if ((cred.SignCount > 0 || signCount > 0) && signCount <= cred.SignCount)
            {
                RecordLocked("passkey_counter_refused", scopeId, userId,
                    "Passkey signature counter did not advance — possible cloned authenticator; refused.");
                return PasskeyAttempt.FailedMaterial;
            }
            var clientHash = SHA256.HashData(Encoding.UTF8.GetBytes(clientDataJson));
            var signed = new byte[authenticatorData.Length + clientHash.Length];
            authenticatorData.CopyTo(signed, 0);
            clientHash.CopyTo(signed, authenticatorData.Length);
            bool ok;
            try
            {
                using var ecdsa = ECDsa.Create(new ECParameters
                {
                    Curve = ECCurve.NamedCurves.nistP256,
                    Q = new ECPoint
                    {
                        X = Convert.FromBase64String(cred.PublicKeyXBase64),
                        Y = Convert.FromBase64String(cred.PublicKeyYBase64),
                    },
                });
                ok = ecdsa.VerifyData(signed, signature, HashAlgorithmName.SHA256,
                    DSASignatureFormat.Rfc3279DerSequence);
            }
            catch { return PasskeyAttempt.FailedMaterial; }
            if (!ok) return PasskeyAttempt.FailedMaterial;
            _passkeys[Key(scopeId, userId, credentialIdBase64)] = cred with { SignCount = signCount };
            RecordLocked("passkey_verified", scopeId, userId, "Passkey assertion verified.");
            return PasskeyAttempt.Verified;
        }
    }

    public bool RemovePasskey(string scopeId, string userId, string credentialIdBase64, string actorUserId)
    {
        lock (_gate)
        {
            var self = string.Equals(actorUserId, userId, StringComparison.OrdinalIgnoreCase) && LiveHuman(scopeId, actorUserId);
            var admin = _roster.IsCompanyAdmin(scopeId, actorUserId) && LiveHuman(scopeId, actorUserId);
            if (!self && !admin) return false;
            if (!_passkeys.Remove(Key(scopeId, userId, credentialIdBase64))) return false;
            RecordLocked("passkey_removed", scopeId, userId, $"Passkey removed by {actorUserId}.");
            return true;
        }
    }

    // ---- persistence ------------------------------------------------------

    private sealed record TotpDto(string ScopeId, string UserId, string SealedSecretBase64,
        string State, DateTimeOffset CreatedUtc, long LastAcceptedStep);
    private sealed record PasskeyDto(string ScopeId, string UserId, string CredentialIdBase64,
        string PublicKeyXBase64, string PublicKeyYBase64, uint SignCount, DateTimeOffset CreatedUtc);
    private sealed record EventDto(DateTimeOffset Utc, string Kind, string ScopeId,
        string UserId, string Detail);
    private sealed record ThrottleDto(string ScopeId, string UserId, int Failures,
        DateTimeOffset LockedUntil);
    private sealed record StoreDto(TotpDto[] Totp, PasskeyDto[] Passkeys, EventDto[]? Events,
        ThrottleDto[]? Throttle = null);

    /// <summary>Serialize the factor store. TOTP secrets travel
    /// ONLY in their sealed form — the export of an unsealed secret
    /// is unrepresentable here. The event history travels too
    /// (D38 review F1: the acts are part of the record).</summary>
    public string ExportJson()
    {
        lock (_gate)
        {
            var store = new StoreDto(
                _totp.Values.Concat(_pending.Values).Select(e => new TotpDto(e.ScopeId, e.UserId,
                    e.SealedSecretBase64, e.State, e.CreatedUtc, e.LastAcceptedStep)).ToArray(),
                _passkeys.Values.Select(c => new PasskeyDto(c.ScopeId, c.UserId, c.CredentialIdBase64,
                    c.PublicKeyXBase64, c.PublicKeyYBase64, c.SignCount, c.CreatedUtc)).ToArray(),
                _events.Select(e => new EventDto(e.Utc, e.Kind, e.ScopeId, e.UserId, e.Detail)).ToArray(),
                _throttle.Select(kv =>
                {
                    var parts = kv.Key.Split('\n', 2);
                    return new ThrottleDto(parts[0], parts.Length > 1 ? parts[1] : "",
                        kv.Value.Failures, kv.Value.LockedUntil);
                }).ToArray());
            return JsonSerializer.Serialize(store);
        }
    }

    /// <summary>Restore. Re-validated, never trusted: entries for
    /// users who are not live humans of the scope are dropped,
    /// unknown states are dropped, malformed key material is
    /// dropped, and a TOTP enrollment whose sealed secret no longer
    /// unseals is dropped (it could never verify — keeping it would
    /// present a factor that silently always fails).</summary>
    public int ImportJson(string json)
    {
        StoreDto? store;
        try { store = JsonSerializer.Deserialize<StoreDto>(json); }
        catch { return 0; }
        if (store is null) return 0;
        var restored = 0;
        lock (_gate)
        {
            // Throttle state (Block H): merged, never cleared —
            // an import takes the MORE restrictive of stored vs
            // in-memory (max failures, max lockout), so restoring
            // a store can never launder away a live lockout.
            foreach (var dto in store.Throttle ?? Array.Empty<ThrottleDto>())
            {
                if (dto is null || string.IsNullOrWhiteSpace(dto.ScopeId) ||
                    string.IsNullOrWhiteSpace(dto.UserId)) continue;
                var key = Key(dto.ScopeId, dto.UserId);
                if (_throttle.TryGetValue(key, out var cur))
                    _throttle[key] = (Math.Max(cur.Failures, dto.Failures),
                                      cur.LockedUntil > dto.LockedUntil ? cur.LockedUntil : dto.LockedUntil);
                else
                    _throttle[key] = (dto.Failures, dto.LockedUntil);
            }
            foreach (var dto in store.Events ?? Array.Empty<EventDto>())
            {
                if (dto is null || string.IsNullOrWhiteSpace(dto.Kind)) continue;
                _events.Add(new SecondFactorEvent(dto.Utc, dto.Kind, dto.ScopeId, dto.UserId, dto.Detail ?? ""));
            }
            foreach (var dto in store.Totp ?? Array.Empty<TotpDto>())
            {
                if (dto is null || !LiveHuman(dto.ScopeId, dto.UserId)) continue;
                if (dto.State is not ("pending" or "active")) continue;
                var target = dto.State == "active" ? _totp : _pending;
                if (target.ContainsKey(Key(dto.ScopeId, dto.UserId))) continue;
                // D38 review F10: the stored replay counter is
                // UNTRUSTED — a hand-edited store must not roll
                // it back and resurrect used codes. An imported
                // ACTIVE enrollment's floor is the CURRENT step:
                // codes for steps at or before the import moment
                // can never verify again; only future codes work.
                var lastStep = dto.State == "active"
                    ? Math.Max(dto.LastAcceptedStep, Totp.CounterFor(DateTimeOffset.UtcNow))
                    : dto.LastAcceptedStep;
                var e = new TotpEnrollment(dto.ScopeId, dto.UserId, dto.SealedSecretBase64,
                    dto.State, dto.CreatedUtc, lastStep);
                if (SecretOf(e) is null) continue;
                target[Key(dto.ScopeId, dto.UserId)] = e;
                restored++;
            }
            foreach (var dto in store.Passkeys ?? Array.Empty<PasskeyDto>())
            {
                if (dto is null || !LiveHuman(dto.ScopeId, dto.UserId)) continue;
                if (_passkeys.ContainsKey(Key(dto.ScopeId, dto.UserId, dto.CredentialIdBase64))) continue;
                byte[] x, y;
                try
                {
                    Convert.FromBase64String(dto.CredentialIdBase64);
                    x = Convert.FromBase64String(dto.PublicKeyXBase64);
                    y = Convert.FromBase64String(dto.PublicKeyYBase64);
                }
                catch { continue; }
                if (x.Length != 32 || y.Length != 32) continue;
                // D38 review F10: the same on-curve probe
                // RegisterPasskey runs — import does not skip it.
                try
                {
                    using var probe = ECDsa.Create(new ECParameters
                    {
                        Curve = ECCurve.NamedCurves.nistP256,
                        Q = new ECPoint { X = x, Y = y },
                    });
                }
                catch { continue; }
                _passkeys[Key(dto.ScopeId, dto.UserId, dto.CredentialIdBase64)] = new PasskeyCredential(
                    dto.ScopeId, dto.UserId, dto.CredentialIdBase64, dto.PublicKeyXBase64,
                    dto.PublicKeyYBase64, dto.SignCount, dto.CreatedUtc);
                restored++;
            }
        }
        return restored;
    }
}
