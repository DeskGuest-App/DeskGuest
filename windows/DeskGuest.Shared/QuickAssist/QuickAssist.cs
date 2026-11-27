using System.Security.Cryptography;
using System.Text;

namespace DeskGuest.Shared.QuickAssist;

// =====================================================================
// Quick assist (D24, Block F): one-off help rides SESSION CODES
// (D22's one-off path, SCAM-12 hygiene). A code is:
//  * single-use — a successful redeem consumes it, forever;
//  * short-lived — 10 minutes by default;
//  * view-only bound — a quick-assist grant can never carry
//    control; full control is the portable helper's own session
//    act on the helped machine, never this code's grant;
//  * burn-protected — failed redeem attempts count; after the
//    threshold the mint locks for a cooldown, so code guessing
//    burns the channel, not just the code (the SCAM-12 / pairing
//    attempt-burn pattern);
//  * dead on close — closing the session burns the grant; a code
//    or grant replayed after close refuses.
// Only the code's HASH is stored. The code itself is shown once,
// on the helped machine (portable helper) or by the operator who
// minted it — the same display discipline as enrollment codes.
// Helper impersonation defense: the grant is bound at redeem to a
// client binding hash the redeeming side generates and keeps; a
// grant presented with a different binding refuses. Knowing a
// code after its single use buys an impersonator nothing.
// =====================================================================

public sealed record QuickAssistGrant(
    string GrantId, string CodeId, string ScopeId, string HostDeviceId,
    string InitiatorUserId, bool ViewOnly, DateTimeOffset GrantedUtc, DateTimeOffset ExpiresUtc);

public sealed class QuickAssistService
{
    public const string Alphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
    public static readonly TimeSpan DefaultTtl = TimeSpan.FromMinutes(10);
    public const int MaxFailedAttempts = 5;
    public static readonly TimeSpan Lockout = TimeSpan.FromMinutes(10);
    /// <summary>Quick-assist grants are view-only BY CONSTRUCTION:
    /// this constant is the grant's only capability.</summary>
    public const bool GrantViewOnly = true;

    private sealed class CodeState
    {
        public required string Id;
        public required string CodeHash;
        public required string ScopeId;
        public required string HostDeviceId;
        public required string InitiatorUserId;
        public required DateTimeOffset ExpiresUtc;
        public bool Used;
        public bool Closed;
        public string? GrantId;
    }

    private sealed class GrantState
    {
        public required QuickAssistGrant Grant;
        public required string TokenHash;
        public required string ClientBindingHash;
        public bool Closed;
    }

    private readonly Dictionary<string, CodeState> _codes = new();
    private readonly Dictionary<string, GrantState> _grants = new();
    private readonly object _gate = new();
    // bd-shared-plat-2/F7: failure discipline is PER CLIENT
    // BINDING, not service-wide — five junk redeems from one
    // binding lock THAT binding, never every user's quick assist.
    private readonly Dictionary<string, (int Failures, DateTimeOffset LockedUntil)> _attemptsByBinding =
        new(StringComparer.Ordinal);
    /// <summary>bd-shared-plat-2/F7: a grant's own session
    /// lifetime, independent of the code's 10-minute mint window —
    /// a session no longer dies minutes after the code was minted.
    /// Close still kills it instantly.</summary>
    public static readonly TimeSpan GrantLifetime = TimeSpan.FromHours(8);

    private static string Hash(string s) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(s))).ToLowerInvariant();

    public static string Normalize(string? code) =>
        (code ?? "").Trim().ToUpperInvariant().Replace("-", "").Replace(" ", "");

    public static bool IsWellFormed(string? code)
    {
        var n = Normalize(code);
        return n.Length == 8 && n.All(c => Alphabet.Contains(c));
    }

    /// <summary>Mint a session code bound to (scope, host device,
    /// initiator). Returns the code ONCE for display; only its hash
    /// is kept.</summary>
    public string Mint(string scopeId, string hostDeviceId, string initiatorUserId, DateTimeOffset now, TimeSpan? ttl = null)
    {
        var chars = new char[8];
        // bd-shared-plat-2/F7: unbiased selection (GetInt32), not
        // bytes % 31, which skewed the alphabet distribution.
        for (var i = 0; i < 8; i++) chars[i] = Alphabet[RandomNumberGenerator.GetInt32(Alphabet.Length)];
        var code = new string(chars);
        lock (_gate)
        {
            // bd-shared-plat-2/F7: prune expired codes and
            // closed/expired grants at mint — the stores no longer
            // grow without bound.
            foreach (var dead in _codes.Where(kv => now > kv.Value.ExpiresUtc).Select(kv => kv.Key).ToList())
                _codes.Remove(dead);
            foreach (var dead in _grants.Where(kv => kv.Value.Closed || now > kv.Value.Grant.ExpiresUtc).Select(kv => kv.Key).ToList())
                _grants.Remove(dead);
            _codes[Hash(code)] = new CodeState
            {
                Id = Guid.NewGuid().ToString("N"),
                CodeHash = Hash(code),
                ScopeId = scopeId,
                HostDeviceId = hostDeviceId,
                InitiatorUserId = initiatorUserId,
                ExpiresUtc = now + (ttl ?? DefaultTtl),
            };
        }
        return code[..4] + "-" + code[4..];
    }

    /// <summary>Redeem a code for a VIEW-ONLY grant. The redeeming
    /// side presents a client binding (a hash of a secret it keeps);
    /// the grant answers only to that binding afterwards.</summary>
    public (bool Ok, string Detail, QuickAssistGrant? Grant, string? GrantToken) Redeem(
        string? code, string clientBinding, DateTimeOffset now)
    {
        var bindingKey = Hash(clientBinding ?? "");
        lock (_gate)
        {
            if (IsLockedLocked(bindingKey, now))
                return (false, "quick assist is locked for this client after failed attempts — try again later (attempt burn, per client binding)", null, null);
            if (!IsWellFormed(code))
            { RegisterFailure(bindingKey, now); return (false, "not a quick-assist code", null, null); }
            if (!_codes.TryGetValue(Hash(Normalize(code)), out var state))
            { RegisterFailure(bindingKey, now); return (false, "unknown code", null, null); }
            if (state.Closed) return (false, "this code's session is closed — the code is dead", null, null);
            if (state.Used) return (false, "this code was already used — codes work once", null, null);
            if (now > state.ExpiresUtc) return (false, "this code has expired", null, null);
            if (string.IsNullOrWhiteSpace(clientBinding))
                return (false, "a client binding is required", null, null);
            state.Used = true;
            _attemptsByBinding.Remove(bindingKey);
            var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
            var grant = new QuickAssistGrant(
                Guid.NewGuid().ToString("N"), state.Id, state.ScopeId, state.HostDeviceId,
                state.InitiatorUserId, GrantViewOnly, now, now + GrantLifetime);
            _grants[grant.GrantId] = new GrantState
            {
                Grant = grant, TokenHash = Hash(token), ClientBindingHash = Hash(clientBinding),
            };
            state.GrantId = grant.GrantId;
            return (true, "view-only grant issued (quick assist never grants control)", grant, token);
        }
    }

    /// <summary>Validate a grant presentation: token + the binding
    /// it was issued to. A grant replayed after close, after expiry,
    /// or from a different binding refuses.</summary>
    public (bool Ok, string Detail, QuickAssistGrant? Grant) Validate(string? grantId, string? grantToken, string clientBinding, DateTimeOffset now)
    {
        lock (_gate)
        {
            if (grantId is null || !_grants.TryGetValue(grantId, out var g))
                return (false, "unknown grant", null);
            if (g.Closed) return (false, "grant closed — the session is over", null);
            if (now > g.Grant.ExpiresUtc) return (false, "grant expired", null);
            if (grantToken is null || !FixedEq(g.TokenHash, Hash(grantToken)))
                return (false, "grant token mismatch", null);
            if (!FixedEq(g.ClientBindingHash, Hash(clientBinding ?? "")))
                return (false, "grant binding mismatch — this grant answers only to the side that redeemed it", null);
            return (true, "grant valid (view-only)", g.Grant);
        }
    }

    /// <summary>Close: the code AND its grant die together. Nothing
    /// about a closed quick-assist session can be replayed.</summary>
    /// <summary>Close by the DISPLAY code (the portable helper's
    /// exit path: when the helper closes, its code dies with it —
    /// the helper knows the code it showed, not internal ids).</summary>
    public bool CloseCode(string? displayCode)
    {
        var hash = Hash(Normalize(displayCode));
        lock (_gate)
        {
            var closed = false;
            foreach (var c in _codes.Values.Where(c => c.CodeHash == hash))
            {
                c.Closed = true; closed = true;
                foreach (var g in _grants.Values.Where(g => g.Grant.CodeId == c.Id)) g.Closed = true;
            }
            return closed;
        }
    }

    public bool Close(string codeIdOrGrantId)
    {
        lock (_gate)
        {
            var closed = false;
            foreach (var c in _codes.Values.Where(c => c.Id == codeIdOrGrantId || c.GrantId == codeIdOrGrantId))
            { c.Closed = true; closed = true; }
            foreach (var g in _grants.Values.Where(g => g.Grant.GrantId == codeIdOrGrantId || g.Grant.CodeId == codeIdOrGrantId))
            { g.Closed = true; closed = true; }
            return closed;
        }
    }

    /// <summary>BD-ENTERPRISE-DOCS F2: close a grant on the
    /// redeeming client's own authority — the one-time grant token
    /// issued at redeem PLUS the client binding the grant answers
    /// to. The web front door holds no mesh bearer credential, so
    /// its close must prove possession of what redeem issued; a
    /// copied grant id alone (the pre-fix close body) closes
    /// nothing here. Validation runs first and is not consumed by
    /// the close attempt: a wrong token or binding leaves the grant
    /// alive and unclosed.</summary>
    public (bool Ok, string Detail) CloseWithBinding(string? grantId, string? grantToken, string clientBinding, DateTimeOffset now)
    {
        var (ok, detail, _) = Validate(grantId, grantToken, clientBinding, now);
        if (!ok) return (false, detail);
        return Close(grantId!) ? (true, "grant closed by its redeeming client") : (false, "grant could not be closed");
    }

    /// <summary>bd-shared-plat-2/F7: lock state is per client
    /// binding. With no binding named, reports whether ANY binding
    /// is currently locked (diagnostics).</summary>
    public bool IsLocked(DateTimeOffset now, string? clientBinding = null)
    {
        lock (_gate)
            return clientBinding is null
                ? _attemptsByBinding.Values.Any(a => now < a.LockedUntil)
                : IsLockedLocked(Hash(clientBinding), now);
    }

    public int FailedAttempts(string? clientBinding = null)
    {
        lock (_gate)
            return clientBinding is null
                ? _attemptsByBinding.Values.Sum(a => a.Failures)
                : _attemptsByBinding.TryGetValue(Hash(clientBinding), out var a) ? a.Failures : 0;
    }

    private bool IsLockedLocked(string bindingKey, DateTimeOffset now) =>
        _attemptsByBinding.TryGetValue(bindingKey, out var a) && now < a.LockedUntil;

    private void RegisterFailure(string bindingKey, DateTimeOffset now)
    {
        var a = _attemptsByBinding.TryGetValue(bindingKey, out var cur) ? cur : (0, DateTimeOffset.MinValue);
        a.Item1++;
        if (a.Item1 >= MaxFailedAttempts)
        {
            a.Item2 = now + Lockout;
            a.Item1 = 0;
        }
        _attemptsByBinding[bindingKey] = a;
    }

    private static bool FixedEq(string a, string b) =>
        CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(a), Encoding.UTF8.GetBytes(b));
}
