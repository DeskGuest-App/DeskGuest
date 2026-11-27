using System.Security.Cryptography;
using System.Text.Json;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.Security;

namespace DeskGuest.Shared.VendorAccess;

// =====================================================================
// RMM-23 (item 1) — Privileged access passes for vendors.
//
// A pass lets an OUTSIDE VENDOR into a SPECIFIC device (or device
// group) for a BOUNDED time, under DeskGuest's full presence/audit rules.
// The pass changes WHO may connect and HOW LONG — it never changes
// the consent floor: a vendor session is a session, with presence,
// STOP and the hash-chained audit exactly as for any other session.
//
// Doctrine carried from the register + the lane assignment:
//   * A pass is NOT a pairing. It reuses the pairing/expiry
//     MACHINERY (one-time presentation, SHA-256 token hash at rest,
//     fail-closed authenticate) with a vendor-shaped, NARROWER
//     scope: named vendor identity, explicit device/group scope,
//     session scopes only. A pass can never carry admin,
//     background-tools, backstage or unlock rights — those scopes
//     are refused at issue, by construction, not by convention.
//   * DURATION RULE (named): VendorPassDurationRule.RefuseOutside-
//     Bounds. A requested lifetime under 48h or over 30d REFUSES at
//     issue — it is never silently clamped, because clamping would
//     change the issuer's stated intent without a decision. The
//     bounds are the register's (48h–30d).
//   * NO SILENT EXTENSION: there is no extend operation. Extending
//     a pass is issuing a NEW pass — a new audited decision by a
//     named issuer. ExtendPass exists only to refuse by name.
//   * REVOCATION KILLS LIVE SESSIONS: the store tracks the live
//     session ids bound to each pass; revocation returns them so
//     the service layer tears those sessions down through the
//     session layer's own teardown. A revoked/expired pass
//     authenticates NOTHING, including mid-session re-checks.
//   * CREDENTIAL INJECTION, and its boundary with the NEVER rule:
//     FEATURES §6/§8 forbid an AI (and any operator) from TYPING or
//     READING credential-class material — the credential-field
//     refusal. Injection is a different mechanism entirely: the DeskGuest
//     HOST's own vault code retrieves the credential and the DeskGuest
//     SESSION LAYER presents it to the target's logon surface. The
//     vendor never receives the credential value — not in the pass,
//     not in the token, not in any receipt, audit entry, session
//     event or error path. The value moves vault → session-layer
//     sink inside host code; no human or AI types it and no caller
//     of the injection API ever sees it. VaultCredentialHandle makes
//     that structural: the only consumer is the sink callback.
//   * AUDIT: every lifecycle act (issue, authenticate success AND
//     failure, session bind/unbind, injection, revocation, refused
//     extension/escalation) lands in the pass's own audit trail AND
//     (service layer) the hash-chained ledger. Audit text carries
//     the credential REFERENCE id only — never a value.
//   * POLICY: the whole feature is RMM-07 policy content under the
//     seeded toggle rmm.vendor_passes.enabled (TOTAL POLICY
//     CONTROL). The service layer enforces it; the store is the
//     mechanism underneath.
// =====================================================================

/// <summary>TOTAL POLICY CONTROL keys for RMM-23 item 1.</summary>
public static class VendorPassPolicyKeys
{
    /// <summary>The seeded RMM-07 registry toggle (default ON).</summary>
    public const string Enabled = "rmm.vendor_passes.enabled";
}

/// <summary>Named bounds for vendor passes. Every bound refuses by
/// name — none is a hidden constant.</summary>
public static class VendorPassLimits
{
    /// <summary>Register bound: the shortest pass is 48 hours.</summary>
    public static readonly TimeSpan MinDuration = TimeSpan.FromHours(48);
    /// <summary>Register bound: the longest pass is 30 days.</summary>
    public static readonly TimeSpan MaxDuration = TimeSpan.FromDays(30);
    public const int MaxDevicesPerPass = 256;
    public const int MaxGroupsPerPass = 64;
    public const int MaxIdLength = 128;
    public const int MaxNameLength = 256;
    /// <summary>D38 F12: per-pass audit trails are bounded — a token
    /// holder must not be able to grow a trail without limit by
    /// failing authentication repeatedly.</summary>
    public const int MaxAuditEntriesPerPass = 2048;
}

/// <summary>D38 F3 — the canonical credential-REFERENCE shape. A
/// reference is a vault id in the vault's own namespace: it must
/// carry the "cred-" prefix and an ASCII [A-Za-z0-9._-] tail. The
/// earlier charset-only check admitted any short token — including
/// ordinary passwords like "Summer2026" or "hunter2" and Unicode
/// lookalikes (char.IsLetterOrDigit accepts Unicode letters). The
/// prefix + ASCII-only rule is still only a SHAPE: the service
/// layer additionally requires the reference to RESOLVE in the
/// vault at issue time, so a password-shaped string can never be
/// persisted as a "reference" on any surface.</summary>
public static class CredentialReference
{
    public const string Prefix = "cred-";
    public static bool IsShape(string? reference) =>
        reference is not null &&
        reference.Length >= Prefix.Length + 1 && reference.Length <= VendorPassLimits.MaxIdLength &&
        reference.StartsWith(Prefix, StringComparison.Ordinal) &&
        char.IsAsciiLetterOrDigit(reference[Prefix.Length]) &&
        reference[Prefix.Length..].All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-');
    public static string? Validate(string? reference) =>
        reference is null || IsShape(reference) ? null
            : "credential reference is not reference-shaped — refused (a reference is a vault id in the cred- namespace, ASCII [A-Za-z0-9._-] after the prefix; credential material is never accepted where a reference belongs)";
}

/// <summary>THE duration rule, named: a pass whose requested
/// lifetime falls outside [48h, 30d] is REFUSED at issue. It is
/// never clamped: a 10-minute pass and a 31-day pass are both
/// decisions an issuer must restate inside the bounds, on the
/// record — the system does not quietly rewrite either one.</summary>
public static class VendorPassDurationRule
{
    public const string Name = "RefuseOutsideBounds";

    public static string? Validate(TimeSpan duration)
    {
        if (duration < VendorPassLimits.MinDuration)
            return $"pass duration {duration} is below the 48h minimum — refused by rule {Name} (a shorter pass is restated inside the bounds, never clamped up silently)";
        if (duration > VendorPassLimits.MaxDuration)
            return $"pass duration {duration} exceeds the 30d maximum — refused by rule {Name} (a longer need is a new audited pass, never clamped down silently)";
        return null;
    }
}

/// <summary>The closed set of scopes a pass may carry. Session
/// scopes only: a pass is session-scoped BY CONSTRUCTION. Admin,
/// background-tools, backstage, unlock and terminal are outside
/// this set and refuse at issue — no caller-supplied scope list can
/// widen a pass past it.</summary>
public static class VendorPassScopes
{
    public static readonly IReadOnlySet<string> Allowed = new HashSet<string>
    {
        Scopes.Observe, Scopes.Drive, Scopes.Shell,
    };

    /// <summary>Scopes named explicitly as never pass-grantable, for
    /// refusal messages that name what was asked for.</summary>
    public static readonly IReadOnlySet<string> NeverGrantable = new HashSet<string>
    {
        Scopes.Admin, Scopes.BackgroundTools, Scopes.Backstage, Scopes.Unlock, Scopes.Terminal,
    };
}

/// <summary>A NAMED vendor identity. Anonymous passes do not exist:
/// a pass names the person, their organisation and a contact, and
/// the pass token is BOUND to this identity — presentation by any
/// other vendor identity fails authentication.</summary>
public sealed record VendorIdentity(string Id, string DisplayName, string Organization, string Contact)
{
    public string? Validate()
    {
        if (string.IsNullOrWhiteSpace(Id) || Id.Length > VendorPassLimits.MaxIdLength)
            return "vendor identity needs an id within bounds — refused (a pass is bound to a named vendor, never anonymous)";
        if (string.IsNullOrWhiteSpace(DisplayName) || string.IsNullOrWhiteSpace(Organization) ||
            string.IsNullOrWhiteSpace(Contact))
            return "vendor identity must name the person, their organisation and a contact — refused (anonymous or half-named vendor access is not issued)";
        if (DisplayName.Length > VendorPassLimits.MaxNameLength ||
            Organization.Length > VendorPassLimits.MaxNameLength ||
            Contact.Length > VendorPassLimits.MaxNameLength)
            return "vendor identity fields are over bounds — refused";
        return null;
    }
}

/// <summary>One vendor access pass. CredentialRef is a vault
/// REFERENCE (an id the host vault resolves at injection time) —
/// a pass record never carries a credential value, and neither
/// does its export form.</summary>
public sealed record VendorPass(
    string Id,
    string IssuerId,
    VendorIdentity Vendor,
    string ScopeId,
    IReadOnlySet<string> DeviceIds,
    IReadOnlySet<string> GroupIds,
    IReadOnlySet<string> Scopes,
    DateTimeOffset IssuedUtc,
    DateTimeOffset ExpiresUtc,
    string? CredentialRef,
    bool Revoked,
    DateTimeOffset? RevokedUtc,
    string? RevokedBy,
    string? RevocationReason)
{
    public IReadOnlySet<string> DeviceIds { get; init; } = DeviceIds ?? new HashSet<string>();
    public IReadOnlySet<string> GroupIds { get; init; } = GroupIds ?? new HashSet<string>();
    public IReadOnlySet<string> Scopes { get; init; } = Scopes ?? new HashSet<string>();
    public TimeSpan Duration => ExpiresUtc - IssuedUtc;
    public bool IsExpired(DateTimeOffset now) => now >= ExpiresUtc;
    public bool IsNotYetValid(DateTimeOffset now) => now < IssuedUtc;
    /// <summary>Active = issued, in its window, not revoked. This is
    /// the ONLY state in which authentication can succeed.</summary>
    public bool IsActive(DateTimeOffset now) => !Revoked && !IsExpired(now) && !IsNotYetValid(now);
    /// <summary>Device scope test: the device is named directly, or
    /// belongs to a named group (membership supplied by the caller
    /// from the roster/facts — the pass itself stores ids only).</summary>
    public bool CoversDevice(string? deviceId, IEnumerable<string>? deviceGroupIds = null)
    {
        if (string.IsNullOrWhiteSpace(deviceId)) return false;
        if (DeviceIds.Contains(deviceId)) return true;
        if (deviceGroupIds is not null)
            foreach (var g in deviceGroupIds)
                if (GroupIds.Contains(g)) return true;
        return false;
    }
}

/// <summary>Result of a successful issue: the pass plus the bearer
/// token, shown ONCE (only its SHA-256 hash is kept at rest — the
/// PairingService discipline).</summary>
public sealed record VendorPassIssue(VendorPass Pass, string BearerToken);

/// <summary>One entry in a pass's own audit trail. Detail text is
/// written by the store/service and must never carry credential
/// material — it carries the credential REFERENCE at most.</summary>
public sealed record PassAuditEntry(
    DateTimeOffset AtUtc, string PassId, string Kind, string Actor, string Detail);

public static class PassAuditKinds
{
    public const string Issued = "pass_issued";
    public const string AuthSucceeded = "pass_auth_succeeded";
    public const string AuthFailed = "pass_auth_failed";
    public const string SessionBound = "pass_session_bound";
    public const string SessionUnbound = "pass_session_unbound";
    public const string CredentialInjected = "pass_credential_injected";
    public const string Revoked = "pass_revoked";
    public const string ExtensionRefused = "pass_extension_refused";
    public const string IssueRefused = "pass_issue_refused";
    public const string Expired = "pass_expired_observed";
}

/// <summary>
/// The vendor-pass store: issue / authenticate / revoke with the
/// pairing machinery's discipline (hash-only token at rest,
/// fixed-time compare, fail-closed authenticate, malformed import
/// entries skipped never fatal, defensive copies at admission).
/// The store also tracks live session bindings per pass so
/// revocation can name exactly the sessions the service layer must
/// tear down. All time reads take an explicit `now` — expiry is a
/// pure function of (pass, now), so clock games are testable and a
/// pass can never be "extended" by moving a stored field.
/// </summary>
public sealed class VendorPassStore
{
    private sealed record StoredPass(VendorPass Pass, string TokenHash);

    private readonly Dictionary<string, StoredPass> _passes = new(StringComparer.Ordinal);
    // BD-SHARED-PLAT-3/F10: authenticate is a dictionary lookup keyed
    // by the presented token's hash — the old shape linearly scanned
    // every pass ever issued and hex-decoded every stored hash under
    // the store lock on EVERY attempt, so login traffic contended
    // with mid-session revalidation and cost grew with history. The
    // key is the SHA-256 of a 256-bit random token; a lookup by that
    // hash leaks nothing useful through timing, and the single hit
    // is still confirmed with FixedTimeEquals.
    private readonly Dictionary<string, StoredPass> _byTokenHash = new(StringComparer.Ordinal);
    private readonly Dictionary<string, List<PassAuditEntry>> _audit = new(StringComparer.Ordinal);
    private readonly Dictionary<string, HashSet<string>> _liveSessions = new(StringComparer.Ordinal);
    private readonly object _gate = new();
    // BD-SHARED-PLAT-3/F6: when a protector is wired (production:
    // the host ISecretProtector), exports are SEALED with it — a
    // hand-edited export no longer unseals, so editing Revoked:false
    // into an export cannot resurrect a revoked pass on restore
    // into an empty store. Without a protector the export stays the
    // legacy plain shape (bare tooling/tests) and the store says so
    // via ExportsSealed.
    private readonly ISecretProtector? _protector;

    public VendorPassStore(ISecretProtector? protector = null) => _protector = protector;

    /// <summary>True when exports from this store are sealed with
    /// the wired protector (tamper-evident restore).</summary>
    public bool ExportsSealed => _protector is not null;

    public event Action? Changed;

    private void TrailLocked(VendorPass pass, string kind, string actor, string detail, DateTimeOffset now)
    {
        if (!_audit.TryGetValue(pass.Id, out var list)) _audit[pass.Id] = list = new List<PassAuditEntry>();
        // D38 F12: bounded trail. Beyond the cap, further entries
        // are dropped rather than letting a token holder grow the
        // trail (and every export of it) without limit.
        // BD-SHARED-PLAT-3/F5: the cap must never eat the acts that
        // matter. AuthFailed is the floodable kind (any token holder
        // can mint failures); lifecycle acts (issued, revoked,
        // injected, bound/unbound, expiry, extension refusals) are
        // bounded by real operations. At the cap, a new AuthFailed
        // is dropped; a lifecycle act EVICTS the oldest AuthFailed
        // to make room, and is itself dropped only when the trail
        // holds nothing but lifecycle acts at the cap.
        if (list.Count >= VendorPassLimits.MaxAuditEntriesPerPass)
        {
            if (kind == PassAuditKinds.AuthFailed) return;
            var evict = list.FindIndex(e => e.Kind == PassAuditKinds.AuthFailed);
            if (evict < 0) return;
            list.RemoveAt(evict);
        }
        list.Add(new PassAuditEntry(now, pass.Id, kind, actor, detail));
    }

    public IReadOnlyList<PassAuditEntry> AuditTrail(string passId)
    {
        lock (_gate)
            return passId is not null && _audit.TryGetValue(passId, out var list)
                ? list.ToList() : Array.Empty<PassAuditEntry>();
    }

    public VendorPass? Get(string? passId)
    {
        lock (_gate)
            return passId is not null && _passes.TryGetValue(passId, out var s) ? s.Pass : null;
    }

    public IReadOnlyList<VendorPass> List()
    {
        lock (_gate) return _passes.Values.Select(s => s.Pass).OrderBy(p => p.IssuedUtc).ToList();
    }

    public IReadOnlyList<string> LiveSessions(string passId)
    {
        lock (_gate)
            return passId is not null && _liveSessions.TryGetValue(passId, out var set)
                ? set.OrderBy(x => x, StringComparer.Ordinal).ToList() : Array.Empty<string>();
    }

    /// <summary>Issue a pass. Refusals (returned, never thrown):
    /// anonymous/half-named vendor, self-issue (issuer == vendor),
    /// an issuer who is themselves a vendor on an active pass (a
    /// pass holder mints NOTHING — escalation by construction),
    /// empty device scope, a scope naming admin/background/
    /// backstage/unlock/terminal or any scope outside the allowed
    /// session set, a duration outside the register bounds (the
    /// named rule), or an empty issuer. The credential is a vault
    /// REFERENCE only; a caller passing anything shaped like a
    /// credential value as the reference is refused by the service
    /// layer's reference-shape check (see VendorPassService).</summary>
    public (VendorPassIssue? Issue, string Reason) Issue(
        string issuerId, VendorIdentity vendor, string scopeId,
        IEnumerable<string> deviceIds, IEnumerable<string> groupIds,
        IEnumerable<string> scopes, TimeSpan duration, string? credentialRef,
        DateTimeOffset now)
    {
        (VendorPassIssue?, string) Refuse(string reason) => (null, reason);
        if (string.IsNullOrWhiteSpace(issuerId))
            return Refuse("a pass needs a named issuer — refused (an unattributed grant is not issued)");
        if (vendor is null) return Refuse("a pass needs a vendor identity — refused");
        if (vendor.Validate() is { } vendorInvalid) return Refuse(vendorInvalid);
        if (string.Equals(issuerId.Trim(), vendor.Id.Trim(), StringComparison.OrdinalIgnoreCase))
            return Refuse("issuer and vendor are the same identity — refused (a vendor cannot issue their own pass)");
        if (string.IsNullOrWhiteSpace(scopeId))
            return Refuse("a pass needs a scope — refused");
        var devices = new HashSet<string>(
            (deviceIds ?? Array.Empty<string>()).Where(d => !string.IsNullOrWhiteSpace(d)).Select(d => d.Trim()),
            StringComparer.OrdinalIgnoreCase);
        var groups = new HashSet<string>(
            (groupIds ?? Array.Empty<string>()).Where(g => !string.IsNullOrWhiteSpace(g)).Select(g => g.Trim()),
            StringComparer.OrdinalIgnoreCase);
        if (devices.Count == 0 && groups.Count == 0)
            return Refuse("a pass needs a device scope (at least one device or device group) — refused (an unscoped vendor pass is a fleet pass, and those do not exist)");
        if (devices.Count > VendorPassLimits.MaxDevicesPerPass || groups.Count > VendorPassLimits.MaxGroupsPerPass)
            return Refuse($"pass scope exceeds bounds ({VendorPassLimits.MaxDevicesPerPass} devices / {VendorPassLimits.MaxGroupsPerPass} groups) — refused");
        var scopeSet = new HashSet<string>(
            (scopes ?? Array.Empty<string>()).Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => s.Trim().ToLowerInvariant()),
            StringComparer.Ordinal);
        if (scopeSet.Count == 0)
            return Refuse("a pass needs at least one session scope — refused");
        foreach (var s in scopeSet)
        {
            if (VendorPassScopes.NeverGrantable.Contains(s))
                return Refuse($"scope '{s}' can never be granted by a pass — refused (passes are session-scoped by construction: no admin, no background tools, no backstage, no unlock, no terminal)");
            if (!VendorPassScopes.Allowed.Contains(s))
                return Refuse($"scope '{s}' is not a pass-grantable session scope — refused (allowed: {string.Join(", ", VendorPassScopes.Allowed.OrderBy(x => x, StringComparer.Ordinal))})");
        }
        if (VendorPassDurationRule.Validate(duration) is { } durationRefusal)
            return Refuse(durationRefusal);
        // D38 F3/F5: the store enforces the canonical reference
        // shape itself — the guard no longer lives only in the
        // service layer, so a direct store issue cannot persist a
        // value-shaped "reference" either.
        if (CredentialReference.Validate(credentialRef) is { } refInvalid)
            return Refuse(refInvalid);

        // BD-SHARED-PLAT-3/F11: Changed is raised AFTER the gate is
        // released (SiteDocumentationService's discipline) — a
        // subscriber that calls back into the store (e.g. to export
        // for persistence) must never run under the lock.
        (VendorPassIssue? Issue, string Reason) result;
        lock (_gate)
        {
            // Escalation guard (D38 F6): an identity that holds —
            // or has EVER held — a vendor pass cannot issue passes
            // at all. The earlier active-only check let a vendor
            // whose pass had expired or been revoked mint passes
            // for an accomplice; minting is an operator act and a
            // pass (current or past) confers no operator rights.
            foreach (var s in _passes.Values)
                if (string.Equals(s.Pass.Vendor.Id, issuerId.Trim(), StringComparison.OrdinalIgnoreCase))
                    return Refuse($"issuer '{issuerId}' is a vendor-pass holder (active, expired or revoked) — refused (a pass holder cannot mint passes; passes confer session access only)");

            var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
            var pass = new VendorPass(
                Id: Guid.NewGuid().ToString("N"),
                IssuerId: issuerId.Trim(),
                Vendor: vendor,
                ScopeId: scopeId.Trim(),
                DeviceIds: devices, GroupIds: groups, Scopes: scopeSet,
                IssuedUtc: now, ExpiresUtc: now + duration,
                CredentialRef: credentialRef,
                Revoked: false, RevokedUtc: null, RevokedBy: null, RevocationReason: null);
            var stored = new StoredPass(pass, Hash(token));
            _passes[pass.Id] = stored;
            _byTokenHash[stored.TokenHash] = stored;
            _liveSessions[pass.Id] = new HashSet<string>(StringComparer.Ordinal);
            TrailLocked(pass, PassAuditKinds.Issued, pass.IssuerId,
                $"vendor={vendor.Id} org={vendor.Organization} devices=[{string.Join(",", devices.OrderBy(x => x, StringComparer.Ordinal))}] groups=[{string.Join(",", groups.OrderBy(x => x, StringComparer.Ordinal))}] scopes=[{string.Join(",", scopeSet.OrderBy(x => x, StringComparer.Ordinal))}] expires={pass.ExpiresUtc:O} credentialRef={credentialRef ?? "(none)"}", now);
            result = (new VendorPassIssue(pass, token), $"pass {pass.Id} issued to vendor '{vendor.Id}' until {pass.ExpiresUtc:O}");
        }
        Changed?.Invoke();
        return result;
    }

    /// <summary>Authenticate a presented pass token for a vendor on
    /// a device. Fail-closed on EVERY axis: unknown token, wrong
    /// vendor identity (a pass is bound to its vendor — transfer
    /// fails), device outside scope, not-yet-valid, expired,
    /// revoked. Group membership for the device is supplied by the
    /// caller. Every outcome is trailed on the matched pass (a
    /// wholly unknown token matches no pass and trails nowhere —
    /// the service layer still ledgers the attempt).</summary>
    public (VendorPass? Pass, string Reason) Authenticate(
        string? bearerToken, string? vendorId, string? deviceId,
        IEnumerable<string>? deviceGroupIds, DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(bearerToken))
            return (null, "no pass token presented — refused");
        var hash = Hash(bearerToken);
        byte[] hashBytes;
        try { hashBytes = Convert.FromHexString(hash); } catch { return (null, "malformed pass token — refused"); }
        // BD-SHARED-PLAT-3/F10+F11: one indexed lookup + one
        // fixed-time confirmation inside the gate; the trail write
        // happens under the gate, Changed fires after it.
        (VendorPass? Pass, string Reason) result;
        var trailed = false;
        lock (_gate)
        {
            if (!_byTokenHash.TryGetValue(hash, out var match))
                return (null, "unknown pass token — refused");
            byte[] storedBytes;
            try { storedBytes = Convert.FromHexString(match.TokenHash); }
            catch (FormatException) { return (null, "unknown pass token — refused"); } // a corrupt entry matches nothing
            if (!CryptographicOperations.FixedTimeEquals(storedBytes, hashBytes))
                return (null, "unknown pass token — refused");
            var pass = match.Pass;
            (VendorPass?, string) Fail(string reason)
            {
                TrailLocked(pass, PassAuditKinds.AuthFailed, vendorId ?? "(unknown)",
                    $"device={deviceId ?? "(none)"} reason={reason}", now);
                trailed = true;
                return (null, reason);
            }
            if (!string.Equals(pass.Vendor.Id, (vendorId ?? "").Trim(), StringComparison.OrdinalIgnoreCase))
                result = Fail($"pass is bound to vendor '{pass.Vendor.Id}' — presentation by '{vendorId}' refused (passes are not transferable)");
            else if (pass.Revoked)
                result = Fail($"pass was revoked by {pass.RevokedBy} — refused (revocation is terminal)");
            else if (pass.IsNotYetValid(now))
                result = Fail($"pass is not valid before {pass.IssuedUtc:O} — refused");
            else if (pass.IsExpired(now))
            {
                TrailLocked(pass, PassAuditKinds.Expired, vendorId ?? "(unknown)",
                    $"device={deviceId ?? "(none)"} expired={pass.ExpiresUtc:O}", now);
                result = Fail($"pass expired at {pass.ExpiresUtc:O} — refused (expiry is judged against the presented instant; there is no grace window)");
            }
            else if (!pass.CoversDevice(deviceId, deviceGroupIds))
                result = Fail($"device '{deviceId}' is outside this pass's scope — refused (a pass for one device authorizes no other)");
            else
            {
                TrailLocked(pass, PassAuditKinds.AuthSucceeded, pass.Vendor.Id,
                    $"device={deviceId}", now);
                trailed = true;
                result = (pass, $"pass {pass.Id} authenticated for vendor '{pass.Vendor.Id}' on device '{deviceId}'");
            }
        }
        if (trailed) Changed?.Invoke();
        return result;
    }

    /// <summary>Re-validate a pass mid-session (the session layer's
    /// periodic re-check + the revocation race): the pass must
    /// still be active NOW. A session bound to a pass that has
    /// since expired or been revoked fails this and must end.</summary>
    public bool Revalidate(string passId, DateTimeOffset now)
    {
        lock (_gate)
            return _passes.TryGetValue(passId ?? "", out var s) && s.Pass.IsActive(now);
    }

    /// <summary>Bind a live session to a pass (called by the service
    /// layer when a vendor session starts). The pass must be active
    /// and cover the device at bind time.</summary>
    public (bool Ok, string Reason) BindSession(string passId, string sessionId, string deviceId,
        IEnumerable<string>? deviceGroupIds, DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(sessionId)) return (false, "a session bind needs a session id — refused");
        (bool, string) result;
        lock (_gate)
        {
            if (!_passes.TryGetValue(passId ?? "", out var s)) return (false, $"no pass '{passId}' — refused");
            var pass = s.Pass;
            if (!pass.IsActive(now))
                return (false, $"pass '{passId}' is not active (revoked={pass.Revoked}, expired={pass.IsExpired(now)}) — session bind refused");
            if (!pass.CoversDevice(deviceId, deviceGroupIds))
                return (false, $"device '{deviceId}' is outside pass '{passId}' scope — session bind refused");
            if (!_liveSessions.TryGetValue(pass.Id, out var liveSet))
                _liveSessions[pass.Id] = liveSet = new HashSet<string>(StringComparer.Ordinal);
            // D38 F8: a session id binds ONCE. Re-binding an already
            // live id refused — otherwise a failed second bind's
            // rollback unbind would silently remove the ORIGINAL
            // live binding and revocation would neither name nor
            // end that session.
            if (liveSet.Contains(sessionId))
                return (false, $"session '{sessionId}' is already bound to pass '{passId}' — duplicate bind refused (the original binding stands)");
            liveSet.Add(sessionId);
            TrailLocked(pass, PassAuditKinds.SessionBound, pass.Vendor.Id,
                $"session={sessionId} device={deviceId}", now);
            result = (true, $"session {sessionId} bound to pass {pass.Id}");
        }
        Changed?.Invoke();
        return result;
    }

    public void UnbindSession(string passId, string sessionId, DateTimeOffset now)
    {
        var trailed = false;
        lock (_gate)
        {
            if (!_passes.TryGetValue(passId ?? "", out var s)) return;
            if (_liveSessions.TryGetValue(passId, out var set)) set.Remove(sessionId ?? "");
            TrailLocked(s.Pass, PassAuditKinds.SessionUnbound, s.Pass.Vendor.Id,
                $"session={sessionId}", now);
            trailed = true;
        }
        // BD-SHARED-PLAT-3/F11: raised after the gate, like every
        // other mutation in this store.
        if (trailed) Changed?.Invoke();
    }

    /// <summary>Revoke a pass. Terminal: a revoked pass never
    /// authenticates again, and revocation RETURNS the live session
    /// ids bound to it so the caller tears those sessions down
    /// through the session layer. Revoking an unknown or already-
    /// revoked pass refuses by name (no silent no-op success).</summary>
    public (bool Ok, string Reason, IReadOnlyList<string> LiveSessionIds) Revoke(
        string passId, string revokedBy, string reason, DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(revokedBy))
            return (false, "revocation needs a named revoker — refused", Array.Empty<string>());
        if (string.IsNullOrWhiteSpace(reason))
            return (false, "revocation needs a recorded reason — refused (a revocation without a reason is an unexplained act)", Array.Empty<string>());
        (bool, string, IReadOnlyList<string>) result;
        lock (_gate)
        {
            if (!_passes.TryGetValue(passId ?? "", out var s))
                return (false, $"no pass '{passId}' — refused", Array.Empty<string>());
            // D38 F12b/D05b: revocation is an operator act. An
            // identity that is the vendor of a DIFFERENT pass
            // cannot revoke this one (a pass holder revoking a
            // rival/accomplice's pass is an escalation surface).
            // A vendor surrendering their OWN pass stays allowed.
            foreach (var other in _passes.Values)
                if (other.Pass.Id != s.Pass.Id &&
                    string.Equals(other.Pass.Vendor.Id, revokedBy.Trim(), StringComparison.OrdinalIgnoreCase))
                    return (false, $"revoker '{revokedBy}' is a vendor-pass holder — refused (a pass holder cannot revoke another vendor's pass)", Array.Empty<string>());
            if (s.Pass.Revoked)
                return (false, $"pass '{passId}' is already revoked — refused (revocation is recorded once, by its first revoker)", Array.Empty<string>());
            var live = _liveSessions.TryGetValue(passId, out var set)
                ? set.OrderBy(x => x, StringComparer.Ordinal).ToList() : new List<string>();
            var updated = s.Pass with
            {
                Revoked = true, RevokedUtc = now, RevokedBy = revokedBy.Trim(), RevocationReason = reason.Trim(),
            };
            var replaced = s with { Pass = updated };
            _passes[passId] = replaced;
            _byTokenHash[replaced.TokenHash] = replaced;
            _liveSessions[passId] = new HashSet<string>(StringComparer.Ordinal);
            TrailLocked(updated, PassAuditKinds.Revoked, revokedBy.Trim(),
                $"reason={reason.Trim()} liveSessionsKilled=[{string.Join(",", live)}]", now);
            result = (true, $"pass {passId} revoked by {revokedBy.Trim()}; {live.Count} live session(s) named for teardown", live);
        }
        Changed?.Invoke();
        return result;
    }

    /// <summary>Extension does not exist. This method is the named
    /// refusal every extension attempt meets: more time is a NEW
    /// pass, issued as a new audited decision — never a mutation of
    /// this pass's expiry, by anyone, through any path.</summary>
    public (bool Ok, string Reason) ExtendPass(string passId, TimeSpan additional, string requestedBy, DateTimeOffset now)
    {
        // BD-SHARED-PLAT-3/F11: Changed fires only when something
        // actually changed (a trail entry landed) and after the
        // gate — the old shape fired it even for an unknown pass id
        // where nothing happened.
        var trailed = false;
        lock (_gate)
        {
            if (_passes.TryGetValue(passId ?? "", out var s))
            {
                TrailLocked(s.Pass, PassAuditKinds.ExtensionRefused, requestedBy ?? "(unknown)",
                    $"additional={additional} — extension is a new pass, never a mutation", now);
                trailed = true;
            }
        }
        if (trailed) Changed?.Invoke();
        return (false, $"pass '{passId}' cannot be extended — refused (a pass's expiry is fixed at issue; more time is a NEW pass issued as a new audited decision)");
    }

    /// <summary>Trail an injection on a pass (service layer calls
    /// this after the injector reports success). Carries the
    /// credential REFERENCE and the session id only.</summary>
    public void TrailInjection(string passId, string sessionId, string credentialRef, DateTimeOffset now)
    {
        var trailed = false;
        lock (_gate)
        {
            if (!_passes.TryGetValue(passId ?? "", out var s)) return;
            TrailLocked(s.Pass, PassAuditKinds.CredentialInjected, s.Pass.Vendor.Id,
                $"session={sessionId} credentialRef={credentialRef}", now);
            trailed = true;
        }
        if (trailed) Changed?.Invoke();
    }

    private static string Hash(string token) =>
        Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(token)));

    // ---- persistence (hash-only, PairingService discipline) --------

    private sealed record StoredDto(
        string Id, string IssuerId, string VendorId, string VendorName, string VendorOrg, string VendorContact,
        string ScopeId, string[] DeviceIds, string[] GroupIds, string[] Scopes,
        DateTimeOffset IssuedUtc, DateTimeOffset ExpiresUtc, string? CredentialRef,
        bool Revoked, DateTimeOffset? RevokedUtc, string? RevokedBy, string? RevocationReason,
        string TokenHash,
        // BD-SHARED-PLAT-3/F5: the per-pass audit trail is part of
        // the export — the old shape serialized passes only, so the
        // trail (the lifecycle evidence) was lost on every restart.
        // Live session bindings are deliberately NOT exported: a
        // restart ends the sessions themselves, so there is nothing
        // live left for a later revocation to name.
        List<PassAuditEntry>? Trail = null);

    public string ExportJson()
    {
        string json;
        lock (_gate)
        {
            var dtos = _passes.Values.Select(s => new StoredDto(
                s.Pass.Id, s.Pass.IssuerId, s.Pass.Vendor.Id, s.Pass.Vendor.DisplayName,
                s.Pass.Vendor.Organization, s.Pass.Vendor.Contact, s.Pass.ScopeId,
                s.Pass.DeviceIds.ToArray(), s.Pass.GroupIds.ToArray(), s.Pass.Scopes.ToArray(),
                s.Pass.IssuedUtc, s.Pass.ExpiresUtc, s.Pass.CredentialRef,
                s.Pass.Revoked, s.Pass.RevokedUtc, s.Pass.RevokedBy, s.Pass.RevocationReason,
                s.TokenHash,
                _audit.TryGetValue(s.Pass.Id, out var trail) ? trail.ToList() : new List<PassAuditEntry>())).ToList();
            json = JsonSerializer.Serialize(dtos);
        }
        // BD-SHARED-PLAT-3/F6: sealed when a protector is wired.
        return _protector is null ? json : _protector.Protect(json);
    }

    /// <summary>Restore a store produced by ExportJson. Malformed
    /// entries are skipped, never fatal; entries whose shape would
    /// violate issue-time invariants (forbidden scope, out-of-bounds
    /// duration, anonymous vendor) are ALSO skipped — a hand-edited
    /// store can never produce a pass the issuer could not have
    /// issued (the SessionService import-repair discipline).</summary>
    public int ImportJson(string json)
    {
        // BD-SHARED-PLAT-3/F6: a sealed export (protector wired)
        // must unseal before it parses — a hand-edited sealed
        // export restores NOTHING. Plain legacy exports still
        // restore when they parse directly.
        var text = json;
        StoredDto[] dtos;
        try { dtos = JsonSerializer.Deserialize<StoredDto[]>(text) ?? Array.Empty<StoredDto>(); }
        catch
        {
            if (_protector is null) return 0;
            try { text = _protector.Unprotect(json); }
            catch { return 0; }
            try { dtos = JsonSerializer.Deserialize<StoredDto[]>(text) ?? Array.Empty<StoredDto>(); }
            catch { return 0; }
        }
        var restored = 0;
        lock (_gate)
        {
            foreach (var dto in dtos)
            {
                if (string.IsNullOrWhiteSpace(dto.Id) || dto.TokenHash is null ||
                    dto.TokenHash.Length != 64 || !dto.TokenHash.All(Uri.IsHexDigit)) continue;
                var vendor = new VendorIdentity(dto.VendorId ?? "", dto.VendorName ?? "",
                    dto.VendorOrg ?? "", dto.VendorContact ?? "");
                if (vendor.Validate() is not null) continue;
                // D38 F5: import re-checks EVERY issue invariant,
                // not a subset — issuer, scope id, reference shape
                // and the device/group bounds included.
                if (string.IsNullOrWhiteSpace(dto.IssuerId) ||
                    string.Equals(dto.IssuerId.Trim(), vendor.Id.Trim(), StringComparison.OrdinalIgnoreCase)) continue;
                if (string.IsNullOrWhiteSpace(dto.ScopeId)) continue;
                if (CredentialReference.Validate(dto.CredentialRef) is not null) continue;
                var scopes = new HashSet<string>(dto.Scopes ?? Array.Empty<string>(), StringComparer.Ordinal);
                if (scopes.Count == 0 || scopes.Any(s => !VendorPassScopes.Allowed.Contains(s))) continue;
                var duration = dto.ExpiresUtc - dto.IssuedUtc;
                if (VendorPassDurationRule.Validate(duration) is not null) continue;
                var devices = new HashSet<string>(dto.DeviceIds ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
                var groups = new HashSet<string>(dto.GroupIds ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
                if (devices.Count == 0 && groups.Count == 0) continue;
                if (devices.Count > VendorPassLimits.MaxDevicesPerPass || groups.Count > VendorPassLimits.MaxGroupsPerPass) continue;
                if (devices.Any(d => string.IsNullOrWhiteSpace(d) || d.Length > VendorPassLimits.MaxIdLength) ||
                    groups.Any(g => string.IsNullOrWhiteSpace(g) || g.Length > VendorPassLimits.MaxIdLength)) continue;
                // D38 F5: revocation is TERMINAL across import. An
                // entry whose id already exists never overwrites —
                // above all, a hand-edited export with Revoked:false
                // cannot resurrect a revoked pass.
                if (_passes.ContainsKey(dto.Id)) continue;
                // BD-SHARED-PLAT-3/F6: revocation fields must be
                // CONSISTENT — a revoked entry without a revoker and
                // timestamp, or an unrevoked entry carrying a
                // revoker, is a hand-shaped record and is skipped.
                if (dto.Revoked && (string.IsNullOrWhiteSpace(dto.RevokedBy) || dto.RevokedUtc is null)) continue;
                if (!dto.Revoked && (!string.IsNullOrWhiteSpace(dto.RevokedBy) || dto.RevokedUtc is not null)) continue;
                var pass = new VendorPass(dto.Id, dto.IssuerId ?? "", vendor, dto.ScopeId ?? "",
                    devices, groups, scopes, dto.IssuedUtc, dto.ExpiresUtc, dto.CredentialRef,
                    dto.Revoked, dto.RevokedUtc, dto.RevokedBy, dto.RevocationReason);
                var storedPass = new StoredPass(pass, dto.TokenHash);
                _passes[pass.Id] = storedPass;
                _byTokenHash[dto.TokenHash] = storedPass;
                if (!_liveSessions.ContainsKey(pass.Id))
                    _liveSessions[pass.Id] = new HashSet<string>(StringComparer.Ordinal);
                // BD-SHARED-PLAT-3/F5: restore the trail with the
                // pass (entries naming another pass are dropped).
                if (dto.Trail is { Count: > 0 })
                    _audit[pass.Id] = dto.Trail
                        .Where(e => e is not null && string.Equals(e.PassId, pass.Id, StringComparison.Ordinal))
                        .Take(VendorPassLimits.MaxAuditEntriesPerPass).ToList();
                restored++;
            }
        }
        if (restored > 0) Changed?.Invoke();
        return restored;
    }
}

// =====================================================================
// Credential injection — the vault → session-layer mechanism.
//
// BOUNDARY (stated for reviewers, enforced by shape): the NEVER
// rule forbids an AI/operator from typing into or reading
// credential-class fields. Injection is NOT typing by a caller: it
// is DeskGuest's own host code moving a credential from the vault to the
// target's logon surface through the session layer's sink. The
// vendor (and any AI) sees only a RECEIPT naming the reference and
// the session — the value exists only inside the handle's Use
// callback, whose sole legitimate consumer is the sink.
// =====================================================================

/// <summary>An opaque vault credential. D38 F1: the value is
/// reachable ONLY through the INTERNAL <see cref="Use"/> — callable
/// solely by code in this assembly, which in practice is the
/// <see cref="VaultCredentialInjector"/> presenting to the session
/// layer's sink. The earlier public Use(Action&lt;string&gt;) let
/// ANY code holding the vault extract the plaintext with its own
/// callback (ResolveForInjection(ref).Use(v =&gt; leaked = v)) —
/// the "sink is the only consumer" claim was convention, not
/// types. Now the types enforce it: a handle obtained outside the
/// injector exposes no public member that yields or forwards the
/// value. ToString, equality and every record surface deliberately
/// exclude the value.</summary>
public sealed class VaultCredentialHandle
{
    private readonly string _value;
    internal VaultCredentialHandle(string value) => _value = value;
    /// <summary>Present the credential to the session layer's sink.
    /// INTERNAL by design (D38 F1): only the injector in this
    /// assembly may call it. The sink consumes the value (types it
    /// into the target logon surface inside host code); the caller
    /// learns nothing back.</summary>
    internal void Use(Action<string> sink) => sink(_value);
    public override string ToString() => "[vault credential — value never surfaced]";
}

/// <summary>The vault seam injection resolves references through.
/// Production wiring is the FEATURES §8 credential vault under
/// ISecretProtector; the in-memory implementation below is the
/// test/dev form (protector-backed, never plaintext at rest).</summary>
public interface IVendorCredentialVault
{
    /// <summary>Resolve a reference to a handle, or null when the
    /// reference names nothing (fail closed — injection refuses).</summary>
    VaultCredentialHandle? ResolveForInjection(string credentialRef);
    /// <summary>D38 F3: existence check WITHOUT resolving — lets the
    /// service layer refuse a dangling or value-shaped reference at
    /// issue time, before it can be persisted on any surface.</summary>
    bool Contains(string credentialRef);
    void Store(string credentialRef, string credentialValue);
    bool Remove(string credentialRef);
}

/// <summary>Protector-backed in-memory vault (dev/test form of the
/// §8 vault seam): values are stored protected, resolved to handles
/// only through the injection path.</summary>
public sealed class InMemoryVendorCredentialVault : IVendorCredentialVault
{
    private readonly Dictionary<string, string> _protected = new(StringComparer.Ordinal);
    private readonly ISecretProtector _protector;
    private readonly object _gate = new();
    public InMemoryVendorCredentialVault(ISecretProtector protector) =>
        _protector = protector ?? throw new ArgumentNullException(nameof(protector));

    public void Store(string credentialRef, string credentialValue)
    {
        lock (_gate) _protected[credentialRef] = _protector.Protect(credentialValue);
    }

    public bool Remove(string credentialRef)
    {
        lock (_gate) return _protected.Remove(credentialRef);
    }

    public bool Contains(string credentialRef)
    {
        lock (_gate) return credentialRef is not null && _protected.ContainsKey(credentialRef);
    }

    public VaultCredentialHandle? ResolveForInjection(string credentialRef)
    {
        lock (_gate)
        {
            if (credentialRef is null || !_protected.TryGetValue(credentialRef, out var p)) return null;
            try { return new VaultCredentialHandle(_protector.Unprotect(p)); }
            catch { return null; } // an unprotectable entry resolves to nothing (fail closed)
        }
    }
}

/// <summary>The session layer's credential sink: the ONLY consumer
/// of a credential value. In production this is the session host
/// presenting the credential to the target's logon surface; the
/// vendor's session receives an authenticated desktop, never the
/// credential.</summary>
public interface ISessionCredentialSink
{
    /// <summary>Consume the credential for one session's logon.
    /// Returns true when the target accepted the logon.</summary>
    bool PresentCredential(string sessionId, string credentialValue);
}

/// <summary>Proof an injection happened: session, reference, time,
/// outcome. Carries NO credential material by construction.</summary>
public sealed record CredentialInjectionReceipt(
    string SessionId, string PassId, string CredentialRef,
    DateTimeOffset InjectedUtc, bool Accepted);

/// <summary>The injection contract. Implementations resolve the
/// reference through the vault and present through the sink; the
/// caller (vendor session setup) receives only the receipt.</summary>
public interface ICredentialInjector
{
    (CredentialInjectionReceipt? Receipt, string Reason) Inject(
        string passId, string sessionId, string credentialRef, DateTimeOffset now);
    /// <summary>D38 F3: does this reference name a real vault entry?
    /// Checked at issue time WITHOUT exposing any value, so a
    /// dangling or value-shaped reference is refused before it is
    /// persisted anywhere.</summary>
    bool ReferenceResolves(string credentialRef);
}

/// <summary>The host injector: vault → sink, inside host code. A
/// missing reference or a refused logon refuses the injection (and
/// therefore the session's credential leg) by name.</summary>
public sealed class VaultCredentialInjector : ICredentialInjector
{
    private readonly IVendorCredentialVault _vault;
    private readonly ISessionCredentialSink _sink;
    public VaultCredentialInjector(IVendorCredentialVault vault, ISessionCredentialSink sink)
    {
        _vault = vault ?? throw new ArgumentNullException(nameof(vault));
        _sink = sink ?? throw new ArgumentNullException(nameof(sink));
    }

    public (CredentialInjectionReceipt? Receipt, string Reason) Inject(
        string passId, string sessionId, string credentialRef, DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(credentialRef))
            return (null, "injection needs a credential reference — refused");
        var handle = _vault.ResolveForInjection(credentialRef);
        if (handle is null)
            // D38 F3: the refusal reason no longer echoes the
            // reference back to the caller — a reference belongs in
            // the pass record and the receipt, not in error text
            // returned toward the vendor side.
            return (null, "the credential reference on this pass resolves to nothing in the vault — injection refused (fail closed)");
        var accepted = false;
        handle.Use(value => accepted = _sink.PresentCredential(sessionId, value));
        if (!accepted)
            return (null, $"the target refused the injected credential for session '{sessionId}' — injection failed (the credential value was presented by the session layer and never surfaced)");
        return (new CredentialInjectionReceipt(sessionId, passId, credentialRef, now, true),
            $"credential injected for session {sessionId} via its vault reference — the vendor never receives the value");
    }

    public bool ReferenceResolves(string credentialRef) =>
        credentialRef is not null && _vault.Contains(credentialRef);
}

/// <summary>Test double sink: records THAT a presentation happened
/// (session ids + a fingerprint), never usable as an exfiltration
/// path in assertions — tests compare the fingerprint, and assert
/// the raw value appears in no audit/receipt/export surface.
/// BD-SHARED-PLAT-3/F2: the fingerprint is a per-instance SALTED
/// HMAC, not a bare SHA-256 — the old shape was the offline-cracking
/// oracle the SiteDocs vault bans (an unsalted hash of a low-entropy
/// credential lets anyone who reads the list test guesses offline).
/// The salt never leaves the instance, so a recorded fingerprint
/// can only be compared through THIS sink's FingerprintOf.</summary>
public sealed class RecordingCredentialSink : ISessionCredentialSink
{
    private readonly byte[] _salt = RandomNumberGenerator.GetBytes(16);
    public List<string> Sessions { get; } = new();
    public List<string> Fingerprints { get; } = new();
    public bool Accept { get; set; } = true;
    public bool PresentCredential(string sessionId, string credentialValue)
    {
        Sessions.Add(sessionId);
        Fingerprints.Add(FingerprintOf(credentialValue));
        return Accept;
    }
    public string FingerprintOf(string value) =>
        Convert.ToHexString(HMACSHA256.HashData(_salt,
            System.Text.Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
}
