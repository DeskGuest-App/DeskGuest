using System.Text.Json;
using Acp.Shared.Enterprise;
using Acp.Shared.Hub;
using Acp.Shared.Security;

namespace Acp.Shared.Encryption;

// =====================================================================
// RMM-18 — Recovery-key escrow: recovery keys land in the hub vault
// under ACP's existing vault discipline (ISecretProtector at rest —
// DPAPI in production) and the existing dual-control machinery's
// pattern (BreakGlassService: two DISTINCT actors, loud chained
// audit BEFORE the grant exists).
//
// D38 fix pass (packet d73d0923) — what changed and why:
//   * F1: the escrow OWNS its clock. Every timestamp and expiry
//     decision uses the clock injected at construction; the `now`
//     parameters on the public methods are retained only for
//     call-site compatibility and are NEVER trusted (a caller
//     passing the request's own RequestedUtc cannot resurrect an
//     expired approval, and cannot backdate audit entries — audit
//     timestamps come from the same owned clock).
//   * F2: actor names are NORMALISED (trimmed) before storage and
//     comparison, so "admin-a " is admin-a and cannot pass the
//     distinct-approver check as a different person. An optional
//     admin authorizer (Func<string,bool> over the normalised
//     name) can be injected by the host; when present, request /
//     decide / reveal all require it. When absent, actor identity
//     remains caller-supplied at this layer — the same seam every
//     sibling lane uses (the host authenticates the caller); that
//     residual is named, not hidden.
//   * F3: Decide and Reveal are ATOMIC: read, checks, state
//     transition (and, for Reveal, unprotect + fingerprint verify
//     + burn + audit) all happen inside the one gate lock, so two
//     concurrent reveals cannot both return the key and an
//     approve cannot race a deny.
//   * F8: listings now carry the BitLocker key-protector ID (when
//     the escrowing read supplied one) and an IsCurrentForVolume
//     marker: escrowing a new key for a volume marks every older
//     entry for that volume superseded, so a recovery operator can
//     tell which key is current. The service intake path only
//     escrows keys the driver read for volumes in the device's own
//     report; direct Escrow callers are the trusted intake seam.
//   * F11: caller free text is percent-escaped in audit details.
//   * F12: terminal reveal requests (revealed / denied / expired)
//     are pruned when a new request is recorded — the chained
//     audit is the permanent record, the live store stays bounded.
//     An optional operation gate (device, actor, op) lets the
//     owning service apply its policy toggle to this path too.
// =====================================================================

/// <summary>Escrow metadata — the ONLY shape listings expose. There
/// is deliberately no key field, no protected-text field.</summary>
public sealed record EscrowedKeyMetadata(
    string Ref,
    string DeviceId,
    string VolumeId,
    string ScopeId,
    string KeyFingerprint,        // SHA-256 of the key material — a fingerprint, never the key
    string KeyProtectorType,
    string EscrowedBy,
    DateTimeOffset EscrowedUtc,
    string ProtectorName,
    bool IsRealProtection,
    string? KeyProtectorId = null,     // D38 F8: the OS key-protector ID (e.g. BitLocker protector GUID) when the read supplied one — the id the recovery screen shows
    bool IsCurrentForVolume = true)    // D38 F8: false once a newer key has been escrowed for the same (device, volume) — superseded, retained as history
{
}

public static class RevealRequestStates
{
    public const string PendingApproval = "pending_approval";
    public const string Approved = "approved";
    public const string Revealed = "revealed";
    public const string Expired = "expired";
    public const string Denied = "denied";
}

/// <summary>A dual-control reveal request. Carries metadata only.</summary>
public sealed record RevealRequest(
    string RequestId,
    string EscrowRef,
    string DeviceId,
    string VolumeId,
    string RequestedBy,
    string Reason,
    DateTimeOffset RequestedUtc,
    DateTimeOffset ExpiresUtc,
    string State,
    string? ApprovedBy,
    DateTimeOffset? ApprovedUtc,
    DateTimeOffset? RevealedUtc)
{
    public static string IdFor(string escrowRef, string requestedBy, DateTimeOffset requestedUtc) =>
        "reveal-" + EncryptionHash.Sha256Hex($"{escrowRef}|{requestedBy}|{requestedUtc:O}")[..20];
}

public sealed class RecoveryKeyEscrow
{
    /// <summary>How long an approved (or pending) reveal request
    /// lives. Short: a reveal grant left lying around is a standing
    /// hole, so the window is an hour, named here.</summary>
    public static readonly TimeSpan RevealWindow = TimeSpan.FromHours(1);

    private sealed record Entry(string ProtectedValue, EscrowedKeyMetadata Metadata);

    private readonly Dictionary<string, Entry> _entries = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, RevealRequest> _requests = new(StringComparer.OrdinalIgnoreCase);
    private readonly ISecretProtector _protector;
    private readonly ChainedAuditLog _audit;
    private readonly Func<DateTimeOffset> _clock;
    private readonly Func<string, bool>? _isAdminActor;
    private readonly Func<string, string, string, bool>? _operationGate;
    private readonly object _gate = new();

    /// <param name="clock">The escrow's OWN clock (D38 F1). All
    /// timestamps and expiry decisions use it; caller-supplied
    /// times are never trusted. Defaults to UTC now.</param>
    /// <param name="isAdminActor">Optional admin authorizer over
    /// the NORMALISED actor name (D38 F2).</param>
    /// <param name="operationGate">Optional (deviceId, actor, op)
    /// gate — the owning service's policy toggle (D38 F12).</param>
    public RecoveryKeyEscrow(ISecretProtector protector, ChainedAuditLog audit,
        Func<DateTimeOffset>? clock = null,
        Func<string, bool>? isAdminActor = null,
        Func<string, string, string, bool>? operationGate = null)
    {
        _protector = protector ?? throw new ArgumentNullException(nameof(protector));
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
        _isAdminActor = isAdminActor;
        _operationGate = operationGate;
    }

    public bool IsRealProtection => _protector.IsRealProtection;
    public string ProtectorName => _protector.Name;

    private DateTimeOffset Now() => _clock();

    /// <summary>Actor normalisation (D38 F2): surrounding whitespace
    /// is not a different person. bd-shared-sec-1/F5: trailing
    /// punctuation is not a different person either — "admin-a." is
    /// admin-a for every storage and distinctness comparison.</summary>
    public static string NormalizeActor(string? actor) => (actor ?? "").Trim().TrimEnd('.').Trim();

    /// <summary>bd-shared-sec-1/F5 (BLOCKER-adjacent HIGH): dual
    /// control FAILS CLOSED. When no admin authorizer is wired, the
    /// reveal path (request / decide / reveal) refuses EVERY actor —
    /// one person typing two free-text names must never be able to
    /// extract a key. Escrow intake is unaffected (it is the
    /// endpoint agent's act, not an admin act).</summary>
    private bool AdminRefused(string actor) => _isAdminActor is null || !_isAdminActor(actor);

    /// <summary>Raised after every successful mutation so the host
    /// can write the escrow through to disk (bd-shared-sec-1/F1).</summary>
    public event Action? Changed;
    private bool GateRefused(string deviceId, string actor, string op) =>
        _operationGate is not null && !_operationGate(deviceId, actor, op);

    public static string RefFor(string deviceId, string volumeId, string keyFingerprint) =>
        "escrow-" + EncryptionHash.Sha256Hex($"{deviceId}|{volumeId}|{keyFingerprint}")[..20];

    private static string E(string? s) => EncryptionAuditText.Escape(s);

    // ---- escrow --------------------------------------------------------------

    /// <summary>Escrow one recovery key read by the endpoint driver
    /// for (deviceId, volumeId). The binding (device, volume, key
    /// hash) is computed HERE from the actual key, so the entry can
    /// never claim a binding its material does not satisfy. Re-
    /// escrowing the same key for the same volume is idempotent
    /// (same ref); a DIFFERENT key for the same volume creates a new
    /// ref and SUPERSEDES the old entry in listings (the old entry
    /// is retained, marked IsCurrentForVolume=false — an escrow
    /// history is evidence; rotation is loud). Audit + return carry
    /// metadata only. The `now` argument is NOT trusted (D38 F1);
    /// the escrow's own clock stamps the entry.</summary>
    public (bool Ok, string Reason, EscrowedKeyMetadata? Metadata) Escrow(
        string deviceId, string volumeId, string scopeId, string keyMaterial,
        string keyProtectorType, string escrowedBy, DateTimeOffset now,
        string? keyProtectorId = null)
    {
        var stamp = Now();
        escrowedBy = NormalizeActor(escrowedBy);
        (bool, string, EscrowedKeyMetadata?) Refuse(string reason)
        {
            _audit.Append("encryption_key_escrow_refused", escrowedBy,
                $"device={E(deviceId)} volume={E(volumeId)} reason={E(reason)}", stamp);
            return (false, reason, null);
        }
        if (string.IsNullOrWhiteSpace(deviceId) || string.IsNullOrWhiteSpace(volumeId))
            return Refuse("escrow needs a device and a volume — refused (an unbound key is never escrowed)");
        if (string.IsNullOrWhiteSpace(keyMaterial))
            return Refuse("no key material was read for this volume — refused (nothing is escrowed on a guess)");
        if (string.IsNullOrWhiteSpace(escrowedBy))
            return Refuse("escrow needs a named actor — refused");
        if (GateRefused(deviceId, escrowedBy, "key escrow"))
            return Refuse($"key escrow for device '{deviceId}' is refused by the owning service's policy gate");

        var fingerprint = EncryptionHash.Sha256Hex(keyMaterial);
        var meta = new EscrowedKeyMetadata(
            RefFor(deviceId, volumeId, fingerprint), deviceId, volumeId, scopeId ?? "",
            fingerprint, keyProtectorType ?? "", escrowedBy, stamp,
            _protector.Name, _protector.IsRealProtection, keyProtectorId, IsCurrentForVolume: true);
        List<string> supersededRefs;
        lock (_gate)
        {
            // D38 F8: the new entry supersedes every older entry for
            // this (device, volume) in listings.
            var older = _entries.Where(kv => kv.Key != meta.Ref
                         && string.Equals(kv.Value.Metadata.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase)
                         && string.Equals(kv.Value.Metadata.VolumeId, volumeId, StringComparison.OrdinalIgnoreCase)).ToList();
            supersededRefs = older.Where(kv => kv.Value.Metadata.IsCurrentForVolume)
                .Select(kv => kv.Key).ToList();
            foreach (var kv in older)
                _entries[kv.Key] = kv.Value with { Metadata = kv.Value.Metadata with { IsCurrentForVolume = false } };
            _entries[meta.Ref] = new Entry(_protector.Protect(keyMaterial), meta);
        }
        Changed?.Invoke();
        _audit.Append("encryption_key_escrowed", escrowedBy,
            $"ref={E(meta.Ref)} device={E(deviceId)} volume={E(volumeId)} scope={E(meta.ScopeId)} fingerprint={fingerprint} protector={E(meta.ProtectorName)} protectorId={E(meta.KeyProtectorId)} realProtection={meta.IsRealProtection}", stamp);
        // W10 / V2-C1 (escrow limb): a supersede is a ROTATION, never
        // a silent replace — the superseded entries are RETAINED
        // (marked not-current, still revealable under dual control
        // while their protector lives), and the rotation itself is a
        // distinctly-named chained audit event naming both refs, so
        // an intake caller swapping the current key leaves a loud,
        // attributable record rather than a quiet overwrite.
        foreach (var oldRef in supersededRefs)
            _audit.Append("encryption_key_escrow_superseded", escrowedBy,
                $"ref={E(oldRef)} supersededBy={E(meta.Ref)} device={E(deviceId)} volume={E(volumeId)} newFingerprint={fingerprint}", stamp);
        return (true, $"recovery key escrowed for device '{deviceId}' volume '{volumeId}' as {meta.Ref} (fingerprint {fingerprint[..12]}…)", meta);
    }

    /// <summary>Metadata listings — refs and fingerprints, never key
    /// material (the DTO has no field that could carry it).</summary>
    public IReadOnlyList<EscrowedKeyMetadata> List(string? deviceId = null, string? scopeId = null)
    {
        lock (_gate) return _entries.Values.Select(e => e.Metadata)
            .Where(m => (deviceId is null || string.Equals(m.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase)) &&
                        (scopeId is null || string.Equals(m.ScopeId, scopeId, StringComparison.OrdinalIgnoreCase)))
            .OrderBy(m => m.Ref, StringComparer.Ordinal).ToList();
    }

    public EscrowedKeyMetadata? GetMetadata(string escrowRef)
    {
        lock (_gate) return escrowRef is not null && _entries.TryGetValue(escrowRef, out var e) ? e.Metadata : null;
    }

    // ---- dual-control reveal ---------------------------------------------------

    /// <summary>Step 1: an admin requests a reveal, naming the
    /// device + volume the key must be bound to. A request whose
    /// device/volume does not match the entry's binding refuses
    /// HERE (escrow substitution is caught at request time, not
    /// after approval effort is spent). Expiry runs from the
    /// escrow's OWN clock (D38 F1).</summary>
    public (bool Ok, string Reason, RevealRequest? Request) RequestReveal(
        string escrowRef, string deviceId, string volumeId, string requestedBy, string reason, DateTimeOffset now)
    {
        var stamp = Now();
        requestedBy = NormalizeActor(requestedBy);
        (bool, string, RevealRequest?) Refuse(string r)
        {
            _audit.Append("encryption_key_reveal_refused", requestedBy,
                $"ref={E(escrowRef)} device={E(deviceId)} volume={E(volumeId)} stage=request reason={E(r)}", stamp);
            return (false, r, null);
        }
        if (string.IsNullOrWhiteSpace(requestedBy))
            return Refuse("a reveal request needs a named requester — refused");
        if (AdminRefused(requestedBy))
            return Refuse($"actor '{requestedBy}' is not an authorized admin — refused (dual control runs on authorized admins, not free-text names)");
        if (string.IsNullOrWhiteSpace(reason))
            return Refuse("a reveal request needs a stated reason — refused (a key reveal is never casual)");
        EscrowedKeyMetadata? meta;
        lock (_gate) meta = escrowRef is not null && _entries.TryGetValue(escrowRef, out var e) ? e.Metadata : null;
        if (meta is null)
            return Refuse($"no escrowed key under ref '{escrowRef}' — refused");
        if (GateRefused(meta.DeviceId, requestedBy, "reveal request"))
            return Refuse($"reveal requests for device '{meta.DeviceId}' are refused by the owning service's policy gate");
        if (!string.Equals(meta.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(meta.VolumeId, volumeId, StringComparison.OrdinalIgnoreCase))
            return Refuse($"binding mismatch: ref '{escrowRef}' is bound to device '{meta.DeviceId}' volume '{meta.VolumeId}', not device '{deviceId}' volume '{volumeId}' — refused (escrow substitution defense)");

        var req = new RevealRequest(
            RevealRequest.IdFor(meta.Ref, requestedBy, stamp), meta.Ref, meta.DeviceId, meta.VolumeId,
            requestedBy, reason, stamp, stamp.Add(RevealWindow), RevealRequestStates.PendingApproval,
            null, null, null);
        lock (_gate)
        {
            // D38 F12: prune terminal requests — the audit chain is
            // the permanent record; the live store stays bounded.
            foreach (var kv in _requests.Where(kv => kv.Value.State is RevealRequestStates.Revealed
                         or RevealRequestStates.Denied or RevealRequestStates.Expired).ToList())
                _requests.Remove(kv.Key);
            _requests[req.RequestId] = req;
        }
        Changed?.Invoke();
        _audit.Append("encryption_key_reveal_requested", requestedBy,
            $"request={E(req.RequestId)} ref={E(meta.Ref)} device={E(meta.DeviceId)} volume={E(meta.VolumeId)} reason={E(reason)} expires={req.ExpiresUtc:O}", stamp);
        return (true, $"reveal request '{req.RequestId}' recorded for device '{meta.DeviceId}' volume '{meta.VolumeId}' — a SECOND admin must approve before any key is revealed", req);
    }

    /// <summary>Step 2: a SECOND, DISTINCT admin approves (or any
    /// admin denies). Self-approval refuses — dual control is real:
    /// one admin alone cannot move a reveal past this step. The
    /// decision is atomic (D38 F3): state read, checks and the
    /// transition happen in the one lock, so an approve cannot race
    /// a deny. Expiry uses the escrow's own clock (D38 F1).</summary>
    public (bool Ok, string Reason) ApproveReveal(string requestId, string approver, DateTimeOffset now) =>
        Decide(requestId, approver, approve: true);

    public (bool Ok, string Reason) DenyReveal(string requestId, string denier, DateTimeOffset now) =>
        Decide(requestId, denier, approve: false);

    private (bool Ok, string Reason) Decide(string requestId, string actor, bool approve)
    {
        var stamp = Now();
        actor = NormalizeActor(actor);
        var stage = approve ? "approve" : "deny";
        (bool, string) Refuse(string r)
        {
            _audit.Append("encryption_key_reveal_refused", actor,
                $"request={E(requestId)} stage={stage} reason={E(r)}", stamp);
            return (false, r);
        }
        if (string.IsNullOrWhiteSpace(actor))
            return Refuse("an approval/denial needs a named actor — refused");
        if (AdminRefused(actor))
            return Refuse($"actor '{actor}' is not an authorized admin — refused (dual control runs on authorized admins, not free-text names)");
        RevealRequest decided = null!;
        lock (_gate)
        {
            if (!_requests.TryGetValue(requestId ?? "", out var req) || req is null)
                return Refuse($"unknown reveal request '{requestId}' — refused");
            if (GateRefused(req.DeviceId, actor, approve ? "reveal approval" : "reveal denial"))
                return Refuse($"reveal decisions for device '{req.DeviceId}' are refused by the owning service's policy gate");
            if (req.State != RevealRequestStates.PendingApproval)
                return Refuse($"reveal request '{requestId}' is '{req.State}' — only a pending request can be decided; refused");
            if (stamp > req.ExpiresUtc)
            {
                _requests[requestId] = req with { State = RevealRequestStates.Expired };
                return Refuse($"reveal request '{requestId}' expired at {req.ExpiresUtc:O} — refused (a fresh request is required)");
            }
            if (approve && string.Equals(actor, req.RequestedBy, StringComparison.OrdinalIgnoreCase))
                return Refuse("the requester cannot approve their own reveal request — dual control requires a second, distinct admin; refused");
            decided = req with
            {
                State = approve ? RevealRequestStates.Approved : RevealRequestStates.Denied,
                ApprovedBy = actor,
                ApprovedUtc = stamp,
            };
            _requests[requestId] = decided;
        }
        Changed?.Invoke();
        _audit.Append(approve ? "encryption_key_reveal_approved" : "encryption_key_reveal_denied", actor,
            $"request={E(requestId)} ref={E(decided.EscrowRef)} device={E(decided.DeviceId)} volume={E(decided.VolumeId)} requestedBy={E(decided.RequestedBy)}", stamp);
        return (true, approve
            ? $"reveal request '{requestId}' approved by second admin '{actor}' — the requester may now reveal, once, within the window"
            : $"reveal request '{requestId}' denied by '{actor}' — no key will be revealed under it");
    }

    /// <summary>Step 3 — THE reveal: the ONLY path key material
    /// leaves the vault. ATOMIC (D38 F3): the request read, every
    /// gate check, the unprotect + fingerprint re-verification, the
    /// single-use burn and the audit append all happen inside the
    /// one gate lock, so two concurrent reveals cannot both succeed
    /// and no crash or replay produces an unaudited or repeated
    /// reveal. Expiry uses the escrow's own clock (D38 F1); the
    /// audit entry is appended BEFORE the key is returned.</summary>
    public (bool Ok, string Reason, string? KeyMaterial) Reveal(string requestId, string revealedBy, DateTimeOffset now)
    {
        var stamp = Now();
        revealedBy = NormalizeActor(revealedBy);
        (bool, string, string?) Refuse(string r)
        {
            _audit.Append("encryption_key_reveal_refused", revealedBy,
                $"request={E(requestId)} stage=reveal reason={E(r)}", stamp);
            return (false, r, null);
        }
        if (AdminRefused(revealedBy))
            return Refuse($"actor '{revealedBy}' is not an authorized admin — refused (dual control runs on authorized admins, not free-text names)");
        lock (_gate)
        {
            if (!_requests.TryGetValue(requestId ?? "", out var req) || req is null)
                return Refuse($"unknown reveal request '{requestId}' — refused");
            if (!_entries.TryGetValue(req.EscrowRef, out var entry) || entry is null)
                return Refuse($"escrow entry '{req.EscrowRef}' no longer exists — refused");
            if (GateRefused(req.DeviceId, revealedBy, "reveal"))
                return Refuse($"reveals for device '{req.DeviceId}' are refused by the owning service's policy gate");
            if (req.State != RevealRequestStates.Approved)
                return Refuse($"reveal request '{requestId}' is '{req.State}' — a reveal requires a completed dual-control approval; refused (single-actor reveal is impossible by construction)");
            if (stamp > req.ExpiresUtc)
            {
                _requests[requestId] = req with { State = RevealRequestStates.Expired };
                return Refuse($"reveal request '{requestId}' expired at {req.ExpiresUtc:O} — refused");
            }
            if (!string.Equals(revealedBy, req.RequestedBy, StringComparison.OrdinalIgnoreCase))
                return Refuse($"only the original requester '{req.RequestedBy}' may complete this reveal — refused");

            string key;
            try { key = _protector.Unprotect(entry.ProtectedValue); }
            catch { return Refuse($"escrow entry '{req.EscrowRef}' could not be unprotected — refused (the key is NOT revealed on a protection failure)"); }
            if (!string.Equals(EncryptionHash.Sha256Hex(key), entry.Metadata.KeyFingerprint, StringComparison.OrdinalIgnoreCase))
                return Refuse($"escrow entry '{req.EscrowRef}' material does not match its binding fingerprint — SUBSTITUTION/TAMPER suspected; refused, the mismatched material is never revealed");

            // Burn + audit BEFORE returning the material — same lock.
            _requests[requestId] = req with { State = RevealRequestStates.Revealed, RevealedUtc = stamp };
            Changed?.Invoke();
            _audit.Append("encryption_key_revealed", revealedBy,
                $"request={E(requestId)} ref={E(req.EscrowRef)} device={E(req.DeviceId)} volume={E(req.VolumeId)} approvedBy={E(req.ApprovedBy)} fingerprint={entry.Metadata.KeyFingerprint}", stamp);
            return (true, $"recovery key for device '{req.DeviceId}' volume '{req.VolumeId}' revealed under dual control (request {requestId}, approved by {req.ApprovedBy})", key);
        }
    }

    public RevealRequest? GetRequest(string requestId)
    {
        lock (_gate) return requestId is not null && _requests.TryGetValue(requestId, out var r) ? r : null;
    }

    public IReadOnlyList<RevealRequest> Requests
    {
        get { lock (_gate) return _requests.Values.OrderBy(r => r.RequestId, StringComparer.Ordinal).ToList(); }
    }

    // ---- hub persistence (bd-shared-sec-1/F1, the BLOCKER) ------
    // The escrow previously lived ONLY in two in-memory
    // dictionaries: a hub restart lost every escrowed recovery key
    // exactly when a machine sat at its recovery screen. The export
    // carries ONLY the ISecretProtector-protected text + metadata
    // (never plaintext key material), wrapped in the HubPersistence
    // integrity envelope (TreatmentStore's pattern).

    private sealed record EntryDto(string ProtectedValue, EscrowedKeyMetadata Metadata);
    private sealed record StoreDto(List<EntryDto> Entries, List<RevealRequest> Requests);

    public string ExportJson()
    {
        lock (_gate)
            return HubPersistence.Wrap("acp-recovery-key-escrow-v1",
                JsonSerializer.Serialize(new StoreDto(
                    _entries.Values.OrderBy(e => e.Metadata.Ref, StringComparer.Ordinal)
                        .Select(e => new EntryDto(e.ProtectedValue, e.Metadata)).ToList(),
                    _requests.Values.OrderBy(r => r.RequestId, StringComparer.Ordinal).ToList())));
    }

    /// <summary>Restore escrowed keys + live reveal requests. Every
    /// entry is RE-VERIFIED before it lands: the protector name must
    /// be this escrow's protector (provenance), the protected text
    /// must unprotect, the recomputed fingerprint must equal the
    /// stored fingerprint, and the ref must recompute from
    /// (device, volume, fingerprint). An entry failing any check is
    /// skipped, never imported — a tampered-but-envelope-valid file
    /// cannot plant a key under a false binding. Terminal reveal
    /// requests are not restored (the chained audit is their
    /// permanent record). Returns the number of ENTRIES restored.</summary>
    public int ImportJson(string json)
    {
        var payload = HubPersistence.Unwrap(json, "acp-recovery-key-escrow-v1");
        if (payload is null) return 0;
        StoreDto? dto;
        try { dto = JsonSerializer.Deserialize<StoreDto>(payload); } catch { return 0; }
        if (dto is null) return 0;
        var restored = 0;
        lock (_gate)
        {
            foreach (var e in dto.Entries ?? new List<EntryDto>())
            {
                if (e?.Metadata is null || string.IsNullOrWhiteSpace(e.ProtectedValue)) continue;
                var m = e.Metadata;
                if (_entries.ContainsKey(m.Ref)) continue;
                if (!string.Equals(m.ProtectorName, _protector.Name, StringComparison.Ordinal)) continue;
                string key;
                try { key = _protector.Unprotect(e.ProtectedValue); } catch { continue; }
                var fingerprint = EncryptionHash.Sha256Hex(key);
                if (!string.Equals(fingerprint, m.KeyFingerprint, StringComparison.OrdinalIgnoreCase)) continue;
                if (!string.Equals(RefFor(m.DeviceId, m.VolumeId, fingerprint), m.Ref, StringComparison.OrdinalIgnoreCase)) continue;
                _entries[m.Ref] = new Entry(e.ProtectedValue, m);
                restored++;
            }
            foreach (var r in dto.Requests ?? new List<RevealRequest>())
            {
                if (r is null || _requests.ContainsKey(r.RequestId)) continue;
                if (r.State is RevealRequestStates.Revealed or RevealRequestStates.Denied or RevealRequestStates.Expired) continue;
                if (!_entries.ContainsKey(r.EscrowRef)) continue;
                _requests[r.RequestId] = r;
            }
        }
        if (restored > 0) Changed?.Invoke();
        return restored;
    }
}
