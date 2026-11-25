using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Acp.Shared.Security;

namespace Acp.Shared.Enterprise;

// =====================================================================
// Block E — BUILD-NOW backlog models: revocation tracking (BAD),
// creator-attributed inventory (BAD-15), scam friction (SCAM),
// session receipts (HELP), access reviews, drift, transfer controls,
// service tokens, legal hold, admin-removal guard, SPOF detection,
// signed revocation records, clean verification, permission vocabulary.
// =====================================================================

// ------------------------------------------------- BAD-02/03/04/12/36/37
// + R-10: tracked revocation fan-out. Each sub-action is independently
// confirmed / pending / failed. ACP identity revocation and mesh node
// revocation are SEPARATE sub-actions; neither is inferred from the
// other (BAD-04). While any acknowledgement is pending the summary
// wording never says plain "revoked" (BAD-03). State checkpoints:
// ExportState/ImportState resume at the first unconfirmed sub-action
// (BAD-36). Completion exports a signed incident record (BAD-37).

public sealed record RevocationSubAction(string Kind, string TargetId, string State, DateTimeOffset? GrantExpiresUtc);
public sealed class RevocationTracker
{
    public const string Pending = "pending", Confirmed = "confirmed", Failed = "failed";
    private readonly List<RevocationSubAction> _subs = new();
    public string IncidentId { get; }
    public string Trigger { get; }
    public DateTimeOffset StartedUtc { get; }
    public RevocationTracker(string incidentId, string trigger, DateTimeOffset startedUtc) { IncidentId = incidentId; Trigger = trigger; StartedUtc = startedUtc; }
    public IReadOnlyList<RevocationSubAction> SubActions => _subs.ToList();

    public void Add(string kind, string targetId, DateTimeOffset? grantExpiresUtc = null) =>
        _subs.Add(new RevocationSubAction(kind, targetId, Pending, grantExpiresUtc));
    public void SetState(string kind, string targetId, string state)
    {
        var i = _subs.FindIndex(s => s.Kind == kind && s.TargetId == targetId);
        if (i < 0) throw new InvalidOperationException($"no sub-action {kind}/{targetId}");
        _subs[i] = _subs[i] with { State = state };
    }
    /// <summary>BAD-36: the first unconfirmed sub-action is the resume point.</summary>
    public RevocationSubAction? FirstUnconfirmed() => _subs.FirstOrDefault(s => s.State != Confirmed);
    public bool AllConfirmed => _subs.Count > 0 && _subs.All(s => s.State == Confirmed);

    /// <summary>BAD-03 wording rule: unqualified "revoked" is forbidden
    /// while acknowledgements are pending; pending peers are named with
    /// the time their existing grants expire.</summary>
    public string SummaryWording()
    {
        var pending = _subs.Where(s => s.State != Confirmed).ToList();
        if (pending.Count == 0) return $"Revoked: all {_subs.Count} sub-actions confirmed for incident {IncidentId}.";
        var names = string.Join("; ", pending.Select(p => $"{p.Kind}/{p.TargetId} ({p.State}" + (p.GrantExpiresUtc is { } g ? $", existing grants expire {g:O}" : "") + ")"));
        return $"Revocation in progress for incident {IncidentId}: {_subs.Count - pending.Count} of {_subs.Count} confirmed. Not yet confirmed: {names}.";
    }

    public string ExportState() => JsonSerializer.Serialize(new { IncidentId, Trigger, StartedUtc, Subs = _subs });
    public static RevocationTracker ImportState(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var r = doc.RootElement;
        var t = new RevocationTracker(r.GetProperty("IncidentId").GetString()!, r.GetProperty("Trigger").GetString()!, r.GetProperty("StartedUtc").GetDateTimeOffset());
        foreach (var s in r.GetProperty("Subs").EnumerateArray())
            t._subs.Add(new RevocationSubAction(s.GetProperty("Kind").GetString()!, s.GetProperty("TargetId").GetString()!, s.GetProperty("State").GetString()!,
                s.GetProperty("GrantExpiresUtc").ValueKind == JsonValueKind.Null ? null : s.GetProperty("GrantExpiresUtc").GetDateTimeOffset()));
        return t;
    }

    /// <summary>BAD-37: exportable, signed incident record (local file;
    /// export is a user act — nothing here transmits anything).</summary>
    public string ExportSignedIncidentRecord(DeviceIdentity signer, DateTimeOffset exposureWindowEndUtc)
    {
        var body = JsonSerializer.Serialize(new
        {
            IncidentId, Trigger, StartedUtc, ExposureWindowEndUtc = exposureWindowEndUtc,
            SubActions = _subs, Summary = SummaryWording(), SignerDeviceId = signer.DeviceId
        });
        var sig = Convert.ToBase64String(signer.Sign(Encoding.UTF8.GetBytes(body)));
        return JsonSerializer.Serialize(new { record = JsonDocument.Parse(body).RootElement, signature = sig });
    }
}

/// <summary>BAD-35: revocation records are signed trust-log entries,
/// propagatable over any transport, applied on receipt, with expiry as
/// the offline backstop.</summary>
public sealed record SignedRevocation(string TargetId, string Kind, DateTimeOffset IssuedUtc, DateTimeOffset ExpiresUtc, string IssuerDeviceId, string SignatureBase64)
{
    public static SignedRevocation Create(DeviceIdentity issuer, string targetId, string kind, DateTimeOffset now, TimeSpan lifetime) =>
        new(targetId, kind, now, now + lifetime, issuer.DeviceId,
            Convert.ToBase64String(issuer.Sign(Encoding.UTF8.GetBytes(Canonical(targetId, kind, now, now + lifetime, issuer.DeviceId)))));
    public static string Canonical(string t, string k, DateTimeOffset i, DateTimeOffset e, string d) => $"acp-revocation-v1|{t}|{k}|{i:O}|{e:O}|{d}";
    public static PolicyVerdict ApplyOnReceipt(SignedRevocation r, byte[] issuerPublicKey, DateTimeOffset now)
    {
        bool ok;
        try { ok = Ed25519.Verify(issuerPublicKey, Encoding.UTF8.GetBytes(Canonical(r.TargetId, r.Kind, r.IssuedUtc, r.ExpiresUtc, r.IssuerDeviceId)), Convert.FromBase64String(r.SignatureBase64)); }
        catch { ok = false; }
        if (!ok) return new PolicyVerdict(false, "revocation record signature invalid — not applied");
        if (now > r.ExpiresUtc) return new PolicyVerdict(false, "revocation record expired — offline backstop reached; re-issue required");
        return new PolicyVerdict(true, "revocation applied on receipt");
    }
}

/// <summary>BAD-05: capability/session tokens are short-lived and
/// locally expiry-enforced. The shipped default IS the worst-case
/// offline revocation window and is stated, in-product, as such.</summary>
public static class TokenLifetimePolicy
{
    public static readonly TimeSpan DefaultMaxLifetime = TimeSpan.FromHours(24);
    public const string StatedOfflineWindow = "24 hours (the shipped default maximum token lifetime is the worst-case offline revocation window)";
    public static PolicyVerdict Validate(TimeSpan requested, TimeSpan? companyMax = null)
    {
        var cap = companyMax ?? DefaultMaxLifetime;
        if (requested <= TimeSpan.Zero) return new PolicyVerdict(false, "non-positive token lifetime refused");
        if (requested > cap) return new PolicyVerdict(false, $"token lifetime {requested} exceeds the cap {cap} — long-lived grants to a device identity are prohibited (BAD-05)");
        return new PolicyVerdict(true, "token lifetime within cap");
    }
}

// ------------------------------------------------- BAD-08/13/15/16/20
// + ADIR-25 + R-17: creator-attributed inventory of every security
// object. The D14 blast list is computed FROM this inventory (BAD-13),
// and removal must evict identities the target's keys ADMITTED, not
// only objects the target created (BAD-16). Sparing an admitted
// identity requires naming it + a recorded reason (BAD-16).

public sealed record SecurityObject(string Kind, string Id, string CreatedByUserId, string ScopeId,
    DateTimeOffset CreatedUtc, IReadOnlyList<string> AdmittedIds);

public sealed class SecurityObjectInventory
{
    private readonly List<SecurityObject> _items = new();
    public void Record(SecurityObject o) => _items.Add(o);
    public IReadOnlyList<SecurityObject> CreatedBy(string userId) => _items.Where(i => i.CreatedByUserId == userId).ToList();
    public IReadOnlyList<SecurityObject> All => _items.ToList();

    /// <summary>BAD-16 eviction list: every identity admitted by any
    /// object the target created, minus explicitly spared identities.</summary>
    public IReadOnlyList<string> EvictionList(string targetUserId, IReadOnlyDictionary<string, string> sparedWithReasons)
    {
        var admitted = CreatedBy(targetUserId).SelectMany(o => o.AdmittedIds).Distinct().ToList();
        return admitted.Where(id => !sparedWithReasons.ContainsKey(id)).ToList();
    }
    public static PolicyVerdict ValidateSparing(string identityId, string? reason) =>
        string.IsNullOrWhiteSpace(reason)
            ? new PolicyVerdict(false, $"sparing admitted identity {identityId} requires a recorded reason (BAD-16)")
            : new PolicyVerdict(true, "sparing recorded with reason");

    /// <summary>BAD-20: post-removal rotation checklist. The boundary is
    /// stated honestly — ACP cannot list secrets it never held.</summary>
    public IReadOnlyList<string> RotationChecklist(string removedUserId, string externalSystemName)
    {
        var lines = CreatedBy(removedUserId).Select(o => $"Rotate/revoke {o.Kind} {o.Id} (created by {removedUserId})").ToList();
        lines.Add($"ACP cannot list passwords held only in {externalSystemName} — rotate those separately.");
        return lines;
    }
}

/// <summary>BAD-14: single-point-of-human-failure detection. The warning
/// names the specific remedy for each sole-holder state.</summary>
public static class SpofDetector
{
    public static IReadOnlyList<string> Detect(bool soleAdmin, bool soleSigningAuthorityHolder, bool soleBreakGlassHolder, bool soleApprover, bool personalScope)
    {
        var w = new List<string>();
        if (soleAdmin) w.Add("Sole company admin: add a second admin — a sole rogue admin is removable only via break-glass (BAD-19).");
        if (soleSigningAuthorityHolder) w.Add("Sole holder of a signing authority: nominate a second holder.");
        if (soleBreakGlassHolder) w.Add("Sole break-glass holder: seal a second holder or an offline artefact (BAD-32).");
        if (soleApprover) w.Add("Sole approver: dual control is impossible until a second approver exists (BAD-18).");
        if (personalScope && w.Count == 0) w.Add("You are your only recovery path except your printed recovery key.");
        return w;
    }
}

/// <summary>BAD-18 + ADIR-14: admin-removes-admin. With at least two
/// other admins, a second admin must confirm (dual control). Otherwise
/// a notified cooling-off window applies with the target frozen, and
/// any admin may veto.</summary>
public static class AdminRemovalGuard
{
    public sealed record Decision(string Mode, DateTimeOffset? CoolingOffEndsUtc, string Reason);
    public static Decision Evaluate(int otherAdminCount, bool secondAdminConfirmed, DateTimeOffset now) =>
        otherAdminCount >= 2
            ? (secondAdminConfirmed
                ? new Decision("dual_control_satisfied", null, "second admin confirmed (BAD-18)")
                : new Decision("dual_control_required", null, "a second admin must confirm before this removal fires (BAD-18)"))
            : new Decision("cooling_off", now.AddHours(24), "dual control impossible: 24h notified cooling-off, target frozen, any admin may veto (BAD-18)");
}

/// <summary>BAD-33: a suspended object resumes only by explicit
/// re-authorisation of its scope by its new owner — never by restoring
/// its pre-suspension scope.</summary>
public static class SuspendedResumeGuard
{
    public static PolicyVerdict CheckResume(string objectKind, string? reauthorisedByNewOwner) =>
        string.IsNullOrWhiteSpace(reauthorisedByNewOwner)
            ? new PolicyVerdict(false, $"suspended {objectKind} may resume only by explicit re-authorisation from its new owner (BAD-33)")
            : new PolicyVerdict(true, "resume re-authorised by new owner");
}

/// <summary>BAD-34: the reusable "clean" verification: roster
/// reconciliation, credential-inventory reconciliation, negative tests,
/// log continuity across at least two holders, named residuals.</summary>
public sealed record CleanVerification(bool RosterReconciled, bool InventoryReconciled, bool NegativeTestsPassed,
    int LogHoldersVerified, IReadOnlyList<string> NamedResiduals)
{
    public bool IsClean => RosterReconciled && InventoryReconciled && NegativeTestsPassed && LogHoldersVerified >= 2;
    public string Verdict => IsClean && NamedResiduals.Count == 0 ? "clean" : $"not clean: residuals=[{string.Join("; ", NamedResiduals)}] holders={LogHoldersVerified}";
}

// ------------------------------------------------- SCAM-01..22 model +
// HELP-07: first-seen-operator friction. Friction lives at
// first-session / first-operator and is endpoint-local. Established
// status is EARNED (>=3 completed, endpoint-not-stopped sessions, no
// sensitive-context triggers) and is the only fast path (SCAM-15).
// Nothing in policy or configuration can disable these states
// (SCAM-20): this type takes no policy input at all.

public sealed record OperatorHistory(int CompletedCleanSessions, int StoppedSessions, int SensitiveContextTriggers, DateTimeOffset? LastStopUtc, bool MarkedKnownTrustedLocally);
public sealed record FrictionDecision(string Level, bool StartsViewOnly, bool SecondConsentRequired, int SecondConsentEarliestSeconds,
    bool WarningRequired, string PresenceLabel, string Reason);

public static class ScamFriction
{
    private static readonly string[] ImpersonationTerms =
        { "microsoft", "apple", "support", "fraud department", "irs", "fbi", "police", "bank", "amazon", "paypal", "tech support" };

    public static bool HasImpersonationTerm(string? displayName) =>
        displayName is not null && ImpersonationTerms.Any(t => displayName.Contains(t, StringComparison.OrdinalIgnoreCase));

    public static bool IsEstablished(OperatorHistory h) =>
        h.CompletedCleanSessions >= 3 && h.StoppedSessions == 0 && h.SensitiveContextTriggers == 0;

    /// <summary>SCAM-22: an operator who once triggered a sensitive-context
    /// pause on a banking surface, or whose session was stopped, is never
    /// treated as first-seen-friendly again — friction returns in full.</summary>
    public static FrictionDecision Evaluate(string operatorKey, string? displayName, OperatorHistory h, DateTimeOffset? installFirstRunUtc, DateTimeOffset now, bool callActive)
    {
        var freshInstall = installFirstRunUtc is { } f && now - f < TimeSpan.FromHours(24); // SCAM-13
        var inCooldown = h.LastStopUtc is { } s && now - s < TimeSpan.FromMinutes(30);       // SCAM-08
        var impersonation = HasImpersonationTerm(displayName) && !h.MarkedKnownTrustedLocally; // SCAM-05
        var established = IsEstablished(h) && !freshInstall && !inCooldown && !impersonation && h.SensitiveContextTriggers == 0;
        // SCAM-04: the presence label carries verification state, not just a name.
        var label = established ? (displayName ?? operatorKey) : $"Unverified helper calling themselves '{displayName ?? operatorKey}'";
        if (established)
            return new FrictionDecision("established", false, false, 0, false, label, "earned fast path (SCAM-15)");
        var reasons = new List<string>();
        if (h.CompletedCleanSessions == 0) reasons.Add("first session from this operator (SCAM-01)");
        if (freshInstall) reasons.Add("fresh install within 24h (SCAM-13)");
        if (inCooldown) reasons.Add("cooldown after a stopped session (SCAM-08)");
        if (impersonation) reasons.Add("impersonation-term display name (SCAM-05)");
        if (callActive) reasons.Add("voice call active during first-contact request (SCAM-14 model)");
        if (h.SensitiveContextTriggers > 0) reasons.Add("repeat sensitive-context trigger (SCAM-22)");
        // SCAM-01: view-only start; second consent no earlier than 60s.
        return new FrictionDecision("high_friction", true, true, 60, true, label, string.Join("; ", reasons));
    }

    /// <summary>SCAM-02: the first-pairing ceremony step is local-only.
    /// There is deliberately no operator-side completion path.</summary>
    public static PolicyVerdict CompletePairingCeremony(bool completedAtEndpointLocally, bool operatorClaimsCompletion) =>
        completedAtEndpointLocally && !operatorClaimsCompletion
            ? new PolicyVerdict(true, "pairing ceremony completed at the endpoint")
            : new PolicyVerdict(false, "pairing ceremony can only be completed by the person at the endpoint (SCAM-02)");

    /// <summary>SCAM-09 / HELP-07: sensitive contexts mechanically pause
    /// control for non-established operators.</summary>
    public static bool SensitiveContextPauses(string foregroundContext, OperatorHistory h) =>
        !IsEstablished(h) && foregroundContext is "banking" or "password_field" or "password_manager" or "otp_prompt";

    /// <summary>SCAM-11 persistence lockdown: in-session, an operator may
    /// never create unattended access, change the allowed list, or change
    /// security settings.</summary>
    public static PolicyVerdict InSessionAction(string action) =>
        action is "create_unattended_access" or "modify_allowed_operators" or "change_security_settings"
            ? new PolicyVerdict(false, $"in-session '{action}' is prohibited (SCAM-11 persistence lockdown)")
            : new PolicyVerdict(true, "action not persistence-class");

    /// <summary>SCAM-12: one-off session codes — single-use, 10-minute
    /// expiry, bound view-only until SCAM-01's second consent.</summary>
    public static PolicyVerdict ValidateOneOffCode(DateTimeOffset issuedUtc, bool alreadyUsed, DateTimeOffset now) =>
        alreadyUsed ? new PolicyVerdict(false, "one-off code already used (SCAM-12)")
        : now - issuedUtc > TimeSpan.FromMinutes(10) ? new PolicyVerdict(false, "one-off code expired after 10 minutes (SCAM-12)")
        : new PolicyVerdict(true, "one-off code valid; session starts view-only");
}

// ------------------------------------------------- HELP-08/09 + SCAM-18:
// session-end receipt. Categories are NEVER silently omitted: where
// nothing happened, the receipt says so in plain words — including
// "We did not record this session" where no recording exists.

public sealed record ReceiptFacts(string OperatorName, DateTimeOffset StartedUtc, DateTimeOffset EndedUtc,
    int ControlMinutes, int ViewingMinutes, IReadOnlyList<string> FilesCopied, IReadOnlyList<string> ProgramsOpened,
    bool WasRecorded, string EndReason);

public static class SessionReceipt
{
    public static string Generate(ReceiptFacts f)
    {
        var lines = new List<string>
        {
            $"{f.OperatorName} connected at {f.StartedUtc:t} and finished at {f.EndedUtc:t} ({(f.EndedUtc - f.StartedUtc).TotalMinutes:0} minutes).",
            $"{f.OperatorName} controlled this device for {f.ControlMinutes} minutes and watched for {f.ViewingMinutes} minutes.",
            f.FilesCopied.Count > 0 ? $"Files copied to {f.OperatorName}: {string.Join(", ", f.FilesCopied)}." : "No files were copied.",
            f.ProgramsOpened.Count > 0 ? $"Programs opened: {string.Join(", ", f.ProgramsOpened)}." : "No programs were opened.",
            f.WasRecorded ? "This session was recorded." : "We did not record this session.",
            $"How it ended: {f.EndReason}."
        };
        return string.Join("\n", lines);
    }
}

// ------------------------------------------------- DIR-54 / ADIR-17:
// access-review campaigns. Non-response has a DEFAULT outcome (suspend)
// that fires at the deadline; every disposition is exportable for the
// auditor.

public sealed class AccessReviewCampaign
{
    public sealed record Item(string UserId, string Decision); // pending | attested | remove | defaulted_suspend
    private readonly Dictionary<string, Item> _items = new();
    public DateTimeOffset DeadlineUtc { get; }
    public AccessReviewCampaign(IEnumerable<string> userIds, DateTimeOffset deadlineUtc)
    {
        DeadlineUtc = deadlineUtc;
        foreach (var u in userIds) _items[u] = new Item(u, "pending");
    }
    public void Attest(string userId) => _items[userId] = new Item(userId, "attested");
    public void MarkRemove(string userId) => _items[userId] = new Item(userId, "remove");
    public IReadOnlyList<Item> ApplyDeadlineDefaults(DateTimeOffset now)
    {
        if (now >= DeadlineUtc)
            foreach (var k in _items.Keys.ToList())
                if (_items[k].Decision == "pending") _items[k] = new Item(k, "defaulted_suspend");
        return _items.Values.ToList();
    }
    public string Export() => JsonSerializer.Serialize(_items.Values);
}

// ------------------------------------------------- DIR-55: drift report.
public sealed record DeviceDriftState(string DeviceId, string PolicyVersion, string BuildVersion);
public static class DriftReport
{
    public static IReadOnlyList<string> Compare(IReadOnlyList<DeviceDriftState> fleet, string desiredPolicyVersion, string desiredBuildVersion) =>
        fleet.Where(d => d.PolicyVersion != desiredPolicyVersion || d.BuildVersion != desiredBuildVersion)
             .Select(d => $"{d.DeviceId}: policy {d.PolicyVersion} (want {desiredPolicyVersion}), build {d.BuildVersion} (want {desiredBuildVersion}) — DRIFTED")
             .ToList();
}

// ------------------------------------------------- DIR-62: file-transfer
// content controls. The org's own scanner verdict is an input; an
// unknown verdict BLOCKS when policy requires a verdict. ACP ships no
// scanner of its own and claims none.

public sealed record TransferPolicy(int MaxBytes, IReadOnlySet<string> BlockedExtensions, bool RequireScanVerdict);
public static class FileTransferControls
{
    public static PolicyVerdict Evaluate(string fileName, long sizeBytes, string? scanVerdict, TransferPolicy p)
    {
        var ext = Path.GetExtension(fileName).ToLowerInvariant();
        if (p.BlockedExtensions.Contains(ext)) return new PolicyVerdict(false, $"transfer blocked: extension {ext} is blocked by policy (DIR-62)");
        if (sizeBytes > p.MaxBytes) return new PolicyVerdict(false, $"transfer blocked: {sizeBytes} bytes exceeds policy maximum {p.MaxBytes} (DIR-62)");
        if (scanVerdict == "malicious") return new PolicyVerdict(false, "transfer blocked: org scanner verdict is malicious (DIR-62)");
        if (p.RequireScanVerdict && scanVerdict is null) return new PolicyVerdict(false, "transfer blocked: policy requires an org scanner verdict and none exists (DIR-62)");
        return new PolicyVerdict(true, "transfer permitted by content controls");
    }
}

// ------------------------------------------------- ADIR-29: scoped API
// service tokens. A token carries ONLY its named scopes and an expiry;
// it never inherits a human's role (there is no user field at all).

public sealed class ServiceTokenStore
{
    private sealed record Entry(string TokenHash, IReadOnlySet<string> Scopes, DateTimeOffset ExpiresUtc);
    private readonly Dictionary<string, Entry> _byId = new();
    public (string Id, string SecretOnce) Issue(IReadOnlySet<string> scopes, TimeSpan lifetime, DateTimeOffset now)
    {
        if (lifetime <= TimeSpan.Zero || lifetime > TimeSpan.FromDays(90)) throw new InvalidOperationException("service token lifetime must be positive and <= 90 days");
        var id = Guid.NewGuid().ToString("N");
        var secret = Convert.ToHexString(RandomNumberGenerator.GetBytes(24)).ToLowerInvariant();
        _byId[id] = new Entry(EntUtil.Sha256Hex(secret), scopes, now + lifetime);
        return (id, secret);
    }
    public PolicyVerdict Authorize(string id, string secret, string requiredScope, DateTimeOffset now)
    {
        if (!_byId.TryGetValue(id, out var e)) return new PolicyVerdict(false, "unknown service token");
        if (!EntUtil.FixedEq(e.TokenHash, EntUtil.Sha256Hex(secret))) return new PolicyVerdict(false, "service token secret mismatch");
        if (now >= e.ExpiresUtc) return new PolicyVerdict(false, "service token expired");
        return e.Scopes.Contains(requiredScope) ? new PolicyVerdict(true, "authorized") : new PolicyVerdict(false, $"service token lacks scope '{requiredScope}'");
    }
}

// ------------------------------------------------- ADIR-35 / REC-17:
// legal hold. A hold suspends retention expiry for its slice; a hold
// is NOT a viewing capability (it grants no read access anywhere).

public sealed class LegalHoldStore
{
    private readonly Dictionary<string, (string PlacedByRole, DateTimeOffset ExpiresUtc)> _holds = new();
    public PolicyVerdict Place(string recordingId, string placedByRole, DateTimeOffset expiresUtc)
    {
        if (placedByRole is not ("company_admin" or "legal")) return new PolicyVerdict(false, "legal hold may only be placed by a named authorised role (REC-17)");
        _holds[recordingId] = (placedByRole, expiresUtc);
        return new PolicyVerdict(true, "legal hold placed (retention expiry suspended; no viewing capability granted)");
    }
    public bool IsHeld(string recordingId, DateTimeOffset now) => _holds.TryGetValue(recordingId, out var h) && now < h.ExpiresUtc;
    public PolicyVerdict CheckDeletion(string recordingId, DateTimeOffset now) =>
        IsHeld(recordingId, now)
            ? new PolicyVerdict(false, "deletion blocked: legal hold active (REC-17) — blocked in code, not policy-advised")
            : new PolicyVerdict(true, "no legal hold; deletion governed by retention/erasure rules");
    public void Release(string recordingId) => _holds.Remove(recordingId);
}

// ------------------------------------------------- ADIR-06/07/11:
// the permission vocabulary and the admin surface inventory. The
// withheld permissions DO NOT EXIST in the vocabulary — they are not
// denied, they are unrepresentable. Tests assert their absence.

public static class PermissionVocabulary
{
    public static readonly IReadOnlySet<string> All = new HashSet<string>
    {
        "directory.read", "directory.write", "groups.write", "grants.write", "policy.write",
        "enrollment.oversight", "offboarding.execute", "updates.pin", "audit.read", "audit.export",
        "alerts.read", "breakglass.coauthor", "recording.review", "sessions.terminate", "keys.rotate"
    };
    public static readonly string[] ForbiddenConcepts =
        { "audit.edit", "audit.delete", "presence.configure", "stop.configure", "personal_scope.access", "private_key.view", "credential.view", "session.watch_silent", "user.impersonate", "password.view", "password.set_for_user" };
    /// <summary>ADIR-07: admin session APIs expose metadata + terminate
    /// only. This inventory is the complete admin session surface.</summary>
    public static readonly IReadOnlySet<string> AdminSessionSurface = new HashSet<string> { "session.metadata", "session.terminate" };
}
