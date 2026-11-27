using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.VendorAccess;

namespace DeskGuest.Core.Services;

// =====================================================================
// RMM-23 (item 1) — VendorPassService: the Core wiring for vendor
// access passes.
//
// Composition, not reinvention:
//   * the pass store (DeskGuest.Shared.VendorAccess) carries the model,
//     the token-hash discipline and the per-pass audit trail — this
//     service adds the TOTAL POLICY CONTROL gate
//     (rmm.vendor_passes.enabled), the hash-chained ledger, the
//     credential-reference shape check, session binding with
//     credential injection, and revocation teardown through the
//     session layer's seam (IVendorSessionTeardown).
//   * a vendor session is a REAL session: presence, STOP and audit
//     apply in full (the session layer's own rules). This service
//     binds pass → session id and enforces pass validity at bind
//     and on revalidation; it does not create a shadow session
//     type with weaker rules.
//   * CREDENTIAL INJECTION BOUNDARY: injection runs through
//     ICredentialInjector (vault → session-layer sink, host code).
//     The credential VALUE never transits this service: issue takes
//     a vault REFERENCE (shape-checked by the canonical
//     CredentialReference rule — the cred- vault namespace, ASCII
//     only — AND required to resolve in the vault at issue time,
//     so a password-shaped string can never be persisted as a
//     "reference"), and session setup receives only the injector's
//     receipt.
//   * D38 fixes carried here: F2 — BeginVendorSession and
//     RevokePass are serialised on _gate and the pass is
//     revalidated immediately before AND after injection, so a
//     revocation landing anywhere in the bind→inject window
//     refuses the session instead of presenting a credential for
//     a revoked pass. F4 — group membership is read from the
//     authoritative device facts, never from the caller. F5 — the
//     store is internal: every outside caller goes through this
//     service's policy gates. F7 — RevalidatePass re-checks the
//     policy kill switch, not just the pass's own window.
// =====================================================================

/// <summary>The session layer's teardown seam for pass revocation:
/// end the named live sessions NOW. Implementations are the real
/// SessionService composition in production wiring; the fake below
/// records the contract for tests.</summary>
public interface IVendorSessionTeardown
{
    /// <summary>End every named session; returns the ids actually
    /// ended (a session that already ended is not claimed).</summary>
    IReadOnlyList<string> EndSessions(IReadOnlyList<string> sessionIds, string reason);
}

/// <summary>Test double teardown: records calls, "ends" every named
/// session it has not already ended.</summary>
public sealed class RecordingSessionTeardown : IVendorSessionTeardown
{
    public List<(IReadOnlyList<string> SessionIds, string Reason)> Calls { get; } = new();
    public HashSet<string> AlreadyEnded { get; } = new(StringComparer.Ordinal);
    public IReadOnlyList<string> EndSessions(IReadOnlyList<string> sessionIds, string reason)
    {
        Calls.Add((sessionIds.ToList(), reason));
        return sessionIds.Where(id => !AlreadyEnded.Contains(id)).ToList();
    }
}

public sealed class VendorPassService
{
    private readonly ChainedAuditLog _audit;
    private readonly ManagementPolicyEngine _policy;
    private readonly Func<string, IDeviceFacts?> _factsByDevice;
    private readonly ICredentialInjector? _injector;
    private readonly IVendorSessionTeardown? _teardown;
    private readonly Func<DateTimeOffset> _now;
    private readonly Func<string, string, bool>? _operatorAuthorizer;
    private readonly object _gate = new();

    /// <summary>D38 F5: the store is INTERNAL, not a public
    /// surface. When it was publicly reachable, any caller could
    /// skip this service's policy gate entirely (issue/revoke/
    /// import around TOTAL POLICY CONTROL). The store still
    /// enforces every model invariant itself (defence in depth);
    /// this service is the only public door. Tests reach it via
    /// InternalsVisibleTo.</summary>
    internal VendorPassStore Store { get; }

    /// <param name="operatorAuthorizer">BD-SHARED-PLAT-3/F7:
    /// (scopeId, userId) → true when the user is a live human scope
    /// admin/operator of the scope. When wired (production:
    /// CoreRuntime backs it with the roster), IssuePass and
    /// RevokePass REQUIRE it — the store's free-string escalation
    /// guards alone let any non-vendor string mint or revoke.
    /// When null (bare tooling/tests) the store's own guards are
    /// the only check, exactly as before.</param>
    /// <param name="storeProtector">BD-SHARED-PLAT-3/F6: seals the
    /// pass store's exports (tamper-evident restore).</param>
    public VendorPassService(
        ChainedAuditLog audit,
        ManagementPolicyEngine policy,
        Func<string, IDeviceFacts?> factsByDevice,
        ICredentialInjector? injector = null,
        IVendorSessionTeardown? teardown = null,
        Func<DateTimeOffset>? now = null,
        Func<string, string, bool>? operatorAuthorizer = null,
        DeskGuest.Shared.Security.ISecretProtector? storeProtector = null)
    {
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _policy = policy ?? throw new ArgumentNullException(nameof(policy));
        _factsByDevice = factsByDevice ?? throw new ArgumentNullException(nameof(factsByDevice));
        _injector = injector;
        _teardown = teardown;
        _now = now ?? (() => DateTimeOffset.UtcNow);
        _operatorAuthorizer = operatorAuthorizer;
        Store = new VendorPassStore(storeProtector);
    }

    private bool FeatureEnabledFor(string deviceId)
    {
        var facts = _factsByDevice(deviceId);
        // No facts → policy cannot be evaluated → fail closed.
        return facts is not null && _policy.IsEnabled(facts, VendorPassPolicyKeys.Enabled);
    }

    private bool AnyScopeDeviceEnabled(IEnumerable<string> deviceIds, IEnumerable<string> groupIds)
    {
        // Device-scoped passes gate on a named device's facts.
        foreach (var d in deviceIds)
            if (FeatureEnabledFor(d)) return true;
        // Group-only passes: gate on any facts the caller can
        // resolve — with no resolvable device the issue still
        // proceeds only if a group member device is enabled; the
        // service resolves facts per device id only, so a group-
        // only pass with no device facts refuses (fail closed) and
        // names it. Callers issuing group passes pass a
        // representative device via deviceIds in tests/wiring.
        return false;
    }

    /// <summary>D38 F3: the reference-shape check is the canonical
    /// CredentialReference rule from the model — a vault id in the
    /// cred- namespace with an ASCII [A-Za-z0-9._-] tail. The
    /// earlier charset-only check admitted ordinary passwords
    /// ("Summer2026", "hunter2"), API keys and Unicode lookalikes
    /// (char.IsLetterOrDigit accepts Unicode letters) as
    /// "references", which then persisted and exported as if they
    /// were ids. Shape alone is not enough either: IssuePass also
    /// requires the reference to RESOLVE in the vault.</summary>
    public static bool IsCredentialReferenceShape(string? reference) =>
        CredentialReference.IsShape(reference);

    /// <summary>Issue a pass under policy. Gates, in order: issuer
    /// named → credential-reference shape → policy enabled for the
    /// scope (a named device's facts; group-only passes resolve
    /// through their member devices' facts supplied by the wiring —
    /// here: at least one device id must be present OR the first
    /// group must resolve via facts lookup by group id is not
    /// available, so group-only issue requires the toggle to be
    /// enabled for a representative device the caller names in
    /// deviceIds; failing that, fail closed) → store issue (all
    /// model invariants). Every outcome is ledgered.</summary>
    public (VendorPassIssue? Issue, string Reason) IssuePass(
        string issuerId, VendorIdentity vendor, string scopeId,
        IEnumerable<string> deviceIds, IEnumerable<string> groupIds,
        IEnumerable<string> scopes, TimeSpan duration, string? credentialRef)
    {
        var now = _now();
        var deviceList = (deviceIds ?? Array.Empty<string>()).ToList();
        var groupList = (groupIds ?? Array.Empty<string>()).ToList();
        (VendorPassIssue?, string) Refuse(string reason)
        {
            _audit.Append("vendor_pass_issue_refused", issuerId ?? "vendor-pass-service",
                $"vendor={vendor?.Id ?? "(none)"} reason={reason}", now);
            return (null, reason);
        }
        // BD-SHARED-PLAT-3/F7: minting is an operator act — when
        // an authorizer is wired, the issuer must be a live human
        // scope admin/operator of THIS scope, resolved against the
        // roster, not merely a string that is not some vendor's id.
        if (_operatorAuthorizer is not null &&
            (string.IsNullOrWhiteSpace(issuerId) || !_operatorAuthorizer(scopeId ?? "", issuerId)))
            return Refuse($"issuer '{issuerId}' is not a live human scope admin/operator of scope '{scopeId}' — refused (issuing a vendor pass is an operator act, checked against the roster)");
        if (credentialRef is not null && !IsCredentialReferenceShape(credentialRef))
            return Refuse("credential reference is not reference-shaped (a reference is a vault id in the cred- namespace, ASCII only) — refused: the issue path accepts a vault REFERENCE only, never credential material");
        if (credentialRef is not null)
        {
            // D38 F3 (second half): a reference must RESOLVE at
            // issue time. A dangling reference would otherwise be
            // persisted onto the pass record, the export, the
            // trails and the ledger as if it were a real vault id.
            if (_injector is null)
                return Refuse("pass carries a credential reference but no credential injector is wired on this host — refused (a credential-bearing pass cannot be issued where its reference cannot be resolved or injected)");
            if (!_injector.ReferenceResolves(credentialRef))
                return Refuse("credential reference resolves to nothing in the vault — refused at issue (a reference is issued only against a real vault entry; it is never persisted dangling)");
        }
        if (deviceList.Count > 0)
        {
            if (!deviceList.Any(FeatureEnabledFor))
                return Refuse($"vendor passes are disabled by policy ({VendorPassPolicyKeys.Enabled}) for every device in scope, or no device facts resolve — refused (fail closed)");
        }
        else if (groupList.Count > 0)
        {
            return Refuse("group-only pass issue needs a representative device to evaluate policy against — refused (fail closed; name a device or wire group fact resolution)");
        }
        else
        {
            return Refuse("a pass needs a device scope — refused");
        }
        var (issue, reason) = Store.Issue(issuerId, vendor, scopeId, deviceList, groupList,
            scopes, duration, credentialRef, now);
        if (issue is null) return Refuse(reason);
        _audit.Append("vendor_pass_issued", issuerId,
            $"pass={issue.Pass.Id} vendor={vendor.Id} org={vendor.Organization} expires={issue.Pass.ExpiresUtc:O} credentialRef={credentialRef ?? "(none)"}", now);
        return (issue, reason);
    }

    /// <summary>D38 F4: the device's group membership comes from
    /// the AUTHORITATIVE device facts this service already resolves
    /// for the policy gate — never from the caller. The
    /// deviceGroupIds parameter is retained for call-site
    /// compatibility and is IGNORED: a forged caller-supplied group
    /// list must not be able to widen a group-scoped pass onto a
    /// device that is not in the group.</summary>
    private IReadOnlySet<string> AuthoritativeGroups(string? deviceId) =>
        deviceId is not null ? _factsByDevice(deviceId)?.DirectGroupIds ?? new HashSet<string>()
                             : new HashSet<string>();

    /// <summary>Authenticate a vendor presentation (token + vendor
    /// + device). Policy is re-checked at authentication: a pass
    /// issued while the feature was on authenticates NOTHING once
    /// policy turns it off for that device.</summary>
    public (VendorPass? Pass, string Reason) Authenticate(
        string? bearerToken, string? vendorId, string? deviceId, IEnumerable<string>? deviceGroupIds)
    {
        var now = _now();
        if (deviceId is not null && !FeatureEnabledFor(deviceId))
        {
            _audit.Append("vendor_pass_auth_failed", vendorId ?? "(unknown)",
                $"device={deviceId} reason=vendor passes disabled by policy for this device ({VendorPassPolicyKeys.Enabled}) or no facts resolve", now);
            return (null, $"vendor passes are disabled by policy for device '{deviceId}' — refused (fail closed)");
        }
        var (pass, reason) = Store.Authenticate(bearerToken, vendorId, deviceId, AuthoritativeGroups(deviceId), now);
        _audit.Append(pass is not null ? "vendor_pass_auth_succeeded" : "vendor_pass_auth_failed",
            vendorId ?? "(unknown)", $"device={deviceId ?? "(none)"} pass={pass?.Id ?? "(none)"} reason={reason}", now);
        return (pass, reason);
    }

    /// <summary>Begin a vendor session: authenticate, bind the
    /// session to the pass, and — when the pass carries a
    /// credential reference — inject the credential through the
    /// vault → sink path. The session id is the SESSION LAYER's id
    /// (the caller creates the real session under full presence
    /// rules); this method is the pass-side gate for it. Injection
    /// failure unbinds and refuses: a session that was promised an
    /// injected credential never proceeds without one, and never
    /// falls back to the vendor typing/knowing anything.</summary>
    public (bool Ok, string Reason, CredentialInjectionReceipt? Receipt) BeginVendorSession(
        string? bearerToken, string? vendorId, string deviceId,
        IEnumerable<string>? deviceGroupIds, string sessionId)
    {
        // D38 F2: the whole authenticate → bind → revalidate →
        // inject → revalidate sequence runs under _gate, and
        // RevokePass takes the same gate — a revocation cannot
        // interleave between bind and inject through this service.
        // The pass is ALSO revalidated immediately before and
        // after injection, so a revocation that lands through any
        // other path in that window refuses the session (and
        // unbinds it) instead of presenting a credential for a
        // revoked pass and returning Ok with a receipt.
        lock (_gate)
        {
            var now = _now();
            var groups = AuthoritativeGroups(deviceId);
            var (pass, authReason) = Authenticate(bearerToken, vendorId, deviceId, groups);
            if (pass is null) return (false, authReason, null);
            var (bound, bindReason) = Store.BindSession(pass.Id, sessionId, deviceId, groups, now);
            if (!bound) return (false, bindReason, null);
            _audit.Append("vendor_pass_session_bound", pass.Vendor.Id,
                $"pass={pass.Id} session={sessionId} device={deviceId}", now);

            (bool, string, CredentialInjectionReceipt?) RefuseBound(string reason, string kind)
            {
                Store.UnbindSession(pass.Id, sessionId, _now());
                _audit.Append(kind, pass.Vendor.Id,
                    $"pass={pass.Id} session={sessionId} credentialRef={pass.CredentialRef ?? "(none)"} reason={reason}", _now());
                return (false, reason, null);
            }

            if (pass.CredentialRef is null)
                return (true, $"vendor session {sessionId} bound to pass {pass.Id} (no credential injection on this pass)", null);
            if (_injector is null)
                return RefuseBound("pass carries a credential reference but no credential injector is wired on this host — session refused rather than proceed without the promised injection (and the vendor is never asked for the credential)", "vendor_pass_injection_failed");
            if (!Store.Revalidate(pass.Id, _now()))
                return RefuseBound($"pass '{pass.Id}' stopped being valid between bind and injection (revoked or expired) — session refused; no credential was presented", "vendor_pass_injection_failed");
            var (receipt, injectReason) = _injector.Inject(pass.Id, sessionId, pass.CredentialRef, _now());
            if (receipt is null)
                return RefuseBound(injectReason, "vendor_pass_injection_failed");
            if (!Store.Revalidate(pass.Id, _now()))
                return RefuseBound($"pass '{pass.Id}' was revoked or expired while its credential was being injected — session refused and unbound; the session never begins", "vendor_pass_injection_failed");
            Store.TrailInjection(pass.Id, sessionId, pass.CredentialRef, _now());
            _audit.Append("vendor_pass_credential_injected", pass.Vendor.Id,
                $"pass={pass.Id} session={sessionId} credentialRef={pass.CredentialRef} — value moved vault→session-layer sink in host code; never surfaced to the vendor", _now());
            return (true, injectReason, receipt);
        }
    }

    /// <summary>End a vendor session's pass binding (the session
    /// itself ends through the session layer; this releases the
    /// pass-side binding so revocation accounting stays exact).</summary>
    public void EndVendorSession(string passId, string sessionId)
    {
        var now = _now();
        Store.UnbindSession(passId, sessionId, now);
        _audit.Append("vendor_pass_session_unbound", "vendor-pass-service",
            $"pass={passId} session={sessionId}", now);
    }

    /// <summary>Mid-session revalidation: false the moment a pass
    /// expires or is revoked. The session layer polls/consults this
    /// and ends the session on false — a pass never outlives its
    /// window inside a live session.</summary>
    public bool RevalidatePass(string passId)
    {
        var pass = Store.Get(passId);
        if (pass is null || !Store.Revalidate(passId, _now())) return false;
        // BD-SHARED-PLAT-3/F3: a pass whose site credential has
        // been DELETED from the vault no longer revalidates — the
        // deletion takes effect on live passes, not only on the
        // next injection. (No injector wired = no credential leg
        // was ever promised; the pass's own window governs.)
        if (pass.CredentialRef is not null && _injector is not null &&
            !_injector.ReferenceResolves(pass.CredentialRef)) return false;
        // D38 F7: the kill switch applies mid-session too. The
        // earlier check consulted only the pass's own window, so
        // after an emergency policy-off, live vendor sessions kept
        // passing revalidation — the kill switch only stopped NEW
        // sessions. A device-scoped pass now revalidates only
        // while the feature is still enabled for at least one
        // device it names. (Group-only passes name no device to
        // evaluate facts against; the device overload below is the
        // precise check for a session on a known device.)
        if (pass.DeviceIds.Count > 0 && !pass.DeviceIds.Any(FeatureEnabledFor)) return false;
        return true;
    }

    /// <summary>D38 F7, device-precise form: revalidation for a
    /// session running on a KNOWN device — the pass must still be
    /// active, the kill switch must still be on for THAT device,
    /// and the pass must still cover it (authoritative groups).</summary>
    public bool RevalidatePass(string passId, string deviceId)
    {
        var pass = Store.Get(passId);
        if (pass is null || !Store.Revalidate(passId, _now())) return false;
        if (!FeatureEnabledFor(deviceId)) return false;
        return pass.CoversDevice(deviceId, AuthoritativeGroups(deviceId));
    }

    /// <summary>Revoke a pass AND kill its live sessions through
    /// the teardown seam. The store names the sessions; the seam
    /// ends them; both halves are ledgered. When no teardown seam
    /// is wired the revocation still lands (authentication dies
    /// immediately) and the un-killed session ids are NAMED in the
    /// result — never silently claimed killed.</summary>
    public (bool Ok, string Reason, IReadOnlyList<string> SessionsEnded, IReadOnlyList<string> SessionsNamedNotEnded) RevokePass(
        string passId, string revokedBy, string reason)
    {
        // D38 F2: serialised with BeginVendorSession on _gate — a
        // revocation and a bind→inject sequence can never
        // interleave through this service.
        lock (_gate)
        {
        var now = _now();
        // BD-SHARED-PLAT-3/F7: revocation is an operator act too.
        // When an authorizer is wired, the revoker must be a live
        // human scope admin/operator of the pass's scope — or the
        // pass's own vendor surrendering their own pass (the store
        // already allows that single self-act).
        if (_operatorAuthorizer is not null)
        {
            var target = Store.Get(passId);
            if (target is not null &&
                !string.Equals(revokedBy ?? "", target.Vendor.Id, StringComparison.OrdinalIgnoreCase) &&
                !_operatorAuthorizer(target.ScopeId, revokedBy ?? ""))
            {
                var refuseReason = $"revoker '{revokedBy}' is not a live human scope admin/operator of scope '{target.ScopeId}' — refused (revoking a vendor pass is an operator act, checked against the roster)";
                _audit.Append("vendor_pass_revoke_refused", revokedBy ?? "vendor-pass-service",
                    $"pass={passId} reason={refuseReason}", now);
                return (false, refuseReason, Array.Empty<string>(), Array.Empty<string>());
            }
        }
        var (ok, revokeReason, live) = Store.Revoke(passId, revokedBy, reason, now);
        if (!ok)
        {
            _audit.Append("vendor_pass_revoke_refused", revokedBy ?? "vendor-pass-service",
                $"pass={passId} reason={revokeReason}", now);
            return (false, revokeReason, Array.Empty<string>(), Array.Empty<string>());
        }
        _audit.Append("vendor_pass_revoked", revokedBy,
            $"pass={passId} reason={reason} liveSessions=[{string.Join(",", live)}]", now);
        if (live.Count == 0)
            return (true, revokeReason + "; no live sessions to kill", live, Array.Empty<string>());
        if (_teardown is null)
        {
            _audit.Append("vendor_pass_teardown_unwired", revokedBy,
                $"pass={passId} sessions=[{string.Join(",", live)}] — no session teardown seam wired; authentication is dead but these sessions were NOT ended by this call (named, never silently claimed)", now);
            return (true, revokeReason + $"; WARNING: no teardown seam wired — sessions [{string.Join(",", live)}] named but NOT ended by this call", Array.Empty<string>(), live);
        }
        var ended = _teardown.EndSessions(live, $"vendor pass {passId} revoked: {reason}");
        var notEnded = live.Except(ended).ToList();
        _audit.Append("vendor_pass_sessions_killed", revokedBy,
            $"pass={passId} ended=[{string.Join(",", ended)}] notEnded=[{string.Join(",", notEnded)}]", now);
        return (true, revokeReason + $"; {ended.Count} live session(s) ended via teardown", ended, notEnded);
        }
    }

    /// <summary>Extension attempt: refused by name at the store;
    /// ledgered here so the attempt itself is evidence.</summary>
    public (bool Ok, string Reason) ExtendPass(string passId, TimeSpan additional, string requestedBy)
    {
        var now = _now();
        var result = Store.ExtendPass(passId, additional, requestedBy, now);
        _audit.Append("vendor_pass_extension_refused", requestedBy ?? "vendor-pass-service",
            $"pass={passId} additional={additional} reason={result.Reason}", now);
        return result;
    }
}
