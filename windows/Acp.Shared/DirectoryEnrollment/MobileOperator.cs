using System.Text;
using Acp.Shared.Enterprise;
using Acp.Shared.Enrollment;
using Acp.Shared.Monitoring;
using Acp.Shared.Roster;
using Acp.Shared.Security;

namespace Acp.Shared.DirectoryEnrollment;

// =====================================================================
// RMM-24 (item 2) — Full mobile operator client: MODEL + CONTRACT.
//
// STATE LABEL (honest): this is the platform-neutral contract and
// authorization model. The Android UI is DESIGN-PHASE — the Android
// build path is environment-blocked (Gradle, banked) — so nothing
// here claims a shipped phone surface. What IS built and tested:
// the shared-model pieces any mobile client must obey — client
// registration, authorization, the approval channel, and the
// notification queue — so the eventual UI is a surfacing project
// over a proven contract, exactly as the register's build shape
// states ("mobile client is a surfacing project on the existing
// Android app").
//
// THE AUTHORIZATION LAW: the mobile client holds the OPERATOR's
// keys, scoped EXACTLY like the desktop operator. There is no
// mobile rights set: every check delegates to RosterService
// .UserHasRight for the operator's user record, so a right the
// desktop operator doesn't hold does not exist on the phone, and
// a right they lose (suspension, offboarding, grant removal) is
// lost on the phone at the same instant — the check is live, not
// cached at registration.
//
// THE APPROVAL CHANNEL: a phone approval is a REAL approval
// channel (it composes with the existing dual-control machinery's
// discipline: named approver, bound content, append-only record).
// An approval is valid only as a signature, by the operator's
// enrolled client device key, over the canonical approval message
// — verified through Slice 1's VerifyEnrolledSignature against
// the enrolled public key. A device that isn't the operator's
// keyed client cannot forge one; a revoked client device cannot
// approve at all.
//
// NOTIFICATIONS: alerts reach the phone VIA THE HUB. The queue
// accepts an alert only from a verified source: an alert id that
// resolves in the hub's own HealthAlertCentre, or a payload signed
// by the hub's key. A fake alert injected by anyone else has no
// path in. TRANSPORT HONESTY (per deployment shape): the
// self-hosted shape has NO third-party push — delivery is
// hub-direct (the client polls/connects to the user's own hub) or
// a user-owned relay. APNs/FCM exist only as a NAMED platform
// transit in shapes that choose them; this model refuses to queue
// a vendor-push delivery in the self-hosted shape rather than
// silently transiting a third party.
//
// PRESENCE: a mobile session is a session. Starting one requires
// the same pairing-derived rights (the "use" grant) and carries
// presence as a non-optional fact of the request shape — there is
// no field by which a mobile session could ask to be invisible
// (the §7.10 floor is not a setting, here either).
// =====================================================================

/// <summary>TOTAL POLICY CONTROL key for the mobile operator
/// client: the RMM-07 registry's seeded RMM-24 toggle.</summary>
public static class MobileOperatorPolicyKeys
{
    /// <summary>bd-shared-plat-2/F4: the mobile client's OWN key.
    /// It previously aliased the push-enrollment key, so toggling
    /// push enrollment silently killed/enabled the mobile client
    /// (and its phone approvals). Seeded in the RMM-07 registry
    /// alongside the directory key, which keeps
    /// rmm.enrollment_push.enabled for the push half only.</summary>
    public const string Enabled = "rmm.mobile_operator.enabled";
}

/// <summary>The mobile client's capability contract — what the
/// phone surface may do, stated as data so any client build can be
/// checked against it. Every capability names the roster right it
/// rides; there is deliberately NO capability with a null right
/// (a capability needing no right does not exist in this contract).</summary>
public sealed record MobileCapability(string Id, string RosterRight, string Description);

public static class MobileOperatorContract
{
    public static readonly IReadOnlyList<MobileCapability> Capabilities = new[]
    {
        new MobileCapability("browse_roster", "view", "Browse the operator's roster for their scope"),
        new MobileCapability("view_device_health", "view", "See device health + alerts (RMM-01/28 feeds) for devices the operator may view"),
        new MobileCapability("start_session", "use", "Start a session under the same pairing + presence rules as desktop"),
        new MobileCapability("observe_session", "view", "Observe a session the operator may view"),
        new MobileCapability("approve_dual_control", "admin", "Approve dual-control requests (a real approval channel, signature-bound)"),
        new MobileCapability("receive_alert_notifications", "view", "Receive alert notifications via the hub"),
    };

    public static MobileCapability? For(string capabilityId) =>
        Capabilities.FirstOrDefault(c => string.Equals(c.Id, capabilityId ?? "", StringComparison.OrdinalIgnoreCase));

    /// <summary>Rights the mobile client adds over the desktop
    /// operator's: NONE, by construction. This set is the scope-
    /// creep regression surface — it must stay empty.</summary>
    public static readonly IReadOnlySet<string> MobileOnlyRights = new HashSet<string>();
}

/// <summary>Notification transports, named honestly per shape.</summary>
public sealed record MobileNotificationTransport(string Id, string Label, bool AllowedInSelfHosted, string HonestNote);

public static class MobileNotificationTransports
{
    public static readonly MobileNotificationTransport HubDirect = new(
        "hub_direct", "Hub-direct (client connects/polls the user's own hub)",
        true, "No third party transits the alert. Delivery waits for the client to reach the hub.");
    public static readonly MobileNotificationTransport UserOwnedRelay = new(
        "user_owned_relay", "User-owned relay (an endpoint the user operates)",
        true, "The relay is the user's own infrastructure; ACP ships no relay of its own.");
    public static readonly MobileNotificationTransport PlatformPush = new(
        "platform_push", "Platform push (APNs/FCM)",
        false, "Platform transit by OS design: alert metadata transits Apple/Google. NOT part of the self-hosted shape; a deployment that chooses it names it in-product (the RMM-31 honesty pattern).");

    public static readonly IReadOnlyList<MobileNotificationTransport> All =
        new[] { HubDirect, UserOwnedRelay, PlatformPush };

    public static MobileNotificationTransport? For(string id) =>
        All.FirstOrDefault(t => string.Equals(t.Id, id ?? "", StringComparison.OrdinalIgnoreCase));
}

// ---- client registration ------------------------------------------------------

/// <summary>One registered mobile client: an operator user bound to
/// ONE enrolled client device (their phone). The binding is the
/// approval channel's root: signatures verify against THIS device's
/// enrolled key, for THIS user.</summary>
public sealed record MobileClientRegistration(
    string UserId, string ScopeId, string ClientDeviceId, DateTimeOffset RegisteredUtc);

public sealed class MobileClientRegistry
{
    private readonly EnrollmentService _enrollments;
    private readonly RosterService _roster;
    private readonly ChainedAuditLog _audit;
    private readonly Dictionary<string, MobileClientRegistration> _byDevice = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();

    public MobileClientRegistry(EnrollmentService enrollments, RosterService roster, ChainedAuditLog audit)
    {
        _enrollments = enrollments ?? throw new ArgumentNullException(nameof(enrollments));
        _roster = roster ?? throw new ArgumentNullException(nameof(roster));
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
    }

    /// <summary>W5 wiring: raised after any durable mutation so
    /// the host can write the store through to disk (bd-shared-
    /// plat-2/F12 remainder: CoreRuntime persistence).</summary>
    public event Action? Changed;

    /// <summary>The canonical message a registration proof signs:
    /// the device key signs (scope, user, device) — proving the
    /// presenter HOLDS the device being bound (D38 rmm24 F3).</summary>
    public static byte[] CanonicalRegistrationMessage(string scopeId, string userId, string clientDeviceId) =>
        Encoding.UTF8.GetBytes($"acp-mobile-register-v1|{scopeId}|{userId}|{clientDeviceId}");

    /// <summary>Register a phone as a user's mobile client — the
    /// approval channel's root, so registration is an AUTHORIZED
    /// act, not a bare binding (D38 rmm24 F3). The full wall:
    /// a live human roster user; an enrolled, unrevoked client
    /// device whose enrollment group is in the scope (D8); an
    /// ACTOR who is either the user themselves or an admin of the
    /// scope; a device-key signature over the canonical
    /// registration message proving the presenter holds the device
    /// being bound; and no silent re-binding — a device already
    /// registered to a DIFFERENT user moves only on a scope
    /// admin's act, audited as a rebind. Without all of these, any
    /// enrolled device (e.g. a push-enrolled workstation) could be
    /// registered as an admin's mobile client and then "approve"
    /// with its own enrolled key.</summary>
    public (MobileClientRegistration? Registration, string Reason) Register(
        string scopeId, string userId, string clientDeviceId, string actorUserId,
        string? deviceProofSignatureBase64, DateTimeOffset now)
    {
        (MobileClientRegistration?, string) Refuse(string reason)
        {
            _audit.Append("mobile_client_registration_refused", actorUserId ?? "(unknown)",
                $"scope={scopeId} user={userId} clientDevice={clientDeviceId} reason={reason}", now);
            return (null, reason);
        }
        var user = _roster.GetUser(scopeId, userId);
        if (user is null || user.Suspended || user.Kind != "human")
            return Refuse("mobile client registration needs a live human roster user in the scope — refused");
        var device = _enrollments.List().FirstOrDefault(d =>
            string.Equals(d.DeviceId, clientDeviceId ?? "", StringComparison.OrdinalIgnoreCase));
        if (device is null || device.Revoked)
            return Refuse("the client device is not an enrolled, unrevoked device — refused (an unenrolled phone holds no operator keys)");
        var group = _roster.FindDeviceGroup(device.GroupId);
        if (group is null || !string.Equals(group.ScopeId, scopeId, StringComparison.OrdinalIgnoreCase))
            return Refuse("the client device's enrollment group is outside this scope — refused (D8 wall)");
        var actorIsSelf = string.Equals(actorUserId ?? "", user.Id, StringComparison.OrdinalIgnoreCase);
        var actorIsAdmin = _roster.IsScopeAdmin(scopeId, actorUserId) ||
                           _roster.HasAdminRight(scopeId, actorUserId, deviceGroupId: device.GroupId);
        if (!actorIsSelf && !actorIsAdmin)
            return Refuse($"actor '{actorUserId}' is neither the user nor an admin of this scope — refused (binding a user to a device is an authorized act)");
        if (!_enrollments.VerifyEnrolledSignature(device.DeviceId,
                CanonicalRegistrationMessage(group.ScopeId, user.Id, device.DeviceId), deviceProofSignatureBase64))
            return Refuse("no valid device-key proof for this binding — refused (registration requires proof the presenter holds the device being bound)");
        var registration = new MobileClientRegistration(user.Id, group.ScopeId, device.DeviceId, now);
        lock (_gate)
        {
            if (_byDevice.TryGetValue(device.DeviceId, out var existing) &&
                !string.Equals(existing.UserId, user.Id, StringComparison.OrdinalIgnoreCase))
            {
                if (!actorIsAdmin || !_roster.IsScopeAdmin(scopeId, actorUserId))
                    return Refuse($"device {device.DeviceId} is already registered to '{existing.UserId}' — re-binding to another user requires a scope admin's act, never a silent overwrite");
                _audit.Append("mobile_client_rebound", actorUserId,
                    $"clientDevice={device.DeviceId} fromUser={existing.UserId} toUser={user.Id} scope={group.ScopeId} (scope-admin rebind)", now);
            }
            _byDevice[device.DeviceId] = registration;
        }
        _audit.Append("mobile_client_registered", actorUserId ?? user.Id,
            $"user={user.Id} clientDevice={device.DeviceId} scope={group.ScopeId} actorSelf={actorIsSelf}", now);
        Changed?.Invoke();
        return (registration, $"mobile client registered for '{user.Id}' on device {device.DeviceId}");
    }

    public MobileClientRegistration? For(string? clientDeviceId)
    {
        lock (_gate)
            return clientDeviceId is not null && _byDevice.TryGetValue(clientDeviceId, out var r) ? r : null;
    }

    /// <summary>The registration, only while the client device is
    /// STILL enrolled and unrevoked — re-checked live against
    /// Slice 1 on every call (D38 rmm24 F4). A device revoked
    /// through EnrollmentService loses every mobile right at that
    /// instant; no manual Unregister is needed for revocation to
    /// bite (Unregister remains the lost/replaced-device act).</summary>
    public MobileClientRegistration? ForLive(string? clientDeviceId)
    {
        var registration = For(clientDeviceId);
        if (registration is null) return null;
        var device = _enrollments.List().FirstOrDefault(d =>
            string.Equals(d.DeviceId, registration.ClientDeviceId, StringComparison.OrdinalIgnoreCase));
        return device is not null && !device.Revoked ? registration : null;
    }

    /// <summary>The registered client device of a user, if any
    /// (the notification queue's addressing root).</summary>
    public string? ClientDeviceFor(string? userId)
    {
        lock (_gate)
            return _byDevice.Values.FirstOrDefault(r =>
                string.Equals(r.UserId, userId ?? "", StringComparison.OrdinalIgnoreCase))?.ClientDeviceId;
    }

    // bd-shared-plat-2/F12: persistence for client registrations.
    public string ExportJson()
    {
        lock (_gate) return Acp.Shared.Hub.HubPersistence.Wrap("acp-mobile-clients-v1",
            System.Text.Json.JsonSerializer.Serialize(_byDevice.Values.ToArray()));
    }

    public int ImportJson(string json)
    {
        var payload = Acp.Shared.Hub.HubPersistence.Unwrap(json, "acp-mobile-clients-v1");
        if (payload is null) return 0;
        MobileClientRegistration[]? items;
        try { items = System.Text.Json.JsonSerializer.Deserialize<MobileClientRegistration[]>(payload); }
        catch { return 0; }
        if (items is null) return 0;
        var n = 0;
        lock (_gate)
            foreach (var r in items)
            {
                if (r is null || string.IsNullOrWhiteSpace(r.ClientDeviceId) || _byDevice.ContainsKey(r.ClientDeviceId)) continue;
                _byDevice[r.ClientDeviceId] = r; n++;
            }
        if (n > 0) Changed?.Invoke();
        return n;
    }

    /// <summary>Unregister (device lost / replaced). Approvals and
    /// authorizations for the device die with the registration.</summary>
    public bool Unregister(string clientDeviceId, string actorUserId, DateTimeOffset now)
    {
        lock (_gate)
        {
            if (!_byDevice.Remove(clientDeviceId ?? "")) return false;
        }
        _audit.Append("mobile_client_unregistered", actorUserId ?? "(unknown)",
            $"clientDevice={clientDeviceId}", now);
        Changed?.Invoke();
        return true;
    }
}

// ---- authorization --------------------------------------------------------------

/// <summary>A mobile session request. PresenceVisible is a fact of
/// the shape, fixed true — a mobile session is present exactly like
/// a desktop one, and no caller input can change it.</summary>
public sealed record MobileSessionRequest(
    string UserId, string ClientDeviceId, string TargetDeviceId, string DeviceGroupId, string Mode)
{
    public bool PresenceVisible => true; // the floor: not a setting, not a field
    public static readonly IReadOnlySet<string> Modes = new HashSet<string> { "drive", "observe" };
}

public sealed class MobileAuthorization
{
    private readonly RosterService _roster;
    private readonly MobileClientRegistry _clients;
    private readonly Func<bool> _policyEnabled;
    private readonly Func<string, string?>? _targetGroupOf;

    /// <param name="targetGroupOf">bd-shared-plat-2/F2: server-side
    /// lookup of a target device's enrolled device group. When
    /// wired (the production service wires it from Slice 1
    /// enrollment), session-start authorization is judged against
    /// the TARGET's group — the caller-supplied DeviceGroupId can
    /// never widen it, and an unknown target refuses.</param>
    public MobileAuthorization(RosterService roster, MobileClientRegistry clients, Func<bool>? policyEnabled = null,
        Func<string, string?>? targetGroupOf = null)
    {
        _roster = roster ?? throw new ArgumentNullException(nameof(roster));
        _clients = clients ?? throw new ArgumentNullException(nameof(clients));
        // bd-shared-plat-2/F4: an unwired policy gate FAILS CLOSED.
        _policyEnabled = policyEnabled ?? (() => false);
        _targetGroupOf = targetGroupOf;
    }

    /// <summary>bd-shared-plat-2/F12 (W9 closure): may this operator
    /// RAISE a dual-control approval request against this device
    /// group? Judged LIVE against the roster, exactly like Can:
    /// policy enables the mobile surface, the requester is a live,
    /// unsuspended user of the scope, and they hold the "use" right
    /// on the request's device group (a scope admin holds every
    /// right by the roster's own rule). A requester with no right
    /// on the group cannot mint approval requests against it —
    /// CreateRequest's bare `requestedBy` string was accepted with
    /// no actor check at all before this gate.</summary>
    public bool CanRequestApproval(string scopeId, string userId, string deviceGroupId)
    {
        if (!_policyEnabled()) return false;
        var user = _roster.GetUser(scopeId, userId);
        if (user is null || user.Suspended) return false;
        return _roster.IsScopeAdmin(scopeId, userId) ||
               _roster.UserHasRight(scopeId, userId, deviceGroupId, "use");
    }

    /// <summary>The one authorization question every mobile surface
    /// asks. True ONLY when: policy enables the mobile client, the
    /// client device is registered to this user, and the user holds
    /// the capability's roster right on the device group — judged
    /// LIVE against the roster, exactly as desktop. There is no
    /// mobile-only path around any of the three.</summary>
    public bool Can(string scopeId, string userId, string clientDeviceId, string capabilityId, string deviceGroupId)
    {
        if (!_policyEnabled()) return false;
        var capability = MobileOperatorContract.For(capabilityId);
        if (capability is null) return false;
        var registration = _clients.ForLive(clientDeviceId);
        if (registration is null) return false;
        if (!string.Equals(registration.UserId, userId ?? "", StringComparison.OrdinalIgnoreCase)) return false;
        if (!string.Equals(registration.ScopeId, scopeId ?? "", StringComparison.OrdinalIgnoreCase)) return false;
        return _roster.UserHasRight(scopeId, userId, deviceGroupId, capability.RosterRight);
    }

    /// <summary>Validate a session start: mode must be a contract
    /// mode, drive needs "use", observe needs "view", and the
    /// request's presence fact is structural (always visible).</summary>
    public (bool Ok, string Reason) ValidateSessionStart(string scopeId, MobileSessionRequest request)
    {
        if (request is null) return (false, "no session request — refused");
        // ONE normalized mode drives BOTH the allow-list check and
        // the capability pick (D38 rmm24 F2): comparing the RAW
        // string for the capability let "Drive"/"DRIVE" pass the
        // mode check yet fall through to the observe (view-only)
        // capability — a view-only operator got drive authorisation.
        var mode = (request.Mode ?? "").Trim().ToLowerInvariant();
        if (!MobileSessionRequest.Modes.Contains(mode))
            return (false, $"session mode '{request.Mode}' is not a mobile contract mode — refused");
        var capability = mode == "drive" ? "start_session" : "observe_session";
        // bd-shared-plat-2/F2: when the target-group lookup is
        // wired, the TARGET's enrolled group is authoritative.
        // A request naming group A for a device enrolled in
        // group B refuses — the caller-supplied group is never
        // the basis of the check.
        var effectiveGroup = request.DeviceGroupId;
        if (_targetGroupOf is not null)
        {
            var targetGroup = _targetGroupOf(request.TargetDeviceId);
            if (targetGroup is null)
                return (false, $"target device '{request.TargetDeviceId}' is not an enrolled device with a known group — refused (session targets are resolved server-side)");
            if (!string.IsNullOrWhiteSpace(request.DeviceGroupId) &&
                !string.Equals(request.DeviceGroupId, targetGroup, StringComparison.OrdinalIgnoreCase))
                return (false, $"request names group '{request.DeviceGroupId}' but target device '{request.TargetDeviceId}' is enrolled in group '{targetGroup}' — refused (a caller-supplied group never widens a session onto another group's device)");
            effectiveGroup = targetGroup;
        }
        if (!Can(scopeId, request.UserId, request.ClientDeviceId, capability, effectiveGroup))
            return (false, $"operator '{request.UserId}' may not {mode} devices in group '{effectiveGroup}' from this client — refused (mobile rights are the operator's roster rights, no more)");
        return (true, $"mobile {mode} session authorized under the operator's roster rights; presence is visible (the floor)");
    }

    /// <summary>The operator's roster through the mobile contract:
    /// the SAME OperatorRoster shape the desktop reads (D2),
    /// scope-filtered, gated on any mobile capability's registration
    /// check. Null when the client is not this user's registered
    /// client in this scope.</summary>
    public OperatorRoster? RosterFor(string scopeId, string userId, string clientDeviceId)
    {
        // Policy gate + LIVE registration + a live, UNSUSPENDED
        // user (D38 rmm24 F12b/F4): existence of a user record was
        // never enough — a suspended operator's phone reads nothing.
        if (!_policyEnabled()) return null;
        var registration = _clients.ForLive(clientDeviceId);
        if (registration is null) return null;
        if (!string.Equals(registration.UserId, userId ?? "", StringComparison.OrdinalIgnoreCase)) return null;
        if (!string.Equals(registration.ScopeId, scopeId ?? "", StringComparison.OrdinalIgnoreCase)) return null;
        var user = _roster.GetUser(scopeId, userId);
        if (user is null || user.Suspended) return null;
        var full = _roster.OperatorRoster(scopeId);
        if (full is null) return null;
        // bd-shared-plat-2/F3: the browse_roster capability's view
        // right is now actually checked, and the roster is FILTERED
        // to what the operator may view (the data-absent discipline
        // HealthFor already follows). A scope admin sees the scope;
        // anyone else sees only the device groups they hold view
        // on, the grants touching those groups, the user groups
        // holding those grants, and the users in them (plus
        // themselves). No view right anywhere → no roster at all.
        if (_roster.IsScopeAdmin(scopeId, userId)) return full;
        var viewable = full.DeviceGroups
            .Where(g => _roster.UserHasRight(scopeId, userId, g.Id, "view"))
            .ToList();
        if (viewable.Count == 0) return null;
        var viewableIds = new HashSet<string>(viewable.Select(g => g.Id), StringComparer.OrdinalIgnoreCase);
        var grants = full.Grants.Where(g => viewableIds.Contains(g.DeviceGroupId)).ToList();
        var userGroupIds = new HashSet<string>(grants.Select(g => g.UserGroupId), StringComparer.OrdinalIgnoreCase);
        var userGroups = full.UserGroups.Where(g => userGroupIds.Contains(g.Id)).ToList();
        var memberIds = new HashSet<string>(userGroups.SelectMany(g => g.MemberUserIds), StringComparer.OrdinalIgnoreCase)
        { userId };
        return full with
        {
            Users = full.Users.Where(u => memberIds.Contains(u.Id)).ToList(),
            CompanyAdminIds = Array.Empty<string>(),
            UserGroups = userGroups,
            DeviceGroups = viewable,
            Grants = grants,
            Devices = full.Devices.Where(d => viewableIds.Contains(d.GroupId)).ToList(),
            Events = Array.Empty<RosterEvent>(),
        };
    }

    /// <summary>Device health through the mobile contract: hub
    /// health views filtered to devices in groups the operator may
    /// VIEW. A device the operator has no view right on is absent,
    /// not redacted — the same data-absent discipline as D2.</summary>
    public IReadOnlyList<DeviceHealthView> HealthFor(
        string scopeId, string userId, string clientDeviceId,
        HubHealthIngest hubHealth, Func<string, string?> deviceGroupOf, DateTimeOffset now)
    {
        // Registration + policy gate first (a capability-level check
        // against any group the operator can view); the per-device
        // filter below then applies the live per-group view right.
        var registration = _clients.ForLive(clientDeviceId);
        if (registration is null ||
            !string.Equals(registration.UserId, userId ?? "", StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(registration.ScopeId, scopeId ?? "", StringComparison.OrdinalIgnoreCase) ||
            !_policyEnabled())
            return Array.Empty<DeviceHealthView>();
        return hubHealth.Views(now)
            .Where(v =>
            {
                var group = deviceGroupOf(v.DeviceId);
                return group is not null && _roster.UserHasRight(scopeId, userId, group, "view");
            })
            .ToList();
    }
}

// ---- approval channel -----------------------------------------------------------

public static class MobileApprovalDecisions
{
    public const string Approved = "approved";
    public const string Denied = "denied";
    public static readonly IReadOnlySet<string> All = new HashSet<string> { Approved, Denied };
}

public static class MobileApprovalStates
{
    public const string Pending = "pending";
    public const string Approved = "approved";
    public const string Denied = "denied";
    public const string Expired = "expired";
}

/// <summary>One dual-control approval request awaiting an operator
/// decision. Content-bound: the approval signs (request id,
/// action hash, decision) — approving one action can never be
/// replayed onto another.</summary>
public sealed record MobileApprovalRequest(
    string Id, string ScopeId, string DeviceGroupId, string Action,
    string ActionHash, string RequestedBy, DateTimeOffset CreatedUtc, DateTimeOffset ExpiresUtc,
    string State, string? DecidedBy, string? DecidedByClientDeviceId, DateTimeOffset? DecidedUtc);

public sealed class MobileApprovalService
{
    private readonly EnrollmentService _enrollments;
    private readonly MobileClientRegistry _clients;
    private readonly MobileAuthorization _auth;
    private readonly ChainedAuditLog _audit;
    private readonly Dictionary<string, MobileApprovalRequest> _requests = new(StringComparer.Ordinal);
    private readonly object _gate = new();

    public MobileApprovalService(EnrollmentService enrollments, MobileClientRegistry clients,
        MobileAuthorization auth, ChainedAuditLog audit)
    {
        _enrollments = enrollments ?? throw new ArgumentNullException(nameof(enrollments));
        _clients = clients ?? throw new ArgumentNullException(nameof(clients));
        _auth = auth ?? throw new ArgumentNullException(nameof(auth));
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
    }

    /// <summary>W5 wiring: raised after any durable mutation so
    /// the host can write the store through to disk.</summary>
    public event Action? Changed;

    /// <summary>The canonical message an approval signs.</summary>
    public static byte[] CanonicalMessage(string requestId, string actionHash, string decision) =>
        Encoding.UTF8.GetBytes($"acp-mobile-approval-v1|{requestId}|{actionHash}|{decision}");

    public static string HashAction(string action) =>
        Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
            Encoding.UTF8.GetBytes(action ?? ""))).ToLowerInvariant();

    /// <summary>bd-shared-plat-2/F12: approval TTL is CAPPED —
    /// an unbounded TTL (TimeSpan.MaxValue overflowed the expiry
    /// computation) can no longer be minted.</summary>
    public static readonly TimeSpan MaxApprovalTtl = TimeSpan.FromHours(24);

    /// <summary>Create one dual-control approval request. Returns
    /// null on refusal: bd-shared-plat-2/F12 (W9 closure) — the
    /// requester is authorization-checked FIRST (see
    /// MobileAuthorization.CanRequestApproval): a bare caller-named
    /// `requestedBy` with no roster right on the device group mints
    /// nothing, and the refusal is audited like every other refusal
    /// on this surface. (Pre-fix this method accepted any
    /// requestedBy string and any TTL; the TTL cap landed in W4,
    /// the authorization context is this closure.)</summary>
    public MobileApprovalRequest? CreateRequest(
        string scopeId, string deviceGroupId, string action, string requestedBy,
        TimeSpan ttl, DateTimeOffset now)
    {
        if (!_auth.CanRequestApproval(scopeId, requestedBy, deviceGroupId))
        {
            _audit.Append("mobile_approval_request_refused", requestedBy ?? "(unknown)",
                $"scope={scopeId} deviceGroup={deviceGroupId} reason=requester holds no use right on the device group (or is not a live user of the scope, or the mobile surface is off by policy)", now);
            return null;
        }
        if (ttl <= TimeSpan.Zero) ttl = TimeSpan.FromMinutes(10);
        if (ttl > MaxApprovalTtl) ttl = MaxApprovalTtl;
        var request = new MobileApprovalRequest(
            Id: Guid.NewGuid().ToString("N"), ScopeId: scopeId, DeviceGroupId: deviceGroupId,
            Action: action, ActionHash: HashAction(action), RequestedBy: requestedBy,
            CreatedUtc: now, ExpiresUtc: now + ttl, State: MobileApprovalStates.Pending,
            DecidedBy: null, DecidedByClientDeviceId: null, DecidedUtc: null);
        lock (_gate)
        {
            // Bounded retention (D38 rmm24 F12c): decided/expired
            // requests 30 days past expiry are pruned; pending
            // requests are never pruned.
            var dead = _requests.Values
                .Where(r => r.State != MobileApprovalStates.Pending &&
                            now - r.ExpiresUtc > TimeSpan.FromDays(30))
                .Select(r => r.Id).ToList();
            foreach (var id in dead) _requests.Remove(id);
            _requests[request.Id] = request;
        }
        _audit.Append("mobile_approval_requested", requestedBy,
            $"request={request.Id} scope={scopeId} deviceGroup={deviceGroupId} actionHash={request.ActionHash} expires={request.ExpiresUtc:O}", now);
        Changed?.Invoke();
        return request;
    }

    public MobileApprovalRequest? Get(string requestId)
    {
        lock (_gate) return requestId is not null && _requests.TryGetValue(requestId, out var r) ? r : null;
    }

    public IReadOnlyList<MobileApprovalRequest> Pending
    {
        get { lock (_gate) return _requests.Values.Where(r => r.State == MobileApprovalStates.Pending).ToList(); }
    }

    /// <summary>bd-shared-plat-2/F12: pending AS OF a moment —
    /// requests past their expiry are not pending, even before a
    /// Decide call marks them expired.</summary>
    public IReadOnlyList<MobileApprovalRequest> PendingAt(DateTimeOffset now)
    {
        lock (_gate) return _requests.Values
            .Where(r => r.State == MobileApprovalStates.Pending && now < r.ExpiresUtc).ToList();
    }

    // bd-shared-plat-2/F12: persistence for the approval store.
    public string ExportJson()
    {
        lock (_gate) return Acp.Shared.Hub.HubPersistence.Wrap("acp-mobile-approvals-v1",
            System.Text.Json.JsonSerializer.Serialize(_requests.Values.ToArray()));
    }

    public int ImportJson(string json)
    {
        var payload = Acp.Shared.Hub.HubPersistence.Unwrap(json, "acp-mobile-approvals-v1");
        if (payload is null) return 0;
        MobileApprovalRequest[]? items;
        try { items = System.Text.Json.JsonSerializer.Deserialize<MobileApprovalRequest[]>(payload); }
        catch { return 0; }
        if (items is null) return 0;
        var n = 0;
        lock (_gate)
            foreach (var r in items)
            {
                if (r is null || string.IsNullOrWhiteSpace(r.Id) || _requests.ContainsKey(r.Id)) continue;
                _requests[r.Id] = r; n++;
            }
        if (n > 0) Changed?.Invoke();
        return n;
    }

    /// <summary>Decide a request FROM a mobile client. The full
    /// wall, in order: the request exists and is pending and
    /// unexpired; the decision is a contract decision; the client
    /// is registered to the deciding user; the user holds the
    /// approval capability (admin right) on the request's device
    /// group; and the signature verifies against the client
    /// device's ENROLLED key over the canonical message. Any
    /// failure refuses and audits — an unsigned, wrongly-signed,
    /// replayed or unregistered approval is not an approval.</summary>
    public (bool Ok, string Reason) Decide(
        string requestId, string userId, string clientDeviceId, string decision,
        string? signatureBase64, DateTimeOffset now)
    {
        (bool, string) Refuse(string reason)
        {
            _audit.Append("mobile_approval_refused", userId ?? "(unknown)",
                $"request={requestId} clientDevice={clientDeviceId} reason={reason}", now);
            return (false, reason);
        }
        var normalizedDecision = (decision ?? "").Trim().ToLowerInvariant();
        if (!MobileApprovalDecisions.All.Contains(normalizedDecision))
            return Refuse($"decision '{decision}' is not an approval decision — refused");
        MobileApprovalRequest? request;
        lock (_gate) _requests.TryGetValue(requestId ?? "", out request);
        if (request is null) return Refuse("unknown approval request — refused");
        if (request.State != MobileApprovalStates.Pending)
            return Refuse($"request is already '{request.State}' — refused (a decided request cannot be re-decided; approvals are append-only history)");
        if (now > request.ExpiresUtc)
        {
            lock (_gate) _requests[request.Id] = request with { State = MobileApprovalStates.Expired };
            Changed?.Invoke();
            return Refuse("request expired — refused");
        }
        // DUAL CONTROL means a SECOND operator (D38 rmm24 F6):
        // the requester can never decide their own request, however
        // valid their signature — one person raising and approving
        // the same action is a single point of control wearing a
        // dual-control label.
        if (string.Equals(userId ?? "", request.RequestedBy ?? "", StringComparison.OrdinalIgnoreCase))
            return Refuse($"operator '{userId}' requested this action and cannot decide it — refused (dual control requires a second operator)");
        var registration = _clients.ForLive(clientDeviceId);
        if (registration is null || !string.Equals(registration.UserId, userId ?? "", StringComparison.OrdinalIgnoreCase))
            return Refuse("the deciding device is not this operator's registered mobile client (or its enrollment has been revoked) — refused (approvals come only from the operator's keyed client)");
        if (!_auth.Can(request.ScopeId, userId, clientDeviceId, "approve_dual_control", request.DeviceGroupId))
            return Refuse($"operator '{userId}' holds no approval right (admin) on device group '{request.DeviceGroupId}' — refused");
        var message = CanonicalMessage(request.Id, request.ActionHash, normalizedDecision);
        if (!_enrollments.VerifyEnrolledSignature(clientDeviceId, message, signatureBase64))
            return Refuse("approval signature does not verify against the client device's enrolled key — refused (forgery wall)");
        lock (_gate)
        {
            // Re-check under the gate: a concurrent decision wins once.
            var current = _requests[request.Id];
            if (current.State != MobileApprovalStates.Pending)
                return Refuse($"request is already '{current.State}' — refused");
            _requests[request.Id] = current with
            {
                State = normalizedDecision,
                DecidedBy = userId, DecidedByClientDeviceId = clientDeviceId, DecidedUtc = now,
            };
        }
        _audit.Append("mobile_approval_decided", userId,
            $"request={request.Id} decision={normalizedDecision} clientDevice={clientDeviceId} actionHash={request.ActionHash} (signature verified against the enrolled client key)", now);
        Changed?.Invoke();
        return (true, $"approval recorded: {normalizedDecision} for request {request.Id} by '{userId}' from their registered mobile client");
    }
}

// ---- notification queue -----------------------------------------------------------

public static class MobileNotificationStates
{
    public const string Queued = "queued";
    public const string Delivered = "delivered";
    public const string Acknowledged = "acknowledged";
}

public sealed record MobileNotification(
    string Id, string OperatorUserId, string AlertId, string DeviceId,
    string Severity, string Detail, string Source, DateTimeOffset EnqueuedUtc, string State);

/// <summary>The hub-side per-operator notification queue. Alerts
/// enter ONLY from verified sources (see the file header): a hub
/// alert-centre id, or a hub-key-signed payload. Delivery is
/// transport-checked against the deployment shape.</summary>
public sealed class MobileNotificationQueue
{
    private readonly Func<string, HealthAlertEvent?> _alertLookup;
    private readonly byte[]? _hubPublicKey;
    private readonly ChainedAuditLog _audit;
    private readonly MobileAuthorization? _auth;
    private readonly string? _scopeId;
    private readonly Func<string, string?>? _deviceGroupOf;
    private readonly Func<string, string?>? _clientDeviceOf;
    private readonly Dictionary<string, MobileNotification> _byId = new(StringComparer.Ordinal);
    private readonly object _gate = new();

    /// <param name="alertLookup">Resolves an alert id in the hub's
    /// own HealthAlertCentre — the anti-spoofing root for the
    /// id-based path.</param>
    /// <param name="hubPublicKey">The hub's Ed25519 public key for
    /// the signed-payload path; null disables that path.</param>
    /// <param name="auth">When wired (the production shape, via
    /// MobileOperatorService), every enqueue is ALSO gated on the
    /// target operator's live view right for the alert's device
    /// (D38 rmm24 F7a — the data-absent rule HealthFor applies:
    /// an alert from a group the operator cannot view never
    /// reaches their phone).</param>
    /// <param name="deviceGroupOf">Device id → its device group.</param>
    /// <param name="clientDeviceOf">Operator user id → their
    /// registered client device id.</param>
    /// <summary>W5 wiring: raised after any durable mutation so
    /// the host can write the store through to disk.</summary>
    public event Action? Changed;

    public MobileNotificationQueue(Func<string, HealthAlertEvent?> alertLookup, ChainedAuditLog audit, byte[]? hubPublicKey = null,
        MobileAuthorization? auth = null, string? scopeId = null,
        Func<string, string?>? deviceGroupOf = null, Func<string, string?>? clientDeviceOf = null)
    {
        _alertLookup = alertLookup ?? throw new ArgumentNullException(nameof(alertLookup));
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _hubPublicKey = hubPublicKey?.ToArray();
        _auth = auth;
        _scopeId = scopeId;
        _deviceGroupOf = deviceGroupOf;
        _clientDeviceOf = clientDeviceOf;
    }

    /// <summary>The F7a gate: true when no authorization context is
    /// wired (direct model use), otherwise true ONLY when the
    /// operator's registered client holds the notification
    /// capability (view) on the alert device's group, judged live.</summary>
    private bool OperatorMayBeNotified(string operatorUserId, string deviceId, string alertId, DateTimeOffset now)
    {
        if (_auth is null) return true;
        var clientDevice = _clientDeviceOf?.Invoke(operatorUserId);
        var group = _deviceGroupOf?.Invoke(deviceId);
        if (clientDevice is not null && group is not null &&
            _auth.Can(_scopeId ?? "", operatorUserId, clientDevice, "receive_alert_notifications", group))
            return true;
        _audit.Append("mobile_notification_refused", operatorUserId ?? "(unknown)",
            $"alert={alertId} device={deviceId} reason=operator holds no view right on the alert device's group (or has no live registered client) — refused (data-absent: alerts from unviewable groups never reach the phone)", now);
        return false;
    }

    public IReadOnlyList<MobileNotification> ForOperator(string operatorUserId)
    {
        lock (_gate)
            return _byId.Values
                .Where(n => string.Equals(n.OperatorUserId, operatorUserId ?? "", StringComparison.OrdinalIgnoreCase))
                .OrderBy(n => n.EnqueuedUtc).ToList();
    }

    /// <summary>Enqueue from a hub alert id. An id that does not
    /// resolve in the hub's alert centre enqueues NOTHING — that
    /// refusal is the notification-spoofing wall.</summary>
    public (MobileNotification? Notification, string Reason) EnqueueFromHubAlert(
        string alertId, string operatorUserId, DateTimeOffset now)
    {
        var alert = string.IsNullOrWhiteSpace(alertId) ? null : _alertLookup(alertId);
        if (alert is null)
        {
            _audit.Append("mobile_notification_refused", operatorUserId ?? "(unknown)",
                $"alert={alertId} reason=alert id does not resolve in the hub alert centre — refused (spoofing wall)", now);
            return (null, "alert id does not resolve in the hub's alert centre — refused (a notification can only carry a real hub alert)");
        }
        if (!OperatorMayBeNotified(operatorUserId, alert.DeviceId, alert.AlertId, now))
            return (null, "operator may not view the alert's device — refused (data-absent notification gate)");
        return EnqueueLocked(new MobileNotification(
            Guid.NewGuid().ToString("N"), operatorUserId, alert.AlertId, alert.DeviceId,
            alert.Severity, alert.Detail, "hub_alert_centre", now, MobileNotificationStates.Queued), now);
    }

    /// <summary>The canonical signed-notification payload, v2
    /// (D38 rmm24 F7b/c): the OPERATOR is inside the signed bytes
    /// (a payload signed for one operator can never be enqueued
    /// for another), and every field is LENGTH-PREFIXED — the v1
    /// bare '|' join let a genuine signature over
    /// (a1, ws-1, warning, "real|text") verify for
    /// (a1, "ws-1|warning", real, text), shifting device and
    /// severity. Length prefixes make field boundaries part of
    /// the signed structure, so no re-split verifies.</summary>
    public static byte[] CanonicalPayload(string alertId, string deviceId, string severity, string detail, string operatorUserId)
    {
        static string Field(string? s) { s ??= ""; return $"|{s.Length}:{s}"; }
        return Encoding.UTF8.GetBytes("acp-mobile-notify-v2"
            + Field(operatorUserId) + Field(alertId) + Field(deviceId) + Field(severity) + Field(detail));
    }

    /// <summary>Enqueue from a hub-signed payload (the path a
    /// hub-to-hub or relay leg uses). The signature must verify
    /// against the hub key; an unsigned or wrongly-signed payload
    /// is a spoof and enqueues nothing.</summary>
    public (MobileNotification? Notification, string Reason) EnqueueSigned(
        string alertId, string deviceId, string severity, string detail,
        string operatorUserId, string? signatureBase64, DateTimeOffset now)
    {
        if (_hubPublicKey is null)
        {
            _audit.Append("mobile_notification_refused", operatorUserId ?? "(unknown)",
                $"alert={alertId} reason=signed-notification path is not configured (no hub key) — refused", now);
            return (null, "the signed-notification path is not configured (no hub key) — refused");
        }
        byte[] signature;
        try { signature = Convert.FromBase64String(signatureBase64 ?? ""); }
        catch
        {
            // EVERY refusal audits (D38 rmm24 F7d) — a malformed
            // signature was previously the one silent path.
            _audit.Append("mobile_notification_refused", operatorUserId ?? "(unknown)",
                $"alert={alertId} reason=notification signature is malformed (not base64) — refused (spoofing wall)", now);
            return (null, "notification signature is malformed — refused (spoofing wall)");
        }
        if (!Ed25519.Verify(_hubPublicKey, CanonicalPayload(alertId, deviceId, severity, detail, operatorUserId), signature))
        {
            _audit.Append("mobile_notification_refused", operatorUserId ?? "(unknown)",
                $"alert={alertId} reason=signature does not verify against the hub key — refused (spoofing wall)", now);
            return (null, "notification signature does not verify against the hub key — refused (spoofing wall)");
        }
        if (!OperatorMayBeNotified(operatorUserId, deviceId, alertId, now))
            return (null, "operator may not view the alert's device — refused (data-absent notification gate)");
        return EnqueueLocked(new MobileNotification(
            Guid.NewGuid().ToString("N"), operatorUserId, alertId, deviceId,
            severity, detail, "hub_signed", now, MobileNotificationStates.Queued), now);
    }

    private (MobileNotification?, string) EnqueueLocked(MobileNotification notification, DateTimeOffset now)
    {
        lock (_gate)
        {
            // Bounded retention (D38 rmm24 F12c): acknowledged
            // notifications 30 days old are pruned at enqueue.
            var dead = _byId.Values
                .Where(n => n.State == MobileNotificationStates.Acknowledged &&
                            now - n.EnqueuedUtc > TimeSpan.FromDays(30))
                .Select(n => n.Id).ToList();
            foreach (var id in dead) _byId.Remove(id);
            // Dedup: one queued/delivered notification per
            // (operator, alert). bd-shared-plat-2/F12: an
            // ACKNOWLEDGED notification no longer dedups — a
            // re-raised alert with the same id notifies again.
            var existing = _byId.Values.FirstOrDefault(n =>
                n.State is MobileNotificationStates.Queued or MobileNotificationStates.Delivered &&
                string.Equals(n.OperatorUserId, notification.OperatorUserId, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(n.AlertId, notification.AlertId, StringComparison.Ordinal));
            if (existing is not null) return (existing, "notification already queued for this alert (dedup)");
            _byId[notification.Id] = notification;
        }
        _audit.Append("mobile_notification_queued", notification.OperatorUserId,
            $"notification={notification.Id} alert={notification.AlertId} device={notification.DeviceId} severity={notification.Severity} source={notification.Source}", now);
        Changed?.Invoke();
        return (notification, "notification queued");
    }

    /// <summary>Mark delivery over a named transport. In the
    /// self-hosted shape, platform push REFUSES by name — the
    /// deployment-shape honesty rule, enforced not documented.</summary>
    public (bool Ok, string Reason) MarkDelivered(string notificationId, string transportId, bool selfHostedShape, DateTimeOffset now)
    {
        var transport = MobileNotificationTransports.For(transportId);
        if (transport is null) return (false, $"unknown notification transport '{transportId}' — refused");
        if (selfHostedShape && !transport.AllowedInSelfHosted)
            return (false, $"transport '{transport.Id}' is NOT part of the self-hosted shape — refused: {transport.HonestNote}");
        lock (_gate)
        {
            if (!_byId.TryGetValue(notificationId ?? "", out var n)) return (false, "unknown notification — refused");
            if (n.State != MobileNotificationStates.Queued) return (false, $"notification is '{n.State}', not queued — refused");
            _byId[n.Id] = n with { State = MobileNotificationStates.Delivered };
        }
        _audit.Append("mobile_notification_delivered", "hub",
            $"notification={notificationId} transport={transport.Id} selfHosted={selfHostedShape}", now);
        Changed?.Invoke();
        return (true, $"notification delivered via {transport.Id}");
    }

    public bool Acknowledge(string notificationId, string operatorUserId, DateTimeOffset now)
    {
        lock (_gate)
        {
            if (!_byId.TryGetValue(notificationId ?? "", out var n)) return false;
            if (!string.Equals(n.OperatorUserId, operatorUserId ?? "", StringComparison.OrdinalIgnoreCase)) return false;
            if (n.State != MobileNotificationStates.Delivered) return false;
            _byId[n.Id] = n with { State = MobileNotificationStates.Acknowledged };
        }
        // bd-shared-plat-2/F12: acknowledgements are audited.
        _audit.Append("mobile_notification_acknowledged", operatorUserId ?? "(unknown)",
            $"notification={notificationId}", now);
        Changed?.Invoke();
        return true;
    }

    // bd-shared-plat-2/F12: persistence for the notification queue.
    public string ExportJson()
    {
        lock (_gate) return Acp.Shared.Hub.HubPersistence.Wrap("acp-mobile-notifications-v1",
            System.Text.Json.JsonSerializer.Serialize(_byId.Values.ToArray()));
    }

    public int ImportJson(string json)
    {
        var payload = Acp.Shared.Hub.HubPersistence.Unwrap(json, "acp-mobile-notifications-v1");
        if (payload is null) return 0;
        MobileNotification[]? items;
        try { items = System.Text.Json.JsonSerializer.Deserialize<MobileNotification[]>(payload); }
        catch { return 0; }
        if (items is null) return 0;
        var n = 0;
        lock (_gate)
            foreach (var item in items)
            {
                if (item is null || string.IsNullOrWhiteSpace(item.Id) || _byId.ContainsKey(item.Id)) continue;
                _byId[item.Id] = item; n++;
            }
        if (n > 0) Changed?.Invoke();
        return n;
    }
}
