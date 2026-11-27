using System.Text.Json;
using DeskGuest.Shared.Enrollment;

namespace DeskGuest.Shared.Roster;

/// <summary>A scope (D8): one app holds a personal scope plus any
/// number of company scopes side by side. Every record below carries
/// a ScopeId and every query is scope-filtered — a company scope gains
/// NO visibility or rights over a personal scope (the wall, D8/D14).
/// TransportCeiling is the scope-level allowed-rung cap (D10/D31):
/// company scopes may carry one; a personal scope is always uncapped.</summary>
public sealed record Scope(
    string Id,
    string Kind,
    string Name,
    IReadOnlyList<string>? TransportCeiling = null)
{
    /// <summary>Ordered allowed-rung cap for this scope, or null when
    /// uncapped. Always null for a personal scope (D31).</summary>
    public IReadOnlyList<string> TransportCeiling { get; init; } =
        TransportCeiling ?? Array.Empty<string>();

    /// <summary>True when a ceiling is in force (company scope with a
    /// non-empty cap). An empty list means uncapped.</summary>
    public bool HasCeiling => TransportCeiling.Count > 0;
}

/// <summary>A user record (accounts model: company users are directory
/// records in the company's OWN scope; personal identity lives in the
/// personal scope). Kind is "human" | "ai". An AI is a pairing, not an
/// account (D9): PairedByUserId names the human who paired it, and an
/// AI can NEVER hold an admin seat — assignment refuses (see
/// RosterService.AddCompanyAdmin / AddUserGroupAdmin).</summary>
public sealed record User(
    string Id,
    string ScopeId,
    string DisplayName,
    string Kind,
    string? PairedByUserId = null,
    bool Suspended = false);

/// <summary>A user group (D12): people, carrying rights via grants.
/// Admins of a user group are appointed under the company admin (D13)
/// and must be human (D9).</summary>
public sealed record UserGroup(
    string Id,
    string ScopeId,
    string Name,
    IReadOnlySet<string>? MemberUserIds = null,
    IReadOnlySet<string>? AdminUserIds = null)
{
    public IReadOnlySet<string> MemberUserIds { get; init; } =
        MemberUserIds ?? new HashSet<string>();
    public IReadOnlySet<string> AdminUserIds { get; init; } =
        AdminUserIds ?? new HashSet<string>();
}

/// <summary>A device group (D12/D32). TransportSet is the group's
/// ORDERED list of rung ids chosen from the six automatic rungs —
/// order is failover order (D32). Membership is NOT stored here: it is
/// derived from the Slice 1 enrollment roster (group id bound at mint),
/// never a second hand-edited list.</summary>
public sealed record DeviceGroup(
    string Id,
    string ScopeId,
    string Name,
    IReadOnlyList<string>? TransportSet = null)
{
    /// <summary>The group's ordered transport set (D32).</summary>
    public IReadOnlyList<string> TransportSet { get; init; } =
        TransportSet ?? Array.Empty<string>();
}

/// <summary>A grant (D12/D7): user-group × device-group × rights, with
/// Rights ⊆ { use, enroll, admin, view }. Membership in a user group plus a
/// grant is what lets a member see/use a device group and enroll
/// devices into it (D7).</summary>
public sealed record Grant(
    string ScopeId,
    string UserGroupId,
    string DeviceGroupId,
    IReadOnlySet<string>? Rights = null)
{
    public IReadOnlySet<string> Rights { get; init; } =
        Rights ?? new HashSet<string>();
}

/// <summary>Attribution for an enrollment a user minted (D14: the
/// "auth keys they created" that offboarding must revoke). Slice 1's
/// EnrolledDevice carries no minted-by field, so the roster tracks the
/// attribution here, keyed to the enrolled device id.</summary>
public sealed record MintedEnrollment(string ScopeId, string MintedByUserId, string DeviceId);

/// <summary>An audit-shaped record in the store's event list (admin
/// removals, offboarding, structural acts). The session/audit layers
/// consume these; the offboarding event in particular is the record
/// the session layer must honor for live-session termination (D14).</summary>
public sealed record RosterEvent(
    DateTimeOffset Utc,
    string Kind,
    string ScopeId,
    string? ActorUserId,
    string? SubjectId,
    string Detail);

/// <summary>The offboarding blast list (D14): everything removing a
/// user will touch, computed and returned BEFORE anything fires.
/// PreviewRemoveUser returns this with no mutation; RemoveUser returns
/// the same shape for the removal it actually fired.</summary>
public sealed record OffboardingBlast(
    string ScopeId,
    string UserId,
    IReadOnlyList<string> UserGroupSeatIds,
    IReadOnlyList<string> UserGroupAdminSeatIds,
    bool CompanyAdminSeat,
    IReadOnlyList<Grant> Grants,
    IReadOnlyList<string> MintedEnrollmentDeviceIds,
    IReadOnlyList<string> OwnedAiUserIds,
    bool RequiresLiveSessionTermination,
    string LiveSessionRequirement);

/// <summary>One operator allowed to connect to an endpoint, derived
/// from the endpoint's own Slice 1 receipts (D2).</summary>
public sealed record AllowedOperator(
    string EnrollerName,
    string EnrollerDeviceId,
    string Scope,
    string GroupName,
    DateTimeOffset EnrolledUtc);

/// <summary>The endpoint read shape (D2): ONLY the device's own
/// enrolled record, its own receipts, and the allowed-operators list
/// derived from those receipts. No other device's record, no group
/// roster, no fleet list exists in this shape — the data is absent,
/// not hidden.</summary>
public sealed record EndpointView(
    EnrolledDevice Device,
    IReadOnlyList<EnrollmentReceipt> Receipts,
    IReadOnlyList<AllowedOperator> AllowedOperators);

/// <summary>The operator read shape (D2): the full roster of ONE
/// scope — operator side only, scope-filtered (D8).</summary>
public sealed record OperatorRoster(
    Scope Scope,
    IReadOnlyList<User> Users,
    IReadOnlyList<string> CompanyAdminIds,
    IReadOnlyList<UserGroup> UserGroups,
    IReadOnlyList<DeviceGroup> DeviceGroups,
    IReadOnlyList<Grant> Grants,
    IReadOnlyList<EnrolledDevice> Devices,
    IReadOnlyList<RosterEvent> Events);

/// <summary>
/// Roster &amp; groups store (Slice 2), mirroring PairingService /
/// EnrollmentService discipline: ExportJson/ImportJson + Changed,
/// malformed entries skipped on import, never fatal. Guard refusals
/// (AI admin, last admin, missing step-up, missing admin right,
/// cross-scope, out-of-set pin) return false/null — fail-closed,
/// never an exception and never a silent widening.
/// </summary>
public sealed class RosterService
{
    /// <summary>Valid scope kinds (D8).</summary>
    public static readonly IReadOnlySet<string> ValidScopeKinds =
        new HashSet<string> { "personal", "company" };

    /// <summary>Valid user kinds (D9).</summary>
    public static readonly IReadOnlySet<string> ValidUserKinds =
        new HashSet<string> { "human", "ai" };

    /// <summary>Valid grant rights (D12). "view" was added by the
    /// RMM-11 camera-viewing extension (2026-11-20 adoption): view
    /// is a permissioned right in this same grant model
    /// (user-group × device-group × view), checked through
    /// UserHasRight like every other right.</summary>
    public static readonly IReadOnlySet<string> ValidRights =
        new HashSet<string> { "use", "enroll", "admin", "view" };

    /// <summary>The automatic transport rungs, canonical order:
    /// D32's six (lan, hub, mesh, ipv6, ownpath, tor) plus the two
    /// rungs the transport bench found missing and FR-131/FR-132
    /// built — `netbird` beside `mesh` (the second borrowed-mesh
    /// account rung) and `relay` after `ownpath` (the public
    /// sealed relay: the guaranteed road when no direct or
    /// user-owned path exists, ahead of only Tor). Manual WebRTC
    /// sits below the chain and is never a rung id in a group set.</summary>
    public static readonly IReadOnlyList<string> AllTransportRungs =
        new[] { "lan", "hub", "mesh", "netbird", "ipv6", "ownpath", "relay", "tor" };

    private static readonly HashSet<string> RungSet = new(AllTransportRungs);

    /// <summary>The live-session requirement every blast list names
    /// (D14): sessions are a later slice, so the blast list names the
    /// requirement and the offboarding event records it for the
    /// session layer to honor.</summary>
    public const string LiveSessionRequirementText =
        "Any live session of this user must be terminated; the session layer must honor the recorded offboarding event.";

    private readonly EnrollmentService? _enrollments;
    private readonly Dictionary<string, Scope> _scopes = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, User> _users = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, HashSet<string>> _companyAdmins = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, UserGroup> _userGroups = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DeviceGroup> _deviceGroups = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<Grant> _grants = new();
    /// <summary>Device-group ids that have existed and been deleted.
    /// Enrollment binds a device to a group by bare id (Slice 1), so a
    /// deleted id must NEVER be reusable: re-creating it in any scope
    /// would capture the orphaned enrollments filed under it
    /// (D38 S2-WIN F2). Tombstones persist with the store.</summary>
    private readonly HashSet<string> _deletedDeviceGroupIds = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<MintedEnrollment> _minted = new();
    private readonly List<RosterEvent> _events = new();
    private readonly object _gate = new();

    public RosterService(EnrollmentService? enrollments = null) => _enrollments = enrollments;

    /// <summary>Raised after any durable mutation so the host can
    /// persist the roster (PairingService pattern).</summary>
    public event Action? Changed;

    /// <summary>Composite dictionary key, length-prefixed so it is
    /// injective for ANY id strings: the naive scopeId + "\n" + id
    /// form collides across scopes when an id itself contains a
    /// newline (user "a\nb" in scope "x" == user "b" in scope "x\na")
    /// — D38 S2-WIN F7.</summary>
    private static string Key(string scopeId, string id) =>
        (scopeId ?? "").Length + ":" + (scopeId ?? "") + "\n" + (id ?? "");

    /// <summary>An id fit to be a key: non-blank and free of control
    /// characters (newlines above all — see <see cref="Key"/>).</summary>
    private static bool IsValidId(string? id) =>
        !string.IsNullOrWhiteSpace(id) && !id.Any(char.IsControl);

    private void RecordEvent(string kind, string scopeId, string? actor, string? subject, string detail) =>
        _events.Add(new RosterEvent(DateTimeOffset.UtcNow, kind, scopeId, actor, subject, detail));

    public IReadOnlyList<RosterEvent> ListEvents(string? scopeId = null)
    {
        lock (_gate)
            return _events
                .Where(e => scopeId is null || string.Equals(e.ScopeId, scopeId, StringComparison.OrdinalIgnoreCase))
                .ToList();
    }

    // ---- scopes -----------------------------------------------------------

    /// <summary>Create a scope. Null on refusal: malformed id/name,
    /// unknown kind, duplicate id, or a ceiling containing a rung id
    /// outside the six (D32). A personal scope's ceiling is forced
    /// away — personal is uncapped (D31).</summary>
    public Scope? CreateScope(string id, string kind, string name, IEnumerable<string>? transportCeiling = null)
    {
        if (!IsValidId(id) || string.IsNullOrWhiteSpace(name)) return null;
        var normalizedKind = NormalizeKind(kind, ValidScopeKinds);
        if (normalizedKind is null) return null;
        var ceiling = NormalizeRungs(transportCeiling, out var ceilingOk);
        if (!ceilingOk) return null;
        lock (_gate)
        {
            if (_scopes.ContainsKey(id.Trim())) return null;
            var scope = new Scope(id.Trim(), normalizedKind, name.Trim(),
                normalizedKind == "personal" ? Array.Empty<string>() : ceiling);
            _scopes[scope.Id] = scope;
            Changed?.Invoke();
            return Clone(scope);
        }
    }

    public Scope? GetScope(string? scopeId)
    {
        if (string.IsNullOrWhiteSpace(scopeId)) return null;
        lock (_gate) return _scopes.TryGetValue(scopeId, out var s) ? Clone(s) : null;
    }

    public IReadOnlyList<Scope> ListScopes()
    {
        lock (_gate) return _scopes.Values.Select(Clone).ToList();
    }

    /// <summary>Set/replace a company scope's transport ceiling
    /// (D10/D31). False for a personal scope (uncapped by definition),
    /// an unknown scope, or a ceiling naming a non-rung. Null clears
    /// the cap.</summary>
    public bool SetScopeTransportCeiling(string scopeId, IEnumerable<string>? ceiling)
    {
        // An empty list is NOT a synonym for clearing the cap: stored
        // as-is it would read back as "uncapped" and silently widen
        // the scope to every rung. Refuse it — null is the one clear
        // operation (D38 S2-WIN F8).
        if (ceiling is not null && !ceiling.Any()) return false;
        var normalized = NormalizeRungs(ceiling, out var ok);
        if (!ok) return false;
        lock (_gate)
        {
            if (!_scopes.TryGetValue(scopeId ?? "", out var scope)) return false;
            if (scope.Kind != "company") return false; // personal = uncapped (D31)
            _scopes[scope.Id] = scope with { TransportCeiling = normalized };
            Changed?.Invoke();
            return true;
        }
    }

    /// <summary>The scope's ceiling as a set for resolution, or null
    /// when uncapped (always null for a personal scope, D31).</summary>
    public IReadOnlyList<string>? GetScopeTransportCeiling(string scopeId)
    {
        lock (_gate)
        {
            if (!_scopes.TryGetValue(scopeId ?? "", out var scope)) return null;
            return scope.HasCeiling ? scope.TransportCeiling.ToList() : null;
        }
    }

    // ---- users --------------------------------------------------------------

    /// <summary>Create a user in a scope. Null on refusal: unknown
    /// scope, unknown kind, duplicate id in the scope, a human carrying
    /// a PairedByUserId, or an AI whose pairing owner is missing / not
    /// a human user of the SAME scope (D9 — cross-scope ownership is
    /// exactly the leak the wall forbids, D8).</summary>
    public User? CreateUser(string id, string scopeId, string displayName, string kind, string? pairedByUserId = null)
    {
        if (!IsValidId(id) || string.IsNullOrWhiteSpace(displayName)) return null;
        var normalizedKind = NormalizeKind(kind, ValidUserKinds);
        if (normalizedKind is null || string.IsNullOrWhiteSpace(scopeId)) return null;
        lock (_gate)
        {
            if (!_scopes.TryGetValue(scopeId, out var scope)) return null;
            if (_users.ContainsKey(Key(scope.Id, id.Trim()))) return null;
            // Personal scope: the owner is the SOLE human user (Slice 2
            // spec) — every human there is its admin by IsScopeAdmin,
            // so a second human is a second full owner (D38 S2-WIN F7).
            if (scope.Kind == "personal" && normalizedKind == "human" &&
                _users.Values.Any(u => string.Equals(u.ScopeId, scope.Id, StringComparison.OrdinalIgnoreCase) &&
                                       u.Kind == "human"))
                return null;
            string? owner = null;
            if (normalizedKind == "ai")
            {
                if (string.IsNullOrWhiteSpace(pairedByUserId)) return null;
                if (!_users.TryGetValue(Key(scope.Id, pairedByUserId), out var ownerUser) || ownerUser.Kind != "human")
                    return null;
                owner = ownerUser.Id;
            }
            else if (!string.IsNullOrWhiteSpace(pairedByUserId))
            {
                return null; // PairedByUserId is AI-only (D9)
            }
            var user = new User(id.Trim(), scope.Id, displayName.Trim(), normalizedKind, owner, Suspended: false);
            _users[Key(scope.Id, user.Id)] = user;
            Changed?.Invoke();
            return user;
        }
    }

    public User? GetUser(string? scopeId, string? userId)
    {
        if (string.IsNullOrWhiteSpace(scopeId) || string.IsNullOrWhiteSpace(userId)) return null;
        lock (_gate) return _users.TryGetValue(Key(scopeId, userId), out var u) ? u : null;
    }

    /// <summary>Users of ONE scope only (D8 scope isolation).</summary>
    public IReadOnlyList<User> ListUsers(string scopeId)
    {
        lock (_gate)
            return _users.Values
                .Where(u => string.Equals(u.ScopeId, scopeId, StringComparison.OrdinalIgnoreCase))
                .ToList();
    }

    public bool SetUserSuspended(string scopeId, string userId, bool suspended)
    {
        lock (_gate)
        {
            if (!_users.TryGetValue(Key(scopeId ?? "", userId ?? ""), out var user)) return false;
            if (suspended && !user.Suspended &&
                _scopes.TryGetValue(user.ScopeId, out var scope) && scope.Kind == "company" &&
                IsLiveCompanyAdminLocked(user.ScopeId, user.Id) &&
                _companyAdmins[user.ScopeId].Count(id => IsLiveCompanyAdminLocked(user.ScopeId, id)) <= 1)
                return false; // suspending the sole LIVE admin locks the scope (D26's guard, applied to suspension — D38 S2-WIN F1/F5)
            if (user.Suspended != suspended)
            {
                _users[Key(user.ScopeId, user.Id)] = user with { Suspended = suspended };
                RecordEvent(suspended ? "user_suspended" : "user_unsuspended", user.ScopeId, null, user.Id,
                    suspended ? "User suspended." : "User suspension lifted.");
            }
            Changed?.Invoke();
            return true;
        }
    }

    // ---- company admins (D13/D26) --------------------------------------------

    /// <summary>The scope-level company-admin set (peer admins, D26).</summary>
    public IReadOnlySet<string> CompanyAdmins(string scopeId)
    {
        lock (_gate)
            return _companyAdmins.TryGetValue(scopeId ?? "", out var set)
                ? new HashSet<string>(set, StringComparer.OrdinalIgnoreCase)
                : new HashSet<string>();
    }

    public bool IsCompanyAdmin(string scopeId, string userId)
    {
        lock (_gate)
            return _companyAdmins.TryGetValue(scopeId ?? "", out var set) && set.Contains(userId ?? "");
    }

    /// <summary>Seat membership PLUS liveness (gate held): the seat
    /// alone is not power — a suspended or removed admin holds none.
    /// AddCompanyAdmin refuses to seat a suspended user; every power
    /// path (offboarding, fellow-admin removal) must apply the same
    /// liveness rule to an already-seated admin who is later
    /// suspended (destruction gate DG-S2-01).</summary>
    private bool IsLiveCompanyAdminLocked(string scopeId, string? userId)
    {
        if (string.IsNullOrWhiteSpace(userId)) return false;
        if (!_companyAdmins.TryGetValue(scopeId ?? "", out var set) || !set.Contains(userId)) return false;
        return _users.TryGetValue(Key(scopeId, userId), out var user) &&
               user.Kind == "human" && !user.Suspended;
    }

    /// <summary>Assign a company-admin seat. Refuses (false) for a
    /// non-company scope, an unknown or suspended user, and — always —
    /// an AI: an AI can NEVER hold an admin seat (D9).</summary>
    public bool AddCompanyAdmin(string scopeId, string userId)
    {
        lock (_gate)
        {
            if (!_scopes.TryGetValue(scopeId ?? "", out var scope) || scope.Kind != "company") return false;
            if (!_users.TryGetValue(Key(scope.Id, userId ?? ""), out var user)) return false;
            if (user.Kind != "human" || user.Suspended) return false; // D9: AI never admin
            if (!_companyAdmins.TryGetValue(scope.Id, out var set))
                _companyAdmins[scope.Id] = set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (!set.Add(user.Id)) return false;
            RecordEvent("company_admin_added", scope.Id, null, user.Id, "Company admin seat assigned.");
            Changed?.Invoke();
            return true;
        }
    }

    /// <summary>Remove a company-admin seat. Guards (D26/D13): the
    /// LAST company admin cannot be removed; the actor must themselves
    /// be a company admin; removing a FELLOW admin requires stepUp =
    /// true. A successful fellow-admin removal writes an audit-shaped
    /// record into the store's event list.</summary>
    public bool RemoveCompanyAdmin(string scopeId, string userId, string actorUserId, bool stepUp = false)
    {
        lock (_gate)
        {
            if (!_scopes.TryGetValue(scopeId ?? "", out var scope) || scope.Kind != "company") return false;
            if (!_companyAdmins.TryGetValue(scope.Id, out var set) || !set.Contains(userId ?? "")) return false;
            if (set.Count <= 1) return false; // last-admin guard (D26)
            if (!IsLiveCompanyAdminLocked(scope.Id, actorUserId)) return false; // actor must be a live peer admin
            // The guard counts LIVE admins, not seats: with a suspended
            // peer on paper, removing the sole live admin would strand
            // the scope at zero usable admins (D38 S2-WIN F5).
            if (IsLiveCompanyAdminLocked(scope.Id, userId) &&
                set.Count(id => IsLiveCompanyAdminLocked(scope.Id, id)) <= 1)
                return false;
            var fellow = !string.Equals(actorUserId, userId, StringComparison.OrdinalIgnoreCase);
            if (fellow && !stepUp) return false; // step-up required (D13/D26)
            set.Remove(userId);
            RecordEvent("company_admin_removed", scope.Id, actorUserId, userId,
                fellow ? "Fellow company admin removed with step-up confirmation." : "Company admin removed own seat.");
            Changed?.Invoke();
            return true;
        }
    }

    /// <summary>Scope-admin test used by structural acts: a company
    /// admin of a company scope, or the human owner of a personal
    /// scope (the owner is the sole user and admin, D8).</summary>
    public bool IsScopeAdmin(string scopeId, string? userId)
    {
        if (string.IsNullOrWhiteSpace(userId)) return false;
        lock (_gate)
        {
            if (!_scopes.TryGetValue(scopeId ?? "", out var scope)) return false;
            if (!_users.TryGetValue(Key(scope.Id, userId), out var user) || user.Suspended) return false;
            if (scope.Kind == "personal") return user.Kind == "human";
            return _companyAdmins.TryGetValue(scope.Id, out var set) && set.Contains(user.Id);
        }
    }

    // ---- user groups (D12) -----------------------------------------------------

    /// <summary>Create a user group. Null on refusal: unknown scope,
    /// duplicate id in the scope, a member/admin who is not a user of
    /// the SAME scope (D8), or an AI in the admin list (D9 — assignment
    /// refuses). Group admins are also members.</summary>
    public UserGroup? CreateUserGroup(string id, string scopeId, string name,
        IEnumerable<string>? memberUserIds = null, IEnumerable<string>? adminUserIds = null)
    {
        if (!IsValidId(id) || string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(scopeId)) return null;
        lock (_gate)
        {
            if (!_scopes.TryGetValue(scopeId, out var scope)) return null;
            if (_userGroups.ContainsKey(Key(scope.Id, id.Trim()))) return null;
            var members = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var memberId in memberUserIds ?? Array.Empty<string>())
            {
                if (!_users.TryGetValue(Key(scope.Id, memberId ?? ""), out var member)) return null;
                members.Add(member.Id);
            }
            var admins = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var adminId in adminUserIds ?? Array.Empty<string>())
            {
                if (!_users.TryGetValue(Key(scope.Id, adminId ?? ""), out var admin)) return null;
                if (admin.Kind != "human") return null; // D9: AI never admin
                admins.Add(admin.Id);
                members.Add(admin.Id);
            }
            var group = new UserGroup(id.Trim(), scope.Id, name.Trim(), members, admins);
            _userGroups[Key(scope.Id, group.Id)] = group;
            Changed?.Invoke();
            return Clone(group);
        }
    }

    public UserGroup? GetUserGroup(string scopeId, string groupId)
    {
        lock (_gate) return _userGroups.TryGetValue(Key(scopeId ?? "", groupId ?? ""), out var g) ? Clone(g) : null;
    }

    /// <summary>User groups of ONE scope only (D8).</summary>
    public IReadOnlyList<UserGroup> ListUserGroups(string scopeId)
    {
        lock (_gate)
            return _userGroups.Values
                .Where(g => string.Equals(g.ScopeId, scopeId, StringComparison.OrdinalIgnoreCase))
                .Select(Clone).ToList();
    }

    /// <summary>Admin-gated membership change (D7: only admins control
    /// membership). The actor needs an admin right on this group.</summary>
    public bool AddUserGroupMember(string scopeId, string groupId, string userId, string actorUserId)
    {
        lock (_gate)
        {
            if (!_userGroups.TryGetValue(Key(scopeId ?? "", groupId ?? ""), out var group)) return false;
            if (!_users.TryGetValue(Key(group.ScopeId, userId ?? ""), out var user)) return false;
            if (!HasAdminRightLocked(group.ScopeId, actorUserId, userGroupId: group.Id)) return false;
            var members = new HashSet<string>(group.MemberUserIds, StringComparer.OrdinalIgnoreCase) { user.Id };
            _userGroups[Key(group.ScopeId, group.Id)] = group with { MemberUserIds = members };
            Changed?.Invoke();
            return true;
        }
    }

    /// <summary>Remove a member (and any group-admin seat they held).
    /// Admin-gated (D7: only admins can remove a user from a group);
    /// a regular member's attempt is refused (D5/D6).</summary>
    public bool RemoveUserGroupMember(string scopeId, string groupId, string userId, string actorUserId)
    {
        lock (_gate)
        {
            if (!_userGroups.TryGetValue(Key(scopeId ?? "", groupId ?? ""), out var group)) return false;
            if (!HasAdminRightLocked(group.ScopeId, actorUserId, userGroupId: group.Id)) return false;
            var members = new HashSet<string>(group.MemberUserIds, StringComparer.OrdinalIgnoreCase);
            var admins = new HashSet<string>(group.AdminUserIds, StringComparer.OrdinalIgnoreCase);
            if (!members.Remove(userId ?? "")) return false;
            admins.Remove(userId ?? "");
            _userGroups[Key(group.ScopeId, group.Id)] = group with { MemberUserIds = members, AdminUserIds = admins };
            Changed?.Invoke();
            return true;
        }
    }

    /// <summary>Appoint a user-group admin (D13: appointed under the
    /// company admin). Refuses an AI outright (D9), a cross-scope user,
    /// and an actor who is neither company admin nor an existing admin
    /// of this group (nor the personal-scope owner).</summary>
    public bool AddUserGroupAdmin(string scopeId, string groupId, string userId, string actorUserId)
    {
        lock (_gate)
        {
            if (!_userGroups.TryGetValue(Key(scopeId ?? "", groupId ?? ""), out var group)) return false;
            if (!_users.TryGetValue(Key(group.ScopeId, userId ?? ""), out var user)) return false;
            if (user.Kind != "human" || user.Suspended) return false; // D9
            if (!HasAdminRightLocked(group.ScopeId, actorUserId, userGroupId: group.Id)) return false;
            var admins = new HashSet<string>(group.AdminUserIds, StringComparer.OrdinalIgnoreCase) { user.Id };
            var members = new HashSet<string>(group.MemberUserIds, StringComparer.OrdinalIgnoreCase) { user.Id };
            _userGroups[Key(group.ScopeId, group.Id)] = group with { AdminUserIds = admins, MemberUserIds = members };
            RecordEvent("user_group_admin_added", group.ScopeId, actorUserId, user.Id, $"Group admin appointed for user group {group.Id}.");
            Changed?.Invoke();
            return true;
        }
    }

    /// <summary>Delete a user group and the grants that reference it.
    /// Structural act (D5/D6/D7): requires the admin right on the group
    /// or a company-admin seat — a regular member is refused.</summary>
    public bool DeleteUserGroup(string scopeId, string groupId, string actorUserId)
    {
        lock (_gate)
        {
            if (!_userGroups.TryGetValue(Key(scopeId ?? "", groupId ?? ""), out var group)) return false;
            if (!HasAdminRightLocked(group.ScopeId, actorUserId, userGroupId: group.Id)) return false;
            _userGroups.Remove(Key(group.ScopeId, group.Id));
            _grants.RemoveAll(g => string.Equals(g.ScopeId, group.ScopeId, StringComparison.OrdinalIgnoreCase) &&
                                    string.Equals(g.UserGroupId, group.Id, StringComparison.OrdinalIgnoreCase));
            RecordEvent("user_group_deleted", group.ScopeId, actorUserId, group.Id, "User group deleted by an admin actor.");
            Changed?.Invoke();
            return true;
        }
    }

    // ---- device groups (D12/D32) ------------------------------------------------

    /// <summary>Create a device group with its ordered transport set
    /// (D32). Device-group ids are globally unique because Slice 1
    /// enrollment binds a group by id alone at mint. Null on refusal:
    /// unknown scope, duplicate id, or a transport set naming a rung
    /// outside the six. A null set defaults to all six rungs in
    /// canonical order; an explicit empty set is honored.</summary>
    public DeviceGroup? CreateDeviceGroup(string id, string scopeId, string name, IEnumerable<string>? transportSet = null)
    {
        if (!IsValidId(id) || string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(scopeId)) return null;
        var ok = true;
        var set = transportSet is null ? AllTransportRungs.ToList() : NormalizeRungs(transportSet, out ok);
        if (!ok) return null;
        lock (_gate)
        {
            if (!_scopes.TryGetValue(scopeId, out var scope)) return null;
            if (_deviceGroups.Values.Any(g => string.Equals(g.Id, id.Trim(), StringComparison.OrdinalIgnoreCase))) return null;
            if (_deletedDeviceGroupIds.Contains(id.Trim())) return null; // tombstoned: never reusable (F2)
            var group = new DeviceGroup(id.Trim(), scope.Id, name.Trim(), set);
            _deviceGroups[Key(scope.Id, group.Id)] = group;
            Changed?.Invoke();
            return Clone(group);
        }
    }

    public DeviceGroup? GetDeviceGroup(string scopeId, string groupId)
    {
        lock (_gate) return _deviceGroups.TryGetValue(Key(scopeId ?? "", groupId ?? ""), out var g) ? Clone(g) : null;
    }

    /// <summary>Find a device group by its (globally unique) id alone —
    /// the lookup enrollment-bound devices resolve through.</summary>
    public DeviceGroup? FindDeviceGroup(string groupId)
    {
        lock (_gate)
        {
            var group = _deviceGroups.Values.FirstOrDefault(
                g => string.Equals(g.Id, groupId ?? "", StringComparison.OrdinalIgnoreCase));
            return group is null ? null : Clone(group);
        }
    }

    /// <summary>Device groups of ONE scope only (D8).</summary>
    public IReadOnlyList<DeviceGroup> ListDeviceGroups(string scopeId)
    {
        lock (_gate)
            return _deviceGroups.Values
                .Where(g => string.Equals(g.ScopeId, scopeId, StringComparison.OrdinalIgnoreCase))
                .Select(Clone).ToList();
    }

    /// <summary>Device-group membership, DERIVED from the Slice 1
    /// enrollment roster (D12): the enrolled, non-revoked devices whose
    /// enrollment was minted into this group. There is no stored
    /// membership list to hand-edit — revoking an enrollment removes
    /// the device here on the next read.</summary>
    public IReadOnlyList<string> DeviceGroupDeviceIds(string scopeId, string groupId)
    {
        DeviceGroup? group;
        lock (_gate) _deviceGroups.TryGetValue(Key(scopeId ?? "", groupId ?? ""), out group);
        if (group is null || _enrollments is null) return Array.Empty<string>();
        return _enrollments.List()
            .Where(d => !d.Revoked && string.Equals(d.GroupId, group.Id, StringComparison.OrdinalIgnoreCase))
            .Select(d => d.DeviceId)
            .ToList();
    }

    /// <summary>Replace a device group's ordered transport set (D32).
    /// Changing the SET is a group-admin act: the actor needs an admin
    /// right on this device group or a company-admin seat — a
    /// non-admin attempting to widen (or otherwise change) the set is
    /// refused. Unknown rung ids are refused, never dropped silently
    /// into a different set than the admin chose.</summary>
    public bool SetGroupTransports(string scopeId, string groupId, IEnumerable<string> transportSet, string actorUserId)
    {
        var set = NormalizeRungs(transportSet, out var ok);
        if (!ok) return false;
        lock (_gate)
        {
            if (!_deviceGroups.TryGetValue(Key(scopeId ?? "", groupId ?? ""), out var group)) return false;
            if (!HasAdminRightLocked(group.ScopeId, actorUserId, deviceGroupId: group.Id)) return false;
            _deviceGroups[Key(group.ScopeId, group.Id)] = group with { TransportSet = set };
            RecordEvent("device_group_transports_changed", group.ScopeId, actorUserId, group.Id,
                $"Transport set changed to [{string.Join(", ", set)}].");
            Changed?.Invoke();
            return true;
        }
    }

    /// <summary>Delete a device group and the grants that reference
    /// it. Structural act (D7): requires the admin right on the group
    /// or a company-admin seat. Enrolled devices keep their Slice 1
    /// records (revocation is DeleteDevice's act, not this one's).</summary>
    public bool DeleteDeviceGroup(string scopeId, string groupId, string actorUserId)
    {
        lock (_gate)
        {
            if (!_deviceGroups.TryGetValue(Key(scopeId ?? "", groupId ?? ""), out var group)) return false;
            if (!HasAdminRightLocked(group.ScopeId, actorUserId, deviceGroupId: group.Id)) return false;
            _deviceGroups.Remove(Key(group.ScopeId, group.Id));
            _deletedDeviceGroupIds.Add(group.Id); // tombstone (F2): orphaned enrollments keep this bare id
            _grants.RemoveAll(g => string.Equals(g.ScopeId, group.ScopeId, StringComparison.OrdinalIgnoreCase) &&
                                    string.Equals(g.DeviceGroupId, group.Id, StringComparison.OrdinalIgnoreCase));
            RecordEvent("device_group_deleted", group.ScopeId, actorUserId, group.Id, "Device group deleted by an admin actor.");
            Changed?.Invoke();
            return true;
        }
    }

    /// <summary>Delete a device (D7: only admins can delete a device).
    /// The roster-side act is Slice 1 revocation — immediate effect.
    /// Refused without an admin right on the device's group, across
    /// scopes (the device's group must belong to the given scope, D8),
    /// and for unknown devices.</summary>
    public bool DeleteDevice(string scopeId, string deviceId, string actorUserId)
    {
        if (_enrollments is null || string.IsNullOrWhiteSpace(deviceId)) return false;
        var device = _enrollments.List().FirstOrDefault(
            d => string.Equals(d.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase));
        if (device is null) return false;
        lock (_gate)
        {
            var group = _deviceGroups.Values.FirstOrDefault(
                g => string.Equals(g.Id, device.GroupId, StringComparison.OrdinalIgnoreCase));
            // Unknown group: FAIL CLOSED. The old fallback let the admin
            // of ANY caller-supplied scope revoke an orphaned device in
            // every other scope — a cross-scope write path (D38 S2-WIN F3).
            if (group is null) return false;
            if (!string.Equals(group.ScopeId, scopeId, StringComparison.OrdinalIgnoreCase))
                return false; // cross-scope structural act refused (D8 wall)
            if (!HasAdminRightLocked(group.ScopeId, actorUserId, deviceGroupId: group.Id)) return false;
            if (!_enrollments.Revoke(device.DeviceId)) return false;
            RecordEvent("device_deleted", scopeId, actorUserId, device.DeviceId,
                "Device deleted by an admin actor (enrollment revoked).");
            Changed?.Invoke();
            return true;
        }
    }

    // ---- grants (D12/D7) ---------------------------------------------------------

    /// <summary>Create (or replace the rights of) a grant:
    /// user-group × device-group × rights. Null on refusal: unknown
    /// scope, either group missing from THAT scope (D8), or rights
    /// empty / naming a right outside { use, enroll, admin }.</summary>
    public Grant? AddGrant(string scopeId, string userGroupId, string deviceGroupId, IEnumerable<string> rights)
    {
        if (string.IsNullOrWhiteSpace(scopeId)) return null;
        var normalizedRights = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var right in rights ?? Array.Empty<string>())
        {
            var r = (right ?? "").Trim().ToLowerInvariant();
            if (!ValidRights.Contains(r)) return null;
            normalizedRights.Add(r);
        }
        if (normalizedRights.Count == 0) return null;
        lock (_gate)
        {
            if (!_scopes.TryGetValue(scopeId, out var scope)) return null;
            if (!_userGroups.TryGetValue(Key(scope.Id, userGroupId ?? ""), out var userGroup)) return null;
            if (!_deviceGroups.TryGetValue(Key(scope.Id, deviceGroupId ?? ""), out var deviceGroup)) return null;
            var grant = new Grant(scope.Id, userGroup.Id, deviceGroup.Id, normalizedRights);
            var existing = _grants.FindIndex(g =>
                string.Equals(g.ScopeId, scope.Id, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(g.UserGroupId, grant.UserGroupId, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(g.DeviceGroupId, grant.DeviceGroupId, StringComparison.OrdinalIgnoreCase));
            if (existing >= 0) _grants[existing] = grant; else _grants.Add(grant);
            // bd-shared-plat-2/F10: grant creation/changes leave
            // an audit trail (RemoveGrant already recorded
            // grant_removed; creation recorded nothing).
            RecordEvent(existing >= 0 ? "grant_changed" : "grant_added", scope.Id,
                _grantActorHint, grant.UserGroupId,
                $"userGroup={grant.UserGroupId} deviceGroup={grant.DeviceGroupId} rights=[{string.Join(",", grant.Rights.OrderBy(r => r, StringComparer.Ordinal))}] actor={_grantActorHint ?? "(bootstrap/local-operator construction)"}");
            Changed?.Invoke();
            return Clone(grant);
        }
    }

    // bd-shared-plat-2/F10: the actor-gated overload stamps its
    // actor here so the shared construction path records it.
    [ThreadStatic] private static string? _grantActorHint;

    /// <summary>Lane A (camera ruling 2026-11-21 (b), D9 hardening):
    /// actor-gated grant creation — the shape RemoveGrant already
    /// had and AddGrant lacked. Creating a grant is a structural
    /// act: the actor must hold an admin right on the grant's
    /// device group or a company-admin seat (HasAdminRightLocked,
    /// which AI actors never pass). This closes the one path by
    /// which a non-admin caller of the store could have widened
    /// ANY pairing's reach — including an AI's camera `view` —
    /// without a human admin's act. The actor-less overload above
    /// remains for bootstrap/local-operator construction only.</summary>
    public Grant? AddGrant(string scopeId, string userGroupId, string deviceGroupId,
        IEnumerable<string> rights, string actorUserId)
    {
        lock (_gate)
        {
            if (!HasAdminRightLocked(scopeId ?? "", actorUserId ?? "", deviceGroupId: deviceGroupId))
                return null;
        }
        _grantActorHint = actorUserId;
        try { return AddGrant(scopeId, userGroupId, deviceGroupId, rights); }
        finally { _grantActorHint = null; }
    }

    /// <summary>Grants of ONE scope only (D8).</summary>
    public IReadOnlyList<Grant> ListGrants(string scopeId)
    {
        lock (_gate)
            return _grants
                .Where(g => string.Equals(g.ScopeId, scopeId, StringComparison.OrdinalIgnoreCase))
                .Select(Clone).ToList();
    }

    /// <summary>Remove a grant. Structural act: requires an admin
    /// right on the grant's device group or a company-admin seat.</summary>
    public bool RemoveGrant(string scopeId, string userGroupId, string deviceGroupId, string actorUserId)
    {
        lock (_gate)
        {
            var grant = _grants.FirstOrDefault(g =>
                string.Equals(g.ScopeId, scopeId ?? "", StringComparison.OrdinalIgnoreCase) &&
                string.Equals(g.UserGroupId, userGroupId ?? "", StringComparison.OrdinalIgnoreCase) &&
                string.Equals(g.DeviceGroupId, deviceGroupId ?? "", StringComparison.OrdinalIgnoreCase));
            if (grant is null) return false;
            if (!HasAdminRightLocked(grant.ScopeId, actorUserId, deviceGroupId: grant.DeviceGroupId)) return false;
            _grants.Remove(grant);
            RecordEvent("grant_removed", grant.ScopeId, actorUserId, grant.DeviceGroupId, "Grant removed by an admin actor.");
            Changed?.Invoke();
            return true;
        }
    }

    /// <summary>Does this user hold a right on a device group (D7/D12)?
    /// Company admins hold every right; otherwise the user must be a
    /// member of a user group whose grant on the device group carries
    /// the right. An AI NEVER holds the admin right (D9), whatever its
    /// groups' grants say. Suspended users hold nothing.</summary>
    public bool UserHasRight(string scopeId, string userId, string deviceGroupId, string right)
    {
        var r = (right ?? "").Trim().ToLowerInvariant();
        if (!ValidRights.Contains(r)) return false;
        lock (_gate)
        {
            if (!_users.TryGetValue(Key(scopeId ?? "", userId ?? ""), out var user) || user.Suspended) return false;
            if (r == "admin" && user.Kind != "human") return false; // D9
            if (IsScopeAdminLocked(user.ScopeId, user.Id)) return true;
            var memberGroupIds = _userGroups.Values
                .Where(g => string.Equals(g.ScopeId, user.ScopeId, StringComparison.OrdinalIgnoreCase) &&
                            g.MemberUserIds.Contains(user.Id))
                .Select(g => g.Id).ToList();
            return _grants.Any(g =>
                string.Equals(g.ScopeId, user.ScopeId, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(g.DeviceGroupId, deviceGroupId ?? "", StringComparison.OrdinalIgnoreCase) &&
                memberGroupIds.Contains(g.UserGroupId, StringComparer.OrdinalIgnoreCase) &&
                g.Rights.Contains(r));
        }
    }

    /// <summary>Admin-right test for structural acts (call with the
    /// gate held): company-admin seat, personal-scope ownership, admin
    /// of the named user group, or admin of a user group holding an
    /// `admin` grant on the named device group. AI actors never pass
    /// (D9).</summary>
    public bool HasAdminRight(string scopeId, string? actorUserId, string? userGroupId = null, string? deviceGroupId = null)
    {
        lock (_gate) return HasAdminRightLocked(scopeId, actorUserId, userGroupId, deviceGroupId);
    }

    private bool HasAdminRightLocked(string scopeId, string? actorUserId, string? userGroupId = null, string? deviceGroupId = null)
    {
        if (string.IsNullOrWhiteSpace(actorUserId)) return false;
        if (!_users.TryGetValue(Key(scopeId ?? "", actorUserId), out var actor) || actor.Suspended) return false;
        if (actor.Kind != "human") return false; // D9: AI never admin
        if (IsScopeAdminLocked(actor.ScopeId, actor.Id)) return true;
        if (userGroupId is not null &&
            _userGroups.TryGetValue(Key(actor.ScopeId, userGroupId), out var named) &&
            named.AdminUserIds.Contains(actor.Id))
            return true;
        if (deviceGroupId is not null)
        {
            var adminGroupIds = _userGroups.Values
                .Where(g => string.Equals(g.ScopeId, actor.ScopeId, StringComparison.OrdinalIgnoreCase) &&
                            g.AdminUserIds.Contains(actor.Id))
                .Select(g => g.Id).ToList();
            if (_grants.Any(g =>
                    string.Equals(g.ScopeId, actor.ScopeId, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(g.DeviceGroupId, deviceGroupId, StringComparison.OrdinalIgnoreCase) &&
                    adminGroupIds.Contains(g.UserGroupId, StringComparer.OrdinalIgnoreCase) &&
                    g.Rights.Contains("admin")))
                return true;
        }
        return false;
    }

    /// <summary>Lane A (item 4, FL-25): the LIVE approver-principal
    /// source — human, non-suspended scope admins across every
    /// scope (company-admin seats; in a personal scope every human
    /// user is its admin, per IsScopeAdminLocked). AI users are
    /// never approver principals (D9). CoreRuntime feeds this to
    /// the FL-25 decision gate so approvals resolve against real
    /// roster principals, refreshed at decision time; an empty
    /// roster yields an empty set and decisions fail closed.</summary>
    public IReadOnlyList<string> ApproverPrincipalIds()
    {
        lock (_gate)
        {
            var ids = new List<string>();
            foreach (var scope in _scopes.Values)
                foreach (var user in _users.Values)
                    if (string.Equals(user.ScopeId, scope.Id, StringComparison.OrdinalIgnoreCase) &&
                        IsScopeAdminLocked(scope.Id, user.Id))
                        ids.Add(user.Id);
            return ids.OrderBy(i => i, StringComparer.Ordinal).ToList();
        }
    }

    private bool IsScopeAdminLocked(string scopeId, string? userId)
    {
        if (string.IsNullOrWhiteSpace(userId)) return false;
        if (!_scopes.TryGetValue(scopeId ?? "", out var scope)) return false;
        if (!_users.TryGetValue(Key(scope.Id, userId), out var user) || user.Suspended) return false;
        if (scope.Kind == "personal") return user.Kind == "human";
        return _companyAdmins.TryGetValue(scope.Id, out var set) && set.Contains(user.Id);
    }

    // ---- transport resolution (D31/D32) -------------------------------------------

    public static bool IsValidRung(string? rung) =>
        rung is not null && RungSet.Contains(rung.Trim().ToLowerInvariant());

    /// <summary>EffectiveTransports (D31/D32), the pure resolution:
    /// start from the group's ORDERED set; intersect with the company
    /// ceiling (group order preserved; a personal scope passes null =
    /// uncapped); then apply the device's Slice 1 fields — `inherit`
    /// and `auto` keep the resolved order, `manual` pins to the
    /// device's AllowedTransports, intersected with the resolved set
    /// in resolved order. A pin outside the resolved set can never
    /// widen the result here, and is REJECTED at update time (see
    /// UpdateDeviceTransportPolicy) rather than reaching resolution.</summary>
    public static IReadOnlyList<string> EffectiveTransports(
        EnrolledDevice device, DeviceGroup deviceGroup, IEnumerable<string>? companyCeiling)
    {
        var resolved = deviceGroup.TransportSet.ToList();
        if (companyCeiling is not null)
        {
            var cap = new HashSet<string>(companyCeiling.Select(c => c.Trim().ToLowerInvariant()), StringComparer.OrdinalIgnoreCase);
            resolved = resolved.Where(cap.Contains).ToList();
        }
        var mode = EnrollmentService.NormalizeTransportMode(device.TransportMode) ?? "inherit";
        if (mode == "manual" && device.AllowedTransports.Count > 0)
        {
            var pins = new HashSet<string>(device.AllowedTransports, StringComparer.OrdinalIgnoreCase);
            resolved = resolved.Where(pins.Contains).ToList();
        }
        return resolved;
    }

    /// <summary>Resolve a device's effective transports from the
    /// store: its device group (bound at enrollment) and that group's
    /// scope ceiling. Null when the device or its group is unknown.</summary>
    public IReadOnlyList<string>? EffectiveTransportsForDevice(string deviceId)
    {
        if (_enrollments is null || string.IsNullOrWhiteSpace(deviceId)) return null;
        var device = _enrollments.List().FirstOrDefault(
            d => string.Equals(d.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase));
        if (device is null) return null;
        var group = FindDeviceGroup(device.GroupId);
        if (group is null) return null;
        return EffectiveTransports(device, group, GetScopeTransportCeiling(group.ScopeId));
    }

    /// <summary>Update a device's Slice 1 transport fields (the
    /// enrollment-update act, D31/D32). Narrowing/pinning WITHIN the
    /// resolved set never needs an admin. A manual pin naming any rung
    /// outside the resolved set (group set ∩ company ceiling) is
    /// REJECTED — false, device unchanged — never silently widened;
    /// widening the set itself is SetGroupTransports, an admin act.
    /// Unknown modes and non-rung pins are likewise refused.</summary>
    public bool UpdateDeviceTransportPolicy(string deviceId, string transportMode, IEnumerable<string>? allowedTransports)
    {
        // The check and the write run under ONE hold of the roster gate
        // (D38 S2-WIN F12): a concurrent SetGroupTransports / ceiling
        // change can no longer slip between the pin validation and the
        // store, leaving a pin that was already outside the resolved
        // set at the moment it was stored. (Monitor is reentrant: the
        // helpers below take the same gate on this thread.)
        lock (_gate)
        {
            if (_enrollments is null || string.IsNullOrWhiteSpace(deviceId)) return false;
            var mode = EnrollmentService.NormalizeTransportMode(transportMode);
            if (mode is null) return false;
            var pins = NormalizeRungs(allowedTransports, out var ok);
            if (!ok) return false;
            var device = _enrollments.List().FirstOrDefault(
                d => string.Equals(d.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase));
            if (device is null || device.Revoked) return false;
            // Pins are meaningful only in manual mode — resolution
            // ignores them otherwise. Storing them under inherit/auto
            // left state on the record that contradicted the mode
            // (D38 S2-WIN F12): refuse the combination instead.
            if (pins.Count > 0 && mode != "manual") return false;
            if (pins.Count > 0)
            {
                var group = FindDeviceGroup(device.GroupId);
                if (group is null) return false; // no group set to pin within: fail closed
                var resolved = EffectiveTransports(
                    device with { TransportMode = "inherit", AllowedTransports = new HashSet<string>() },
                    group, GetScopeTransportCeiling(group.ScopeId));
                if (!pins.All(p => resolved.Contains(p, StringComparer.OrdinalIgnoreCase)))
                    return false; // pin outside the resolved set: REJECTED (D32)
            }
            return _enrollments.TryUpdateTransports(device.DeviceId, mode, pins);
        }
    }

    // ---- minted-enrollment attribution (D14) ---------------------------------------

    /// <summary>Record that a user minted an enrollment (the auth key
    /// they created). Offboarding revokes exactly these (D14).</summary>
    public bool RecordMintedEnrollment(string scopeId, string mintedByUserId, string deviceId)
    {
        if (string.IsNullOrWhiteSpace(deviceId)) return false;
        lock (_gate)
        {
            if (!_scopes.TryGetValue(scopeId ?? "", out var scope)) return false;
            if (!_users.TryGetValue(Key(scope.Id, mintedByUserId ?? ""), out var user)) return false;
            // Attribution is a revocation warrant at offboarding time:
            // when an enrollment store exists, the device must exist
            // AND its group must belong to THIS scope — otherwise a
            // company offboarding could revoke a personal-scope or
            // other-company device by recording it here (D38 S2-WIN F4).
            if (_enrollments is not null)
            {
                var device = _enrollments.List().FirstOrDefault(
                    d => string.Equals(d.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase));
                if (device is null) return false;
                var group = _deviceGroups.Values.FirstOrDefault(
                    g => string.Equals(g.Id, device.GroupId, StringComparison.OrdinalIgnoreCase));
                if (group is null || !string.Equals(group.ScopeId, scope.Id, StringComparison.OrdinalIgnoreCase))
                    return false;
            }
            var entry = new MintedEnrollment(scope.Id, user.Id, deviceId.Trim());
            if (_minted.Any(m => string.Equals(m.ScopeId, entry.ScopeId, StringComparison.OrdinalIgnoreCase) &&
                                 string.Equals(m.MintedByUserId, entry.MintedByUserId, StringComparison.OrdinalIgnoreCase) &&
                                 string.Equals(m.DeviceId, entry.DeviceId, StringComparison.OrdinalIgnoreCase)))
                return false;
            _minted.Add(entry);
            Changed?.Invoke();
            return true;
        }
    }

    public IReadOnlyList<MintedEnrollment> ListMintedEnrollments(string scopeId, string? mintedByUserId = null)
    {
        lock (_gate)
            return _minted
                .Where(m => string.Equals(m.ScopeId, scopeId, StringComparison.OrdinalIgnoreCase) &&
                            (mintedByUserId is null || string.Equals(m.MintedByUserId, mintedByUserId, StringComparison.OrdinalIgnoreCase)))
                .ToList();
    }

    // ---- offboarding (D14) ------------------------------------------------------------

    /// <summary>Compute the blast list for removing a user WITHOUT
    /// firing anything (D14): user-group seats (member + admin),
    /// the company-admin seat, the grants touching those groups, the
    /// enrollments the user minted, the AI pairings they own, and the
    /// live-session requirement, named. Null when the scope or the
    /// user-in-that-scope does not exist.</summary>
    public OffboardingBlast? PreviewRemoveUser(string scopeId, string userId)
    {
        lock (_gate)
        {
            if (!_scopes.TryGetValue(scopeId ?? "", out var scope)) return null;
            if (!_users.TryGetValue(Key(scope.Id, userId ?? ""), out var user)) return null;
            var seats = _userGroups.Values
                .Where(g => string.Equals(g.ScopeId, scope.Id, StringComparison.OrdinalIgnoreCase) &&
                            g.MemberUserIds.Contains(user.Id))
                .Select(g => g.Id).ToList();
            var adminSeats = _userGroups.Values
                .Where(g => string.Equals(g.ScopeId, scope.Id, StringComparison.OrdinalIgnoreCase) &&
                            g.AdminUserIds.Contains(user.Id))
                .Select(g => g.Id).ToList();
            var touchedGroupIds = new HashSet<string>(seats.Concat(adminSeats), StringComparer.OrdinalIgnoreCase);
            var grants = _grants
                .Where(g => string.Equals(g.ScopeId, scope.Id, StringComparison.OrdinalIgnoreCase) &&
                            touchedGroupIds.Contains(g.UserGroupId))
                .Select(Clone).ToList();
            var minted = _minted
                .Where(m => string.Equals(m.ScopeId, scope.Id, StringComparison.OrdinalIgnoreCase) &&
                            string.Equals(m.MintedByUserId, user.Id, StringComparison.OrdinalIgnoreCase))
                .Select(m => m.DeviceId).ToList();
            var ownedAi = _users.Values
                .Where(u => string.Equals(u.ScopeId, scope.Id, StringComparison.OrdinalIgnoreCase) &&
                            u.Kind == "ai" &&
                            string.Equals(u.PairedByUserId, user.Id, StringComparison.OrdinalIgnoreCase))
                .Select(u => u.Id).ToList();
            var adminSeat = _companyAdmins.TryGetValue(scope.Id, out var set) && set.Contains(user.Id);
            return new OffboardingBlast(scope.Id, user.Id, seats, adminSeats, adminSeat, grants,
                minted, ownedAi, RequiresLiveSessionTermination: true, LiveSessionRequirementText);
        }
    }

    /// <summary>Remove a user from a company scope in one action
    /// (D14). Returns the blast list it fired, or null on refusal.
    /// Guards: a personal scope is untouchable (null — the wall cuts
    /// both ways); the user must belong to THIS scope (a user id from
    /// another scope is a cross-scope removal, refused); the actor
    /// must be a company admin of this scope (D13); the last company
    /// admin cannot be removed (D26); removing a fellow company admin
    /// requires stepUp = true (D26).
    /// On fire: user-group seats (member + admin) removed, company-
    /// admin seat removed, enrollments the user minted REVOKED in the
    /// Slice 1 roster, AI pairings they own SUSPENDED (not deleted —
    /// pending a new owner, D14/D9), the user record removed, and an
    /// offboarding event recorded for the session layer.</summary>
    public OffboardingBlast? RemoveUser(string scopeId, string userId, string actorUserId, bool stepUp = false)
    {
        lock (_gate)
        {
            if (!_scopes.TryGetValue(scopeId ?? "", out var scope)) return null;
            if (scope.Kind != "company") return null; // personal scope untouchable (D14 wall)
            if (!_users.TryGetValue(Key(scope.Id, userId ?? ""), out var user)) return null; // cross-scope: refused
            if (!IsLiveCompanyAdminLocked(scope.Id, actorUserId)) return null; // actor must be a LIVE company admin (D13)
            var blast = PreviewRemoveUser(scope.Id, user.Id);
            if (blast is null) return null;
            if (blast.CompanyAdminSeat)
            {
                if (CompanyAdmins(scope.Id).Count <= 1) return null; // last-admin guard (D26)
                // Live-admin form of the same guard (D38 S2-WIN F5): a
                // suspended peer's seat must not make the sole LIVE
                // admin look removable.
                if (IsLiveCompanyAdminLocked(scope.Id, user.Id) &&
                    CompanyAdmins(scope.Id).Count(id => IsLiveCompanyAdminLocked(scope.Id, id)) <= 1)
                    return null;
                var fellow = !string.Equals(actorUserId, user.Id, StringComparison.OrdinalIgnoreCase);
                if (fellow && !stepUp) return null; // step-up required (D26)
            }

            // Fire.
            foreach (var groupId in blast.UserGroupSeatIds.Concat(blast.UserGroupAdminSeatIds).Distinct(StringComparer.OrdinalIgnoreCase))
            {
                if (!_userGroups.TryGetValue(Key(scope.Id, groupId), out var group)) continue;
                var members = new HashSet<string>(group.MemberUserIds, StringComparer.OrdinalIgnoreCase);
                var admins = new HashSet<string>(group.AdminUserIds, StringComparer.OrdinalIgnoreCase);
                members.Remove(user.Id);
                admins.Remove(user.Id);
                _userGroups[Key(scope.Id, group.Id)] = group with { MemberUserIds = members, AdminUserIds = admins };
            }
            if (blast.CompanyAdminSeat && _companyAdmins.TryGetValue(scope.Id, out var adminSet))
                adminSet.Remove(user.Id);
            // Minted enrollments revoked (D14) — but ONLY devices whose
            // group provably belongs to THIS scope, re-checked at fire
            // time: a forged/imported attribution naming a personal or
            // other-company device must not let this offboarding touch
            // it (D38 S2-WIN F4). Entries whose revocation did not
            // actually happen (no enrollment store, unknown device,
            // unprovable scope) are KEPT as evidence instead of being
            // deleted as if fired (D38 S2-WIN F10).
            var revokedMinted = new List<string>();
            if (_enrollments is not null)
            {
                foreach (var deviceId in blast.MintedEnrollmentDeviceIds)
                {
                    var device = _enrollments.List().FirstOrDefault(
                        d => string.Equals(d.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase));
                    if (device is null) continue;
                    var group = _deviceGroups.Values.FirstOrDefault(
                        g => string.Equals(g.Id, device.GroupId, StringComparison.OrdinalIgnoreCase));
                    if (group is null || !string.Equals(group.ScopeId, scope.Id, StringComparison.OrdinalIgnoreCase))
                        continue;
                    if (device.Revoked || _enrollments.Revoke(device.DeviceId))
                        revokedMinted.Add(device.DeviceId);
                }
                _enrollments.RevokePendingCodesMintedBy(user.Id); // still-pending codes they minted die too (D14)
                _minted.RemoveAll(m => string.Equals(m.ScopeId, scope.Id, StringComparison.OrdinalIgnoreCase) &&
                                       string.Equals(m.MintedByUserId, user.Id, StringComparison.OrdinalIgnoreCase) &&
                                       revokedMinted.Contains(m.DeviceId, StringComparer.OrdinalIgnoreCase));
            }
            foreach (var aiId in blast.OwnedAiUserIds)
            {
                if (_users.TryGetValue(Key(scope.Id, aiId), out var ai))
                    _users[Key(scope.Id, aiId)] = ai with { Suspended = true }; // suspended, not deleted (D14)
            }
            _users.Remove(Key(scope.Id, user.Id));
            RecordEvent("user_removed", scope.Id, actorUserId, user.Id,
                $"Offboarded: {blast.UserGroupSeatIds.Count} group seat(s), company admin seat: {blast.CompanyAdminSeat}, " +
                $"{revokedMinted.Count} minted enrollment(s) revoked, {blast.OwnedAiUserIds.Count} owned AI pairing(s) suspended. " +
                LiveSessionRequirementText);
            Changed?.Invoke();
            return blast;
        }
    }

    // ---- read shapes (D2) -----------------------------------------------------------------

    /// <summary>The full roster of ONE scope (operator side only, D2),
    /// scope-filtered throughout (D8): a company roster contains no
    /// personal record and vice versa. Devices are the Slice 1
    /// enrollments filed into this scope's device groups.</summary>
    public OperatorRoster? OperatorRoster(string scopeId)
    {
        lock (_gate)
        {
            if (!_scopes.TryGetValue(scopeId ?? "", out var scope)) return null;
            var deviceGroups = ListDeviceGroups(scope.Id);
            var groupIds = new HashSet<string>(deviceGroups.Select(g => g.Id), StringComparer.OrdinalIgnoreCase);
            var devices = _enrollments is null
                ? new List<EnrolledDevice>()
                : _enrollments.List().Where(d => groupIds.Contains(d.GroupId)).ToList();
            return new OperatorRoster(
                Clone(scope),
                ListUsers(scope.Id),
                CompanyAdmins(scope.Id).ToList(),
                ListUserGroups(scope.Id),
                deviceGroups,
                ListGrants(scope.Id),
                devices,
                ListEvents(scope.Id));
        }
    }

    /// <summary>The endpoint view (D2): ONLY this device's own
    /// enrolled record, its own Slice 1 receipts, and the
    /// allowed-operators list derived from those receipts. There is no
    /// code path here to another device's record — the roster is
    /// absent from this shape, not hidden. Null for unknown devices.</summary>
    public EndpointView? EndpointView(string deviceId)
    {
        if (_enrollments is null || string.IsNullOrWhiteSpace(deviceId)) return null;
        var device = _enrollments.List().FirstOrDefault(
            d => string.Equals(d.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase));
        if (device is null) return null;
        if (device.Revoked) return null; // revocation takes effect immediately (Slice 1) — no view for a revoked device (D38 S2-WIN F6)
        var receipts = _enrollments.ListReceipts();
        var operators = receipts
            .GroupBy(r => r.EnrollerDeviceId, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .Select(r => new AllowedOperator(r.EnrollerName, r.EnrollerDeviceId, r.Scope, r.GroupName, r.EnrolledUtc))
            .ToList();
        return new EndpointView(device, receipts, operators);
    }

    // ---- helpers ---------------------------------------------------------------------------

    private static string? NormalizeKind(string? kind, IReadOnlySet<string> valid)
    {
        if (string.IsNullOrWhiteSpace(kind)) return null;
        var k = kind.Trim().ToLowerInvariant();
        return valid.Contains(k) ? k : null;
    }

    /// <summary>Normalize a rung list: trim/lowercase, dedupe
    /// preserving first-seen order. ok=false when any entry is not one
    /// of the six rungs (D32) — callers refuse rather than guess.</summary>
    private static List<string> NormalizeRungs(IEnumerable<string>? rungs, out bool ok)
    {
        ok = true;
        var result = new List<string>();
        foreach (var rung in rungs ?? Array.Empty<string>())
        {
            var r = (rung ?? "").Trim().ToLowerInvariant();
            if (!RungSet.Contains(r)) { ok = false; return new List<string>(); }
            if (!result.Contains(r)) result.Add(r);
        }
        return result;
    }

    private static Scope Clone(Scope s) => s with { TransportCeiling = s.TransportCeiling.ToList() };
    private static UserGroup Clone(UserGroup g) => g with
    {
        MemberUserIds = new HashSet<string>(g.MemberUserIds, StringComparer.OrdinalIgnoreCase),
        AdminUserIds = new HashSet<string>(g.AdminUserIds, StringComparer.OrdinalIgnoreCase),
    };
    private static DeviceGroup Clone(DeviceGroup g) => g with { TransportSet = g.TransportSet.ToList() };
    private static Grant Clone(Grant g) => g with { Rights = new HashSet<string>(g.Rights, StringComparer.OrdinalIgnoreCase) };

    // ---- persistence -------------------------------------------------------------------------

    private sealed record ScopeDto(string Id, string Kind, string Name, string[]? TransportCeiling);
    private sealed record UserDto(string Id, string ScopeId, string DisplayName, string Kind, string? PairedByUserId, bool Suspended);
    private sealed record AdminDto(string ScopeId, string UserId);
    private sealed record UserGroupDto(string Id, string ScopeId, string Name, string[]? MemberUserIds, string[]? AdminUserIds);
    private sealed record DeviceGroupDto(string Id, string ScopeId, string Name, string[]? TransportSet);
    private sealed record GrantDto(string ScopeId, string UserGroupId, string DeviceGroupId, string[]? Rights);
    private sealed record StoreDto(
        ScopeDto[] Scopes, UserDto[] Users, AdminDto[] CompanyAdmins,
        UserGroupDto[] UserGroups, DeviceGroupDto[] DeviceGroups, GrantDto[] Grants,
        MintedEnrollment[] Minted, RosterEvent[] Events,
        string[]? DeletedDeviceGroupIds = null);

    /// <summary>Serialize the whole roster store. No secret of any
    /// kind exists in this store — users are directory records, admins
    /// are id sets, devices are referenced by id only (their records
    /// live in the Slice 1 store).</summary>
    public string ExportJson()
    {
        lock (_gate)
        {
            var store = new StoreDto(
                _scopes.Values.Select(s => new ScopeDto(s.Id, s.Kind, s.Name,
                    s.HasCeiling ? s.TransportCeiling.ToArray() : null)).ToArray(),
                _users.Values.Select(u => new UserDto(u.Id, u.ScopeId, u.DisplayName, u.Kind, u.PairedByUserId, u.Suspended)).ToArray(),
                _companyAdmins.SelectMany(kv => kv.Value.Select(id => new AdminDto(kv.Key, id))).ToArray(),
                _userGroups.Values.Select(g => new UserGroupDto(g.Id, g.ScopeId, g.Name,
                    g.MemberUserIds.ToArray(), g.AdminUserIds.ToArray())).ToArray(),
                _deviceGroups.Values.Select(g => new DeviceGroupDto(g.Id, g.ScopeId, g.Name, g.TransportSet.ToArray())).ToArray(),
                _grants.Select(g => new GrantDto(g.ScopeId, g.UserGroupId, g.DeviceGroupId, g.Rights.ToArray())).ToArray(),
                _minted.ToArray(),
                _events.ToArray(),
                _deletedDeviceGroupIds.ToArray());
            return JsonSerializer.Serialize(store);
        }
    }

    /// <summary>Restore a store previously produced by ExportJson.
    /// Malformed entries are skipped, never fatal — unknown kinds,
    /// cross-scope references, AI admin seats (D9), and non-rung
    /// transports are all dropped at the entry that carries them, and
    /// malformed JSON as a whole restores nothing rather than
    /// throwing. Returns the number of entries restored.</summary>
    public int ImportJson(string json)
    {
        StoreDto? store;
        try { store = JsonSerializer.Deserialize<StoreDto>(json); }
        catch { return 0; }
        if (store is null) return 0;
        var restored = 0;
        lock (_gate)
        {
            foreach (var dto in store.Scopes ?? Array.Empty<ScopeDto>())
            {
                if (dto is null || string.IsNullOrWhiteSpace(dto.Id)) continue;
                var kind = NormalizeKind(dto.Kind, ValidScopeKinds);
                if (kind is null || _scopes.ContainsKey(dto.Id)) continue;
                var ceiling = NormalizeRungs(dto.TransportCeiling, out var ok);
                if (!ok) continue;
                _scopes[dto.Id] = new Scope(dto.Id, kind, dto.Name ?? "",
                    kind == "personal" ? Array.Empty<string>() : ceiling);
                restored++;
            }
            // Two passes — humans first, then AIs (D38 S2-WIN F9): an AI
            // is only importable once its owner exists, and export order
            // is dictionary order, which stops matching insertion order
            // after any removal. A single pass silently dropped AIs
            // written before their owners.
            var userDtos = store.Users ?? Array.Empty<UserDto>();
            var orderedUserDtos = userDtos.Where(d => NormalizeKind(d?.Kind, ValidUserKinds) != "ai")
                .Concat(userDtos.Where(d => NormalizeKind(d?.Kind, ValidUserKinds) == "ai"));
            foreach (var dto in orderedUserDtos)
            {
                if (dto is null || string.IsNullOrWhiteSpace(dto.Id) || string.IsNullOrWhiteSpace(dto.ScopeId)) continue;
                var kind = NormalizeKind(dto.Kind, ValidUserKinds);
                if (kind is null) continue;
                if (!_scopes.TryGetValue(dto.ScopeId, out var scope)) continue;
                if (_users.ContainsKey(Key(scope.Id, dto.Id))) continue;
                if (scope.Kind == "personal" && kind == "human" &&
                    _users.Values.Any(u => string.Equals(u.ScopeId, scope.Id, StringComparison.OrdinalIgnoreCase) &&
                                           u.Kind == "human"))
                    continue; // personal scope holds ONE human (F7), import included
                string? owner = null;
                if (kind == "ai")
                {
                    if (string.IsNullOrWhiteSpace(dto.PairedByUserId)) continue;
                    if (!_users.TryGetValue(Key(scope.Id, dto.PairedByUserId), out var ownerUser) || ownerUser.Kind != "human") continue;
                    owner = ownerUser.Id;
                }
                else if (!string.IsNullOrWhiteSpace(dto.PairedByUserId)) continue;
                _users[Key(scope.Id, dto.Id)] = new User(dto.Id, scope.Id, dto.DisplayName ?? "", kind, owner, dto.Suspended);
                restored++;
            }
            foreach (var dto in store.CompanyAdmins ?? Array.Empty<AdminDto>())
            {
                if (dto is null) continue;
                if (!_scopes.TryGetValue(dto.ScopeId ?? "", out var scope) || scope.Kind != "company") continue;
                if (!_users.TryGetValue(Key(scope.Id, dto.UserId ?? ""), out var user)) continue;
                if (user.Kind != "human") continue; // D9 holds on import too
                if (user.Suspended) continue; // AddCompanyAdmin refuses the suspended; import is no side door
                if (!_companyAdmins.TryGetValue(scope.Id, out var set))
                    _companyAdmins[scope.Id] = set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                if (set.Add(user.Id)) restored++;
            }
            foreach (var dto in store.UserGroups ?? Array.Empty<UserGroupDto>())
            {
                if (dto is null || string.IsNullOrWhiteSpace(dto.Id)) continue;
                if (!_scopes.TryGetValue(dto.ScopeId ?? "", out var scope)) continue;
                if (_userGroups.ContainsKey(Key(scope.Id, dto.Id))) continue;
                var members = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var id in dto.MemberUserIds ?? Array.Empty<string>())
                    if (_users.TryGetValue(Key(scope.Id, id ?? ""), out var member)) members.Add(member.Id);
                var admins = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var id in dto.AdminUserIds ?? Array.Empty<string>())
                    if (_users.TryGetValue(Key(scope.Id, id ?? ""), out var admin) && admin.Kind == "human")
                    { admins.Add(admin.Id); members.Add(admin.Id); } // AI admins dropped (D9)
                _userGroups[Key(scope.Id, dto.Id)] = new UserGroup(dto.Id, scope.Id, dto.Name ?? "", members, admins);
                restored++;
            }
            foreach (var tombstone in store.DeletedDeviceGroupIds ?? Array.Empty<string>())
                if (!string.IsNullOrWhiteSpace(tombstone)) _deletedDeviceGroupIds.Add(tombstone);
            foreach (var dto in store.DeviceGroups ?? Array.Empty<DeviceGroupDto>())
            {
                if (dto is null || string.IsNullOrWhiteSpace(dto.Id)) continue;
                if (_deletedDeviceGroupIds.Contains(dto.Id)) continue; // tombstoned ids never resurrect (F2)
                if (!_scopes.TryGetValue(dto.ScopeId ?? "", out var scope)) continue;
                if (_deviceGroups.Values.Any(g => string.Equals(g.Id, dto.Id, StringComparison.OrdinalIgnoreCase))) continue;
                var set = NormalizeRungs(dto.TransportSet, out var ok);
                if (!ok) continue;
                _deviceGroups[Key(scope.Id, dto.Id)] = new DeviceGroup(dto.Id, scope.Id, dto.Name ?? "", set);
                restored++;
            }
            foreach (var dto in store.Grants ?? Array.Empty<GrantDto>())
            {
                if (dto is null || dto.UserGroupId is null || dto.DeviceGroupId is null) continue;
                if (!_scopes.TryGetValue(dto.ScopeId ?? "", out var scope)) continue;
                if (!_userGroups.ContainsKey(Key(scope.Id, dto.UserGroupId))) continue;
                if (!_deviceGroups.ContainsKey(Key(scope.Id, dto.DeviceGroupId))) continue;
                var rights = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var right in dto.Rights ?? Array.Empty<string>())
                {
                    var r = (right ?? "").Trim().ToLowerInvariant();
                    if (ValidRights.Contains(r)) rights.Add(r);
                }
                if (rights.Count == 0) continue;
                if (_grants.Any(g => string.Equals(g.ScopeId, scope.Id, StringComparison.OrdinalIgnoreCase) &&
                                     string.Equals(g.UserGroupId, dto.UserGroupId, StringComparison.OrdinalIgnoreCase) &&
                                     string.Equals(g.DeviceGroupId, dto.DeviceGroupId, StringComparison.OrdinalIgnoreCase) &&
                                     g.Rights.SetEquals(rights)))
                    continue; // re-import must not multiply grants
                _grants.Add(new Grant(scope.Id, dto.UserGroupId, dto.DeviceGroupId, rights));
                restored++;
            }
            foreach (var entry in store.Minted ?? Array.Empty<MintedEnrollment>())
            {
                if (entry is null || string.IsNullOrWhiteSpace(entry.DeviceId)) continue;
                if (!_scopes.TryGetValue(entry.ScopeId ?? "", out var mintedScope)) continue;
                // Attribution must name a real user OF THAT SCOPE: a
                // ghost-minter entry is a forged revocation warrant
                // waiting for an offboarding (D38 S2-WIN F9).
                if (!_users.TryGetValue(Key(mintedScope.Id, entry.MintedByUserId ?? ""), out var mintedBy)) continue;
                if (_minted.Any(m => string.Equals(m.ScopeId, mintedScope.Id, StringComparison.OrdinalIgnoreCase) &&
                                     string.Equals(m.MintedByUserId, mintedBy.Id, StringComparison.OrdinalIgnoreCase) &&
                                     string.Equals(m.DeviceId, entry.DeviceId, StringComparison.OrdinalIgnoreCase)))
                    continue; // re-import must not duplicate attribution
                _minted.Add(new MintedEnrollment(mintedScope.Id, mintedBy.Id, entry.DeviceId));
                restored++;
            }
            foreach (var entry in store.Events ?? Array.Empty<RosterEvent>())
            {
                if (entry is null || string.IsNullOrWhiteSpace(entry.Kind)) continue;
                _events.Add(entry);
                restored++;
            }
        }
        return restored;
    }
}
