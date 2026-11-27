using System.Security.Cryptography;
using System.Text;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.Enrollment;
using DeskGuest.Shared.Hub;
using DeskGuest.Shared.Inventory;
using DeskGuest.Shared.Roster;

namespace DeskGuest.Shared.DirectoryEnrollment;

// =====================================================================
// RMM-24 (item 1) — Directory-driven enrollment push.
//
// The ORG'S directory (AD/Entra-style) is the source of WHO gets
// enrolled: a directory GROUP maps to an DeskGuest device group + user
// group in one scope, and membership in the directory group is a
// scoped enrollment right (BRAINSTORM-REMOTE roster decisions:
// COMPANY groups are admin-curated; membership = scoped enrollment
// right). This lane COMPOSES the existing machinery — it replaces
// none of it:
//   * enrollment itself is Slice 1's EnrollmentService: the push
//     mints a normal one-time code bound to the mapped device group
//     at mint time, and redemption is the endpoint's own act.
//   * offboarding is D14's RosterService.RemoveUser path: when a
//     user leaves the directory group this lane FLAGS + INITIATES
//     through IOffboardingInitiator; it does not execute a second
//     offboarding and it does not revoke enrollments itself beyond
//     killing the departed user's still-pending push codes (the
//     codes this lane minted — leaving them live would leave the
//     departed user a working enrollment key).
//   * directory-listed machines that have never enrolled land in
//     the KNOWN-UNMANAGED list: a directory fact, distinct from a
//     rogue (a machine discovery finds that no directory names —
//     RMM-11's category, never this lane's).
//
// ENDPOINT ACCEPTANCE IS THE WALL (settled rule): a directory push
// can OFFER and PRE-STAGE — it mints the code and records the
// offer — but it can never silently enroll an endpoint. Enrollment
// happens only when the endpoint itself presents the code and
// proves possession of its device key through EnrollmentService
// .Redeem (which validates the DeviceId fingerprint). A poisoned
// directory entry therefore enrolls NOTHING by itself: it can at
// most cause an offer to a roster user, and the offer still dies
// without the endpoint's own acceptance.
//
// EVERY push/flag/mapping act is written to the shared hash-chained
// ledger (ChainedAuditLog). Offer codes are held in memory only,
// hash-compared, and NEVER exported: the export form carries the
// code's SHA-256 hash so an export can never be replayed as a code.
// =====================================================================

/// <summary>TOTAL POLICY CONTROL keys for RMM-24.</summary>
public static class DirectoryEnrollmentPolicyKeys
{
    /// <summary>The directory-enrollment toggle (seeded ON in the
    /// Core wiring; the RMM-07 registry's RMM-24 line is the seeded
    /// alias <see cref="MobileOperatorPolicyKeys.Enabled"/>).</summary>
    public const string DirectoryEnabled = "rmm.directory_enrollment.enabled";
}

public static class DirectoryEnrollmentLimits
{
    public static readonly TimeSpan OfferTtl = TimeSpan.FromDays(7);
    public const int MaxMappings = 256;
    public const int MaxIdLength = 128;
    /// <summary>Terminal-state offers are pruned this long after
    /// their decision (D38 rmm24 F12c — stores must not grow
    /// without bound); flags are pruned after FlagRetention (the
    /// departed SET, which carries the flag's effect, is retained
    /// and exported separately).</summary>
    public static readonly TimeSpan OfferRetention = TimeSpan.FromDays(30);
    public static readonly TimeSpan FlagRetention = TimeSpan.FromDays(90);
}

// ---- directory connector -------------------------------------------------

public sealed record DirectoryUser(string Id, string DisplayName, string? Email);
public sealed record DirectoryGroup(string Id, string Name, IReadOnlyList<string> MemberUserIds);
public sealed record DirectoryMachine(string MachineId, string Hostname, string? OwnerUserId, string? DirectoryGroupId);

/// <summary>One directory read. Users/Groups/Machines are the
/// directory's own facts; the engine trusts NONE of them past the
/// walls documented on the engine (roster existence, endpoint
/// acceptance, admin-gated mappings).</summary>
public sealed record DirectorySnapshot(
    IReadOnlyList<DirectoryUser> Users,
    IReadOnlyList<DirectoryGroup> Groups,
    IReadOnlyList<DirectoryMachine> Machines,
    DateTimeOffset ReadUtc);

/// <summary>The directory connector contract. The real AD/Entra
/// connector is HOST WIRING against the org's IdP/directory (it
/// runs where the org's directory credentials live, under the
/// org's own sign-in — D4); this model ships the interface plus an
/// honest in-memory fake for tests and demos. A connector NEVER
/// writes to DeskGuest stores: it only reads the directory.</summary>
public interface IDirectoryConnector
{
    string Name { get; }
    /// <summary>True for the in-memory fake — surfaced honestly in
    /// every surface that names the connector in use.</summary>
    bool IsFake { get; }
    DirectorySnapshot ReadSnapshot(DateTimeOffset now);
}

/// <summary>Honest fake directory: mutable in-memory users/groups/
/// machines, labelled fake wherever it is named. Tests drive group
/// departures by editing it between syncs.</summary>
public sealed class FakeDirectoryConnector : IDirectoryConnector
{
    public string Name => "fake-directory (in-memory test double — NOT a real AD/Entra connector)";
    public bool IsFake => true;
    public List<DirectoryUser> Users { get; } = new();
    public List<DirectoryGroup> Groups { get; } = new();
    public List<DirectoryMachine> Machines { get; } = new();

    public DirectorySnapshot ReadSnapshot(DateTimeOffset now) => new(
        Users.ToList(),
        Groups.Select(g => g with { MemberUserIds = g.MemberUserIds.ToList() }).ToList(),
        Machines.ToList(), now);

    public void RemoveMember(string groupId, string userId)
    {
        var i = Groups.FindIndex(g => string.Equals(g.Id, groupId, StringComparison.OrdinalIgnoreCase));
        if (i < 0) return;
        Groups[i] = Groups[i] with
        {
            MemberUserIds = Groups[i].MemberUserIds
                .Where(u => !string.Equals(u, userId, StringComparison.OrdinalIgnoreCase)).ToList(),
        };
    }
}

// ---- mapping ---------------------------------------------------------------

/// <summary>One directory-group → DeskGuest mapping. A mapping is an
/// admin-curated structural act: it names ONE scope, ONE directory
/// group, ONE DeskGuest device group (the enrollment target bound at
/// mint) and ONE DeskGuest user group (the roster home of the mapped
/// users). Revision is monotonic per mapping id.</summary>
public sealed record DirectoryGroupMapping(
    string Id,
    string ScopeId,
    string DirectoryGroupId,
    string DeviceGroupId,
    string UserGroupId,
    bool EnrollmentEnabled,
    long Revision);

// ---- offers ------------------------------------------------------------------

public static class OfferStates
{
    public const string Offered = "offered";           // pre-staged; awaiting the endpoint's own acceptance
    public const string Accepted = "accepted";         // the endpoint redeemed the code itself
    public const string Declined = "declined";         // the endpoint/user declined
    public const string Expired = "expired";
    public const string Cancelled = "cancelled";       // mapping/policy/sync cancelled it
    public const string OffboardingFlagged = "offboarding_flagged"; // user left the directory group
}

/// <summary>One enrollment offer (the push). The display code is
/// held by the engine in memory only; this record carries its
/// SHA-256 hash so exports and read surfaces can name the offer
/// without ever carrying a redeemable code.</summary>
public sealed record EnrollmentOffer(
    string Id,
    string MappingId,
    string ScopeId,
    string UserId,
    string DirectoryGroupId,
    string DeviceGroupId,
    string CodeHash,
    string State,
    DateTimeOffset CreatedUtc,
    DateTimeOffset ExpiresUtc,
    string? AcceptedDeviceId,
    DateTimeOffset? DecidedUtc);

/// <summary>A directory-listed machine that has never enrolled:
/// KNOWN-UNMANAGED. Distinct from a rogue — a rogue is a machine
/// NO directory names (RMM-11 discovery's category). This record
/// exists so "we know this machine, it simply has no agent yet"
/// is a first-class fleet fact, and it can never become a managed
/// device by editing it (managed status comes only from
/// enrollment — the UnmanagedAssetRegister invariant, mirrored).</summary>
public sealed record KnownUnmanagedDevice(
    string MachineId,
    string Hostname,
    string ScopeId,
    string? DirectoryGroupId,
    string? OwnerUserId,
    DateTimeOffset FirstSeenUtc,
    DateTimeOffset LastSeenUtc)
{
    public bool ManagedByAgent => false;
    public const string Classification = "known_unmanaged";
}

/// <summary>An offboarding flag raised by this lane: the user left
/// a mapped directory group. The flag NAMES the enrollments the
/// user accepted through the push and the offers still pending;
/// executing the removal is D14's path, reached through
/// <see cref="IOffboardingInitiator"/>.</summary>
public sealed record OffboardingFlag(
    string Id,
    string ScopeId,
    string UserId,
    string MappingId,
    string DirectoryGroupId,
    IReadOnlyList<string> AcceptedDeviceIds,
    DateTimeOffset FlaggedUtc,
    string Reason,
    bool Initiated);

/// <summary>The seam to the COMPLETE OFFBOARDING model (D14). The
/// production implementation calls RosterService.RemoveUser (via
/// the enterprise DirectorySyncService discipline); this lane only
/// flags + initiates. Returns true when the offboarding path
/// accepted initiation.</summary>
public interface IOffboardingInitiator
{
    bool Initiate(OffboardingFlag flag, DateTimeOffset now);
}

/// <summary>The push delivery channel: how a pre-staged offer's
/// code reaches the mapped user's endpoint (in production this is
/// the directory-push mechanism itself — GPO/MDM-class delivery to
/// the user's devices, host wiring). The code exists ONLY here and
/// in the engine's memory: never in the offer record, the audit, or
/// any export. A null delivery channel means offers are pre-staged
/// but undeliverable — sync names that in its outcome path via the
/// audit (delivery is the push's whole point, so the host must
/// supply one).</summary>
public interface IOfferDelivery
{
    void Deliver(EnrollmentOffer offer, string displayCode, DateTimeOffset now);
}

/// <summary>Recording double for IOfferDelivery (tests capture the
/// delivered code exactly as an endpoint would receive it).</summary>
public sealed class RecordingOfferDelivery : IOfferDelivery
{
    public List<(string OfferId, string UserId, string Code)> Delivered { get; } = new();
    public void Deliver(EnrollmentOffer offer, string displayCode, DateTimeOffset now) =>
        Delivered.Add((offer.Id, offer.UserId, displayCode));
    public string? CodeFor(string offerId) =>
        Delivered.LastOrDefault(d => d.OfferId == offerId).Code;
}

/// <summary>Recording double for IOffboardingInitiator.</summary>
public sealed class RecordingOffboardingInitiator : IOffboardingInitiator
{
    public List<OffboardingFlag> Initiated { get; } = new();
    public bool Accept { get; set; } = true;
    public bool Initiate(OffboardingFlag flag, DateTimeOffset now)
    {
        if (Accept) Initiated.Add(flag);
        return Accept;
    }
}

/// <summary>Outcome of one sync pass, named counts only.</summary>
public sealed record DirectorySyncOutcome(
    int OffersCreated, int OffersRefreshed, int UnmanagedSeen,
    int DeparturesFlagged, int PoisonSuspects, string Reason);

// ---- the engine ---------------------------------------------------------------

public sealed class DirectoryEnrollmentEngine
{
    private readonly EnrollmentService _enrollments;
    private readonly RosterService _roster;
    private readonly ChainedAuditLog _audit;
    private readonly IDirectoryConnector _connector;
    private readonly IOffboardingInitiator _offboarding;
    private readonly Func<string, bool> _policyEnabledForScope;
    private readonly UnmanagedAssetRegister? _unmanagedRegister;
    private readonly IOfferDelivery? _delivery;

    private readonly Dictionary<string, DirectoryGroupMapping> _mappings = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, EnrollmentOffer> _offers = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> _offerCodes = new(StringComparer.Ordinal); // offerId -> display code, MEMORY ONLY
    private readonly Dictionary<string, KnownUnmanagedDevice> _knownUnmanaged = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<OffboardingFlag> _flags = new();
    private readonly HashSet<string> _departedUsers = new(StringComparer.OrdinalIgnoreCase); // scopeId|userId
    private readonly Dictionary<string, HashSet<string>> _lastMembersByMapping = new(StringComparer.OrdinalIgnoreCase); // scopeId|mappingId -> members
    private readonly HashSet<string> _mirroredAssetIds = new(StringComparer.OrdinalIgnoreCase); // asset ids this engine mirrored into the unmanaged register
    private readonly object _gate = new();

    public DirectoryEnrollmentEngine(
        EnrollmentService enrollments, RosterService roster, ChainedAuditLog audit,
        IDirectoryConnector connector, IOffboardingInitiator offboarding,
        Func<string, bool>? policyEnabledForScope = null, UnmanagedAssetRegister? unmanagedRegister = null,
        IOfferDelivery? delivery = null)
    {
        _enrollments = enrollments ?? throw new ArgumentNullException(nameof(enrollments));
        _roster = roster ?? throw new ArgumentNullException(nameof(roster));
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _connector = connector ?? throw new ArgumentNullException(nameof(connector));
        _offboarding = offboarding ?? throw new ArgumentNullException(nameof(offboarding));
        _policyEnabledForScope = policyEnabledForScope ?? (_ => true);
        _unmanagedRegister = unmanagedRegister;
        _delivery = delivery;
    }

    public IDirectoryConnector Connector => _connector;

    private static string DepartedKey(string scopeId, string userId) => $"{scopeId}|{userId}";
    private static string BaselineKey(DirectoryGroupMapping mapping) => $"{mapping.ScopeId}|{mapping.Id}";

    /// <summary>The Slice 1 minter attribution for codes THIS
    /// ENGINE mints: the engine is the minter, acting for the named
    /// user (D38 rmm24 F12a — attributing the mint to the end user
    /// misled D14 attribution, and the unscoped
    /// RevokePendingCodesMintedBy(userId) kill reached codes the
    /// user minted themselves in every scope). Departure kills use
    /// exactly this namespaced value, so they kill exactly the
    /// engine's codes for that user — nothing else.</summary>
    private static string EngineMintedBy(string userId) => $"directory-sync:{userId}";

    /// <summary>True while the user holds live push-derived rights:
    /// a departed (flagged) user holds NONE — this is the check
    /// acceptance consults before any code is redeemed.</summary>
    public bool HasLivePushRights(string scopeId, string userId)
    {
        lock (_gate) return !_departedUsers.Contains(DepartedKey(scopeId ?? "", userId ?? ""));
    }

    public IReadOnlyList<DirectoryGroupMapping> Mappings
    {
        get { lock (_gate) return _mappings.Values.OrderBy(m => m.Id, StringComparer.Ordinal).ToList(); }
    }

    public IReadOnlyList<EnrollmentOffer> Offers
    {
        get { lock (_gate) return _offers.Values.OrderBy(o => o.CreatedUtc).ThenBy(o => o.Id, StringComparer.Ordinal).ToList(); }
    }

    public IReadOnlyList<KnownUnmanagedDevice> KnownUnmanaged
    {
        get { lock (_gate) return _knownUnmanaged.Values.OrderBy(k => k.MachineId, StringComparer.Ordinal).ToList(); }
    }

    public IReadOnlyList<OffboardingFlag> Flags
    {
        get { lock (_gate) return _flags.ToList(); }
    }

    // -- mappings (admin-gated; widening needs step-up) --

    /// <summary>Admit or replace a mapping. The actor must hold an
    /// admin right in the scope (RosterService.HasAdminRight /
    /// company admin). WIDENING — a new mapping, enabling enrollment
    /// on a disabled mapping, or retargeting a mapping to a
    /// different device/user group — additionally requires
    /// stepUp = true: a mapping edit can never silently widen who
    /// gets enrollment rights. Stale revisions refuse. The mapping's
    /// scope, device group and user group must all exist in the
    /// roster and belong together (D8 wall). Every outcome audits.</summary>
    public (bool Ok, string Reason) SetMapping(DirectoryGroupMapping mapping, string actorUserId, bool stepUp, DateTimeOffset now)
    {
        (bool, string) Refuse(string reason)
        {
            _audit.Append("directory_mapping_refused", actorUserId ?? "(unknown)",
                $"mapping={mapping?.Id} reason={reason}", now);
            return (false, reason);
        }
        if (mapping is null) return Refuse("no mapping — refused");
        if (string.IsNullOrWhiteSpace(mapping.Id) || string.IsNullOrWhiteSpace(mapping.ScopeId) ||
            string.IsNullOrWhiteSpace(mapping.DirectoryGroupId) || string.IsNullOrWhiteSpace(mapping.DeviceGroupId) ||
            string.IsNullOrWhiteSpace(mapping.UserGroupId))
            return Refuse("a mapping needs an id, scope, directory group, device group and user group — refused");
        if (!_roster.HasAdminRight(mapping.ScopeId, actorUserId, userGroupId: mapping.UserGroupId, deviceGroupId: mapping.DeviceGroupId) &&
            !_roster.IsScopeAdmin(mapping.ScopeId, actorUserId))
            return Refuse($"actor '{actorUserId}' holds no admin right for this mapping — refused (directory mappings are admin-curated)");
        var deviceGroup = _roster.FindDeviceGroup(mapping.DeviceGroupId);
        if (deviceGroup is null || !string.Equals(deviceGroup.ScopeId, mapping.ScopeId, StringComparison.OrdinalIgnoreCase))
            return Refuse($"device group '{mapping.DeviceGroupId}' does not exist in scope '{mapping.ScopeId}' — refused (cross-scope mapping is the D8 wall)");
        if (_roster.GetUserGroup(mapping.ScopeId, mapping.UserGroupId) is null)
            return Refuse($"user group '{mapping.UserGroupId}' does not exist in scope '{mapping.ScopeId}' — refused");
        lock (_gate)
        {
            if (_mappings.TryGetValue(mapping.Id, out var existing))
            {
                if (mapping.Revision <= existing.Revision)
                    return Refuse($"mapping '{mapping.Id}' revision {mapping.Revision} is not after the admitted revision {existing.Revision} — refused (stale mapping edits never land)");
                // A mapping's SCOPE is part of its identity (D38
                // rmm24 F5): retargeting an admitted id into another
                // scope would replace that scope's mapping on the
                // incoming scope's admin right alone, and the old
                // scope's departure baseline would feed the new
                // mapping. Refused outright — a mapping in another
                // scope is a NEW mapping under a new id, admitted by
                // that scope's admin.
                if (!string.Equals(existing.ScopeId, mapping.ScopeId, StringComparison.OrdinalIgnoreCase))
                    return Refuse($"mapping '{mapping.Id}' already exists in scope '{existing.ScopeId}' — a mapping's scope cannot be retargeted to '{mapping.ScopeId}' (cross-scope takeover wall); create a new mapping id in the new scope");
                var widens =
                    (!existing.EnrollmentEnabled && mapping.EnrollmentEnabled) ||
                    !string.Equals(existing.DeviceGroupId, mapping.DeviceGroupId, StringComparison.OrdinalIgnoreCase) ||
                    !string.Equals(existing.UserGroupId, mapping.UserGroupId, StringComparison.OrdinalIgnoreCase) ||
                    !string.Equals(existing.DirectoryGroupId, mapping.DirectoryGroupId, StringComparison.OrdinalIgnoreCase);
                if (widens && !stepUp)
                    return Refuse($"mapping '{mapping.Id}' edit WIDENS enrollment scope (retarget or enable) — refused without step-up confirmation (a mapping edit never silently widens scope)");
            }
            else
            {
                if (_mappings.Count >= DirectoryEnrollmentLimits.MaxMappings)
                    return Refuse("mapping limit reached — refused");
                if (mapping.EnrollmentEnabled && !stepUp)
                    return Refuse($"new mapping '{mapping.Id}' enables enrollment — refused without step-up confirmation (creating an enrollment right is a widening act)");
            }
            // Freeze the admitted mapping: mappings are immutable
            // records, and the with-copy additionally detaches the
            // stored instance from the caller's reference (D38
            // rmm24 F12d — the copy is real, and immutability is
            // what makes a shallow copy sufficient).
            _mappings[mapping.Id] = mapping with { };
            _audit.Append("directory_mapping_set", actorUserId,
                $"mapping={mapping.Id} scope={mapping.ScopeId} directoryGroup={mapping.DirectoryGroupId} deviceGroup={mapping.DeviceGroupId} userGroup={mapping.UserGroupId} enabled={mapping.EnrollmentEnabled} revision={mapping.Revision} stepUp={stepUp}", now);
            return (true, $"mapping '{mapping.Id}' admitted at revision {mapping.Revision}");
        }
    }

    // -- sync: the push --

    /// <summary>One directory sync: read the directory, drive
    /// offers for mapped-group members, record directory-listed
    /// unenrolled machines as known-unmanaged, and flag departures
    /// for offboarding. Refused whole when policy disables the
    /// feature. A directory user with NO roster record in the
    /// scope is a poison suspect: no offer is created (the roster
    /// is admin-curated; the directory alone cannot provision a
    /// person into DeskGuest), the fact is audited and counted.</summary>
    public DirectorySyncOutcome Sync(DateTimeOffset now)
    {
        // Policy is evaluated PER SCOPE (D38 rmm24 F8): a scope
        // whose directory toggle is off is skipped (audited); the
        // sync refuses whole only when EVERY mapped scope is off.
        PruneTerminalRecords(now);
        var snapshot = _connector.ReadSnapshot(now);
        var usersById = new Dictionary<string, DirectoryUser>(StringComparer.OrdinalIgnoreCase);
        foreach (var u in snapshot.Users)
            if (!string.IsNullOrWhiteSpace(u.Id)) usersById[u.Id.Trim()] = u;

        var created = 0; var refreshed = 0; var poison = 0; var departed = 0;

        List<DirectoryGroupMapping> mappings;
        lock (_gate) mappings = _mappings.Values.ToList();

        var enabledMappings = 0;
        foreach (var mapping in mappings)
        {
            if (!_policyEnabledForScope(mapping.ScopeId))
            {
                _audit.Append("directory_sync_scope_skipped", "directory-sync",
                    $"mapping={mapping.Id} scope={mapping.ScopeId} reason=directory enrollment disabled by policy for this scope ({DirectoryEnrollmentPolicyKeys.DirectoryEnabled}) — mapping skipped, baseline untouched", now);
                continue;
            }
            enabledMappings++;
            var dirGroup = snapshot.Groups.FirstOrDefault(g =>
                string.Equals(g.Id, mapping.DirectoryGroupId, StringComparison.OrdinalIgnoreCase));
            // A MISSING directory group is a read anomaly, NOT a
            // mass departure (D38 rmm24 F1): a transient read
            // failure, a renamed group or a wiped group must never
            // flag every previous member for offboarding. The
            // baseline is left untouched and nothing is flagged.
            if (dirGroup is null)
            {
                _audit.Append("directory_group_missing", "directory-sync",
                    $"mapping={mapping.Id} directoryGroup={mapping.DirectoryGroupId} reason=group absent from this snapshot — treated as a directory read anomaly, NOT a mass departure; no departures flagged and the member baseline is preserved", now);
                continue;
            }
            var currentMembers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var m in dirGroup.MemberUserIds)
                if (!string.IsNullOrWhiteSpace(m)) currentMembers.Add(m.Trim());

            // Departures: in the last snapshot's member set, gone now.
            HashSet<string> previous;
            lock (_gate)
                previous = _lastMembersByMapping.TryGetValue(BaselineKey(mapping), out var p)
                    ? new HashSet<string>(p, StringComparer.OrdinalIgnoreCase)
                    : new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var goneUserId in previous.Except(currentMembers, StringComparer.OrdinalIgnoreCase).ToList())
                if (FlagDeparture(mapping, goneUserId, now)) departed++;

            lock (_gate) _lastMembersByMapping[BaselineKey(mapping)] = currentMembers;

            if (!mapping.EnrollmentEnabled || dirGroup is null) continue;
            var deviceGroup = _roster.FindDeviceGroup(mapping.DeviceGroupId);
            if (deviceGroup is null) continue;

            foreach (var userId in currentMembers)
            {
                // Poison wall #1: the directory cannot provision a
                // person. No roster record in THIS scope → no offer.
                var rosterUser = _roster.GetUser(mapping.ScopeId, userId);
                if (rosterUser is null || rosterUser.Suspended || rosterUser.Kind != "human")
                {
                    poison++;
                    _audit.Append("directory_offer_refused", "directory-sync",
                        $"mapping={mapping.Id} user={userId} reason=no live human roster record in scope {mapping.ScopeId} — directory entry alone provisions nobody (poison suspect)", now);
                    continue;
                }
                lock (_gate)
                {
                    if (_departedUsers.Contains(DepartedKey(mapping.ScopeId, userId)))
                        continue; // flagged users get no new offers until an admin clears the flag by re-provisioning
                    var live = _offers.Values.FirstOrDefault(o =>
                        o.State == OfferStates.Offered &&
                        string.Equals(o.MappingId, mapping.Id, StringComparison.OrdinalIgnoreCase) &&
                        string.Equals(o.UserId, userId, StringComparison.OrdinalIgnoreCase));
                    if (live is not null) { refreshed++; continue; }
                    var alreadyAccepted = _offers.Values.Any(o =>
                        o.State == OfferStates.Accepted &&
                        string.Equals(o.MappingId, mapping.Id, StringComparison.OrdinalIgnoreCase) &&
                        string.Equals(o.UserId, userId, StringComparison.OrdinalIgnoreCase));
                    if (alreadyAccepted) continue;
                }
                // Pre-stage: mint the normal Slice 1 code, bound to
                // the mapped device group at mint. The Slice 1 scope
                // is the roster scope's KIND (local/personal/company
                // — derived from the mapping's scope, never a
                // hard-coded literal: D38 rmm24 F12a), and the
                // minter attribution is the ENGINE acting for the
                // user (EngineMintedBy), so D14 attribution stays
                // truthful and the departure kill stays scoped to
                // exactly these codes.
                var scopeKind = _roster.GetScope(mapping.ScopeId)?.Kind ?? "company";
                var code = _enrollments.CreateEnrollmentCode(scopeKind, deviceGroup.Id, deviceGroup.Name,
                    DirectoryEnrollmentLimits.OfferTtl, mintedByUserId: EngineMintedBy(userId));
                var offer = new EnrollmentOffer(
                    Id: Guid.NewGuid().ToString("N"),
                    MappingId: mapping.Id, ScopeId: mapping.ScopeId, UserId: userId,
                    DirectoryGroupId: mapping.DirectoryGroupId, DeviceGroupId: deviceGroup.Id,
                    CodeHash: HashCode(code),
                    State: OfferStates.Offered, CreatedUtc: now,
                    ExpiresUtc: now + DirectoryEnrollmentLimits.OfferTtl,
                    AcceptedDeviceId: null, DecidedUtc: null);
                lock (_gate)
                {
                    _offers[offer.Id] = offer;
                    _offerCodes[offer.Id] = code;
                }
                // Delivery is the push: the code travels ONLY this
                // channel to the user's endpoint. No channel wired →
                // the offer is pre-staged but undelivered, and the
                // audit says so plainly.
                if (_delivery is not null) _delivery.Deliver(offer, code, now);
                else _audit.Append("directory_offer_undelivered", "directory-sync",
                    $"offer={offer.Id} user={userId} reason=no offer delivery channel wired — pre-staged only, the endpoint cannot accept what it never received", now);
                created++;
                _audit.Append("directory_offer_created", "directory-sync",
                    $"offer={offer.Id} mapping={mapping.Id} user={userId} deviceGroup={deviceGroup.Id} expires={offer.ExpiresUtc:O} connector={_connector.Name} fake={_connector.IsFake}", now);
            }
        }

        if (mappings.Count > 0 && enabledMappings == 0)
        {
            _audit.Append("directory_sync_refused", "directory-sync",
                $"connector={_connector.Name} reason=feature disabled by policy for every mapped scope ({DirectoryEnrollmentPolicyKeys.DirectoryEnabled})", now);
            return new DirectorySyncOutcome(0, 0, 0, 0, 0, "directory enrollment push is disabled by policy — sync refused");
        }

        // Known-unmanaged: directory-listed machines with no enrollment.
        // Enrollment is proven ONLY by identity: the directory
        // machine id IS the enrolled DeviceId. A hostname match
        // against an enrolled device's DisplayName proves NOTHING
        // (D38 rmm24 F11) — the endpoint supplies its own display
        // name at redemption, so any enrolled endpoint could call
        // itself "CEO-LAPTOP" and erase the real machine from this
        // list. Name matches are audited as untrusted and the
        // record STANDS until an id-matched enrollment reconciles
        // it (including the mirrored register record).
        var enrolledById = _enrollments.List().Where(d => !d.Revoked)
            .ToDictionary(d => d.DeviceId, StringComparer.OrdinalIgnoreCase);
        var enrolledNames = new HashSet<string>(
            enrolledById.Values.Select(d => d.DisplayName), StringComparer.OrdinalIgnoreCase);
        var unmanagedSeen = 0;
        foreach (var machine in snapshot.Machines)
        {
            if (string.IsNullOrWhiteSpace(machine.MachineId)) continue;
            var isEnrolled = enrolledById.ContainsKey(machine.MachineId);
            if (!isEnrolled && enrolledNames.Contains(machine.Hostname ?? ""))
                _audit.Append("directory_known_unmanaged_name_match_untrusted", "directory-sync",
                    $"machine={machine.MachineId} host={machine.Hostname} reason=an enrolled device carries this display name, but display names are endpoint-supplied free text — NOT treated as enrolled; the known-unmanaged record stands until an enrollment with this machine's id appears", now);
            lock (_gate)
            {
                if (isEnrolled)
                {
                    _knownUnmanaged.Remove(machine.MachineId);
                    ReconcileUnmanagedMirror(machine.MachineId, now);
                    continue;
                }
                unmanagedSeen++;
                if (_knownUnmanaged.TryGetValue(machine.MachineId, out var known))
                    _knownUnmanaged[machine.MachineId] = known with { LastSeenUtc = now, Hostname = machine.Hostname };
                else
                {
                    var scopeId = mappings.FirstOrDefault(m =>
                        string.Equals(m.DirectoryGroupId, machine.DirectoryGroupId ?? "", StringComparison.OrdinalIgnoreCase))?.ScopeId ?? "";
                    var record = new KnownUnmanagedDevice(machine.MachineId, machine.Hostname ?? "",
                        scopeId, machine.DirectoryGroupId, machine.OwnerUserId, now, now);
                    _knownUnmanaged[machine.MachineId] = record;
                    _audit.Append("directory_known_unmanaged", "directory-sync",
                        $"machine={machine.MachineId} host={machine.Hostname} classification=known_unmanaged (directory-listed, never enrolled — distinct from a rogue)", now);
                    MirrorToUnmanagedRegister(record, now);
                }
            }
        }

        _audit.Append("directory_sync_completed", "directory-sync",
            $"connector={_connector.Name} fake={_connector.IsFake} offersCreated={created} offersLive={refreshed} unmanaged={unmanagedSeen} departures={departed} poisonSuspects={poison}", now);
        return new DirectorySyncOutcome(created, refreshed, unmanagedSeen, departed, poison,
            $"sync complete: {created} offer(s) created, {departed} departure(s) flagged, {poison} poison suspect(s) refused");
    }

    private void MirrorToUnmanagedRegister(KnownUnmanagedDevice record, DateTimeOffset now)
    {
        if (_unmanagedRegister is null) return;
        var assetId = (record.MachineId ?? "").Trim().ToLowerInvariant();
        // The register's id grammar is its own; an id it refuses is
        // named in the audit, never forced.
        var added = _unmanagedRegister.Add(new UnmanagedAsset(
            assetId, string.IsNullOrWhiteSpace(record.ScopeId) ? "directory" : record.ScopeId,
            string.IsNullOrWhiteSpace(record.Hostname) ? assetId : record.Hostname,
            UnmanagedAssetKinds.Other, null, null, null, null, null, null, null,
            UnmanagedLifecycleStates.Discovered, Array.Empty<string>(),
            new HashSet<string>(), new Dictionary<string, string>(), null,
            "rmm24-directory", now, now));
        if (added is null)
            _audit.Append("directory_unmanaged_mirror_refused", "directory-sync",
                $"machine={record.MachineId} reason=unmanaged register refused the mirror (id grammar, collision, or policy) — the known-unmanaged record stands in this engine regardless", now);
        else
            lock (_gate) _mirroredAssetIds.Add(assetId);
    }

    /// <summary>Reconcile a mirror this engine placed in the
    /// UnmanagedAssetRegister once the machine enrolls by id
    /// (D38 rmm24 F11): the mirrored record is removed so the
    /// register never carries a managed machine as unmanaged.
    /// Only ids THIS engine mirrored are touched.</summary>
    private void ReconcileUnmanagedMirror(string machineId, DateTimeOffset now)
    {
        if (_unmanagedRegister is null) return;
        var assetId = (machineId ?? "").Trim().ToLowerInvariant();
        bool mirrored;
        lock (_gate) mirrored = _mirroredAssetIds.Remove(assetId);
        if (mirrored && _unmanagedRegister.Remove(assetId))
            _audit.Append("directory_unmanaged_mirror_reconciled", "directory-sync",
                $"machine={machineId} reason=machine enrolled by id — mirrored unmanaged-register record removed", now);
    }

    /// <summary>Bounded retention (D38 rmm24 F12c): terminal-state
    /// offers past OfferRetention and flags past FlagRetention are
    /// pruned at sync. Live offers, the departed set (exported
    /// separately) and the member baselines are never pruned.</summary>
    private void PruneTerminalRecords(DateTimeOffset now)
    {
        int prunedOffers, prunedFlags;
        lock (_gate)
        {
            var deadOffers = _offers.Values
                .Where(o => o.State != OfferStates.Offered && o.DecidedUtc is not null &&
                            now - o.DecidedUtc.Value > DirectoryEnrollmentLimits.OfferRetention)
                .Select(o => o.Id).ToList();
            foreach (var id in deadOffers)
            {
                // bd-shared-plat-1/F3 (belt): a terminal offer's
                // Slice-1 code must be dead even if it arrived via
                // a path that skipped the transition revocation.
                if (_offers.TryGetValue(id, out var deadOffer))
                    _enrollments.RevokePendingCodeByHash(deadOffer.CodeHash);
                _offers.Remove(id); _offerCodes.Remove(id);
            }
            prunedOffers = deadOffers.Count;
            prunedFlags = _flags.RemoveAll(f => now - f.FlaggedUtc > DirectoryEnrollmentLimits.FlagRetention);
        }
        if (prunedOffers + prunedFlags > 0)
            _audit.Append("directory_store_pruned", "directory-sync",
                $"offersPruned={prunedOffers} flagsPruned={prunedFlags} (bounded retention; departed set and baselines are retained)", now);
    }

    private bool FlagDeparture(DirectoryGroupMapping mapping, string userId, DateTimeOffset now)
    {
        // ELIGIBILITY (D38 rmm24 F1): directory membership alone
        // never offboards anyone. A departure is flagged only for a
        // live roster user who belongs to the mapping's DeskGuest user
        // group or who holds offers under this mapping — the people
        // the mapping actually covers. A directory-only id (poison
        // suspect) or a roster user outside the mapped user group
        // is dropped from the baseline with an audit note, never
        // flagged, and their codes are never touched here.
        var rosterUser = _roster.GetUser(mapping.ScopeId, userId);
        if (rosterUser is null)
        {
            _audit.Append("directory_departure_ignored", "directory-sync",
                $"mapping={mapping.Id} user={userId} reason=no roster record in scope {mapping.ScopeId} — a directory-only id is a poison suspect, not an offboarding subject; nothing flagged, no codes touched", now);
            return false;
        }
        var inMappedUserGroup = _roster.GetUserGroup(mapping.ScopeId, mapping.UserGroupId)?.MemberUserIds
            .Contains(rosterUser.Id, StringComparer.OrdinalIgnoreCase) == true;
        bool hasOffers;
        lock (_gate)
            hasOffers = _offers.Values.Any(o =>
                string.Equals(o.MappingId, mapping.Id, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(o.UserId, userId, StringComparison.OrdinalIgnoreCase));
        if (!inMappedUserGroup && !hasOffers)
        {
            _audit.Append("directory_departure_ignored", "directory-sync",
                $"mapping={mapping.Id} user={userId} reason=user is not a member of the mapping's user group '{mapping.UserGroupId}' and holds no offers under this mapping — directory membership alone does not offboard; nothing flagged", now);
            return false;
        }
        // A SCOPE ADMIN is never auto-offboarded by a directory
        // diff (D38 rmm24 F1): adding the admin to the group and
        // removing them on the next sync must not delete them. The
        // flag is raised for a HUMAN admin decision (the D14 path
        // with its own step-up), initiation is NOT attempted, and
        // the audit names why.
        var isScopeAdmin = _roster.IsScopeAdmin(mapping.ScopeId, userId);
        List<string> acceptedDevices;
        lock (_gate)
        {
            _departedUsers.Add(DepartedKey(mapping.ScopeId, userId));
            acceptedDevices = _offers.Values
                .Where(o => o.State == OfferStates.Accepted &&
                            string.Equals(o.MappingId, mapping.Id, StringComparison.OrdinalIgnoreCase) &&
                            string.Equals(o.UserId, userId, StringComparison.OrdinalIgnoreCase))
                .Select(o => o.AcceptedDeviceId!).Where(d => !string.IsNullOrWhiteSpace(d)).ToList();
            foreach (var offer in _offers.Values.Where(o =>
                         o.State == OfferStates.Offered &&
                         string.Equals(o.MappingId, mapping.Id, StringComparison.OrdinalIgnoreCase) &&
                         string.Equals(o.UserId, userId, StringComparison.OrdinalIgnoreCase)).ToList())
            {
                _offers[offer.Id] = offer with { State = OfferStates.OffboardingFlagged, DecidedUtc = now };
                _offerCodes.Remove(offer.Id);
            }
        }
        // The departed user's still-pending ENGINE-minted codes die
        // NOW, so no live push key survives the flag (departed-user
        // persistence wall). The kill is scoped to this engine's
        // mint namespace for this user (D38 rmm24 F1/F12a): codes
        // the user minted themselves, in any scope, are D14's
        // business at removal time — never this sync's.
        var killed = _enrollments.RevokePendingCodesMintedBy(EngineMintedBy(userId));
        var flag = new OffboardingFlag(
            Id: Guid.NewGuid().ToString("N"), ScopeId: mapping.ScopeId, UserId: userId,
            MappingId: mapping.Id, DirectoryGroupId: mapping.DirectoryGroupId,
            AcceptedDeviceIds: acceptedDevices, FlaggedUtc: now,
            Reason: isScopeAdmin
                ? $"user left directory group '{mapping.DirectoryGroupId}' (mapping '{mapping.Id}') — SCOPE ADMIN: auto-offboarding refused, a human admin decision with step-up is required"
                : $"user left directory group '{mapping.DirectoryGroupId}' (mapping '{mapping.Id}')",
            Initiated: false);
        var initiated = !isScopeAdmin && _offboarding.Initiate(flag, now);
        flag = flag with { Initiated = initiated };
        lock (_gate) _flags.Add(flag);
        _audit.Append("directory_departure_flagged", "directory-sync",
            $"flag={flag.Id} user={userId} scope={mapping.ScopeId} mapping={mapping.Id} acceptedDevices=[{string.Join(",", acceptedDevices)}] pendingCodesKilled={killed} offboardingInitiated={initiated} scopeAdmin={isScopeAdmin} (execution is the D14 path — this lane flags + initiates only; a scope admin is never initiated)", now);
        return true;
    }

    /// <summary>Admin re-provisioning (D38 rmm24 F10b): the ONLY
    /// way a departure flag's effect is cleared. A scope admin (or
    /// an actor holding an admin right in the scope) clears the
    /// departed mark for a user — e.g. a re-hire — after which a
    /// fresh sync may offer again. The flag RECORD stays as
    /// history; what clears is the departed set's block. Every
    /// clearing audits with its actor.</summary>
    public (bool Ok, string Reason) ReprovisionUser(string scopeId, string userId, string actorUserId, DateTimeOffset now)
    {
        if (!_roster.IsScopeAdmin(scopeId, actorUserId) && !_roster.HasAdminRight(scopeId, actorUserId))
        {
            _audit.Append("directory_reprovision_refused", actorUserId ?? "(unknown)",
                $"scope={scopeId} user={userId} reason=actor holds no admin right in the scope — only an admin can clear a departure flag (re-provisioning is an admin act)", now);
            return (false, "clearing a departure flag is an admin act — refused for a non-admin actor");
        }
        bool cleared;
        lock (_gate) cleared = _departedUsers.Remove(DepartedKey(scopeId ?? "", userId ?? ""));
        _audit.Append("directory_departure_cleared", actorUserId,
            $"scope={scopeId} user={userId} wasDeparted={cleared} (admin re-provisioning; a fresh sync may offer again)", now);
        return cleared
            ? (true, $"departure flag cleared for '{userId}' by admin re-provisioning")
            : (true, $"user '{userId}' was not flagged departed — nothing to clear");
    }

    // -- endpoint acceptance (the wall) --

    /// <summary>The endpoint accepts an offer ITSELF: it presents
    /// the offer id, the code, and its own device claim; enrollment
    /// is Slice 1 redemption (DeviceId fingerprint proof included).
    /// Refusals: unknown/expired/decided offer, departed user, code
    /// mismatch, policy off, or Slice 1 refusing the device claim.
    /// A directory push alone NEVER reaches the enrollment store —
    /// this method is the only path, and it is the endpoint's act.</summary>
    public (EnrolledDevice? Device, string Reason) AcceptOffer(
        string offerId, string? presentedCode, EnrollingDevice? device, DateTimeOffset now)
    {
        (EnrolledDevice?, string) Refuse(string reason, string? auditOfferId = null)
        {
            _audit.Append("directory_offer_accept_refused", device?.DeviceId ?? "(unknown)",
                $"offer={auditOfferId ?? offerId} reason={reason}", now);
            return (null, reason);
        }
        // The WHOLE acceptance runs under the gate (D38 rmm24 F9):
        // state check, departed check, redemption and the accepted
        // write are one atomic unit, so a concurrent FlagDeparture
        // or DeclineOffer can never be overwritten by an Accepted
        // write based on a stale snapshot (and the expiry write
        // below is likewise decided on the live record). Slice 1
        // and the roster keep their own gates and never call back
        // into this engine, so holding the gate across them cannot
        // deadlock.
        EnrolledDevice enrolled;
        EnrollmentOffer offer;
        lock (_gate)
        {
            if (!_offers.TryGetValue(offerId ?? "", out var found) || found is null)
                return Refuse("unknown offer — refused");
            offer = found;
            if (!_policyEnabledForScope(offer.ScopeId))
                return Refuse("directory enrollment push is disabled by policy for this scope — acceptance refused", offer.Id);
            if (offer.State != OfferStates.Offered)
                return Refuse($"offer is in state '{offer.State}', not offered — refused", offer.Id);
            if (now > offer.ExpiresUtc)
            {
                _offers[offer.Id] = offer with { State = OfferStates.Expired, DecidedUtc = now };
                // bd-shared-plat-1/F3: the underlying Slice-1 code
                // dies with the expiry — dropping only the engine's
                // copy left it redeemable directly for up to 7 days.
                if (_offerCodes.TryGetValue(offer.Id, out var expiringCode))
                    _enrollments.RevokePendingCode(expiringCode);
                _offerCodes.Remove(offer.Id);
                return Refuse("offer expired — refused (a fresh sync pre-stages a fresh offer)", offer.Id);
            }
            if (_departedUsers.Contains(DepartedKey(offer.ScopeId, offer.UserId)))
                return Refuse($"user '{offer.UserId}' is flagged for offboarding — acceptance refused (a departed user retains no live enrollment rights past the flag)", offer.Id);
            _offerCodes.TryGetValue(offerId ?? "", out var heldCode);
            var normalized = EnrollmentService.NormalizeCode(presentedCode);
            if (normalized is null || heldCode is null ||
                !string.Equals(HashCode(normalized), offer.CodeHash, StringComparison.Ordinal))
                return Refuse("presented code does not match this offer — refused", offer.Id);
            // The endpoint's own act: Slice 1 redemption proves the
            // device key and binds scope/group from the MINT, never
            // from anything the directory or the endpoint claims here.
            var redeemed = _enrollments.Redeem(heldCode, device);
            if (redeemed is null)
                return Refuse("enrollment redemption refused by Slice 1 (unknown/expired/consumed code, malformed or mismatched device claim, or a revoked device) — offer stands unaccepted", offer.Id);
            enrolled = redeemed;
            _offers[offer.Id] = offer with
            {
                State = OfferStates.Accepted, AcceptedDeviceId = enrolled.DeviceId, DecidedUtc = now,
            };
            _offerCodes.Remove(offer.Id);
            _roster.RecordMintedEnrollment(offer.ScopeId, offer.UserId, enrolled.DeviceId);
        }
        _audit.Append("directory_offer_accepted", enrolled.DeviceId,
            $"offer={offer.Id} user={offer.UserId} deviceGroup={offer.DeviceGroupId} (endpoint accepted itself via Slice 1 redemption; attribution recorded for D14)", now);
        return (enrolled, $"offer accepted by the endpoint itself: device {enrolled.DeviceId} enrolled into '{offer.DeviceGroupId}'");
    }

    /// <summary>The endpoint/user declines an offer. The code dies
    /// with the decline (it is single-purpose pre-staging, not a
    /// standing key).</summary>
    public (bool Ok, string Reason) DeclineOffer(string offerId, string declinedBy, DateTimeOffset now)
    {
        lock (_gate)
        {
            if (!_offers.TryGetValue(offerId ?? "", out var offer) || offer.State != OfferStates.Offered)
                return (false, "no live offer to decline — refused");
            _offers[offer.Id] = offer with { State = OfferStates.Declined, DecidedUtc = now };
            // bd-shared-plat-1/F3: revoke the Slice-1 code itself,
            // not just the engine's copy of it.
            if (_offerCodes.TryGetValue(offer.Id, out var declinedCode))
                _enrollments.RevokePendingCode(declinedCode);
            _offerCodes.Remove(offer.Id);
        }
        _audit.Append("directory_offer_declined", declinedBy ?? "(unknown)",
            $"offer={offerId} — code retired with the decline", now);
        return (true, "offer declined; its pre-staged code is retired");
    }

    private static string HashCode(string displayOrNormalizedCode)
    {
        var normalized = EnrollmentService.NormalizeCode(displayOrNormalizedCode) ?? displayOrNormalizedCode;
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(normalized))).ToLowerInvariant();
    }

    // -- persistence: offers export WITHOUT codes (hash only) --

    private sealed record OfferDto(
        string Id, string MappingId, string ScopeId, string UserId, string DirectoryGroupId,
        string DeviceGroupId, string CodeHash, string State, DateTimeOffset CreatedUtc,
        DateTimeOffset ExpiresUtc, string? AcceptedDeviceId, DateTimeOffset? DecidedUtc);

    private sealed record StoreDto(
        OfferDto[] Offers, KnownUnmanagedDevice[] KnownUnmanaged, OffboardingFlag[] Flags,
        string[]? DepartedUsers = null, Dictionary<string, string[]>? LastMembersByMapping = null,
        // bd-shared-plat-1/F7: mappings persist with the store —
        // without them a restart silently disabled every sync.
        DirectoryGroupMapping[]? Mappings = null);

    public string ExportJson()
    {
        lock (_gate)
        {
            var store = new StoreDto(
                _offers.Values.Select(o => new OfferDto(o.Id, o.MappingId, o.ScopeId, o.UserId,
                    o.DirectoryGroupId, o.DeviceGroupId, o.CodeHash, o.State, o.CreatedUtc,
                    o.ExpiresUtc, o.AcceptedDeviceId, o.DecidedUtc)).ToArray(),
                _knownUnmanaged.Values.ToArray(),
                _flags.ToArray(),
                // The departed set AND the per-mapping member
                // baseline travel with the store (D38 rmm24 F10a):
                // without the baseline, a restart forgets who was
                // in the group, and anyone removed from the
                // directory during the downtime is never flagged.
                _departedUsers.ToArray(),
                _lastMembersByMapping.ToDictionary(
                    kv => kv.Key, kv => kv.Value.ToArray(), StringComparer.OrdinalIgnoreCase),
                _mappings.Values.OrderBy(m => m.Id, StringComparer.Ordinal).ToArray());
            // bd-shared-plat-1/F6: the export carries the
            // HubPersistence integrity envelope, like
            // PackageRepository — a hand-edited file can no longer
            // silently strip DepartedUsers/Flags and restore a
            // departed user's push rights.
            return HubPersistence.Wrap("deskguest-directory-enrollment-v1",
                System.Text.Json.JsonSerializer.Serialize(store));
        }
    }

    /// <summary>Restore offers/known-unmanaged/flags. Restored
    /// OFFERED offers come back EXPIRED: their codes lived in memory
    /// only and are gone, so the honest state is "pre-staging lost —
    /// a fresh sync re-offers". Nothing in an import can resurrect
    /// a redeemable code or clear a departure flag's effect (flags
    /// restore the departed set too).</summary>
    public int ImportJson(string json)
    {
        // bd-shared-plat-1/F6: integrity envelope first. A wrapped
        // export whose hash fails restores NOTHING. A legacy plain
        // (pre-envelope) payload is still accepted for migration.
        var payload = HubPersistence.Unwrap(json, "deskguest-directory-enrollment-v1");
        if (payload is null)
        {
            if (json is not null && json.Contains("\"Kind\"", StringComparison.Ordinal)) return 0;
            payload = json;
        }
        StoreDto? store;
        try { store = System.Text.Json.JsonSerializer.Deserialize<StoreDto>(payload); }
        catch { return 0; }
        if (store is null) return 0;
        var restored = 0;
        lock (_gate)
        {
            // bd-shared-plat-1/F7: mappings restore through the
            // SetMapping SHAPE checks (scope exists via its groups,
            // device group in scope, user group in scope, revision
            // monotonic) — never blindly.
            foreach (var m in store.Mappings ?? Array.Empty<DirectoryGroupMapping>())
            {
                if (m is null || string.IsNullOrWhiteSpace(m.Id) ||
                    string.IsNullOrWhiteSpace(m.ScopeId)) continue;
                if (_mappings.TryGetValue(m.Id, out var existingM) && m.Revision <= existingM.Revision) continue;
                var dg = _roster.FindDeviceGroup(m.DeviceGroupId);
                if (dg is null || !string.Equals(dg.ScopeId, m.ScopeId, StringComparison.OrdinalIgnoreCase)) continue;
                if (_roster.GetUserGroup(m.ScopeId, m.UserGroupId) is null) continue;
                _mappings[m.Id] = m with { };
                restored++;
            }
            foreach (var dto in store.Offers ?? Array.Empty<OfferDto>())
            {
                if (dto is null || string.IsNullOrWhiteSpace(dto.Id) || _offers.ContainsKey(dto.Id)) continue;
                var state = dto.State == OfferStates.Offered ? OfferStates.Expired : dto.State;
                // bd-shared-plat-1/F3: an offer imported as Expired
                // kills any live Slice-1 code with its hash.
                if (dto.State == OfferStates.Offered)
                    _enrollments.RevokePendingCodeByHash(dto.CodeHash);
                _offers[dto.Id] = new EnrollmentOffer(dto.Id, dto.MappingId, dto.ScopeId, dto.UserId,
                    dto.DirectoryGroupId, dto.DeviceGroupId, dto.CodeHash, state, dto.CreatedUtc,
                    dto.ExpiresUtc, dto.AcceptedDeviceId, dto.DecidedUtc);
                restored++;
            }
            foreach (var k in store.KnownUnmanaged ?? Array.Empty<KnownUnmanagedDevice>())
            {
                if (k is null || string.IsNullOrWhiteSpace(k.MachineId) || _knownUnmanaged.ContainsKey(k.MachineId)) continue;
                _knownUnmanaged[k.MachineId] = k;
                restored++;
            }
            foreach (var f in store.Flags ?? Array.Empty<OffboardingFlag>())
            {
                if (f is null) continue;
                _flags.Add(f);
                // bd-shared-plat-1/F6: when the export carries an
                // explicit DepartedUsers set, THAT set alone
                // rebuilds the departed state — flag RECORDS are
                // history, and a ReprovisionUser clear (which keeps
                // the record) must survive a restart. Only legacy
                // exports without the set fall back to flags.
                if (store.DepartedUsers is null)
                    _departedUsers.Add(DepartedKey(f.ScopeId, f.UserId));
                restored++;
            }
            foreach (var key in store.DepartedUsers ?? Array.Empty<string>())
            {
                if (string.IsNullOrWhiteSpace(key)) continue;
                _departedUsers.Add(key);
                restored++;
            }
            foreach (var (key, members) in store.LastMembersByMapping ?? new Dictionary<string, string[]>())
            {
                if (string.IsNullOrWhiteSpace(key) || _lastMembersByMapping.ContainsKey(key)) continue;
                _lastMembersByMapping[key] = new HashSet<string>(
                    (members ?? Array.Empty<string>()).Where(m => !string.IsNullOrWhiteSpace(m)),
                    StringComparer.OrdinalIgnoreCase);
                restored++;
            }
        }
        return restored;
    }
}
