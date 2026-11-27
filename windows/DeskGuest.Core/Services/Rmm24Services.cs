using DeskGuest.Shared.DirectoryEnrollment;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.Enrollment;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.Roster;

namespace DeskGuest.Core.Services;

// =====================================================================
// RMM-24 — Core wiring for (1) directory-driven enrollment push and
// (2) the mobile operator client contract.
//
// Composition, not reinvention:
//   * The push engine (DeskGuest.Shared.DirectoryEnrollment) composes
//     Slice 1 enrollment + the roster; this service adds the TOTAL
//     POLICY CONTROL gate (rmm.directory_enrollment.enabled,
//     evaluated per scope through the RMM-07 engine) and the D14
//     offboarding composition: the initiator below calls
//     RosterService.RemoveUser — the COMPLETE OFFBOARDING model —
//     with the scope's directory-sync admin as actor. When no live
//     admin actor is available the initiation reports false and the
//     flag stands uninitiated in the engine's record (named, never
//     silently claimed executed).
//   * The mobile services add the seeded RMM-24 policy gate
//     (rmm.enrollment_push.enabled) over the shared contract.
//   * The real AD/Entra connector is host wiring against the org's
//     directory (its credentials never enter DeskGuest — D4); until that
//     wiring exists the host supplies FakeDirectoryConnector and
//     every audit entry names it as fake.
// =====================================================================

/// <summary>D14 composition: flag → RosterService.RemoveUser.</summary>
public sealed class RosterOffboardingInitiator : IOffboardingInitiator
{
    private readonly RosterService _roster;
    private readonly Func<string, string?> _adminActorForScope;

    /// <param name="adminActorForScope">Resolves the scope's
    /// directory-sync admin actor (a live company admin). Null when
    /// none exists — initiation then honestly fails.</param>
    public RosterOffboardingInitiator(RosterService roster, Func<string, string?> adminActorForScope)
    {
        _roster = roster ?? throw new ArgumentNullException(nameof(roster));
        _adminActorForScope = adminActorForScope ?? throw new ArgumentNullException(nameof(adminActorForScope));
    }

    public bool Initiate(OffboardingFlag flag, DateTimeOffset now)
    {
        var actor = _adminActorForScope(flag.ScopeId);
        if (actor is null) return false;
        // The user may already be gone (DIR-51 sync removed them
        // first) — initiation is satisfied when the D14 outcome
        // (user absent from the scope) already holds.
        if (_roster.GetUser(flag.ScopeId, flag.UserId) is null) return true;
        // stepUp is DELIBERATELY false (D38 rmm24 F1): step-up is a
        // HUMAN admin's confirmation, and a sync engine cannot
        // fabricate it. With stepUp:false, D14's own guards decide
        // — an ordinary user's removal proceeds; removing a FELLOW
        // company admin refuses inside RemoveUser (its step-up and
        // last-admin guards intact), initiation reports false, and
        // the flag stands for a human admin decision. The engine
        // additionally never initiates for a scope admin at all.
        return _roster.RemoveUser(flag.ScopeId, flag.UserId, actor, stepUp: false) is not null;
    }
}

public sealed class DirectoryEnrollmentService
{
    private readonly ManagementPolicyEngine _policy;

    public DirectoryEnrollmentEngine Engine { get; }

    public DirectoryEnrollmentService(
        EnrollmentService enrollments, RosterService roster, ChainedAuditLog audit,
        ManagementPolicyEngine policy, IDirectoryConnector connector,
        IOffboardingInitiator offboarding, IOfferDelivery? delivery = null)
    {
        _policy = policy ?? throw new ArgumentNullException(nameof(policy));
        // TOTAL POLICY CONTROL: the directory toggle must exist in
        // the registry or IsEnabled fails closed forever. Register
        // it (seeded ON) when the RMM-07 seed does not carry it —
        // the seeded alias rmm.enrollment_push.enabled covers the
        // mobile half; this key is the directory half per the lane.
        if (!_policy.Registry.TryGet(DirectoryEnrollmentPolicyKeys.DirectoryEnabled, out _))
            _policy.Registry.Register(new FeatureToggle(
                DirectoryEnrollmentPolicyKeys.DirectoryEnabled, "RMM-24", true,
                "Directory-driven enrollment push (directory group → DeskGuest group mapping drives offers)"));
        Engine = new DirectoryEnrollmentEngine(enrollments, roster, audit, connector, offboarding,
            policyEnabledForScope: ScopeEnabled, delivery: delivery);
    }

    // The policy gate is evaluated PER MAPPING SCOPE by the engine
    // (D38 rmm24 F8): the RMM-07 engine's org documents target a
    // scope, so each mapping's own scope decides its own sync —
    // there is no shared mutable scope hint for the last caller to
    // poison, and disabling one scope never touches another.
    // SetScopeHint is retained as a no-op for host API compat.
    public void SetScopeHint(string scopeId) { /* superseded by per-scope evaluation (D38 rmm24 F8) */ }

    private bool ScopeEnabled(string scopeId)
    {
        var facts = StaticDeviceFacts.Of("directory-sync", scopeId);
        // The DIRECTORY gate is the directory key ALONE (D38 rmm24
        // F8): it previously ALSO required the mobile toggle
        // (rmm.enrollment_push.enabled), so turning off the mobile
        // client silently turned off directory push. The two halves
        // of RMM-24 have separate toggles and neither reaches the
        // §7.10 consent floor.
        return _policy.IsEnabled(facts, DirectoryEnrollmentPolicyKeys.DirectoryEnabled);
    }

    public DirectorySyncOutcome Sync(DateTimeOffset now) => Engine.Sync(now);
}

/// <summary>Mobile operator contract wiring: registry + authorization
/// + approval channel + notification queue under the seeded RMM-24
/// policy toggle.</summary>
public sealed class MobileOperatorService
{
    public MobileClientRegistry Clients { get; }
    public MobileAuthorization Authorization { get; }
    public MobileApprovalService Approvals { get; }
    public MobileNotificationQueue Notifications { get; }

    public MobileOperatorService(
        EnrollmentService enrollments, RosterService roster, ChainedAuditLog audit,
        ManagementPolicyEngine policy, string scopeId,
        Func<string, DeskGuest.Shared.Monitoring.HealthAlertEvent?> alertLookup,
        byte[]? hubPublicKey = null)
    {
        Clients = new MobileClientRegistry(enrollments, roster, audit);
        Authorization = new MobileAuthorization(roster, Clients,
            () => policy.IsEnabled(StaticDeviceFacts.Of("mobile-operator", scopeId),
                MobileOperatorPolicyKeys.Enabled),
            // bd-shared-plat-2/F2: session targets resolve to their
            // ENROLLED group server-side in production wiring.
            targetGroupOf: deviceId => enrollments.List().FirstOrDefault(d =>
                string.Equals(d.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase))?.GroupId);
        Approvals = new MobileApprovalService(enrollments, Clients, Authorization, audit);
        // The notification queue is wired WITH the authorization
        // context (D38 rmm24 F7a): enqueues are gated on the target
        // operator's live view right for the alert device's group.
        Notifications = new MobileNotificationQueue(alertLookup, audit, hubPublicKey,
            Authorization, scopeId,
            deviceGroupOf: deviceId => enrollments.List().FirstOrDefault(d =>
                string.Equals(d.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase))?.GroupId,
            clientDeviceOf: userId => Clients.ClientDeviceFor(userId));
    }
}
