using DeskGuest.Shared.DirectoryEnrollment;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.Enrollment;
using DeskGuest.Shared.Monitoring;
using DeskGuest.Shared.Roster;
using DeskGuest.Shared.Security;

namespace DeskGuest.Tests;

// RMM-24 DESTRUCTION — hostile pass over the directory push and the
// mobile operator contract. Attacker classes: a poisoned directory,
// a rogue admin-curious editor, a departed insider, a phone thief /
// forger, a notification spoofer, and the operator's own phone
// reaching past the operator's rights.
public class Rmm24DestructionTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    private const string Scope = "co-1";
    private const string Admin = "admin-1";
    private const string Op = "op-1";
    private const string Tech = "tech-1";
    private const string UG = "ug-1";
    private const string DG = "dg-1";
    private const string DirGroup = "dir-techs";

    private static Rmm24Tests.Rig Rig() => new();

    // D24-01 — DIRECTORY POISONING: a rogue directory entry tries to
    // enroll an attacker's device. Walls: roster existence (the
    // directory provisions nobody), endpoint acceptance (a push
    // alone enrolls nothing), code possession (no code, no redeem).
    [Fact]
    public void Attack_RogueDirectoryUser_GetsNoOffer_EnrollsNothing()
    {
        var rig = Rig();
        rig.Directory.Users.Add(new DirectoryUser("attacker", "Attacker", "a@evil.example"));
        rig.Directory.Groups[0] = rig.Directory.Groups[0] with
        {
            MemberUserIds = new[] { Tech, "attacker" },
        };
        rig.AdmitMapping();
        var outcome = rig.Engine.Sync(T0);
        Assert.Equal(1, outcome.OffersCreated); // tech only
        Assert.Equal(1, outcome.PoisonSuspects);
        Assert.DoesNotContain(rig.Engine.Offers, o => o.UserId == "attacker");
        Assert.Empty(rig.Enrollments.List());
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "directory_offer_refused");
    }

    [Fact]
    public void Attack_RogueDirectoryEntry_AttackerDeviceCannotAccept_TechsOffer()
    {
        var rig = Rig();
        var offer = rig.SyncOneOffer();
        var attacker = new DeviceIdentity(new DevOnlyPassThroughProtector());
        // Attacker knows an offer exists but not its code: every
        // guessed code refuses, and direct Slice 1 redemption has
        // no code to present either.
        var (device, _) = rig.Engine.AcceptOffer(offer.Id, "ZZZZZ-ZZZZZ",
            new EnrollingDevice(attacker.DeviceId, attacker.PublicKeyBase64, "evil-1"), T0);
        Assert.Null(device);
        Assert.Null(rig.Enrollments.Redeem("ZZZZZ-ZZZZZ",
            new EnrollingDevice(attacker.DeviceId, attacker.PublicKeyBase64, "evil-1")));
        Assert.Empty(rig.Enrollments.List());
    }

    [Fact]
    public void Attack_SuspendedRosterUser_InDirectory_GetsNoOffer()
    {
        var rig = Rig();
        Assert.True(rig.Roster.SetUserSuspended(Scope, Tech, true));
        rig.AdmitMapping();
        var outcome = rig.Engine.Sync(T0);
        Assert.Equal(0, outcome.OffersCreated);
        Assert.Equal(1, outcome.PoisonSuspects);
    }

    // D24-02 — GROUP-MAPPING WIDENING: a mapping edit that silently
    // widens scope must never land.
    [Fact]
    public void Attack_MappingWidening_WithoutStepUp_Refused_AllShapes()
    {
        var rig = Rig();
        // New enrollment-enabled mapping without step-up.
        var (okNew, _) = rig.Engine.SetMapping(rig.Mapping(), Admin, stepUp: false, T0);
        Assert.False(okNew);
        rig.AdmitMapping();
        // Retarget to another device group without step-up.
        rig.Roster.CreateDeviceGroup("dg-2", Scope, "Servers");
        var widened = new DirectoryGroupMapping("map-1", Scope, DirGroup, "dg-2", UG, true, 2);
        var (okWiden, reason) = rig.Engine.SetMapping(widened, Admin, stepUp: false, T0);
        Assert.False(okWiden);
        Assert.Contains("WIDENS", reason);
        Assert.Equal(DG, rig.Engine.Mappings.Single().DeviceGroupId);
        // With step-up the SAME edit is a named, audited decision.
        var (okStepped, _) = rig.Engine.SetMapping(widened, Admin, stepUp: true, T0);
        Assert.True(okStepped);
        Assert.Equal("dg-2", rig.Engine.Mappings.Single().DeviceGroupId);
    }

    [Fact]
    public void Attack_Mapping_StaleRevision_AndCrossScope_Refused()
    {
        var rig = Rig();
        rig.AdmitMapping();
        var stale = rig.Mapping(rev: 1);
        Assert.False(rig.Engine.SetMapping(stale, Admin, stepUp: true, T0).Ok);
        // Cross-scope: device group lives in another scope.
        rig.Roster.CreateScope("co-2", "company", "Other");
        rig.Roster.CreateUser("admin-2", "co-2", "Admin Two", "human");
        rig.Roster.AddCompanyAdmin("co-2", "admin-2");
        rig.Roster.CreateDeviceGroup("dg-x", "co-2", "Foreign");
        rig.Roster.CreateUserGroup("ug-x", "co-2", "Foreign UG");
        var cross = new DirectoryGroupMapping("map-x", Scope, DirGroup, "dg-x", UG, true, 1);
        var (okCross, reasonCross) = rig.Engine.SetMapping(cross, Admin, stepUp: true, T0);
        Assert.False(okCross);
        Assert.Contains("does not exist in scope", reasonCross);
    }

    // D24-03 — DEPARTED-USER PERSISTENCE: a user removed from the
    // directory must retain NO live enrollment rights past the flag.
    [Fact]
    public void Attack_DepartedUser_PendingCodesDie_AcceptanceRefused_ReAddDoesNotRevive()
    {
        var rig = Rig();
        var offer = rig.SyncOneOffer();
        var code = rig.Delivery.CodeFor(offer.Id)!;
        rig.Directory.RemoveMember(DirGroup, Tech);
        var outcome = rig.Engine.Sync(T0.AddHours(1));
        Assert.Equal(1, outcome.DeparturesFlagged);
        // The pre-staged code is dead at Slice 1 too (killed at flag).
        Assert.Null(rig.Enrollments.Redeem(code,
            new EnrollingDevice(rig.EndpointIdentity.DeviceId, rig.EndpointIdentity.PublicKeyBase64, "ws-1")));
        // Engine-level acceptance also refuses.
        var (device, reason) = rig.Engine.AcceptOffer(offer.Id, code,
            new EnrollingDevice(rig.EndpointIdentity.DeviceId, rig.EndpointIdentity.PublicKeyBase64, "ws-1"), T0.AddHours(2));
        Assert.Null(device);
        Assert.Contains("offboarding", reason);
        // Re-adding the user to the directory group does NOT revive
        // rights: the departed flag stands until re-provisioning.
        rig.Directory.Groups[0] = rig.Directory.Groups[0] with { MemberUserIds = new[] { Tech } };
        var outcome2 = rig.Engine.Sync(T0.AddHours(3));
        Assert.Equal(0, outcome2.OffersCreated);
        Assert.False(rig.Engine.HasLivePushRights(Scope, Tech));
    }

    // D24-04 — MOBILE APPROVAL FORGERY.
    [Fact]
    public void Attack_ApprovalForgery_UnkeyedDevice_WrongSigner_WrongDecision_AllRefused()
    {
        var rig = Rig();
        rig.RegisterPhone();
        var req = rig.Approvals.CreateRequest(Scope, DG, "reboot ws-1", Admin, TimeSpan.FromHours(1), T0);
        var msg = MobileApprovalService.CanonicalMessage(req.Id, req.ActionHash, "approved");
        // (a) A different device's key signing the right message.
        var stranger = new DeviceIdentity(new DevOnlyPassThroughProtector());
        rig.EnrollDevice(stranger, "stranger-device");
        var sigStranger = Convert.ToBase64String(stranger.Sign(msg));
        Assert.False(rig.Approvals.Decide(req.Id, Op, stranger.DeviceId, "approved", sigStranger, T0).Ok);
        // (b) The right key signing the WRONG decision, presented as approved.
        var sigDenied = Convert.ToBase64String(rig.PhoneIdentity.Sign(
            MobileApprovalService.CanonicalMessage(req.Id, req.ActionHash, "denied")));
        Assert.False(rig.Approvals.Decide(req.Id, Op, rig.PhoneIdentity.DeviceId, "approved", sigDenied, T0).Ok);
        // (c) No signature at all.
        Assert.False(rig.Approvals.Decide(req.Id, Op, rig.PhoneIdentity.DeviceId, "approved", null, T0).Ok);
        Assert.Equal(MobileApprovalStates.Pending, rig.Approvals.Get(req.Id)!.State);
        // The genuine approval still lands, exactly once (replay dies).
        var sig = Convert.ToBase64String(rig.PhoneIdentity.Sign(msg));
        Assert.True(rig.Approvals.Decide(req.Id, Op, rig.PhoneIdentity.DeviceId, "approved", sig, T0).Ok);
        Assert.False(rig.Approvals.Decide(req.Id, Op, rig.PhoneIdentity.DeviceId, "approved", sig, T0).Ok);
    }

    [Fact]
    public void Attack_Approval_RevokedClientDevice_CannotApprove()
    {
        var rig = Rig();
        rig.RegisterPhone();
        var req = rig.Approvals.CreateRequest(Scope, DG, "reboot ws-1", Admin, TimeSpan.FromHours(1), T0);
        Assert.True(rig.Enrollments.Revoke(rig.PhoneIdentity.DeviceId));
        var sig = Convert.ToBase64String(rig.PhoneIdentity.Sign(
            MobileApprovalService.CanonicalMessage(req.Id, req.ActionHash, "approved")));
        var (ok, reason) = rig.Approvals.Decide(req.Id, Op, rig.PhoneIdentity.DeviceId, "approved", sig, T0);
        Assert.False(ok);
        // Convergence reconciliation (2026-11-22): the revoked-device
        // refusal now fires at the client-binding check (MobileOperator:
        // "the deciding device is not this operator's registered mobile
        // client (or its enrollment has been revoked)") before signature
        // verification is reached. The security property — a revoked
        // client device cannot approve — is unchanged; the asserted
        // reason now names the check that actually refuses.
        Assert.Contains("not this operator's registered mobile client", reason);
    }

    [Fact]
    public void Attack_Approval_ExpiredRequest_Refused()
    {
        var rig = Rig();
        rig.RegisterPhone();
        var req = rig.Approvals.CreateRequest(Scope, DG, "reboot ws-1", Admin, TimeSpan.FromMinutes(5), T0);
        var sig = Convert.ToBase64String(rig.PhoneIdentity.Sign(
            MobileApprovalService.CanonicalMessage(req.Id, req.ActionHash, "approved")));
        Assert.False(rig.Approvals.Decide(req.Id, Op, rig.PhoneIdentity.DeviceId, "approved", sig, T0.AddHours(1)).Ok);
        Assert.Equal(MobileApprovalStates.Expired, rig.Approvals.Get(req.Id)!.State);
    }

    // D24-05 — NOTIFICATION SPOOFING.
    [Fact]
    public void Attack_NotificationSpoofing_FakeAlertId_AndForgedHubSignature_Refused()
    {
        var rig = Rig();
        var (note, _) = rig.Notifications.EnqueueFromHubAlert("no-such-alert", Op, T0);
        Assert.Null(note);
        Assert.Empty(rig.Notifications.ForOperator(Op));

        rig.RegisterPhone(); // D38 F7a: the queue is gated on the operator's live client + view right
        var hub = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var queue = new MobileNotificationQueue(id => rig.HealthCentre.Get(id), rig.Audit, hub.PublicKey,
            rig.Auth, Scope,
            deviceGroupOf: id => id == "ws-1" ? DG : null,
            clientDeviceOf: userId => rig.Clients.ClientDeviceFor(userId));
        var attacker = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var payload = MobileNotificationQueue.CanonicalPayload("a1", "ws-1", "critical", "fake breach", Op);
        var forged = Convert.ToBase64String(attacker.Sign(payload));
        Assert.Null(queue.EnqueueSigned("a1", "ws-1", "critical", "fake breach", Op, forged, T0).Notification);
        // Tampered detail under the hub's genuine signature for other text.
        var genuine = Convert.ToBase64String(hub.Sign(
            MobileNotificationQueue.CanonicalPayload("a1", "ws-1", "warning", "real text", Op)));
        Assert.Null(queue.EnqueueSigned("a1", "ws-1", "critical", "fake breach", Op, genuine, T0).Notification);
        // The genuine signed payload lands.
        Assert.NotNull(queue.EnqueueSigned("a1", "ws-1", "warning", "real text", Op, genuine, T0).Notification);
    }

    // D24-06 — MOBILE SCOPE CREEP: the phone exercising a right the
    // desktop operator does not hold.
    [Fact]
    public void Attack_MobileScopeCreep_ViewOnlyOperator_CannotDriveOrApprove()
    {
        var rig = Rig();
        // A second operator whose group holds view ONLY.
        rig.Roster.CreateUser("viewer-1", Scope, "Viewer", "human");
        rig.Roster.CreateUserGroup("ug-view", Scope, "Viewers", new[] { "viewer-1" });
        rig.Roster.AddGrant(Scope, "ug-view", DG, new[] { "view" });
        var viewerPhone = new DeviceIdentity(new DevOnlyPassThroughProtector());
        rig.EnrollDevice(viewerPhone, "viewer-phone");
        Assert.NotNull(rig.RegisterClientSelf("viewer-1", viewerPhone).Registration);
        Assert.True(rig.Auth.Can(Scope, "viewer-1", viewerPhone.DeviceId, "browse_roster", DG));
        Assert.False(rig.Auth.Can(Scope, "viewer-1", viewerPhone.DeviceId, "start_session", DG));
        Assert.False(rig.Auth.Can(Scope, "viewer-1", viewerPhone.DeviceId, "approve_dual_control", DG));
        var drive = new MobileSessionRequest("viewer-1", viewerPhone.DeviceId, "ws-1", DG, "drive");
        Assert.False(rig.Auth.ValidateSessionStart(Scope, drive).Ok);
        // Approval attempt by the view-only operator refuses BEFORE
        // signature checks (no admin right).
        var req = rig.Approvals.CreateRequest(Scope, DG, "reboot ws-1", Admin, TimeSpan.FromHours(1), T0);
        var sig = Convert.ToBase64String(viewerPhone.Sign(
            MobileApprovalService.CanonicalMessage(req.Id, req.ActionHash, "approved")));
        Assert.False(rig.Approvals.Decide(req.Id, "viewer-1", viewerPhone.DeviceId, "approved", sig, T0).Ok);
    }

    [Fact]
    public void Attack_MobileScopeCreep_SuspensionKillsPhoneRightsLive()
    {
        var rig = Rig();
        rig.RegisterPhone();
        Assert.True(rig.Auth.Can(Scope, Op, rig.PhoneIdentity.DeviceId, "start_session", DG));
        Assert.True(rig.Roster.SetUserSuspended(Scope, Op, true));
        Assert.False(rig.Auth.Can(Scope, Op, rig.PhoneIdentity.DeviceId, "start_session", DG));
        Assert.False(rig.Auth.Can(Scope, Op, rig.PhoneIdentity.DeviceId, "browse_roster", DG));
    }

    [Fact]
    public void Attack_MobileRegistration_CrossScopePhone_Refused()
    {
        var rig = Rig();
        rig.Roster.CreateScope("co-2", "company", "Other");
        rig.Roster.CreateDeviceGroup("dg-foreign", "co-2", "Foreign");
        var foreign = new DeviceIdentity(new DevOnlyPassThroughProtector());
        rig.EnrollDevice(foreign, "foreign-phone", "dg-foreign");
        var (reg, _) = rig.RegisterClientSelf(Op, foreign);
        Assert.Null(reg);
    }
}
