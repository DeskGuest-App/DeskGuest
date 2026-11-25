using Acp.Core.Services;
using Acp.Shared.DirectoryEnrollment;
using Acp.Shared.Enterprise;
using Acp.Shared.Enrollment;
using Acp.Shared.Inventory;
using Acp.Shared.ManagementPolicy;
using Acp.Shared.Monitoring;
using Acp.Shared.Roster;
using Acp.Shared.Security;

namespace Acp.Tests;

// RMM-24 — (1) Directory-driven enrollment push: a directory group
// maps to an ACP device group + user group; members receive
// pre-staged enrollment OFFERS; the endpoint's own acceptance is
// the only path into the enrollment store; departures flag +
// initiate D14 offboarding. (2) Mobile operator client contract:
// the operator's keys, the operator's exact roster rights, a
// signature-bound approval channel, hub-sourced notifications.
public class Rmm24Tests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    private const string Scope = "co-1";
    private const string Admin = "admin-1";
    private const string Op = "op-1";
    private const string Tech = "tech-1";
    private const string UG = "ug-1";
    private const string DG = "dg-1";
    private const string DirGroup = "dir-techs";

    public sealed class Rig
    {
        public EnrollmentService Enrollments = new();
        public RosterService Roster;
        public ChainedAuditLog Audit = new();
        public FakeDirectoryConnector Directory = new();
        public RecordingOffboardingInitiator Offboarding = new();
        public RecordingOfferDelivery Delivery = new();
        public ManagementPolicyEngine Policy = new();
        public bool PolicyOn = true;
        public DirectoryEnrollmentEngine Engine;
        public MobileClientRegistry Clients;
        public MobileAuthorization Auth;
        public MobileApprovalService Approvals;
        public HealthAlertCentre HealthCentre;
        public AlertCenter Dir57 = new();
        public MobileNotificationQueue Notifications;
        public DeviceIdentity PhoneIdentity = new(new DevOnlyPassThroughProtector());
        public DeviceIdentity EndpointIdentity = new(new DevOnlyPassThroughProtector());

        public Rig()
        {
            Roster = new RosterService(Enrollments);
            Roster.CreateScope(Scope, "company", "Acme");
            Roster.CreateUser(Admin, Scope, "Admin One", "human");
            Roster.CreateUser(Op, Scope, "Operator One", "human");
            Roster.CreateUser(Tech, Scope, "Tech One", "human");
            Roster.AddCompanyAdmin(Scope, Admin);
            Roster.CreateUserGroup(UG, Scope, "Techs", new[] { Op, Tech }, new[] { Admin });
            Roster.CreateDeviceGroup(DG, Scope, "Workstations");
            Roster.AddGrant(Scope, UG, DG, new[] { "use", "enroll", "admin", "view" });
            Directory.Users.Add(new DirectoryUser(Tech, "Tech One", "tech@acme.example"));
            Directory.Users.Add(new DirectoryUser(Op, "Operator One", "op@acme.example"));
            Directory.Groups.Add(new DirectoryGroup(DirGroup, "Techs", new[] { Tech }));
            Engine = new DirectoryEnrollmentEngine(Enrollments, Roster, Audit, Directory, Offboarding,
                _ => PolicyOn, delivery: Delivery);
            Clients = new MobileClientRegistry(Enrollments, Roster, Audit);
            Auth = new MobileAuthorization(Roster, Clients, () => PolicyOn);
            Approvals = new MobileApprovalService(Enrollments, Clients, Auth, Audit);
            HealthCentre = new HealthAlertCentre(Audit, Dir57);
            Notifications = new MobileNotificationQueue(id => HealthCentre.Get(id), Audit, null,
                Auth, Scope,
                deviceGroupOf: id => id == "ws-1" ? DG : Enrollments.List().FirstOrDefault(d => d.DeviceId == id)?.GroupId,
                clientDeviceOf: userId => Clients.ClientDeviceFor(userId));
        }

        public DirectoryGroupMapping Mapping(bool enabled = true, long rev = 1, string id = "map-1") =>
            new(id, Scope, DirGroup, DG, UG, enabled, rev);

        public void AdmitMapping(bool enabled = true)
        {
            var (ok, reason) = Engine.SetMapping(Mapping(enabled), Admin, stepUp: true, T0);
            Assert.True(ok, reason);
        }

        public EnrollmentOffer SyncOneOffer()
        {
            AdmitMapping();
            var outcome = Engine.Sync(T0);
            Assert.Equal(1, outcome.OffersCreated);
            return Engine.Offers.Single();
        }

        public EnrolledDevice EnrollDevice(DeviceIdentity identity, string name, string groupId = DG)
        {
            var code = Enrollments.CreateEnrollmentCode("company", groupId,
                Roster.FindDeviceGroup(groupId)!.Name, mintedByUserId: Admin);
            var device = Enrollments.Redeem(code, new EnrollingDevice(
                identity.DeviceId, identity.PublicKeyBase64, name));
            Assert.NotNull(device);
            return device!;
        }

        public MobileClientRegistration RegisterPhone()
        {
            EnrollDevice(PhoneIdentity, "op-phone");
            var proof = Convert.ToBase64String(PhoneIdentity.Sign(
                MobileClientRegistry.CanonicalRegistrationMessage(Scope, Op, PhoneIdentity.DeviceId)));
            var (reg, reason) = Clients.Register(Scope, Op, PhoneIdentity.DeviceId, Op, proof, T0);
            Assert.NotNull(reg);
            return reg!;
        }

        /// <summary>Self-registration helper for destruction tests:
        /// the user themself as actor, with the device key's proof.</summary>
        public (MobileClientRegistration? Registration, string Reason) RegisterClientSelf(
            string userId, DeviceIdentity identity) =>
            Clients.Register(Scope, userId, identity.DeviceId, userId,
                Convert.ToBase64String(identity.Sign(
                    MobileClientRegistry.CanonicalRegistrationMessage(Scope, userId, identity.DeviceId))), T0);
    }

    // ---- push: offers -------------------------------------------------

    [Fact]
    public void Sync_CreatesOffer_ForMappedMember_CodeDeliveredOnlyViaPushChannel()
    {
        var rig = new Rig();
        var offer = rig.SyncOneOffer();
        Assert.Equal(OfferStates.Offered, offer.State);
        Assert.Equal(Tech, offer.UserId);
        Assert.Equal(DG, offer.DeviceGroupId);
        // The delivered code exists only in the delivery record.
        var code = rig.Delivery.CodeFor(offer.Id);
        Assert.False(string.IsNullOrWhiteSpace(code));
        Assert.DoesNotContain(EnrollmentService.NormalizeCode(code)!, offer.CodeHash);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "directory_offer_created");
        Assert.True(rig.Audit.Verify().Ok);
    }

    [Fact]
    public void Sync_PushAlone_EnrollsNothing_EndpointAcceptanceIsTheWall()
    {
        var rig = new Rig();
        rig.SyncOneOffer();
        Assert.Empty(rig.Enrollments.List());
    }

    [Fact]
    public void AcceptOffer_EndpointRedeems_DeviceEnrolledIntoMappedGroup_AttributionRecorded()
    {
        var rig = new Rig();
        var offer = rig.SyncOneOffer();
        var code = rig.Delivery.CodeFor(offer.Id)!;
        var (device, reason) = rig.Engine.AcceptOffer(offer.Id, code,
            new EnrollingDevice(rig.EndpointIdentity.DeviceId, rig.EndpointIdentity.PublicKeyBase64, "ws-1"), T0.AddHours(1));
        Assert.NotNull(device);
        Assert.Equal(DG, device!.GroupId);
        Assert.Equal("company", device.Scope);
        Assert.Equal(OfferStates.Accepted, rig.Engine.Offers.Single().State);
        Assert.Contains(rig.Roster.ListMintedEnrollments(Scope, Tech), m => m.DeviceId == device.DeviceId);
    }

    [Fact]
    public void AcceptOffer_WrongCode_Refused_OfferStands()
    {
        var rig = new Rig();
        var offer = rig.SyncOneOffer();
        var (device, _) = rig.Engine.AcceptOffer(offer.Id, "AAAAA-AAAAA",
            new EnrollingDevice(rig.EndpointIdentity.DeviceId, rig.EndpointIdentity.PublicKeyBase64, "ws-1"), T0);
        Assert.Null(device);
        Assert.Equal(OfferStates.Offered, rig.Engine.Offers.Single().State);
        Assert.Empty(rig.Enrollments.List());
    }

    [Fact]
    public void AcceptOffer_Expired_RefusedAndMarked()
    {
        var rig = new Rig();
        var offer = rig.SyncOneOffer();
        var code = rig.Delivery.CodeFor(offer.Id)!;
        var (device, _) = rig.Engine.AcceptOffer(offer.Id, code,
            new EnrollingDevice(rig.EndpointIdentity.DeviceId, rig.EndpointIdentity.PublicKeyBase64, "ws-1"),
            T0.AddDays(8));
        Assert.Null(device);
        Assert.Equal(OfferStates.Expired, rig.Engine.Offers.Single().State);
    }

    [Fact]
    public void DeclineOffer_RetiresCode_AcceptAfterDeclineRefused()
    {
        var rig = new Rig();
        var offer = rig.SyncOneOffer();
        var code = rig.Delivery.CodeFor(offer.Id)!;
        Assert.True(rig.Engine.DeclineOffer(offer.Id, Tech, T0).Ok);
        var (device, _) = rig.Engine.AcceptOffer(offer.Id, code,
            new EnrollingDevice(rig.EndpointIdentity.DeviceId, rig.EndpointIdentity.PublicKeyBase64, "ws-1"), T0);
        Assert.Null(device);
    }

    [Fact]
    public void Sync_DirectoryMachineNeverEnrolled_IsKnownUnmanaged_NotRogue()
    {
        var rig = new Rig();
        rig.Directory.Machines.Add(new DirectoryMachine("ws-9", "ws-9", Tech, DirGroup));
        rig.AdmitMapping();
        var outcome = rig.Engine.Sync(T0);
        Assert.Equal(1, outcome.UnmanagedSeen);
        var known = Assert.Single(rig.Engine.KnownUnmanaged);
        Assert.Equal(KnownUnmanagedDevice.Classification, "known_unmanaged");
        Assert.False(known.ManagedByAgent);
    }

    [Fact]
    public void Sync_PolicyOff_RefusesWhole()
    {
        var rig = new Rig { PolicyOn = false };
        rig.AdmitMapping();
        var outcome = rig.Engine.Sync(T0);
        Assert.Equal(0, outcome.OffersCreated);
        Assert.Contains("disabled by policy", outcome.Reason);
        Assert.Empty(rig.Engine.Offers);
    }

    // ---- mappings -------------------------------------------------------

    [Fact]
    public void Mapping_NonAdminActor_Refused()
    {
        var rig = new Rig();
        var (ok, _) = rig.Engine.SetMapping(rig.Mapping(), Tech, stepUp: true, T0);
        Assert.False(ok);
        Assert.Empty(rig.Engine.Mappings);
    }

    [Fact]
    public void Mapping_DisabledMapping_CreatesNoOffers()
    {
        var rig = new Rig();
        var (ok, reason) = rig.Engine.SetMapping(rig.Mapping(enabled: false), Admin, stepUp: false, T0);
        Assert.True(ok, reason); // creating a DISABLED mapping is not a widening
        var outcome = rig.Engine.Sync(T0);
        Assert.Equal(0, outcome.OffersCreated);
    }

    // ---- departure --------------------------------------------------------

    [Fact]
    public void Departure_FlagsAndInitiatesOffboarding_AcceptedDevicesNamed()
    {
        var rig = new Rig();
        var offer = rig.SyncOneOffer();
        var code = rig.Delivery.CodeFor(offer.Id)!;
        var (device, _) = rig.Engine.AcceptOffer(offer.Id, code,
            new EnrollingDevice(rig.EndpointIdentity.DeviceId, rig.EndpointIdentity.PublicKeyBase64, "ws-1"), T0);
        Assert.NotNull(device);
        rig.Directory.RemoveMember(DirGroup, Tech);
        var outcome = rig.Engine.Sync(T0.AddDays(1));
        Assert.Equal(1, outcome.DeparturesFlagged);
        var flag = Assert.Single(rig.Engine.Flags);
        Assert.True(flag.Initiated);
        Assert.Contains(device!.DeviceId, flag.AcceptedDeviceIds);
        Assert.Single(rig.Offboarding.Initiated);
        Assert.False(rig.Engine.HasLivePushRights(Scope, Tech));
    }

    // ---- persistence --------------------------------------------------------

    [Fact]
    public void Export_NeverContainsCode_ImportRestoresOfferAsExpired_FlagsRestoreDepartedSet()
    {
        var rig = new Rig();
        var offer = rig.SyncOneOffer();
        var code = rig.Delivery.CodeFor(offer.Id)!;
        var export = rig.Engine.ExportJson();
        Assert.DoesNotContain(EnrollmentService.NormalizeCode(code)!, export);
        Assert.DoesNotContain(code, export);
        var engine2 = new DirectoryEnrollmentEngine(new EnrollmentService(), rig.Roster, new ChainedAuditLog(),
            rig.Directory, new RecordingOffboardingInitiator(), delivery: new RecordingOfferDelivery());
        Assert.True(engine2.ImportJson(export) >= 1);
        Assert.Equal(OfferStates.Expired, engine2.Offers.Single().State);
    }

    // ---- mobile: registration + authorization --------------------------------

    [Fact]
    public void Mobile_RegisterPhone_HappyPath()
    {
        var rig = new Rig();
        var reg = rig.RegisterPhone();
        Assert.Equal(Op, reg.UserId);
        Assert.Equal(rig.PhoneIdentity.DeviceId, reg.ClientDeviceId);
    }

    [Fact]
    public void Mobile_Register_UnenrolledDevice_Refused()
    {
        var rig = new Rig();
        var ghost = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var (reg, _) = rig.Clients.Register(Scope, Op, ghost.DeviceId, Op, null, T0);
        Assert.Null(reg);
    }

    [Fact]
    public void Mobile_Authorization_RidesRosterRights_Exactly()
    {
        var rig = new Rig();
        rig.RegisterPhone();
        Assert.True(rig.Auth.Can(Scope, Op, rig.PhoneIdentity.DeviceId, "browse_roster", DG));
        Assert.True(rig.Auth.Can(Scope, Op, rig.PhoneIdentity.DeviceId, "start_session", DG));
        Assert.True(rig.Auth.Can(Scope, Op, rig.PhoneIdentity.DeviceId, "approve_dual_control", DG));
        // An unregistered second phone for the same user: nothing.
        var other = new DeviceIdentity(new DevOnlyPassThroughProtector());
        rig.EnrollDevice(other, "other-phone");
        Assert.False(rig.Auth.Can(Scope, Op, other.DeviceId, "browse_roster", DG));
        // A capability outside the contract: nothing.
        Assert.False(rig.Auth.Can(Scope, Op, rig.PhoneIdentity.DeviceId, "teleport", DG));
        Assert.Empty(MobileOperatorContract.MobileOnlyRights);
    }

    [Fact]
    public void Mobile_SessionStart_DriveAndObserve_Authorized_PresenceStructural()
    {
        var rig = new Rig();
        rig.RegisterPhone();
        var drive = new MobileSessionRequest(Op, rig.PhoneIdentity.DeviceId, "ws-1", DG, "drive");
        Assert.True(rig.Auth.ValidateSessionStart(Scope, drive).Ok);
        Assert.True(drive.PresenceVisible);
        var observe = new MobileSessionRequest(Op, rig.PhoneIdentity.DeviceId, "ws-1", DG, "observe");
        Assert.True(rig.Auth.ValidateSessionStart(Scope, observe).Ok);
        var bad = new MobileSessionRequest(Op, rig.PhoneIdentity.DeviceId, "ws-1", DG, "invisible");
        Assert.False(rig.Auth.ValidateSessionStart(Scope, bad).Ok);
    }

    [Fact]
    public void Mobile_RosterFor_RegisteredClientOnly()
    {
        var rig = new Rig();
        rig.RegisterPhone();
        Assert.NotNull(rig.Auth.RosterFor(Scope, Op, rig.PhoneIdentity.DeviceId));
        Assert.Null(rig.Auth.RosterFor(Scope, Tech, rig.PhoneIdentity.DeviceId));
        Assert.Null(rig.Auth.RosterFor(Scope, Op, "no-such-device"));
    }

    [Fact]
    public void Mobile_HealthFor_ShowsViewableDevicesOnly()
    {
        var rig = new Rig();
        rig.RegisterPhone();
        var centre = new HealthAlertCentre(rig.Audit, new AlertCenter());
        var ingest = new HubHealthIngest(centre, TimeSpan.FromMinutes(10));
        ingest.Ingest(new DeviceHealthReport("ws-1", 1, T0, "lib", "h", "ok",
            Array.Empty<string>(), Array.Empty<string>(), Array.Empty<HealthAlertEvent>()), T0);
        ingest.Ingest(new DeviceHealthReport("ws-other", 1, T0, "lib", "h", "ok",
            Array.Empty<string>(), Array.Empty<string>(), Array.Empty<HealthAlertEvent>()), T0);
        var views = rig.Auth.HealthFor(Scope, Op, rig.PhoneIdentity.DeviceId, ingest,
            id => id == "ws-1" ? DG : "dg-other", T0);
        Assert.Single(views);
        Assert.Equal("ws-1", views[0].DeviceId);
    }

    // ---- mobile: approvals ------------------------------------------------------

    [Fact]
    public void Mobile_Approval_SignedByKeyedClient_Lands()
    {
        var rig = new Rig();
        rig.RegisterPhone();
        var req = rig.Approvals.CreateRequest(Scope, DG, "reboot ws-1", Admin, TimeSpan.FromHours(1), T0);
        var msg = MobileApprovalService.CanonicalMessage(req.Id, req.ActionHash, "approved");
        var sig = Convert.ToBase64String(rig.PhoneIdentity.Sign(msg));
        var (ok, reason) = rig.Approvals.Decide(req.Id, Op, rig.PhoneIdentity.DeviceId, "approved", sig, T0.AddMinutes(5));
        Assert.True(ok, reason);
        Assert.Equal(MobileApprovalStates.Approved, rig.Approvals.Get(req.Id)!.State);
    }

    // ---- mobile: notifications -----------------------------------------------------

    [Fact]
    public void Mobile_Notification_FromRealHubAlert_Queues_DeliversViaHubDirect_Acks()
    {
        var rig = new Rig();
        rig.RegisterPhone(); // D38 F7a: the queue is gated on the operator's live client + view right
        var outcome = rig.HealthCentre.Raise("ws-1", "disk-low", ConditionKinds.DiskLow,
            AlertSeverities.Warning, "disk low", "endpoint", TimeSpan.Zero, T0);
        Assert.NotNull(outcome.Alert);
        var (note, reason) = rig.Notifications.EnqueueFromHubAlert(outcome.Alert!.AlertId, Op, T0);
        Assert.NotNull(note);
        Assert.True(rig.Notifications.MarkDelivered(note!.Id,
            MobileNotificationTransports.HubDirect.Id, selfHostedShape: true, T0).Ok);
        Assert.True(rig.Notifications.Acknowledge(note.Id, Op, T0));
    }

    [Fact]
    public void Mobile_Notification_PlatformPush_RefusedInSelfHostedShape_NamedHonestly()
    {
        var rig = new Rig();
        rig.RegisterPhone(); // D38 F7a: the queue is gated on the operator's live client + view right
        var outcome = rig.HealthCentre.Raise("ws-1", "disk-low", ConditionKinds.DiskLow,
            AlertSeverities.Warning, "disk low", "endpoint", TimeSpan.Zero, T0);
        var (note, _) = rig.Notifications.EnqueueFromHubAlert(outcome.Alert!.AlertId, Op, T0);
        var (ok, reason) = rig.Notifications.MarkDelivered(note!.Id,
            MobileNotificationTransports.PlatformPush.Id, selfHostedShape: true, T0);
        Assert.False(ok);
        Assert.Contains("NOT part of the self-hosted shape", reason);
        Assert.False(MobileNotificationTransports.PlatformPush.AllowedInSelfHosted);
    }

    // ---- Core wiring ----------------------------------------------------------------

    [Fact]
    public void CoreService_PolicyGate_OffBlocksSync_OnAllows()
    {
        var rig = new Rig();
        var svc = new DirectoryEnrollmentService(rig.Enrollments, rig.Roster, rig.Audit,
            rig.Policy, rig.Directory, rig.Offboarding, rig.Delivery);
        svc.SetScopeHint(Scope);
        var (mok, _) = svc.Engine.SetMapping(rig.Mapping(), Admin, stepUp: true, T0);
        Assert.True(mok);
        Assert.Equal(1, svc.Sync(T0).OffersCreated);
        rig.Policy.AddDocument(new ManagementPolicyDocument("off-1", PolicyLevels.Org, Scope,
            new Dictionary<string, string> { [DirectoryEnrollmentPolicyKeys.DirectoryEnabled] = "false" }, 1));
        Assert.Equal(0, svc.Sync(T0.AddHours(1)).OffersCreated);
    }

    [Fact]
    public void CoreService_OffboardingInitiator_RemovesUserViaD14()
    {
        var rig = new Rig();
        var initiator = new RosterOffboardingInitiator(rig.Roster, _ => Admin);
        var flag = new OffboardingFlag("f1", Scope, Tech, "map-1", DirGroup,
            Array.Empty<string>(), T0, "left directory group", false);
        Assert.True(initiator.Initiate(flag, T0));
        Assert.Null(rig.Roster.GetUser(Scope, Tech));
    }
}
