using DeskGuest.Core.Services;
using DeskGuest.Shared.DirectoryEnrollment;
using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.Enrollment;
using DeskGuest.Shared.Inventory;
using DeskGuest.Shared.ManagementPolicy;
using DeskGuest.Shared.Monitoring;
using DeskGuest.Shared.Roster;
using DeskGuest.Shared.Security;

namespace DeskGuest.Tests;

// RMM-24 D38 FIX — regression tests for the cross-review packet
// 919332a7 findings F1–F12. Every test names the finding it pins;
// several are re-attacks of the original attack in the finding's
// own shape.
public class Rmm24D38FixTests
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

    // ---- F1: directory → roster deletion --------------------------------

    [Fact]
    public void F1_MissingDirectoryGroup_FlagsNobody_BaselinePreserved()
    {
        var rig = Rig();
        rig.SyncOneOffer(); // baseline: Tech is a member
        // The group vanishes from the snapshot entirely (transient
        // read failure / rename / wipe).
        rig.Directory.Groups.Clear();
        var outcome = rig.Engine.Sync(T0.AddHours(1));
        Assert.Equal(0, outcome.DeparturesFlagged);
        Assert.Empty(rig.Engine.Flags);
        Assert.Empty(rig.Offboarding.Initiated);
        Assert.NotNull(rig.Roster.GetUser(Scope, Tech));
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "directory_group_missing");
        // Baseline survived: when the group returns WITHOUT Tech,
        // the departure is now flagged (proof the missing-group
        // sync did not silently reset the baseline to empty).
        rig.Directory.Groups.Add(new DirectoryGroup(DirGroup, "Techs", Array.Empty<string>()));
        var outcome2 = rig.Engine.Sync(T0.AddHours(2));
        Assert.Equal(1, outcome2.DeparturesFlagged);
    }

    [Fact]
    public void F1_ScopeAdminDeparture_NeverInitiated_AdminSurvives()
    {
        var rig = Rig();
        // Admin is a member of UG (group admins are members) — put
        // them in the directory group too, sync a baseline, then
        // remove them: the poisoned-directory admin-deletion path.
        rig.Directory.Groups[0] = rig.Directory.Groups[0] with
        {
            MemberUserIds = new[] { Tech, Admin },
        };
        rig.AdmitMapping();
        rig.Engine.Sync(T0);
        rig.Directory.RemoveMember(DirGroup, Admin);
        var outcome = rig.Engine.Sync(T0.AddHours(1));
        Assert.Equal(1, outcome.DeparturesFlagged); // flagged for a HUMAN decision
        var flag = Assert.Single(rig.Engine.Flags);
        Assert.False(flag.Initiated); // never auto-initiated
        Assert.DoesNotContain(rig.Offboarding.Initiated, f => f.UserId == Admin);
        Assert.NotNull(rig.Roster.GetUser(Scope, Admin)); // admin NOT deleted
        Assert.Contains("SCOPE ADMIN", flag.Reason);
    }

    [Fact]
    public void F1_CoreInitiator_NoFabricatedStepUp_FellowAdminRemovalRefusedByD14()
    {
        var rig = Rig();
        rig.Roster.CreateUser("admin-2", Scope, "Admin Two", "human");
        rig.Roster.AddCompanyAdmin(Scope, "admin-2");
        var initiator = new RosterOffboardingInitiator(rig.Roster, _ => "admin-2");
        // Fellow-admin removal without a human step-up: D14 refuses.
        var adminFlag = new OffboardingFlag("f-a", Scope, Admin, "map-1", DirGroup,
            Array.Empty<string>(), T0, "left directory group", false);
        Assert.False(initiator.Initiate(adminFlag, T0));
        Assert.NotNull(rig.Roster.GetUser(Scope, Admin));
        // An ordinary user's removal still proceeds through D14.
        var techFlag = new OffboardingFlag("f-t", Scope, Tech, "map-1", DirGroup,
            Array.Empty<string>(), T0, "left directory group", false);
        Assert.True(initiator.Initiate(techFlag, T0));
        Assert.Null(rig.Roster.GetUser(Scope, Tech));
    }

    [Fact]
    public void F1_Departure_KillsOnlyEngineMintedCodes_UsersOwnCodesSurvive()
    {
        var rig = Rig();
        var offer = rig.SyncOneOffer();
        var offerCode = rig.Delivery.CodeFor(offer.Id)!;
        // A code Tech minted THEMSELVES (e.g. from the desktop) —
        // the old unscoped kill destroyed these too.
        var ownCode = rig.Enrollments.CreateEnrollmentCode("company", DG, "Workstations",
            mintedByUserId: Tech);
        rig.Directory.RemoveMember(DirGroup, Tech);
        rig.Engine.Sync(T0.AddHours(1));
        Assert.Equal(1, rig.Engine.Flags.Count);
        // Engine-minted offer code: dead.
        Assert.Null(rig.Enrollments.Redeem(offerCode,
            new EnrollingDevice(rig.EndpointIdentity.DeviceId, rig.EndpointIdentity.PublicKeyBase64, "ws-1")));
        // Tech's own code: untouched by the directory sync (it is
        // D14's business at removal time, not the sync's).
        var own = rig.Enrollments.Redeem(ownCode,
            new EnrollingDevice(rig.EndpointIdentity.DeviceId, rig.EndpointIdentity.PublicKeyBase64, "ws-1"));
        Assert.NotNull(own);
    }

    [Fact]
    public void F1_Departure_UserOutsideMappedUserGroup_NotFlagged()
    {
        var rig = Rig();
        rig.Roster.CreateUser("outsider-1", Scope, "Outsider", "human");
        rig.Directory.Groups[0] = rig.Directory.Groups[0] with
        {
            MemberUserIds = new[] { Tech, "outsider-1" },
        };
        // Disabled mapping: no offers exist, so eligibility can only
        // come from mapped-user-group membership.
        var (ok, reason) = rig.Engine.SetMapping(rig.Mapping(enabled: false), Admin, stepUp: false, T0);
        Assert.True(ok, reason);
        rig.Engine.Sync(T0);
        rig.Directory.RemoveMember(DirGroup, "outsider-1");
        rig.Directory.RemoveMember(DirGroup, Tech);
        var outcome = rig.Engine.Sync(T0.AddHours(1));
        Assert.Equal(1, outcome.DeparturesFlagged); // Tech only
        Assert.DoesNotContain(rig.Engine.Flags, f => f.UserId == "outsider-1");
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "directory_departure_ignored");
    }

    // ---- F2: mode normalization ------------------------------------------

    [Fact]
    public void F2_SessionStart_ModeCaseVariants_CannotCreepToDrive()
    {
        var rig = Rig();
        rig.Roster.CreateUser("viewer-1", Scope, "Viewer", "human");
        rig.Roster.CreateUserGroup("ug-view", Scope, "Viewers", new[] { "viewer-1" });
        rig.Roster.AddGrant(Scope, "ug-view", DG, new[] { "view" });
        var viewerPhone = new DeviceIdentity(new DevOnlyPassThroughProtector());
        rig.EnrollDevice(viewerPhone, "viewer-phone");
        Assert.NotNull(rig.RegisterClientSelf("viewer-1", viewerPhone).Registration);
        foreach (var mode in new[] { "Drive", "DRIVE", " drive ", "dRiVe" })
        {
            var req = new MobileSessionRequest("viewer-1", viewerPhone.DeviceId, "ws-1", DG, mode);
            Assert.False(rig.Auth.ValidateSessionStart(Scope, req).Ok, $"mode '{mode}' crept to drive");
        }
        // And the operator WITH the use right is authorized under
        // any casing — the same normalized mode drives both checks.
        rig.RegisterPhone();
        var drive = new MobileSessionRequest(Op, rig.PhoneIdentity.DeviceId, "ws-1", DG, "DRIVE");
        Assert.True(rig.Auth.ValidateSessionStart(Scope, drive).Ok);
    }

    // ---- F3: registration root --------------------------------------------

    [Fact]
    public void F3_Register_NoProofOrStrangerActorOrOthersDevice_Refused()
    {
        var rig = Rig();
        var device = rig.EnrollDevice(rig.PhoneIdentity, "op-phone");
        // (a) No device-key proof at all.
        Assert.Null(rig.Clients.Register(Scope, Op, device.DeviceId, Op, null, T0).Registration);
        // (b) A proof signed by a DIFFERENT key.
        var stranger = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var wrongProof = Convert.ToBase64String(stranger.Sign(
            MobileClientRegistry.CanonicalRegistrationMessage(Scope, Op, device.DeviceId)));
        Assert.Null(rig.Clients.Register(Scope, Op, device.DeviceId, Op, wrongProof, T0).Registration);
        // (c) Valid device proof, but the ACTOR is a stranger: Tech
        // tries to bind Op to a device (Tech is neither Op nor an
        // admin).
        var proof = Convert.ToBase64String(rig.PhoneIdentity.Sign(
            MobileClientRegistry.CanonicalRegistrationMessage(Scope, Op, device.DeviceId)));
        Assert.Null(rig.Clients.Register(Scope, Op, device.DeviceId, Tech, proof, T0).Registration);
        // (d) The genuine self-registration lands.
        Assert.NotNull(rig.Clients.Register(Scope, Op, device.DeviceId, Op, proof, T0).Registration);
    }

    [Fact]
    public void F3_RebindToAnotherUser_SilentMoveRefused_AdminRebindAudited()
    {
        var rig = Rig();
        rig.RegisterPhone(); // phone bound to Op
        var proofForTech = Convert.ToBase64String(rig.PhoneIdentity.Sign(
            MobileClientRegistry.CanonicalRegistrationMessage(Scope, Tech, rig.PhoneIdentity.DeviceId)));
        // Tech (not a scope admin) cannot move Op's phone to Tech.
        Assert.Null(rig.Clients.Register(Scope, Tech, rig.PhoneIdentity.DeviceId, Tech, proofForTech, T0).Registration);
        Assert.Equal(Op, rig.Clients.For(rig.PhoneIdentity.DeviceId)!.UserId);
        // A scope admin CAN rebind — as a named, audited act.
        Assert.NotNull(rig.Clients.Register(Scope, Tech, rig.PhoneIdentity.DeviceId, Admin, proofForTech, T0).Registration);
        Assert.Equal(Tech, rig.Clients.For(rig.PhoneIdentity.DeviceId)!.UserId);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "mobile_client_rebound");
    }

    // ---- F4: live revocation -----------------------------------------------

    [Fact]
    public void F4_RevokedClientDevice_LosesEveryMobileRightLive()
    {
        var rig = Rig();
        rig.RegisterPhone();
        Assert.True(rig.Auth.Can(Scope, Op, rig.PhoneIdentity.DeviceId, "browse_roster", DG));
        Assert.True(rig.Enrollments.Revoke(rig.PhoneIdentity.DeviceId));
        // No Unregister call — revocation alone must bite everywhere.
        Assert.False(rig.Auth.Can(Scope, Op, rig.PhoneIdentity.DeviceId, "browse_roster", DG));
        Assert.False(rig.Auth.Can(Scope, Op, rig.PhoneIdentity.DeviceId, "start_session", DG));
        Assert.Null(rig.Auth.RosterFor(Scope, Op, rig.PhoneIdentity.DeviceId));
        var req = rig.Approvals.CreateRequest(Scope, DG, "reboot ws-1", Admin, TimeSpan.FromHours(1), T0);
        var sig = Convert.ToBase64String(rig.PhoneIdentity.Sign(
            MobileApprovalService.CanonicalMessage(req.Id, req.ActionHash, "approved")));
        Assert.False(rig.Approvals.Decide(req.Id, Op, rig.PhoneIdentity.DeviceId, "approved", sig, T0).Ok);
    }

    // ---- F5: cross-scope mapping takeover -----------------------------------

    [Fact]
    public void F5_MappingScopeRetarget_Refused_OriginalIntact()
    {
        var rig = Rig();
        rig.AdmitMapping();
        rig.Roster.CreateScope("co-2", "company", "Other");
        rig.Roster.CreateUser("admin-2", "co-2", "Admin Two", "human");
        rig.Roster.AddCompanyAdmin("co-2", "admin-2");
        rig.Roster.CreateDeviceGroup("dg-x", "co-2", "Foreign DG");
        rig.Roster.CreateUserGroup("ug-x", "co-2", "Foreign UG");
        // Scope B's admin submits scope A's mapping id with B's
        // scope, a higher revision and step-up.
        var takeover = new DirectoryGroupMapping("map-1", "co-2", DirGroup, "dg-x", "ug-x", true, 99);
        var (ok, reason) = rig.Engine.SetMapping(takeover, "admin-2", stepUp: true, T0);
        Assert.False(ok);
        Assert.Contains("cannot be retargeted", reason);
        var original = Assert.Single(rig.Engine.Mappings);
        Assert.Equal(Scope, original.ScopeId);
        Assert.Equal(DG, original.DeviceGroupId);
    }

    // ---- F6: dual control -----------------------------------------------------

    [Fact]
    public void F6_SelfApproval_Refused_SecondOperatorDecides()
    {
        var rig = Rig();
        rig.RegisterPhone();
        var req = rig.Approvals.CreateRequest(Scope, DG, "reboot ws-1", Op, TimeSpan.FromHours(1), T0);
        var sig = Convert.ToBase64String(rig.PhoneIdentity.Sign(
            MobileApprovalService.CanonicalMessage(req.Id, req.ActionHash, "approved")));
        var (ok, reason) = rig.Approvals.Decide(req.Id, Op, rig.PhoneIdentity.DeviceId, "approved", sig, T0);
        Assert.False(ok);
        Assert.Contains("cannot decide it", reason);
        Assert.Equal(MobileApprovalStates.Pending, rig.Approvals.Get(req.Id)!.State);
        // A second operator (Admin, own registered phone) decides.
        var adminPhone = new DeviceIdentity(new DevOnlyPassThroughProtector());
        rig.EnrollDevice(adminPhone, "admin-phone");
        Assert.NotNull(rig.RegisterClientSelf(Admin, adminPhone).Registration);
        var sig2 = Convert.ToBase64String(adminPhone.Sign(
            MobileApprovalService.CanonicalMessage(req.Id, req.ActionHash, "approved")));
        Assert.True(rig.Approvals.Decide(req.Id, Admin, adminPhone.DeviceId, "approved", sig2, T0).Ok);
    }

    // ---- F7: notification queue -------------------------------------------------

    private static (MobileNotificationQueue Queue, DeviceIdentity Hub) SignedQueue(Rmm24Tests.Rig rig)
    {
        var hub = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var queue = new MobileNotificationQueue(id => rig.HealthCentre.Get(id), rig.Audit, hub.PublicKey,
            rig.Auth, Scope,
            deviceGroupOf: id => id == "ws-1" ? DG : null,
            clientDeviceOf: userId => rig.Clients.ClientDeviceFor(userId));
        return (queue, hub);
    }

    [Fact]
    public void F7a_Notification_ForUnviewableDevice_Refused_BothPaths()
    {
        var rig = Rig();
        rig.RegisterPhone();
        // Hub-alert path: an alert on a device whose group the rig
        // cannot map for Op (no view right) never reaches the phone.
        var outcome = rig.HealthCentre.Raise("ws-secret", "disk-low", ConditionKinds.DiskLow,
            AlertSeverities.Warning, "disk low", "endpoint", TimeSpan.Zero, T0);
        Assert.NotNull(outcome.Alert);
        Assert.Null(rig.Notifications.EnqueueFromHubAlert(outcome.Alert!.AlertId, Op, T0).Notification);
        Assert.Empty(rig.Notifications.ForOperator(Op));
        // Signed path: genuine hub signature, unviewable device.
        var (queue, hub) = SignedQueue(rig);
        var sig = Convert.ToBase64String(hub.Sign(
            MobileNotificationQueue.CanonicalPayload("a9", "ws-secret", "warning", "x", Op)));
        Assert.Null(queue.EnqueueSigned("a9", "ws-secret", "warning", "x", Op, sig, T0).Notification);
    }

    [Fact]
    public void F7b_SignedPayload_IsBoundToItsOperator()
    {
        var rig = Rig();
        rig.RegisterPhone();
        var (queue, hub) = SignedQueue(rig);
        // Hub signed a payload FOR Op; presenting it FOR Tech fails
        // — the operator is inside the signed bytes.
        var sig = Convert.ToBase64String(hub.Sign(
            MobileNotificationQueue.CanonicalPayload("a1", "ws-1", "warning", "real text", Op)));
        Assert.Null(queue.EnqueueSigned("a1", "ws-1", "warning", "real text", Tech, sig, T0).Notification);
        Assert.NotNull(queue.EnqueueSigned("a1", "ws-1", "warning", "real text", Op, sig, T0).Notification);
    }

    [Fact]
    public void F7c_FieldShiftSignature_DoesNotVerify()
    {
        var rig = Rig();
        rig.RegisterPhone();
        var (queue, hub) = SignedQueue(rig);
        // v1 attack: a genuine signature over detail "real|text"
        // re-presented with the fields shifted across the '|'.
        var sig = Convert.ToBase64String(hub.Sign(
            MobileNotificationQueue.CanonicalPayload("a1", "ws-1", "warning", "real|text", Op)));
        Assert.Null(queue.EnqueueSigned("a1", "ws-1|warning", "real", "text", Op, sig, T0).Notification);
        // The genuine field split still verifies.
        Assert.NotNull(queue.EnqueueSigned("a1", "ws-1", "warning", "real|text", Op, sig, T0).Notification);
    }

    [Fact]
    public void F7d_MalformedSignature_RefusalIsAudited()
    {
        var rig = Rig();
        rig.RegisterPhone();
        var (queue, _) = SignedQueue(rig);
        var before = rig.Audit.Entries.Count(e => e.Kind == "mobile_notification_refused");
        Assert.Null(queue.EnqueueSigned("a1", "ws-1", "warning", "x", Op, "!!!not-base64!!!", T0).Notification);
        Assert.True(rig.Audit.Entries.Count(e => e.Kind == "mobile_notification_refused") > before);
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "mobile_notification_refused" && e.Detail.Contains("malformed"));
    }

    // ---- F8: per-scope policy -----------------------------------------------------

    [Fact]
    public void F8_PolicyGate_IsPerScope_DisablingOneScopeLeavesTheOther()
    {
        var rig = Rig();
        var disabled = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var engine = new DirectoryEnrollmentEngine(rig.Enrollments, rig.Roster, rig.Audit,
            rig.Directory, rig.Offboarding, s => !disabled.Contains(s), delivery: rig.Delivery);
        // Second scope with its own admin/groups/directory group.
        rig.Roster.CreateScope("co-2", "company", "Other");
        rig.Roster.CreateUser("admin-2", "co-2", "Admin Two", "human");
        rig.Roster.CreateUser("tech-2", "co-2", "Tech Two", "human");
        rig.Roster.AddCompanyAdmin("co-2", "admin-2");
        rig.Roster.CreateUserGroup("ug-2", "co-2", "Techs2", new[] { "tech-2" });
        rig.Roster.CreateDeviceGroup("dg-2", "co-2", "Servers");
        rig.Directory.Groups.Add(new DirectoryGroup("dir-2", "Techs2", new[] { "tech-2" }));
        Assert.True(engine.SetMapping(new DirectoryGroupMapping("map-1", Scope, DirGroup, DG, UG, true, 1), Admin, true, T0).Ok);
        Assert.True(engine.SetMapping(new DirectoryGroupMapping("map-2", "co-2", "dir-2", "dg-2", "ug-2", true, 1), "admin-2", true, T0).Ok);
        disabled.Add("co-2");
        var outcome = engine.Sync(T0);
        Assert.Equal(1, outcome.OffersCreated); // co-1 only
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "directory_sync_scope_skipped");
        disabled.Remove("co-2");
        var outcome2 = engine.Sync(T0.AddHours(1));
        Assert.Equal(1, outcome2.OffersCreated); // co-2 now syncs too
    }

    [Fact]
    public void F8_CoreService_MobileToggleOff_DoesNotDisableDirectoryPush()
    {
        var rig = Rig();
        var svc = new DirectoryEnrollmentService(rig.Enrollments, rig.Roster, rig.Audit,
            rig.Policy, rig.Directory, rig.Offboarding, rig.Delivery);
        Assert.True(svc.Engine.SetMapping(rig.Mapping(), Admin, stepUp: true, T0).Ok);
        rig.Policy.AddDocument(new ManagementPolicyDocument("mob-off", PolicyLevels.Org, Scope,
            new Dictionary<string, string> { [MobileOperatorPolicyKeys.Enabled] = "false" }, 1));
        // The mobile key is off; the directory key is untouched —
        // directory push must still run.
        Assert.Equal(1, svc.Sync(T0).OffersCreated);
    }

    // ---- F9: acceptance atomicity ---------------------------------------------------

    [Fact]
    public void F9_ConcurrentAcceptAndDecline_ExactlyOneOutcome()
    {
        for (var i = 0; i < 20; i++)
        {
            var rig = Rig();
            var offer = rig.SyncOneOffer();
            var code = rig.Delivery.CodeFor(offer.Id)!;
            var accept = Task.Run(() => rig.Engine.AcceptOffer(offer.Id, code,
                new EnrollingDevice(rig.EndpointIdentity.DeviceId, rig.EndpointIdentity.PublicKeyBase64, "ws-1"), T0));
            var decline = Task.Run(() => rig.Engine.DeclineOffer(offer.Id, Tech, T0));
            Task.WaitAll(accept, decline);
            var final = rig.Engine.Offers.Single();
            if (final.State == OfferStates.Declined)
            {
                // Decline won: NO enrollment may exist behind it.
                Assert.Empty(rig.Enrollments.List());
                Assert.Null(accept.Result.Device);
            }
            else
            {
                Assert.Equal(OfferStates.Accepted, final.State);
                Assert.Single(rig.Enrollments.List());
                Assert.False(decline.Result.Ok);
            }
        }
    }

    // ---- F10: persistence + re-provisioning --------------------------------------------

    [Fact]
    public void F10a_BaselineSurvivesRestart_DepartureDuringDowntimeFlagged()
    {
        var rig = Rig();
        rig.SyncOneOffer(); // baseline: Tech is a member
        var export = rig.Engine.ExportJson();
        var engine2 = new DirectoryEnrollmentEngine(new EnrollmentService(), rig.Roster, new ChainedAuditLog(),
            rig.Directory, new RecordingOffboardingInitiator(), delivery: new RecordingOfferDelivery());
        Assert.True(engine2.ImportJson(export) >= 2); // offer + baseline at least
        // bd-shared-plat-1/F7: mappings are persisted now — the
        // mapping survives the restart, so the old re-SetMapping
        // setup is not just unnecessary, it is refused as a stale
        // revision. Assert the restoration instead.
        Assert.Contains(engine2.Mappings, m => m.Id == rig.Mapping().Id);
        // Tech leaves the directory "during the downtime".
        rig.Directory.RemoveMember(DirGroup, Tech);
        var outcome = engine2.Sync(T0.AddDays(1));
        Assert.Equal(1, outcome.DeparturesFlagged);
    }

    [Fact]
    public void F10b_Reprovision_AdminClearsDeparture_OffersResume_NonAdminRefused()
    {
        var rig = Rig();
        rig.SyncOneOffer();
        rig.Directory.RemoveMember(DirGroup, Tech);
        rig.Engine.Sync(T0.AddHours(1));
        Assert.False(rig.Engine.HasLivePushRights(Scope, Tech));
        // A non-admin cannot clear the flag.
        Assert.False(rig.Engine.ReprovisionUser(Scope, Tech, Op, T0.AddHours(2)).Ok);
        Assert.False(rig.Engine.HasLivePushRights(Scope, Tech));
        // An admin re-provisions (re-hire): the block clears and a
        // fresh sync offers again.
        Assert.True(rig.Engine.ReprovisionUser(Scope, Tech, Admin, T0.AddHours(2)).Ok);
        Assert.True(rig.Engine.HasLivePushRights(Scope, Tech));
        rig.Directory.Groups[0] = rig.Directory.Groups[0] with { MemberUserIds = new[] { Tech } };
        var outcome = rig.Engine.Sync(T0.AddHours(3));
        Assert.Equal(1, outcome.OffersCreated);
    }

    // ---- F11: known-unmanaged identity ---------------------------------------------------

    [Fact]
    public void F11_KnownUnmanaged_NameSpoofDoesNotReconcile_IdMatchAndMirrorDo()
    {
        var register = new UnmanagedAssetRegister();
        var rig = Rig();
        var engine = new DirectoryEnrollmentEngine(rig.Enrollments, rig.Roster, rig.Audit,
            rig.Directory, rig.Offboarding, _ => true, register, rig.Delivery);
        // A directory machine whose id IS a real device identity,
        // plus the CEO's laptop (name-spoof target).
        var machineIdentity = new DeviceIdentity(new DevOnlyPassThroughProtector());
        rig.Directory.Machines.Add(new DirectoryMachine(machineIdentity.DeviceId, "ws-real", Tech, DirGroup));
        rig.Directory.Machines.Add(new DirectoryMachine("ceo-1", "CEO-LAPTOP", Tech, DirGroup));
        engine.Sync(T0);
        Assert.Equal(2, engine.KnownUnmanaged.Count);
        Assert.NotNull(register.Get(machineIdentity.DeviceId)); // mirrored
        // An enrolled endpoint calls ITSELF "CEO-LAPTOP": the real
        // machine's record must STAND (names are endpoint-supplied).
        rig.EnrollDevice(new DeviceIdentity(new DevOnlyPassThroughProtector()), "CEO-LAPTOP");
        engine.Sync(T0.AddHours(1));
        Assert.Contains(engine.KnownUnmanaged, k => k.MachineId == "ceo-1");
        Assert.Contains(rig.Audit.Entries, e => e.Kind == "directory_known_unmanaged_name_match_untrusted");
        // The real machine enrolls BY ID: record and mirror reconcile.
        rig.EnrollDevice(machineIdentity, "ws-real");
        engine.Sync(T0.AddHours(2));
        Assert.DoesNotContain(engine.KnownUnmanaged, k => k.MachineId == machineIdentity.DeviceId);
        Assert.Null(register.Get(machineIdentity.DeviceId));
        Assert.Contains(engine.KnownUnmanaged, k => k.MachineId == "ceo-1"); // still unmanaged, honestly
    }

    // ---- F12: attribution / roster gate / pruning ---------------------------------------------

    [Fact]
    public void F12a_EngineCodes_AreNotTheUsersOwnMint_UserNamespaceKillMissesThem()
    {
        var rig = Rig();
        var offer = rig.SyncOneOffer();
        var code = rig.Delivery.CodeFor(offer.Id)!;
        // Killing "codes minted by Tech" must NOT kill the engine's
        // offer code — the engine minted it, for Tech.
        Assert.Equal(0, rig.Enrollments.RevokePendingCodesMintedBy(Tech));
        var (device, _) = rig.Engine.AcceptOffer(offer.Id, code,
            new EnrollingDevice(rig.EndpointIdentity.DeviceId, rig.EndpointIdentity.PublicKeyBase64, "ws-1"), T0);
        Assert.NotNull(device);
    }

    [Fact]
    public void F12a_PersonalScopeMapping_MintsPersonalKindCodes()
    {
        var rig = Rig();
        rig.Roster.CreateScope("me-1", "personal", "Mine");
        rig.Roster.CreateUser("owner-1", "me-1", "Owner", "human");
        rig.Roster.CreateUserGroup("ug-me", "me-1", "Mine", new[] { "owner-1" });
        rig.Roster.CreateDeviceGroup("dg-me", "me-1", "My devices");
        rig.Directory.Groups.Add(new DirectoryGroup("dir-me", "Mine", new[] { "owner-1" }));
        var mapping = new DirectoryGroupMapping("map-me", "me-1", "dir-me", "dg-me", "ug-me", true, 1);
        Assert.True(rig.Engine.SetMapping(mapping, "owner-1", stepUp: true, T0).Ok);
        var outcome = rig.Engine.Sync(T0);
        Assert.Equal(1, outcome.OffersCreated);
        var offer = rig.Engine.Offers.Single(o => o.ScopeId == "me-1");
        var code = rig.Delivery.CodeFor(offer.Id)!;
        var (device, reason) = rig.Engine.AcceptOffer(offer.Id, code,
            new EnrollingDevice(rig.EndpointIdentity.DeviceId, rig.EndpointIdentity.PublicKeyBase64, "my-pc"), T0);
        Assert.NotNull(device);
        Assert.Equal("personal", device!.Scope); // not the hard-coded "company"
    }

    [Fact]
    public void F12b_RosterFor_SuspendedOperatorOrPolicyOff_GetsNothing()
    {
        var rig = Rig();
        rig.RegisterPhone();
        Assert.NotNull(rig.Auth.RosterFor(Scope, Op, rig.PhoneIdentity.DeviceId));
        Assert.True(rig.Roster.SetUserSuspended(Scope, Op, true));
        Assert.Null(rig.Auth.RosterFor(Scope, Op, rig.PhoneIdentity.DeviceId));
        Assert.True(rig.Roster.SetUserSuspended(Scope, Op, false));
        rig.PolicyOn = false;
        Assert.Null(rig.Auth.RosterFor(Scope, Op, rig.PhoneIdentity.DeviceId));
    }

    [Fact]
    public void F12c_TerminalRecords_ArePruned_LiveRecordsSurvive()
    {
        var rig = Rig();
        // Offers: a declined offer is pruned after retention; the
        // fresh live offer from the later sync survives.
        var offer = rig.SyncOneOffer();
        Assert.True(rig.Engine.DeclineOffer(offer.Id, Tech, T0).Ok);
        var outcome = rig.Engine.Sync(T0.AddDays(31));
        Assert.Equal(1, outcome.OffersCreated);
        Assert.DoesNotContain(rig.Engine.Offers, o => o.State == OfferStates.Declined);
        Assert.Single(rig.Engine.Offers);
        // Approvals: a decided request is pruned when a later
        // request is created past its retention.
        rig.RegisterPhone();
        var req = rig.Approvals.CreateRequest(Scope, DG, "reboot ws-1", Admin, TimeSpan.FromHours(1), T0);
        var sig = Convert.ToBase64String(rig.PhoneIdentity.Sign(
            MobileApprovalService.CanonicalMessage(req.Id, req.ActionHash, "approved")));
        Assert.True(rig.Approvals.Decide(req.Id, Op, rig.PhoneIdentity.DeviceId, "approved", sig, T0).Ok);
        rig.Approvals.CreateRequest(Scope, DG, "later", Admin, TimeSpan.FromHours(1), T0.AddDays(32));
        Assert.Null(rig.Approvals.Get(req.Id));
        // Notifications: an acknowledged notification is pruned
        // when a later one is enqueued past its retention.
        var raised = rig.HealthCentre.Raise("ws-1", "disk-low", ConditionKinds.DiskLow,
            AlertSeverities.Warning, "disk low", "endpoint", TimeSpan.Zero, T0);
        var (note, _) = rig.Notifications.EnqueueFromHubAlert(raised.Alert!.AlertId, Op, T0);
        Assert.NotNull(note);
        Assert.True(rig.Notifications.MarkDelivered(note!.Id, MobileNotificationTransports.HubDirect.Id, true, T0).Ok);
        Assert.True(rig.Notifications.Acknowledge(note.Id, Op, T0));
        var raised2 = rig.HealthCentre.Raise("ws-1", "cpu-high", ConditionKinds.CpuHigh,
            AlertSeverities.Warning, "cpu hot", "endpoint", TimeSpan.Zero, T0.AddDays(31));
        Assert.NotNull(raised2.Alert);
        Assert.NotNull(rig.Notifications.EnqueueFromHubAlert(raised2.Alert!.AlertId, Op, T0.AddDays(31)).Notification);
        Assert.DoesNotContain(rig.Notifications.ForOperator(Op), n => n.Id == note.Id);
    }
}
