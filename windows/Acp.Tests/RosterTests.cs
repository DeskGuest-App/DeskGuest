using System.Text.Json;
using Acp.Shared.Enrollment;
using Acp.Shared.Roster;
using Acp.Shared.Security;

namespace Acp.Tests;

/// <summary>Slice 2 — roster &amp; groups. Every test cites the
/// decision (BUILD-PROGRAMME / BRAINSTORM-REMOTE D-number) it
/// enforces in its name.</summary>
public class RosterTests
{
    private sealed class World
    {
        public required EnrollmentService Enrollments { get; init; }
        public required RosterService Roster { get; init; }
    }

    private static World Setup()
    {
        var enrollments = new EnrollmentService();
        var roster = new RosterService(enrollments);
        Assert.NotNull(roster.CreateScope("personal-1", "personal", "Personal"));
        Assert.NotNull(roster.CreateScope("company-1", "company", "Company A"));
        Assert.NotNull(roster.CreateUser("owner", "personal-1", "Owner One", "human"));
        return new World { Enrollments = enrollments, Roster = roster };
    }

    private static User AddUser(World w, string id, string scope = "company-1", string kind = "human", string? pairedBy = null)
    {
        var user = w.Roster.CreateUser(id, scope, "User " + id, kind, pairedBy);
        Assert.NotNull(user);
        return user!;
    }

    private static User AddCompanyAdmin(World w, string id)
    {
        var user = AddUser(w, id);
        Assert.True(w.Roster.AddCompanyAdmin("company-1", id));
        return user;
    }

    private static EnrolledDevice Enroll(World w, string scopeKind, string groupId, string name = "Device")
    {
        var identity = new DeviceIdentity(new DevOnlyPassThroughProtector());
        var code = w.Enrollments.CreateEnrollmentCode(scopeKind, groupId, "Group " + groupId);
        var enrolled = w.Enrollments.Redeem(code, new EnrollingDevice(identity.DeviceId, identity.PublicKeyBase64, name));
        Assert.NotNull(enrolled);
        return enrolled!;
    }

    // ---- D8: scope isolation -------------------------------------------------

    [Fact]
    public void ScopeIsolation_CompanyQueriesNeverReturnPersonalRecords_D8()
    {
        var w = Setup();
        AddUser(w, "tech");
        Assert.NotNull(w.Roster.CreateUserGroup("ug-personal", "personal-1", "Mine", new[] { "owner" }, new[] { "owner" }));
        Assert.NotNull(w.Roster.CreateUserGroup("ug-company", "company-1", "Techs", new[] { "tech" }));
        Assert.NotNull(w.Roster.CreateDeviceGroup("dg-personal", "personal-1", "Home PCs"));
        Assert.NotNull(w.Roster.CreateDeviceGroup("dg-company", "company-1", "Fleet"));
        Assert.NotNull(w.Roster.AddGrant("personal-1", "ug-personal", "dg-personal", new[] { "use" }));
        Assert.NotNull(w.Roster.AddGrant("company-1", "ug-company", "dg-company", new[] { "use" }));

        var users = w.Roster.ListUsers("company-1");
        Assert.All(users, u => Assert.Equal("company-1", u.ScopeId));
        Assert.DoesNotContain(users, u => u.Id == "owner");
        Assert.All(w.Roster.ListUserGroups("company-1"), g => Assert.Equal("company-1", g.ScopeId));
        Assert.All(w.Roster.ListDeviceGroups("company-1"), g => Assert.Equal("company-1", g.ScopeId));
        Assert.All(w.Roster.ListGrants("company-1"), g => Assert.Equal("company-1", g.ScopeId));
        Assert.DoesNotContain(w.Roster.ListGrants("company-1"), g => g.UserGroupId == "ug-personal");

        // The full operator roster of the company scope is equally walled.
        var roster = w.Roster.OperatorRoster("company-1");
        Assert.NotNull(roster);
        Assert.DoesNotContain(roster!.Users, u => u.ScopeId == "personal-1");
        Assert.DoesNotContain(roster.UserGroups, g => g.Id == "ug-personal");
        Assert.DoesNotContain(roster.DeviceGroups, g => g.Id == "dg-personal");
        Assert.DoesNotContain(roster.Grants, g => g.DeviceGroupId == "dg-personal");
    }

    [Fact]
    public void ScopeIsolation_OperatorRosterDevices_OnlyOwnScopeGroups_D8()
    {
        var w = Setup();
        Assert.NotNull(w.Roster.CreateDeviceGroup("dg-personal", "personal-1", "Home PCs"));
        Assert.NotNull(w.Roster.CreateDeviceGroup("dg-company", "company-1", "Fleet"));
        var personalDevice = Enroll(w, "personal", "dg-personal", "Home PC");
        var companyDevice = Enroll(w, "company", "dg-company", "Site PC");

        var companyRoster = w.Roster.OperatorRoster("company-1")!;
        Assert.Single(companyRoster.Devices);
        Assert.Equal(companyDevice.DeviceId, companyRoster.Devices[0].DeviceId);

        var personalRoster = w.Roster.OperatorRoster("personal-1")!;
        Assert.Single(personalRoster.Devices);
        Assert.Equal(personalDevice.DeviceId, personalRoster.Devices[0].DeviceId);
    }

    [Fact]
    public void CreateUser_AiOwnedAcrossScopes_Refused_D8_D9()
    {
        var w = Setup();
        // "owner" exists only in the personal scope; an AI in the
        // company scope cannot be owned across the wall.
        Assert.Null(w.Roster.CreateUser("ai-x", "company-1", "AI X", "ai", pairedByUserId: "owner"));
        // A human carrying a pairing owner is malformed (D9 field is AI-only).
        Assert.Null(w.Roster.CreateUser("h-x", "company-1", "H", "human", pairedByUserId: "owner"));
    }

    // ---- D9: AI can never hold an admin seat -----------------------------------

    [Fact]
    public void AiUser_CannotHoldCompanyAdminSeat_D9()
    {
        var w = Setup();
        AddCompanyAdmin(w, "admin");
        AddUser(w, "ai-1", kind: "ai", pairedBy: "admin");
        Assert.False(w.Roster.AddCompanyAdmin("company-1", "ai-1"));
        Assert.DoesNotContain("ai-1", w.Roster.CompanyAdmins("company-1"));
        Assert.False(w.Roster.IsScopeAdmin("company-1", "ai-1"));
    }

    [Fact]
    public void AiUser_CannotHoldUserGroupAdminSeat_D9()
    {
        var w = Setup();
        var admin = AddCompanyAdmin(w, "admin");
        AddUser(w, "ai-1", kind: "ai", pairedBy: "admin");
        // Refused at creation...
        Assert.Null(w.Roster.CreateUserGroup("ug-ai", "company-1", "Nope",
            memberUserIds: new[] { "admin", "ai-1" }, adminUserIds: new[] { "ai-1" }));
        // ...and refused by appointment.
        var group = w.Roster.CreateUserGroup("ug-1", "company-1", "Techs", new[] { "admin", "ai-1" });
        Assert.NotNull(group);
        Assert.False(w.Roster.AddUserGroupAdmin("company-1", "ug-1", "ai-1", admin.Id));
        Assert.DoesNotContain("ai-1", w.Roster.GetUserGroup("company-1", "ug-1")!.AdminUserIds);
    }

    [Fact]
    public void AiUser_NeverHoldsAdminRight_EvenViaGrant_D9()
    {
        var w = Setup();
        AddCompanyAdmin(w, "admin");
        AddUser(w, "ai-1", kind: "ai", pairedBy: "admin");
        Assert.NotNull(w.Roster.CreateUserGroup("ug-1", "company-1", "Techs", new[] { "ai-1" }));
        Assert.NotNull(w.Roster.CreateDeviceGroup("dg-1", "company-1", "Fleet"));
        Assert.NotNull(w.Roster.AddGrant("company-1", "ug-1", "dg-1", new[] { "use", "enroll", "admin" }));
        // Use/enroll flow through membership + grant; admin never does for an AI.
        Assert.True(w.Roster.UserHasRight("company-1", "ai-1", "dg-1", "use"));
        Assert.True(w.Roster.UserHasRight("company-1", "ai-1", "dg-1", "enroll"));
        Assert.False(w.Roster.UserHasRight("company-1", "ai-1", "dg-1", "admin"));
        Assert.False(w.Roster.HasAdminRight("company-1", "ai-1", deviceGroupId: "dg-1"));
    }

    // ---- D26/D13: peer company admins, last-admin guard, step-up -----------------

    [Fact]
    public void LastCompanyAdmin_CannotBeRemoved_D26()
    {
        var w = Setup();
        var admin = AddCompanyAdmin(w, "admin");
        Assert.False(w.Roster.RemoveCompanyAdmin("company-1", "admin", admin.Id));
        Assert.False(w.Roster.RemoveCompanyAdmin("company-1", "admin", admin.Id, stepUp: true));
        Assert.Contains("admin", w.Roster.CompanyAdmins("company-1"));
    }

    [Fact]
    public void RemoveFellowCompanyAdmin_RequiresStepUp_AndWritesEvent_D26_D13()
    {
        var w = Setup();
        var a = AddCompanyAdmin(w, "admin-a");
        AddCompanyAdmin(w, "admin-b");
        // No step-up: refused, seat intact, no event.
        Assert.False(w.Roster.RemoveCompanyAdmin("company-1", "admin-b", a.Id, stepUp: false));
        Assert.Contains("admin-b", w.Roster.CompanyAdmins("company-1"));
        // A non-admin actor is refused even with step-up.
        AddUser(w, "member");
        Assert.False(w.Roster.RemoveCompanyAdmin("company-1", "admin-b", "member", stepUp: true));
        // Step-up from a peer admin: fires, and the audit-shaped event exists.
        Assert.True(w.Roster.RemoveCompanyAdmin("company-1", "admin-b", a.Id, stepUp: true));
        Assert.DoesNotContain("admin-b", w.Roster.CompanyAdmins("company-1"));
        Assert.Contains(w.Roster.ListEvents("company-1"),
            e => e.Kind == "company_admin_removed" && e.SubjectId == "admin-b" && e.ActorUserId == "admin-a");
    }

    [Fact]
    public void CompanyAdmin_SelfRemoval_AllowedWhenNotLast_D26()
    {
        var w = Setup();
        var a = AddCompanyAdmin(w, "admin-a");
        AddCompanyAdmin(w, "admin-b");
        Assert.True(w.Roster.RemoveCompanyAdmin("company-1", "admin-a", a.Id)); // not a *fellow* removal: no step-up needed
        Assert.DoesNotContain("admin-a", w.Roster.CompanyAdmins("company-1"));
    }

    // ---- D12/D7: grants -------------------------------------------------------------

    [Fact]
    public void Grant_MembershipPlusGrant_GivesRights_D12_D7()
    {
        var w = Setup();
        AddCompanyAdmin(w, "admin");
        AddUser(w, "member");
        AddUser(w, "outsider");
        Assert.NotNull(w.Roster.CreateUserGroup("ug-1", "company-1", "Techs", new[] { "member" }));
        Assert.NotNull(w.Roster.CreateDeviceGroup("dg-1", "company-1", "Fleet"));
        Assert.NotNull(w.Roster.AddGrant("company-1", "ug-1", "dg-1", new[] { "use", "enroll" }));

        Assert.True(w.Roster.UserHasRight("company-1", "member", "dg-1", "use"));
        Assert.True(w.Roster.UserHasRight("company-1", "member", "dg-1", "enroll"));
        Assert.False(w.Roster.UserHasRight("company-1", "member", "dg-1", "admin")); // not in the grant
        Assert.False(w.Roster.UserHasRight("company-1", "outsider", "dg-1", "use")); // no membership
        Assert.True(w.Roster.UserHasRight("company-1", "admin", "dg-1", "admin")); // company admin holds all
    }

    [Fact]
    public void Grant_InvalidOrCrossScope_Refused_D12_D8()
    {
        var w = Setup();
        Assert.NotNull(w.Roster.CreateUserGroup("ug-1", "company-1", "Techs"));
        Assert.NotNull(w.Roster.CreateUserGroup("ug-p", "personal-1", "Mine"));
        Assert.NotNull(w.Roster.CreateDeviceGroup("dg-1", "company-1", "Fleet"));
        Assert.Null(w.Roster.AddGrant("company-1", "ug-1", "dg-1", new[] { "use", "destroy" })); // unknown right
        Assert.Null(w.Roster.AddGrant("company-1", "ug-1", "dg-1", Array.Empty<string>())); // empty rights
        Assert.Null(w.Roster.AddGrant("company-1", "ug-p", "dg-1", new[] { "use" })); // user group of another scope
        Assert.Empty(w.Roster.ListGrants("company-1"));
    }

    // ---- D5/D6/D7: structural acts are admin-gated --------------------------------------

    [Fact]
    public void StructuralActs_RegularMemberCannotDeleteGroups_D5_D6_D7()
    {
        var w = Setup();
        AddCompanyAdmin(w, "admin");
        AddUser(w, "member");
        Assert.NotNull(w.Roster.CreateUserGroup("ug-1", "company-1", "Techs", new[] { "member" }));
        Assert.NotNull(w.Roster.CreateDeviceGroup("dg-1", "company-1", "Fleet"));

        Assert.False(w.Roster.DeleteUserGroup("company-1", "ug-1", "member"));
        Assert.False(w.Roster.DeleteDeviceGroup("company-1", "dg-1", "member"));
        Assert.False(w.Roster.RemoveUserGroupMember("company-1", "ug-1", "member", "member"));
        Assert.NotNull(w.Roster.GetUserGroup("company-1", "ug-1"));
        Assert.NotNull(w.Roster.GetDeviceGroup("company-1", "dg-1"));

        // The company admin can do all three.
        Assert.True(w.Roster.RemoveUserGroupMember("company-1", "ug-1", "member", "admin"));
        Assert.True(w.Roster.DeleteDeviceGroup("company-1", "dg-1", "admin"));
        Assert.True(w.Roster.DeleteUserGroup("company-1", "ug-1", "admin"));
    }

    [Fact]
    public void StructuralActs_GroupAdminWithAdminGrant_CanDeleteDeviceGroup_D7_D12()
    {
        var w = Setup();
        AddCompanyAdmin(w, "admin");
        AddUser(w, "lead");
        AddUser(w, "plain");
        Assert.NotNull(w.Roster.CreateUserGroup("ug-leads", "company-1", "Leads",
            memberUserIds: new[] { "lead", "plain" }, adminUserIds: new[] { "lead" }));
        Assert.NotNull(w.Roster.CreateDeviceGroup("dg-1", "company-1", "Fleet"));
        Assert.NotNull(w.Roster.AddGrant("company-1", "ug-leads", "dg-1", new[] { "use", "admin" }));

        // A plain member of the same group still cannot; its group admin can.
        Assert.False(w.Roster.DeleteDeviceGroup("company-1", "dg-1", "plain"));
        Assert.True(w.Roster.DeleteDeviceGroup("company-1", "dg-1", "lead"));
    }

    [Fact]
    public void StructuralActs_PersonalOwnerIsAdminOfOwnGroups_D8_D5()
    {
        var w = Setup();
        Assert.NotNull(w.Roster.CreateDeviceGroup("dg-p", "personal-1", "Home PCs"));
        Assert.NotNull(w.Roster.CreateUserGroup("ug-p", "personal-1", "Mine", new[] { "owner" }, new[] { "owner" }));
        // No admin set exists in a personal scope; the owner is the admin.
        Assert.True(w.Roster.IsScopeAdmin("personal-1", "owner"));
        Assert.True(w.Roster.DeleteDeviceGroup("personal-1", "dg-p", "owner"));
        Assert.True(w.Roster.DeleteUserGroup("personal-1", "ug-p", "owner"));
    }

    [Fact]
    public void DeleteDevice_RequiresAdmin_AndRevokesEnrollment_D7()
    {
        var w = Setup();
        AddCompanyAdmin(w, "admin");
        AddUser(w, "member");
        Assert.NotNull(w.Roster.CreateDeviceGroup("dg-1", "company-1", "Fleet"));
        var device = Enroll(w, "company", "dg-1", "Site PC");

        Assert.False(w.Roster.DeleteDevice("company-1", device.DeviceId, "member"));
        Assert.False(w.Enrollments.List().Single().Revoked);
        // Cross-scope: the personal owner cannot delete a company device.
        Assert.False(w.Roster.DeleteDevice("personal-1", device.DeviceId, "owner"));

        Assert.True(w.Roster.DeleteDevice("company-1", device.DeviceId, "admin"));
        Assert.True(w.Enrollments.List().Single().Revoked);
    }

    // ---- D12: device-group membership derived from the enrollment roster ------------------

    [Fact]
    public void DeviceGroupMembership_DerivedFromEnrollmentRoster_D12()
    {
        var w = Setup();
        Assert.NotNull(w.Roster.CreateDeviceGroup("dg-1", "company-1", "Fleet"));
        Assert.NotNull(w.Roster.CreateDeviceGroup("dg-2", "company-1", "Other"));
        var a = Enroll(w, "company", "dg-1", "A");
        var b = Enroll(w, "company", "dg-1", "B");
        var c = Enroll(w, "company", "dg-2", "C");

        var members = w.Roster.DeviceGroupDeviceIds("company-1", "dg-1");
        Assert.Equal(new HashSet<string> { a.DeviceId, b.DeviceId }, new HashSet<string>(members));
        Assert.Equal(new[] { c.DeviceId }, w.Roster.DeviceGroupDeviceIds("company-1", "dg-2"));

        // Derived, not stored: revoking an enrollment shrinks membership
        // on the next read with no roster-side edit.
        Assert.True(w.Enrollments.Revoke(a.DeviceId));
        Assert.Equal(new[] { b.DeviceId }, w.Roster.DeviceGroupDeviceIds("company-1", "dg-1"));
    }

    // ---- D31/D32: transport resolution ------------------------------------------------------

    [Fact]
    public void TransportResolution_GroupOrderPreserved_ForInheritAndAuto_D32_D29()
    {
        var w = Setup();
        Assert.NotNull(w.Roster.CreateDeviceGroup("dg-1", "company-1", "Fleet",
            transportSet: new[] { "tor", "lan", "hub" }));
        var device = Enroll(w, "company", "dg-1");
        // inherit (the Slice 1 default) = the group's set, in the group's order.
        Assert.Equal(new[] { "tor", "lan", "hub" }, w.Roster.EffectiveTransportsForDevice(device.DeviceId));
        // auto = failover across the same set, same order.
        Assert.True(w.Roster.UpdateDeviceTransportPolicy(device.DeviceId, "auto", null));
        Assert.Equal(new[] { "tor", "lan", "hub" }, w.Roster.EffectiveTransportsForDevice(device.DeviceId));
    }

    [Fact]
    public void TransportResolution_CompanyCeilingIntersects_PreservingGroupOrder_D31_D32()
    {
        var w = Setup();
        Assert.NotNull(w.Roster.CreateDeviceGroup("dg-1", "company-1", "Fleet",
            transportSet: new[] { "tor", "lan", "hub", "mesh" }));
        var device = Enroll(w, "company", "dg-1");
        Assert.True(w.Roster.SetScopeTransportCeiling("company-1", new[] { "hub", "tor" }));
        // Intersection keeps the GROUP's order (tor before hub), not the ceiling's.
        Assert.Equal(new[] { "tor", "hub" }, w.Roster.EffectiveTransportsForDevice(device.DeviceId));
    }

    [Fact]
    public void TransportResolution_PersonalScopeIsUncapped_D31()
    {
        var w = Setup();
        Assert.NotNull(w.Roster.CreateDeviceGroup("dg-p", "personal-1", "Home",
            transportSet: new[] { "tor", "lan" }));
        var device = Enroll(w, "personal", "dg-p");
        Assert.False(w.Roster.SetScopeTransportCeiling("personal-1", new[] { "lan" })); // personal = no cap
        Assert.Null(w.Roster.GetScopeTransportCeiling("personal-1"));
        Assert.Equal(new[] { "tor", "lan" }, w.Roster.EffectiveTransportsForDevice(device.DeviceId));
    }

    [Fact]
    public void TransportResolution_ManualPinSubsetAccepted_InResolvedOrder_D32()
    {
        var w = Setup();
        Assert.NotNull(w.Roster.CreateDeviceGroup("dg-1", "company-1", "Fleet",
            transportSet: new[] { "tor", "lan", "hub" }));
        var device = Enroll(w, "company", "dg-1");
        // Pin given in the opposite order: resolution follows the group's order.
        Assert.True(w.Roster.UpdateDeviceTransportPolicy(device.DeviceId, "manual", new[] { "hub", "lan" }));
        Assert.Equal(new[] { "lan", "hub" }, w.Roster.EffectiveTransportsForDevice(device.DeviceId));
        var stored = w.Enrollments.List().Single();
        Assert.Equal("manual", stored.TransportMode);
        Assert.Equal(new HashSet<string> { "hub", "lan" }, stored.AllowedTransports);
    }

    [Fact]
    public void TransportResolution_ManualPinOutsideSet_RejectedAtUpdate_NeverWidened_D32()
    {
        var w = Setup();
        Assert.NotNull(w.Roster.CreateDeviceGroup("dg-1", "company-1", "Fleet",
            transportSet: new[] { "lan", "hub" }));
        var device = Enroll(w, "company", "dg-1");
        // "mesh" is a real rung but NOT in this group's set: rejected, device unchanged.
        Assert.False(w.Roster.UpdateDeviceTransportPolicy(device.DeviceId, "manual", new[] { "lan", "mesh" }));
        var stored = w.Enrollments.List().Single();
        Assert.Equal("inherit", stored.TransportMode);
        Assert.Empty(stored.AllowedTransports);
        Assert.Equal(new[] { "lan", "hub" }, w.Roster.EffectiveTransportsForDevice(device.DeviceId));
        // A non-rung pin and a bogus mode are refused too.
        Assert.False(w.Roster.UpdateDeviceTransportPolicy(device.DeviceId, "manual", new[] { "warp" }));
        Assert.False(w.Roster.UpdateDeviceTransportPolicy(device.DeviceId, "ludicrous", null));
    }

    [Fact]
    public void TransportResolution_ManualPinOutsideCeiling_RejectedAtUpdate_D31_D32()
    {
        var w = Setup();
        Assert.NotNull(w.Roster.CreateDeviceGroup("dg-1", "company-1", "Fleet",
            transportSet: new[] { "lan", "hub", "tor" }));
        var device = Enroll(w, "company", "dg-1");
        Assert.True(w.Roster.SetScopeTransportCeiling("company-1", new[] { "lan", "hub" }));
        // "tor" is in the group set but above the company ceiling: rejected.
        Assert.False(w.Roster.UpdateDeviceTransportPolicy(device.DeviceId, "manual", new[] { "tor" }));
        Assert.True(w.Roster.UpdateDeviceTransportPolicy(device.DeviceId, "manual", new[] { "hub" }));
        Assert.Equal(new[] { "hub" }, w.Roster.EffectiveTransportsForDevice(device.DeviceId));
    }

    [Fact]
    public void SetGroupTransports_RequiresAdminActor_D32()
    {
        var w = Setup();
        AddCompanyAdmin(w, "admin");
        AddUser(w, "member");
        Assert.NotNull(w.Roster.CreateDeviceGroup("dg-1", "company-1", "Fleet",
            transportSet: new[] { "lan", "hub" }));
        // Widening (or any change) by a non-admin is refused; the set is untouched.
        Assert.False(w.Roster.SetGroupTransports("company-1", "dg-1",
            new[] { "lan", "hub", "mesh", "ipv6", "ownpath", "tor" }, "member"));
        Assert.Equal(new[] { "lan", "hub" }, w.Roster.GetDeviceGroup("company-1", "dg-1")!.TransportSet);
        // An invalid rung is refused even for an admin.
        Assert.False(w.Roster.SetGroupTransports("company-1", "dg-1", new[] { "lan", "warp" }, "admin"));
        // The admin act itself works and preserves the chosen order.
        Assert.True(w.Roster.SetGroupTransports("company-1", "dg-1", new[] { "tor", "mesh", "lan" }, "admin"));
        Assert.Equal(new[] { "tor", "mesh", "lan" }, w.Roster.GetDeviceGroup("company-1", "dg-1")!.TransportSet);
    }

    [Fact]
    public void CreateDeviceGroup_InvalidRungOrDuplicateId_Refused_D32()
    {
        var w = Setup();
        Assert.Null(w.Roster.CreateDeviceGroup("dg-x", "company-1", "Bad", new[] { "lan", "warp" }));
        Assert.NotNull(w.Roster.CreateDeviceGroup("dg-1", "company-1", "Fleet"));
        // Device-group ids are global (Slice 1 enrollment binds by id alone):
        // the same id in another scope is refused.
        Assert.Null(w.Roster.CreateDeviceGroup("dg-1", "personal-1", "Copy"));
    }

    // ---- D14: offboarding (security-board S4 completeness) -------------------------------------

    /// <summary>A fully-loaded offboarding target: two user-group seats
    /// (one as admin), a company-admin seat, grants on both groups, a
    /// minted enrollment, and an owned AI pairing.</summary>
    private sealed class OffboardWorld
    {
        public required World W { get; init; }
        public required EnrolledDevice MintedDevice { get; init; }
        public required EnrolledDevice OtherDevice { get; init; }
    }

    private static OffboardWorld OffboardSetup()
    {
        var w = Setup();
        AddCompanyAdmin(w, "admin-a");
        AddCompanyAdmin(w, "admin-b");
        AddCompanyAdmin(w, "target"); // third peer admin: removal is not the last-admin case
        AddUser(w, "colleague");
        Assert.NotNull(w.Roster.CreateUserGroup("ug-1", "company-1", "Techs",
            memberUserIds: new[] { "target", "colleague" }));
        Assert.NotNull(w.Roster.CreateUserGroup("ug-2", "company-1", "Leads",
            memberUserIds: new[] { "colleague" }, adminUserIds: new[] { "target" }));
        Assert.NotNull(w.Roster.CreateDeviceGroup("dg-1", "company-1", "Fleet"));
        Assert.NotNull(w.Roster.AddGrant("company-1", "ug-1", "dg-1", new[] { "use", "enroll" }));
        Assert.NotNull(w.Roster.AddGrant("company-1", "ug-2", "dg-1", new[] { "admin" }));
        AddUser(w, "ai-1", kind: "ai", pairedBy: "target");
        AddUser(w, "ai-other", kind: "ai", pairedBy: "colleague");
        var minted = Enroll(w, "company", "dg-1", "Minted By Target");
        var other = Enroll(w, "company", "dg-1", "Minted By Colleague");
        Assert.True(w.Roster.RecordMintedEnrollment("company-1", "target", minted.DeviceId));
        Assert.True(w.Roster.RecordMintedEnrollment("company-1", "colleague", other.DeviceId));
        return new OffboardWorld { W = w, MintedDevice = minted, OtherDevice = other };
    }

    [Fact]
    public void Offboarding_BlastList_Complete_BeforeFire_D14()
    {
        var o = OffboardSetup();
        var w = o.W;
        var blast = w.Roster.PreviewRemoveUser("company-1", "target");
        Assert.NotNull(blast);
        Assert.Equal(new HashSet<string> { "ug-1", "ug-2" }, new HashSet<string>(blast!.UserGroupSeatIds));
        Assert.Equal(new[] { "ug-2" }, blast.UserGroupAdminSeatIds);
        Assert.True(blast.CompanyAdminSeat);
        Assert.Equal(2, blast.Grants.Count); // grants touching ug-1 and ug-2
        Assert.Equal(new[] { o.MintedDevice.DeviceId }, blast.MintedEnrollmentDeviceIds);
        Assert.Equal(new[] { "ai-1" }, blast.OwnedAiUserIds);
        Assert.True(blast.RequiresLiveSessionTermination);
        Assert.False(string.IsNullOrWhiteSpace(blast.LiveSessionRequirement));

        // Preview fires NOTHING: every fact is exactly as before.
        Assert.NotNull(w.Roster.GetUser("company-1", "target"));
        Assert.Contains("target", w.Roster.CompanyAdmins("company-1"));
        Assert.Contains("target", w.Roster.GetUserGroup("company-1", "ug-1")!.MemberUserIds);
        Assert.Contains("target", w.Roster.GetUserGroup("company-1", "ug-2")!.AdminUserIds);
        Assert.False(w.Enrollments.List().Single(d => d.DeviceId == o.MintedDevice.DeviceId).Revoked);
        Assert.False(w.Roster.GetUser("company-1", "ai-1")!.Suspended);
    }

    [Fact]
    public void Offboarding_Fire_RemovedUserProvablyLosesEverything_D14()
    {
        var o = OffboardSetup();
        var w = o.W;
        var blast = w.Roster.RemoveUser("company-1", "target", "admin-a", stepUp: true);
        Assert.NotNull(blast);

        // The user record and every seat are gone.
        Assert.Null(w.Roster.GetUser("company-1", "target"));
        Assert.DoesNotContain("target", w.Roster.CompanyAdmins("company-1"));
        Assert.DoesNotContain("target", w.Roster.GetUserGroup("company-1", "ug-1")!.MemberUserIds);
        Assert.DoesNotContain("target", w.Roster.GetUserGroup("company-1", "ug-2")!.MemberUserIds);
        Assert.DoesNotContain("target", w.Roster.GetUserGroup("company-1", "ug-2")!.AdminUserIds);
        // Every right the user held is gone with the seats.
        Assert.False(w.Roster.UserHasRight("company-1", "target", "dg-1", "use"));
        Assert.False(w.Roster.UserHasRight("company-1", "target", "dg-1", "enroll"));
        Assert.False(w.Roster.UserHasRight("company-1", "target", "dg-1", "admin"));
        Assert.False(w.Roster.HasAdminRight("company-1", "target", deviceGroupId: "dg-1"));
        // Enrollments they minted are revoked; a colleague's are untouched.
        Assert.True(w.Enrollments.List().Single(d => d.DeviceId == o.MintedDevice.DeviceId).Revoked);
        Assert.False(w.Enrollments.List().Single(d => d.DeviceId == o.OtherDevice.DeviceId).Revoked);
        Assert.Empty(w.Roster.ListMintedEnrollments("company-1", "target"));
        Assert.Single(w.Roster.ListMintedEnrollments("company-1", "colleague"));
        // Owned AI pairings are SUSPENDED, not deleted; others' AIs untouched.
        var ai = w.Roster.GetUser("company-1", "ai-1");
        Assert.NotNull(ai);
        Assert.True(ai!.Suspended);
        Assert.False(w.Roster.GetUser("company-1", "ai-other")!.Suspended);
        Assert.False(w.Roster.UserHasRight("company-1", "ai-1", "dg-1", "use")); // suspended holds nothing
        // Everyone else is untouched: admins, colleague's seats and grants stand.
        Assert.Contains("admin-a", w.Roster.CompanyAdmins("company-1"));
        Assert.Contains("admin-b", w.Roster.CompanyAdmins("company-1"));
        Assert.Contains("colleague", w.Roster.GetUserGroup("company-1", "ug-1")!.MemberUserIds);
        Assert.Equal(2, w.Roster.ListGrants("company-1").Count); // grants belong to groups, not the user
        // The offboarding event is recorded for the session layer to honor.
        Assert.Contains(w.Roster.ListEvents("company-1"),
            e => e.Kind == "user_removed" && e.SubjectId == "target" && e.ActorUserId == "admin-a");
        // A second removal finds nothing.
        Assert.Null(w.Roster.RemoveUser("company-1", "target", "admin-a", stepUp: true));
    }

    [Fact]
    public void Offboarding_LastCompanyAdmin_Refused_D14_D26()
    {
        var w = Setup();
        var solo = AddCompanyAdmin(w, "solo");
        AddUser(w, "member");
        // Even self-removal by the last admin is refused, step-up or not.
        Assert.Null(w.Roster.RemoveUser("company-1", "solo", solo.Id, stepUp: true));
        Assert.NotNull(w.Roster.GetUser("company-1", "solo"));
        Assert.Contains("solo", w.Roster.CompanyAdmins("company-1"));
    }

    [Fact]
    public void Offboarding_RemovingFellowAdmin_RequiresStepUp_D14_D26()
    {
        var o = OffboardSetup();
        var w = o.W;
        Assert.Null(w.Roster.RemoveUser("company-1", "target", "admin-a", stepUp: false));
        Assert.NotNull(w.Roster.GetUser("company-1", "target"));
        Assert.Contains("target", w.Roster.CompanyAdmins("company-1"));
    }

    [Fact]
    public void Offboarding_NonAdminActor_Refused_D13_D14()
    {
        var o = OffboardSetup();
        var w = o.W;
        Assert.Null(w.Roster.RemoveUser("company-1", "target", "colleague", stepUp: true));
        Assert.NotNull(w.Roster.GetUser("company-1", "target"));
    }

    [Fact]
    public void Offboarding_CrossScope_Refused_PersonalScopeUntouchable_D14_D8()
    {
        var o = OffboardSetup();
        var w = o.W;
        // A company offboarding can never touch the personal scope...
        Assert.Null(w.Roster.RemoveUser("personal-1", "owner", "admin-a", stepUp: true));
        Assert.NotNull(w.Roster.GetUser("personal-1", "owner"));
        // ...and a user id that exists only in the personal scope is not
        // removable through the company scope either.
        Assert.Null(w.Roster.RemoveUser("company-1", "owner", "admin-a", stepUp: true));
        Assert.NotNull(w.Roster.GetUser("personal-1", "owner"));
        // Nor can a personal-scope actor offboard a company user.
        Assert.Null(w.Roster.RemoveUser("company-1", "target", "owner", stepUp: true));
        Assert.NotNull(w.Roster.GetUser("company-1", "target"));
    }

    // ---- D2: endpoint view vs operator roster ----------------------------------------------

    [Fact]
    public void EndpointView_ContainsOnlyOwnDeviceReceiptsAndOperators_D2()
    {
        var w = Setup();
        Assert.NotNull(w.Roster.CreateDeviceGroup("dg-1", "company-1", "Fleet"));
        Assert.NotNull(w.Roster.CreateDeviceGroup("dg-2", "company-1", "Other"));
        var mine = Enroll(w, "company", "dg-1", "My Device");
        var other1 = Enroll(w, "company", "dg-1", "Other Device One");
        var other2 = Enroll(w, "company", "dg-2", "Other Device Two");
        w.Enrollments.RecordReceipt("Operator One", "operator-device-1", "company", "Fleet");

        var view = w.Roster.EndpointView(mine.DeviceId);
        Assert.NotNull(view);
        Assert.Equal(mine.DeviceId, view!.Device.DeviceId);
        Assert.Single(view.Receipts);
        Assert.Single(view.AllowedOperators);
        Assert.Equal("operator-device-1", view.AllowedOperators[0].EnrollerDeviceId);
        Assert.Equal("Operator One", view.AllowedOperators[0].EnrollerName);

        // Exhaustive: NOTHING of any other device exists anywhere in the shape.
        var json = JsonSerializer.Serialize(view);
        Assert.DoesNotContain(other1.DeviceId, json);
        Assert.DoesNotContain(other2.DeviceId, json);
        Assert.DoesNotContain("Other Device One", json);
        Assert.DoesNotContain("Other Device Two", json);
        Assert.DoesNotContain(other1.PublicKeyBase64, json);
        Assert.DoesNotContain(other2.PublicKeyBase64, json);

        // Contrast: the operator roster (operator side only) does see the fleet.
        Assert.Equal(3, w.Roster.OperatorRoster("company-1")!.Devices.Count);
        // Unknown device: no view at all.
        Assert.Null(w.Roster.EndpointView("no-such-device"));
    }

    // ---- persistence --------------------------------------------------------------------------

    [Fact]
    public void Persistence_RoundTrip_PreservesAllRecords()
    {
        var o = OffboardSetup();
        var w = o.W;
        Assert.True(w.Roster.SetScopeTransportCeiling("company-1", new[] { "lan", "tor" }));
        Assert.NotNull(w.Roster.CreateDeviceGroup("dg-ordered", "company-1", "Ordered",
            transportSet: new[] { "tor", "mesh", "lan" }));
        // One event beyond the setup's own, to prove events roundtrip too.
        Assert.True(w.Roster.SetGroupTransports("company-1", "dg-ordered", new[] { "mesh", "tor" }, "admin-a"));

        var restored = new RosterService(new EnrollmentService());
        var count = restored.ImportJson(w.Roster.ExportJson());
        Assert.True(count > 0);

        Assert.Equal(2, restored.ListScopes().Count);
        Assert.Equal(new[] { "lan", "tor" }, restored.GetScopeTransportCeiling("company-1"));
        Assert.Equal(w.Roster.ListUsers("company-1").Count, restored.ListUsers("company-1").Count);
        Assert.Equal(new HashSet<string> { "admin-a", "admin-b", "target" }, restored.CompanyAdmins("company-1"));
        var ug2 = restored.GetUserGroup("company-1", "ug-2")!;
        Assert.Contains("target", ug2.AdminUserIds);
        Assert.Contains("target", ug2.MemberUserIds); // group admins are members
        Assert.Equal(new[] { "mesh", "tor" }, restored.GetDeviceGroup("company-1", "dg-ordered")!.TransportSet);
        var grant = Assert.Single(restored.ListGrants("company-1"), g => g.UserGroupId == "ug-2");
        Assert.Equal(new HashSet<string> { "admin" }, grant.Rights);
        Assert.Single(restored.ListMintedEnrollments("company-1", "target"));
        Assert.Equal(w.Roster.ListEvents().Count, restored.ListEvents().Count);
        Assert.Equal("target", restored.GetUser("company-1", "ai-1")!.PairedByUserId);
    }

    [Fact]
    public void Persistence_MalformedEntries_Skipped_NeverFatal()
    {
        const string json = """
        {
          "Scopes": [
            {"Id":"company-1","Kind":"company","Name":"Company A","TransportCeiling":["lan","tor"]},
            {"Id":"bad-scope","Kind":"galactic","Name":"Nope","TransportCeiling":null}
          ],
          "Users": [
            {"Id":"admin","ScopeId":"company-1","DisplayName":"Admin","Kind":"human","PairedByUserId":null,"Suspended":false},
            {"Id":"robot","ScopeId":"company-1","DisplayName":"Robot","Kind":"robot","PairedByUserId":null,"Suspended":false},
            {"Id":"ghost","ScopeId":"nowhere","DisplayName":"Ghost","Kind":"human","PairedByUserId":null,"Suspended":false},
            {"Id":"ai1","ScopeId":"company-1","DisplayName":"AI","Kind":"ai","PairedByUserId":"admin","Suspended":false}
          ],
          "CompanyAdmins": [
            {"ScopeId":"company-1","UserId":"admin"},
            {"ScopeId":"company-1","UserId":"ai1"}
          ],
          "UserGroups": [
            {"Id":"ug1","ScopeId":"company-1","Name":"Techs","MemberUserIds":["admin","missing"],"AdminUserIds":["ai1"]}
          ],
          "DeviceGroups": [
            {"Id":"dg1","ScopeId":"company-1","Name":"Bad Rung","TransportSet":["lan","warp"]},
            {"Id":"dg2","ScopeId":"company-1","Name":"Fleet","TransportSet":["tor","lan"]}
          ],
          "Grants": [
            {"ScopeId":"company-1","UserGroupId":"ug1","DeviceGroupId":"dg2","Rights":["use","bogus"]},
            {"ScopeId":"company-1","UserGroupId":"ug1","DeviceGroupId":"dg1","Rights":["use"]}
          ],
          "Minted": [],
          "Events": []
        }
        """;
        var restored = new RosterService(new EnrollmentService());
        Assert.True(restored.ImportJson(json) > 0);

        Assert.NotNull(restored.GetScope("company-1"));
        Assert.Null(restored.GetScope("bad-scope")); // unknown kind skipped
        Assert.NotNull(restored.GetUser("company-1", "admin"));
        Assert.NotNull(restored.GetUser("company-1", "ai1"));
        Assert.Null(restored.GetUser("company-1", "robot")); // unknown kind skipped
        Assert.Null(restored.GetUser("company-1", "ghost")); // unknown scope skipped
        Assert.Equal(new HashSet<string> { "admin" }, restored.CompanyAdmins("company-1")); // AI admin dropped (D9)
        var ug = restored.GetUserGroup("company-1", "ug1")!;
        Assert.Equal(new HashSet<string> { "admin" }, ug.MemberUserIds); // missing member dropped
        Assert.Empty(ug.AdminUserIds); // AI group admin dropped (D9)
        Assert.Null(restored.GetDeviceGroup("company-1", "dg1")); // non-rung transport set skipped
        Assert.Equal(new[] { "tor", "lan" }, restored.GetDeviceGroup("company-1", "dg2")!.TransportSet);
        var grant = Assert.Single(restored.ListGrants("company-1")); // grant to the skipped group dropped
        Assert.Equal("dg2", grant.DeviceGroupId);
        Assert.Equal(new HashSet<string> { "use" }, grant.Rights); // bogus right filtered

        // Wholly malformed JSON restores nothing and does not throw.
        Assert.Equal(0, new RosterService().ImportJson("{not json"));
        Assert.Equal(0, new RosterService().ImportJson(""));
    }

    [Fact]
    public void Changed_FiresOnMutations()
    {
        var enrollments = new EnrollmentService();
        var roster = new RosterService(enrollments);
        var fired = 0;
        roster.Changed += () => fired++;
        roster.CreateScope("company-1", "company", "Company A");
        roster.CreateUser("admin", "company-1", "Admin", "human");
        roster.AddCompanyAdmin("company-1", "admin");
        roster.CreateDeviceGroup("dg-1", "company-1", "Fleet");
        Assert.Equal(4, fired);
    }
}
