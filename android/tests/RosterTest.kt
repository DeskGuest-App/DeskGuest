import io.deskguest.app.enrollment.DeviceIdentity
import io.deskguest.app.enrollment.EnrollmentStore
import io.deskguest.app.roster.RosterStore
import io.deskguest.app.roster.TransportPolicy
import java.io.File
import java.nio.file.Files

/**
 * JVM tests for Slice 2 (roster & groups). Every check cites the
 * decision it enforces:
 * - D8 scope isolation / the wall (incl. cross-scope refusals)
 * - D9 AI users can never hold an admin seat or admin right
 * - D26/D13 peer company admins, last-admin guard, step-up removal
 * - D12/D7 user groups x device groups x grants; structural acts
 *   are grant/company-admin gated; membership derived from Slice 1
 * - D31/D32 transport resolution: order, company-ceiling
 *   intersection, pin subset accepted / outside-set pin rejected at
 *   update time, transport-set changes are admin-only
 * - D14 offboarding: blast list first (complete, non-firing), then
 *   fire effects; personal scope untouchable. The after-fire checks
 *   double as the security-board S4 offboarding-completeness proof:
 *   the removed user provably retains nothing in the scope.
 * - D2 endpoint view exhaustiveness vs operator roster
 * - Persistence: TSV roundtrip, corrupt lines skipped, no secret
 */
private var failures = 0

private fun check(name: String, condition: Boolean) {
    if (condition) println("PASS  $name")
    else {
        println("FAIL  $name")
        failures++
    }
}

private fun newStores(dir: File, tag: String): Pair<RosterStore, EnrollmentStore> {
    val enrollment = EnrollmentStore(File(dir, "$tag-enroll.tsv"))
    val roster = RosterStore(File(dir, "$tag-roster.tsv"), enrollment)
    return roster to enrollment
}

private fun enroll(
    enrollment: EnrollmentStore, scopeKind: String, groupId: String, groupName: String, displayName: String
): String {
    val identity = DeviceIdentity.generate()
    val code = enrollment.mint(scopeKind, groupId, groupName)
    val enrolled = enrollment.redeem(
        code,
        EnrollmentStore.EnrollingDevice(identity.deviceId, identity.publicKeyBase64, displayName)
    )
    check("setup: enrollment of $displayName succeeds", enrolled != null)
    return identity.deviceId
}

/** A company scope "co" with admin1 seated, plus a personal scope. */
private fun basicCompany(roster: RosterStore) {
    check("D8 add company scope", roster.addScope(RosterStore.Scope("co", "company", "Acme Co")))
    check("D8 add personal scope", roster.addScope(RosterStore.Scope("pers", "personal", "Mine")))
    check("D8 duplicate scope id refused", !roster.addScope(RosterStore.Scope("co", "company", "Again")))
    check("D8 unknown scope kind refused", !roster.addScope(RosterStore.Scope("x", "galaxy", "Nope")))
    check("setup: add admin1", roster.addUser(RosterStore.User("admin1", "co", "Admin One", "human")))
    check("setup: seat admin1 (bootstrap)", roster.addCompanyAdmin("co", "admin1"))
}

fun main() {
    val dir = Files.createTempDirectory("deskguest-roster-test").toFile()

    // ================= D8 scope isolation =================
    run {
        val (roster, _) = newStores(dir, "iso")
        basicCompany(roster)
        check("setup: add co member", roster.addUser(RosterStore.User("mem1", "co", "Member One", "human")))
        check("setup: add personal owner", roster.addUser(RosterStore.User("owner", "pers", "Owner", "human")))
        check("D8 usersInScope returns only that scope's users",
            roster.usersInScope("co").map { it.id } == listOf("admin1", "mem1") &&
                roster.usersInScope("pers").map { it.id } == listOf("owner"))
        check("D8 user from another scope is invisible by scope query",
            roster.usersInScope("pers").none { it.id == "mem1" })
        check("D8 AI paired by a user in ANOTHER scope refused",
            !roster.addUser(RosterStore.User("aiX", "co", "AI X", "ai", pairedByUserId = "owner")))
        check("D8 AI with unknown pairing owner refused",
            !roster.addUser(RosterStore.User("aiY", "co", "AI Y", "ai", pairedByUserId = "ghost")))
        check("D9 human carrying a pairing owner refused",
            !roster.addUser(RosterStore.User("h2", "co", "H Two", "human", pairedByUserId = "admin1")))
        check("D8 user added to an unknown scope refused",
            !roster.addUser(RosterStore.User("h3", "nowhere", "H Three", "human")))
        check("setup: personal owner is sole admin of personal scope",
            roster.addCompanyAdmin("pers", "owner"))
        check("D8/D13 personal scope refuses a second admin seat",
            roster.addUser(RosterStore.User("memP", "pers", "Second", "human")) &&
                !roster.addCompanyAdmin("pers", "memP", actorUserId = "owner"))
        // Cross-scope group references refused.
        check("setup: co user group by admin",
            roster.addUserGroup(RosterStore.UserGroup("ug-co", "co", "Techs", memberUserIds = setOf("mem1")), "admin1"))
        check("D8 adding a personal-scope user to a company group refused",
            !roster.addUserToGroup("co", "ug-co", "owner", "admin1"))
        check("D8 company admin of one scope is not admin of another",
            !roster.isCompanyAdmin("pers", "admin1") && !roster.isCompanyAdmin("co", "owner"))
    }

    // ================= D9 AI never admin; D26/D13 admins =================
    run {
        val (roster, _) = newStores(dir, "admins")
        basicCompany(roster)
        check("setup: add human2", roster.addUser(RosterStore.User("admin2", "co", "Admin Two", "human")))
        check("setup: add AI paired by admin1",
            roster.addUser(RosterStore.User("ai1", "co", "Helper AI", "ai", pairedByUserId = "admin1")))
        check("D9 AI cannot be seated as company admin",
            !roster.addCompanyAdmin("co", "ai1", actorUserId = "admin1") &&
                "ai1" !in roster.companyAdmins("co"))
        check("D9 AI cannot be created as a user-group admin",
            !roster.addUserGroup(
                RosterStore.UserGroup("ug-ai", "co", "AI Led", memberUserIds = setOf("ai1"), adminUserIds = setOf("ai1")),
                "admin1"
            ))
        check("setup: user group with the AI as plain member",
            roster.addUserGroup(RosterStore.UserGroup("ug1", "co", "Techs", memberUserIds = setOf("ai1", "admin2")), "admin1"))
        check("D9 AI cannot be appointed user-group admin after creation",
            !roster.addUserGroupAdmin("co", "ug1", "ai1", "admin1"))
        check("D26 last company admin cannot be removed",
            !roster.removeCompanyAdmin("co", "admin1", actorUserId = "admin1", stepUp = true) &&
                roster.isCompanyAdmin("co", "admin1"))
        check("D13 seating a second admin requires an existing admin actor",
            !roster.addCompanyAdmin("co", "admin2", actorUserId = "admin2") &&
                roster.addCompanyAdmin("co", "admin2", actorUserId = "admin1"))
        check("D13/D26 removing a fellow admin without step-up refused",
            !roster.removeCompanyAdmin("co", "admin2", actorUserId = "admin1", stepUp = false) &&
                roster.isCompanyAdmin("co", "admin2"))
        check("D13/D26 removing a fellow admin with step-up succeeds",
            roster.removeCompanyAdmin("co", "admin2", actorUserId = "admin1", stepUp = true) &&
                !roster.isCompanyAdmin("co", "admin2"))
        check("D13 step-up admin removal writes an audit-shaped event",
            roster.events().any { it.type == RosterStore.EVENT_ADMIN_REMOVED && it.subjectId == "admin2" })
        check("D26 non-admin cannot unseat an admin",
            !roster.removeCompanyAdmin("co", "admin1", actorUserId = "admin2", stepUp = true))
    }

    // ================= D12/D7 groups, grants, structural acts =================
    run {
        val (roster, enrollment) = newStores(dir, "grants")
        basicCompany(roster)
        roster.addUser(RosterStore.User("mem1", "co", "Member One", "human"))
        roster.addUser(RosterStore.User("mem2", "co", "Member Two", "human"))
        roster.addUser(RosterStore.User("ai1", "co", "Helper AI", "ai", pairedByUserId = "mem1"))
        check("D13 group creation by a non-admin refused",
            !roster.addUserGroup(RosterStore.UserGroup("ug1", "co", "Techs"), "mem1"))
        check("D12 user group created by company admin",
            roster.addUserGroup(
                RosterStore.UserGroup("ug1", "co", "Techs", memberUserIds = setOf("mem1", "ai1")), "admin1"
            ))
        check("D12 second user group created",
            roster.addUserGroup(RosterStore.UserGroup("ug2", "co", "Leads", memberUserIds = setOf("mem2")), "admin1"))
        check("D13 device group creation by a non-admin refused",
            !roster.addDeviceGroup(RosterStore.DeviceGroup("dg1", "co", "Fleet"), "mem1"))
        check("D12/D32 device group created with an ordered transport set",
            roster.addDeviceGroup(
                RosterStore.DeviceGroup("dg1", "co", "Fleet", listOf("lan", "hub", "tor")), "admin1"
            ) && roster.deviceGroup("dg1")!!.transportSet == listOf("lan", "hub", "tor"))
        check("D32 device group with a non-rung transport refused",
            !roster.addDeviceGroup(RosterStore.DeviceGroup("dgBad", "co", "Bad", listOf("lan", "warp")), "admin1"))
        check("setup: second device group",
            roster.addDeviceGroup(RosterStore.DeviceGroup("dg2", "co", "Site", listOf("lan", "mesh")), "admin1"))

        check("D12 grant creation by a non-admin refused",
            !roster.addGrant(RosterStore.Grant("co", "ug1", "dg1", setOf("use")), "mem1"))
        check("D12 grant with an unknown right refused",
            !roster.addGrant(RosterStore.Grant("co", "ug1", "dg1", setOf("fly")), "admin1"))
        check("D12 grant use+enroll created by company admin",
            roster.addGrant(RosterStore.Grant("co", "ug1", "dg1", setOf("use", "enroll")), "admin1"))
        check("D7 member of a granted user group can use + enroll",
            roster.canUse("co", "mem1", "dg1") && roster.canEnroll("co", "mem1", "dg1"))
        check("D7 member cannot administer without the admin right",
            !roster.canAdministerDeviceGroup("co", "mem1", "dg1"))
        check("D7 non-member has no rights on the device group",
            roster.rightsFor("co", "mem2", "dg1").isEmpty() && !roster.canUse("co", "mem2", "dg1"))
        check("D8 member sees only device groups their groups are granted",
            roster.visibleDeviceGroupsForUser("co", "mem1").map { it.id } == listOf("dg1") &&
                roster.visibleDeviceGroupsForUser("co", "admin1").map { it.id } == listOf("dg1", "dg2"))
        // D9 backstop: even with an admin grant on its group, an AI holds no admin right.
        check("setup: admin grant to the group containing the AI",
            roster.addGrant(RosterStore.Grant("co", "ug1", "dg2", setOf("use", "admin")), "admin1"))
        check("D9 AI's effective rights never contain admin, even via an admin grant",
            RosterStore.RIGHT_ADMIN !in roster.rightsFor("co", "ai1", "dg2") &&
                roster.canUse("co", "ai1", "dg2") &&
                !roster.canAdministerDeviceGroup("co", "ai1", "dg2"))

        // Membership derived from the Slice 1 enrollment roster (D12).
        val devA = enroll(enrollment, "company", "dg1", "Fleet", "Device A")
        val devB = enroll(enrollment, "company", "dg2", "Site", "Device B")
        check("D12 device-group membership derives from the enrollment roster (mint-bound group)",
            roster.deviceGroupMemberIds("co", "dg1") == listOf(devA) &&
                roster.deviceGroupMemberIds("co", "dg2") == listOf(devB))
        check("D12 membership of an unknown/other-scope group is empty",
            roster.deviceGroupMemberIds("pers", "dg1").isEmpty())
        check("setup: revoke device B directly in the enrollment roster", enrollment.revoke(devB))
        check("D12 revoked devices drop out of derived membership",
            roster.deviceGroupMemberIds("co", "dg2").isEmpty())

        // Structural acts are grant/company-admin gated (D7/D12).
        check("D7 delete device by a use-only member refused",
            !roster.deleteDevice("co", devA, "mem1") && enrollment.byId(devA)?.revoked == false)
        check("D7 delete device group by a use-only member refused",
            !roster.deleteDeviceGroup("co", "dg1", "mem1") && roster.deviceGroup("dg1") != null)
        check("D7 delete user group by a plain member refused",
            !roster.deleteUserGroup("co", "ug1", "mem1") && roster.userGroup("ug1") != null)
        check("setup: company admin grants the admin right on dg1 to mem1's group",
            roster.addGrant(RosterStore.Grant("co", "ug1", "dg1", setOf("use", "enroll", "admin")), "admin1"))
        check("D7 delete device by the grant-admin member succeeds (revocation in the one roster)",
            roster.deleteDevice("co", devA, "mem1") && enrollment.byId(devA)?.revoked == true)
        check("D7 delete device group by a member holding an admin grant on it succeeds",
            roster.deleteDeviceGroup("co", "dg1", "mem1") && roster.deviceGroup("dg1") == null)
        check("D12 deleting a device group removes its grants",
            roster.grantsInScope("co").none { it.deviceGroupId == "dg1" })
        val devC = enroll(enrollment, "company", "dg2", "Site", "Device C")
        check("D7 delete device by company admin succeeds and revokes immediately",
            roster.deleteDevice("co", devC, "admin1") && enrollment.byId(devC)?.revoked == true)
        check("D7 delete user group by company admin succeeds",
            roster.deleteUserGroup("co", "ug2", "admin1") && roster.userGroup("ug2") == null)
    }

    // ================= D31/D32 transport resolution =================
    run {
        fun device(mode: String, allowed: Set<String>) = EnrollmentStore.EnrolledDevice(
            deviceId = "dev-t", displayName = "T", publicKeyBase64 = "AAAA",
            scope = "company", groupId = "dg", groupName = "G",
            enrolledAtMs = 1L, revoked = false, transportMode = mode, allowedTransports = allowed
        )
        val groupSet = listOf("lan", "hub", "mesh", "tor")
        check("D32 inherit keeps the group's ordered set",
            TransportPolicy.effectiveTransports(device("inherit", emptySet()), groupSet, null) == groupSet)
        check("D32 auto walks the group's set in its order",
            TransportPolicy.effectiveTransports(device("auto", emptySet()), groupSet, null) == groupSet)
        check("D31/D32 company ceiling intersects, preserving GROUP order (not ceiling order)",
            TransportPolicy.effectiveTransports(
                device("inherit", emptySet()), groupSet, listOf("tor", "mesh", "ipv6")
            ) == listOf("mesh", "tor"))
        check("D31 personal scope is uncapped (null ceiling = no intersection)",
            TransportPolicy.effectiveTransports(device("inherit", emptySet()), groupSet, null).size == 4)
        check("D32 manual pin resolves in the resolved set's order",
            TransportPolicy.effectiveTransports(device("manual", setOf("tor", "lan")), groupSet, null) ==
                listOf("lan", "tor"))
        check("D32 manual pin is capped by the ceiling before pinning",
            TransportPolicy.effectiveTransports(
                device("manual", setOf("tor", "lan")), groupSet, listOf("lan", "hub")
            ) == listOf("lan"))
        check("D32 pin subset of the resolved set is accepted",
            TransportPolicy.isPinWithinSet(setOf("lan", "tor"), groupSet, null))
        check("D32 pin outside the group set is not within the set",
            !TransportPolicy.isPinWithinSet(setOf("ipv6"), groupSet, null))
        check("D31 pin inside the group set but outside the company ceiling is not within the set",
            !TransportPolicy.isPinWithinSet(setOf("tor"), groupSet, listOf("lan", "hub")))
        check("D32 the six rungs are exactly the D32 enumeration",
            TransportPolicy.RUNGS == listOf("lan", "hub", "mesh", "ipv6", "ownpath", "tor"))
    }

    // Transport updates through the store: admin-gated set, pin rules.
    run {
        val (roster, enrollment) = newStores(dir, "transport")
        basicCompany(roster)
        roster.addUser(RosterStore.User("mem1", "co", "Member One", "human"))
        roster.addUserGroup(RosterStore.UserGroup("ug1", "co", "Techs", memberUserIds = setOf("mem1")), "admin1")
        roster.addDeviceGroup(RosterStore.DeviceGroup("dg1", "co", "Fleet", listOf("lan", "hub", "mesh")), "admin1")
        roster.addGrant(RosterStore.Grant("co", "ug1", "dg1", setOf("use", "enroll")), "admin1")
        val dev = enroll(enrollment, "company", "dg1", "Fleet", "Transport Device")

        check("D32 setGroupTransports by a non-admin (member) refused — widening attempt",
            !roster.setGroupTransports("co", "dg1", listOf("lan", "hub", "mesh", "tor"), "mem1") &&
                roster.deviceGroup("dg1")!!.transportSet == listOf("lan", "hub", "mesh"))
        check("D32 setGroupTransports by a non-admin refused — narrowing attempt too",
            !roster.setGroupTransports("co", "dg1", listOf("lan"), "mem1"))
        check("D32 setGroupTransports with a non-rung id refused even for an admin",
            !roster.setGroupTransports("co", "dg1", listOf("lan", "warp"), "admin1"))
        check("D32 setGroupTransports by company admin succeeds and keeps the given order",
            roster.setGroupTransports("co", "dg1", listOf("mesh", "lan", "tor"), "admin1") &&
                roster.deviceGroup("dg1")!!.transportSet == listOf("mesh", "lan", "tor"))
        check("setup: restore group set for pin tests",
            roster.setGroupTransports("co", "dg1", listOf("lan", "hub", "mesh"), "admin1"))

        check("D32 pin subset accepted at update time",
            roster.updateDeviceTransports("co", dev, "manual", setOf("hub", "lan"), "mem1") &&
                enrollment.byId(dev)?.transportMode == "manual" &&
                enrollment.byId(dev)?.allowedTransports == setOf("hub", "lan"))
        check("D31/D32 effective transports for the pinned device follow the resolved order",
            roster.effectiveTransportsFor("co", dev) == listOf("lan", "hub"))
        check("D32 pin outside the resolved set REJECTED at update time, record untouched",
            !roster.updateDeviceTransports("co", dev, "manual", setOf("tor"), "mem1") &&
                enrollment.byId(dev)?.allowedTransports == setOf("hub", "lan"))
        check("D32 an unknown transport mode is refused at update time, not degraded",
            !roster.updateDeviceTransports("co", dev, "warp", emptySet(), "mem1") &&
                enrollment.byId(dev)?.transportMode == "manual")
        check("setup: company ceiling caps the scope (admin act)",
            roster.setCompanyCeiling("co", listOf("lan", "mesh"), "admin1"))
        check("D31 ceiling change by a non-admin refused",
            !roster.setCompanyCeiling("co", listOf("lan"), "mem1"))
        check("D31/D32 pin inside the group set but outside the ceiling REJECTED",
            !roster.updateDeviceTransports("co", dev, "manual", setOf("hub"), "mem1") &&
                enrollment.byId(dev)?.allowedTransports == setOf("hub", "lan"))
        check("D31/D32 effective transports intersect the ceiling",
            roster.effectiveTransportsFor("co", dev) == listOf("lan"))
        check("D31 personal scope reports no ceiling",
            roster.companyCeiling("pers") == null)
        check("D31 ceiling cannot be set on a personal scope",
            !roster.setCompanyCeiling("pers", listOf("lan"), "admin1"))
    }

    // ================= D14 offboarding =================
    run {
        val (roster, enrollment) = newStores(dir, "offboard")
        basicCompany(roster)
        roster.addUser(RosterStore.User("admin2", "co", "Admin Two", "human"))
        roster.addCompanyAdmin("co", "admin2", actorUserId = "admin1")
        roster.addUser(RosterStore.User("target", "co", "Leaving Tech", "human"))
        roster.addCompanyAdmin("co", "target", actorUserId = "admin1")
        roster.addUser(RosterStore.User("aiT", "co", "Target's AI", "ai", pairedByUserId = "target"))
        roster.addUserGroup(
            RosterStore.UserGroup("ug1", "co", "Techs", memberUserIds = setOf("target")), "admin1"
        )
        roster.addUserGroup(
            RosterStore.UserGroup(
                "ug2", "co", "Leads", memberUserIds = setOf("target"), adminUserIds = setOf("target")
            ), "admin1"
        )
        roster.addDeviceGroup(RosterStore.DeviceGroup("dg1", "co", "Fleet", listOf("lan", "hub")), "admin1")
        roster.addGrant(RosterStore.Grant("co", "ug1", "dg1", setOf("use", "enroll")), "admin1")
        roster.addGrant(RosterStore.Grant("co", "ug2", "dg1", setOf("admin")), "admin1")
        // Minted device enrolled with its identity kept, so the
        // after-fire proof can show signature verification dying
        // with the revocation (S4 offboarding-completeness proof).
        val mintedIdentity = DeviceIdentity.generate()
        val mintedCode = enrollment.mint("company", "dg1", "Fleet")
        val mintedEnrolled = enrollment.redeem(
            mintedCode,
            EnrollmentStore.EnrollingDevice(
                mintedIdentity.deviceId, mintedIdentity.publicKeyBase64, "Minted By Target"
            )
        )
        check("setup: enrollment of Minted By Target succeeds", mintedEnrolled != null)
        val mintedDev = mintedIdentity.deviceId
        val mintedMsg = "offboarding proof".toByteArray(Charsets.UTF_8)
        val mintedSig = mintedIdentity.sign(mintedMsg)
        check("setup: minted device verifies before offboarding",
            enrollment.verifyEnrolledSignature(mintedDev, mintedMsg, mintedSig))
        roster.recordEnrollmentMint("co", mintedDev, "target")
        check("setup: mint attribution recorded", roster.mintedBy(mintedDev) == "target")

        val blast = roster.blastList("co", "target")
        check("D14 blast list names every user-group seat",
            blast != null && blast.userGroupSeats.toSet() == setOf("ug1", "ug2"))
        check("D14 blast list names the company-admin seat", blast?.isCompanyAdmin == true)
        check("D14 blast list names the grants touching those groups",
            blast != null && blast.grantsTouching.map { it.userGroupId to it.deviceGroupId }.toSet() ==
                setOf("ug1" to "dg1", "ug2" to "dg1"))
        check("D14 blast list names enrollments minted by the user",
            blast?.mintedEnrollmentDeviceIds == listOf(mintedDev))
        check("D14 blast list names AI pairings owned by the user",
            blast?.ownedAiUserIds == listOf("aiT"))
        check("D14 blast list names the live-session requirement",
            blast != null && blast.requiresLiveSessionKill &&
                blast.liveSessionRequirement.contains("live sessions"))
        check("D14 computing the blast list fires NOTHING",
            roster.user("target") != null && roster.isCompanyAdmin("co", "target") &&
                enrollment.byId(mintedDev)?.revoked == false &&
                roster.user("aiT")?.suspended == false &&
                "target" in roster.userGroup("ug1")!!.memberUserIds)

        val noStepUp = roster.removeUser("co", "target", actorUserId = "admin1", stepUp = false)
        check("D14/D26 removing a company admin without step-up refused, blast still returned",
            !noStepUp.fired && noStepUp.blast?.userId == "target" &&
                noStepUp.refusal?.contains("step-up") == true && roster.user("target") != null)
        val byNonAdmin = roster.removeUser("co", "target", actorUserId = "aiT", stepUp = true)
        check("D14 removal by a non-company-admin actor refused",
            !byNonAdmin.fired && roster.user("target") != null)

        val fired = roster.removeUser("co", "target", actorUserId = "admin1", stepUp = true)
        check("D14 offboarding fires with step-up and returns the blast list",
            fired.fired && fired.refusal == null && fired.blast?.userId == "target")
        check("D14 on fire: the user record is removed from the scope",
            roster.user("target") == null && roster.usersInScope("co").none { it.id == "target" })
        check("D14 on fire: all user-group seats (member + group-admin) removed",
            roster.userGroup("ug1")!!.memberUserIds.isEmpty() &&
                roster.userGroup("ug2")!!.memberUserIds.isEmpty() &&
                roster.userGroup("ug2")!!.adminUserIds.isEmpty())
        check("D14 on fire: the company-admin seat is removed",
            !roster.isCompanyAdmin("co", "target"))
        check("D14 on fire: enrollments minted by the user are REVOKED",
            enrollment.byId(mintedDev)?.revoked == true)
        check("D14 on fire: owned AI pairings are SUSPENDED, not deleted",
            roster.user("aiT") != null && roster.user("aiT")?.suspended == true)
        check("D14 on fire: an offboarding event is recorded for the session layer",
            roster.events().any {
                it.type == RosterStore.EVENT_USER_OFFBOARDED && it.subjectId == "target" &&
                    it.detail.contains("liveSessionsMustBeKilled=true")
            })
        check("D14 a suspended AI holds no rights",
            roster.rightsFor("co", "aiT", "dg1").isEmpty())

        // ---- S4 / D14 offboarding-completeness proof: the removed
        // user provably retains NOTHING in the scope. ----
        check("D14/S4 proof: the removed user holds no seat in ANY user group in the scope",
            roster.userGroupsInScope("co").all {
                "target" !in it.memberUserIds && "target" !in it.adminUserIds
            })
        check("D14/S4 proof: the removed user holds no company-admin seat and no rights on any device group",
            "target" !in roster.companyAdmins("co") &&
                roster.deviceGroupsInScope("co").all { roster.rightsFor("co", "target", it.id).isEmpty() })
        check("D14/S4 proof: the grants still belong to their groups but are dead for the removed user",
            roster.grantsInScope("co").map { it.userGroupId to it.deviceGroupId }.toSet() ==
                setOf("ug1" to "dg1", "ug2" to "dg1") &&
                !roster.canUse("co", "target", "dg1") && !roster.canEnroll("co", "target", "dg1"))
        check("D14/S4 proof: the removed user can perform no structural act",
            !roster.deleteDeviceGroup("co", "dg1", "target") &&
                !roster.addGrant(RosterStore.Grant("co", "ug1", "dg1", setOf("admin")), "target") &&
                !roster.setGroupTransports("co", "dg1", listOf("lan"), "target"))
        check("D14/S4 proof: minted enrollment revocation kills signature verification and group membership",
            !enrollment.verifyEnrolledSignature(mintedDev, mintedMsg, mintedSig) &&
                mintedDev !in roster.deviceGroupMemberIds("co", "dg1"))
        check("D14/S4 proof: the mint attribution is gone (nothing left pointing at the removed user as minter)",
            roster.mintedBy(mintedDev) == null)
        check("D14/S4 proof: the suspended AI's record survives intact (suspended, not deleted or re-owned)",
            roster.user("aiT")?.pairedByUserId == "target" && roster.user("aiT")?.suspended == true)
        check("D14/S4 proof: nobody else in the scope was touched",
            roster.user("admin1") != null && roster.user("admin2") != null &&
                roster.isCompanyAdmin("co", "admin1") && roster.isCompanyAdmin("co", "admin2") &&
                roster.userGroup("ug1") != null && roster.deviceGroup("dg1") != null)

        // Last-admin guard through RemoveUser (admin1 + admin2 remain; remove down to one).
        check("setup: admin2 removes admin1 with step-up",
            roster.removeUser("co", "admin1", actorUserId = "admin2", stepUp = true).fired)
        val lastTry = roster.removeUser("co", "admin2", actorUserId = "admin2", stepUp = true)
        check("D14/D26 the LAST company admin cannot be removed, even by themselves with step-up",
            !lastTry.fired && lastTry.refusal?.contains("last company admin") == true &&
                roster.user("admin2") != null && roster.isCompanyAdmin("co", "admin2"))

        // The wall cuts both ways + cross-scope refusal.
        roster.addUser(RosterStore.User("owner", "pers", "Owner", "human"))
        roster.addCompanyAdmin("pers", "owner")
        val personalTry = roster.removeUser("pers", "owner", actorUserId = "owner", stepUp = true)
        check("D14 a personal scope is untouchable by offboarding",
            !personalTry.fired && personalTry.refusal?.contains("personal scope") == true &&
                roster.user("owner") != null)
        val crossTry = roster.removeUser("co", "owner", actorUserId = "admin2", stepUp = true)
        check("D8/D14 cross-scope removal refused (company action cannot touch a personal user)",
            !crossTry.fired && roster.user("owner") != null)
        check("D14/S4 proof: the personal scope is fully intact after every company offboarding above",
            roster.usersInScope("pers").map { it.id } == listOf("owner") &&
                roster.isCompanyAdmin("pers", "owner") &&
                roster.events().none {
                    it.type == RosterStore.EVENT_USER_OFFBOARDED && it.scopeId == "pers"
                })
    }

    // ================= D2 endpoint view vs operator roster =================
    run {
        val (roster, enrollment) = newStores(dir, "endpoint")
        basicCompany(roster)
        roster.addDeviceGroup(RosterStore.DeviceGroup("dg1", "co", "Fleet", listOf("lan")), "admin1")
        roster.addDeviceGroup(RosterStore.DeviceGroup("dg2", "co", "Site", listOf("lan")), "admin1")
        val devA = enroll(enrollment, "company", "dg1", "Fleet", "Endpoint Alpha")
        val devB = enroll(enrollment, "company", "dg2", "Site", "Endpoint Beta")
        enrollment.recordReceipt(
            EnrollmentStore.EnrollmentReceipt(
                enrollerName = "Operator One", enrollerDeviceId = "operator-device-1",
                scope = "company", groupName = "Fleet", enrolledAtMs = 1700000000000L
            )
        )
        val view = roster.endpointView(devA)
        check("D2 endpoint view returns the device's own record",
            view != null && view.device.deviceId == devA && view.device.displayName == "Endpoint Alpha")
        check("D2 endpoint view returns its Slice 1 receipts",
            view?.receipts?.size == 1 && view?.receipts?.get(0)?.enrollerName == "Operator One")
        check("D2 endpoint view's allowed operators derive from the receipts",
            view?.allowedOperators?.map { it.enrollerDeviceId } == listOf("operator-device-1"))
        check("D2 endpoint view contains NO other device's data (exhaustive content check)",
            view != null && !view.toString().contains(devB) && !view.toString().contains("Endpoint Beta") &&
                !view.toString().contains("dg2"))
        check("D2 EndpointView shape has exactly the three permitted components",
            RosterStore.EndpointView::class.java.declaredFields.map { it.name }.toSet() ==
                setOf("device", "receipts", "allowedOperators"))
        check("D2 endpoint view of an unknown device is null",
            roster.endpointView("no-such-device") == null)
        val operator = roster.operatorRoster("co")
        check("D2 operator roster (operator side) DOES hold the fleet of its scope",
            operator != null && operator.devices.map { it.deviceId }.toSet() == setOf(devA, devB) &&
                operator.deviceGroupMemberIds["dg1"] == listOf(devA))
        check("D8 operator roster of an unknown scope is null", roster.operatorRoster("nope") == null)
        check("D8 operator roster carries only its own scope's users",
            operator?.users?.map { it.id } == listOf("admin1"))
    }

    // ================= Persistence =================
    run {
        val file = File(dir, "persist-roster.tsv")
        val enrollment = EnrollmentStore(File(dir, "persist-enroll.tsv"))
        val roster = RosterStore(file, enrollment)
        basicCompany(roster)
        roster.addUser(RosterStore.User("mem1", "co", "Member One", "human"))
        roster.addUser(RosterStore.User("ai1", "co", "Helper AI", "ai", pairedByUserId = "mem1", suspended = true))
        roster.addUserGroup(
            RosterStore.UserGroup("ug1", "co", "Techs", memberUserIds = setOf("mem1"), adminUserIds = setOf("admin1")),
            "admin1"
        )
        roster.addDeviceGroup(RosterStore.DeviceGroup("dg1", "co", "Fleet", listOf("tor", "lan", "hub")), "admin1")
        roster.addGrant(RosterStore.Grant("co", "ug1", "dg1", setOf("use", "enroll")), "admin1")
        roster.setCompanyCeiling("co", listOf("lan", "tor"), "admin1")
        val dev = enroll(enrollment, "company", "dg1", "Fleet", "Persisted Device")
        roster.recordEnrollmentMint("co", dev, "mem1")
        val eventsBefore = roster.events().size

        val reloaded = RosterStore(file, enrollment)
        check("persistence: scopes roundtrip",
            reloaded.allScopes().map { it.id } == listOf("co", "pers"))
        check("persistence: users roundtrip incl. AI pairing owner + suspended flag",
            reloaded.user("ai1")?.pairedByUserId == "mem1" && reloaded.user("ai1")?.suspended == true &&
                reloaded.user("mem1")?.displayName == "Member One")
        check("persistence: company admin seats roundtrip",
            reloaded.companyAdmins("co") == setOf("admin1"))
        check("persistence: user group members + admins roundtrip",
            reloaded.userGroup("ug1")?.memberUserIds == setOf("mem1") &&
                reloaded.userGroup("ug1")?.adminUserIds == setOf("admin1"))
        check("D32 persistence: device group transport ORDER roundtrips",
            reloaded.deviceGroup("dg1")?.transportSet == listOf("tor", "lan", "hub"))
        check("persistence: grants roundtrip",
            reloaded.grant("co", "ug1", "dg1")?.rights == setOf("use", "enroll"))
        check("persistence: company ceiling roundtrips",
            reloaded.companyCeiling("co") == listOf("lan", "tor"))
        check("persistence: mint attribution roundtrips", reloaded.mintedBy(dev) == "mem1")
        check("persistence: events roundtrip", reloaded.events().size == eventsBefore &&
            reloaded.events().any { it.type == RosterStore.EVENT_ADMIN_SEATED })
        check("persistence: derived membership still works after reload",
            reloaded.deviceGroupMemberIds("co", "dg1") == listOf(dev))

        val onDisk = file.readText()
        check("persistence: the store contains no password/token/seed material",
            !onDisk.contains("password") && !onDisk.contains("token") && !onDisk.contains("seed"))

        file.appendText(
            "\ngarbage line with no tabs\nuser\ttoo\tfew\nscope\tbad\tgalaxy\tNope\n" +
                "grant\tco\tug1\tdg1\tfly\ndevicegroup\tonly\ttwo\n"
        )
        val afterCorrupt = RosterStore(file, enrollment)
        check("persistence: corrupt lines are skipped, never fatal — records intact",
            afterCorrupt.allScopes().size == 2 && afterCorrupt.usersInScope("co").size == 3 &&
                afterCorrupt.deviceGroup("dg1") != null &&
                afterCorrupt.grant("co", "ug1", "dg1")?.rights == setOf("use", "enroll"))
    }

    // ================= D38 reconciliation (S2-AND findings) =================
    run {
        val (roster, enrollment) = newStores(dir, "d38")
        basicCompany(roster)
        roster.addUser(RosterStore.User("admin2", "co", "Admin Two", "human"))
        roster.addCompanyAdmin("co", "admin2", actorUserId = "admin1")
        roster.addUser(RosterStore.User("mem1", "co", "Member One", "human"))
        roster.addUser(RosterStore.User("mem2", "co", "Member Two", "human"))
        roster.addUser(RosterStore.User("gadmin", "co", "Group Admin", "human"))
        roster.addUser(RosterStore.User("ai1", "co", "Helper AI", "ai", pairedByUserId = "mem1"))
        roster.addUserGroup(
            RosterStore.UserGroup("ug1", "co", "Techs", memberUserIds = setOf("mem1"), adminUserIds = setOf("gadmin")),
            "admin1"
        )
        roster.addDeviceGroup(RosterStore.DeviceGroup("dg1", "co", "Fleet", listOf("lan", "hub", "mesh")), "admin1")
        roster.addGrant(RosterStore.Grant("co", "ug1", "dg1", setOf("use", "admin")), "admin1")

        // F1: membership changes are admin acts.
        check("D38/F1 a plain member cannot add THEMSELVES to a group holding an admin grant",
            !roster.addUserToGroup("co", "ug1", "mem2", "mem2") &&
                "mem2" !in roster.userGroup("ug1")!!.memberUserIds &&
                !roster.canAdministerDeviceGroup("co", "mem2", "dg1"))
        check("D38/F1 a plain member cannot add an AI to the group either",
            !roster.addUserToGroup("co", "ug1", "ai1", "mem1"))
        check("D38/F1 a group admin (non-company-admin) CAN add a member",
            roster.addUserToGroup("co", "ug1", "mem2", "gadmin") &&
                "mem2" in roster.userGroup("ug1")!!.memberUserIds)
        check("D38/F1 a plain member cannot strip members or group admins out of a group",
            !roster.removeUserFromGroup("co", "ug1", "mem1", "mem2") &&
                "mem1" in roster.userGroup("ug1")!!.memberUserIds)
        check("D38/F1 a company admin CAN remove a member, and the act is evented",
            roster.removeUserFromGroup("co", "ug1", "mem2", "admin1") &&
                "mem2" !in roster.userGroup("ug1")!!.memberUserIds &&
                roster.events().any { it.type == RosterStore.EVENT_USER_GROUP_MEMBER_REMOVED })

        // F2: cross-scope device deletion.
        val devPersonal = enroll(enrollment, "personal", "dg1", "Fleet", "Personal Device")
        check("D38/F2 a company admin cannot delete a PERSONAL-scope device via their own scopeId",
            !roster.deleteDevice("co", devPersonal, "admin1") &&
                enrollment.byId(devPersonal)?.revoked == false)
        check("D38/F2 canAdministerDeviceGroup is false for a group that lives in another scope",
            !roster.canAdministerDeviceGroup("pers", "admin1", "dg1"))

        // F3: endpoint view receipts are the device's own.
        val devA = enroll(enrollment, "company", "dg1", "Fleet", "Fleet Device")
        enrollment.recordReceipt(
            EnrollmentStore.EnrollmentReceipt("Op One", "op-dev-1", "company", "Fleet", 1700000000000L)
        )
        enrollment.recordReceipt(
            EnrollmentStore.EnrollmentReceipt("Op Two", "op-dev-2", "company", "OtherGroup", 1700000001000L)
        )
        val viewA = roster.endpointView(devA)
        check("D38/F3 endpoint view returns ONLY its own enrollment's receipts (other groups filtered)",
            viewA != null && viewA.receipts.map { it.enrollerDeviceId } == listOf("op-dev-1") &&
                viewA.allowedOperators.map { it.enrollerDeviceId } == listOf("op-dev-1"))

        // F4: suspension is gated, evented, and strips authority.
        check("D38/F4 suspension by a non-admin is refused and changes nothing",
            !roster.setUserSuspended("co", "mem1", true, "mem2") &&
                roster.user("mem1")?.suspended == false)
        check("D38/F4 suspending a company admin without step-up is refused",
            !roster.setUserSuspended("co", "admin2", true, "admin1") &&
                roster.user("admin2")?.suspended == false)
        check("D38/F4 suspending a company admin WITH step-up succeeds and writes an event",
            roster.setUserSuspended("co", "admin2", true, "admin1", stepUp = true) &&
                roster.user("admin2")?.suspended == true &&
                roster.events().any { it.type == RosterStore.EVENT_USER_SUSPENDED && it.subjectId == "admin2" })
        check("D38/F4 a suspended company admin has NO authority (seat kept, power gone)",
            !roster.isCompanyAdmin("co", "admin2") &&
                "admin2" in roster.companyAdmins("co") &&
                !roster.addGrant(RosterStore.Grant("co", "ug1", "dg1", setOf("use")), "admin2") &&
                !roster.setUserSuspended("co", "mem1", true, "admin2"))
        check("D38/F4 a suspended member holds no rights",
            roster.setUserSuspended("co", "mem1", true, "admin1") &&
                roster.rightsFor("co", "mem1", "dg1").isEmpty() &&
                roster.setUserSuspended("co", "mem1", false, "admin1"))
        check("D38/F4 unsuspension restores the admin's authority",
            roster.setUserSuspended("co", "admin2", false, "admin1") &&
                roster.isCompanyAdmin("co", "admin2"))

        // F5: mint attribution is validated.
        check("D38/F5 attribution for an unknown device is refused, nothing recorded",
            !roster.recordEnrollmentMint("co", "no-such-device", "mem1") &&
                roster.mintedBy("no-such-device") == null)
        check("D38/F5 attribution for a device whose group is not in the scope is refused",
            !roster.recordEnrollmentMint("co", devPersonal, "mem1") &&
                roster.mintedBy(devPersonal) == null)
        check("D38/F5 a valid attribution is recorded",
            roster.recordEnrollmentMint("co", devA, "mem1") && roster.mintedBy(devA) == "mem1")

        // F7: device transport updates are actor-gated and widen-aware.
        // mem3 holds `use` only (via ug3) — the widening guinea pig.
        roster.addUser(RosterStore.User("mem3", "co", "Member Three", "human"))
        roster.addUserGroup(
            RosterStore.UserGroup("ug3", "co", "Viewers", memberUserIds = setOf("mem3")), "admin1"
        )
        roster.addGrant(RosterStore.Grant("co", "ug3", "dg1", setOf("use")), "admin1")
        check("D38/F7 a user with NO rights on the group cannot update a device's transports",
            !roster.updateDeviceTransports("co", devA, "manual", setOf("lan"), "mem2") &&
                enrollment.byId(devA)?.transportMode == "inherit")
        check("D38/F7 manual with an EMPTY pin is refused",
            !roster.updateDeviceTransports("co", devA, "manual", emptySet(), "mem3") &&
                enrollment.byId(devA)?.transportMode == "inherit")
        check("D38/F7 narrowing to a pin by a use-holder succeeds",
            roster.updateDeviceTransports("co", devA, "manual", setOf("lan"), "mem3") &&
                roster.effectiveTransportsFor("co", devA) == listOf("lan"))
        check("D38/F7 WIDENING (manual pin -> auto) by a use-only member is refused",
            !roster.updateDeviceTransports("co", devA, "auto", emptySet(), "mem3") &&
                enrollment.byId(devA)?.transportMode == "manual")
        check("D38/F7 the same widening by a company admin succeeds",
            roster.updateDeviceTransports("co", devA, "auto", emptySet(), "admin1") &&
                roster.effectiveTransportsFor("co", devA) == listOf("lan", "hub", "mesh"))
        check("D38/F7 a revoked device refuses transport updates",
            enrollment.revoke(devA) &&
                !roster.updateDeviceTransports("co", devA, "manual", setOf("lan"), "admin1"))
        check("D38/F7 an empty device-group transport set is refused at creation",
            !roster.addDeviceGroup(RosterStore.DeviceGroup("dgEmpty", "co", "Empty", emptyList()), "admin1"))
        check("D38/F7 an empty company ceiling is refused (null is the way to clear)",
            !roster.setCompanyCeiling("co", emptyList(), "admin1"))
        check("D32/F7 a Slice-1 manual record with NO pin resolves to the capped set, never zero transports",
            TransportPolicy.effectiveTransports(
                EnrollmentStore.EnrolledDevice(
                    "dev-nopin", "NP", "AAAA", "company", "dg1", "Fleet", 1L,
                    revoked = false, transportMode = "manual", allowedTransports = emptySet()
                ),
                listOf("lan", "hub"), null
            ) == listOf("lan", "hub"))

        // F8: blast list names group-admin-only seats.
        roster.addUser(RosterStore.User("adminOnly", "co", "Admin Only", "human"))
        roster.addUserGroup(
            RosterStore.UserGroup("ugAO", "co", "AO Group", memberUserIds = emptySet(), adminUserIds = setOf("adminOnly")),
            "admin1"
        )
        roster.addGrant(RosterStore.Grant("co", "ugAO", "dg1", setOf("admin")), "admin1")
        val blastAO = roster.blastList("co", "adminOnly")
        check("D38/F8 the blast list names a group-admin seat held WITHOUT membership",
            blastAO != null && blastAO.userGroupSeats.isEmpty() &&
                blastAO.userGroupAdminSeats == listOf("ugAO") &&
                blastAO.grantsTouching.any { it.userGroupId == "ugAO" })
        check("D38/F8 firing strips the admin-only seat the blast list named",
            roster.removeUser("co", "adminOnly", actorUserId = "admin1", stepUp = false).fired &&
                "adminOnly" !in roster.userGroup("ugAO")!!.adminUserIds)

        // F9: operator roster applies the scope-kind rule too.
        check("D38/F9 the operator roster does NOT list the personal-scope device under a colliding groupId",
            roster.operatorRoster("co")!!.devices.none { it.deviceId == devPersonal })

        // F11: on-disk schema is an allowlist, not a word search.
        val tags = File(dir, "d38-roster.tsv").readLines().filter { it.isNotBlank() }
            .map { it.substringBefore('\t') }.toSet()
        check("D38/F11 every persisted roster line carries an allowlisted type tag",
            tags.isNotEmpty() && tags.all {
                it in setOf("scope", "user", "admin", "ceiling", "usergroup", "devicegroup", "grant", "mint", "event")
            })
        check("D38/F12 no .tmp file is left behind by saves (atomic rename)",
            !File(dir, "d38-roster.tsv.tmp").exists())
    }

    // F4: the last ACTIVE company admin cannot be suspended.
    run {
        val (roster, _) = newStores(dir, "d38-lastadmin")
        basicCompany(roster)
        check("D38/F4 suspending the LAST active company admin is refused even with step-up",
            !roster.setUserSuspended("co", "admin1", true, "admin1", stepUp = true) &&
                roster.user("admin1")?.suspended == false && roster.isCompanyAdmin("co", "admin1"))
    }

    // F6: offboarding refuses when revocation cannot be proven.
    run {
        val file = File(dir, "d38-f6-roster.tsv")
        val enrollment = EnrollmentStore(File(dir, "d38-f6-enroll.tsv"))
        val roster = RosterStore(file, enrollment)
        basicCompany(roster)
        roster.addUser(RosterStore.User("admin2", "co", "Admin Two", "human"))
        roster.addCompanyAdmin("co", "admin2", actorUserId = "admin1")
        roster.addUser(RosterStore.User("target", "co", "Leaving", "human"))
        roster.addDeviceGroup(RosterStore.DeviceGroup("dg1", "co", "Fleet", listOf("lan")), "admin1")
        val dev = enroll(enrollment, "company", "dg1", "Fleet", "Target Minted")
        check("setup: attribution recorded for the F6 case", roster.recordEnrollmentMint("co", dev, "target"))
        val blind = RosterStore(file, null) // same roster file, NO enrollment store
        val outcome = blind.removeUser("co", "target", actorUserId = "admin1", stepUp = false)
        check("D38/F6 offboarding with minted devices but NO enrollment store REFUSES, user intact",
            !outcome.fired && outcome.refusal?.contains("enrollment store") == true &&
                blind.user("target") != null && blind.mintedBy(dev) == "target")
    }

    // F10: load-time sanitization of hand-edited admin state.
    run {
        val file = File(dir, "d38-f10-roster.tsv")
        file.writeText(
            listOf(
                "scope\tco\tcompany\tAcme",
                "user\tadmin1\tco\tAdmin One\thuman\t\t0",
                "user\tai1\tco\tHelper AI\tai\tadmin1\t0",
                "user\tmem1\tco\tMember One\thuman\t\t0",
                "admin\tco\tadmin1",
                "admin\tco\tai1",
                "admin\tco\tghost",
                "usergroup\tug1\tco\tTechs\tmem1\tai1,admin1"
            ).joinToString("\n")
        )
        val roster = RosterStore(file, null)
        check("D38/F10 a hand-edited file cannot seat an AI or a ghost as company admin",
            roster.isCompanyAdmin("co", "admin1") &&
                !roster.isCompanyAdmin("co", "ai1") && !roster.isCompanyAdmin("co", "ghost") &&
                roster.companyAdmins("co") == setOf("admin1"))
        check("D38/F10 a hand-edited file cannot make an AI a user-group admin",
            roster.userGroup("ug1")?.adminUserIds == setOf("admin1") &&
                roster.events().any { it.type == RosterStore.EVENT_LOAD_SANITIZED })
    }

    dir.deleteRecursively()
    println(if (failures == 0) "ALL ROSTER TESTS PASSED" else "$failures ROSTER TEST(S) FAILED")
    if (failures > 0) kotlin.system.exitProcess(1)
}
