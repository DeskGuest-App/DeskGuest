package io.agenticcontrol.app.roster

import io.agenticcontrol.app.enrollment.EnrollmentStore
import java.io.File

/**
 * Roster & groups (Slice 2): scopes, users, company admins, user
 * groups, device groups, grants, transport resolution, offboarding,
 * and the two read shapes (operator roster vs endpoint view).
 *
 * Discipline follows Slice 1's stores (PairingStore /
 * EnrollmentStore): every public entry point is serialized on this
 * store's monitor (@Synchronized); persistence is one TSV file with
 * type-tagged lines; corrupt lines are skipped on load, never fatal;
 * string fields are TSV-sanitised. The store holds public ids and
 * display names only — no reusable password, token, seed, or any
 * other secret ever appears in it (D22).
 *
 * Scope isolation (D8): every record carries a ScopeId and every
 * query is scope-filtered. A company scope gains no visibility or
 * rights over a personal scope — cross-scope references are refused
 * at write time, not merely filtered at read time.
 *
 * Device-group membership is DERIVED from the Slice 1 enrollment
 * roster (the group id bound at mint, D7/D12): this store keeps no
 * hand-edited device list. It reads devices through the injected
 * [enrollmentStore] (or a caller-supplied roster snapshot for the
 * pure derivations) and revokes through it on offboarding / device
 * removal, so revocation takes effect in the one roster that exists.
 *
 * Modules only: nothing here is wired into any live surface.
 */
class RosterStore(
    private val storeFile: File,
    private val enrollmentStore: EnrollmentStore? = null,
    private val clockMs: () -> Long = { System.currentTimeMillis() }
) {

    // ---- records ----

    /** D8: one app holds a personal scope plus any number of company
     *  scopes side by side. */
    data class Scope(val id: String, val kind: String, val name: String)

    /** D9/D12: a user is a directory record inside exactly one
     *  scope. AI users are pairings, not accounts: [pairedByUserId]
     *  names the human who paired them (AI only). */
    data class User(
        val id: String,
        val scopeId: String,
        val displayName: String,
        val kind: String,
        val pairedByUserId: String? = null,
        val suspended: Boolean = false
    )

    /** D12: people; carry rights via grants. [adminUserIds] are the
     *  group's own admins, appointed under the company admin (D13). */
    data class UserGroup(
        val id: String,
        val scopeId: String,
        val name: String,
        val memberUserIds: Set<String> = emptySet(),
        val adminUserIds: Set<String> = emptySet()
    )

    /** D12/D32: devices; [transportSet] is the group's ORDERED list
     *  of rung ids from the six automatic rungs — order is failover
     *  order. Membership is NOT stored here (derived, see class doc). */
    data class DeviceGroup(
        val id: String,
        val scopeId: String,
        val name: String,
        val transportSet: List<String> = TransportPolicy.RUNGS
    )

    /** D12/D7: user-group x device-group x rights. */
    data class Grant(
        val scopeId: String,
        val userGroupId: String,
        val deviceGroupId: String,
        val rights: Set<String>
    )

    /** Audit-shaped record written into the store's event list
     *  (step-up admin removals D13/D26, offboarding D14, structural
     *  acts). Detail is a plain summary — never a secret. */
    data class RosterEvent(
        val atMs: Long,
        val type: String,
        val scopeId: String,
        val actorUserId: String,
        val subjectId: String,
        val detail: String
    )

    /** D14 blast list: everything removing a user will touch,
     *  computed BEFORE anything fires. [liveSessionRequirement]
     *  names the live-session obligation in words because sessions
     *  are a later slice: the offboarding event recorded on fire is
     *  the record the session layer must honor. */
    data class BlastList(
        val scopeId: String,
        val userId: String,
        val userGroupSeats: List<String>,
        /** D38 S2-AND F8: groups where the user holds a group-ADMIN
         *  seat (whether or not they are also a member). The fire
         *  step strips these seats too, so the confirmation list
         *  must name them — a group-admin seat carries structural
         *  power (e.g. deleteUserGroup) and was previously
         *  invisible here. */
        val userGroupAdminSeats: List<String> = emptyList(),
        val isCompanyAdmin: Boolean,
        val grantsTouching: List<Grant>,
        val mintedEnrollmentDeviceIds: List<String>,
        val ownedAiUserIds: List<String>,
        val liveSessionRequirement: String,
        val requiresLiveSessionKill: Boolean = true
    )

    data class RemoveOutcome(
        val blast: BlastList?,
        val fired: Boolean,
        val refusal: String?
    )

    /** D2 allowed operator, derived from a Slice 1 receipt. */
    data class AllowedOperator(
        val enrollerDeviceId: String,
        val enrollerName: String,
        val scope: String,
        val groupName: String
    )

    /**
     * D2 endpoint view: ONLY the device's own enrolled record, its
     * Slice 1 receipts, and the allowed-operators list derived from
     * them. There is deliberately no other field in this shape — no
     * other device's record, no group roster, no fleet list exists
     * here to be hidden; the data is ABSENT, not filtered.
     */
    data class EndpointView(
        val device: EnrollmentStore.EnrolledDevice,
        val receipts: List<EnrollmentStore.EnrollmentReceipt>,
        val allowedOperators: List<AllowedOperator>
    )

    /** D2/D8 operator-side read shape: the full roster of ONE scope. */
    data class OperatorRoster(
        val scope: Scope,
        val users: List<User>,
        val companyAdminUserIds: Set<String>,
        val userGroups: List<UserGroup>,
        val deviceGroups: List<DeviceGroup>,
        val deviceGroupMemberIds: Map<String, List<String>>,
        val grants: List<Grant>,
        val devices: List<EnrollmentStore.EnrolledDevice>
    )

    // ---- state ----

    private val scopes = mutableListOf<Scope>()
    private val users = mutableListOf<User>()
    private val adminSeats = mutableMapOf<String, MutableSet<String>>() // scopeId -> userIds
    private val userGroups = mutableListOf<UserGroup>()
    private val deviceGroups = mutableListOf<DeviceGroup>()
    private val grants = mutableListOf<Grant>()
    private val ceilings = mutableMapOf<String, List<String>>() // scopeId -> ordered cap
    private val mintAttributions = mutableMapOf<String, Pair<String, String>>() // deviceId -> (scopeId, mintedByUserId)
    private val eventList = mutableListOf<RosterEvent>()

    init {
        load()
    }

    /**
     * C20 wiring: re-read the store file after a recovery restore
     * rewrote it, so the live store and the file agree (see
     * EnrollmentStore.reloadForRecovery). load() re-runs its
     * admin-state sanitisation over the restored records.
     */
    @Synchronized
    fun reloadForRecovery() {
        scopes.clear()
        users.clear()
        adminSeats.clear()
        userGroups.clear()
        deviceGroups.clear()
        grants.clear()
        ceilings.clear()
        mintAttributions.clear()
        eventList.clear()
        load()
    }

    // ---- bd-and-remote F12(b) fix (2026-11-22): snapshot-and-
    // rollback for every mutator. Before this fix the mutators
    // mutated memory and then called save() with no rollback
    // (unlike the EnrollmentStore D38 F4 pattern): a failed save
    // left memory claiming a change the disk did not hold, and
    // the exception escaped into the caller. Now every mutator
    // snapshots first and a failed save restores the snapshot and
    // returns false — the act did not happen, in memory or on disk.

    private inner class Snapshot {
        private val scopesCopy = scopes.toList()
        private val usersCopy = users.toList()
        private val seatsCopy = adminSeats.mapValues { it.value.toMutableSet() }
        private val userGroupsCopy = userGroups.toList()
        private val deviceGroupsCopy = deviceGroups.toList()
        private val grantsCopy = grants.toList()
        private val ceilingsCopy = ceilings.mapValues { it.value.toList() }
        private val mintsCopy = mintAttributions.toMap()
        private val eventsSize = eventList.size
        fun restore() {
            scopes.clear(); scopes.addAll(scopesCopy)
            users.clear(); users.addAll(usersCopy)
            adminSeats.clear(); adminSeats.putAll(seatsCopy)
            userGroups.clear(); userGroups.addAll(userGroupsCopy)
            deviceGroups.clear(); deviceGroups.addAll(deviceGroupsCopy)
            grants.clear(); grants.addAll(grantsCopy)
            ceilings.clear(); ceilings.putAll(ceilingsCopy)
            mintAttributions.clear(); mintAttributions.putAll(mintsCopy)
            while (eventList.size > eventsSize) eventList.removeAt(eventList.size - 1)
        }
    }

    private fun persistOrRollback(snap: Snapshot): Boolean =
        try { save(); true } catch (e: Exception) { snap.restore(); false }

    // ---- scopes (D8) ----

    @Synchronized
    fun addScope(scope: Scope): Boolean {
        val kind = scope.kind.trim().lowercase()
        if (kind !in SCOPE_KINDS) return false
        if (scope.id.isBlank() || scopes.any { it.id == scope.id }) return false
        val snap = Snapshot()
        scopes.add(scope.copy(kind = kind))
        return persistOrRollback(snap)
    }

    @Synchronized
    fun scope(scopeId: String): Scope? = scopes.firstOrNull { it.id == scopeId }

    @Synchronized
    fun allScopes(): List<Scope> = scopes.toList()

    // ---- users (D9/D12) ----

    /**
     * Add a user to a scope. Refuses: unknown scope, duplicate id,
     * a human carrying a pairing owner, an AI with no pairing owner,
     * or a pairing owner who is not a human in the SAME scope (the
     * D8 wall applies to references, not just queries).
     */
    @Synchronized
    fun addUser(user: User): Boolean {
        val kind = user.kind.trim().lowercase()
        if (kind !in USER_KINDS) return false
        if (user.id.isBlank() || users.any { it.id == user.id }) return false
        if (scope(user.scopeId) == null) return false
        if (kind == USER_HUMAN && !user.pairedByUserId.isNullOrBlank()) return false
        if (kind == USER_AI) {
            val ownerId = user.pairedByUserId?.takeIf { it.isNotBlank() } ?: return false
            val owner = users.firstOrNull { it.id == ownerId } ?: return false
            if (owner.scopeId != user.scopeId || owner.kind != USER_HUMAN) return false
        }
        val snap = Snapshot()
        users.add(user.copy(kind = kind))
        return persistOrRollback(snap)
    }

    @Synchronized
    fun user(userId: String): User? = users.firstOrNull { it.id == userId }

    /** Scope-filtered (D8): users of any other scope are absent. */
    @Synchronized
    fun usersInScope(scopeId: String): List<User> = users.filter { it.scopeId == scopeId }

    /**
     * Suspend / unsuspend a user (D38 S2-AND F4; ADIR-09/DIR-09 at
     * the store level). Suspension is an ADMIN act: [actorUserId]
     * must be a company admin of the scope (which, per
     * [isCompanyAdmin], means a non-suspended human seat holder).
     * Suspending a company admin requires [stepUp] = true
     * (D13/D26), and suspending the LAST non-suspended company
     * admin is refused — a scope must never be left with no active
     * admin. Every change writes an audit-shaped event; there is
     * no silent path.
     */
    @Synchronized
    fun setUserSuspended(
        scopeId: String, userId: String, suspended: Boolean,
        actorUserId: String, stepUp: Boolean = false
    ): Boolean {
        val index = users.indexOfFirst { it.id == userId && it.scopeId == scopeId }
        if (index < 0) return false
        if (!isCompanyAdmin(scopeId, actorUserId)) return false
        if (users[index].suspended == suspended) return false
        val snap = Snapshot()
        if (suspended && userId in companyAdmins(scopeId)) {
            if (!stepUp) return false // D13/D26: admin target needs step-up
            val activeAdmins = companyAdmins(scopeId).count { id ->
                users.firstOrNull { it.id == id }?.suspended == false
            }
            if (activeAdmins <= 1) return false // last active admin guard
        }
        users[index] = users[index].copy(suspended = suspended)
        recordEvent(
            if (suspended) EVENT_USER_SUSPENDED else EVENT_USER_UNSUSPENDED,
            scopeId, actorUserId, userId,
            if (suspended) "user suspended" else "user unsuspended"
        )
        return persistOrRollback(snap)
    }

    // ---- company admins (D13/D26, D9) ----

    @Synchronized
    fun companyAdmins(scopeId: String): Set<String> =
        adminSeats[scopeId]?.toSet() ?: emptySet()

    /**
     * Authority check, not a raw seat lookup (D38 S2-AND F4/F10
     * backstop): a seat confers authority only while its holder is
     * a HUMAN user OF THIS SCOPE who is not suspended. A suspended
     * admin keeps the seat (unsuspension restores authority) but
     * can perform no admin act while suspended; an AI or a
     * cross-scope / unknown id named by a hand-edited file has no
     * authority whatever the seat set says.
     */
    @Synchronized
    fun isCompanyAdmin(scopeId: String, userId: String): Boolean {
        if (!companyAdmins(scopeId).contains(userId)) return false
        val user = users.firstOrNull { it.id == userId } ?: return false
        return user.scopeId == scopeId && user.kind == USER_HUMAN && !user.suspended
    }

    /**
     * Seat a company admin. D9: an AI can NEVER hold an admin seat —
     * assignment refuses outright. D26/D13: once a scope has admins,
     * seating another requires an existing admin as [actorUserId]
     * (the empty-set case is the bootstrap appointment). Personal
     * scope: the owner is the sole user and admin, so a second seat
     * is refused.
     */
    @Synchronized
    fun addCompanyAdmin(scopeId: String, userId: String, actorUserId: String? = null): Boolean {
        val scope = scope(scopeId) ?: return false
        val candidate = users.firstOrNull { it.id == userId } ?: return false
        if (candidate.scopeId != scopeId) return false // D8 wall
        if (candidate.kind != USER_HUMAN) return false // D9: AI never admin
        if (candidate.suspended) return false // D38 F4: no authority for a suspended user
        val current = adminSeats.getOrPut(scopeId) { mutableSetOf() }
        if (userId in current) return false
        if (scope.kind == SCOPE_PERSONAL && current.isNotEmpty()) return false
        if (current.isNotEmpty() && (actorUserId == null || !isCompanyAdmin(scopeId, actorUserId))) return false
        val snap = Snapshot()
        current.add(userId)
        recordEvent(EVENT_ADMIN_SEATED, scopeId, actorUserId ?: userId, userId, "company admin seated")
        return persistOrRollback(snap)
    }

    /**
     * Unseat a company admin. D26: the LAST company admin cannot be
     * removed — the guard refuses. D13/D26: removing a FELLOW admin
     * requires [stepUp] = true and writes an audit-shaped event.
     */
    @Synchronized
    fun removeCompanyAdmin(scopeId: String, userId: String, actorUserId: String, stepUp: Boolean): Boolean {
        val current = adminSeats[scopeId] ?: return false
        if (userId !in current) return false
        if (!isCompanyAdmin(scopeId, actorUserId)) return false
        if (current.size <= 1) return false // D26 last-admin guard
        if (actorUserId != userId && !stepUp) return false // D13/D26 step-up
        val snap = Snapshot()
        current.remove(userId)
        recordEvent(EVENT_ADMIN_REMOVED, scopeId, actorUserId, userId, "company admin removed (stepUp=$stepUp)")
        return persistOrRollback(snap)
    }

    // ---- user groups (D12/D13) ----

    /**
     * Create a user group. The actor must be a company admin of the
     * scope (in a personal scope, its sole admin/owner) — group
     * structure is an admin act (D13). Members and group admins must
     * be users of the same scope; group admins must be human (D9).
     */
    @Synchronized
    fun addUserGroup(group: UserGroup, actorUserId: String): Boolean {
        if (scope(group.scopeId) == null) return false
        if (group.id.isBlank() || userGroups.any { it.id == group.id }) return false
        if (!isCompanyAdmin(group.scopeId, actorUserId)) return false
        if (!membersValid(group.scopeId, group.memberUserIds)) return false
        if (!groupAdminsValid(group.scopeId, group.adminUserIds)) return false
        val snap = Snapshot()
        userGroups.add(group)
        return persistOrRollback(snap)
    }

    @Synchronized
    fun userGroup(groupId: String): UserGroup? = userGroups.firstOrNull { it.id == groupId }

    @Synchronized
    fun userGroupsInScope(scopeId: String): List<UserGroup> =
        userGroups.filter { it.scopeId == scopeId }

    /**
     * Membership changes are structural acts (D38 S2-AND F1):
     * [actorUserId] must be a company admin of the scope or a
     * human admin OF THIS user group, and must not be suspended.
     * Without that gate any member could add themselves (or an AI
     * they control) to a group holding an `admin` grant and
     * inherit its rights via [rightsFor].
     */
    @Synchronized
    fun addUserToGroup(scopeId: String, groupId: String, userId: String, actorUserId: String): Boolean {
        val index = userGroups.indexOfFirst { it.id == groupId && it.scopeId == scopeId }
        if (index < 0) return false
        if (!canChangeGroupMembership(scopeId, userGroups[index], actorUserId)) return false
        val member = users.firstOrNull { it.id == userId } ?: return false
        if (member.scopeId != scopeId) return false // D8 wall
        val snap = Snapshot()
        userGroups[index] = userGroups[index].copy(
            memberUserIds = userGroups[index].memberUserIds + userId
        )
        recordEvent(EVENT_USER_GROUP_MEMBER_ADDED, scopeId, actorUserId, userId, "added to user group $groupId")
        return persistOrRollback(snap)
    }

    @Synchronized
    fun removeUserFromGroup(scopeId: String, groupId: String, userId: String, actorUserId: String): Boolean {
        val index = userGroups.indexOfFirst { it.id == groupId && it.scopeId == scopeId }
        if (index < 0) return false
        if (!canChangeGroupMembership(scopeId, userGroups[index], actorUserId)) return false
        val snap = Snapshot()
        userGroups[index] = userGroups[index].copy(
            memberUserIds = userGroups[index].memberUserIds - userId,
            adminUserIds = userGroups[index].adminUserIds - userId
        )
        recordEvent(EVENT_USER_GROUP_MEMBER_REMOVED, scopeId, actorUserId, userId, "removed from user group $groupId")
        return persistOrRollback(snap)
    }

    /** Callers hold the monitor. */
    private fun canChangeGroupMembership(scopeId: String, group: UserGroup, actorUserId: String): Boolean {
        if (isCompanyAdmin(scopeId, actorUserId)) return true
        val actor = users.firstOrNull { it.id == actorUserId } ?: return false
        return actor.scopeId == scopeId && actor.kind == USER_HUMAN && !actor.suspended &&
            actorUserId in group.adminUserIds
    }

    /** Appoint a user-group admin (D13: under the company admin).
     *  D9: an AI can never hold this seat either — refused. */
    @Synchronized
    fun addUserGroupAdmin(scopeId: String, groupId: String, userId: String, actorUserId: String): Boolean {
        val index = userGroups.indexOfFirst { it.id == groupId && it.scopeId == scopeId }
        if (index < 0) return false
        if (!isCompanyAdmin(scopeId, actorUserId)) return false
        val candidate = users.firstOrNull { it.id == userId } ?: return false
        if (candidate.scopeId != scopeId) return false
        if (candidate.kind != USER_HUMAN) return false // D9
        val snap = Snapshot()
        userGroups[index] = userGroups[index].copy(
            memberUserIds = userGroups[index].memberUserIds + userId,
            adminUserIds = userGroups[index].adminUserIds + userId
        )
        return persistOrRollback(snap)
    }

    // ---- device groups (D12/D32) ----

    /** Create a device group; actor must be a company admin of the
     *  scope (D13). The transport set is validated against the six
     *  rungs and stored in the given (failover) order (D32). */
    @Synchronized
    fun addDeviceGroup(group: DeviceGroup, actorUserId: String): Boolean {
        if (scope(group.scopeId) == null) return false
        if (group.id.isBlank() || deviceGroups.any { it.id == group.id }) return false
        if (!isCompanyAdmin(group.scopeId, actorUserId)) return false
        if (group.transportSet.isEmpty() || !TransportPolicy.isValidSet(group.transportSet)) return false // D38 F7: empty set refused
        val snap = Snapshot()
        deviceGroups.add(group.copy(transportSet = TransportPolicy.normalizeOrderedSet(group.transportSet)))
        return persistOrRollback(snap)
    }

    @Synchronized
    fun deviceGroup(groupId: String): DeviceGroup? = deviceGroups.firstOrNull { it.id == groupId }

    @Synchronized
    fun deviceGroupsInScope(scopeId: String): List<DeviceGroup> =
        deviceGroups.filter { it.scopeId == scopeId }

    /**
     * D32: changing a device group's transport SET is a group-admin
     * act. The actor must be a company admin of the scope or hold
     * the `admin` right on a grant covering this device group.
     * Anyone else is refused — widening AND narrowing alike; the set
     * is never changed by a non-admin, silently or otherwise.
     */
    @Synchronized
    fun setGroupTransports(scopeId: String, groupId: String, transports: List<String>, actorUserId: String): Boolean {
        val index = deviceGroups.indexOfFirst { it.id == groupId && it.scopeId == scopeId }
        if (index < 0) return false
        if (transports.isEmpty() || !TransportPolicy.isValidSet(transports)) return false // D38 F7
        if (!canAdministerDeviceGroup(scopeId, actorUserId, groupId)) return false
        val snap = Snapshot()
        deviceGroups[index] = deviceGroups[index].copy(
            transportSet = TransportPolicy.normalizeOrderedSet(transports)
        )
        recordEvent(EVENT_GROUP_TRANSPORTS_SET, scopeId, actorUserId, groupId,
            "transport set -> ${TransportPolicy.normalizeOrderedSet(transports).joinToString(",")}")
        return persistOrRollback(snap)
    }

    /**
     * Device-group membership, DERIVED from the Slice 1 enrollment
     * roster: a device is a member exactly when its enrollment
     * record (group id bound at mint) names this group, its scope
     * matches the group's scope kind (or it was a local pairing
     * filed into the group), and it is not revoked. There is no
     * second, hand-edited membership list in this store.
     */
    @Synchronized
    fun deviceGroupMemberIds(scopeId: String, groupId: String): List<String> =
        membersOf(scopeId, groupId, enrollmentStore?.all() ?: emptyList())

    /** Pure derivation over a caller-supplied roster snapshot. */
    fun membersOf(scopeId: String, groupId: String, roster: List<EnrollmentStore.EnrolledDevice>): List<String> {
        val group = deviceGroups.firstOrNull { it.id == groupId && it.scopeId == scopeId } ?: return emptyList()
        val scopeKind = scopes.firstOrNull { it.id == scopeId }?.kind ?: return emptyList()
        return roster.filter { device ->
            !device.revoked && device.groupId == group.id &&
                (device.scope == scopeKind || device.scope == EnrollmentStore.SCOPE_LOCAL)
        }.map { it.deviceId }
    }

    // ---- grants (D12/D7) ----

    /**
     * Create/replace a grant. Both groups must live in [scopeId]
     * (cross-scope grants are refused, D8); rights must be a
     * non-empty subset of {use, enroll, admin}. The actor must be a
     * company admin of the scope (D12/D13: the network's admin
     * decides who may use/enroll/administer).
     */
    @Synchronized
    fun addGrant(grant: Grant, actorUserId: String): Boolean {
        if (scope(grant.scopeId) == null) return false
        if (!isCompanyAdmin(grant.scopeId, actorUserId)) return false
        if (grant.rights.isEmpty() || !grant.rights.all { it in RIGHTS }) return false
        val ug = userGroups.firstOrNull { it.id == grant.userGroupId } ?: return false
        val dg = deviceGroups.firstOrNull { it.id == grant.deviceGroupId } ?: return false
        if (ug.scopeId != grant.scopeId || dg.scopeId != grant.scopeId) return false
        val snap = Snapshot()
        grants.removeAll { it.scopeId == grant.scopeId && it.userGroupId == grant.userGroupId && it.deviceGroupId == grant.deviceGroupId }
        grants.add(grant.copy(rights = grant.rights.map { it.trim().lowercase() }.toSet()))
        return persistOrRollback(snap)
    }

    @Synchronized
    fun grantsInScope(scopeId: String): List<Grant> = grants.filter { it.scopeId == scopeId }

    @Synchronized
    fun grant(scopeId: String, userGroupId: String, deviceGroupId: String): Grant? =
        grants.firstOrNull {
            it.scopeId == scopeId && it.userGroupId == userGroupId && it.deviceGroupId == deviceGroupId
        }

    /**
     * Effective rights of a user over a device group: the union over
     * every user group they sit in of that group's grants (D7/D12).
     * D9 backstop: an AI's union NEVER contains `admin`, whatever
     * any grant says.
     */
    @Synchronized
    fun rightsFor(scopeId: String, userId: String, deviceGroupId: String): Set<String> {
        val user = users.firstOrNull { it.id == userId && it.scopeId == scopeId } ?: return emptySet()
        if (user.suspended) return emptySet()
        val rights = mutableSetOf<String>()
        userGroups.filter { it.scopeId == scopeId && userId in it.memberUserIds }.forEach { ug ->
            grant(scopeId, ug.id, deviceGroupId)?.let { rights.addAll(it.rights) }
        }
        if (user.kind == USER_AI) rights.remove(RIGHT_ADMIN) // D9
        return rights
    }

    @Synchronized
    fun canUse(scopeId: String, userId: String, deviceGroupId: String): Boolean =
        RIGHT_USE in rightsFor(scopeId, userId, deviceGroupId)

    /**
     * Scope-admin test (mirror of the Windows IsScopeAdminLocked):
     * in a PERSONAL scope every live human user of the scope is
     * its admin (the owner); in a company scope, a company-admin
     * seat holder. Suspended users hold no authority.
     */
    @Synchronized
    fun isScopeAdmin(scopeId: String, userId: String): Boolean {
        val scopeRecord = scope(scopeId) ?: return false
        val user = users.firstOrNull { it.id == userId && it.scopeId == scopeId } ?: return false
        if (user.suspended) return false
        if (scopeRecord.kind == SCOPE_PERSONAL) return user.kind == USER_HUMAN
        return isCompanyAdmin(scopeId, userId)
    }

    /**
     * Does this user hold a right on a device group (D7/D12)?
     * Mirror of the Windows UserHasRight: scope admins hold every
     * right (in a personal scope that is the owner); otherwise the
     * user must sit in a user group whose grant on the device
     * group carries the right. An AI NEVER holds the admin right
     * (D9), whatever its groups' grants say. Suspended users hold
     * nothing. Unknown right names hold nothing.
     */
    @Synchronized
    fun userHasRight(scopeId: String, userId: String, deviceGroupId: String, right: String): Boolean {
        val r = right.trim().lowercase()
        if (r !in RIGHTS) return false
        val user = users.firstOrNull { it.id == userId && it.scopeId == scopeId } ?: return false
        if (user.suspended) return false
        if (r == RIGHT_ADMIN && user.kind != USER_HUMAN) return false // D9
        // D38 Block H review F5: the admin shortcut is exactly as
        // wide as its doc — no wider. (a) The device group must
        // belong to THIS scope first (the canAdministerDeviceGroup
        // D38 F2 rule): a foreign group id confers nothing, not
        // even to an admin. (b) In a PERSONAL scope the shortcut
        // belongs to the OWNER — the scope's first live human —
        // not to every human who happens to be in the scope: a
        // second human in a personal scope holds only granted
        // rights.
        if (deviceGroups.none { it.id == deviceGroupId && it.scopeId == scopeId }) return false
        if (isScopeAdminForRight(scopeId, userId)) return true
        return r in rightsFor(scopeId, userId, deviceGroupId)
    }

    /** The admin test [userHasRight] applies: company scope —
     *  [isScopeAdmin] as-is; personal scope — only the owner
     *  (the first non-suspended human in the scope, in roster
     *  order). [isScopeAdmin] itself is unchanged for its other
     *  callers (suspension and structural acts keep their
     *  recorded posture). */
    private fun isScopeAdminForRight(scopeId: String, userId: String): Boolean {
        val scopeRecord = scope(scopeId) ?: return false
        if (scopeRecord.kind != SCOPE_PERSONAL) return isScopeAdmin(scopeId, userId)
        val owner = users.firstOrNull {
            it.scopeId == scopeId && it.kind == USER_HUMAN && !it.suspended
        } ?: return false
        return owner.id == userId
    }

    @Synchronized
    fun canEnroll(scopeId: String, userId: String, deviceGroupId: String): Boolean =
        RIGHT_ENROLL in rightsFor(scopeId, userId, deviceGroupId)

    /** Structural authority over a device group: a company-admin
     *  seat, or the `admin` right via a grant (D12/D7). AI: never. */
    @Synchronized
    fun canAdministerDeviceGroup(scopeId: String, userId: String, deviceGroupId: String): Boolean {
        // D38 S2-AND F2: a group id that does not live in THIS scope
        // confers nothing here — the company-admin shortcut must not
        // fire for a foreign (or personal-scope) group.
        if (deviceGroups.none { it.id == deviceGroupId && it.scopeId == scopeId }) return false
        val user = users.firstOrNull { it.id == userId && it.scopeId == scopeId } ?: return false
        if (user.kind != USER_HUMAN) return false // D9
        if (user.suspended) return false // D38 F4: suspended = no authority
        if (isCompanyAdmin(scopeId, userId)) return true
        return RIGHT_ADMIN in rightsFor(scopeId, userId, deviceGroupId)
    }

    /** Device groups a user can see in a scope (D8): company admins
     *  see the full roster; members see the groups their user groups
     *  hold any grant on. */
    @Synchronized
    fun visibleDeviceGroupsForUser(scopeId: String, userId: String): List<DeviceGroup> {
        if (isCompanyAdmin(scopeId, userId)) return deviceGroupsInScope(scopeId)
        return deviceGroupsInScope(scopeId).filter { rightsFor(scopeId, userId, it.id).isNotEmpty() }
    }

    // ---- structural acts, grant-gated (D7/D12) ----

    /** Delete a device group: requires the `admin` right on a grant
     *  covering it or a company-admin seat. Grants touching the
     *  group are removed with it. */
    @Synchronized
    fun deleteDeviceGroup(scopeId: String, groupId: String, actorUserId: String): Boolean {
        val group = deviceGroups.firstOrNull { it.id == groupId && it.scopeId == scopeId } ?: return false
        if (!canAdministerDeviceGroup(scopeId, actorUserId, groupId)) return false
        val snap = Snapshot()
        deviceGroups.remove(group)
        grants.removeAll { it.scopeId == scopeId && it.deviceGroupId == groupId }
        recordEvent(EVENT_DEVICE_GROUP_DELETED, scopeId, actorUserId, groupId, "device group deleted")
        return persistOrRollback(snap)
    }

    /** Delete a user group: requires a company-admin seat or the
     *  actor's own admin seat ON THAT user group (D7: a group's
     *  admin controls its structural acts). A grant's `admin` right
     *  is over a DEVICE group — it confers no structural rights
     *  over the user group that holds the grant. */
    @Synchronized
    fun deleteUserGroup(scopeId: String, groupId: String, actorUserId: String): Boolean {
        val group = userGroups.firstOrNull { it.id == groupId && it.scopeId == scopeId } ?: return false
        val actor = users.firstOrNull { it.id == actorUserId && it.scopeId == scopeId } ?: return false
        if (actor.kind != USER_HUMAN) return false // D9
        if (actor.suspended) return false // D38 F4
        if (!isCompanyAdmin(scopeId, actorUserId) && actorUserId !in group.adminUserIds) return false
        val snap = Snapshot()
        userGroups.remove(group)
        grants.removeAll { it.scopeId == scopeId && it.userGroupId == groupId }
        recordEvent(EVENT_USER_GROUP_DELETED, scopeId, actorUserId, groupId, "user group deleted")
        return persistOrRollback(snap)
    }

    /**
     * Delete a device (D7: admins only). Slice 1's roster has no
     * hard delete — removal IS revocation there, effective
     * immediately — so this revokes through the enrollment store.
     * Requires the `admin` right on the device's group or a
     * company-admin seat.
     */
    @Synchronized
    fun deleteDevice(scopeId: String, deviceId: String, actorUserId: String): Boolean {
        val store = enrollmentStore ?: return false
        val device = store.byId(deviceId) ?: return false
        // D38 S2-AND F2: the device must belong to THIS scope — its
        // group must be a device group of the scope and its
        // enrollment scope kind must match the scope's kind (or be a
        // local pairing filed into the group). A company admin of
        // one scope can never revoke another scope's device by
        // passing their own scopeId.
        val scopeRecord = scope(scopeId) ?: return false
        if (deviceGroups.none { it.id == device.groupId && it.scopeId == scopeId }) return false
        if (device.scope != scopeRecord.kind && device.scope != EnrollmentStore.SCOPE_LOCAL) return false
        if (!canAdministerDeviceGroup(scopeId, actorUserId, device.groupId)) return false
        val snap = Snapshot()
        if (!store.revoke(deviceId)) return false
        recordEvent(EVENT_DEVICE_DELETED, scopeId, actorUserId, deviceId, "device revoked (delete)")
        return persistOrRollback(snap)
    }

    // ---- company ceiling + transport resolution (D31/D32) ----

    /** Set the scope-level transport ceiling (D10/D31 cap). Company
     *  scopes only; actor must be a company admin. Null clears the
     *  cap. Personal scopes are uncapped by definition (D31). */
    @Synchronized
    fun setCompanyCeiling(scopeId: String, ceiling: List<String>?, actorUserId: String): Boolean {
        val scopeRecord = scope(scopeId) ?: return false
        if (scopeRecord.kind != SCOPE_COMPANY) return false
        if (!isCompanyAdmin(scopeId, actorUserId)) return false
        val snap = Snapshot()
        if (ceiling == null) {
            ceilings.remove(scopeId)
        } else {
            if (ceiling.isEmpty() || !TransportPolicy.isValidSet(ceiling)) return false // D38 F7: empty ceiling refused (null clears)
            ceilings[scopeId] = TransportPolicy.normalizeOrderedSet(ceiling)
        }
        return persistOrRollback(snap)
    }

    @Synchronized
    fun companyCeiling(scopeId: String): List<String>? {
        val scopeRecord = scope(scopeId) ?: return null
        if (scopeRecord.kind == SCOPE_PERSONAL) return null // D31: personal = uncapped
        return ceilings[scopeId]
    }

    /** D31/D32 resolution for an enrolled device in this store. */
    @Synchronized
    fun effectiveTransports(device: EnrollmentStore.EnrolledDevice, deviceGroup: DeviceGroup): List<String> =
        TransportPolicy.effectiveTransports(
            device, deviceGroup.transportSet,
            if (deviceGroup.scopeId.isNotBlank()) companyCeiling(deviceGroup.scopeId) else null
        )

    @Synchronized
    fun effectiveTransportsFor(scopeId: String, deviceId: String): List<String>? {
        val device = enrollmentStore?.byId(deviceId) ?: return null
        val group = deviceGroups.firstOrNull { it.id == device.groupId && it.scopeId == scopeId } ?: return null
        return TransportPolicy.effectiveTransports(device, group.transportSet, companyCeiling(scopeId))
    }

    /**
     * Update a device's transport mode / pin (D31/D32). The pin must
     * be a subset of the resolved set (group set ∩ company ceiling):
     * a pin outside the set is REJECTED here, at update time — the
     * stored record is left untouched, never silently widened.
     *
     * D38 S2-AND F7: this DOES need an actor. The old "narrow-only,
     * no actor" reasoning was false — switching manual -> auto or
     * inherit un-pins the device and WIDENS it to the full resolved
     * set. Rules: [actorUserId] must be a non-suspended user of the
     * scope holding `use`/`enroll`/`admin` on the device's group
     * (or a company admin); any update whose resulting effective
     * set is not a subset of the current effective set is a
     * WIDENING and requires [canAdministerDeviceGroup]; `manual`
     * with an empty pin is refused (a pin must name its rungs);
     * revoked devices refuse.
     */
    @Synchronized
    fun updateDeviceTransports(
        scopeId: String,
        deviceId: String,
        transportMode: String,
        allowedTransports: Set<String>,
        actorUserId: String
    ): Boolean {
        val store = enrollmentStore ?: return false
        val device = store.byId(deviceId) ?: return false
        if (device.revoked) return false
        val group = deviceGroups.firstOrNull { it.id == device.groupId && it.scopeId == scopeId } ?: return false
        val actor = users.firstOrNull { it.id == actorUserId && it.scopeId == scopeId } ?: return false
        if (actor.suspended) return false
        if (!isCompanyAdmin(scopeId, actorUserId) && rightsFor(scopeId, actorUserId, group.id).isEmpty()) {
            return false
        }
        val mode = EnrollmentStore.normalizeTransportMode(transportMode)
        if (mode != transportMode.trim().lowercase()) return false // unknown mode: refuse, don't degrade
        val pin = allowedTransports.map { it.trim().lowercase() }.filter { it.isNotBlank() }.toSet()
        if (mode == EnrollmentStore.TRANSPORT_MODE_MANUAL && pin.isEmpty()) return false // D38 F7
        if (pin.isNotEmpty() &&
            !TransportPolicy.isPinWithinSet(pin, group.transportSet, companyCeiling(scopeId))
        ) return false // D32: outside-set pin rejected at update time
        val ceiling = companyCeiling(scopeId)
        val currentEffective = TransportPolicy.effectiveTransports(device, group.transportSet, ceiling).toSet()
        val newEffective = TransportPolicy.effectiveTransports(
            device.copy(transportMode = mode, allowedTransports = pin), group.transportSet, ceiling
        ).toSet()
        if (!currentEffective.containsAll(newEffective) &&
            !canAdministerDeviceGroup(scopeId, actorUserId, group.id)
        ) return false // D38 F7: widening is an admin act
        return store.setTransport(deviceId, mode, pin)
    }

    // ---- enrollment mint attribution (for D14) ----

    /** Record that [mintedByUserId] minted the enrollment of
     *  [deviceId] in [scopeId]. Attribution only — membership still
     *  derives from the enrollment roster itself.
     *
     *  D38 S2-AND F5: attribution is VALIDATED, not voluntary —
     *  the device must exist in the enrollment roster, not be
     *  revoked, and its mint-bound group must be a device group of
     *  THIS scope. Without that, a company scope could attribute a
     *  personal-scope device to one of its users and revoke it
     *  through offboarding. Returns whether attribution was
     *  recorded. (Deriving attribution from the Slice 1 mint
     *  itself needs a minter field in Slice 1's record — named as
     *  a spec gap in the D38 reconciliation report.) */
    @Synchronized
    fun recordEnrollmentMint(scopeId: String, deviceId: String, mintedByUserId: String): Boolean {
        val minter = users.firstOrNull { it.id == mintedByUserId && it.scopeId == scopeId } ?: return false
        val device = enrollmentStore?.byId(deviceId) ?: return false
        if (device.revoked) return false
        if (deviceGroups.none { it.id == device.groupId && it.scopeId == scopeId }) return false
        val scopeRecord = scope(scopeId) ?: return false
        if (device.scope != scopeRecord.kind && device.scope != EnrollmentStore.SCOPE_LOCAL) return false
        val snap = Snapshot()
        mintAttributions[deviceId] = scopeId to minter.id
        return persistOrRollback(snap)
    }

    @Synchronized
    fun mintedBy(deviceId: String): String? = mintAttributions[deviceId]?.second

    // ---- offboarding (D14/D26) ----

    /**
     * Compute the blast list for removing [userId] from [scopeId]
     * WITHOUT firing anything: user-group seats, the company-admin
     * seat, grants touching those groups, enrollments the user
     * minted, AI pairings they own, and the live-session
     * requirement, named. Null when the user is not in the scope.
     */
    @Synchronized
    fun blastList(scopeId: String, userId: String): BlastList? {
        val user = users.firstOrNull { it.id == userId && it.scopeId == scopeId } ?: return null
        val seats = userGroups.filter { it.scopeId == scopeId && userId in it.memberUserIds }.map { it.id }
        val adminSeatsHeld = userGroups.filter { it.scopeId == scopeId && userId in it.adminUserIds }.map { it.id }
        val touching = grants.filter { g ->
            g.scopeId == scopeId && (g.userGroupId in seats || g.userGroupId in adminSeatsHeld)
        }
        val minted = mintAttributions.entries
            .filter { it.value.first == scopeId && it.value.second == userId }
            .map { it.key }.sorted()
        val ownedAis = users.filter {
            it.scopeId == scopeId && it.kind == USER_AI && it.pairedByUserId == userId
        }.map { it.id }
        return BlastList(
            scopeId = scopeId,
            userId = userId,
            userGroupSeats = seats,
            userGroupAdminSeats = adminSeatsHeld,
            // Seat fact, not authority: the D13/D26 guards in
            // removeUser must fire for a suspended seat holder too.
            isCompanyAdmin = companyAdmins(scopeId).contains(userId),
            grantsTouching = touching,
            mintedEnrollmentDeviceIds = minted,
            ownedAiUserIds = ownedAis,
            liveSessionRequirement = LIVE_SESSION_REQUIREMENT,
            requiresLiveSessionKill = true
        )
    }

    /**
     * D14 complete offboarding in one action. The blast list is
     * computed and returned BEFORE anything fires (see
     * [RemoveOutcome.blast]); on a refusal nothing has changed.
     *
     * Guards, in order: a personal scope is untouchable (the wall
     * cuts both ways); the target must be a user of THIS scope and
     * the actor a company admin of THIS scope (cross-scope removal
     * refused); the last company admin cannot be removed (D26);
     * removing a company admin requires [stepUp] = true (D13/D26).
     *
     * On fire: user-group seats and any group-admin seats removed,
     * the company-admin seat removed, enrollments the user minted
     * REVOKED in the enrollment roster, AI pairings they own
     * SUSPENDED (not deleted, D14/D9), the user record removed, and
     * an offboarding event recorded for the session layer to honor
     * (live sessions must be killed — the requirement named in the
     * blast list).
     */
    @Synchronized
    fun removeUser(scopeId: String, userId: String, actorUserId: String, stepUp: Boolean): RemoveOutcome {
        val scopeRecord = scope(scopeId)
            ?: return RemoveOutcome(null, false, "unknown scope")
        val blast = blastList(scopeId, userId)
            ?: return RemoveOutcome(null, false, "user is not in this scope (cross-scope removal refused)")
        if (scopeRecord.kind == SCOPE_PERSONAL) {
            return RemoveOutcome(blast, false, "personal scope is untouchable (D14 wall)")
        }
        if (!isCompanyAdmin(scopeId, actorUserId)) {
            return RemoveOutcome(blast, false, "actor is not a company admin of this scope")
        }
        if (blast.isCompanyAdmin && companyAdmins(scopeId).size <= 1) {
            return RemoveOutcome(blast, false, "last company admin cannot be removed (D26)")
        }
        if (blast.isCompanyAdmin && !stepUp) {
            return RemoveOutcome(blast, false, "removing a company admin requires step-up confirmation (D13/D26)")
        }
        // D38 S2-AND F6: revocation must be PROVABLE before anything
        // fires. If the user minted enrollments, the enrollment
        // store must be present and every minted device must exist
        // in it — otherwise refuse with NOTHING changed, instead of
        // reporting a revocation that never happened.
        if (blast.mintedEnrollmentDeviceIds.isNotEmpty()) {
            val store = enrollmentStore
                ?: return RemoveOutcome(blast, false, "enrollment store unavailable: minted enrollments cannot be revoked")
            if (blast.mintedEnrollmentDeviceIds.any { store.byId(it) == null }) {
                return RemoveOutcome(blast, false, "a minted enrollment is missing from the enrollment roster: revocation cannot be proven")
            }
            // Scope check (F5 defense in depth): never revoke a
            // device whose group is not a group of THIS scope.
            if (blast.mintedEnrollmentDeviceIds.any { deviceId ->
                    val dev = store.byId(deviceId)!!
                    deviceGroups.none { it.id == dev.groupId && it.scopeId == scopeId } ||
                        (dev.scope != scopeRecord.kind && dev.scope != EnrollmentStore.SCOPE_LOCAL)
                }) {
                return RemoveOutcome(blast, false, "a minted enrollment belongs to another scope: revocation refused (D8 wall)")
            }
        }
        // Fire — with a snapshot so a persistence failure rolls the
        // whole act back instead of leaving memory, disk and the
        // enrollment roster out of sync (F6).
        val groupsBefore = userGroups.toList()
        val seatsBefore = adminSeats.mapValues { it.value.toMutableSet() }
        val usersBefore = users.toList()
        val mintsBefore = mintAttributions.toMap()
        val eventsBefore = eventList.size
        var revokedCount = 0
        try {
            for (i in userGroups.indices) {
                val ug = userGroups[i]
                if (ug.scopeId == scopeId && (userId in ug.memberUserIds || userId in ug.adminUserIds)) {
                    userGroups[i] = ug.copy(
                        memberUserIds = ug.memberUserIds - userId,
                        adminUserIds = ug.adminUserIds - userId
                    )
                }
            }
            adminSeats[scopeId]?.remove(userId)
            blast.mintedEnrollmentDeviceIds.forEach { deviceId ->
                if (enrollmentStore?.revoke(deviceId) == true) revokedCount++
                mintAttributions.remove(deviceId)
            }
            for (i in users.indices) {
                val u = users[i]
                if (u.scopeId == scopeId && u.kind == USER_AI && u.pairedByUserId == userId) {
                    users[i] = u.copy(suspended = true)
                }
            }
            users.removeAll { it.id == userId && it.scopeId == scopeId }
            recordEvent(
                EVENT_USER_OFFBOARDED, scopeId, actorUserId, userId,
                "seats=${blast.userGroupSeats.size} adminSeats=${blast.userGroupAdminSeats.size} " +
                    "admin=${blast.isCompanyAdmin} " +
                    "mintedRevoked=$revokedCount aiSuspended=${blast.ownedAiUserIds.size} " +
                    "liveSessionsMustBeKilled=true"
            )
            save()
        } catch (e: Exception) {
            userGroups.clear(); userGroups.addAll(groupsBefore)
            adminSeats.clear(); adminSeats.putAll(seatsBefore)
            users.clear(); users.addAll(usersBefore)
            mintAttributions.clear(); mintAttributions.putAll(mintsBefore)
            while (eventList.size > eventsBefore) eventList.removeAt(eventList.size - 1)
            // bd-and-remote F12(b): the roster state above IS
            // rolled back, but enrollment revocations already made
            // in the (separate) enrollment store are NOT undone —
            // revocation has no inverse, by design. The outcome
            // says so plainly instead of claiming a clean rollback.
            return RemoveOutcome(blast, false,
                "persistence failed during offboarding: roster change rolled back (${e.message}); " +
                    "WARNING: $revokedCount enrollment revocation(s) already made are irreversible and stand")
        }
        return RemoveOutcome(blast, true, null)
    }

    // ---- read shapes (D2) ----

    /** Operator side only: the full roster of ONE scope (D8-filtered). */
    @Synchronized
    fun operatorRoster(scopeId: String): OperatorRoster? {
        val scope = scope(scopeId) ?: return null
        val roster = enrollmentStore?.all() ?: emptyList()
        val groups = deviceGroupsInScope(scopeId)
        return OperatorRoster(
            scope = scope,
            users = usersInScope(scopeId),
            companyAdminUserIds = companyAdmins(scopeId),
            userGroups = userGroupsInScope(scopeId),
            deviceGroups = groups,
            deviceGroupMemberIds = groups.associate { it.id to membersOf(scopeId, it.id, roster) },
            grants = grantsInScope(scopeId),
            devices = roster.filter { device ->
                // D38 S2-AND F9: same scope-kind rule as membersOf —
                // groupId alone must never pull a foreign-kind
                // device into this scope's fleet.
                !device.revoked && groups.any { it.id == device.groupId } &&
                    (device.scope == scope.kind || device.scope == EnrollmentStore.SCOPE_LOCAL)
            }
        )
    }

    /**
     * D2: the endpoint's view of itself. Returns ONLY the device's
     * own enrolled record, its Slice 1 receipts, and the
     * allowed-operators list derived from those receipts. Receipts
     * in Slice 1 are endpoint-local records (recorded on the
     * endpoint when IT was enrolled), so the store's receipt list is
     * this device's own history. No other device's data exists in
     * this shape.
     */
    @Synchronized
    fun endpointView(deviceId: String): EndpointView? {
        val store = enrollmentStore ?: return null
        val device = store.byId(deviceId) ?: return null
        // D38 S2-AND F3: receipts are endpoint-local records, but on
        // a shared store instance only the receipts of THIS device's
        // own enrollment (same scope kind + group name) are its
        // history — another device's receipts are not returned.
        val receipts = store.receipts().filter {
            it.scope == device.scope && it.groupName == device.groupName
        }
        val operators = receipts.distinctBy { it.enrollerDeviceId }.map {
            AllowedOperator(it.enrollerDeviceId, it.enrollerName, it.scope, it.groupName)
        }
        return EndpointView(device, receipts, operators)
    }

    // ---- events ----

    @Synchronized
    fun events(): List<RosterEvent> = eventList.toList()

    private fun recordEvent(type: String, scopeId: String, actorUserId: String, subjectId: String, detail: String) {
        eventList.add(RosterEvent(clockMs(), type, scopeId, actorUserId, subjectId, detail))
    }

    // ---- validation helpers (callers hold the monitor) ----

    private fun membersValid(scopeId: String, memberIds: Set<String>): Boolean =
        memberIds.all { id -> users.any { it.id == id && it.scopeId == scopeId } }

    private fun groupAdminsValid(scopeId: String, adminIds: Set<String>): Boolean =
        adminIds.all { id ->
            users.any { it.id == id && it.scopeId == scopeId && it.kind == USER_HUMAN }
        }

    // ---- persistence (PairingStore/EnrollmentStore style) ----

    private fun load() {
        if (!storeFile.exists()) return
        try {
            storeFile.readLines().forEach { line ->
                if (line.isBlank()) return@forEach
                val parts = line.split('\t')
                try {
                    when (parts.getOrNull(0)) {
                        "scope" -> {
                            if (parts.size < 4) return@forEach
                            val kind = parts[2].trim().lowercase()
                            if (kind !in SCOPE_KINDS) return@forEach
                            if (scopes.any { it.id == parts[1] }) return@forEach
                            scopes.add(Scope(parts[1], kind, parts[3]))
                        }
                        "user" -> {
                            if (parts.size < 7) return@forEach
                            val kind = parts[4].trim().lowercase()
                            if (kind !in USER_KINDS) return@forEach
                            if (users.any { it.id == parts[1] }) return@forEach
                            users.add(
                                User(
                                    id = parts[1], scopeId = parts[2], displayName = parts[3],
                                    kind = kind,
                                    pairedByUserId = parts[5].takeIf { it.isNotBlank() },
                                    suspended = parts[6] == "1"
                                )
                            )
                        }
                        "admin" -> {
                            if (parts.size < 3) return@forEach
                            adminSeats.getOrPut(parts[1]) { mutableSetOf() }.add(parts[2])
                        }
                        "ceiling" -> {
                            if (parts.size < 3) return@forEach
                            ceilings[parts[1]] = parts[2].csvList()
                        }
                        "usergroup" -> {
                            if (parts.size < 6) return@forEach
                            if (userGroups.any { it.id == parts[1] }) return@forEach
                            userGroups.add(
                                UserGroup(parts[1], parts[2], parts[3], parts[4].csvSet(), parts[5].csvSet())
                            )
                        }
                        "devicegroup" -> {
                            if (parts.size < 5) return@forEach
                            if (deviceGroups.any { it.id == parts[1] }) return@forEach
                            deviceGroups.add(
                                DeviceGroup(parts[1], parts[2], parts[3], TransportPolicy.normalizeOrderedSet(parts[4].csvList()))
                            )
                        }
                        "grant" -> {
                            if (parts.size < 5) return@forEach
                            val rights = parts[4].csvSet()
                            if (rights.isEmpty() || !rights.all { it in RIGHTS }) return@forEach
                            grants.add(Grant(parts[1], parts[2], parts[3], rights))
                        }
                        "mint" -> {
                            if (parts.size < 4) return@forEach
                            mintAttributions[parts[2]] = parts[1] to parts[3]
                        }
                        "event" -> {
                            if (parts.size < 7) return@forEach
                            eventList.add(
                                RosterEvent(
                                    atMs = parts[1].toLongOrNull() ?: return@forEach,
                                    type = parts[2], scopeId = parts[3],
                                    actorUserId = parts[4], subjectId = parts[5], detail = parts[6]
                                )
                            )
                        }
                        else -> Unit // corrupt/unknown line: skip, never fatal
                    }
                } catch (_: Exception) {
                    // corrupt line: skip, never fatal
                }
            }
        } catch (_: Exception) {
            // unreadable store: start empty, never fatal
        }
        sanitizeLoadedAdminState()
    }

    /**
     * D38 S2-AND F10: load() parses lines without cross-checks, so a
     * hand-edited or corrupted file could name an AI, a cross-scope
     * user, or a nonexistent user as a company admin or user-group
     * admin. After parsing, drop every such seat: admin authority
     * may only ever rest on a human user OF THE SAME SCOPE who
     * exists in the loaded roster. (Suspended humans keep their
     * seats — [isCompanyAdmin] withholds authority while suspended
     * and unsuspension restores it.) Drops are recorded as an event.
     */
    private fun sanitizeLoadedAdminState() {
        var dropped = 0
        val seatScopes = adminSeats.keys.toList()
        for (scopeId in seatScopes) {
            val seats = adminSeats[scopeId] ?: continue
            val invalid = seats.filter { id ->
                val u = users.firstOrNull { it.id == id }
                u == null || u.scopeId != scopeId || u.kind != USER_HUMAN
            }
            if (invalid.isNotEmpty()) {
                dropped += invalid.size
                seats.removeAll(invalid.toSet())
                recordEvent(EVENT_LOAD_SANITIZED, scopeId, "store", invalid.joinToString(","),
                    "dropped invalid company-admin seats at load")
            }
        }
        for (i in userGroups.indices) {
            val g = userGroups[i]
            val invalid = g.adminUserIds.filter { id ->
                val u = users.firstOrNull { it.id == id }
                u == null || u.scopeId != g.scopeId || u.kind != USER_HUMAN
            }
            if (invalid.isNotEmpty()) {
                dropped += invalid.size
                userGroups[i] = g.copy(adminUserIds = g.adminUserIds - invalid.toSet())
                recordEvent(EVENT_LOAD_SANITIZED, g.scopeId, "store", invalid.joinToString(","),
                    "dropped invalid user-group admin ids at load for group ${g.id}")
            }
        }
    }

    private fun save() {
        val lines = mutableListOf<String>()
        scopes.forEach { s ->
            lines.add(listOf("scope", s.id.csvSafe(), s.kind.csvSafe(), s.name.csvSafe()).joinToString("\t"))
        }
        ceilings.forEach { (scopeId, rungs) ->
            lines.add(listOf("ceiling", scopeId.csvSafe(), rungs.joinToString(",")).joinToString("\t"))
        }
        users.forEach { u ->
            lines.add(
                listOf(
                    "user", u.id.csvSafe(), u.scopeId.csvSafe(), u.displayName.csvSafe(),
                    u.kind.csvSafe(), (u.pairedByUserId ?: "").csvSafe(), if (u.suspended) "1" else "0"
                ).joinToString("\t")
            )
        }
        adminSeats.forEach { (scopeId, ids) ->
            ids.forEach { lines.add(listOf("admin", scopeId.csvSafe(), it.csvSafe()).joinToString("\t")) }
        }
        userGroups.forEach { g ->
            lines.add(
                listOf(
                    "usergroup", g.id.csvSafe(), g.scopeId.csvSafe(), g.name.csvSafe(),
                    g.memberUserIds.joinToString(",") { it.csvSafe() },
                    g.adminUserIds.joinToString(",") { it.csvSafe() }
                ).joinToString("\t")
            )
        }
        deviceGroups.forEach { g ->
            lines.add(
                listOf(
                    "devicegroup", g.id.csvSafe(), g.scopeId.csvSafe(), g.name.csvSafe(),
                    g.transportSet.joinToString(",")
                ).joinToString("\t")
            )
        }
        grants.forEach { g ->
            lines.add(
                listOf(
                    "grant", g.scopeId.csvSafe(), g.userGroupId.csvSafe(), g.deviceGroupId.csvSafe(),
                    g.rights.joinToString(",")
                ).joinToString("\t")
            )
        }
        mintAttributions.forEach { (deviceId, attribution) ->
            lines.add(
                listOf("mint", attribution.first.csvSafe(), deviceId.csvSafe(), attribution.second.csvSafe())
                    .joinToString("\t")
            )
        }
        eventList.forEach { e ->
            lines.add(
                listOf(
                    "event", e.atMs.toString(), e.type.csvSafe(), e.scopeId.csvSafe(),
                    e.actorUserId.csvSafe(), e.subjectId.csvSafe(), e.detail.csvSafe()
                ).joinToString("\t")
            )
        }
        // D38 S2-AND F12 / S3-AND F6: atomic replace only — write
        // the tmp file, fsync, rename over the store. The old
        // in-place writeText fallback could truncate the store on
        // a crash mid-write; a failed rename now throws instead.
        val parent = storeFile.parentFile
        val bytes = lines.joinToString("\n").toByteArray(Charsets.UTF_8)
        if (parent != null) {
            val tmp = File(parent, storeFile.name + ".tmp")
            java.io.FileOutputStream(tmp).use { out ->
                out.write(bytes)
                out.fd.sync()
            }
            if (!tmp.renameTo(storeFile)) {
                tmp.delete()
                throw IllegalStateException("roster store: atomic rename failed for ${storeFile.name}")
            }
        } else {
            java.io.FileOutputStream(storeFile).use { out ->
                out.write(bytes)
                out.fd.sync()
            }
        }
    }

    private fun String.csvList(): List<String> = split(',').filter { it.isNotBlank() }
    private fun String.csvSet(): Set<String> = csvList().toSet()

    /** Field values ride a TSV line and some ride comma-joined
     *  sub-fields, so tabs, newlines and commas cannot survive. */
    private fun String.csvSafe(): String =
        replace('\t', ' ').replace('\n', ' ').replace('\r', ' ').replace(',', ' ')

    companion object {
        const val SCOPE_PERSONAL = "personal"
        const val SCOPE_COMPANY = "company"
        val SCOPE_KINDS = setOf(SCOPE_PERSONAL, SCOPE_COMPANY)

        const val USER_HUMAN = "human"
        const val USER_AI = "ai"
        val USER_KINDS = setOf(USER_HUMAN, USER_AI)

        const val RIGHT_USE = "use"
        const val RIGHT_ENROLL = "enroll"
        const val RIGHT_ADMIN = "admin"
        /** RMM-11 camera extension (Android mirror, Lane B3): the
         *  `view` right, added to the roster's own D12 machinery —
         *  no shadow permission store. Per the 2026-11-21 camera
         *  ruling (b), an AI pairing may hold `view` ONLY when a
         *  human admin explicitly scoped it; rightsFor's D9 backstop
         *  strips `admin` only, so `view` follows the ordinary grant
         *  path and is never present by default. */
        const val RIGHT_VIEW = "view"
        val RIGHTS = setOf(RIGHT_USE, RIGHT_ENROLL, RIGHT_ADMIN, RIGHT_VIEW)

        const val EVENT_ADMIN_SEATED = "admin_seated"
        const val EVENT_ADMIN_REMOVED = "admin_removed"
        const val EVENT_USER_GROUP_DELETED = "user_group_deleted"
        const val EVENT_DEVICE_GROUP_DELETED = "device_group_deleted"
        const val EVENT_DEVICE_DELETED = "device_deleted"
        const val EVENT_GROUP_TRANSPORTS_SET = "group_transports_set"
        const val EVENT_USER_OFFBOARDED = "user_offboarded"
        const val EVENT_USER_SUSPENDED = "user_suspended"
        const val EVENT_USER_UNSUSPENDED = "user_unsuspended"
        const val EVENT_USER_GROUP_MEMBER_ADDED = "user_group_member_added"
        const val EVENT_USER_GROUP_MEMBER_REMOVED = "user_group_member_removed"
        const val EVENT_LOAD_SANITIZED = "load_sanitized"

        /** D14: sessions are a later slice — the blast list names
         *  the requirement and the offboarding event is the record
         *  the session layer must honor. */
        const val LIVE_SESSION_REQUIREMENT =
            "live sessions of the removed user must be killed by the session layer when it honors the offboarding event"
    }
}
