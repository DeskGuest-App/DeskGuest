package io.deskguest.app

import android.app.Activity
import android.os.Bundle
import android.view.Gravity
import android.view.ViewGroup
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import io.deskguest.app.roster.RosterStore
import io.deskguest.app.transport.DiscoveredDevice
import io.deskguest.app.ui.Fonts
import io.deskguest.app.ui.UiKit
import io.deskguest.app.wiring.PlatformRuntime
import io.deskguest.app.wiring.PlatformStores

/**
 * "People & groups" — the operator surface for the Slice 2 roster
 * (wired 0.4.6): scopes side by side (personal + company, D8), users,
 * company admins, user groups × device groups with their ordered
 * transport sets, and grants.
 *
 * Every act on this screen goes through the roster store with the
 * acting user the operator names — the store enforces the gates
 * (company admin / grant admin right, last-admin guard, step-up,
 * scope wall) and this screen reports refusals as refusals; it
 * never substitutes another actor or retries around a gate.
 *
 * Offboarding (D14) is two explicit steps: "Show what removal does"
 * renders the blast list FIRST; only then does the remove button
 * exist, and firing re-checks everything in the store.
 */
class RosterActivity : Activity() {

    private lateinit var root: LinearLayout
    private lateinit var stores: PlatformStores

    private var selectedScopeId: String? = null
    private var actorId: String = ""
    private var newScopeKind: String = RosterStore.SCOPE_PERSONAL
    private var newUserKind: String = RosterStore.USER_HUMAN
    private var stepUp: Boolean = false
    private var blastForUserId: String? = null
    private var discoveredDevices: List<DiscoveredDevice>? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        stores = PlatformRuntime.get(this)
        root = UiKit.page(this)
        refresh()
    }

    private fun refresh() {
        root.removeAllViews()
        renderHeader()
        section("actor") { renderActor() }
        section("scopes") { renderScopes() }
        section("discovery") { renderDiscovery() }
        section("sas") { renderSas() }
        val scopeId = selectedScopeId
        if (scopeId != null && stores.roster.scope(scopeId) != null) {
            section("scope detail") { renderScopeDetail(scopeId) }
            section("add user") { renderAddUser(scopeId) }
            section("groups") { renderGroupForms(scopeId) }
            section("grants") { renderGrantForm(scopeId) }
            section("offboarding") { renderOffboarding(scopeId) }
        }
    }

    private fun section(name: String, block: () -> Unit) {
        try {
            block()
        } catch (t: Throwable) {
            CrashTrap.record(this, "roster section '$name'", t)
            try {
                root.addView(UiKit.muted(this, "One part of this screen failed to load ($name). The failure was recorded."))
            } catch (_: Throwable) {
            }
        }
    }

    private fun renderHeader() {
        val header = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        header.addView(TextView(this).apply {
            text = "‹"
            textSize = 30f
            setTextColor(UiKit.TEXT)
            setPadding(0, 0, UiKit.dp(this@RosterActivity, 12), UiKit.dp(this@RosterActivity, 4))
            isClickable = true
            setOnClickListener { finish() }
        })
        header.addView(TextView(this).apply {
            text = "People & groups"
            textSize = 24f
            typeface = Fonts.medium(this@RosterActivity)
            setTextColor(UiKit.TEXT)
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        })
        root.addView(header)
    }

    /** U9: pairing verification — for each device enrolled through
     *  this device, show the SAS both sides derived from both keys.
     *  The human compares it with the string on the other device
     *  and confirms HERE, on this endpoint (the confirm is a local
     *  act; nothing remote can set it). Until then the record
     *  honestly shows "not yet verified". This lives on the roster
     *  (operator) screen, NOT the endpoint screen — the endpoint
     *  screen's D2 no-.all() discipline stands. */
    private fun renderSas() {
        val devices = stores.enrollment.all().filter { it.sas.isNotBlank() }
        if (devices.isEmpty()) return
        root.addView(UiKit.sectionTitle(this, "Pairing verification"))
        val card = UiKit.card(this)
        card.addView(
            UiKit.muted(
                this,
                "Compare each string with the one shown on the other device. " +
                    "If they differ, the wrong key was enrolled — report the mismatch."
            )
        )
        devices.forEach { d ->
            card.addView(UiKit.body(this, d.displayName))
            card.addView(UiKit.mono(this, "Compare: ${d.sas}", 14f))
            if (d.sasConfirmed) {
                card.addView(UiKit.muted(this, "Verified ✓"))
            } else {
                card.addView(UiKit.muted(this, "Not yet verified"))
                card.addView(UiKit.primaryButton(this, "They match — confirm") {
                    stores.enrollment.confirmSas(d.deviceId)
                    toast("Verified for ${d.displayName}.")
                    refresh()
                })
                card.addView(UiKit.outlineButton(this, "They don't match") {
                    stores.enrollment.reportSasMismatch(d.deviceId)
                    toast("Mismatch recorded for ${d.displayName}. The pairing stays unconfirmed.")
                    refresh()
                })
            }
        }
        root.addView(card)
    }

    private fun renderActor() {
        val card = UiKit.card(this)
        card.addView(
            UiKit.muted(
                this,
                "Structural acts run as the user named here, and the roster's own gates " +
                    "decide what that user may do. A refusal is the gate working."
            )
        )
        val actorField = field("Acting as (user ID)").apply { setText(actorId) }
        card.addView(actorField)
        card.addView(UiKit.outlineButton(this, "Use this actor") {
            actorId = actorField.text.toString().trim()
            blastForUserId = null
            refresh()
        })
        card.addView(UiKit.switchRow(this, "Step-up confirmed (for admin acts)", stepUp) { stepUp = it })
        root.addView(card)
    }

    private fun renderScopes() {
        root.addView(UiKit.sectionTitle(this, "Scopes"))
        val scopes = stores.scopes()
        if (scopes.isEmpty()) {
            root.addView(UiKit.muted(this, "No scopes yet. Create the first one below."))
        }
        // Personal and company scopes sit side by side (D8); neither
        // sees into the other — selecting one shows only its records.
        scopes.forEach { scope ->
            val roster = stores.operatorRoster(scope.id)
            val card = UiKit.card(this)
            val row = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
            }
            row.addView(TextView(this).apply {
                text = scope.name
                textSize = 17f
                typeface = Fonts.medium(this@RosterActivity)
                setTextColor(UiKit.TEXT)
                layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
            })
            row.addView(UiKit.chip(this, scope.kind, UiKit.ChipKind.NEUTRAL))
            if (scope.id == selectedScopeId) row.addView(UiKit.chip(this, "Open", UiKit.ChipKind.GOOD))
            card.addView(row)
            card.addView(
                UiKit.muted(
                    this,
                    "${roster?.users?.size ?: 0} user(s) · ${roster?.userGroups?.size ?: 0} user group(s) · " +
                        "${roster?.deviceGroups?.size ?: 0} device group(s) · ${roster?.devices?.size ?: 0} device(s)"
                )
            )
            card.addView(UiKit.outlineButton(this, if (scope.id == selectedScopeId) "Close" else "Open this scope") {
                selectedScopeId = if (scope.id == selectedScopeId) null else scope.id
                blastForUserId = null
                refresh()
            })
            root.addView(card)
        }
        val createCard = UiKit.card(this)
        createCard.addView(UiKit.body(this, "New scope"))
        val idField = field("Scope ID (e.g. home, acme)")
        val nameField = field("Scope name")
        createCard.addView(idField)
        createCard.addView(nameField)
        createCard.addView(UiKit.navRow(this, "Kind", newScopeKind) {
            newScopeKind = if (newScopeKind == RosterStore.SCOPE_PERSONAL) {
                RosterStore.SCOPE_COMPANY
            } else {
                RosterStore.SCOPE_PERSONAL
            }
            refresh()
        })
        createCard.addView(UiKit.primaryButton(this, "Create scope") {
            val id = idField.text.toString().trim()
            val name = nameField.text.toString().trim()
            if (id.isEmpty() || name.isEmpty()) {
                toast("Enter the scope ID and name.")
                return@primaryButton
            }
            if (stores.addScope(id, newScopeKind, name)) {
                selectedScopeId = id
                toast("Scope created.")
            } else {
                toast("That scope was refused — the ID may already exist.")
            }
            refresh()
        })
        root.addView(createCard)
    }

    private fun renderScopeDetail(scopeId: String) {
        val roster = stores.operatorRoster(scopeId) ?: return
        root.addView(UiKit.sectionTitle(this, roster.scope.name))
        // users + admins
        val usersCard = UiKit.card(this)
        usersCard.addView(UiKit.body(this, "Users"))
        if (roster.users.isEmpty()) usersCard.addView(UiKit.muted(this, "No users in this scope yet."))
        roster.users.forEach { user ->
            val isAdmin = user.id in roster.companyAdminUserIds
            usersCard.addView(UiKit.body(this, "${user.displayName} (${user.id})"))
            val chips = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
            chips.addView(UiKit.chip(this, user.kind, UiKit.ChipKind.NEUTRAL))
            if (isAdmin) chips.addView(UiKit.chip(this, "company admin", UiKit.ChipKind.ACCENT))
            if (user.suspended) chips.addView(UiKit.chip(this, "suspended", UiKit.ChipKind.BAD))
            usersCard.addView(chips)
            val actions = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
            if (!isAdmin && user.kind == RosterStore.USER_HUMAN) {
                actions.addView(UiKit.textButton(this, "Make admin") {
                    act(stores.addCompanyAdmin(scopeId, user.id, actorId.ifBlank { null }), "Admin seat granted.", "Refused — the actor must already be a company admin (or this is the first seat).")
                })
            }
            if (isAdmin) {
                actions.addView(UiKit.textButton(this, "Remove admin") {
                    act(stores.removeCompanyAdmin(scopeId, user.id, actorId, stepUp), "Admin seat removed.", "Refused — removing a fellow admin needs an admin actor and step-up, and the last admin cannot be removed.")
                })
            }
            actions.addView(UiKit.textButton(this, if (user.suspended) "Unsuspend" else "Suspend") {
                act(stores.setUserSuspended(scopeId, user.id, !user.suspended, actorId, stepUp), if (user.suspended) "User unsuspended." else "User suspended — their authority stops now.", "Refused — suspension is a company-admin act (step-up when the target is an admin; the last active admin cannot be suspended).")
            })
            usersCard.addView(actions)
        }
        root.addView(usersCard)
        // user groups
        val ugCard = UiKit.card(this)
        ugCard.addView(UiKit.body(this, "User groups"))
        if (roster.userGroups.isEmpty()) ugCard.addView(UiKit.muted(this, "None yet."))
        roster.userGroups.forEach { group ->
            ugCard.addView(UiKit.body(this, "${group.name} (${group.id})"))
            ugCard.addView(UiKit.muted(this, "Members: ${group.memberUserIds.joinToString(", ").ifBlank { "—" }} · Admins: ${group.adminUserIds.joinToString(", ").ifBlank { "—" }}"))
            ugCard.addView(UiKit.outlineButton(this, "Delete user group") {
                act(stores.deleteUserGroup(scopeId, group.id, actorId), "User group deleted.", "Refused — deleting a group needs a company admin or an admin of that group.")
            })
        }
        root.addView(ugCard)
        // device groups + transports + members + devices
        val dgCard = UiKit.card(this)
        dgCard.addView(UiKit.body(this, "Device groups"))
        if (roster.deviceGroups.isEmpty()) dgCard.addView(UiKit.muted(this, "None yet."))
        roster.deviceGroups.forEach { group ->
            dgCard.addView(UiKit.body(this, "${group.name} (${group.id})"))
            dgCard.addView(UiKit.muted(this, "Transports, in failover order: ${group.transportSet.joinToString(" → ")}"))
            val members = roster.deviceGroupMemberIds[group.id].orEmpty()
            dgCard.addView(UiKit.muted(this, "Devices: ${members.size}"))
            val transportsField = field("New transport set (comma list, e.g. lan,hub,tor)").apply {
                setText(group.transportSet.joinToString(","))
            }
            dgCard.addView(transportsField)
            dgCard.addView(UiKit.outlineButton(this, "Set transports") {
                val set = transportsField.text.toString().split(",").map { it.trim() }.filter { it.isNotEmpty() }
                act(stores.setGroupTransports(scopeId, group.id, set, actorId), "Transport set updated.", "Refused — changing the set is a group-admin act and the set must be valid rungs.")
            })
            dgCard.addView(UiKit.outlineButton(this, "Delete device group") {
                act(stores.deleteDeviceGroup(scopeId, group.id, actorId), "Device group deleted.", "Refused — deleting a group needs the admin right on it or a company-admin seat.")
            })
        }
        root.addView(dgCard)
        // devices in this scope (operator roster)
        if (roster.devices.isNotEmpty()) {
            val devCard = UiKit.card(this)
            devCard.addView(UiKit.body(this, "Devices"))
            roster.devices.forEach { device ->
                devCard.addView(UiKit.body(this, "${device.displayName} — ${device.groupName}"))
                devCard.addView(UiKit.mono(this, device.deviceId, 11f))
                if (device.revoked) devCard.addView(UiKit.chip(this, "revoked", UiKit.ChipKind.BAD))
                if (!device.revoked) {
                    devCard.addView(UiKit.outlineButton(this, "Delete device (revoke)") {
                        act(stores.deleteDevice(scopeId, device.deviceId, actorId), "Device revoked.", "Refused — deleting a device needs the admin right on its group or a company-admin seat, in this scope.")
                    })
                }
            }
            root.addView(devCard)
        }
        // grants
        val grantCard = UiKit.card(this)
        grantCard.addView(UiKit.body(this, "Grants"))
        if (roster.grants.isEmpty()) grantCard.addView(UiKit.muted(this, "None yet."))
        roster.grants.forEach { grant ->
            grantCard.addView(UiKit.muted(this, "${grant.userGroupId} → ${grant.deviceGroupId}: ${grant.rights.joinToString(", ")}"))
        }
        root.addView(grantCard)
    }

    private fun renderAddUser(scopeId: String) {
        root.addView(UiKit.sectionTitle(this, "Add a user"))
        val card = UiKit.card(this)
        val idField = field("User ID")
        val nameField = field("Display name")
        val ownerField = field("Paired by (user ID — AI users only)")
        card.addView(idField)
        card.addView(nameField)
        card.addView(ownerField)
        card.addView(UiKit.navRow(this, "Kind", newUserKind) {
            newUserKind = if (newUserKind == RosterStore.USER_HUMAN) RosterStore.USER_AI else RosterStore.USER_HUMAN
            refresh()
        })
        card.addView(UiKit.primaryButton(this, "Add user") {
            val id = idField.text.toString().trim()
            val name = nameField.text.toString().trim()
            if (id.isEmpty() || name.isEmpty()) {
                toast("Enter the user ID and name.")
                return@primaryButton
            }
            val owner = ownerField.text.toString().trim().ifBlank { null }
            act(stores.addUser(scopeId, id, name, newUserKind, owner), "User added.", "Refused — an AI needs a human pairing owner in this same scope, and IDs must be new.")
        })
        root.addView(card)
    }

    private fun renderGroupForms(scopeId: String) {
        root.addView(UiKit.sectionTitle(this, "Groups & membership"))
        val card = UiKit.card(this)
        val ugId = field("User group ID")
        val ugName = field("User group name")
        card.addView(ugId)
        card.addView(ugName)
        card.addView(UiKit.outlineButton(this, "Create user group") {
            act(
                stores.addUserGroup(scopeId, ugId.text.toString().trim(), ugName.text.toString().trim(), actorId),
                "User group created.", "Refused — creating a group is a company-admin act."
            )
        })
        val dgId = field("Device group ID")
        val dgName = field("Device group name")
        val dgTransports = field("Transport set (comma list)").apply { setText("lan,hub,mesh,ipv6,ownpath,tor") }
        card.addView(dgId)
        card.addView(dgName)
        card.addView(dgTransports)
        card.addView(UiKit.outlineButton(this, "Create device group") {
            val set = dgTransports.text.toString().split(",").map { it.trim() }.filter { it.isNotEmpty() }
            act(
                stores.addDeviceGroup(scopeId, dgId.text.toString().trim(), dgName.text.toString().trim(), set, actorId),
                "Device group created.", "Refused — creating a group is a company-admin act and the transport set must be valid."
            )
        })
        val memberGroup = field("Group ID (membership)")
        val memberUser = field("User ID (membership)")
        card.addView(memberGroup)
        card.addView(memberUser)
        card.addView(UiKit.outlineButton(this, "Add user to group") {
            act(
                stores.addUserToGroup(scopeId, memberGroup.text.toString().trim(), memberUser.text.toString().trim(), actorId),
                "Added to the group.", "Refused — membership changes need a company admin or an admin of that group."
            )
        })
        card.addView(UiKit.outlineButton(this, "Remove user from group") {
            act(
                stores.removeUserFromGroup(scopeId, memberGroup.text.toString().trim(), memberUser.text.toString().trim(), actorId),
                "Removed from the group.", "Refused — membership changes need a company admin or an admin of that group."
            )
        })
        root.addView(card)
    }

    private fun renderGrantForm(scopeId: String) {
        root.addView(UiKit.sectionTitle(this, "Add a grant"))
        val card = UiKit.card(this)
        val ugField = field("User group ID")
        val dgField = field("Device group ID")
        val rightsField = field("Rights (comma list: use, enroll, admin)").apply { setText("use") }
        card.addView(ugField)
        card.addView(dgField)
        card.addView(rightsField)
        card.addView(UiKit.primaryButton(this, "Save grant") {
            val rights = rightsField.text.toString().split(",").map { it.trim() }.filter { it.isNotEmpty() }.toSet()
            act(
                stores.addGrant(scopeId, ugField.text.toString().trim(), dgField.text.toString().trim(), rights, actorId),
                "Grant saved.", "Refused — grants are a company-admin act, both groups must live in this scope, and rights must be use/enroll/admin."
            )
        })
        root.addView(card)
    }

    private fun renderOffboarding(scopeId: String) {
        root.addView(UiKit.sectionTitle(this, "Remove a user (offboarding)"))
        val card = UiKit.card(this)
        card.addView(
            UiKit.muted(
                this,
                "Removal is shown before it happens: the list below is everything the " +
                    "removal will touch. Nothing fires until the remove button is tapped."
            )
        )
        val userField = field("User ID to remove")
        card.addView(userField)
        card.addView(UiKit.outlineButton(this, "Show what removal does") {
            val target = userField.text.toString().trim()
            val blast = stores.offboardPreview(scopeId, target)
            if (blast == null) {
                blastForUserId = null
                toast("No such user in this scope — a removal in another scope is refused here too.")
            } else {
                blastForUserId = target
            }
            refresh()
        })
        val target = blastForUserId
        if (target != null) {
            val blast = stores.offboardPreview(scopeId, target)
            if (blast != null) {
                card.addView(UiKit.body(this, "Removing $target will:"))
                card.addView(UiKit.muted(this, "• Leave user groups: ${blast.userGroupSeats.joinToString(", ").ifBlank { "none" }}"))
                card.addView(UiKit.muted(this, "• Leave group-admin seats: ${blast.userGroupAdminSeats.joinToString(", ").ifBlank { "none" }}"))
                card.addView(UiKit.muted(this, "• Company-admin seat: ${if (blast.isCompanyAdmin) "yes — removed" else "no"}"))
                card.addView(UiKit.muted(this, "• Grants touched: ${blast.grantsTouching.size}"))
                card.addView(UiKit.muted(this, "• Enrollments they minted, revoked: ${blast.mintedEnrollmentDeviceIds.size}"))
                card.addView(UiKit.muted(this, "• AI pairings they own, suspended: ${blast.ownedAiUserIds.joinToString(", ").ifBlank { "none" }}"))
                card.addView(UiKit.muted(this, "• Live sessions: ${blast.liveSessionRequirement}"))
                card.addView(UiKit.stopButton(this, "Remove $target") {
                    val outcome = stores.offboard(scopeId, target, actorId, stepUp)
                    blastForUserId = null
                    if (outcome.fired) {
                        toast("$target removed. Their seats, minted enrollments, and AI pairings were handled as listed.")
                    } else {
                        toast("Removal refused: ${outcome.refusal ?: "the roster's guards refused it."}")
                    }
                    refresh()
                })
            }
        }
        root.addView(card)
    }

    /**
     * Local discovery (D19/D20) — the operator surface. Announcing
     * broadcasts only this device's id hash, its name, and its
     * enrollment state. Browsing listens for one bounded window;
     * devices this install is not enrolled with show as "available
     * to enroll". Discovery grants no trust: nothing here can start
     * a session — enrollment (This device screen) is the only door.
     */
    private fun renderDiscovery() {
        root.addView(UiKit.sectionTitle(this, "Nearby devices (local discovery)"))
        val card = UiKit.card(this)
        card.addView(UiKit.muted(this,
            "Devices on this network running DeskGuest announce themselves. " +
                "An unpaired device is available to enroll — discovery alone never grants control."))
        val nameField = field("This device's announced name").apply {
            setText(android.os.Build.MODEL ?: "Android device")
        }
        card.addView(nameField)
        card.addView(UiKit.outlineButton(this, "Announce this device") {
            val name = nameField.text.toString().trim()
            Thread {
                val ok = stores.announceDiscovery(name)
                runOnUiThread {
                    toast(if (ok) "Announced on the local network." else "Announce failed — check the network.")
                }
            }.start()
        })
        card.addView(UiKit.outlineButton(this, "Look for devices (3 seconds)") {
            toast("Listening for announcements…")
            Thread {
                val found = try { stores.browseDiscovery(3_000) } catch (_: Exception) { emptyList() }
                runOnUiThread {
                    discoveredDevices = found
                    refresh()
                }
            }.start()
        })
        val found = discoveredDevices
        if (found != null) {
            if (found.isEmpty()) {
                card.addView(UiKit.muted(this, "No devices heard in the last look."))
            }
            found.forEach { device ->
                val label = when {
                    device.isKnownPeer -> "${device.announcement.displayName} — enrolled peer"
                    else -> "${device.announcement.displayName} — available to enroll"
                }
                card.addView(UiKit.body(this, label))
                card.addView(UiKit.muted(this,
                    "id hash ${device.announcement.deviceIdHash.take(12)}… · ${device.announcement.enrollmentState}"))
            }
        }
        root.addView(card)
    }

    /** Run a gated act and report the store's verdict honestly. */
    private fun act(ok: Boolean, success: String, refusal: String) {
        toast(if (ok) success else refusal)
        refresh()
    }

    private fun field(hint: String): EditText = EditText(this).apply {
        this.hint = hint
        isSingleLine = true
        textSize = 16f
        typeface = Fonts.regular(this@RosterActivity)
        setTextColor(UiKit.TEXT)
        setHintTextColor(UiKit.SECONDARY)
        background = null
    }

    private fun toast(text: String) =
        Toast.makeText(this, text, Toast.LENGTH_LONG).show()
}
