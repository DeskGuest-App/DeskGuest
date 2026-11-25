package io.agenticcontrol.app.server

/**
 * W89 / S08 Android parity — the AI access-control model: ONE grant
 * state, two views (the stepped slider and the Fine-tune panel),
 * mirroring the Windows model (Acp.Shared/Security/AccessControl.cs,
 * Lane W79) over ANDROID's real scope representation.
 *
 * The grant state is exactly a pairing's scope set
 * ([PairingStore.Pairing.scopes]) — this type invents no second
 * model. Android's scope vocabulary is {observe, drive, shell,
 * admin} (PairingStore.ALL_SCOPES): the five Windows explicit-only
 * classes (terminal, background_tools, backstage,
 * background_kit_admin, unlock) DO NOT EXIST on Android, so they
 * appear nowhere here — Fine-tune carries exactly Android's four
 * real scopes. The ladder's top stop is Android's full preset
 * verbatim (ALL_SCOPES, the same set setAccess "full" resolves to).
 *
 * Android's second layer — caps {see, tap, type, apps, shell,
 * settings}, the set McpCore gates tool calls on — is DERIVED from
 * scopes by [capsForScopes], matching both existing presets
 * exactly: observe → caps {see}; full → all caps / all scopes.
 *
 * Elevation rule (Windows parity): ADDING the admin scope — from
 * the slider or from Fine-tune — always requires the owner's
 * separate elevation confirmation in the preview
 * ([validateProposal]); it is default-refused. Removing it never
 * requires confirmation. DeskGuest never taps Allow on an Android
 * permission popup — the standing line below is part of the
 * surface (the Android form of Windows' UAC line; Android has no
 * UAC, so the copy names the Android permission popup honestly).
 */
object AccessControl {

    /** The standing permission-popup refusal line (S08, Android form). */
    const val PERMISSION_LINE =
        "DeskGuest will never tap Allow on an Android permission popup for anyone — " +
            "that tap must come from a person at the phone."

    /** The elevation class's Fine-tune label (S08 parity). */
    const val ELEVATION_LABEL =
        "Do admin jobs for me (settings changes and admin actions) — off unless you turn it on"

    /** One slider stop: its signed name, its exact grant set, and
     *  the plain consequence shown while staging it. */
    data class Stop(val name: String, val grants: Set<String>, val consequence: String)

    /** The five signed stops (REVISION-DRAFT S08), each mapped to
     *  Android's real scopes. Stop 1 is the observe preset verbatim;
     *  stop 4 is ALL_SCOPES (the full preset) verbatim. */
    val STOPS: List<Stop> = listOf(
        Stop(
            "No access", emptySet(),
            "This helper can't see or do anything on this phone."
        ),
        Stop(
            "Watch only", setOf("observe"),
            "Can see the screen and send messages. Can't tap, type, or run anything."
        ),
        Stop(
            "Suggest first", setOf("observe", "drive"),
            "Can see the screen, and tap and type to show you what it means. It can't run commands."
        ),
        Stop(
            "Ask before acting", setOf("observe", "drive", "shell"),
            "Can also run commands. The big actions — payments, sending, deleting — still ask you first, every time."
        ),
        Stop(
            "Full help", PairingStore.ALL_SCOPES,
            "Can see, drive, run commands, and do admin jobs. That includes the admin jobs switch below — it only turns on when you confirm it in the preview."
        )
    )

    /** One Fine-tune capability row: a real Android scope, its
     *  plain-verb label, and whether it is the elevation class. */
    data class Capability(val scope: String, val label: String, val isElevation: Boolean)

    /** Every grantable capability on Android, simple → advanced,
     *  the elevation class last and separated (the UI renders the
     *  separation; the order here is the panel's order). */
    val CAPABILITIES: List<Capability> = listOf(
        Capability("observe", "See the screen, and send and read messages", false),
        Capability("drive", "Tap, swipe, and type", false),
        Capability("shell", "Run commands", false),
        Capability("admin", ELEVATION_LABEL, true)
    )

    /** Classify a grant state: the stop index whose set it equals
     *  exactly, or -1 for Custom. Any non-ladder set is Custom —
     *  never silently rounded to a stop. */
    fun classify(grants: Set<String>): Int {
        for (i in STOPS.indices) if (STOPS[i].grants == grants) return i
        return -1
    }

    fun isCustom(grants: Set<String>): Boolean = classify(grants) < 0

    /** The display name of a grant state: the stop's name, or "Custom". */
    fun classifyName(grants: Set<String>): String {
        val i = classify(grants)
        return if (i >= 0) STOPS[i].name else "Custom"
    }

    /** One grant that would change: the capability, and whether it
     *  is being added (true) or removed (false). */
    data class GrantChange(val capability: Capability, val added: Boolean)

    /** The exact change preview: every grant that differs between
     *  the current state and a proposed state, in panel order.
     *  This is what the surface shows BEFORE applying — the applied
     *  set must equal the previewed set (pinned). Unknown scope
     *  strings in the CURRENT set (impossible via the store's own
     *  validation, named honestly if a hand-edited store produced
     *  one) are shown as removals, never dropped silently. */
    fun diff(current: Set<String>, proposed: Set<String>): List<GrantChange> {
        val changes = mutableListOf<GrantChange>()
        for (cap in CAPABILITIES) {
            val has = cap.scope in current
            val want = cap.scope in proposed
            if (has != want) changes.add(GrantChange(cap, want))
        }
        val known = CAPABILITIES.map { it.scope }.toSet()
        for (s in current.filter { it !in known }.sorted()) {
            if (s !in proposed) {
                changes.add(GrantChange(Capability(s, "Remove the '$s' grant", false), false))
            }
        }
        return changes
    }

    /** True when moving from current to proposed ADDS the
     *  elevation class — the move that requires the owner's
     *  separate elevation confirmation. */
    fun addsElevation(current: Set<String>, proposed: Set<String>): Boolean =
        "admin" !in current && "admin" in proposed

    /** Validate a proposed grant set for the pairing surface: only
     *  Android's real scopes may be proposed, and adding the
     *  elevation class requires the owner's separate confirmation
     *  (default refused). Returns null when valid, else the refusal
     *  reason. Enforced by PairingStore.updateScopes so the rule
     *  holds at the store, not only in the editor. */
    fun validateProposal(
        current: Set<String>,
        proposed: Set<String>,
        elevationConfirmed: Boolean
    ): String? {
        val known = CAPABILITIES.map { it.scope }.toSet()
        for (s in proposed) {
            if (s !in known) return "unknown grant '$s' — refused"
        }
        if (addsElevation(current, proposed) && !elevationConfirmed) {
            return "adding admin jobs needs the owner's separate confirmation in the preview — " +
                "refused (elevation is off unless the owner turns it on)"
        }
        return null
    }

    /** The caps McpCore gates on, derived deterministically from a
     *  scope set: observe→{see}, drive→{tap, type, apps},
     *  shell→{shell}, admin→{settings}. Matches both existing
     *  presets exactly (observe preset and full preset). */
    fun capsForScopes(scopes: Set<String>): Set<String> {
        val caps = mutableSetOf<String>()
        if ("observe" in scopes) caps.add(PairingStore.CAP_SEE)
        if ("drive" in scopes) {
            caps.add(PairingStore.CAP_TAP)
            caps.add(PairingStore.CAP_TYPE)
            caps.add(PairingStore.CAP_APPS)
        }
        if ("shell" in scopes) caps.add(PairingStore.CAP_SHELL)
        if ("admin" in scopes) caps.add(PairingStore.CAP_SETTINGS)
        return caps
    }

    /** The stored access label for a scope set, in the existing
     *  PairingStore vocabulary: the full set is "full", any subset
     *  of {observe} is "observe", everything else is "custom". */
    fun accessLabelForScopes(scopes: Set<String>): String = when {
        scopes == PairingStore.ALL_SCOPES -> PairingStore.ACCESS_FULL
        scopes.all { it == "observe" } -> PairingStore.ACCESS_OBSERVE
        else -> PairingStore.ACCESS_CUSTOM
    }

    /** The audit detail line for a change: old → new scope sets,
     *  each sorted and named (the W79 audit shape). */
    fun auditDetail(current: Set<String>, proposed: Set<String>): String =
        "grants ${current.sorted().joinToString(",").ifEmpty { "none" }} -> " +
            proposed.sorted().joinToString(",").ifEmpty { "none" }
}
