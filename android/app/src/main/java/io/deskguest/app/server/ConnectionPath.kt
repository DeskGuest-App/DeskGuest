package io.deskguest.app.server

/**
 * W98 / S09(b) Android parity — the per-pairing connection-path
 * model: ONE setting on the pairing record (AUTO / AUTO restricted
 * to an owner-picked subset / MANUAL pinned to one path), mirroring
 * the Windows model (DeskGuest.Shared/Security/ConnectionPath.cs, Lane
 * W97) over ANDROID's real pairing-bearing transports.
 *
 * ANDROID'S REAL PATHS (named from this tree's machinery, not
 * imported from Windows): a paired AI's connections are inbound
 * MCP-over-HTTP requests arriving on [McpHttpServer]'s listeners,
 * and that server binds exactly two kinds of address (0.4.0
 * hardening, McpHttpServer.defaultBindAddresses):
 * - "mesh" — the phone's Tailscale address (100.64.0.0/10), the
 *   same rung id the roster transport model uses
 *   (TransportPolicy.RUNG_MESH);
 * - "loopback" — 127.0.0.1, this phone only.
 *
 * DIVERGENCE FROM WINDOWS, NAMED: the Windows catalogue also lists
 * lan / hub / ipv6 / ownpath / tor rungs. On Android those ids exist
 * ONLY in the roster/TransportPolicy model for OUTBOUND device
 * sessions (the phone connecting to other devices); the pairing MCP
 * server has no such inbound listener — LAN is deliberately NOT
 * bound (0.4.0 hardening), and no hub/ipv6/ownpath/tor listener
 * accepts pairing traffic. Putting them in this catalogue would
 * offer the owner paths no pairing connection can ever arrive on,
 * so the pairing catalogue is exactly {mesh, loopback}.
 *
 * NEVER-WIDEN RULE (the policy's core, Jacob 2026-11-23): a
 * restricted subset or pin with no working path leaves the pairing
 * unreachable and says so — enforcement refuses, it never falls
 * back to a path the owner excluded.
 */
object ConnectionPath {

    const val PATH_MESH = "mesh"
    const val PATH_LOOPBACK = "loopback"

    const val MODE_AUTO = "auto"
    const val MODE_RESTRICTED = "restricted"
    const val MODE_MANUAL = "manual"

    /** One real arrival path: its id and its plain owner-facing name. */
    data class PathInfo(val id: String, val name: String, val blurb: String)

    /** Android's pairing-bearing paths, best first (the order the
     *  surface lists them and Describe names subsets in). */
    val PATHS: List<PathInfo> = listOf(
        PathInfo(
            PATH_MESH, "Private mesh (Tailscale)",
            "Your AI reaches this phone over your private Tailscale network."
        ),
        PathInfo(
            PATH_LOOPBACK, "This phone only (loopback)",
            "Only an AI running on this phone itself can connect."
        )
    )

    val PATH_IDS: Set<String> = PATHS.map { it.id }.toSet()

    fun pathName(id: String?): String =
        PATHS.firstOrNull { it.id == id?.trim()?.lowercase() }?.name ?: "an unknown path"

    /** The setting as stored on a pairing: a mode, the allowed
     *  subset (restricted mode), and the pin (manual mode). */
    data class Setting(
        val mode: String = MODE_AUTO,
        val rungs: Set<String> = emptySet(),
        val pin: String? = null,
        /**
         * W108 / W105-C5 fail-closed marker: this setting is the
         * honest restore of a PRESENT-BUT-CORRUPT stored record.
         * It allows NO path (see [allows]), its [describe] says the
         * setting needs attention instead of claiming a mode the
         * owner never chose, and it is never a valid proposal
         * (see [validate]). The owner re-setting the value through
         * the store is the repair path; that apply clears the flag.
         */
        val needsAttention: Boolean = false
    ) {
        companion object {
            val AUTO = Setting()

            /** The fail-closed restore for a corrupt stored record:
             *  restricted to nothing — every arrival is refused
             *  until the owner re-sets the setting. */
            val FAIL_CLOSED = Setting(
                MODE_RESTRICTED, emptySet(), null, needsAttention = true
            )
        }
    }

    /** Normalise a setting's spelling: mode and path ids trimmed
     *  and lowercased, subset kept in catalogue order. Validation
     *  is separate ([validate]) — normalising never invents or
     *  drops a path, so an unknown id survives to be refused. */
    fun normalize(setting: Setting): Setting {
        val mode = setting.mode.trim().lowercase()
        val rungs = setting.rungs.map { it.trim().lowercase() }
        val ordered = PATHS.map { it.id }.filter { it in rungs } +
            rungs.filter { it !in PATH_IDS }.sorted()
        return Setting(
            mode, ordered.toSet(),
            setting.pin?.trim()?.lowercase()?.ifBlank { null },
            needsAttention = setting.needsAttention
        )
    }

    /** Validate a proposed setting: returns null when valid, else
     *  the refusal reason. Unknown modes and unknown path ids are
     *  refused, never honored; a restricted subset must name at
     *  least one real path; a manual setting must pin exactly one
     *  real path. */
    fun validate(setting: Setting): String? {
        val s = normalize(setting)
        // W108: the fail-closed corrupt-restore marker is a restore
        // state, never a choosable setting — proposing it is refused
        // like any other invalid value.
        if (s.needsAttention) {
            return "this connection setting needs attention — choose a setting again — refused"
        }
        return when (s.mode) {
            MODE_AUTO -> null
            MODE_RESTRICTED -> {
                val unknown = s.rungs.firstOrNull { it !in PATH_IDS }
                when {
                    unknown != null -> "unknown connection path '$unknown' — refused"
                    s.rungs.isEmpty() ->
                        "a restricted setting must allow at least one path — refused"
                    else -> null
                }
            }
            MODE_MANUAL -> {
                val pin = s.pin
                when {
                    pin == null -> "a pinned (manual) setting must name its one path — refused"
                    pin !in PATH_IDS -> "unknown connection path '$pin' — refused"
                    else -> null
                }
            }
            else -> "unknown connection mode '${setting.mode}' — refused"
        }
    }

    /**
     * W108: validate a STORED record's fields at restore — stricter
     * than [validate] for proposals in exactly one respect: an AUTO
     * record whose (mode-ignored) subset/pin fields carry an unknown
     * path id is still a present-but-corrupt record, not an honest
     * AUTO the owner chose, so it too restores fail-closed. Honest
     * stored forms (auto with empty/known extra fields, a valid
     * restricted subset, a valid manual pin) all pass.
     */
    fun validateStored(setting: Setting): String? {
        validate(setting)?.let { return it }
        val s = normalize(setting)
        val unknownRung = s.rungs.firstOrNull { it !in PATH_IDS }
        if (unknownRung != null) return "unknown connection path '$unknownRung' — refused"
        val pin = s.pin
        if (pin != null && pin !in PATH_IDS) return "unknown connection path '$pin' — refused"
        return null
    }

    /** May a connection arriving over [arrivalPath] proceed under
     *  [setting]? AUTO allows every real path; restricted allows
     *  exactly its subset; manual allows exactly its pin. An empty
     *  or unknown arrival claim is NEVER allowed — enforcement
     *  treats a null arrival (not a network arrival at all: an
     *  in-process caller) before ever consulting this, mirroring
     *  W97. */
    fun allows(setting: Setting, arrivalPath: String?): Boolean {
        val arrival = arrivalPath?.trim()?.lowercase().orEmpty()
        if (arrival !in PATH_IDS) return false
        val s = normalize(setting)
        // W108: a corrupt-restore (needs-attention) setting allows
        // NO path at all — fail closed until the owner re-sets it.
        if (s.needsAttention) return false
        return when (s.mode) {
            MODE_RESTRICTED -> arrival in s.rungs
            MODE_MANUAL -> arrival == s.pin
            else -> true // auto (and any pre-W98/unknown stored mode reads as auto)
        }
    }

    /** The plain-language form the surface shows for a setting. */
    fun describe(setting: Setting): String {
        val s = normalize(setting)
        // W108: never describe a corrupt restore as a chosen mode.
        if (s.needsAttention) {
            return "Connection setting needs attention — no path is allowed " +
                "until you set it again"
        }
        return when (s.mode) {
            MODE_RESTRICTED ->
                "Auto, restricted to " + PATHS.filter { it.id in s.rungs }
                    .joinToString(", ") { it.name }
                    .ifEmpty { "no path" }
            MODE_MANUAL -> "Manual — pinned to " + pathName(s.pin)
            else -> "Auto — any working path"
        }
    }

    /** The standing never-widen line the surface carries. */
    const val NEVER_WIDEN_LINE =
        "If none of the allowed paths work, this helper stays unreachable — " +
            "the setting never widens on its own."

    /** The audit detail line for a change: old → new, described. */
    fun auditDetail(old: Setting, new: Setting): String =
        "${describe(old)} -> ${describe(new)}"

    /** The audit detail line for an enforcement refusal at a
     *  choke point: where the connection arrived, and the setting
     *  that excludes it. */
    fun refusalDetail(setting: Setting, arrivalPath: String?): String =
        "arrived over ${pathName(arrivalPath)}, which this pairing's connection " +
            "setting excludes (${describe(setting)})"
}
