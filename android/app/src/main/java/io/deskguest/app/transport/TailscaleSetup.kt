package io.deskguest.app.transport

import org.json.JSONArray
import org.json.JSONObject

/**
 * Block C part 3 — the in-app Tailscale setup (D4), Android form,
 * mirroring the Windows DeskGuest.Shared.Tailscale layer and its T2
 * binding conditions.
 *
 * ANDROID REALITY (TS-03, upstream tailscale#13174): the Android
 * Tailscale app has NO logtail opt-out — the kill switch cannot be
 * asserted on this platform. The mesh rung here is therefore
 * OPERATOR-PERSONAL-DEVICE ONLY: the flow states the carve-out
 * before it proceeds and requires the operator to acknowledge what
 * the vendor collects; an ENDPOINT never offers the mesh rung and
 * its setup is refused at the first gate (D3: endpoints never
 * sign in — they join any mesh with single-use keys DeskGuest mints).
 *
 * The one human moment is Tailscale's own IdP sign-in page; DeskGuest
 * never sees, types, or stores that credential. Everything after
 * it runs on a scoped OAuth trust credential — a personal API
 * token is unscoped 90-day full-admin and is refused by shape.
 * The live-account leg (a real sign-in and API apply) is UNPROVEN:
 * no Tailscale account may be created by this programme; the flow
 * is proven here against a local mock of the API surface.
 */

enum class MeshPlatform { DESKTOP, ANDROID, IOS }
enum class MeshRole { OPERATOR, ENDPOINT }

/** The honesty the flow itself carries (D15/D16 + TS-03). */
object TailscaleHonesty {
    const val VENDOR_LABEL =
        "About this rung: session traffic is end-to-end encrypted between your devices, but on this rung " +
        "Tailscale Inc. processes connection metadata and the device inventory for the tailnet — DeskGuest's " +
        "'no vendor server holds your data' claim does not cover this rung. The free tier covers 6 users " +
        "and 50 tagged resources; beyond that a paid Tailscale plan is required."

    const val MOBILE_CARVE_OUT_LABEL =
        "On Android and iOS the Tailscale app cannot turn off its log uploads (there is no logtail " +
        "opt-out), so this rung is for the operator's own personal device only. The vendor collects " +
        "connection metadata and device inventory on this rung, and diagnostic logs cannot be switched " +
        "off. Endpoints never use this rung."

    const val SIGN_IN_BOUNDARY_LABEL =
        "You sign in on Tailscale's own page. DeskGuest never sees, types, or stores that credential; afterwards " +
        "DeskGuest works through a scoped OAuth trust credential that you can revoke from the tailnet admin console."
}

/** Credential shapes. A personal API token (`tskey-api-…`) is
 *  unscoped, 90-day, full-admin — refused. A scoped OAuth trust
 *  credential (`tskey-client-…` + secret) is the only shape DeskGuest
 *  holds. */
object TailscaleCredentialGuard {
    const val KIND_PERSONAL_API_TOKEN = "personal_api_token"
    const val KIND_SCOPED_OAUTH = "scoped_oauth"
    const val KIND_UNKNOWN = "unknown"

    const val SCOPE_POLICY = "policy_file"
    const val SCOPE_AUTH_KEYS = "auth_keys"
    const val SCOPE_DEVICES_READ = "devices:core:read"

    fun classify(secret: String?): String {
        val s = secret?.trim().orEmpty()
        return when {
            s.startsWith("tskey-api-") -> KIND_PERSONAL_API_TOKEN
            s.startsWith("tskey-client-") -> KIND_SCOPED_OAUTH
            else -> KIND_UNKNOWN
        }
    }

    /** Null = accepted; otherwise the refusal reason. Storage
     *  refuses personal tokens and anything without scopes. */
    fun acceptForStorage(secret: String?, scopes: Set<String>): String? {
        if (secret.isNullOrBlank()) return "no credential was provided"
        return when (classify(secret)) {
            KIND_PERSONAL_API_TOKEN ->
                "refused: that is a personal API token — unscoped, 90-day, full-admin. DeskGuest only holds " +
                "scoped OAuth trust credentials; create one in the tailnet admin console (Settings → " +
                "OAuth clients) with only the scopes this setup needs."
            KIND_SCOPED_OAUTH ->
                if (scopes.isEmpty()) "refused: a scoped credential must name its scopes; a scopeless credential is not stored."
                else null
            else ->
                "refused: unrecognized credential shape. DeskGuest expects a scoped OAuth trust credential " +
                "(client id + secret) from the tailnet admin console."
        }
    }
}

/** The D12 mapping inputs: DeskGuest roster shape → tailnet shape. */
data class TailnetGrant(val userGroup: String, val deviceGroup: String, val rights: Set<String>)

data class TailnetMapping(
    val userGroups: Map<String, List<String>> = emptyMap(),
    val deviceGroups: Map<String, String> = emptyMap(),
    val grants: List<TailnetGrant> = emptyList()
)

/** Builds the tailnet ACL policy from the D12 mapping. Values are
 *  strictly validated character shapes and the document is built
 *  with a real JSON serializer — the T5 config-injection lesson
 *  applied to this API: hostile roster text is refused by name,
 *  never escaped into the payload. The builder NEVER emits an
 *  `ssh` section (TS-10) and never emits a wildcard grant. */
object AclBuilder {
    private val NAME_SHAPE = Regex("^[a-z0-9][a-z0-9._-]{0,62}$")
    private val MEMBER_SHAPE = Regex("^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$")

    fun build(mapping: TailnetMapping, sessionPort: Int): String {
        require(sessionPort in 1..65535) { "session port out of range: $sessionPort" }
        val root = JSONObject()

        val groups = JSONObject()
        for ((group, members) in mapping.userGroups) {
            requireName(group, "user group")
            val arr = JSONArray()
            for (member in members) {
                require(MEMBER_SHAPE.matches(member)) { "invalid group member value: '$member'" }
                arr.put(member)
            }
            groups.put("group:$group", arr)
        }
        root.put("groups", groups)

        val tagOwners = JSONObject()
        val tags = JSONObject()
        for ((deviceGroup, tag) in mapping.deviceGroups) {
            requireName(deviceGroup, "device group")
            requireName(tag, "tag")
            tags.put("tag:$tag", JSONArray())
        }
        // Enroll rights make the user groups owners of the tags of
        // the device groups they may enroll into (D12).
        val ownersByTag = mutableMapOf<String, MutableList<String>>()
        for (grant in mapping.grants) {
            requireName(grant.userGroup, "grant user group")
            requireName(grant.deviceGroup, "grant device group")
            if ("enroll" in grant.rights) {
                val tag = mapping.deviceGroups[grant.deviceGroup]
                    ?: throw IllegalArgumentException("grant names device group '${grant.deviceGroup}' with no tag mapping")
                ownersByTag.getOrPut(tag) { mutableListOf() }.add("group:${grant.userGroup}")
            }
        }
        for ((tag, owners) in ownersByTag) tagOwners.put("tag:$tag", JSONArray(owners.distinct()))
        root.put("tagOwners", tagOwners)
        root.put("tags", tags)

        val acls = JSONArray()
        for (grant in mapping.grants) {
            if ("use" !in grant.rights) continue
            val tag = mapping.deviceGroups[grant.deviceGroup]
                ?: throw IllegalArgumentException("grant names device group '${grant.deviceGroup}' with no tag mapping")
            val entry = JSONObject()
            entry.put("action", "accept")
            entry.put("src", JSONArray().put("group:${grant.userGroup}"))
            entry.put("dst", JSONArray().put("tag:$tag:$sessionPort"))
            acls.put(entry)
        }
        root.put("acls", acls)
        // bd-and-remote F6 fix: pretty-print with a 2-space indent.
        // The old single-line root.toString() made [diff] useless —
        // every policy compared as one '+' and one '-' line.
        return root.toString(2)
    }

    /** A human-readable preview diff: line-level, added/removed. */
    fun diff(before: String, after: String): String {
        val b = before.lines().map { it.trim() }.filter { it.isNotEmpty() }.toSet()
        val a = after.lines().map { it.trim() }.filter { it.isNotEmpty() }.toSet()
        val sb = StringBuilder()
        for (line in a - b) sb.appendLine("+ $line")
        for (line in b - a) sb.appendLine("- $line")
        return if (sb.isEmpty()) "(no changes)" else sb.toString().trimEnd()
    }

    private fun requireName(value: String, what: String) {
        require(NAME_SHAPE.matches(value)) {
            "invalid $what name: '$value' (lowercase letters, digits, '.', '_' or '-', starting alphanumeric, max 63)"
        }
    }
}

/** The slice of Tailscale's API the setup drives. The live
 *  implementation belongs to the platform layer; tests use a
 *  local mock. Secrets travel in bodies/headers, never URLs. */
interface TailscaleApi {
    fun exchangeToken(clientId: String, clientSecret: String, scopes: Set<String>): ApiResult<String>
    fun getPolicy(accessToken: String): ApiResult<String>
    fun validatePolicy(accessToken: String, policyJson: String): ApiResult<Unit>
    fun applyPolicy(accessToken: String, policyJson: String): ApiResult<Unit>
}

data class ApiResult<T>(val ok: Boolean, val value: T? = null, val error: String? = null) {
    companion object {
        fun <T> success(value: T): ApiResult<T> = ApiResult(true, value)
        fun <T> failure(error: String): ApiResult<T> = ApiResult(false, null, error)
    }
}

data class PolicyOutcome(val applied: Boolean, val detail: String, val diff: String)

/** Guarded policy writes: read current → keep it as the rollback
 *  copy → validate the new policy → preview the diff → apply →
 *  roll back on failure. Nothing is applied unvalidated, and a
 *  failed apply restores the previous policy. */
class PolicyGuard(private val api: TailscaleApi) {
    fun apply(accessToken: String, newPolicyJson: String): PolicyOutcome {
        val current = api.getPolicy(accessToken)
        if (!current.ok) return PolicyOutcome(false, "could not read the current policy (${current.error}); nothing applied.", "")
        val rollbackCopy = current.value ?: return PolicyOutcome(false, "the current policy read came back empty; nothing applied.", "")
        val diff = AclBuilder.diff(rollbackCopy, newPolicyJson)
        val validation = api.validatePolicy(accessToken, newPolicyJson)
        if (!validation.ok) return PolicyOutcome(false, "the new policy failed validation (${validation.error}); nothing applied.", diff)
        val applied = api.applyPolicy(accessToken, newPolicyJson)
        if (applied.ok) return PolicyOutcome(true, "policy applied.", diff)
        val rollback = api.applyPolicy(accessToken, rollbackCopy)
        return PolicyOutcome(false,
            if (rollback.ok) "apply failed (${applied.error}); the previous policy was restored from the rollback copy."
            else "apply failed (${applied.error}) AND the rollback failed (${rollback.error}) — the tailnet policy needs manual attention in the admin console.",
            diff)
    }
}

/** Endpoint auth keys (D3): single-use ONLY, tagged, expiry ≤ 90
 *  days. A reusable key request is a refusal, not a warning. */
object EndpointAuthKeyRules {
    const val DEFAULT_EXPIRY_DAYS = 7
    const val MAX_EXPIRY_DAYS = 90

    fun refusal(reusable: Boolean, tags: List<String>, expiryDays: Int): String? = when {
        reusable -> "refused: endpoint auth keys are single-use only — a reusable key outlives the enrollment it was minted for."
        tags.isEmpty() -> "refused: an endpoint auth key must carry the device-group tag (D12)."
        expiryDays < 1 || expiryDays > MAX_EXPIRY_DAYS -> "refused: endpoint auth key expiry must be 1–$MAX_EXPIRY_DAYS days."
        else -> null
    }
}

data class MeshSetupState(
    val stage: String,
    val detail: String,
    val carveOut: Boolean = false
)

/** The setup state machine. Stages: NotStarted → (gates) →
 *  AwaitingSignIn → (sign-in completion + credential + policy) →
 *  Ready; any gate can land it in Refused with the reason.
 *
 *  bd-and-remote F6 fix: with a [stateSink] wired, every state
 *  transition is handed to the sink (the platform layer persists
 *  it — stage + detail + carve-out) and a persisted Ready is
 *  restored at construction via [restore]. Without a sink the
 *  flow keeps the old in-memory-only behavior the JVM suite
 *  drives; the sink is a seam, not a store. */
class MeshSetupFlow(
    private val stateSink: ((MeshSetupState) -> Unit)? = null,
    restored: MeshSetupState? = null
) {
    @Volatile var state: MeshSetupState = restored ?: MeshSetupState(STAGE_NOT_STARTED, "setup has not run")
        private set

    private fun transition(next: MeshSetupState): MeshSetupState {
        state = next
        try { stateSink?.invoke(next) } catch (_: Exception) { /* a failing sink never wedges the flow */ }
        return next
    }

    /** Everything that can be decided BEFORE the one sign-in
     *  moment. [desktopKillSwitchVerified] is the desktop daemon
     *  check; it is meaningless (and unused) on mobile, where the
     *  carve-out governs instead. */
    fun runPreSignIn(
        platform: MeshPlatform,
        role: MeshRole,
        carveOutAcknowledged: Boolean,
        clientVersion: String?,
        desktopKillSwitchVerified: Boolean = false
    ): MeshSetupState {
        fun refuse(reason: String): MeshSetupState =
            transition(MeshSetupState(STAGE_REFUSED, "rung refused: $reason"))

        if (role == MeshRole.ENDPOINT)
            return refuse("endpoints never sign in and never offer the mesh rung (D3). Endpoints join with single-use keys DeskGuest mints.")
        if (!ClientVersionGate.meetsFloor(clientVersion))
            return refuse("the installed Tailscale client '${clientVersion ?: "unknown"}' is below the required floor " +
                "${ClientVersionGate.MIN_CLIENT_VERSION} (pinned: ${ClientVersionGate.PINNED_CLIENT_VERSION}). Update the client first.")
        return when (platform) {
            MeshPlatform.DESKTOP ->
                if (!desktopKillSwitchVerified)
                    refuse("the logtail kill switch (TS_NO_LOGS_NO_SUPPORT) cannot be asserted and verified for the " +
                        "Tailscale daemon on this device. A daemon that ever started without it has already uploaded " +
                        "its startup logs (TS-01/TS-02), so the rung refuses to come up here.")
                else transition(MeshSetupState(STAGE_AWAITING_SIGN_IN,
                    "checks passed (client floor, kill switch verified, SSH/Serve/Funnel off). One human moment " +
                    "remains: sign in on Tailscale's own page."))
            MeshPlatform.ANDROID, MeshPlatform.IOS ->
                if (!carveOutAcknowledged)
                    refuse("on this platform the Tailscale log uploads cannot be switched off (TS-03). The rung is " +
                        "operator-personal-device only, and the flow must say so — and be acknowledged — before it proceeds.")
                else transition(MeshSetupState(STAGE_AWAITING_SIGN_IN,
                    "operator-personal device under the TS-03 carve-out: log uploads CANNOT be switched off on " +
                    "this platform. One human moment remains: sign in on Tailscale's own page.",
                    carveOut = true))
        }
    }

    /** After the sign-in moment. [signInCompleted] is the ONLY
     *  thing that crosses the D4 boundary — DeskGuest receives a
     *  completion, never a credential. */
    fun completeAfterSignIn(
        signInCompleted: Boolean,
        clientId: String,
        clientSecret: String,
        scopes: Set<String>,
        mapping: TailnetMapping,
        sessionPort: Int,
        api: TailscaleApi
    ): MeshSetupState {
        fun refuse(reason: String): MeshSetupState =
            transition(MeshSetupState(STAGE_REFUSED, "rung refused: $reason"))

        if (state.stage != STAGE_AWAITING_SIGN_IN)
            return refuse("setup is not awaiting sign-in (stage: ${state.stage}); run the checks first.")
        if (!signInCompleted)
            return refuse("sign-in was not completed on Tailscale's own page. Nothing was configured.")
        val credentialRefusal = TailscaleCredentialGuard.acceptForStorage(clientSecret, scopes)
        if (credentialRefusal != null) return refuse(credentialRefusal)
        val token = api.exchangeToken(clientId, clientSecret, scopes)
        if (!token.ok) return refuse("the scoped credential could not be exchanged for an access token (${token.error}).")
        val policyJson = try {
            AclBuilder.build(mapping, sessionPort)
        } catch (e: IllegalArgumentException) {
            return refuse("the D12 policy could not be built: ${e.message}")
        }
        val outcome = PolicyGuard(api).apply(token.value!!, policyJson)
        if (!outcome.applied) return refuse("policy apply failed: ${outcome.detail}")
        return transition(MeshSetupState(STAGE_READY,
            "mesh rung ready: scoped credential exchanged, D12 policy applied through the guarded path." +
                if (state.carveOut) " This device runs under the TS-03 mobile carve-out." else "",
            carveOut = state.carveOut))
    }

    companion object {
        const val STAGE_NOT_STARTED = "NotStarted"
        const val STAGE_REFUSED = "Refused"
        const val STAGE_AWAITING_SIGN_IN = "AwaitingSignIn"
        const val STAGE_READY = "Ready"
    }
}
