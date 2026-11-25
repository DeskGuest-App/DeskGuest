package io.agenticcontrol.app.mobileop

import io.agenticcontrol.app.cameraview.ChainedAudit

/**
 * RMM-24 (Android) — Kotlin client BINDING of the six-capability
 * MobileOperator contract (Windows Acp.Shared MobileOperator.cs).
 * Binding + contract only: UI surfaces are design-phase work
 * (completion decision, 2026-11-21) and are NOT built here.
 * Contract invariants, enforced by construction:
 *  - Six capabilities, each bound to a roster right; a capability
 *    the client's rights do not cover is ABSENT, not disabled.
 *  - MobileOnlyRights is empty — there is no mobile-only right.
 *  - Presence is structural: [presenceVisible] is computed true,
 *    never a stored field that could be set false.
 *  - Approvals are content-bound + signed, verified against the
 *    enrolled client key; a signature over different content fails.
 *  - The notification queue accepts ONLY hub-alert-id lookups or
 *    hub-key-signed payloads; `platform_push` is refused BY NAME
 *    in the self-hosted shape (APNs/FCM transit is not ACP's claim).
 */
object MobileOperatorPolicy {
    // bd-and-rmm F2: the registry key for the mobile operator
    // client is rmm.enrollment_push.enabled (RMM-24); the old
    // rmm.mobile_operator.enabled existed nowhere in the registry.
    // bd-and-rest F5 fix: local default OFF until the owner enables.
    @Volatile var enabled: Boolean = false // rmm.enrollment_push.enabled (RMM-24), local default OFF
    fun isEnabled(): Boolean =
        io.agenticcontrol.app.rmmspine.PolicyGate.enabledFor("rmm.enrollment_push.enabled", enabled)
}
val MOBILE_ONLY_RIGHTS: Set<String> = emptySet()

enum class Capability(val right: String) {
    VIEW_DEVICES("use"), APPROVE_SESSION("admin"), ANSWER_ALERT("use"),
    VIEW_AUDIT("admin"), MANAGE_ROSTER("admin"), OPERATE_SESSION("use")
}

fun interface RosterRights { fun rightsFor(scopeId: String, userId: String, deviceGroupId: String): Set<String> }
fun interface HubKeyVerifier { fun verifyHubSignature(payload: ByteArray, signature: String): Boolean }
interface ClientKeySigner { fun sign(payload: ByteArray): String; fun verify(payload: ByteArray, signature: String): Boolean }
fun interface AlertLookup { fun fetchById(alertId: String): String? }

data class Approval(
    val contentId: String, val contentHash: String, val decision: String, val signature: String,
    /** bd-and-rest F12 fix: the device group the approval was made
     *  for — bound into the signed payload (with the scope), so an
     *  approval minted for one group never verifies for another. */
    val deviceGroupId: String = ""
)
data class Notification(val kind: String, val alertId: String?, val payload: String)

class MobileOperatorClient(
    private val scopeId: String, private val userId: String,
    private val rights: RosterRights,
    private val hubKeys: HubKeyVerifier,
    private val clientKeys: ClientKeySigner,
    private val alerts: AlertLookup,
    val audit: ChainedAudit = ChainedAudit()
) {
    val presenceVisible: Boolean get() = true // structural, computed — cannot be turned off

    fun capabilities(deviceGroupId: String): Set<Capability> {
        if (!MobileOperatorPolicy.isEnabled()) return emptySet()
        val held = rights.rightsFor(scopeId, userId, deviceGroupId)
        return Capability.values().filter { it.right in held }.toSet()
    }
    fun can(cap: Capability, deviceGroupId: String): Boolean = cap in capabilities(deviceGroupId)

    /** Canonical approval payload (bd-and-rest F12 fix):
     *  length-prefixed fields — scope, device group, content id,
     *  content hash, decision, user — so no field value can forge
     *  a boundary (the old raw '|' join could), and the approval
     *  binds the scope and device group it was made in. */
    fun approvalPayload(contentId: String, contentHash: String, decision: String, deviceGroupId: String): ByteArray =
        listOf(scopeId, deviceGroupId, contentId, contentHash, decision, userId)
            .joinToString("") { "${it.length}:$it" }.toByteArray(Charsets.UTF_8)

    /** Content-bound approval: the signature covers the canonical
     *  payload (scope + group + id + hash + decision + user). */
    fun approve(contentId: String, contentHash: String, deviceGroupId: String): Approval? {
        if (!can(Capability.APPROVE_SESSION, deviceGroupId)) { audit.append("mobileop_approval_refused", "by=$userId content=$contentId reason=no capability"); return null }
        val payload = approvalPayload(contentId, contentHash, "approve", deviceGroupId)
        val a = Approval(contentId, contentHash, "approve", clientKeys.sign(payload), deviceGroupId)
        audit.append("mobileop_approval", "by=$userId content=$contentId"); return a
    }
    fun verifyApproval(a: Approval): Boolean {
        val payload = approvalPayload(a.contentId, a.contentHash, a.decision, a.deviceGroupId)
        return clientKeys.verify(payload, a.signature)
    }

    private val queue = mutableListOf<Notification>()
    companion object { const val MAX_QUEUED_NOTIFICATIONS = 100 }
    /** Only two accepted shapes; everything else refuses by name. */
    @Synchronized
    fun enqueue(kind: String, alertId: String? = null, payload: ByteArray? = null, signature: String? = null): Result<Notification> {
        fun refuse(r: String): Result<Notification> { audit.append("mobileop_notification_refused", "kind=$kind reason=$r"); return Result.failure(IllegalStateException(r)) }
        // bd-and-rest F12 fix: the queue was unbounded — a flooding
        // hub (or a looping caller) grew it without limit.
        if (queue.size >= MAX_QUEUED_NOTIFICATIONS) return refuse("notification queue is full ($MAX_QUEUED_NOTIFICATIONS) — drain it before enqueueing more")
        return when (kind) {
            "platform_push" -> refuse("platform_push refused in the self-hosted shape: APNs/FCM transit is outside ACP's no-vendor-server claim")
            "hub_alert_lookup" -> {
                val id = alertId ?: return refuse("hub_alert_lookup requires an alert id")
                val body = alerts.fetchById(id) ?: return refuse("unknown alert id")
                val n = Notification(kind, id, body); queue.add(n); Result.success(n)
            }
            "hub_signed" -> {
                if (payload == null || signature == null) return refuse("hub_signed requires payload + signature")
                if (!hubKeys.verifyHubSignature(payload, signature)) return refuse("hub signature verification failed")
                val n = Notification(kind, alertId, String(payload, Charsets.UTF_8)); queue.add(n); Result.success(n)
            }
            else -> refuse("unknown notification kind: $kind")
        }
    }
    @Synchronized fun notifications(): List<Notification> = queue.toList()
}
