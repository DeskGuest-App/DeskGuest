package io.deskguest.app.vendorpass

import io.deskguest.app.cameraview.ChainedAudit

/**
 * RMM-23 (Android completion) — phone-as-TARGET half of vendor
 * privileged-access passes, on the existing roster/session/expiry
 * substrate. A pass is a time-bounded, scope-bound, right-bounded
 * grant to a named vendor identity; it mints nothing the roster
 * does not already govern — session start re-checks the pass AND
 * the live roster right, and expiry/revocation end it immediately.
 * Browser hardening: recorded NOT APPLICABLE off managed devices
 * (RMM-31 tier table) — an app cannot harden Chrome on a personal
 * phone; it is named here, never built, never implied.
 */
object VendorPassPolicy {
    // bd-and-rest F5 fix: local default OFF — the owner enables
    // vendor passes; PolicyGate still governs when a bundle binds.
    @Volatile var enabled: Boolean = false // rmm.vendor_passes.enabled (target side), local default OFF
    fun isEnabled(): Boolean =
        io.deskguest.app.rmmspine.PolicyGate.enabledFor("rmm.vendor_passes.enabled", enabled)
    const val BROWSER_HARDENING_TIER = "not_applicable_personal: browser hardening policy applies only on managed (Device Owner / profile-owner) devices per the RMM-31 tier table; on a personal phone it is recorded, not built."
    const val MAX_TTL_MINUTES = 480L
}

fun interface PassRights { fun hasRight(scopeId: String, userId: String, deviceGroupId: String, right: String): Boolean }
fun interface LiveParty { fun isLive(scopeId: String, userId: String): Boolean }

data class VendorPass(
    val id: String, val scopeId: String, val vendorUserId: String, val deviceGroupId: String,
    val rights: Set<String>, val issuedMs: Long, val expiresMs: Long, var revoked: Boolean = false
)

class VendorPassService(
    private val rights: PassRights,
    private val parties: LiveParty,
    val audit: ChainedAudit = ChainedAudit(),
    private val clockMs: () -> Long = { System.currentTimeMillis() }
) {
    private val passes = mutableMapOf<String, VendorPass>()
    private var nextId = 1
    // bd-and-rest F9 reconciliation: "view" IS a roster right
    // (RosterStore.RIGHT_VIEW, in RosterStore.RIGHTS), so a view
    // pass can authorize — authorize() re-checks the LIVE roster
    // right, and a pass narrows the vendor's existing grant in
    // TIME only; it grants nothing the roster does not.
    companion object { val ALLOWED_RIGHTS = setOf("use", "view") } // a pass never carries admin/enroll

    @Synchronized
    fun issue(scopeId: String, issuerId: String, vendorUserId: String, deviceGroupId: String, passRights: Set<String>, ttlMinutes: Long): Result<VendorPass> {
        fun refuse(r: String): Result<VendorPass> { audit.append("vendor_pass_refused", "vendor=$vendorUserId reason=$r"); return Result.failure(IllegalStateException(r)) }
        if (!VendorPassPolicy.isEnabled()) return refuse("policy rmm.vendor_passes.enabled is OFF")
        if (!parties.isLive(scopeId, issuerId)) return refuse("issuer is not live in the scope")
        if (!rights.hasRight(scopeId, issuerId, deviceGroupId, "admin")) return refuse("issuing a vendor pass is an admin act")
        if (!parties.isLive(scopeId, vendorUserId)) return refuse("vendor is not a live member of the scope")
        if (passRights.isEmpty() || !ALLOWED_RIGHTS.containsAll(passRights)) return refuse("pass rights must be a non-empty subset of $ALLOWED_RIGHTS")
        if (ttlMinutes <= 0) return refuse("TTL must be positive")
        val ttl = minOf(ttlMinutes, VendorPassPolicy.MAX_TTL_MINUTES)
        val p = VendorPass("pass-${nextId++}", scopeId, vendorUserId, deviceGroupId, passRights, clockMs(), clockMs() + ttl * 60_000)
        passes[p.id] = p; audit.append("vendor_pass_issued", "pass=${p.id} vendor=$vendorUserId rights=${passRights.joinToString(",")} ttlMin=$ttl")
        return Result.success(p)
    }
    @Synchronized
    fun authorize(passId: String, right: String): Boolean {
        val p = passes[passId] ?: return false
        if (p.revoked || p.expiresMs <= clockMs()) { audit.append("vendor_pass_denied", "pass=$passId reason=expired-or-revoked"); return false }
        if (right !in p.rights) return false
        // Live re-check: suspension / grant removal kills the pass's effect immediately.
        if (!parties.isLive(p.scopeId, p.vendorUserId)) return false
        if (!rights.hasRight(p.scopeId, p.vendorUserId, p.deviceGroupId, right)) return false
        audit.append("vendor_pass_used", "pass=$passId right=$right"); return true
    }
    @Synchronized
    fun revoke(passId: String, actorId: String): Boolean {
        val p = passes[passId] ?: return false
        if (!rights.hasRight(p.scopeId, actorId, p.deviceGroupId, "admin")) return false
        p.revoked = true; audit.append("vendor_pass_revoked", "pass=$passId actor=$actorId"); return true
    }
    @Synchronized fun pass(id: String): VendorPass? = passes[id]
}
