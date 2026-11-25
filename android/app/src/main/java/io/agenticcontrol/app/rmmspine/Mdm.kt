package io.agenticcontrol.app.rmmspine

import io.agenticcontrol.app.enterprise.ChainedAuditLog
import java.io.File

/**
 * RMM-31 — MDM subset, Android mirror (model + service). Mirrors
 * Windows Acp.Shared/MdmSubset + MdmSubsetService: restriction
 * catalogue tiered per ownership (enforce/detect/impossible,
 * wording preserved verbatim into compliance output — detected ≠
 * enforced, impossible never satisfied), actions riding RMM-03
 * signed commands (class background_action, payload-bound),
 * device-side notice recorded BEFORE execution, locate-once with
 * rate-limit + daily cap + audit. CONTINUOUS TRACKING HAS NO API:
 * no kind, no constant, no method exists for it — by construction.
 */
object MdmKeys {
    const val FEATURE_ENABLED = "rmm.mdm.enabled"
    const val LOCATE_MIN_INTERVAL_MINUTES = "rmm.mdm.locate_min_interval_minutes"
    const val LOCATE_MAX_PER_DAY = "rmm.mdm.locate_max_per_day"
}
object MdmOwnership {
    const val DEVICE_OWNER = "device_owner"; const val PROFILE_OWNER = "profile_owner"
    const val PERSONAL = "personal_no_owner"; const val UNKNOWN = "unknown"
    val ALL = setOf(DEVICE_OWNER, PROFILE_OWNER, PERSONAL, UNKNOWN)
}
object MdmTiers {
    const val ENFORCE = "enforce"; const val DETECT = "detect"; const val IMPOSSIBLE = "impossible"
    fun label(tier: String): String = when (tier) {
        ENFORCE -> "ENFORCE (this tier can apply it)"
        DETECT -> "DETECT ONLY (this tier can observe and report; it cannot apply it)"
        else -> "IMPOSSIBLE (this tier cannot do this; it is never claimed)"
    }
}
object ScreenLockStrengths {
    const val NONE = "none"; const val SWIPE = "swipe"; const val PIN_PATTERN = "pin_pattern"
    const val PASSWORD = "password"; const val BIOMETRIC_STRONG = "biometric_strong"
    val ALL = setOf(NONE, SWIPE, PIN_PATTERN, PASSWORD, BIOMETRIC_STRONG)
    fun rank(s: String?): Int = when ((s ?: "").trim().lowercase()) {
        NONE -> 0; SWIPE -> 1; PIN_PATTERN -> 2; PASSWORD -> 3; BIOMETRIC_STRONG -> 4; else -> -1
    }
}

object MdmLimits {
    const val STATE_FRESHNESS_MS = 24L * 3600 * 1000
    const val MAX_COMMAND_TTL_MS = 15L * 60 * 1000
    const val DEFAULT_LOCATE_MIN_INTERVAL_MS = 15L * 60 * 1000
    const val DEFAULT_LOCATE_MAX_PER_DAY = 6
    const val MAX_MANAGED_APPS = 512
}

/** Encryption tri-state: encryptionOn is true ONLY when the
 *  platform reports encryption ON; null = not known (RMM-18). */
data class MdmDeviceState(
    val deviceId: String, val scopeId: String, val platform: String, val ownership: String,
    val osVersion: String, val encryptionOn: Boolean?, val screenLock: String,
    val acpAppVersion: String, val managedApps: List<String> = emptyList(),
    val appliedRestrictions: List<String> = emptyList(), val reportedMs: Long
) {
    val isDeviceOwner: Boolean get() = ownership == MdmOwnership.DEVICE_OWNER
    fun isStale(nowMs: Long): Boolean = nowMs - reportedMs > MdmLimits.STATE_FRESHNESS_MS
    fun validate(nowMs: Long): String? {
        if (deviceId.isBlank()) return "MDM device state needs a device id — refused"
        if (scopeId.isBlank()) return "MDM device state needs a scope id — refused"
        if (platform.trim().lowercase() !in setOf("android", "ios")) return "unknown MDM platform '$platform' — refused"
        if (ownership.trim().lowercase() !in MdmOwnership.ALL) return "unknown MDM ownership '$ownership' — refused"
        if (screenLock.trim().lowercase() !in ScreenLockStrengths.ALL) return "unknown screen-lock strength '$screenLock' — refused"
        if (reportedMs > nowMs + 5 * 60_000L) return "MDM device state is future-dated — refused"
        if (managedApps.size > MdmLimits.MAX_MANAGED_APPS) return "managed-app list exceeds the bound — refused"
        return null
    }
}

data class MdmRestrictionDef(val id: String, val name: String, val description: String,
    val tierDeviceOwner: String, val tierProfileOwner: String, val tierPersonal: String) {
    fun tierFor(ownership: String?): String = when ((ownership ?: "").trim().lowercase()) {
        MdmOwnership.DEVICE_OWNER -> tierDeviceOwner
        MdmOwnership.PROFILE_OWNER -> tierProfileOwner
        MdmOwnership.PERSONAL -> tierPersonal
        else -> MdmTiers.IMPOSSIBLE // unknown ownership claims nothing
    }
}

object MdmRestrictions {
    val ALL: List<MdmRestrictionDef> = listOf(
        MdmRestrictionDef("require_encryption", "Require device encryption", "Device storage encryption must be on",
            MdmTiers.ENFORCE, MdmTiers.ENFORCE, MdmTiers.DETECT),
        MdmRestrictionDef("require_screen_lock", "Require screen lock (PIN/pattern or stronger)", "A screen lock of at least PIN/pattern strength must be set",
            MdmTiers.ENFORCE, MdmTiers.ENFORCE, MdmTiers.DETECT),
        MdmRestrictionDef("prevent_acp_removal", "Prevent removal of the ACP app", "The ACP endpoint app cannot be uninstalled by the device user",
            MdmTiers.ENFORCE, MdmTiers.ENFORCE, MdmTiers.IMPOSSIBLE),
        MdmRestrictionDef("managed_app_install", "Install managed apps silently", "Push app installs without a per-install user prompt",
            MdmTiers.ENFORCE, MdmTiers.ENFORCE, MdmTiers.IMPOSSIBLE),
        MdmRestrictionDef("managed_app_remove", "Remove managed apps silently", "Remove managed apps without a per-removal user prompt",
            MdmTiers.ENFORCE, MdmTiers.ENFORCE, MdmTiers.IMPOSSIBLE),
        MdmRestrictionDef("kiosk_mode", "Kiosk mode (single-app / locked task)", "Pin the device to a managed app set (site tablets)",
            MdmTiers.ENFORCE, MdmTiers.IMPOSSIBLE, MdmTiers.IMPOSSIBLE),
        MdmRestrictionDef("wifi_vpn_profile", "Push Wi-Fi / VPN profiles", "Deliver network profiles as managed configuration",
            MdmTiers.ENFORCE, MdmTiers.ENFORCE, MdmTiers.IMPOSSIBLE),
        MdmRestrictionDef("passcode_reset", "Reset device passcode", "Admin-initiated passcode reset",
            MdmTiers.ENFORCE, MdmTiers.IMPOSSIBLE, MdmTiers.IMPOSSIBLE)
    )
    fun forId(id: String?): MdmRestrictionDef? =
        ALL.firstOrNull { it.id == (id ?: "").trim().lowercase() }
}

object MdmComplianceOutcomes {
    const val ENFORCED_COMPLIANT = "enforced_compliant"; const val ENFORCEMENT_MISSING = "enforcement_missing"
    const val DETECTED_COMPLIANT = "detected_compliant"; const val DETECTED_NONCOMPLIANT = "detected_noncompliant"
    const val IMPOSSIBLE_NOT_APPLICABLE = "impossible_not_applicable"; const val UNKNOWN_STALE_STATE = "unknown_stale_state"
}
data class MdmComplianceVerdict(val restrictionId: String, val tier: String, val outcome: String, val detail: String) {
    val tierLabel: String get() = MdmTiers.label(tier)
    val isSatisfied: Boolean get() = outcome == MdmComplianceOutcomes.ENFORCED_COMPLIANT || outcome == MdmComplianceOutcomes.DETECTED_COMPLIANT
}

object MdmComplianceEvaluator {
    fun substanceHolds(def: MdmRestrictionDef, state: MdmDeviceState): Boolean? = when (def.id) {
        "require_encryption" -> state.encryptionOn
        "require_screen_lock" -> ScreenLockStrengths.rank(state.screenLock) >= ScreenLockStrengths.rank(ScreenLockStrengths.PIN_PATTERN)
        else -> state.appliedRestrictions.any { it.equals(def.id, true) }
    }

    fun evaluate(def: MdmRestrictionDef, state: MdmDeviceState, nowMs: Long): MdmComplianceVerdict {
        val tier = def.tierFor(state.ownership)
        if (state.isStale(nowMs))
            return MdmComplianceVerdict(def.id, tier, MdmComplianceOutcomes.UNKNOWN_STALE_STATE,
                "device state for '${state.deviceId}' is stale — compliance UNKNOWN, never inferred from old facts [${MdmTiers.label(tier)}]")
        if (tier == MdmTiers.IMPOSSIBLE)
            return MdmComplianceVerdict(def.id, tier, MdmComplianceOutcomes.IMPOSSIBLE_NOT_APPLICABLE,
                "restriction '${def.id}' is IMPOSSIBLE on device '${state.deviceId}' (ownership ${state.ownership}) — it is not applied, not detected, and not counted as satisfied")
        val holds = substanceHolds(def, state)
        if (tier == MdmTiers.ENFORCE) {
            return if (def.id == "require_encryption" || def.id == "require_screen_lock") {
                if (holds == true) MdmComplianceVerdict(def.id, tier, MdmComplianceOutcomes.ENFORCED_COMPLIANT,
                    "restriction '${def.id}' ENFORCED and the reported state satisfies it on '${state.deviceId}'")
                else MdmComplianceVerdict(def.id, tier, MdmComplianceOutcomes.ENFORCEMENT_MISSING,
                    "restriction '${def.id}' is enforce-tier on '${state.deviceId}' but the reported state does NOT satisfy it — enforcement missing/failed, named")
            } else {
                if (state.appliedRestrictions.any { it.equals(def.id, true) })
                    MdmComplianceVerdict(def.id, tier, MdmComplianceOutcomes.ENFORCED_COMPLIANT,
                        "restriction '${def.id}' ENFORCED: the platform reports it applied on '${state.deviceId}'")
                else MdmComplianceVerdict(def.id, tier, MdmComplianceOutcomes.ENFORCEMENT_MISSING,
                    "restriction '${def.id}' is enforce-tier on '${state.deviceId}' but the platform does NOT report it applied — enforcement missing, named")
            }
        }
        return when (holds) {
            true -> MdmComplianceVerdict(def.id, tier, MdmComplianceOutcomes.DETECTED_COMPLIANT,
                "restriction '${def.id}' DETECTED compliant on '${state.deviceId}' — detection only: ACP did not apply this and does not claim enforcement")
            false -> MdmComplianceVerdict(def.id, tier, MdmComplianceOutcomes.DETECTED_NONCOMPLIANT,
                "restriction '${def.id}' DETECTED NON-COMPLIANT on '${state.deviceId}' — detection only: ACP cannot apply this on a ${state.ownership} device")
            null -> MdmComplianceVerdict(def.id, tier, MdmComplianceOutcomes.UNKNOWN_STALE_STATE,
                "restriction '${def.id}' on '${state.deviceId}': the reported facts cannot tell (unknown) — compliance UNKNOWN, never guessed")
        }
    }
}

object MdmActionKinds {
    const val LOCK = "lock_device"; const val LOCATE_ONCE = "locate_once"
    const val WIPE_ACP_DATA = "wipe_acp_data"; const val WIPE_FULL_DEVICE = "wipe_full_device"
    const val PASSCODE_RESET = "passcode_reset"
    val ALL = setOf(LOCK, LOCATE_ONCE, WIPE_ACP_DATA, WIPE_FULL_DEVICE, PASSCODE_RESET)
    // Deliberately ABSENT: any continuous-tracking / geofence kind.
    // Their absence is the exclusion, structural.
}
object AcpWipeTargets {
    const val APP_DATA = "acp_app_data"; const val CREDENTIALS = "acp_credentials"; const val CACHE = "acp_cache"
    val ALL = setOf(APP_DATA, CREDENTIALS, CACHE)
}

data class MdmActionRequest(
    val commandId: String, val deviceId: String, val kind: String,
    val wipeTargets: List<String> = emptyList(), val noticeText: String,
    val issuedMs: Long, val expiresMs: Long
) {
    fun canonicalPayload(): String = listOf(
        "acp-mdm-action-v1", commandId, deviceId, kind,
        wipeTargets.sorted().joinToString(","), noticeText,
        IsoTime.format(issuedMs), IsoTime.format(expiresMs)
    ).joinToString("|")

    fun validate(nowMs: Long): String? {
        if (commandId.isBlank()) return "an MDM action needs a command id — refused"
        if (deviceId.isBlank()) return "an MDM action needs a device id — refused"
        if (kind.trim().lowercase() !in MdmActionKinds.ALL)
            return "unknown MDM action kind '$kind' — refused (continuous location tracking has no kind here by design)"
        if (noticeText.isBlank())
            return "an MDM action needs device-side notice text — refused: a lock/wipe/locate with no on-device trace violates the no-hidden-operation law"
        if (expiresMs <= issuedMs) return "an MDM action expiry must follow its issuance — refused"
        if (expiresMs - issuedMs > MdmLimits.MAX_COMMAND_TTL_MS)
            return "an MDM action TTL exceeds the freshness cap (15 minutes) — refused: a stale lock/wipe must never execute late"
        if (expiresMs <= nowMs) return "this MDM action has EXPIRED — refused: stale commands do not execute"
        if (kind == MdmActionKinds.WIPE_ACP_DATA) {
            if (wipeTargets.isEmpty()) return "an ACP-data wipe needs at least one ACP wipe target — refused"
            for (t in wipeTargets) if (t.trim().lowercase() !in AcpWipeTargets.ALL)
                return "wipe target '$t' is NOT ACP data — refused: an ACP-data wipe reaches ACP's own data only (scope creep is refused, never widened)"
        }
        if (kind != MdmActionKinds.WIPE_ACP_DATA && wipeTargets.isNotEmpty())
            return "action '$kind' carries wipe targets — refused (targets belong to the ACP-data wipe only)"
        return null
    }
}

data class MdmDeviceNotice(val commandId: String, val deviceId: String, val kind: String,
    val noticeText: String, val recordedMs: Long)
data class MdmActionOutcome(val commandId: String, val deviceId: String, val kind: String,
    val executed: Boolean, val detail: String, val notice: MdmDeviceNotice?, val atMs: Long)

/** The on-device executor seam (IMdmActionExecutor mirror). The
 *  Android platform binding lives in MdmPlatform.kt
 *  (DevicePolicyManager); this file stays pure for the JVM suite. */
interface MdmActionExecutor {
    fun execute(request: MdmActionRequest, state: MdmDeviceState, nowMs: Long): Pair<Boolean, String>
}

/** Honest unavailable executor: reports NOT executed, by name. */
class UnavailableMdmActionExecutor : MdmActionExecutor {
    override fun execute(request: MdmActionRequest, state: MdmDeviceState, nowMs: Long): Pair<Boolean, String> =
        false to "no on-device MDM executor is wired on this host for device '${state.deviceId}' — action '${request.kind}' was validated and noticed but NOT executed"
}
class RecordingMdmActionExecutor : MdmActionExecutor {
    val executed = mutableListOf<MdmActionRequest>()
    override fun execute(request: MdmActionRequest, state: MdmDeviceState, nowMs: Long): Pair<Boolean, String> {
        executed += request
        return true to "action '${request.kind}' executed on device '${state.deviceId}' (recording executor)"
    }
}

/**
 * One-shot locate bookkeeping — the anti-tracking defence. Minimum
 * interval + daily cap per device, PERSISTED to a file so a process
 * restart does not reset the defences (closing the Windows lane's
 * in-memory limiter residual on Android). Every attempt is audited
 * by the service.
 */
class LocateRateLimiter(private val storeFile: File? = null) {
    private val byDevice = mutableMapOf<String, MutableList<Long>>()

    /** bd-and-rmm F9 fix: a corrupt/unreadable store file marks the
     *  limiter BROKEN and every acquisition refuses fail-closed.
     *  The old catch reset the counts silently — deleting or
     *  corrupting one file wiped the anti-tracking defence. */
    var broken: Boolean = false
        private set

    init { load() }

    private fun load() {
        if (storeFile == null || !storeFile.exists()) return
        try {
            for (line in storeFile.readLines()) {
                if (line.isBlank()) continue
                val parts = line.split('|')
                if (parts.size != 2) { broken = true; return }
                val ts = parts[1].toLongOrNull() ?: run { broken = true; return }
                byDevice.getOrPut(parts[0]) { mutableListOf() }.add(ts)
            }
        } catch (_: Exception) { broken = true }
    }

    private fun persist() {
        if (storeFile == null) return
        try {
            storeFile.parentFile?.mkdirs()
            val tmp = File(storeFile.parentFile, storeFile.name + ".tmp")
            tmp.writeText(byDevice.entries.flatMap { (d, ts) -> ts.map { "$d|$it" } }.joinToString("\n"))
            if (!tmp.renameTo(storeFile)) tmp.delete()
        } catch (_: Exception) { }
    }

    @Synchronized
    fun tryAcquire(deviceId: String, nowMs: Long, minIntervalMs: Long, maxPerDay: Int): Pair<Boolean, String> {
        if (broken) return false to "one-shot locate for '$deviceId' refused: the locate rate-limiter store is corrupt/unreadable — locates fail CLOSED rather than reset the anti-tracking counts"
        val list = byDevice.getOrPut(deviceId) { mutableListOf() }
        // bd-and-rmm F9: prune history older than 24h (the file
        // previously grew forever) — but ALWAYS retain the most
        // recent timestamp, so the minimum-interval defence never
        // depends on the pruning window.
        val cutoff = nowMs - 86_400_000L
        if (list.size > 1) {
            val lastTs = list.max()
            list.removeAll { it < cutoff && it != lastTs }
        }
        val last = list.lastOrNull()
        if (last != null && nowMs - last < minIntervalMs)
            return false to "one-shot locate for '$deviceId' refused: the minimum interval (${minIntervalMs / 60000} min) has not elapsed since the last locate — repeated locates becoming de-facto tracking is refused by construction"
        val dayStart = nowMs - (nowMs % 86_400_000L)
        if (list.count { it >= dayStart } >= maxPerDay)
            return false to "one-shot locate for '$deviceId' refused: the daily cap ($maxPerDay) is reached — a locate facility that can be polled all day is tracking by another name"
        list.add(nowMs); persist()
        return true to "locate slot acquired"
    }

    @Synchronized
    fun countFor(deviceId: String): Int = byDevice[deviceId]?.size ?: 0
}

/** State reporter seam: the platform binding (MdmPlatform.kt)
 *  reads DevicePolicyManager; tests inject fixed states. Reports
 *  carry freshness (reportedMs) — stale state reads UNKNOWN. */
interface MdmStateReporter {
    fun report(deviceId: String, scopeId: String, nowMs: Long): MdmDeviceState
}

/**
 * The MDM service wall (mirror of MdmSubsetService.ExecuteAction):
 * policy gate → validity → RMM-03 signed gate + payload binding →
 * state present → ownership powers (full wipe device-owner only,
 * REFUSED NEVER SUBSTITUTED; passcode reset enforce-tier only) →
 * locate rate limit → notice recorded BEFORE execution →
 * executor. Every refusal is audited.
 */
class MdmService(
    private val engine: ManagementPolicyEngine,
    private val gate: SignedCommandGate?,
    private val executor: MdmActionExecutor,
    private val audit: ChainedAuditLog,
    private val factsFor: (String) -> DeviceFacts?,
    private val locateLimiter: LocateRateLimiter = LocateRateLimiter(),
    /** bd-and-rmm F9: durable notice store. The device-visible
     *  notice is the "your admin did X" trace — keeping it only in
     *  memory meant a restart erased the only user-visible record
     *  of an executed remote action. Persisted TSV when supplied. */
    private val noticeStoreFile: File? = null
) {
    private val states = mutableMapOf<String, MdmDeviceState>()
    private val noticeList = mutableListOf<MdmDeviceNotice>()
    fun notices(): List<MdmDeviceNotice> = synchronized(this) { noticeList.toList() }

    init { loadNotices() }

    private fun loadNotices() {
        val file = noticeStoreFile ?: return
        try {
            if (!file.exists()) return
            for (line in file.readLines()) {
                val p = line.split('|')
                if (p.size == 5) noticeList += MdmDeviceNotice(p[0], p[1], p[2], p[3], p[4].toLongOrNull() ?: 0L)
            }
        } catch (_: Exception) { /* a corrupt notice store loads what parses; notices are a trace, not a gate */ }
    }

    private fun persistNotices() {
        val file = noticeStoreFile ?: return
        try {
            file.parentFile?.mkdirs()
            val tmp = File(file.parentFile, file.name + ".tmp")
            tmp.writeText(noticeList.joinToString("\n") { n ->
                listOf(n.commandId, n.deviceId, n.kind, n.noticeText.replace('|', '/'), n.recordedMs.toString()).joinToString("|")
            })
            if (!tmp.renameTo(file)) tmp.delete()
        } catch (_: Exception) { }
    }
    fun stateFor(deviceId: String): MdmDeviceState? = synchronized(this) { states[deviceId.lowercase()] }

    private fun policyGate(deviceId: String, op: String): String? {
        val facts = factsFor(deviceId) ?: return "no device facts for '$deviceId' — $op refuses (policy cannot be evaluated; fail closed)"
        if (!engine.isEnabled(facts, MdmKeys.FEATURE_ENABLED))
            return "the MDM subset is disabled by policy for device '$deviceId' (${MdmKeys.FEATURE_ENABLED}) — $op refuses"
        return null
    }

    /** Intake one state report. Capability-inflation wall: a report
     *  claiming an applied restriction whose tier for its ownership
     *  is detect/impossible refuses WHOLE — never stored partially. */
    @Synchronized
    fun reportState(state: MdmDeviceState?, actor: String, nowMs: Long): Pair<MdmDeviceState?, String> {
        if (state == null) return null to "no MDM device state presented — refused"
        policyGate(state.deviceId, "state reporting")?.let {
            audit.append("mdm_state_refused", actor, "device=${state.deviceId} reason=$it", nowMs); return null to it }
        state.validate(nowMs)?.let {
            audit.append("mdm_state_refused", actor, "device=${state.deviceId} reason=$it", nowMs); return null to it }
        for (rid in state.appliedRestrictions) {
            val def = MdmRestrictions.forId(rid)
                ?: run { val r = "state report claims unknown restriction '$rid' — refused whole"
                    audit.append("mdm_state_refused", actor, "device=${state.deviceId} reason=$r", nowMs); return null to r }
            val tier = def.tierFor(state.ownership)
            if (tier != MdmTiers.ENFORCE) {
                val r = "CAPABILITY INFLATION: device '${state.deviceId}' (ownership ${state.ownership}) claims restriction '$rid' applied, but its tier is $tier — report refused whole, nothing stored"
                audit.append("mdm_state_refused", actor, r, nowMs); return null to r
            }
        }
        states[state.deviceId.lowercase()] = state
        audit.append("mdm_state_reported", actor, "device=${state.deviceId} ownership=${state.ownership}", nowMs)
        return state to "state recorded for '${state.deviceId}'"
    }

    fun evaluateCompliance(deviceId: String, actor: String, nowMs: Long): Pair<List<MdmComplianceVerdict>?, String> {
        policyGate(deviceId, "compliance evaluation")?.let { return null to it }
        val state = stateFor(deviceId) ?: return null to "no MDM state for device '$deviceId' — compliance cannot be evaluated"
        return MdmRestrictions.ALL.map { MdmComplianceEvaluator.evaluate(it, state, nowMs) } to "compliance evaluated for '$deviceId'"
    }

    @Synchronized
    fun executeAction(request: MdmActionRequest?, envelope: SignedCommandEnvelope?, actor: String, nowMs: Long): Pair<MdmActionOutcome?, String> {
        fun refuse(reason: String, notice: MdmDeviceNotice? = null): Pair<MdmActionOutcome?, String> {
            audit.append("mdm_action_refused", actor, "command=${request?.commandId ?: "(none)"} reason=$reason", nowMs)
            return (if (request != null) MdmActionOutcome(request.commandId, request.deviceId, request.kind, false, reason, notice, nowMs) else null) to reason
        }
        if (request == null) return refuse("no MDM action presented — refused")
        policyGate(request.deviceId, "action execution")?.let { return refuse(it) }
        request.validate(nowMs)?.let { return refuse(it) }
        if (gate == null) return refuse("no signed-command gate configured — MDM actions refuse (RMM-03 coverage is not claimed)")
        val expectedPayload = request.canonicalPayload().toByteArray(Charsets.UTF_8)
        val v = gate.authorize(envelope, nowMs, SignedCommandClasses.BACKGROUND_ACTION, expectedPayload)
        if (!v.allowed) return refuse("signed-command verification failed: ${v.reason}")
        val state = stateFor(request.deviceId) ?: return refuse("no MDM state for device '${request.deviceId}' — action refuses (ownership powers cannot be checked)")
        if (state.isStale(nowMs)) return refuse("MDM state for device '${request.deviceId}' is stale — action refuses rather than act on old facts")
        // Ownership powers: refused, never substituted.
        when (request.kind) {
            MdmActionKinds.WIPE_FULL_DEVICE ->
                if (state.ownership != MdmOwnership.DEVICE_OWNER)
                    return refuse("full device wipe is DEVICE-OWNER only — device '${request.deviceId}' is ${state.ownership}: refused, never substituted with a lesser wipe")
            MdmActionKinds.PASSCODE_RESET -> {
                val tier = MdmRestrictions.forId("passcode_reset")!!.tierFor(state.ownership)
                if (tier != MdmTiers.ENFORCE)
                    return refuse("passcode reset is enforce-tier only — device '${request.deviceId}' tier is $tier: refused, never substituted")
            }
            MdmActionKinds.LOCATE_ONCE -> {
                val facts = factsFor(request.deviceId)!!
                // bd-and-rmm F9 fix: policy values are CLAMPED to
                // the anti-tracking envelope — a policy setting the
                // interval to 0 or the cap to 10000 previously
                // switched the defence off entirely. Policy may
                // only ever make locates RARER than the defaults.
                val policyMinIv = engine.computeEffective(facts).get(MdmKeys.LOCATE_MIN_INTERVAL_MINUTES)?.value?.toLongOrNull()?.times(60000)
                val minIv = maxOf(policyMinIv ?: MdmLimits.DEFAULT_LOCATE_MIN_INTERVAL_MS, MdmLimits.DEFAULT_LOCATE_MIN_INTERVAL_MS)
                val policyCap = engine.computeEffective(facts).get(MdmKeys.LOCATE_MAX_PER_DAY)?.value?.toIntOrNull()
                val cap = minOf(policyCap ?: MdmLimits.DEFAULT_LOCATE_MAX_PER_DAY, MdmLimits.DEFAULT_LOCATE_MAX_PER_DAY)
                val (ok, why) = locateLimiter.tryAcquire(request.deviceId, nowMs, minIv, cap)
                audit.append(if (ok) "mdm_locate_allowed" else "mdm_locate_refused", actor, "device=${request.deviceId} $why", nowMs)
                if (!ok) return refuse(why)
            }
        }
        // Notice BEFORE execution — the device always carries a
        // trace of what was ordered, even if execution then fails.
        val notice = MdmDeviceNotice(request.commandId, request.deviceId, request.kind, request.noticeText, nowMs)
        noticeList += notice
        persistNotices()
        audit.append("mdm_notice_recorded", actor, "command=${request.commandId} kind=${request.kind} device=${request.deviceId}", nowMs)
        val (executed, detail) = try { executor.execute(request, state, nowMs) }
            catch (ex: Exception) { false to "executor threw (${ex.javaClass.simpleName}: ${ex.message}) — action NOT executed" }
        audit.append(if (executed) "mdm_action_executed" else "mdm_action_not_executed", actor,
            "command=${request.commandId} kind=${request.kind} detail=$detail", nowMs)
        return MdmActionOutcome(request.commandId, request.deviceId, request.kind, executed, detail, notice, nowMs) to detail
    }
}
