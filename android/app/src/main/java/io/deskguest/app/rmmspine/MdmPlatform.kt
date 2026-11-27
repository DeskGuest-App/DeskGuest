package io.deskguest.app.rmmspine

import android.app.KeyguardManager
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.os.Build
import java.io.File

/**
 * RMM-31 Android platform binding (NOT in the JVM suite — Android
 * APIs only; compiled by the manual build). Binds the pure
 * MdmActionExecutor / MdmStateReporter seams to
 * DevicePolicyManager. Every act checks the device's actual
 * ownership tier FIRST: what the tier cannot do returns NOT
 * executed with the reason — refused, never substituted.
 */
class DeskGuestDeviceAdminReceiver : android.app.admin.DeviceAdminReceiver()

class DevicePolicyMdmExecutor(
    private val context: Context,
    /** DeskGuest-data wipe acts (app-internal stores/cache) supplied by
     *  the app wiring — the executor never reaches outside DeskGuest. */
    private val wipeDeskGuestTargets: (List<String>) -> Pair<Boolean, String>,
    /** One-shot locate supplied by the app wiring (a single fix,
     *  never a stream); null = locate cannot be performed here. */
    private val locateOnce: (() -> Pair<Boolean, String>)?
) : MdmActionExecutor {

    private val dpm: DevicePolicyManager? =
        context.getSystemService(Context.DEVICE_POLICY_SERVICE) as? DevicePolicyManager
    private val admin = ComponentName(context, DeskGuestDeviceAdminReceiver::class.java)

    fun ownershipTier(): String {
        val m = dpm ?: return MdmOwnership.UNKNOWN
        return when {
            m.isDeviceOwnerApp(context.packageName) -> MdmOwnership.DEVICE_OWNER
            m.isProfileOwnerApp(context.packageName) -> MdmOwnership.PROFILE_OWNER
            else -> MdmOwnership.PERSONAL
        }
    }

    override fun execute(request: MdmActionRequest, state: MdmDeviceState, nowMs: Long): Pair<Boolean, String> {
        val m = dpm ?: return false to "DevicePolicyManager unavailable on this device — action '${request.kind}' NOT executed"
        return when (request.kind) {
            MdmActionKinds.LOCK -> {
                if (!m.isAdminActive(admin))
                    false to "DeskGuest is not an active device admin — lock NOT executed (the admin grant is the user's to give in Settings)"
                else { m.lockNow(); true to "device locked via DevicePolicyManager.lockNow" }
            }
            MdmActionKinds.WIPE_DESKGUEST_DATA -> wipeDeskGuestTargets(request.wipeTargets)
            MdmActionKinds.WIPE_FULL_DEVICE -> {
                if (!m.isDeviceOwnerApp(context.packageName))
                    false to "full wipe requires Device Owner — this device is ${ownershipTier()}: NOT executed, never substituted"
                else { m.wipeData(0); true to "full device wipe issued via DevicePolicyManager.wipeData (device owner)" }
            }
            MdmActionKinds.PASSCODE_RESET -> {
                val tier = MdmRestrictions.forId("passcode_reset")!!.tierFor(ownershipTier())
                if (tier != MdmTiers.ENFORCE)
                    false to "passcode reset is enforce-tier only — this device is ${ownershipTier()}: NOT executed, never substituted"
                else if (!m.isAdminActive(admin))
                    false to "DeskGuest is not an active device admin — passcode reset NOT executed"
                else {
                    // The hub command carries no new passcode (the
                    // canonical payload has no secret field by
                    // design); resetting to a hub-supplied secret
                    // over this channel is refused by construction.
                    false to "passcode reset NOT executed: no passcode material travels in an RMM-03 envelope by design — reset must be completed on-device by the user"
                }
            }
            MdmActionKinds.LOCATE_ONCE -> {
                val loc = locateOnce ?: return false to
                    "no one-shot locate binding is wired on this host — locate NOT performed (continuous tracking has no API by design)"
                loc()
            }
            else -> false to "unknown MDM action kind '${request.kind}' — NOT executed"
        }
    }
}

/** Reads the phone's real management facts. Anything unreadable is
 *  reported as unknown/absent — never guessed. */
class AndroidMdmStateReporter(
    private val context: Context,
    private val deskguestVersion: String
) : MdmStateReporter {
    override fun report(deviceId: String, scopeId: String, nowMs: Long): MdmDeviceState {
        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as? DevicePolicyManager
        val ownership = when {
            dpm == null -> MdmOwnership.UNKNOWN
            dpm.isDeviceOwnerApp(context.packageName) -> MdmOwnership.DEVICE_OWNER
            dpm.isProfileOwnerApp(context.packageName) -> MdmOwnership.PROFILE_OWNER
            else -> MdmOwnership.PERSONAL
        }
        val encryption: Boolean? = when (dpm?.getStorageEncryptionStatus()) {
            DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE,
            DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_DEFAULT_KEY,
            DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_PER_USER -> true
            DevicePolicyManager.ENCRYPTION_STATUS_INACTIVE,
            DevicePolicyManager.ENCRYPTION_STATUS_UNSUPPORTED -> false
            else -> null // activating / unknown — tri-state honesty
        }
        val km = context.getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager
        val lock = when {
            km == null -> ScreenLockStrengths.NONE
            !km.isDeviceSecure -> ScreenLockStrengths.NONE
            else -> ScreenLockStrengths.PIN_PATTERN // secure lock present; exact strength is not readable — the floor is reported, never inflated
        }
        val applied = mutableListOf<String>()
        if (dpm != null && dpm.isAdminActive(ComponentName(context, DeskGuestDeviceAdminReceiver::class.java))) {
            val admin = ComponentName(context, DeskGuestDeviceAdminReceiver::class.java)
            // bd-and-rmm F9 fixes:
            // (1) getUserRestrictions(admin) THROWS SecurityException
            //     when the admin is active but not the profile/device
            //     owner — the reporter crashed state reporting on
            //     exactly the devices MDM cares about. A throw now
            //     means "restrictions not readable" (none claimed),
            //     never a crash and never an invented claim.
            try {
                dpm.getUserRestrictions(admin)
            } catch (_: SecurityException) {
                // Not readable for this admin — no restriction is
                // claimed from the bundle (see isUninstallBlocked).
            } catch (_: Exception) {
            }
            // (2) prevent_deskguest_removal is about THIS app's uninstall
            //     being blocked for the calling user — the precise
            //     API is DevicePolicyManager.isUninstallBlocked. The
            //     old code read the device-wide DISALLOW_UNINSTALL_APPS
            //     restriction (set by any admin/profile for all apps)
            //     and reported it as DeskGuest-specific protection.
            val uninstallBlocked = try {
                dpm.isUninstallBlocked(admin, context.packageName)
            } catch (_: Exception) {
                false
            }
            if (uninstallBlocked) applied += "prevent_deskguest_removal"
        }
        return MdmDeviceState(
            deviceId = deviceId, scopeId = scopeId, platform = "android", ownership = ownership,
            osVersion = "Android ${Build.VERSION.RELEASE ?: "unknown"} (API ${Build.VERSION.SDK_INT})",
            encryptionOn = encryption, screenLock = lock, deskguestAppVersion = deskguestVersion,
            managedApps = listOf(context.packageName), appliedRestrictions = applied, reportedMs = nowMs
        )
    }
}

/** RMM-08 Android platform acts, via app-supplied hooks: the app
 *  wiring registers what "restart components" means for DeskGuest; the
 *  cache act is real (cacheDir). Unregistered acts refuse by name. */
object RemediationPlatformHooks {
    @Volatile var reapplyPolicy: (() -> Pair<Boolean, String>)? = null
    @Volatile var restartComponents: (() -> Pair<Boolean, String>)? = null
    @Volatile var rerunJob: ((String) -> Pair<Boolean, String>)? = null
}

class AndroidRemediationExecutor(private val context: Context) : RemediationExecutor {
    override fun perform(action: String, deviceId: String, detail: String): Pair<Boolean, String> = when (action) {
        RemediationActions.CLEAR_DESKGUEST_CACHE -> {
            val cache = context.cacheDir
            val before = cache.walkTopDown().filter { it.isFile }.sumOf { it.length() }
            val ok = cache.listFiles()?.all { it.deleteRecursively() } ?: true
            if (ok) true to "DeskGuest cache cleared (${before} bytes in cacheDir)" else false to "DeskGuest cache clear incomplete — some entries could not be deleted"
        }
        RemediationActions.REAPPLY_POLICY ->
            RemediationPlatformHooks.reapplyPolicy?.invoke()
                ?: (false to "re-apply policy hook not registered by app wiring — NOT performed")
        RemediationActions.RESTART_DESKGUEST_COMPONENTS ->
            RemediationPlatformHooks.restartComponents?.invoke()
                ?: (false to "restart-components hook not registered by app wiring — NOT performed")
        RemediationActions.RERUN_FAILED_DESKGUEST_JOB ->
            RemediationPlatformHooks.rerunJob?.invoke(detail)
                ?: (false to "re-run-job hook not registered by app wiring — NOT performed")
        else -> false to "unknown remediation action '$action' — NOT performed"
    }

    companion object {
        /** DeskGuest-data wipe targets for the MDM executor: only DeskGuest's
         *  own stores — the closed DeskGuestWipeTargets set, enforced
         *  upstream at request validation as well. */
        fun wipeDeskGuest(context: Context, storesDir: File): (List<String>) -> Pair<Boolean, String> = { targets ->
            var allOk = true; val notes = mutableListOf<String>()
            for (t in targets) {
                when (t) {
                    DeskGuestWipeTargets.CACHE -> {
                        val ok = context.cacheDir.listFiles()?.all { it.deleteRecursively() } ?: true
                        if (!ok) allOk = false; notes += "cache ${if (ok) "cleared" else "clear incomplete"}"
                    }
                    DeskGuestWipeTargets.APP_DATA -> {
                        val ok = storesDir.listFiles()?.filter { !it.name.contains("identity") }?.all { it.deleteRecursively() } ?: true
                        if (!ok) allOk = false; notes += "app data ${if (ok) "wiped (identity store preserved for re-enrollment honesty)" else "wipe incomplete"}"
                    }
                    DeskGuestWipeTargets.CREDENTIALS -> {
                        val ok = storesDir.listFiles()?.filter { it.name.contains("pairing") || it.name.contains("credential") }
                            ?.all { it.deleteRecursively() } ?: true
                        if (!ok) allOk = false; notes += "credentials ${if (ok) "wiped" else "wipe incomplete"}"
                    }
                    else -> { allOk = false; notes += "target '$t' is not DeskGuest data — refused" }
                }
            }
            allOk to notes.joinToString("; ")
        }
    }
}
