package io.deskguest.app

import android.app.NotificationManager
import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager
import android.os.PowerManager
import android.provider.Settings
import io.deskguest.app.access.ControlAccessibilityService
import java.net.Inet4Address
import java.net.NetworkInterface

/**
 * Live device checks the wizard and self-check read from (SPEC §5.1).
 * Every function observes the device as it is right now — the wizard
 * never asks the user "did it work?", it looks.
 */
object SetupChecks {

    const val TAILSCALE_PACKAGE = "com.tailscale.ipn"

    fun tailscaleInstalled(context: Context): Boolean = try {
        context.packageManager.getPackageInfo(TAILSCALE_PACKAGE, 0)
        true
    } catch (e: PackageManager.NameNotFoundException) {
        false
    }

    /** The phone's Tailscale address (100.64.0.0/10), if Tailscale is up. */
    fun tailnetAddress(): String? = addresses().firstOrNull { isTailnetAddress(it) }

    /** A private LAN address, if the phone is on one. */
    fun lanAddress(): String? = addresses().firstOrNull { isSiteLocal(it) }

    /** Best address for an agent to reach this phone, in preference order. */
    fun bestAddress(): String = tailnetAddress() ?: lanAddress() ?: "127.0.0.1"

    fun batteryExempt(context: Context): Boolean {
        val pm = context.getSystemService(Context.POWER_SERVICE) as PowerManager
        return pm.isIgnoringBatteryOptimizations(context.packageName)
    }

    fun notificationsOn(context: Context): Boolean =
        context.getSystemService(NotificationManager::class.java).areNotificationsEnabled()

    fun overlayOn(context: Context): Boolean = Settings.canDrawOverlays(context)

    // ---------- the accessibility binding watchdog (0.4.0) ----------

    /**
     * Three honest states for the accessibility grant. Android can
     * list the service as enabled while the system has silently
     * dropped the binding (observed in the field after a force-stop):
     * - DISABLED: not in the enabled-services setting at all.
     * - BINDING_STALE: enabled in Settings but no live instance —
     *   recovery is the Settings toggle cycle; the UI deep-links
     *   there instead of claiming a fix it cannot perform.
     * - BOUND: enabled and the service instance is live.
     */
    enum class AccessibilityState { DISABLED, BINDING_STALE, BOUND }

    fun accessibilityState(context: Context): AccessibilityState {
        val expected = ComponentName(context, ControlAccessibilityService::class.java)
        val enabled = Settings.Secure.getString(
            context.contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
        ) ?: return AccessibilityState.DISABLED
        val listed = enabled.split(':').any {
            ComponentName.unflattenFromString(it)?.equals(expected) == true
        }
        if (!listed) return AccessibilityState.DISABLED
        return if (ControlAccessibilityService.isBound) {
            AccessibilityState.BOUND
        } else {
            AccessibilityState.BINDING_STALE
        }
    }

    fun accessibilityBound(context: Context): Boolean =
        accessibilityState(context) == AccessibilityState.BOUND

    // ---------- the connection route (SPEC §5.1 transport choice) ----------

    const val TRANSPORT_WIFI = "wifi"
    const val TRANSPORT_TAILSCALE = "tailscale"
    const val TRANSPORT_TUNNEL = "tunnel"

    private const val PREFS = "setup"
    private const val KEY_TRANSPORT = "transport"

    /** The route the user chose in the wizard, or null when not chosen yet. */
    fun transportChoice(context: Context): String? =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getString(KEY_TRANSPORT, null)

    fun setTransportChoice(context: Context, choice: String) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit().putString(KEY_TRANSPORT, choice).apply()
    }

    /** Plain-words name for a route, for status lines and the report card. */
    fun transportLabel(choice: String?): String = when (choice) {
        TRANSPORT_WIFI -> "This Wi-Fi only"
        TRANSPORT_TAILSCALE -> "Tailscale"
        TRANSPORT_TUNNEL -> "My own tunnel"
        else -> "Not chosen"
    }

    /**
     * The address an AI should use, matching the chosen route. Since
     * 0.4.0 the server binds ONLY the Tailscale address and loopback
     * (never the open LAN — the Part 2 §4 hardening), so every route
     * resolves to the Tailscale address when Tailscale is up; the
     * Wi-Fi choice now means "same network, reached over Tailscale",
     * and the wizard copy says exactly that. Loopback is the last
     * resort (an AI running on this phone itself).
     */
    fun endpointAddress(context: Context): String = when (transportChoice(context)) {
        TRANSPORT_TUNNEL -> tailnetAddress() ?: bestAddress()
        else -> tailnetAddress() ?: "127.0.0.1"
    }

    /**
     * bd-and-rest F8 fix: the address a REMOTE AI can actually
     * reach, or null when there is none. The server binds the
     * tailnet address and loopback only; loopback reaches an AI
     * on THIS phone and nothing else, and the LAN address is not
     * bound at all — so with Tailscale down there is NO honest
     * remote endpoint, and pairing-code creation blocks with the
     * reason instead of writing a prompt around 127.0.0.1 or a
     * LAN address the server never listens on.
     */
    fun reachableRemoteAddress(): String? = tailnetAddress()

    private fun addresses(): List<String> {
        val out = mutableListOf<String>()
        val interfaces = NetworkInterface.getNetworkInterfaces() ?: return out
        for (iface in interfaces) {
            if (!iface.isUp || iface.isLoopback) continue
            for (addr in iface.inetAddresses) {
                if (addr is Inet4Address) addr.hostAddress?.let { out.add(it) }
            }
        }
        return out
    }

    private fun isTailnetAddress(ip: String): Boolean {
        val parts = ip.split('.').mapNotNull { it.toIntOrNull() }
        return parts.size == 4 && parts[0] == 100 && parts[1] in 64..127
    }

    private fun isSiteLocal(ip: String): Boolean {
        val parts = ip.split('.').mapNotNull { it.toIntOrNull() }
        if (parts.size != 4) return false
        return parts[0] == 10 || (parts[0] == 172 && parts[1] in 16..31) ||
            (parts[0] == 192 && parts[1] == 168)
    }
}

/** U6 connection-doctor seam (SetupChecks is where the setup/health
 *  surface already reads its facts): build the doctor's facts from
 *  this device's own current state — interface addresses enumerated
 *  above, rung snapshots supplied by the caller from the transport
 *  layer's own counters/state. Enumeration only — no traffic, and
 *  the doctor itself (transport/ConnectionDoctor.kt) is pure. */
fun SetupChecks.connectionDoctorFacts(rungs: List<io.deskguest.app.transport.RungSnapshot>):
    io.deskguest.app.transport.DoctorFacts {
    val addrs = mutableListOf<String>()
    tailnetAddress()?.let { addrs.add(it) }
    lanAddress()?.let { if (it !in addrs) addrs.add(it) }
    return io.deskguest.app.transport.DoctorFacts(
        localAddresses = addrs, rungs = rungs,
        tailnetAddresses = tailnetAddress()?.let { setOf(it) } ?: emptySet())
}
