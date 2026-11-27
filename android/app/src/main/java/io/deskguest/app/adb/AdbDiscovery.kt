package io.deskguest.app.adb

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import java.net.Inet4Address

/**
 * mDNS/NSD discovery for wireless debugging (0.4.0): the device
 * advertises _adb-tls-pairing._tcp while its pairing dialog is up
 * and _adb-tls-connect._tcp while wireless debugging is on.
 * Discovery only sees the local network, which is exactly where
 * the endpoints live.
 */
class AdbDiscovery(context: Context) {

    data class Service(
        val name: String,
        val host: String,
        val port: Int,
        /** SERVICE_PAIRING or SERVICE_CONNECT. */
        val kind: String
    )

    private val nsd = context.applicationContext
        .getSystemService(Context.NSD_SERVICE) as NsdManager
    private val listeners = mutableMapOf<String, NsdManager.DiscoveryListener>()

    fun start(kind: String, onService: (Service) -> Unit, onError: (String) -> Unit) {
        stop(kind)
        val listener = object : NsdManager.DiscoveryListener {
            override fun onDiscoveryStarted(serviceType: String?) {}
            override fun onDiscoveryStopped(serviceType: String?) {}
            override fun onStartDiscoveryFailed(serviceType: String?, errorCode: Int) {
                onError("Discovery failed to start (code $errorCode).")
            }
            override fun onStopDiscoveryFailed(serviceType: String?, errorCode: Int) {}

            override fun onServiceFound(service: NsdServiceInfo) {
                @Suppress("DEPRECATION")
                nsd.resolveService(service, object : NsdManager.ResolveListener {
                    override fun onResolveFailed(info: NsdServiceInfo?, errorCode: Int) {}
                    override fun onServiceResolved(info: NsdServiceInfo) {
                        val host = info.host ?: return
                        val address = host.hostAddress ?: return
                        // bd-and-ui F3 fix: the wireless-debugging
                        // endpoints live on THIS device — a resolved
                        // service whose address is not one of this
                        // device's own interface addresses is some
                        // other device advertising the same service
                        // type, and is not offered as an endpoint.
                        // (Before this fix any LAN host advertising
                        // _adb-tls-connect._tcp was passed through.)
                        if (!isOwnAddress(address, ownInterfaceAddresses())) return
                        onService(Service(info.serviceName ?: "adb", address, info.port, kind))
                    }
                })
            }

            override fun onServiceLost(service: NsdServiceInfo?) {}
        }
        listeners[kind] = listener
        try {
            nsd.discoverServices(kind, NsdManager.PROTOCOL_DNS_SD, listener)
        } catch (e: Exception) {
            onError("Discovery failed: ${e.message}")
        }
    }

    fun stop(kind: String) {
        val listener = listeners.remove(kind) ?: return
        try {
            nsd.stopServiceDiscovery(listener)
        } catch (_: Exception) {
        }
    }

    fun stopAll() {
        for (kind in listeners.keys.toList()) stop(kind)
    }

    companion object {
        const val SERVICE_PAIRING = "_adb-tls-pairing._tcp"
        const val SERVICE_CONNECT = "_adb-tls-connect._tcp"

        /** F3: delegates to the pure rule in AdbEndpoints. */
        fun isOwnAddress(address: String, ownAddresses: Set<String>): Boolean =
            AdbEndpoints.isOwnAddress(address, ownAddresses)

        fun ownInterfaceAddresses(): Set<String> {
            val out = mutableSetOf<String>()
            try {
                val interfaces = java.net.NetworkInterface.getNetworkInterfaces() ?: return out
                for (ni in interfaces) {
                    for (addr in ni.inetAddresses) {
                        addr.hostAddress?.let { out.add(it) }
                    }
                }
            } catch (_: Exception) { /* unreadable interfaces: loopback only */ }
            return out
        }
    }
}
