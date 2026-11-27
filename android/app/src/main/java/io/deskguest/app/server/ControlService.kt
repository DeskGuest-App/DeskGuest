package io.deskguest.app.server

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.os.IBinder
import io.deskguest.app.CrashTrap
import io.deskguest.app.crypto.AesGcmLineCipher
import io.deskguest.app.crypto.IdentityLineCipher
import io.deskguest.app.crypto.LineCipher
import io.deskguest.app.presence.PresenceOverlay
import java.io.File

/**
 * Foreground service hosting the MCP server (SPEC §4.1). The service is
 * the product's always-visible anchor: while it runs, a persistent
 * notification says the control channel is open — the product never
 * listens in secret.
 */
class ControlService : Service() {

    private var httpServer: McpHttpServer? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    override fun onCreate() {
        super.onCreate()
        io.deskguest.app.Breadcrumb.mark(this, "svc_create_start")
        // Start the presence watcher in the service's own lifecycle, so
        // it runs for exactly as long as the control channel does. (It
        // used to be started from a one-shot thread in onStartCommand;
        // when that server-start attempt failed or raced, the watcher
        // never ran and sessions opened with no banner, glow or STOP.)
        try {
            PresenceOverlay.watch(applicationContext)
        } catch (t: Throwable) {
            CrashTrap.record(this, "PresenceOverlay.watch", t)
        }
        // Guarded (0.4.2): a failure to go foreground must leave a
        // recorded report, never a silent dead channel.
        try {
            createChannel()
            startForeground(NOTIFICATION_ID, buildNotification("Control channel is open on port ${McpHttpServer.PORT}"))
        } catch (t: Throwable) {
            CrashTrap.record(this, "startForeground", t)
        }
        io.deskguest.app.Breadcrumb.mark(this, "svc_foreground_done")

        // The pairing store is built WITHOUT the Android Keystore
        // (0.4.3): the 0.4.2 breadcrumb trail ends at
        // svc_foreground_done — the process died silently in exactly
        // the Keystore-backed store construction that used to stand
        // here, before the channel ever opened, leaving no crash
        // report. The store now starts in the plain form that ran
        // reliably through 0.3.x (app-private file, never backed
        // up), and the Keystore is probed separately, in the
        // background, after the channel is up (see probeKeystore).
        io.deskguest.app.Breadcrumb.mark(this, "svc_before_store")
        val store = buildPairingStore()
        sharedPairingStore = store
        // bd-and-core F4: revoking a pairing, or downgrading its
        // access off the drive caps, ends a live drive session that
        // pairing owns — presence can never name a revoked agent.
        store.onRevoke = { token -> SessionManager.endIfOwnedBy(token) }
        store.onAccessChanged = { pairing ->
            if (pairing.caps.none { it in PairingStore.DRIVE_CAPS }) {
                SessionManager.endIfOwnedBy(pairing.token)
            }
        }
        io.deskguest.app.Breadcrumb.mark(this, "svc_store_ready")
        // Each tool host is built defensively (0.4.1): a host that
        // fails to construct — including linkage errors, which are
        // Throwables, not Exceptions — degrades the channel instead
        // of killing the process, and the failure is recorded.
        val hosts = mutableListOf<McpCore.ToolHost>()
        try {
            hosts.add(
                PhoneToolHost(
                    serverStartedAtMs = System.currentTimeMillis(),
                    appVersion = packageManager.getPackageInfo(packageName, 0).versionName ?: "unknown",
                    appContext = applicationContext
                )
            )
        } catch (t: Throwable) {
            CrashTrap.record(this, "PhoneToolHost init", t)
        }
        try {
            hosts.add(AccessToolHost(applicationContext))
        } catch (t: Throwable) {
            CrashTrap.record(this, "AccessToolHost init", t)
        }
        try {
            hosts.add(EventToolHost())
        } catch (t: Throwable) {
            CrashTrap.record(this, "EventToolHost init", t)
        }
        try {
            hosts.add(ShellToolHost(applicationContext))
        } catch (t: Throwable) {
            CrashTrap.record(this, "ShellToolHost init", t)
        }
        try {
            // BD-XCHECK owed tools (2026-11-22): notify_user,
            // notifications_read, file_*, session_replay_data, and
            // the honest camera_capture de-scope stub.
            hosts.add(OwedToolHost(applicationContext))
        } catch (t: Throwable) {
            CrashTrap.record(this, "OwedToolHost init", t)
        }
        try {
            // W8 item 1: Agent chat transport — chat_read /
            // chat_post over the pairing's own MCP channel, bound
            // to the caller's own thread (chat/AgentChatStore).
            // W10 (V3-F2): chat_ask wired to the ordinary approval
            // gate with the chat origin (A17) — the gate is shown
            // by ApprovalOverlay on this application's context,
            // with the deny-and-end teardown behind it.
            hosts.add(
                ChatToolHost(File(filesDir, "agent-chat"), store) { summary, payload, agentName ->
                    // The owner's approval policy still governs:
                    // a Blocked chat-request class refuses without
                    // a prompt. Otherwise the A17 gate always shows
                    // (a chat ask is never silently allowed).
                    val policy = ApprovalSettings.load(
                        applicationContext, ApprovalGate.ActionClass.CHAT_REQUEST
                    )
                    if (ApprovalGate.decide(policy) == ApprovalGate.Decision.DENY) {
                        false
                    } else {
                        ApprovalOverlay.requestApproval(
                            applicationContext,
                            ApprovalGate.ActionClass.CHAT_REQUEST,
                            summary,
                            agentName,
                            payload = payload,
                            fromChat = true,
                            onDenyAndEnd = GateDenyAndEnd.handler(
                                ApprovalGate.ActionClass.CHAT_REQUEST
                            )
                        )
                    }
                }
            )
        } catch (t: Throwable) {
            CrashTrap.record(this, "ChatToolHost init", t)
        }
        try {
            // W8 item 2: the LIVE MdmService — constructed here so
            // RmmNoticesActivity reads live notices from the
            // service (backed by the same durable notice file),
            // not only the persisted store. Honest posture inside
            // MdmWiring: unavailable executor, no signed gate yet.
            sharedMdmService = io.deskguest.app.rmmspine.MdmWiring.build(
                filesDir, io.deskguest.app.enterprise.ChainedAuditLog()
            )
        } catch (t: Throwable) {
            CrashTrap.record(this, "MdmService init", t)
        }
        // Session replay data source (SPEC §7.6): record session
        // events from service start; in-memory, bounded (ReplayLog).
        try {
            ReplayLog.attach()
        } catch (t: Throwable) {
            CrashTrap.record(this, "ReplayLog attach", t)
        }
        // Driving lockout detector (SPEC §7.7): on-demand OS signal
        // query installed as SessionManager's provider.
        try {
            io.deskguest.app.safety.DrivingStateHolder.provider = {
                io.deskguest.app.safety.DrivingDetector.state(applicationContext)
            }
        } catch (t: Throwable) {
            CrashTrap.record(this, "DrivingDetector install", t)
        }
        try {
            // Slice 1–3 wiring (0.4.6): read-only platform session
            // tools. Construction touches NOTHING — the provider
            // opens the platform stores lazily on the first tool
            // call (an HTTP-handler thread), so the identity seed
            // and the platform stores stay off this startup path
            // (0.4.3 lesson). See wiring/PlatformRuntime.
            // bd-and-core F11: the caller-scope filter — the
            // calling pairing sees only its bound roster scopes, or
            // (unbound) the personal scope(s) alone; never every
            // scope's records.
            hosts.add(
                io.deskguest.app.wiring.PlatformToolHost(
                    storesProvider = {
                        io.deskguest.app.wiring.PlatformRuntime.get(applicationContext)
                    },
                    callerScopes = { token ->
                        val pairing = store.pairingForToken(token)
                        when {
                            pairing == null -> emptySet()
                            pairing.scopeIds.isNotEmpty() -> pairing.scopeIds
                            else -> io.deskguest.app.wiring.PlatformRuntime.peek()
                                ?.scopes()
                                ?.filter { it.kind == io.deskguest.app.roster.RosterStore.SCOPE_PERSONAL }
                                ?.map { it.id }?.toSet() ?: emptySet()
                        }
                    }
                )
            )
        } catch (t: Throwable) {
            CrashTrap.record(this, "PlatformToolHost init", t)
        }
        // bd-and-core F12: the SessionStore badge seam — while a
        // human session is recording / blanked / input-blocked, the
        // presence layer shows a non-hideable badge derived from
        // the record (the claim the model's KDoc always made).
        try {
            io.deskguest.app.presence.PresenceOverlay.sessionBadgeProvider = {
                io.deskguest.app.wiring.PlatformRuntime.peek()?.liveSessionBadges()
                    ?: emptyList()
            }
        } catch (t: Throwable) {
            CrashTrap.record(this, "session badge provider", t)
        }
        // RMM-03 gate wiring (Lane INT, 2026-11-21): the gate is
        // ALWAYS constructed and handed to McpCore — over an empty
        // customer key ring when no key has been provisioned, in
        // which state it refuses every hub command envelope
        // (fail-closed) and the state text says exactly that. The
        // construction lives in CommandGateWiring (pure JVM, suite-
        // proven); it never throws and never yields a null gate.
        val commandWiring = CommandGateWiring.build(
            filesDir, io.deskguest.app.enterprise.ChainedAuditLog()
        )
        sharedCommandGateState = commandWiring.stateDetail
        io.deskguest.app.Breadcrumb.mark(this, "svc_gate_wired")
        val core = McpCore(
            pairingStore = store,
            serverVersion = packageManager.getPackageInfo(packageName, 0).versionName ?: "unknown",
            toolHost = CompositeToolHost(*hosts.toTypedArray()),
            commandGate = commandWiring.gate,
            commandGateStateDetail = commandWiring.stateDetail
        )
        wireAudit(core)
        try {
            io.deskguest.app.presence.PresenceOverlay.watch(this)
        } catch (t: Throwable) {
            CrashTrap.record(this, "PresenceOverlay.watch (service)", t)
        }
        io.deskguest.app.Breadcrumb.mark(this, "svc_hosts_ready")
        try {
            httpServer = McpHttpServer(core).also { it.start() }
            sharedServer = httpServer
        } catch (t: Throwable) {
            CrashTrap.record(this, "McpHttpServer.start", t)
        }
        io.deskguest.app.Breadcrumb.mark(this, "svc_server_attempt_done")
        registerNetworkCallback()
        probeKeystore()
        startHostListener()
    }

    /**
     * Host-listener production binding (W4): the Android host
     * listener starts and stops WITH this service (the control
     * channel's lifecycle). It binds the tailnet address — the
     * same posture as the MCP server — and only when Tailscale is
     * up; with no tailnet address there is nothing honest to bind
     * and the attempt is breadcrumbed, not hidden. Construction is
     * OFF the startup path's critical section: the platform stores
     * open lazily on a background thread (they hold the device
     * identity — the 0.4.3 lesson), and any failure is recorded,
     * never fatal to the channel.
     */
    private fun startHostListener() {
        val thread = Thread {
            try {
                val address = io.deskguest.app.SetupChecks.tailnetAddress()
                if (address == null) {
                    io.deskguest.app.Breadcrumb.mark(applicationContext, "svc_host_listener_no_tailnet")
                    return@Thread
                }
                val stores = io.deskguest.app.wiring.PlatformRuntime.get(applicationContext)
                stores.hostPresenceAttach = { sessionId, peer ->
                    SessionEvents.emit("host_session_pending", mapOf("session" to sessionId, "peer" to peer))
                }
                stores.hostPresenceDetach = { sessionId ->
                    SessionEvents.emit("host_session_ended", mapOf("session" to sessionId))
                }
                val ok = stores.startHostListener(java.net.InetAddress.getByName(address))
                io.deskguest.app.Breadcrumb.mark(
                    applicationContext,
                    if (ok) "svc_host_listener_up" else "svc_host_listener_failed")
            } catch (t: Throwable) {
                CrashTrap.record(applicationContext, "host listener start", t)
            }
        }
        thread.isDaemon = true
        thread.name = "host-listener-start"
        thread.start()
    }

    /**
     * The pairing store on the channel's startup path (0.4.3): plain
     * form, and a store file that fails to load falls back to a
     * fresh one — a corrupt or restored file can no longer take the
     * channel down with it.
     */
    private fun buildPairingStore(): PairingStore =
        try {
            // bd-and-core F6: on a recorded probe_ok verdict the
            // store wraps at rest with the Keystore cipher (load
            // migrates plaintext tokens automatically); without a
            // verdict it stays plain, and AtRestCipher names that
            // honestly. The Keystore is touched only when a prior
            // probe already proved it works on this device.
            val cipher = io.deskguest.app.crypto.AtRestCipher.select(filesDir) {
                AesGcmLineCipher(KeystoreKeys.getOrCreate("pairing-token-key"))
            }
            PairingStore(File(filesDir, "pairings.tsv"), cipher)
        } catch (t: Throwable) {
            CrashTrap.record(this, "PairingStore init", t)
            PairingStore(File(filesDir, "pairings-fresh.tsv"), IdentityLineCipher)
        }

    /**
     * Background Keystore probe (0.4.3): proves whether the Android
     * Keystore round-trip works on this device at all, without the
     * answer gating the channel. Its breadcrumb verdict
     * (svc_keystore_probe_ok / _failed — or silence after
     * svc_keystore_probe_start, which is also a verdict) decides
     * whether the at-rest wrap may return in a later build.
     */
    private fun probeKeystore() {
        val thread = Thread {
            io.deskguest.app.Breadcrumb.mark(applicationContext, "svc_keystore_probe_start")
            try {
                val cipher = AesGcmLineCipher(KeystoreKeys.getOrCreate("pairing-token-key"))
                val roundTrip = cipher.decrypt(cipher.encrypt("probe"))
                val ok = roundTrip == "probe"
                io.deskguest.app.Breadcrumb.mark(
                    applicationContext,
                    if (ok) "svc_keystore_probe_ok" else "svc_keystore_probe_failed"
                )
                // bd-and-core F6: the verdict is RECORDED — the
                // next store construction selects the wrap on an ok
                // verdict (crypto/AtRestCipher). A failed probe
                // records failed, and the stores stay plain.
                io.deskguest.app.crypto.AtRestCipher.recordVerdict(filesDir, ok)
            } catch (t: Throwable) {
                CrashTrap.record(applicationContext, "keystore probe", t)
                io.deskguest.app.Breadcrumb.mark(applicationContext, "svc_keystore_probe_failed")
                io.deskguest.app.crypto.AtRestCipher.recordVerdict(filesDir, false)
            }
        }
        thread.isDaemon = true
        thread.name = "keystore-probe"
        thread.start()
    }

    /**
     * The audit log (0.4.0): every tool call and session event is
     * recorded, encrypted, append-only, with no MCP read path — the
     * owner exports it from the app. Also the session-scoped
     * clipboard rule: a value the agent set is wiped when the
     * session ends.
     */
    private fun wireAudit(core: McpCore) {
        val audit = try {
            // bd-and-core F6: same verdict-gated wrap as the
            // pairing store (crypto/AtRestCipher); plain until a
            // probe_ok verdict is on record. No Keystore call sits
            // on this path unless a prior probe proved it works.
            val cipher = io.deskguest.app.crypto.AtRestCipher.select(filesDir) {
                AesGcmLineCipher(KeystoreKeys.getOrCreate("pairing-token-key"))
            }
            AuditStore(applicationContext, cipher)
        } catch (t: Throwable) {
            CrashTrap.record(this, "AuditStore init", t)
            null
        }
        sharedAuditStore = audit
        if (audit != null) {
            core.auditSink = { agent, tool, ok, detail ->
                audit.record("tool", tool, agent, ok, detail)
            }
            // W89 / S08: every per-pairing grant change (and every
            // refused proposal) through PairingStore lands here.
            sharedPairingStore?.onAccessAudit = { name, ok, detail ->
                audit.record("pairing_access", name, "", ok, detail)
            }
            // W98 / S09(b): every per-pairing connection-path
            // change (and refused proposal) through PairingStore,
            // and every choke-point enforcement refusal in McpCore,
            // lands here under the W97 audit kind.
            sharedPairingStore?.onConnectionAudit = { name, ok, detail ->
                audit.record("pairing_connection", name, "", ok, detail)
            }
            core.connectionAuditSink = { name, ok, detail ->
                audit.record("pairing_connection", name, "", ok, detail)
            }
            SessionEvents.addListener { event ->
                audit.record("session", event.state, "", true, "")
            }
        }
        SessionManager.addListener { session ->
            if (session == null && AccessToolHost.clipboardOwned) {
                AccessToolHost.clipboardOwned = false
                try {
                    val clipboard = getSystemService(
                        android.content.ClipboardManager::class.java
                    )
                    clipboard.setPrimaryClip(
                        android.content.ClipData.newPlainText("", "")
                    )
                } catch (_: Exception) {
                }
            }
        }
    }

    /** The bind set follows the network: when Tailscale comes up or
     *  drops, the server re-evaluates its addresses (0.4.0). */
    private fun registerNetworkCallback() {
        val cm = getSystemService(ConnectivityManager::class.java) ?: return
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                httpServer?.rebind()
            }

            override fun onLost(network: Network) {
                httpServer?.rebind()
            }
        }
        try {
            cm.registerDefaultNetworkCallback(callback)
            networkCallback = callback
        } catch (_: Exception) {
        }
    }

    override fun onDestroy() {
        networkCallback?.let { callback ->
            try {
                getSystemService(ConnectivityManager::class.java)
                    ?.unregisterNetworkCallback(callback)
            } catch (_: Exception) {
            }
        }
        networkCallback = null
        try {
            io.deskguest.app.wiring.PlatformRuntime.peek()?.stopHostListener()
        } catch (_: Throwable) {
        }
        httpServer?.stop()
        httpServer = null
        sharedServer = null
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int = START_STICKY

    private fun createChannel() {
        val manager = getSystemService(NotificationManager::class.java)
        val channel = NotificationChannel(
            CHANNEL_ID, "Control channel", NotificationManager.IMPORTANCE_LOW
        ).apply { description = "Shown while the DeskGuest server is running" }
        manager.createNotificationChannel(channel)
    }

    private fun buildNotification(text: String): Notification =
        Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("DeskGuest")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setOngoing(true)
            .build()

    companion object {
        private const val CHANNEL_ID = "control_channel"
        private const val NOTIFICATION_ID = 1001

        /** Set while the service lives; the UI reads server state here. */
        @Volatile
        var sharedServer: McpHttpServer? = null

        /** The audit log, for the home screen's count + export. */
        @Volatile
        var sharedAuditStore: AuditStore? = null

        @Volatile
        var sharedPairingStore: PairingStore? = null

        /** W8 item 2: the live MdmService, for RmmNoticesActivity.
         *  Null only when construction failed (recorded above) —
         *  the surface then falls back to the persisted store and
         *  says so by rendering exactly what the store holds. */
        @Volatile
        var sharedMdmService: io.deskguest.app.rmmspine.MdmService? = null

        /** The RMM-03 gate's honest state line (see CommandGateWiring),
         *  for surfaces that report signed-command posture. */
        @Volatile
        var sharedCommandGateState: String? = null

        /**
         * Guarded (0.4.2): a start refusal must be recorded, not
         * take the calling screen down with it. Returns true when
         * the start request was accepted by the system, false when
         * it was refused (the refusal is recorded either way).
         * TRUE IS NOT "the channel is up" — the service's own
         * breadcrumbs are that proof. The boot receiver (C19) uses
         * the return value to record an honest boot outcome.
         */
        fun start(context: Context): Boolean =
            try {
                context.startForegroundService(Intent(context, ControlService::class.java))
                requestTileRefresh(context)
                true
            } catch (t: Throwable) {
                CrashTrap.record(context, "ControlService.start", t)
                false
            }

        fun stop(context: Context) {
            context.stopService(Intent(context, ControlService::class.java))
            requestTileRefresh(context)
        }

        /** bd-and-ui F6 fix: whenever the channel state changes,
         *  ask the system to re-run the tile's onStartListening so
         *  the tile re-renders from real state instead of whatever
         *  it last showed. */
        private fun requestTileRefresh(context: Context) {
            try {
                android.service.quicksettings.TileService.requestListeningState(
                    context,
                    android.content.ComponentName(
                        context, io.deskguest.app.tile.DeskGuestTileService::class.java)
                )
            } catch (_: Throwable) { /* tile absent on some builds: non-fatal */ }
        }
    }
}
