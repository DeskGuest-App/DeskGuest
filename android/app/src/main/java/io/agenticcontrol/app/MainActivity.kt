package io.agenticcontrol.app

import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.core.content.FileProvider
import io.agenticcontrol.app.presence.PresenceSettings
import io.agenticcontrol.app.strings.consentString
import io.agenticcontrol.app.transport.ConnectionDoctor
import io.agenticcontrol.app.transport.RungSnapshot
import io.agenticcontrol.app.server.ControlService
import io.agenticcontrol.app.server.McpHttpServer
import io.agenticcontrol.app.server.PairingStore
import io.agenticcontrol.app.adb.AdbDiscovery
import io.agenticcontrol.app.adb.AdbPairing
import io.agenticcontrol.app.adb.AndroidAdbIdentity
import io.agenticcontrol.app.server.SessionManager
import io.agenticcontrol.app.server.ShellStore
import io.agenticcontrol.app.ui.Fonts
import io.agenticcontrol.app.ui.LogoView
import io.agenticcontrol.app.ui.UiKit
import io.agenticcontrol.app.update.UpdateChecker
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Home screen (0.4.0, the approved Daylight-White design): the
 * channel's state, the live session (or the quiet dashed card when
 * there is none), the paired AIs and what each may do, the pairing
 * door, devices, setup health, and updates. First run routes
 * straight to the setup wizard (SPEC §5).
 */
class MainActivity : Activity() {

    private lateinit var root: LinearLayout
    private var pairingCode: String? = null
    private var currentPrompt: String = ""
    private var expandedAccessToken: String? = null
    /** W98 / S09(b): the mint-time connection-path choice on the
     *  Connect card (default AUTO), bound to the code by
     *  beginPairing. */
    private var mintConnection: io.agenticcontrol.app.server.ConnectionPath.Setting =
        io.agenticcontrol.app.server.ConnectionPath.Setting.AUTO
    private var sessionTimerView: TextView? = null
    private var discovery: AdbDiscovery? = null
    private val discovered = mutableListOf<AdbDiscovery.Service>()
    private var shellHostField: EditText? = null
    private var shellPortField: EditText? = null
    private val ticker = Handler(Looper.getMainLooper())
    private val tick = object : Runnable {
        override fun run() {
            updateSessionTimer()
            watchServerState()
            ticker.postDelayed(this, 1000)
        }
    }

    // ---- server-status truth (0.4.4) --------------------------------
    // The status card used to be rendered once from whatever state
    // the service happened to be in at that instant: at cold start
    // ControlService.start() is asynchronous, sharedServer was still
    // null, the card painted "Starting" — and nothing ever re-rendered
    // it, so the card sat on Starting forever while the server ran.
    // The card's state is now a key derived from the server's REAL
    // state on every tick; any change re-renders the home screen, so
    // the card can only ever show what is true right now.

    private var homeShown = false
    private var lastServerStateKey: String? = null

    private fun serverStateKey(): String {
        val server = ControlService.sharedServer ?: return "starting"
        return if (server.isRunning) {
            "running:" + server.boundAddresses.joinToString(",")
        } else {
            "stopped"
        }
    }

    private fun watchServerState() {
        if (!homeShown) return
        val key = serverStateKey()
        val last = lastServerStateKey
        lastServerStateKey = key
        if (last != null && key != last) refresh()
    }

    private enum class UpdateState { IDLE, CHECKING, UP_TO_DATE, AVAILABLE, WORKING, FAILED }
    private var updateState = UpdateState.IDLE
    private var updateMessage: String = ""
    private var updateInfo: UpdateChecker.UpdateInfo? = null

    /** Stage 3/4 sections register their renderers here so this file
     *  stays the home screen's spine. (Filled in by later stages.) */
    private val extraSections = mutableListOf<(LinearLayout) -> Unit>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // 0.4.1: a saved failure report is shown before anything else
        // runs, so a startup crash can never again present as a black
        // box — the owner sees what died and can let the app continue.
        val crash = CrashTrap.read(this)
        if (crash != null) {
            showCrash(crash)
            return
        }
        startNormally()
    }

    private fun startNormally() {
        // C19: a human opening the app is the opened-once proof the
        // boot receiver checks — an app never opened has no channel
        // setup to restart after a reboot.
        io.agenticcontrol.app.server.BootRestartSettings.markOpened(this)
        ControlService.start(this)
        root = UiKit.page(this)
        registerExtraSections()
        homeShown = true
        lastServerStateKey = serverStateKey()
        refresh()
        if (!WizardActivity.isDone(this)) {
            startActivity(Intent(this, WizardActivity::class.java))
        }
    }

    /** The failure-report screen: what crashed, and the way through. */
    private fun showCrash(report: String) {
        root = UiKit.page(this)
        root.addView(UiKit.sectionTitle(this, "Something went wrong"))
        root.addView(
            UiKit.body(
                this,
                "DeskGuest hit a failure and recorded this report. " +
                    "Screenshot it for the developer, then continue — the app " +
                    "starts fresh from here."
            )
        )
        root.addView(TextView(this).apply {
            text = report
            textSize = 11f
            typeface = Fonts.mono(this@MainActivity)
            setTextColor(UiKit.TEXT)
        })
        root.addView(UiKit.primaryButton(this, "Clear report and open the app") {
            CrashTrap.clear(this@MainActivity)
            startNormally()
        })
    }

    override fun onResume() {
        super.onResume()
        AppForeground.isForeground = true
        if (::root.isInitialized) refresh()
        ticker.removeCallbacks(tick)
        ticker.post(tick)
    }

    override fun onPause() {
        super.onPause()
        AppForeground.isForeground = false
        ticker.removeCallbacks(tick)
    }

    override fun onDestroy() {
        discovery?.stopAll()
        super.onDestroy()
    }

    /** Later build stages add their home sections (audit, shell,
     *  devices) through here. */
    private fun registerExtraSections() {
        extraSections.add { column -> renderRecoverySection(column) }
        extraSections.add { column -> renderPlatformSection(column) }
        extraSections.add { column -> renderBootRestartSection(column) }
        extraSections.add { column -> renderAuditSection(column) }
        extraSections.add { column -> renderApprovalsSection(column) }
        extraSections.add { column -> renderShellSection(column) }
        extraSections.add { column -> renderDevicesSection(column) }
        extraSections.add { column -> renderInvisibleAppsSection(column) }
    }

    /** Invisible apps (SPEC §7.5, BD-XCHECK owed item, 2026-11-22):
     *  the owner marks apps an agent may never see, list, or drive.
     *  Owner-only surface — no tool can read or change this list;
     *  a blocked app reports only `blocked_by_user_rule`. */
    private fun renderInvisibleAppsSection(column: LinearLayout) {
        column.addView(UiKit.sectionTitle(this, "Invisible apps"))
        val card = UiKit.card(this)
        card.addView(
            UiKit.body(
                this,
                "Apps you mark here are invisible to every paired agent: they cannot be " +
                    "snapshotted, screenshotted, opened, driven, or even named back. " +
                    "Banking and password-manager apps are the usual marks."
            )
        )
        val store = io.agenticcontrol.app.safety.InvisibleAppStore
        val marked = store.blocklist(this).list()
        if (marked.isEmpty()) {
            card.addView(UiKit.muted(this, "No apps are marked invisible."))
        } else {
            marked.forEach { pkg ->
                card.addView(UiKit.outlineButton(this, "Make visible: $pkg") {
                    store.unmark(this, pkg)
                    refresh()
                })
            }
        }
        val field = EditText(this).apply {
            hint = "Package name, e.g. com.example.bank"
            setSingleLine(true)
        }
        card.addView(field)
        card.addView(UiKit.primaryButton(this, "Mark invisible") {
            val added = store.mark(this, field.text?.toString())
            if (added == null) {
                Toast.makeText(
                    this, "That is not a package name (e.g. com.example.bank).",
                    Toast.LENGTH_LONG
                ).show()
            } else {
                refresh()
            }
        })
        column.addView(card)
    }

    // ---------- rendering ----------

    private fun refresh() {
        root.removeAllViews()
        sessionTimerView = null
        lastServerStateKey = serverStateKey()
        // W6 design record §4 A1 (OI-11): the state sentence comes
        // FIRST on Home, before everything else.
        section("home state") { renderHomeState() }
        section("header") { renderHeader() }
        section("server card") { renderServerCard() }
        section("session card") { renderSessionCard() }
        // W7 §4 A1 order: (2) This phone — the readiness ledger,
        // rendered from HomeModel (problems promoted to the top).
        section("readiness") { renderReadinessLedger() }
        section("pairings") { renderPairings() }
        // W7 §4 A1 order (OI-11): (4) Recent sessions, then
        // (5) the standing sections — below Who may connect.
        section("recent") { renderRecentSessions() }
        section("standing") { renderStandingSections() }
        section("connect") { renderConnect() }
        extraSections.forEach { section("extra section") { it(root) } }
        section("setup row") { renderSetupRow() }
        section("updates") { renderUpdates() }
        root.addView(TextView(this).apply {
            text = "DeskGuest ${appVersionName()}"
            textSize = 13f
            typeface = Fonts.regular(this@MainActivity)
            setTextColor(UiKit.DISABLED)
            gravity = Gravity.CENTER
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply { setMargins(0, UiKit.dp(this@MainActivity, 10), 0, 0) }
        })
        Breadcrumb.last(this)?.let { last ->
            root.addView(TextView(this).apply {
                text = "Diagnostics — last run reached: $last"
                textSize = 11f
                typeface = Fonts.mono(this@MainActivity)
                setTextColor(UiKit.DISABLED)
                gravity = Gravity.CENTER
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
                ).apply { setMargins(0, UiKit.dp(this@MainActivity, 4), 0, 0) }
            })
        }
    }

    /**
     * One home-screen section, guarded (0.4.1): a failure in any single
     * section is recorded for the report screen and replaced with a
     * note, instead of taking the whole screen — and the app — down.
     */
    private fun section(name: String, block: () -> Unit) {
        try {
            block()
        } catch (t: Throwable) {
            CrashTrap.record(this, "home section '$name'", t)
            try {
                root.addView(
                    UiKit.muted(
                        this,
                        "One part of this screen failed to load ($name). " +
                            "The failure was recorded — reopen the app to see the report."
                    )
                )
            } catch (_: Throwable) {
            }
        }
    }

    private fun renderHeader() {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply { setMargins(0, 0, 0, UiKit.dp(this@MainActivity, 16)) }
        }
        row.addView(LogoView(this), LinearLayout.LayoutParams(UiKit.dp(this, 40), UiKit.dp(this, 40)))
        row.addView(TextView(this).apply {
            text = "DeskGuest"
            textSize = 20f
            typeface = Fonts.medium(this@MainActivity)
            setTextColor(UiKit.TEXT)
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
                .apply { setMargins(UiKit.dp(this@MainActivity, 12), 0, 0, 0) }
        })
        row.addView(TextView(this).apply {
            text = "⚙"
            textSize = 22f
            setTextColor(UiKit.SECONDARY)
            setPadding(
                UiKit.dp(this@MainActivity, 10), UiKit.dp(this@MainActivity, 6),
                UiKit.dp(this@MainActivity, 4), UiKit.dp(this@MainActivity, 6)
            )
            isClickable = true
            isFocusable = true
            contentDescription = "Presence settings"
            setOnClickListener {
                startActivity(Intent(this@MainActivity, PresenceActivity::class.java))
            }
        })
        root.addView(row)
    }

    private fun renderServerCard() {
        val server = ControlService.sharedServer
        val card = UiKit.card(this)
        val head = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        when {
            server == null -> {
                head.addView(UiKit.dot(this, UiKit.WARNING, 9))
                head.addView(stateLabel("Starting"))
            }
            server.isRunning -> {
                head.addView(UiKit.dot(this, UiKit.SUCCESS, 9))
                head.addView(stateLabel("Running"))
            }
            else -> {
                head.addView(UiKit.dot(this, UiKit.DISABLED, 9))
                head.addView(stateLabel("Stopped"))
            }
        }
        head.addView(View(this), LinearLayout.LayoutParams(0, 1, 1f))
        head.addView(TextView(this).apply {
            text = "Server Address"
            textSize = 12f
            typeface = Fonts.regular(this@MainActivity)
            setTextColor(UiKit.SECONDARY)
        })
        card.addView(head)
        card.addView(TextView(this).apply {
            text = "${SetupChecks.endpointAddress(this@MainActivity)}: ${McpHttpServer.PORT}"
            textSize = 15f
            typeface = Fonts.mono(this@MainActivity)
            setTextColor(UiKit.TEXT)
            gravity = Gravity.END
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply { setMargins(0, UiKit.dp(this@MainActivity, 2), 0, UiKit.dp(this@MainActivity, 10)) }
        })
        card.addView(
            UiKit.muted(
                this,
                "Route: ${SetupChecks.transportLabel(SetupChecks.transportChoice(this))}. " +
                    "Nothing connects without a pairing you approve here."
            )
        )
        // U6 connection doctor: why-can't-I-connect, from this
        // device's own facts only (server state + interface
        // addresses). Diagnostic only — it probes and changes
        // nothing; a path is called reachable only when the server
        // is actually bound on it.
        // bd-and-rest F6 fix: the LAN entry was built from tailnet
        // facts and called "Bound" whenever a LAN address existed —
        // but the server NEVER binds the LAN (Part 2 §4 hardening).
        // The doctor now reads the server's REAL bound set: LAN is
        // bound only if a LAN address is actually in boundAddresses,
        // and otherwise reports its honest phase. tailnetAddress()
        // is also read once, not six times per render.
        val tailnetAddr = SetupChecks.tailnetAddress()
        val lanAddr = SetupChecks.lanAddress()
        val bound = server?.boundAddresses ?: emptyList()
        val doctorFacts = SetupChecks.connectionDoctorFacts(listOf(
            RungSnapshot(
                id = "tailscale", registered = true,
                configured = tailnetAddr != null,
                connectAttempts = 0,
                laneBound = server?.isRunning == true && tailnetAddr != null && tailnetAddr in bound,
                lanePhaseName = if (tailnetAddr != null && tailnetAddr in bound) "Bound" else "NoAddress",
                laneAddress = tailnetAddr),
            RungSnapshot(
                id = "lan", registered = true,
                configured = lanAddr != null,
                connectAttempts = 0,
                laneBound = server?.isRunning == true && lanAddr != null && lanAddr in bound,
                lanePhaseName = if (lanAddr != null && lanAddr in bound) "Bound" else "NotBound",
                laneAddress = lanAddr)
        ))
        card.addView(UiKit.muted(this,
            ConnectionDoctor.renderLines(ConnectionDoctor.diagnose(doctorFacts)).joinToString("\n")))
        if (server?.isRunning == true) {
            card.addView(UiKit.outlineButton(this, "Stop server") {
                ControlService.stop(this)
                toast("The control channel is stopped.")
                refresh()
            })
        } else if (server != null) {
            card.addView(UiKit.outlineButton(this, "Start server") {
                ControlService.start(this)
                refresh()
            })
        }
        root.addView(card)
    }

    private fun stateLabel(text: String): TextView = TextView(this).apply {
        this.text = text
        textSize = 16f
        typeface = Fonts.medium(this@MainActivity)
        setTextColor(UiKit.TEXT)
    }

    /** W6 §4 A1: Home's opening line — the state sentence. With no
     *  session it is the record's exact no-one sentence; with a
     *  session running it names the agent in the phone. While a
     *  session runs and ACP is in the foreground, the overlay Box
     *  is the only Box — this body carries no STOP of its own in
     *  this section. */
    private fun renderHomeState() {
        val session = SessionManager.active
        val sentence = if (session == null) {
            consentString(R.string.home_no_one_in_phone)
        } else {
            consentString(R.string.home_agent_in_phone, session.agentName)
        }
        root.addView(TextView(this).apply {
            text = sentence
            textSize = 19f
            typeface = Fonts.medium(this@MainActivity)
            setTextColor(UiKit.TEXT)
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply { setMargins(0, 0, 0, UiKit.dp(this@MainActivity, 8)) }
        })
    }

    /** W7 §4 A1 (2): the readiness ledger, built through
     *  HomeModel so the promotion rule (a problem rises; a
     *  non-decision does not appear) is the model's, not the
     *  view's. Each row carries its consequence in plain words. */
    private fun renderReadinessLedger() {
        val rows = mutableListOf<io.agenticcontrol.app.design.HomeModel.ReadinessRow>()
        val channelUp = ControlService.sharedServer?.isRunning == true
        rows += io.agenticcontrol.app.design.HomeModel.ReadinessRow(
            "Control channel",
            if (channelUp) "Your AI can reach this phone."
            else "Your AI cannot reach this phone until the channel is running.",
            isProblem = !channelUp
        )
        val a11y = SetupChecks.accessibilityBound(this)
        rows += io.agenticcontrol.app.design.HomeModel.ReadinessRow(
            "Screen access",
            if (a11y) "Your AI can see and touch the screen when you allow a session."
            else "Your AI can connect but cannot see or touch the screen.",
            isProblem = !a11y
        )
        val overlay = SetupChecks.overlayOn(this)
        rows += io.agenticcontrol.app.design.HomeModel.ReadinessRow(
            "On-screen signals",
            if (overlay) "The box, ring, and glow can be shown during a session."
            else "Presence cannot be shown — sessions cannot start until this is on.",
            isProblem = !overlay
        )
        val model = io.agenticcontrol.app.design.HomeModel.build(
            deviceName = android.os.Build.MODEL ?: "This phone",
            sessionAgent = SessionManager.active?.agentName,
            readiness = rows,
            agents = emptyList(),
            recentSessions = emptyList()
        )
        root.addView(UiKit.sectionTitle(this, consentString(R.string.home_readiness_title)))
        val card = UiKit.card(this)
        for (row in model.readiness) {
            card.addView(UiKit.body(this, row.label))
            card.addView(UiKit.muted(this, row.consequence))
        }
        root.addView(card)
    }

    /** W7 §4 A1 (4): Recent sessions — the latest SessionStore
     *  records, newest first, capped for the Home surface (the
     *  full list lives in Sessions). */
    private fun renderRecentSessions() {
        val all = try {
            io.agenticcontrol.app.wiring.PlatformRuntime.get(this).allSessions()
        } catch (_: Exception) {
            emptyList()
        }
        if (all.isEmpty()) return
        root.addView(UiKit.sectionTitle(this, consentString(R.string.home_recent_title)))
        val card = UiKit.card(this)
        for (session in all.take(3)) {
            card.addView(UiKit.muted(this, "${session.id} — ${session.state.lowercase()}"))
        }
        root.addView(card)
    }

    /** W7 §4 A1 (5): the standing sections the A1 inventory
     *  names — each a named row; a capability not in this build
     *  says so on its row (HomeModel.STANDING_SECTIONS). */
    private fun renderStandingSections() {
        root.addView(UiKit.sectionTitle(this, consentString(R.string.home_standing_title)))
        val card = UiKit.card(this)
        for (name in io.agenticcontrol.app.design.HomeModel.STANDING_SECTIONS) {
            card.addView(UiKit.muted(this, name))
        }
        root.addView(card)
        root.addView(
            UiKit.navRow(this, "Management notices & backup key", "") {
                startActivity(
                    android.content.Intent(this, RmmNoticesActivity::class.java)
                )
            }
        )
    }

    private fun renderSessionCard() {
        val session = SessionManager.active
        if (session == null) {
            val card = UiKit.dashedCard(this)
            card.addView(UiKit.muted(this, "SESSION"))
            card.addView(TextView(this).apply {
                text = consentString(R.string.session_none_title)
                textSize = 17f
                typeface = Fonts.medium(this@MainActivity)
                setTextColor(UiKit.TEXT)
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
                ).apply { setMargins(0, 0, 0, UiKit.dp(this@MainActivity, 6)) }
            })
            card.addView(
                UiKit.muted(
                    this,
                    consentString(R.string.session_none_body)
                )
            )
            root.addView(card)
            return
        }
        val accent = io.agenticcontrol.app.design.PresenceLaw.HUE_AI
        val card = UiKit.card(this, accent = accent)
        val head = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        head.addView(
            UiKit.chip(
                this,
                if (SessionManager.isPaused) consentString(R.string.session_paused_chip) else consentString(R.string.session_active_chip),
                if (SessionManager.isPaused) UiKit.ChipKind.WARN else UiKit.ChipKind.ACCENT
            )
        )
        card.addView(head)
        card.addView(
            UiKit.body(this, if (SessionManager.isPaused) consentString(R.string.session_paused_body, session.agentName) else consentString(R.string.consent_session_active, session.agentName))
        )
        val timer = TextView(this).apply {
            textSize = 40f
            typeface = Fonts.mono(this@MainActivity)
            setTextColor(UiKit.TEXT)
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply { setMargins(0, UiKit.dp(this@MainActivity, 2), 0, UiKit.dp(this@MainActivity, 6)) }
        }
        sessionTimerView = timer
        card.addView(timer)
        updateSessionTimer()
        val meta = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        meta.addView(UiKit.chip(this, consentString(R.string.session_actions, session.actions), UiKit.ChipKind.NEUTRAL))
        if (session.intent.isNotBlank()) {
            meta.addView(UiKit.chip(this, session.intent, UiKit.ChipKind.NEUTRAL))
        }
        card.addView(meta)
        if (SessionManager.isPaused) {
            card.addView(UiKit.outlineButton(this, consentString(R.string.session_resume)) {
                SessionManager.resume()
                refresh()
            })
        }
        card.addView(UiKit.stopButton(this) {
            SessionManager.stopByUser()
            toast(consentString(R.string.session_stopped_toast))
            refresh()
        })
        root.addView(card)
    }

    private fun updateSessionTimer() {
        val view = sessionTimerView ?: return
        val session = SessionManager.active ?: return
        val totalSec = (System.currentTimeMillis() - session.startedAtMs) / 1000
        view.text = "%02d:%02d".format(totalSec / 60, totalSec % 60)
    }

    /** W98 / S09(b): the live current-path label for a pairing
     *  card — from the store's in-memory last-authenticated-arrival
     *  state only (W97's label discipline: a stored claim would be
     *  a lie after a restart, so before the first connection of
     *  this run the label says exactly that). */
    private fun currentPathLine(
        store: io.agenticcontrol.app.server.PairingStore,
        pairing: io.agenticcontrol.app.server.PairingStore.Pairing
    ): String {
        val last = store.lastConnection(pairing.token)
            ?: return "Hasn't connected since the app started — no path to show yet."
        val time = SimpleDateFormat("h:mm a", Locale.US).format(Date(last.second))
        return "Last connected over ${io.agenticcontrol.app.server.ConnectionPath.pathName(last.first)} at $time."
    }

    private fun renderPairings() {
        val store = ControlService.sharedPairingStore
        val paired = store?.all().orEmpty()
        if (paired.isEmpty()) return
        root.addView(UiKit.sectionTitle(this, "Paired AI"))
        val pairingStore = store ?: return
        paired.forEach { pairing ->
            val card = UiKit.card(this)
            val nameRow = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
            }
            nameRow.addView(avatar(displayName(pairing)))
            nameRow.addView(TextView(this).apply {
                text = displayName(pairing)
                textSize = 17f
                typeface = Fonts.medium(this@MainActivity)
                setTextColor(UiKit.TEXT)
                layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
                    .apply { setMargins(UiKit.dp(this@MainActivity, 12), 0, 0, 0) }
            })
            nameRow.addView(UiKit.chip(this, "Paired", UiKit.ChipKind.GOOD))
            card.addView(nameRow)
            if (pairing.createdAtMs > 0) {
                val date = SimpleDateFormat("d MMM yyyy", Locale.US).format(Date(pairing.createdAtMs))
                card.addView(UiKit.muted(this, "Paired $date · ${io.agenticcontrol.app.server.AccessControl.classifyName(pairing.scopes)}"))
            }
            // W7 §4 A17: Agent chat entry on the agent card, with
            // the chat Sent count from the data-flow ledger.
            val chatSent = io.agenticcontrol.app.chat.AgentChatStore.sentCount(pairing.id)
            if (chatSent > 0) {
                card.addView(
                    UiKit.muted(
                        this,
                        io.agenticcontrol.app.design.SessionDetailModel
                            .chatSentLine(chatSent.toInt())
                    )
                )
            }
            card.addView(
                UiKit.navRow(this, "Agent chat", if (chatSent > 0) "$chatSent sent" else "") {
                    startActivity(
                        android.content.Intent(this, AgentChatActivity::class.java)
                            .putExtra(AgentChatActivity.EXTRA_PAIRING_TOKEN, pairing.token)
                    )
                }
            )
            val expanded = expandedAccessToken == pairing.token
            card.addView(
                UiKit.navRow(
                    this, "Access",
                    io.agenticcontrol.app.server.AccessControl.classifyName(pairing.scopes)
                ) {
                    expandedAccessToken = if (expanded) null else pairing.token
                    refresh()
                }
            )
            if (expanded) {
                card.addView(
                    // W89 / S08: the stepped slider + Fine-tune
                    // editor over the pairing's scope set. Nothing
                    // applies until the owner taps Apply in the
                    // preview; adding admin jobs additionally needs
                    // the preview's own elevation switch (the store
                    // refuses without it — default refused), and
                    // every apply/refusal is audited. The W7
                    // full-control confirmation line names the agent
                    // in that preview.
                    UiKit.accessEditor(
                        this, pairing.scopes,
                        io.agenticcontrol.app.design.AccessEditorModel.fullControlConfirmLine(displayName(pairing))
                    ) { proposed, elevationConfirmed ->
                        val result = pairingStore.updateScopes(
                            pairing.token, proposed, elevationConfirmed
                        )
                        when {
                            result.pairing != null -> {
                                toast("Access updated for ${displayName(pairing)}.")
                                refresh()
                                null
                            }
                            result.refusal != null -> "Refused: ${result.refusal}"
                            else -> "That pairing is no longer there."
                        }
                    }
                )
                // W7 item 7: Pairing.scopeIds owner UI (W2-A
                // remainder) — the roster scopes this pairing may
                // see, edited as a comma-separated list and saved
                // through PairingStore.setScopeIds.
                card.addView(UiKit.muted(this, "Scopes this pairing may see (comma-separated)"))
                val scopeField = android.widget.EditText(this).apply {
                    setText(pairing.scopeIds.joinToString(", "))
                    textSize = 14f
                    typeface = Fonts.regular(this@MainActivity)
                    setTextColor(UiKit.TEXT)
                    isSingleLine = false
                }
                card.addView(scopeField)
                card.addView(UiKit.outlineButton(this, "Save scopes") {
                    val ids = io.agenticcontrol.app.design.AccessEditorModel
                        .normaliseScopeIds(scopeField.text.toString().split(","))
                    pairingStore.setScopeIds(pairing.token, ids)
                    toast("Scopes saved for ${displayName(pairing)}.")
                    refresh()
                })
                // W98 / S09(b): the connection-path control, beside
                // the access editor on the pairing card — same
                // staged preview + Apply discipline (the store is
                // the one apply path; change AND refusal audited).
                // The current-path label is built from the store's
                // live last-arrival state, never a stored claim.
                card.addView(
                    UiKit.connectionPathEditor(
                        this, pairing.connection,
                        currentPathLine(pairingStore, pairing)
                    ) { proposed ->
                        val result = pairingStore.updateConnectionPath(pairing.token, proposed)
                        when {
                            result.pairing != null -> {
                                toast("Connection path updated for ${displayName(pairing)}.")
                                refresh()
                                null
                            }
                            result.refusal != null -> "Refused: ${result.refusal}"
                            else -> "That pairing is no longer there."
                        }
                    }
                )
            }
            card.addView(UiKit.outlineButton(this, "Unpair") {
                // §4 A17: unpairing ends the chat thread.
                io.agenticcontrol.app.chat.AgentChatStore.endThread(
                    java.io.File(filesDir, "agent-chat"), pairing.id
                )
                ControlService.sharedPairingStore?.revoke(pairing.token)
                if (expandedAccessToken == pairing.token) expandedAccessToken = null
                toast("${displayName(pairing)} is unpaired. Its token stops working now.")
                refresh()
            })
            root.addView(card)
        }
    }

    /** The initial-letter avatar from the design set. */
    private fun avatar(name: String): View = TextView(this).apply {
        text = name.trim().firstOrNull()?.uppercase() ?: "?"
        textSize = 16f
        typeface = Fonts.medium(this@MainActivity)
        setTextColor(UiKit.TEXT)
        gravity = Gravity.CENTER
        background = GradientDrawable().apply {
            shape = GradientDrawable.OVAL
            setColor(UiKit.SUBTLE)
        }
        layoutParams = LinearLayout.LayoutParams(UiKit.dp(this@MainActivity, 40), UiKit.dp(this@MainActivity, 40))
    }

    private fun renderConnect() {
        root.addView(UiKit.sectionTitle(this, "Connect an AI"))
        val card = UiKit.card(this)
        card.addView(UiKit.body(this, "The app writes a short prompt with a one-time code. Copy it into your AI's app — the AI does the rest."))
        if (pairingCode == null) {
            // W98 / S09(b): the mint-time connection choice
            // (default AUTO), bound to the code when it is made.
            card.addView(
                UiKit.connectionPathMintPicker(this, mintConnection) { chosen ->
                    mintConnection = chosen
                }
            )
        }
        if (pairingCode == null) {
            card.addView(UiKit.primaryButton(this, "Make a pairing code") { beginPairing() })
        } else {
            card.addView(UiKit.muted(this, "Your pairing code"))
            card.addView(TextView(this).apply {
                text = pairingCode
                textSize = 32f
                typeface = Fonts.monoBold(this@MainActivity)
                letterSpacing = 0.18f
                setTextColor(UiKit.TEXT)
            })
            card.addView(UiKit.muted(this, currentPrompt))
            card.addView(UiKit.primaryButton(this, "Copy the prompt for your AI") { copyPrompt() })
            card.addView(UiKit.textButton(this, "Make a new code") { beginPairing() })
        }
        root.addView(card)
    }

    private fun renderSetupRow() {
        val card = UiKit.card(this)
        val a11y = SetupChecks.accessibilityState(this)
        val healthy = a11y == SetupChecks.AccessibilityState.BOUND &&
            SetupChecks.overlayOn(this) && SetupChecks.notificationsOn(this) &&
            SetupChecks.batteryExempt(this)
        val label: String
        val detail: String
        when {
            a11y == SetupChecks.AccessibilityState.BINDING_STALE -> {
                label = "Setup needs attention"
                detail = "Screen access shows as on, but its connection dropped. Open the setup guide to fix it."
            }
            healthy -> {
                label = "Setup complete"
                detail = "Channel, screen access, on-screen signals, notifications, and battery are all in."
            }
            else -> {
                label = "Setup needs attention"
                detail = "One or more grants are missing. Open the setup guide to finish."
            }
        }
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            isClickable = true
            isFocusable = true
            setOnClickListener {
                startActivity(Intent(this@MainActivity, WizardActivity::class.java))
            }
        }
        row.addView(TextView(this).apply {
            text = if (healthy) "✓" else "!"
            textSize = 15f
            typeface = Fonts.medium(this@MainActivity)
            setTextColor(Color.WHITE)
            gravity = Gravity.CENTER
            background = GradientDrawable().apply {
                shape = GradientDrawable.OVAL
                setColor(if (healthy) UiKit.SUCCESS else UiKit.WARNING)
            }
            layoutParams = LinearLayout.LayoutParams(UiKit.dp(this@MainActivity, 26), UiKit.dp(this@MainActivity, 26))
        })
        val texts = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
                .apply { setMargins(UiKit.dp(this@MainActivity, 12), 0, 0, 0) }
        }
        texts.addView(TextView(this).apply {
            text = label
            textSize = 16f
            typeface = Fonts.medium(this@MainActivity)
            setTextColor(UiKit.TEXT)
        })
        texts.addView(TextView(this).apply {
            text = detail
            textSize = 13f
            typeface = Fonts.regular(this@MainActivity)
            setTextColor(UiKit.SECONDARY)
        })
        row.addView(texts)
        row.addView(TextView(this).apply {
            text = "›"
            textSize = 22f
            setTextColor(UiKit.DISABLED)
        })
        card.addView(row)
        root.addView(card)
    }

    // ---------- updates ----------

    private fun renderUpdates() {
        if (updateState == UpdateState.AVAILABLE && updateInfo != null) {
            renderUpdateReady(updateInfo!!)
            return
        }
        root.addView(UiKit.sectionTitle(this, "Updates"))
        val card = UiKit.card(this)
        when (updateState) {
            UpdateState.IDLE ->
                card.addView(UiKit.muted(this, "Updates come from the app's release page. Each one is checked against this app's signing key before anything installs."))
            UpdateState.CHECKING ->
                card.addView(UiKit.body(this, "Checking for updates…"))
            UpdateState.UP_TO_DATE ->
                card.addView(UiKit.body(this, "This app is up to date."))
            UpdateState.FAILED ->
                card.addView(UiKit.body(this, updateMessage))
            UpdateState.WORKING ->
                card.addView(UiKit.body(this, updateMessage))
            UpdateState.AVAILABLE -> {}
        }
        card.addView(
            UiKit.navRow(
                this, "Check for updates",
                when (updateState) {
                    UpdateState.UP_TO_DATE -> "You have ${appVersionName()} — the latest."
                    else -> "You have ${appVersionName()}."
                }
            ) { checkForUpdates() }
        )
        root.addView(card)
    }

    /** The update-ready screen (design image 21), as a home card. */
    private fun renderUpdateReady(info: UpdateChecker.UpdateInfo) {
        root.addView(UiKit.sectionTitle(this, "Update"))
        val card = UiKit.card(this)
        val tileRow = LinearLayout(this).apply { gravity = Gravity.CENTER_HORIZONTAL }
        tileRow.addView(TextView(this).apply {
            text = "⬇"
            textSize = 26f
            setTextColor(UiKit.TEXT)
            gravity = Gravity.CENTER
            background = GradientDrawable().apply {
                cornerRadius = UiKit.dp(this@MainActivity, 14).toFloat()
                setColor(UiKit.SUBTLE)
            }
            layoutParams = LinearLayout.LayoutParams(UiKit.dp(this@MainActivity, 56), UiKit.dp(this@MainActivity, 56))
        })
        card.addView(tileRow)
        card.addView(TextView(this).apply {
            text = "Version ${info.versionName} is ready"
            textSize = 19f
            typeface = Fonts.medium(this@MainActivity)
            setTextColor(UiKit.TEXT)
            gravity = Gravity.CENTER
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply { setMargins(0, UiKit.dp(this@MainActivity, 12), 0, UiKit.dp(this@MainActivity, 4)) }
        })
        card.addView(TextView(this).apply {
            text = "You have ${appVersionName()} · ${formatSize(info.sizeBytes)}"
            textSize = 14f
            typeface = Fonts.regular(this@MainActivity)
            setTextColor(UiKit.SECONDARY)
            gravity = Gravity.CENTER
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply { setMargins(0, 0, 0, UiKit.dp(this@MainActivity, 14)) }
        })
        if (info.notes.isNotBlank()) {
            val notesCard = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                background = GradientDrawable().apply {
                    cornerRadius = UiKit.dp(this@MainActivity, 12).toFloat()
                    setColor(UiKit.SUBTLE)
                }
                setPadding(
                    UiKit.dp(this@MainActivity, 16), UiKit.dp(this@MainActivity, 14),
                    UiKit.dp(this@MainActivity, 16), UiKit.dp(this@MainActivity, 14)
                )
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
                ).apply { setMargins(0, 0, 0, UiKit.dp(this@MainActivity, 14)) }
            }
            notesCard.addView(TextView(this).apply {
                text = "WHAT'S NEW"
                textSize = 12f
                typeface = Fonts.medium(this@MainActivity)
                setTextColor(UiKit.SECONDARY)
            })
            notesCard.addView(TextView(this).apply {
                text = info.notes
                textSize = 14f
                typeface = Fonts.regular(this@MainActivity)
                setTextColor(UiKit.TEXT)
                setLineSpacing(0f, 1.3f)
                setPadding(0, UiKit.dp(this@MainActivity, 6), 0, 0)
            })
            card.addView(notesCard)
        }
        card.addView(UiKit.primaryButton(this, "Update") { downloadAndInstall(info) })
        card.addView(UiKit.outlineButton(this, "Later") {
            updateState = UpdateState.IDLE
            updateInfo = null
            refresh()
        })
        card.addView(TextView(this).apply {
            text = "🛡  Updates are signed. Your settings and pairing are kept."
            textSize = 13f
            typeface = Fonts.regular(this@MainActivity)
            setTextColor(UiKit.SECONDARY)
            gravity = Gravity.CENTER
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply { setMargins(0, UiKit.dp(this@MainActivity, 6), 0, 0) }
        })
        root.addView(card)
    }

    private fun checkForUpdates() {
        if (updateState == UpdateState.CHECKING || updateState == UpdateState.WORKING) return
        updateState = UpdateState.CHECKING
        refresh()
        val checker = UpdateChecker(this)
        Thread {
            val result = checker.check()
            runOnUiThread {
                when (result) {
                    is UpdateChecker.CheckResult.Available -> {
                        updateInfo = result.info
                        updateState = UpdateState.AVAILABLE
                    }
                    UpdateChecker.CheckResult.UpToDate -> {
                        updateInfo = null
                        updateState = UpdateState.UP_TO_DATE
                    }
                    is UpdateChecker.CheckResult.Failed -> {
                        updateInfo = null
                        updateMessage = result.reason
                        updateState = UpdateState.FAILED
                    }
                }
                refresh()
            }
        }.start()
    }

    private fun downloadAndInstall(info: UpdateChecker.UpdateInfo) {
        updateState = UpdateState.WORKING
        updateMessage = "Downloading version ${info.versionName}…"
        refresh()
        val checker = UpdateChecker(this)
        Thread {
            var error: String? = null
            val file = checker.download(info) { message -> error = message }
            runOnUiThread {
                when {
                    file != null -> launchInstaller(file)
                    else -> {
                        updateMessage = error ?: "The download failed."
                        updateState = UpdateState.FAILED
                        refresh()
                    }
                }
            }
        }.start()
    }

    private fun launchInstaller(file: File) {
        try {
            // FileProvider URI (0.4.0): the APK stays in the app's
            // private cache; the installer gets a read-only grant.
            val uri = FileProvider.getUriForFile(this, "io.agenticcontrol.app.files", file)
            val intent = Intent(Intent.ACTION_VIEW).apply {
                setDataAndType(uri, "application/vnd.android.package-archive")
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            startActivity(intent)
            updateMessage = "The installer is open. Tap Update there to finish."
            updateState = UpdateState.WORKING
        } catch (e: ActivityNotFoundException) {
            updateMessage = "No installer is available on this phone."
            updateState = UpdateState.FAILED
        } catch (e: Exception) {
            updateMessage = "The installer could not be opened: ${e.message}"
            updateState = UpdateState.FAILED
        }
        refresh()
    }

    private fun formatSize(bytes: Long): String = when {
        bytes < 1024 -> "$bytes B"
        bytes < 1024 * 1024 -> "${bytes / 1024} KB"
        else -> String.format(Locale.US, "%.1f MB", bytes / (1024.0 * 1024.0))
    }

    // ---------- pairing ----------

    private fun beginPairing() {
        val store = ControlService.sharedPairingStore
        if (store == null) {
            toast("The control channel is still starting — one moment.")
            return
        }
        // bd-and-rest F8 fix: no reachable remote address, no code —
        // a prompt built on loopback or an unbound LAN address
        // fails for a reason the user cannot see.
        if (SetupChecks.reachableRemoteAddress() == null) {
            toast("Tailscale is not up on this phone — an AI on another device could not reach it. Start Tailscale, then make the code.")
            return
        }
        // W14 R-10 (W10-B named remainder 2): aligned with the
        // wizard flow — there is NO owner-typed agent name on this
        // path either. Pairing begins NAMELESS; the pairing's name
        // is the agent's own clientInfo name, bound at pair time by
        // McpCore (PairingStore.bindAgentInfo). The legacy
        // WizardActivity.KEY_AGENT_NAME preference is no longer
        // read here as a pairing name; the constant itself is
        // preserved in WizardActivity exactly as W10-B left it.
        // W98 / S09(b): the mint surface's connection choice is
        // bound to the code; an invalid choice refuses the mint
        // (the store throws) rather than widening to AUTO.
        pairingCode = try {
            store.beginPairing("", mintConnection)
        } catch (e: IllegalArgumentException) {
            toast(e.message ?: "That connection choice can't be used.")
            return
        }
        currentPrompt = buildHandoffPrompt(pairingCode!!)
        toast("Code created. It works once and expires in 10 minutes.")
        refresh()
    }

    private fun copyPrompt() {
        if (currentPrompt.isBlank()) {
            toast("Tap Make a pairing code first — the prompt is written for that code.")
            return
        }
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText("DeskGuest pairing prompt", currentPrompt))
        toast("Copied. Paste it into your AI's app, then come back here.")
    }

    /** The copy-paste handoff prompt (SPEC §5.0): the app writes the words. */
    private fun buildHandoffPrompt(code: String): String {
        val endpoint = "http://${SetupChecks.endpointAddress(this)}:${McpHttpServer.PORT}/mcp"
        return """
            I just installed the DeskGuest app on my phone. It lets you — my AI — see and (with my permission, step by step) operate my phone, and it enforces my consent rules itself.

            Please connect to it now:
            1. Send an MCP initialize request (JSON-RPC) to $endpoint
            2. Then call the "pair" method with this one-time code: $code
               It will return a bearer token — keep it private and use it as the Authorization header for every later request.
            3. Confirm the connection by calling the device_info tool and telling me what phone you see.

            The code works once and expires in 10 minutes. When you're connected, I'll come back to the app — it will notice on its own. If anything fails, tell me in plain words what happened and what I should do next.
        """.trimIndent()
    }

    // ---------- later-stage sections (filled in by their stages) ----------

    /** C19: the boot-restart setting, with its real limits stated
     *  on the surface — Android delivers the boot broadcast only
     *  after the first unlock, a force-stopped app gets no
     *  broadcast at all, and some phones' battery managers can
     *  still block the restart; when that happens the attempt is
     *  recorded in Diagnostics below instead of being hidden. */
    private fun renderBootRestartSection(column: LinearLayout) {
        column.addView(UiKit.sectionTitle(this, "After a reboot"))
        val card = UiKit.card(this)
        val enabled = io.agenticcontrol.app.server.BootRestartSettings.isEnabled(this)
        card.addView(
            UiKit.body(
                this,
                "Restart the control channel after reboot: " + if (enabled) "On" else "Off"
            )
        )
        card.addView(
            UiKit.muted(
                this,
                "When this is on, the app restarts its control channel by itself after " +
                    "the phone reboots and you unlock it — no need to open the app first. " +
                    "Some phones can still block an automatic restart (for example after " +
                    "a force-stop, or under strict battery saving); if that happens, the " +
                    "attempt is recorded in the Diagnostics line at the bottom of this " +
                    "screen, and opening the app starts the channel as usual."
            )
        )
        card.addView(
            UiKit.outlineButton(this, if (enabled) "Turn off restart after reboot" else "Turn on restart after reboot") {
                io.agenticcontrol.app.server.BootRestartSettings.setEnabled(this, !enabled)
                refresh()
            }
        )
        column.addView(card)
    }

    // ---------- C20 recovery blob (owner-local) ----------
    // Export/restore are owner acts on this screen only — no MCP
    // tool reaches them. The key sheet is held in memory just long
    // enough for the owner to write it down; "hide" (or leaving the
    // screen's state) drops it, and it is never written to disk,
    // the audit log, or any export other than the blob itself.

    private var recoverySheet: String? = null
    private var pendingRestorePassphrase: String? = null
    private var pendingRestoreKeySheet: String? = null

    private fun renderRecoverySection(column: LinearLayout) {
        val stores = io.agenticcontrol.app.wiring.PlatformRuntime.get(this)
        // The audit hook is the owner's encrypted log on this phone;
        // fixed outcome strings only (see PlatformStores).
        stores.recoveryAudit = { kind, ok, detail ->
            ControlService.sharedAuditStore?.record("recovery", kind, "owner", ok, detail)
        }
        // bd-and-rest F5 wiring: RMM service audits (Backup / Deploy
        // / MobileOperator / VendorPass / CameraView) forward into
        // this same exportable log via the SharedAuditBridge.
        stores.rmmAuditSink = { kind, detail ->
            ControlService.sharedAuditStore?.record("rmm", kind, "platform", true, detail)
        }
        column.addView(UiKit.sectionTitle(this, "Recovery"))
        val card = UiKit.card(this)
        card.addView(
            UiKit.body(
                this,
                "Export one encrypted file holding this device's identity and stores — you keep it where you choose; there is no cloud copy. " +
                    "Restore lands only into empty stores: a live identity or any existing content refuses, and nothing is overwritten."
            )
        )
        stores.lastRecoveryRestore?.let { rec ->
            val whenText = SimpleDateFormat("d MMM yyyy, HH:mm", Locale.US).format(Date(rec.atMs))
            card.addView(UiKit.body(this, "Recovery was restored on this device ($whenText). Device: ${rec.deviceId.take(12)}…"))
        }
        val sheet = recoverySheet
        if (sheet != null) {
            card.addView(UiKit.body(this, "RECOVERY KEY SHEET — shown once, never stored. Write these 34 words down and keep them with the blob:"))
            card.addView(TextView(this).apply {
                text = sheet
                textSize = 14f
                typeface = Fonts.mono(this@MainActivity)
                setTextColor(UiKit.TEXT)
            })
            card.addView(UiKit.outlineButton(this, "I've written it down — hide the sheet") {
                recoverySheet = null
                refresh()
            })
        }
        fun recoveryField(hint: String): EditText = EditText(this).apply {
            this.hint = hint
            isSingleLine = true
            textSize = 16f
            typeface = Fonts.regular(this@MainActivity)
            setTextColor(UiKit.TEXT)
            setHintTextColor(UiKit.SECONDARY)
            background = null
        }
        val exportPass = recoveryField("Export passphrase (10+ characters)")
        card.addView(exportPass)
        card.addView(UiKit.primaryButton(this, "Export recovery blob") {
            val passphrase = exportPass.text.toString()
            Thread {
                try {
                    val result = stores.exportRecoveryBlob(passphrase)
                    val dir = File(cacheDir, "exports").apply { mkdirs() }
                    val file = File(dir, "acp-recovery.acprecovery")
                    file.writeBytes(result.primaryBlob)
                    runOnUiThread {
                        recoverySheet = result.keySheet
                        try {
                            val uri = FileProvider.getUriForFile(this, "io.agenticcontrol.app.files", file)
                            val intent = Intent(Intent.ACTION_SEND).apply {
                                type = "application/octet-stream"
                                putExtra(Intent.EXTRA_STREAM, uri)
                                putExtra(Intent.EXTRA_SUBJECT, "DeskGuest recovery blob")
                                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                            }
                            startActivity(Intent.createChooser(intent, "Save the recovery blob"))
                        } catch (e: Exception) {
                            toast("Export failed: ${e.message}")
                        }
                        refresh()
                    }
                } catch (e: Exception) {
                    runOnUiThread { toast("Export refused: ${e.message}") }
                }
            }.start()
        })
        val restorePass = recoveryField("Blob passphrase (or use the key sheet below)")
        val restoreSheet = recoveryField("Recovery key sheet (34 words)")
        card.addView(restorePass)
        card.addView(restoreSheet)
        card.addView(UiKit.outlineButton(this, "Pick a recovery blob and restore") {
            pendingRestorePassphrase = restorePass.text.toString().takeIf { it.isNotEmpty() }
            pendingRestoreKeySheet = restoreSheet.text.toString().trim().takeIf { it.isNotEmpty() }
            val pick = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                addCategory(Intent.CATEGORY_OPENABLE)
                type = "*/*"
            }
            try {
                startActivityForResult(pick, REQ_RECOVERY_PICK)
            } catch (e: Exception) {
                toast("No file picker is available: ${e.message}")
            }
        })
        column.addView(card)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != REQ_RECOVERY_PICK || resultCode != RESULT_OK) return
        val uri = data?.data ?: return
        val passphrase = pendingRestorePassphrase
        val keySheet = pendingRestoreKeySheet
        pendingRestorePassphrase = null
        pendingRestoreKeySheet = null
        Thread {
            try {
                val blob = contentResolver.openInputStream(uri)?.use { it.readBytes() }
                    ?: throw IllegalStateException("the picked file could not be read")
                val stores = io.agenticcontrol.app.wiring.PlatformRuntime.get(this)
                val info = stores.inspectRecoveryBlob(blob)
                if (info.kind != io.agenticcontrol.app.recovery.RecoveryBlob.KIND_PRIMARY) {
                    throw IllegalStateException(
                        "this is a sealed contact copy for '${info.contactName}' — it also needs that contact's key, presented in person; the primary blob restores here"
                    )
                }
                val payload = stores.restoreRecoveryBlobPrimary(blob, passphrase, keySheet)
                runOnUiThread {
                    toast("Recovery restored — device ${payload.deviceId.take(12)}… is now this device's identity.")
                    refresh()
                }
            } catch (e: Exception) {
                runOnUiThread { toast("Restore refused: ${e.message}") }
            }
        }.start()
    }

    /** Slices 1–3, wired live (0.4.6): device identity + enrollment,
     *  the roster (scopes, groups, grants, offboarding), and human
     *  sessions — each its own screen, all driven by the real stores
     *  behind wiring/PlatformRuntime. */
    private fun renderPlatformSection(column: LinearLayout) {
        column.addView(UiKit.sectionTitle(this, "Devices, people & sessions"))
        column.addView(UiKit.navRow(
            this,
            "This device",
            "Identity, enrollment, receipts, and who may operate this device"
        ) {
            startActivity(Intent(this, EndpointActivity::class.java))
        })
        column.addView(UiKit.navRow(
            this,
            "People & groups",
            "Scopes, users, groups, grants, and removing a user"
        ) {
            startActivity(Intent(this, RosterActivity::class.java))
        })
        column.addView(UiKit.navRow(
            this,
            "Sessions",
            "Remote sessions on this device — accept here, STOP always works"
        ) {
            startActivity(Intent(this, SessionsActivity::class.java))
        })
    }

    private fun renderAuditSection(column: LinearLayout) {
        column.addView(UiKit.sectionTitle(this, "Audit log"))
        val card = UiKit.card(this)
        card.addView(
            UiKit.body(
                this,
                "Every tool call and session event is written to an encrypted log on this " +
                    "phone. Nothing reads it over the connection — exporting it is yours alone."
            )
        )
        val store = ControlService.sharedAuditStore
        card.addView(
            UiKit.muted(
                this,
                if (store == null) {
                    "The log starts with the control channel."
                } else {
                    "${store.count()} record(s) so far. Passwords, pairing codes, and typed " +
                        "text are never written — lengths and outcomes only."
                }
            )
        )
        if (store != null) {
            card.addView(UiKit.outlineButton(this, "Export audit log") { exportAudit(store) })
        }
        column.addView(card)
        column.addView(UiKit.navRow(
            this,
            "Session replay",
            "The recorded session-event timeline, in this process's memory"
        ) {
            startActivity(Intent(this, ReplayActivity::class.java))
        })
    }

    private fun exportAudit(store: io.agenticcontrol.app.server.AuditStore) {
        Thread {
            val export = store.export()
            val dir = File(cacheDir, "exports").apply { mkdirs() }
            val file = File(dir, "audit-log.jsonl")
            try {
                file.writeText(export.text)
                runOnUiThread {
                    try {
                        val uri = FileProvider.getUriForFile(
                            this, "io.agenticcontrol.app.files", file
                        )
                        val intent = Intent(Intent.ACTION_SEND).apply {
                            type = "text/plain"
                            putExtra(Intent.EXTRA_STREAM, uri)
                            putExtra(
                                Intent.EXTRA_SUBJECT,
                                "DeskGuest audit log (${export.records} records)"
                            )
                            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                        }
                        startActivity(Intent.createChooser(intent, "Export audit log"))
                        if (export.unreadable > 0) {
                            toast("${export.unreadable} record(s) could not be decrypted and were left out.")
                        }
                    } catch (e: Exception) {
                        toast("Export failed: ${e.message}")
                    }
                }
            } catch (e: Exception) {
                runOnUiThread { toast("Export failed: ${e.message}") }
            }
        }.start()
    }

    private fun renderApprovalsSection(column: LinearLayout) {
        column.addView(UiKit.sectionTitle(this, "Approvals"))
        val card = UiKit.card(this)
        card.addView(
            UiKit.muted(
                this,
                "For each kind of action: run it, ask you first on the phone, or block it. " +
                    "Asking is enforced by this app — the AI cannot skip it, and a prompt left " +
                    "unanswered for 30 seconds counts as a no."
            )
        )
        io.agenticcontrol.app.server.ApprovalGate.ActionClass.values().forEach { actionClass ->
            card.addView(TextView(this).apply {
                text = actionClass.label
                textSize = 16f
                typeface = Fonts.medium(this@MainActivity)
                setTextColor(UiKit.TEXT)
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
                ).apply { setMargins(0, UiKit.dp(this@MainActivity, 10), 0, 0) }
            })
            card.addView(UiKit.muted(this, actionClass.blurb))
            val current = io.agenticcontrol.app.server.ApprovalSettings.load(this, actionClass)
            val row = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
                ).apply { setMargins(0, 0, 0, UiKit.dp(this@MainActivity, 8)) }
            }
            io.agenticcontrol.app.server.ApprovalGate.Policy.values().forEach { policy ->
                val selected = policy == current
                row.addView(Button(this).apply {
                    text = policy.label
                    isAllCaps = false
                    textSize = 13.5f
                    typeface = Fonts.medium(this@MainActivity)
                    setTextColor(if (selected) Color.WHITE else UiKit.TEXT)
                    stateListAnimator = null
                    background = GradientDrawable().apply {
                        cornerRadius = UiKit.dp(this@MainActivity, 100).toFloat()
                        setColor(if (selected) UiKit.INK else UiKit.SUBTLE)
                        if (!selected) setStroke(UiKit.dp(this@MainActivity, 1), UiKit.HAIRLINE)
                    }
                    setPadding(
                        UiKit.dp(this@MainActivity, 14), UiKit.dp(this@MainActivity, 8),
                        UiKit.dp(this@MainActivity, 14), UiKit.dp(this@MainActivity, 8)
                    )
                    layoutParams = LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT
                    ).apply { setMargins(0, 0, UiKit.dp(this@MainActivity, 8), 0) }
                    setOnClickListener {
                        io.agenticcontrol.app.server.ApprovalSettings.save(
                            this@MainActivity, actionClass, policy
                        )
                        refresh()
                    }
                })
            }
            card.addView(row)
        }
        card.addView(UiKit.muted(this, UiKit.ALWAYS_ON_LINE))
        column.addView(card)
    }

    private fun renderShellSection(column: LinearLayout) {
        val endpoint = ShellStore.endpoint(this)
        val paired = ShellStore.identityPaired(this)
        column.addView(UiKit.sectionTitle(this, "Shell channel"))
        column.addView(UiKit.body(
            this,
            "The app can pair with this phone's own wireless debugging and run shell " +
                "commands through it — no computer involved. Pair once: turn on Wireless " +
                "debugging in Developer options, open \"Pair device with pairing code\" " +
                "there, then enter the code below."
        ))
        when {
            paired && endpoint != null -> column.addView(
                UiKit.reportRow(this, true, "Shell channel", "Paired — ${endpoint.host}:${endpoint.port}")
            )
            paired -> column.addView(
                UiKit.reportRow(this, true, "Shell channel", "Key paired — pick the connect endpoint below")
            )
            else -> column.addView(
                UiKit.reportRow(this, false, "Shell channel", "Not paired yet")
            )
        }

        column.addView(UiKit.primaryButton(this, "Find debugging services") {
            findShellServices()
        })
        for (service in discovered) {
            val isPairing = service.kind == AdbDiscovery.SERVICE_PAIRING
            column.addView(UiKit.navRow(
                this,
                if (isPairing) "Pairing service — ${service.host}:${service.port}"
                else "Connect service — ${service.host}:${service.port}",
                service.name
            ) {
                if (isPairing) {
                    shellHostField?.setText(service.host)
                    shellPortField?.setText(service.port.toString())
                    toast("Pairing address filled in")
                } else {
                    ShellStore.save(this, ShellStore.Endpoint(service.host, service.port, tls = true))
                    toast("Connect endpoint saved")
                    refresh()
                }
            })
        }

        fun shellField(hint: String): EditText = EditText(this).apply {
            this.hint = hint
            isSingleLine = true
            textSize = 16f
            typeface = Fonts.regular(this@MainActivity)
            setTextColor(UiKit.TEXT)
            setHintTextColor(UiKit.SECONDARY)
            background = null
        }
        val hostField = shellField("Pairing address (e.g. 192.168.1.20)")
        val portField = shellField("Pairing port")
        val codeField = shellField("6-digit pairing code")
        shellHostField = hostField
        shellPortField = portField
        column.addView(hostField)
        column.addView(portField)
        column.addView(codeField)
        column.addView(UiKit.primaryButton(this, "Pair") {
            val host = hostField.text.toString().trim()
            val port = portField.text.toString().trim().toIntOrNull()
            val code = codeField.text.toString().trim()
            if (host.isEmpty() || port == null || code.length != 6) {
                toast("Enter the pairing address, port, and 6-digit code")
                return@primaryButton
            }
            toast("Pairing…")
            Thread {
                val result = try {
                    val identity = AndroidAdbIdentity.getOrCreate()
                    AdbPairing.pair(host, port, code, identity)
                } catch (e: Exception) {
                    AdbPairing.Result(false, "Pairing failed: ${e.message}")
                }
                runOnUiThread {
                    if (result.success) ShellStore.markPaired(this, true)
                    toast(result.message)
                    refresh()
                }
            }.start()
        })
        if (paired || endpoint != null) {
            column.addView(UiKit.outlineButton(this, "Forget shell pairing") {
                ShellStore.clear(this)
                discovered.clear()
                refresh()
            })
        }
    }

    private fun findShellServices() {
        val disc = discovery ?: AdbDiscovery(this).also { discovery = it }
        discovered.clear()
        toast("Searching the local network…")
        val onFound: (AdbDiscovery.Service) -> Unit = { service ->
            runOnUiThread {
                if (discovered.none { it.kind == service.kind && it.port == service.port }) {
                    discovered.add(service)
                    refresh()
                }
            }
        }
        val onError: (String) -> Unit = { message ->
            runOnUiThread { toast(message) }
        }
        disc.start(AdbDiscovery.SERVICE_PAIRING, onFound, onError)
        disc.start(AdbDiscovery.SERVICE_CONNECT, onFound, onError)
    }

    private fun renderDevicesSection(column: LinearLayout) {
        column.addView(UiKit.sectionTitle(this, "Devices"))
        val base = io.agenticcontrol.app.mesh.MeshStore.baseUrl(this)
        column.addView(UiKit.navRow(
            this,
            "Windows 11",
            base ?: "Not set up — the companion is not installed yet"
        ) {
            startActivity(Intent(this, WindowsDeviceActivity::class.java))
        })
    }

    // ---------- helpers ----------

    private fun appVersionName(): String =
        try {
            packageManager.getPackageInfo(packageName, 0).versionName ?: "?"
        } catch (e: Exception) {
            "?"
        }


    /** The name to show for a pairing: the AI's own clientInfo
     *  name when it gave one (never an owner-typed name — W14
     *  R-10, aligned with WizardActivity.displayName); the stored
     *  pairing name is the legacy fallback for pairings created
     *  before that rule. FR-123: when neither exists the label is
     *  the truthful unnamed-pairing label through the U8 strings
     *  door — never the generic fabricated name "Your AI". */
    private fun displayName(pairing: PairingStore.Pairing): String =
        pairing.agentName.ifBlank { pairing.name }
            .ifBlank { consentString(R.string.pairing_unnamed_label) }

    private fun toast(text: String) =
        Toast.makeText(this, text, Toast.LENGTH_LONG).show()

    companion object {
        /** C20 wiring: the recovery-blob file-pick request code. */
        const val REQ_RECOVERY_PICK = 4210
    }
}
