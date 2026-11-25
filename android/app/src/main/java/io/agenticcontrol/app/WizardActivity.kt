package io.agenticcontrol.app

import android.Manifest
import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import io.agenticcontrol.app.server.ControlService
import io.agenticcontrol.app.server.McpHttpServer
import io.agenticcontrol.app.server.PairingStore
import io.agenticcontrol.app.strings.consentString
import io.agenticcontrol.app.ui.Fonts
import io.agenticcontrol.app.ui.LogoView
import io.agenticcontrol.app.ui.UiKit

/**
 * The first-run wizard (SPEC §5.0/§5.1 + design record §4 A2).
 * W8 item 3: SEVEN labelled steps, one per screen, rendered from
 * SetupWizardModel.STEPS — role → transport → battery →
 * accessibility → pair → access level → self-check — each headed
 * "Step N of 7" with labelled segments (never unlabelled dots).
 * The mechanics are the ones the earlier wizard proved: the
 * channel starts here, grants are deep-linked and re-read on
 * return, the pairing code is one-time and expiring with a live
 * countdown, and access is chosen per AI. Role (OI-02) chooses
 * the starting view only; it creates nothing.
 */
class WizardActivity : Activity() {

    private enum class Step(val modelIndex: Int) {
        ROLE(0), TRANSPORT(1), BATTERY(2), ACCESSIBILITY(3),
        PAIR(4), ACCESS(5), SELFCHECK(6)
    }

    private var step = Step.ROLE
    private lateinit var root: LinearLayout
    private var pairingCode: String? = null
    /** W98 / S09(b): the mint-time connection-path choice on the
     *  pair step (default AUTO), bound to the code when it is made. */
    private var mintConnection: io.agenticcontrol.app.server.ConnectionPath.Setting =
        io.agenticcontrol.app.server.ConnectionPath.Setting.AUTO
    private var handoffPrompt: String = ""
    private var transportSel: String? = null
    private var expiryView: TextView? = null
    private val ticker = Handler(Looper.getMainLooper())
    private val tick = object : Runnable {
        override fun run() {
            updateExpiry()
            ticker.postDelayed(this, 1000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        root = UiKit.page(this)
        transportSel = SetupChecks.transportChoice(this)
        // 0.4.2: the failure report is checked here too, not only in
        // MainActivity — reopening the app can restore this wizard
        // directly, and a saved report must never be unreachable
        // behind the screen that failed.
        val crash = CrashTrap.read(this)
        if (crash != null) {
            showCrash(crash)
            return
        }
        render()
    }

    /** The failure-report screen, wizard edition (0.4.2): what was
     *  recorded, and the way through to a fresh wizard. */
    private fun showCrash(report: String) {
        root.addView(UiKit.sectionTitle(this, "Something went wrong"))
        root.addView(
            UiKit.body(
                this,
                "DeskGuest hit a failure and recorded this report. " +
                    "Screenshot it for the developer, then continue — the " +
                    "wizard starts fresh from here."
            )
        )
        root.addView(TextView(this).apply {
            text = report
            textSize = 11f
            typeface = Fonts.mono(this@WizardActivity)
            setTextColor(UiKit.TEXT)
        })
        root.addView(UiKit.primaryButton(this, "Clear report and continue") {
            CrashTrap.clear(this@WizardActivity)
            render()
        })
    }

    override fun onResume() {
        super.onResume()
        // Grants are checked, not remembered: returning from a Settings
        // page re-renders the current step with fresh facts.
        if (::root.isInitialized) render()
        ticker.removeCallbacks(tick)
        ticker.post(tick)
    }

    override fun onPause() {
        super.onPause()
        ticker.removeCallbacks(tick)
    }

    // ---------- step screens ----------

    private fun render() {
        // Guarded (0.4.2): a failure inside any step is recorded and
        // shown HERE, on this screen — never a silent death the owner
        // can only describe as "it crashed when I tapped".
        try {
            root.removeAllViews()
            expiryView = null
            when (step) {
                Step.ROLE -> renderRole()
                Step.TRANSPORT -> renderTransport()
                Step.BATTERY -> renderBattery()
                Step.ACCESSIBILITY -> renderAccessibility()
                Step.PAIR -> renderPairing()
                Step.ACCESS -> renderAccess()
                Step.SELFCHECK -> renderSelfCheck()
            }
        } catch (t: Throwable) {
            CrashTrap.record(this, "wizard render step $step", t)
            showRenderFailure(t)
        }
    }

    /** Last-resort step screen: the failure, in the open, with a way
     *  back to the welcome step. Built only from the primitives the
     *  welcome step itself uses. */
    private fun showRenderFailure(t: Throwable) {
        try {
            root.removeAllViews()
            root.addView(UiKit.headline(this, "Something went wrong"))
            root.addView(
                UiKit.body(
                    this,
                    "This step failed to load, and the failure was recorded. " +
                        "Screenshot this screen for the developer."
                )
            )
            root.addView(TextView(this).apply {
                text = "${t.javaClass.name}: ${t.message}"
                textSize = 12f
                typeface = Fonts.mono(this@WizardActivity)
                setTextColor(UiKit.TEXT)
            })
            root.addView(UiKit.primaryButton(this, "Back to the start") {
                step = Step.ROLE
                render()
            })
        } catch (_: Throwable) {
            // Nowhere left to render to; the record above still stands.
        }
    }

    /** W8 item 3 (§4 A2): the labelled progress header — "Step N
     *  of 7" plus one LABELLED segment per step (the step's own
     *  name under its segment), never unlabelled dots. */
    private fun progressBar(active: Int) {
        root.addView(
            UiKit.muted(
                this,
                io.agenticcontrol.app.design.SetupWizardModel.stepLabel(active)
            )
        )
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply { setMargins(0, 0, 0, UiKit.dp(this@WizardActivity, 18)) }
        }
        for (i in 0 until io.agenticcontrol.app.design.SetupWizardModel.STEP_COUNT) {
            val column = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
                    .apply {
                        if (i < io.agenticcontrol.app.design.SetupWizardModel.STEP_COUNT - 1) {
                            setMargins(0, 0, UiKit.dp(this@WizardActivity, 6), 0)
                        }
                    }
            }
            column.addView(View(this).apply {
                background = android.graphics.drawable.GradientDrawable().apply {
                    cornerRadius = UiKit.dp(this@WizardActivity, 2).toFloat()
                    setColor(if (i <= active) UiKit.TEXT else UiKit.HAIRLINE)
                }
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, UiKit.dp(this@WizardActivity, 4)
                )
            })
            column.addView(TextView(this).apply {
                text = io.agenticcontrol.app.design.SetupWizardModel.STEPS[i]
                // §5 type floor: no text under 11 sp (W10, V3-F3d —
                // these labels were 9 sp).
                textSize = 11f
                typeface = Fonts.regular(this@WizardActivity)
                setTextColor(if (i == active) UiKit.TEXT else UiKit.SECONDARY)
            })
            row.addView(column)
        }
        root.addView(row)
    }

    /** Step 1 of 7 — role (OI-02): chooses the starting view
     *  only; it creates nothing. The welcome copy lives here. */
    private fun renderRole() {
        progressBar(0)
        val logoRow = LinearLayout(this).apply {
            gravity = Gravity.CENTER_HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply { setMargins(0, UiKit.dp(this@WizardActivity, 26), 0, UiKit.dp(this@WizardActivity, 22)) }
        }
        logoRow.addView(
            LogoView(this),
            LinearLayout.LayoutParams(UiKit.dp(this, 84), UiKit.dp(this, 84))
        )
        root.addView(logoRow)
        root.addView(UiKit.headline(this, "Give your AI hands — on your terms"))
        root.addView(
            UiKit.body(
                this,
                "DeskGuest lets an AI you choose see this phone's screen and, during a " +
                    "session, use it for you — tapping, typing, opening apps. You approve the " +
                    "connection here, you choose what it may do, and while it works you can " +
                    "see it the whole time: the Glow at the screen's edge, the Box naming " +
                    "the AI with a STOP button that ends the session at once, and the Ghost " +
                    "that shows where it is about to tap."
            )
        )
        root.addView(
            UiKit.body(
                this,
                // §1.5 vendor line, verbatim — "Nothing was sent"
                // in any form is banned copy (W10, V3-F9). The Box
                // IS the banner (fold table); it is not named as a
                // separate element.
                "Nowhere else — DeskGuest sends nothing to anyone. No account, no " +
                    "tracking, no cloud. The channel stays on your own network, and a " +
                    "notification says so while it is open."
            )
        )
        // Role choice (OI-02): starting view only, creates nothing.
        // Wording is the record's (§4 A2, W10/V3-F3e).
        val roleSel = getSharedPreferences(PREFS, MODE_PRIVATE).getString(KEY_ROLE, ROLE_PERSONAL)
        root.addView(UiKit.muted(this, "Who is this phone for?"))
        root.addView(
            UiKit.radioCard(
                this, "This is my phone",
                "Your own AI on your own phone. The home screen starts with your pairings.",
                roleSel == ROLE_PERSONAL
            ) { chooseRole(ROLE_PERSONAL) }
        )
        root.addView(
            UiKit.radioCard(
                this, "I'm setting this phone up for someone else",
                "This phone will be managed by an organisation, and its home screen starts with management and policy. Choosing this creates nothing — enrolment happens only through its own flow.",
                roleSel == ROLE_ORGANISATION
            ) { chooseRole(ROLE_ORGANISATION) }
        )
        root.addView(UiKit.primaryButton(this, "Get started") {
            Breadcrumb.mark(this, "step1_click_get_started")
            step = Step.TRANSPORT
            render()
        })
        root.addView(UiKit.muted(this, "No hidden background processes."))
        Breadcrumb.last(this)?.let { last ->
            root.addView(UiKit.muted(this, "Diagnostics — last run reached: $last"))
        }
    }

    private fun chooseRole(role: String) {
        getSharedPreferences(PREFS, MODE_PRIVATE).edit().putString(KEY_ROLE, role).apply()
        render()
    }

    /** Step 2 of 7 — transport: the route the AI will use (the
     *  endpoint in the pairing prompt depends on it). */
    private fun renderTransport() {
        progressBar(1)
        root.addView(UiKit.headline(this, "How will your AI reach this phone?"))
        root.addView(
            UiKit.radioCard(
                this, "Tailscale",
                "Works from anywhere, including mobile data. Needs the free Tailscale app on this phone and on your AI's device, signed in to the same account.",
                transportSel == SetupChecks.TRANSPORT_TAILSCALE
            ) { chooseTransport(SetupChecks.TRANSPORT_TAILSCALE) }
        )
        root.addView(
            UiKit.radioCard(
                this, "This Wi-Fi only",
                "Your AI is on this same network. The channel listens only on Tailscale and this phone itself — never the open Wi-Fi — so this choice reaches the phone at its Tailscale address on your own network.",
                transportSel == SetupChecks.TRANSPORT_WIFI
            ) { chooseTransport(SetupChecks.TRANSPORT_WIFI) }
        )
        root.addView(
            UiKit.radioCard(
                this, "My own tunnel",
                "You already run your own private network or tunnel, such as WireGuard. The app hands your AI this phone's Tailscale address; the route is yours.",
                transportSel == SetupChecks.TRANSPORT_TUNNEL
            ) { chooseTransport(SetupChecks.TRANSPORT_TUNNEL) }
        )
        root.addView(UiKit.primaryButton(this, "Continue") {
            step = Step.BATTERY
            render()
        })
    }

    /** Step 3 of 7 — battery / OEM survival. */
    private fun renderBattery() {
        progressBar(2)
        root.addView(UiKit.headline(this, "Keep the app alive"))
        root.addView(
            UiKit.muted(
                this,
                "Android and many phone makers close background apps to save battery — that would drop your AI's connection while the phone sleeps."
            )
        )
        ControlService.start(this)
        val battery = SetupChecks.batteryExempt(this)
        root.addView(
            permissionCard(
                title = "Battery — unrestricted",
                body = "Stops Android closing the app in the background, which would drop your AI's connection while the phone sleeps.",
                state = if (battery) PermState.GRANTED else PermState.MISSING,
                attentionNote = null,
                grantLabel = "Grant"
            ) {
                try {
                    startActivity(
                        Intent(
                            Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
                            Uri.parse("package:$packageName")
                        )
                    )
                } catch (e: ActivityNotFoundException) {
                    try {
                        startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
                    } catch (e2: ActivityNotFoundException) {
                        toast("That page did not open. Set it later in Settings, under Apps, DeskGuest, Battery.")
                    }
                }
            }
        )
        val continueButton = UiKit.primaryButton(this, "Continue") {
            step = Step.ACCESSIBILITY
            render()
        }
        UiKit.stylePrimary(this, continueButton, battery)
        root.addView(continueButton)
        if (!battery) {
            root.addView(UiKit.muted(this, "Continue unlocks when the battery grant is in."))
        }
    }

    /** Step 4 of 7 — accessibility (+ the on-screen signals and
     *  notifications the session presence needs). */
    private fun renderAccessibility() {
        Breadcrumb.mark(this, "step2_build_start")
        progressBar(3)
        root.addView(UiKit.headline(this, "Permissions"))
        root.addView(
            UiKit.muted(
                this,
                "Three grants, each checked by the app itself. Continue unlocks when all three are in."
            )
        )
        Breadcrumb.mark(this, "step2_service_start")
        ControlService.start(this)
        Breadcrumb.mark(this, "step2_service_started")

        Breadcrumb.mark(this, "check_accessibility_start")
        val a11yState = SetupChecks.accessibilityState(this)
        Breadcrumb.mark(this, "check_accessibility_end")
        root.addView(
            permissionCard(
                title = "Accessibility service",
                body = "Lets the app read the screen and, during a session, tap and type. " +
                    "The same system feature screen readers use.",
                state = when (a11yState) {
                    SetupChecks.AccessibilityState.BOUND -> PermState.GRANTED
                    SetupChecks.AccessibilityState.BINDING_STALE -> PermState.ATTENTION
                    SetupChecks.AccessibilityState.DISABLED -> PermState.MISSING
                },
                attentionNote = if (a11yState == SetupChecks.AccessibilityState.BINDING_STALE) {
                    "Android shows this as on, but the connection dropped. Open Accessibility " +
                        "settings, turn DeskGuest off, then on again — the app will notice."
                } else {
                    null
                },
                grantLabel = "Grant"
            ) {
                openSettings(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS))
            }
        )
        if (a11yState != SetupChecks.AccessibilityState.BOUND) {
            root.addView(
                UiKit.muted(
                    this,
                    "In Accessibility settings, find DeskGuest under Installed apps. " +
                        "Because this app was installed from a file, Android may block the switch: " +
                        "if it does, open App info for DeskGuest, tap the menu (⋮) at the top " +
                        "right, choose Allow restricted settings, then come back here."
                )
            )
        }

        Breadcrumb.mark(this, "check_overlay_start")
        val overlay = SetupChecks.overlayOn(this)
        Breadcrumb.mark(this, "check_overlay_end")
        root.addView(
            permissionCard(
                title = "Display over other apps",
                body = "Draws the session signs over the screen: the Glow, the Box, and the STOP button.",
                state = if (overlay) PermState.GRANTED else PermState.MISSING,
                attentionNote = null,
                grantLabel = "Grant"
            ) {
                openSettings(
                    Intent(
                        Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                        Uri.parse("package:$packageName")
                    )
                )
            }
        )

        Breadcrumb.mark(this, "check_notifications_start")
        val notifications = SetupChecks.notificationsOn(this)
        Breadcrumb.mark(this, "check_notifications_end")
        root.addView(
            permissionCard(
                title = "Notifications",
                body = "The persistent notice while the channel is open, and alerts when an AI connects or needs approval.",
                state = if (notifications) PermState.GRANTED else PermState.MISSING,
                attentionNote = null,
                grantLabel = "Grant"
            ) {
                if (Build.VERSION.SDK_INT >= 33) {
                    requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 7)
                } else {
                    val intent = Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS)
                        .putExtra(Settings.EXTRA_APP_PACKAGE, packageName)
                    startActivity(intent)
                }
            }
        )

        val allGranted = a11yState == SetupChecks.AccessibilityState.BOUND &&
            overlay && notifications
        val channelCard = UiKit.card(this)
        val running = ControlService.sharedServer?.isRunning == true
        channelCard.addView(
            UiKit.body(
                this,
                if (running) {
                    "The control channel is open on port ${McpHttpServer.PORT}."
                } else {
                    "The control channel is starting…"
                }
            )
        )
        root.addView(channelCard)
        val continueButton = UiKit.primaryButton(this, "Continue") {
            step = Step.PAIR
            render()
        }
        UiKit.stylePrimary(this, continueButton, allGranted)
        root.addView(continueButton)
        if (!allGranted) {
            root.addView(
                UiKit.muted(
                    this,
                    "Continue unlocks when all three grants are in. Each one is checked live — " +
                        "grant it, come back, and the card turns to Granted on its own."
                )
            )
        }
        Breadcrumb.mark(this, "step2_attach_views_end")
    }

    private enum class PermState { GRANTED, MISSING, ATTENTION }

    /** One permission card: title, plain-words body, and either
     *  the Granted chip or a Grant button. W10 (V3-F8): the state
     *  chips are NEUTRAL — green and amber are presence hues
     *  (§1.1) and are never spent as health/status colours
     *  outside the Box, Ghost and Glow; the state is carried by
     *  the word on the chip. */
    private fun permissionCard(
        title: String,
        body: String,
        state: PermState,
        attentionNote: String?,
        grantLabel: String,
        onGrant: () -> Unit
    ): LinearLayout {
        val card = UiKit.card(this)
        val head = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        head.addView(TextView(this).apply {
            text = title
            textSize = 16f
            typeface = Fonts.medium(this@WizardActivity)
            setTextColor(UiKit.TEXT)
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        })
        when (state) {
            PermState.GRANTED -> head.addView(
                UiKit.chip(this, "✓ Granted", UiKit.ChipKind.NEUTRAL)
            )
            PermState.ATTENTION -> head.addView(
                UiKit.chip(this, "Needs attention", UiKit.ChipKind.NEUTRAL)
            )
            PermState.MISSING -> {}
        }
        card.addView(head)
        card.addView(UiKit.muted(this, body))
        if (attentionNote != null) {
            card.addView(UiKit.body(this, attentionNote))
        }
        if (state != PermState.GRANTED) {
            card.addView(UiKit.outlineButton(this, grantLabel) { onGrant() })
        }
        return card
    }

    /** W98 / S09(b): make a pairing code with the mint step's
     *  connection choice bound. An invalid choice refuses the mint
     *  (the store throws) rather than widening to AUTO — the toast
     *  names the refusal and no code is made. */
    private fun beginWizardPairing(
        store: io.agenticcontrol.app.server.PairingStore
    ): String? = try {
        store.beginPairing("", mintConnection)
    } catch (e: IllegalArgumentException) {
        toast(e.message ?: "That connection choice can't be used.")
        null
    }

    /** W98 / S09(b): the live current-path label (same discipline
     *  as the home pairing card: in-memory last arrival only). */
    private fun currentPathLine(
        store: io.agenticcontrol.app.server.PairingStore,
        pairing: io.agenticcontrol.app.server.PairingStore.Pairing
    ): String {
        val last = store.lastConnection(pairing.token)
            ?: return "Hasn't connected since the app started — no path to show yet."
        val time = java.text.SimpleDateFormat("h:mm a", java.util.Locale.US)
            .format(java.util.Date(last.second))
        return "Last connected over ${io.agenticcontrol.app.server.ConnectionPath.pathName(last.first)} at $time."
    }

    /** Step 5 of 7 — pair (the hero surface).
     *
     *  W10 (V3-F3): the agent's name is its own clientInfo name —
     *  never typed by the owner, never shown before authentication
     *  (record header + §4 A2). There is no name field: pairing
     *  begins nameless and the name arrives with the agent's own
     *  initialize (PairingStore.bindAgentInfo). "Redeemed" means
     *  THIS run's redemption (PairingStore.lastRedeemedPairing) —
     *  never "the store is non-empty" — and the name + safety
     *  phrase bind to that pairing only. Pairing offers QR + code
     *  (§4 A2 [R2F]). */
    private fun renderPairing() {
        progressBar(4)
        root.addView(UiKit.headline(this, "Pair your AI"))
        val store = ControlService.sharedPairingStore
        val redeemed = store?.lastRedeemedPairing()

        val codeCard = UiKit.card(this)
        codeCard.addView(UiKit.muted(this, "PAIRING CODE"))
        if (pairingCode == null) {
            codeCard.addView(
                UiKit.body(
                    this,
                    "The app makes a one-time code, good for 10 minutes and one use, and writes " +
                        "a short prompt for your AI. Copy the prompt, paste it into your AI's app, " +
                        "and your AI does the rest."
                )
            )
            // W98 / S09(b): the mint-time connection choice
            // (default AUTO), bound to the code when it is made.
            codeCard.addView(
                UiKit.connectionPathMintPicker(this, mintConnection) { chosen ->
                    mintConnection = chosen
                }
            )
            codeCard.addView(UiKit.primaryButton(this, "Create my pairing code") {
                if (store == null) {
                    toast("The control channel is still starting — one moment.")
                } else if (SetupChecks.reachableRemoteAddress() == null) {
                    // bd-and-rest F8 fix: same gate as the home
                    // screen — no reachable address, no code.
                    toast("Tailscale is not up on this phone — an AI on another device could not reach it. Start Tailscale, then make the code.")
                } else {
                    // No owner-typed name: the pairing's name is
                    // the agent's own clientInfo name, bound at
                    // pair time by McpCore (bindAgentInfo). W98:
                    // the mint connection choice rides the same
                    // beginPairing call.
                    pairingCode = beginWizardPairing(store) ?: return@primaryButton
                    handoffPrompt = buildHandoffPrompt(pairingCode!!)
                    render()
                }
            })
        } else {
            codeCard.addView(TextView(this).apply {
                text = spacedCode(pairingCode!!)
                textSize = 34f
                typeface = Fonts.monoBold(this@WizardActivity)
                setTextColor(UiKit.TEXT)
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
                ).apply { setMargins(0, 0, 0, UiKit.dp(this@WizardActivity, 6)) }
            })
            expiryView = TextView(this).apply {
                textSize = 14f
                typeface = Fonts.medium(this@WizardActivity)
                // W10 (V3-F8): neutral ink — amber is a presence
                // hue and is never a status colour (§1.1).
                setTextColor(UiKit.TEXT)
            }
            codeCard.addView(expiryView)
            updateExpiry()
            // QR option (§4 A2): the same offer — endpoint +
            // one-time code — as a scannable code beside the
            // digits. One offer, two renderings.
            val endpoint = "http://${SetupChecks.endpointAddress(this)}:${McpHttpServer.PORT}/mcp"
            val offer = io.agenticcontrol.app.design.SetupWizardModel
                .pairingOffer(endpoint, pairingCode!!)
            val symbol = io.agenticcontrol.app.design.QrCode.encode(offer)
            if (symbol != null) {
                codeCard.addView(UiKit.muted(this, "Or let your AI scan this code — it carries the same address and one-time code."))
                codeCard.addView(qrImage(symbol))
            }
            codeCard.addView(UiKit.muted(this, handoffPrompt))
            codeCard.addView(UiKit.primaryButton(this, "Copy the prompt for your AI") {
                val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                clipboard.setPrimaryClip(
                    ClipData.newPlainText("DeskGuest pairing prompt", handoffPrompt)
                )
                toast("Copied. Paste it into your AI's app, then come back here.")
            })
            codeCard.addView(UiKit.textButton(this, "Make a new code") {
                if (store == null) {
                    toast("The control channel is still starting — one moment.")
                } else if (SetupChecks.reachableRemoteAddress() == null) {
                    toast("Tailscale is not up on this phone — an AI on another device could not reach it. Start Tailscale, then make the code.")
                } else {
                    pairingCode = beginWizardPairing(store) ?: return@textButton
                    handoffPrompt = buildHandoffPrompt(pairingCode!!)
                    render()
                }
            })
        }
        root.addView(codeCard)

        // W7 §4 A2 pair step (hero surface c) + W10 (V3-F3b):
        // BEFORE this run's code is redeemed the screen says only
        // "Waiting for your AI" — the agent's name and the safety
        // phrase appear only AFTER this pairing is redeemed, and
        // they are THIS pairing's, never an earlier one's.
        if (pairingCode != null && redeemed == null) {
            root.addView(
                UiKit.muted(
                    this,
                    io.agenticcontrol.app.design.SetupWizardModel.waitingLine()
                )
            )
        }
        val paired = store?.all().orEmpty()
        if (redeemed != null) {
            val target = redeemed
            val connectedCard = UiKit.card(this)
            val head = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
            head.addView(UiKit.chip(this, "Connected", UiKit.ChipKind.NEUTRAL))
            connectedCard.addView(head)
            connectedCard.addView(
                UiKit.body(this, "${displayName(target)} is paired.")
            )
            // W7 §4 A2 + W8 item 3 + W10 (V3-F3a): after THIS
            // pairing's redemption, the SAS confirmation. The MCP
            // PairingStore holds NO key material, so the pinned
            // PairingSas derivation cannot run for an MCP pairing
            // on this surface — the check line names the agent,
            // honestly. The phrase itself is rendered ONLY when
            // the enrollment record FOR THIS PAIRING carries one
            // (SetupWizardModel.sasForPairing, selected by this
            // pairing's id — never the first record with any SAS,
            // which could be another identity's words). No match ⇒
            // no phrase, never a fabricated or borrowed one.
            connectedCard.addView(
                UiKit.muted(
                    this,
                    io.agenticcontrol.app.design.SetupWizardModel.sasCheckLine(displayName(target))
                )
            )
            val enrolledPairs = try {
                io.agenticcontrol.app.wiring.PlatformRuntime.peek()
                    ?.enrollment?.all()?.map { it.deviceId to it.sas } ?: emptyList()
            } catch (_: Throwable) {
                emptyList()
            }
            val boundSas = io.agenticcontrol.app.design.SetupWizardModel
                .sasForPairing(target.id, enrolledPairs)
            if (boundSas != null) {
                connectedCard.addView(
                    UiKit.body(
                        this,
                        io.agenticcontrol.app.design.SetupWizardModel.sasPhraseLine(boundSas)
                    )
                )
            }
            root.addView(connectedCard)
        } else if (paired.isNotEmpty()) {
            // An earlier pairing exists on this phone, but THIS
            // run has redeemed nothing: say so in neutral words —
            // no name, no phrase, no "Connected" for a pairing
            // this run did not make.
            root.addView(
                UiKit.muted(
                    this,
                    "An AI is already paired on this phone. Pair a new code here, or continue."
                )
            )
        }
        val pairContinue = UiKit.primaryButton(this, "Continue") {
            step = Step.ACCESS
            render()
        }
        UiKit.stylePrimary(this, pairContinue, redeemed != null || paired.isNotEmpty())
        root.addView(pairContinue)
        if (redeemed == null && paired.isEmpty()) {
            root.addView(UiKit.muted(this, "Continue unlocks once your AI has paired."))
        }
    }

    /** Render a QrCode symbol as a black-on-white bitmap with the
     *  standard 4-module quiet zone. */
    private fun qrImage(symbol: io.agenticcontrol.app.design.QrCode.Symbol): android.widget.ImageView {
        val quiet = 4
        val total = symbol.size + quiet * 2
        val scale = 10
        val bmp = android.graphics.Bitmap.createBitmap(
            total * scale, total * scale, android.graphics.Bitmap.Config.ARGB_8888
        )
        val canvas = android.graphics.Canvas(bmp)
        canvas.drawColor(android.graphics.Color.WHITE)
        val paint = android.graphics.Paint().apply { color = android.graphics.Color.BLACK }
        for (y in 0 until symbol.size) {
            for (x in 0 until symbol.size) {
                if (symbol.modules[y][x]) {
                    canvas.drawRect(
                        ((x + quiet) * scale).toFloat(), ((y + quiet) * scale).toFloat(),
                        ((x + quiet + 1) * scale).toFloat(), ((y + quiet + 1) * scale).toFloat(),
                        paint
                    )
                }
            }
        }
        return android.widget.ImageView(this).apply {
            setImageBitmap(bmp)
            contentDescription = "Pairing QR code"
            layoutParams = LinearLayout.LayoutParams(
                UiKit.dp(this@WizardActivity, 180), UiKit.dp(this@WizardActivity, 180)
            ).apply { setMargins(0, UiKit.dp(this@WizardActivity, 8), 0, UiKit.dp(this@WizardActivity, 8)) }
        }
    }

    /** Step 6 of 7 — access level for the paired AI. */
    private fun renderAccess() {
        progressBar(5)
        root.addView(UiKit.headline(this, "What may your AI do?"))
        val store = ControlService.sharedPairingStore
        val paired = store?.all().orEmpty()
        if (paired.isEmpty() || store == null) {
            root.addView(UiKit.muted(this, "No AI is paired yet — pair one in the previous step first."))
        } else {
            // W10 (V3-F3b): the access step edits THE pairing this
            // run redeemed when there is one — not whatever
            // pairing happens to be last in the store.
            val target = store.lastRedeemedPairing() ?: paired.last()
            root.addView(
                UiKit.body(this, "${displayName(target)} is paired. Choose what it may do — nothing changes until you tap Apply in the preview.")
            )
            root.addView(
                // W89 / S08: same slider + Fine-tune surface as the
                // home pairing card (one grant state, one apply
                // path, audited; elevation default-refused at the
                // store without the preview's elevation switch).
                UiKit.accessEditor(
                    this, target.scopes,
                    io.agenticcontrol.app.design.AccessEditorModel.fullControlConfirmLine(displayName(target))
                ) { proposed, elevationConfirmed ->
                    val result = store.updateScopes(target.token, proposed, elevationConfirmed)
                    when {
                        result.pairing != null -> {
                            toast("Access updated for ${displayName(target)}.")
                            render()
                            null
                        }
                        result.refusal != null -> "Refused: ${result.refusal}"
                        else -> "That pairing is no longer there."
                    }
                }
            )
            root.addView(
                // W98 / S09(b): the connection-path control beside
                // the access editor, same as the home pairing card
                // (staged preview + Apply; the store is the one
                // apply path; change AND refusal audited).
                UiKit.connectionPathEditor(
                    this, target.connection,
                    currentPathLine(store, target)
                ) { proposed ->
                    val result = store.updateConnectionPath(target.token, proposed)
                    when {
                        result.pairing != null -> {
                            toast("Connection path updated for ${displayName(target)}.")
                            render()
                            null
                        }
                        result.refusal != null -> "Refused: ${result.refusal}"
                        else -> "That pairing is no longer there."
                    }
                }
            )
        }
        root.addView(UiKit.primaryButton(this, "Continue") {
            step = Step.SELFCHECK
            render()
        })
    }

    /** Step 7 of 7 — self-check: only what the app actually
     *  checked, then Done. */
    private fun renderSelfCheck() {
        progressBar(6)
        root.addView(UiKit.headline(this, "Self-check"))
        val store = ControlService.sharedPairingStore
        val paired = store?.all().orEmpty()
        // Compact setup report: only what the app actually checked.
        val report = UiKit.card(this)
        report.addView(
            UiKit.reportRow(
                this, ControlService.sharedServer?.isRunning == true,
                "Control channel", "the channel your AI connects to"
            )
        )
        report.addView(
            UiKit.reportRow(
                this, SetupChecks.accessibilityBound(this),
                "Screen access", "without this, your AI can connect but cannot see or touch the screen"
            )
        )
        report.addView(
            UiKit.reportRow(
                this, SetupChecks.overlayOn(this),
                "On-screen signals", "the Glow, the Box, and STOP during sessions"
            )
        )
        report.addView(
            UiKit.reportRow(
                this, paired.isNotEmpty(),
                "AI connected",
                if (paired.isEmpty()) "not yet — you can connect later from the home screen"
                else paired.joinToString { displayName(it) }
            )
        )
        root.addView(report)

        root.addView(UiKit.primaryButton(this, "Done") {
            getSharedPreferences(PREFS, MODE_PRIVATE).edit().putBoolean(KEY_DONE, true).apply()
            finish()
        })
        // W10 (V3-F3f): the click budget, stated on the
        // self-check screen (§4 A2 [R2F]).
        root.addView(
            UiKit.muted(
                this,
                io.agenticcontrol.app.design.SetupWizardModel.clickBudgetLine()
            )
        )
        root.addView(
            UiKit.muted(this, "Anything not set up here can be changed later from the home screen.")
        )
    }

    private fun chooseTransport(choice: String) {
        transportSel = choice
        SetupChecks.setTransportChoice(this, choice)
        render()
    }

    /** Live expiry line for the pairing code (neutral ink — amber
     *  is a presence hue, never a status colour; W10, V3-F8). */
    private fun updateExpiry() {
        val view = expiryView ?: return
        val store = ControlService.sharedPairingStore
        val remaining = store?.pendingCodeRemainingMs ?: 0L
        view.text = when {
            pairingCode == null -> ""
            remaining <= 0 -> "This code has expired — make a new one."
            else -> {
                val totalSec = (remaining + 999) / 1000
                "Expires in ${totalSec / 60}:${"%02d".format(totalSec % 60)}"
            }
        }
    }

    /** The code as the design shows it: digits in spaced groups. */
    private fun spacedCode(code: String): String =
        code.chunked(3).joinToString("  ")

    // ---------- helpers ----------

    /** The name to show for a pairing: the AI's own clientInfo
     *  name when it gave one (never an owner-typed name — W10,
     *  V3-F3c). FR-123: before the agent has introduced itself
     *  the label is the truthful unnamed-pairing label through
     *  the U8 strings door — never the generic "Your AI". */
    private fun displayName(pairing: PairingStore.Pairing): String =
        pairing.agentName.ifBlank { pairing.name }
            .ifBlank { consentString(R.string.pairing_unnamed_label) }

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

    /**
     * Open a system Settings page (0.4.2): some OEM builds reject a
     * specific or package-scoped intent, so a refusal falls back to
     * this app's details page, then to a plain message — a settings
     * intent can never take the wizard down.
     */
    private fun openSettings(intent: Intent) {
        try {
            startActivity(intent)
        } catch (e: Exception) {
            try {
                startActivity(
                    Intent(
                        Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                        Uri.parse("package:$packageName")
                    )
                )
            } catch (e2: Exception) {
                toast("That settings page did not open. Open it from Android Settings, under Apps, DeskGuest.")
            }
        }
    }

    private fun toast(text: String) =
        Toast.makeText(this, text, Toast.LENGTH_LONG).show()

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        // Detection re-runs on render; the result is observed, not trusted.
        render()
    }

    companion object {
        const val PREFS = "setup"
        const val KEY_DONE = "wizard_done"
        // W10 (V3-F3c): the wizard no longer asks the owner to
        // type the AI's name and never writes this key. It is
        // kept only because MainActivity reads legacy values
        // written by older wizards.
        const val KEY_AGENT_NAME = "agent_name"
        const val KEY_ROLE = "wizard_role"
        const val ROLE_PERSONAL = "personal"
        const val ROLE_ORGANISATION = "organisation"

        fun isDone(context: Context): Boolean =
            context.getSharedPreferences(PREFS, MODE_PRIVATE).getBoolean(KEY_DONE, false)
    }
}
