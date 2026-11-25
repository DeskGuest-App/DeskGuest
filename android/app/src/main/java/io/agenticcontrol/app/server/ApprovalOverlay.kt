package io.agenticcontrol.app.server

import android.content.Context
import android.graphics.PixelFormat
import android.graphics.drawable.GradientDrawable
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.view.WindowManager
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import io.agenticcontrol.app.R
import io.agenticcontrol.app.design.GateModel
import io.agenticcontrol.app.strings.consentString
import io.agenticcontrol.app.ui.Fonts
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The approval prompt (0.4.0): when a gated action is set to Ask
 * First, this window appears over whatever is on screen — what the
 * agent wants to do, an Approve and a Deny button, and a 30-second
 * clock. Deny, timeout, and "cannot show the prompt" all count as
 * NO: the gated tool fails cleanly and the agent is told the user
 * did not approve. The prompt is the host asking, not the agent —
 * the agent cannot dismiss, spoof, or bypass it.
 *
 * W10 (V3 fixes):
 *  - Exits exactly equal (GateModel.exitStyles): same fill, text,
 *    border, 600 weight for Approve / Deny / Deny-and-end. No
 *    solid ink fill — only STOP may be the brightest thing
 *    present, and STOP is not on this sheet.
 *  - Arming (OI-13): a decision click counts only after 600 ms
 *    AND a human activation. A click IS an activation source —
 *    touch or the owner's TalkBack activation on an exit — so a
 *    screen-reader owner can arm and answer the gate. Clicks
 *    before arming are recorded as activation and ignored as
 *    decisions.
 *  - Deny-and-end: [requestApproval]'s handler is non-null,
 *    performs the teardown only, and this overlay writes the
 *    approval_deny_and_end audit event exactly once, after the
 *    handler returns. A throwing handler produces
 *    approval_deny_and_end_failed instead — never a false claim
 *    of an end that did not happen — and the gate still denies.
 *  - Payload (OI-12): quoted in a bounded scroll region with the
 *    exits pinned below it, rendered through
 *    GateModel.escapePayload so bidi/control characters are
 *    visible escapes — what the owner sees decodes back to the
 *    submitted bytes exactly (GateModel.overlayPayloadMatches).
 *  - OI-01: after the sheet is added, the presence Box is
 *    re-raised above it (PresenceOverlay.raiseBoxAboveGate) —
 *    the Box and STOP stay on top, unchanged.
 *  - OI-13 second wall: the card and every exit set
 *    filterTouchesWhenObscured (GateModel.FILTER_TOUCHES_WHEN_OBSCURED).
 */
object ApprovalOverlay {

    private val handler = Handler(Looper.getMainLooper())

    /**
     * Ask, blocking the calling (tool) thread for at most
     * [ApprovalGate.TIMEOUT_MS]. Returns true only on an explicit
     * Approve tap. [onDenyAndEnd] is required: the third exit is
     * always shown, so it must always have a real teardown behind
     * it — a caller cannot show "Deny and end session" and only
     * deny.
     */
    fun requestApproval(
        context: Context,
        actionClass: ApprovalGate.ActionClass,
        summary: String,
        agentName: String,
        // W6 design record §3 (OI-12): the exact payload the tool
        // call will submit, quoted verbatim in the gate — never a
        // re-typed rendering. Null for non-content actions.
        payload: String? = null,
        // §3/A17: a gate raised from Agent chat carries its origin.
        fromChat: Boolean = false,
        // §3 third exit: Deny and end session (teardown only; the
        // audit event is this overlay's single write).
        onDenyAndEnd: () -> Unit
    ): Boolean {
        // W13 P2-F10: the audit event is emitted FIRST, whatever
        // happens next — the old order returned before any emit on
        // devices without the overlay grant, so a refused prompt
        // left no trace. And the prompt itself no longer hard-
        // requires the app-overlay grant: when the accessibility
        // service is bound, the sheet rides
        // TYPE_ACCESSIBILITY_OVERLAY through the service's own
        // context (the presence layer's exact posture). Only a
        // device with NEITHER path refuses — audibly, in the audit.
        SessionEvents.emit(
            "approval_required",
            mapOf("class" to actionClass.name, "summary" to summary.take(120))
        )
        val a11yService = io.agenticcontrol.app.access.ControlAccessibilityService.instance
        val sheetContext: Context
        val sheetType: Int
        when {
            Settings.canDrawOverlays(context) -> {
                sheetContext = context
                sheetType = WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
            }
            a11yService != null -> {
                sheetContext = a11yService
                sheetType = WindowManager.LayoutParams.TYPE_ACCESSIBILITY_OVERLAY
            }
            else -> {
                SessionEvents.emit(
                    "approval_unshowable",
                    mapOf("class" to actionClass.name,
                        "reason" to "no overlay grant and no accessibility service")
                )
                return false
            }
        }
        // bd-and-core F2: the pending latch covers the prompt's
        // whole lifetime — while it is set, SessionManager refuses
        // every drive/observe tool and McpCore refuses every other
        // call, so a concurrent agent call cannot tap this prompt.
        ApprovalPending.begin()
        try {
            val latch = CountDownLatch(1)
            val approved = AtomicBoolean(false)
            // W13 P2-F1 remainder closed: the posted show() carries
            // this prompt's expiry token — if the main thread was
            // busy past the timeout, the runnable finds the token
            // set and never paints a sheet for a dead prompt.
            val expired = AtomicBoolean(false)
            handler.post {
                show(sheetContext, sheetType, actionClass, summary, agentName, latch, approved,
                    payload, fromChat, onDenyAndEnd, expired)
            }
            val answered = latch.await(ApprovalGate.TIMEOUT_MS, TimeUnit.MILLISECONDS)
            expired.set(true)
            SessionEvents.emit(
                "approval_resolved",
                mapOf(
                    "class" to actionClass.name,
                    "approved" to (answered && approved.get())
                )
            )
            return answered && approved.get()
        } finally {
            ApprovalPending.end()
        }
    }

    private fun show(
        context: Context,
        sheetType: Int,
        actionClass: ApprovalGate.ActionClass,
        summary: String,
        agentName: String,
        latch: CountDownLatch,
        approved: AtomicBoolean,
        payload: String?,
        fromChat: Boolean,
        onDenyAndEnd: () -> Unit,
        expired: AtomicBoolean
    ) {
        // W13 P2-F1: a show() that lands after the prompt timed
        // out paints nothing and counts nothing down twice — the
        // latch was already released by the await's timeout.
        if (expired.get()) return
        // W6 design record §3 / OI-01: the gate is a FULL-SCREEN
        // sheet. The presence Box stays held above it, unchanged,
        // STOP included: after this sheet is added, the Box window
        // is re-raised (PresenceOverlay.raiseBoxAboveGate) so the
        // sheet never covers it. Exits are exactly three, at
        // exactly equal weight (GateModel.exitStyles). No
        // session-wide allow exists anywhere.
        val wm = context.getSystemService(Context.WINDOW_SERVICE) as WindowManager
        val night = (context.resources.configuration.uiMode and
            android.content.res.Configuration.UI_MODE_NIGHT_MASK) ==
            android.content.res.Configuration.UI_MODE_NIGHT_YES
        val theme = io.agenticcontrol.app.design.HeroThemes.resolve(
            io.agenticcontrol.app.design.HeroThemes.Mode.FOLLOW_SYSTEM, night)
        val card = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(56, 120, 56, 56)
            setBackgroundColor(theme.surface)
            elevation = 24f
            // OI-13 second wall: third-party overlay taps do not
            // pass through to the gate.
            filterTouchesWhenObscured = GateModel.FILTER_TOUCHES_WHEN_OBSCURED
        }
        card.addView(TextView(context).apply {
            text = context.consentString(R.string.approval_title)
            setTextColor(theme.onSurface)
            textSize = 20f
            typeface = Fonts.medium(context)
        })
        if (fromChat) {
            card.addView(TextView(context).apply {
                text = context.consentString(R.string.gate_asked_from_chat)
                setTextColor(theme.muted)
                textSize = 13f
                typeface = Fonts.regular(context)
                setPadding(0, 8, 0, 0)
            })
        }
        card.addView(TextView(context).apply {
            text = context.consentString(R.string.approval_wants_to, agentName, actionClass.blurb, summary)
            setTextColor(theme.muted)
            textSize = 15f
            typeface = Fonts.regular(context)
            setPadding(0, 12, 0, 20)
            setLineSpacing(0f, 1.3f)
        })
        if (payload != null) {
            // OI-12: the quoted block is the submitted payload
            // itself, in a bounded scroll region so a long payload
            // can never push the exits off screen (the exits are
            // pinned below the scroll region). The text is the
            // payload through GateModel.escapePayload — bidi and
            // control characters show as visible escapes, and the
            // shown string decodes back to the submitted bytes
            // exactly (GateModel.overlayPayloadMatches fixture).
            card.addView(TextView(context).apply {
                text = context.consentString(R.string.gate_draft_not_sent)
                setTextColor(theme.muted)
                textSize = 12f
                typeface = Fonts.medium(context)
            })
            val payloadView = TextView(context).apply {
                text = GateModel.escapePayload(payload)
                setTextColor(theme.onSurface)
                textSize = 14f
                typeface = Fonts.regular(context)
                setPadding(24, 16, 24, 16)
                background = GradientDrawable().apply {
                    setColor(theme.cardSurface)
                    cornerRadius = 24f
                    setStroke(2, theme.border)
                }
            }
            val scroll = ScrollView(context).apply {
                addView(payloadView)
            }
            val maxPayloadHeight =
                (context.resources.displayMetrics.heightPixels * 0.35f).toInt()
            card.addView(scroll, LinearLayout.LayoutParams(-1, maxPayloadHeight).apply {
                topMargin = 8
            })
        }
        card.addView(TextView(context).apply {
            text = context.consentString(R.string.gate_no_session_allow)
            setTextColor(theme.muted)
            textSize = 12.5f
            typeface = Fonts.regular(context)
            setPadding(0, 16, 0, 24)
        })
        val params = WindowManager.LayoutParams(
            WindowManager.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.MATCH_PARENT,
            sheetType,
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE,
            PixelFormat.TRANSLUCENT
        )
        var removed = false
        // W13 P2-F16: when the session ENDS under a live prompt,
        // the prompt dies with it — previously it held its latch
        // count until the 30 s timeout, refusing tools for a
        // session that no longer existed. The listener is removed
        // on every dismissal path.
        lateinit var sessionEndListener: (SessionManager.Session?) -> Unit
        fun dismiss(result: Boolean) {
            if (removed) return
            removed = true
            SessionManager.removeListener(sessionEndListener)
            approved.set(result)
            try {
                wm.removeViewImmediate(card)
            } catch (_: Exception) {
            }
            latch.countDown()
        }
        sessionEndListener = { session -> if (session == null) dismiss(false) }
        // OI-13 arming: a decision counts only after 600 ms AND a
        // human activation. Activation sources: a touch on the
        // sheet, or a click on an exit — a click is how the
        // owner's TalkBack activates a control, so a screen-reader
        // owner can arm the gate (the old touch-only arming made
        // the gate unanswerable by TalkBack). The agent's service
        // is never an activation source: ACP's own action layer
        // refuses agent actions targeting ACP windows (OI-13), and
        // ApprovalPending blocks agent calls while the gate is up.
        // W13 P2-F19: arming is measured on the MONOTONIC clock
        // (elapsedRealtime) — a wall-clock jump could previously
        // arm the exits instantly or never.
        val shownAt = android.os.SystemClock.elapsedRealtime()
        // W13 P1-F12: the activation is a RECORD (when + source)
        // carried into GateModel, not a bare boolean.
        var activation: GateModel.Activation? = null
        fun recordActivation(source: String) {
            if (activation == null) {
                activation = GateModel.Activation(android.os.SystemClock.elapsedRealtime(), source)
            }
        }
        fun armedNow(): Boolean = GateModel.controlsArmed(
            shownAt, android.os.SystemClock.elapsedRealtime(), activation
        )
        card.setOnTouchListener { _, _ -> recordActivation("touch"); false }
        card.isClickable = true
        card.setOnClickListener { recordActivation("click") }
        // W13 P2-F18: on-screen feedback when a tap is discarded
        // (pre-arm, or the agent-gesture guard) — the old behaviour
        // silently swallowed the tap and the owner could not tell
        // the sheet had even seen it.
        val guardNote = TextView(context).apply {
            text = ""
            setTextColor(theme.muted)
            textSize = 13f
            typeface = Fonts.regular(context)
            setPadding(0, 0, 0, 12)
        }
        card.addView(guardNote)
        val exitButtons = mutableListOf<Button>()
        fun exitButton(style: GateModel.ExitStyle, onDecision: () -> Unit): Button =
            Button(context).apply {
                text = style.label
                isAllCaps = false
                textSize = 16f
                // The model's weight, actually read: 600.
                typeface = Fonts.semibold(context)
                setTextColor(style.textColor)
                stateListAnimator = null
                alpha = 0.45f
                filterTouchesWhenObscured = GateModel.FILTER_TOUCHES_WHEN_OBSCURED
                setPadding(40, 22, 40, 22)
                background = GradientDrawable().apply {
                    setColor(style.fill)
                    cornerRadius = 32f
                    setStroke(2, style.borderColor)
                }
                setOnClickListener {
                    // Any owner click activates; only an ARMED
                    // click decides. A pre-arm click says so on
                    // screen (W13 P2-F18) instead of vanishing.
                    recordActivation("click")
                    if (armedNow()) {
                        onDecision()
                    } else {
                        guardNote.text = "One moment — the buttons arm ${io.agenticcontrol.app.design.PresenceLaw.GATE_ARM_MS} ms after the sheet appears, so a stray tap cannot decide."
                    }
                }
            }
        val styles = GateModel.exitStyles(theme)
        // Approve — first, at exactly the same weight as the rest.
        exitButtons += exitButton(styles[0]) {
            // bd-and-core F2 touch guard retained: an Approve tap
            // within TOUCH_GUARD_MS of the agent's last dispatched
            // gesture is not a human decision and is ignored.
            if (ApprovalPending.approveTapAllowed(
                    System.currentTimeMillis(), SessionManager.lastAgentGestureAtMs
                )
            ) {
                dismiss(true)
            } else {
                // W13 P2-F18: the owner SEES why the tap did not
                // decide (and the audit emit stays).
                guardNote.text = "That tap landed too soon after the agent's last action to count as yours — tap Approve again to decide."
                SessionEvents.emit(
                    "approval_tap_guarded",
                    mapOf("class" to actionClass.name)
                )
            }
        }
        // Deny — directly beneath Approve, equal weight.
        exitButtons += exitButton(styles[1]) {
            dismiss(false)
        }
        // Deny and end session — the third lawful exit. The
        // handler performs the teardown; this overlay then writes
        // the audit event exactly once. If the teardown throws,
        // the event written is the failure event — the audit never
        // claims an end that did not happen — and the gate still
        // dismisses as a deny (fail closed).
        exitButtons += exitButton(styles[2]) {
            var ended = false
            try {
                onDenyAndEnd()
                ended = true
            } catch (_: Exception) {
            }
            if (ended) {
                SessionEvents.emit(
                    "approval_deny_and_end",
                    mapOf("class" to actionClass.name, "sessionEnded" to true)
                )
            } else {
                SessionEvents.emit(
                    "approval_deny_and_end_failed",
                    mapOf("class" to actionClass.name)
                )
            }
            dismiss(false)
        }
        for (b in exitButtons) {
            card.addView(b, LinearLayout.LayoutParams(-1, -2).apply {
                bottomMargin = 20
            })
        }
        fun armLoop() {
            if (removed) return
            if (armedNow()) {
                for (b in exitButtons) { b.alpha = 1f }
            } else {
                handler.postDelayed({ armLoop() }, 100)
            }
        }
        try {
            wm.addView(card, params)
        } catch (e: Exception) {
            dismiss(false)
            return
        }
        SessionManager.addListener(sessionEndListener)
        if (SessionManager.active == null) {
            // The session ended between post and show.
            dismiss(false)
            return
        }
        // OI-01: with the sheet up, re-raise the presence Box
        // above it — Box and STOP stay visible and tappable,
        // unchanged, while the gate waits.
        io.agenticcontrol.app.presence.PresenceOverlay.raiseBoxAboveGate()
        armLoop()
        // Timeout cleanup: if the latch already fired this is a no-op
        // beyond removing a stale window.
        handler.postDelayed({ dismiss(approved.get()) }, ApprovalGate.TIMEOUT_MS + 500)
    }
}
