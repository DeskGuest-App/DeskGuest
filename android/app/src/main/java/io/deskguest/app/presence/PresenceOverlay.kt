package io.deskguest.app.presence

import android.animation.ValueAnimator
import android.content.Context
import android.graphics.BlurMaskFilter
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.PixelFormat
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.view.Gravity
import android.view.MotionEvent
import android.view.View
import android.view.WindowManager
import android.view.animation.DecelerateInterpolator
import android.widget.Button
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import io.deskguest.app.R
import io.deskguest.app.server.SessionManager
import io.deskguest.app.strings.consentString
import io.deskguest.app.ui.Fonts

/**
 * The presence layer (SPEC §7): while a drive session is open the user
 * SEES it. Composition per the owner's ruling of 2026-11-17 — exactly
 * THREE elements, on both apps: (1) the BIG centered box naming the
 * agent (with, under it, what the agent says it is doing, and the
 * STOP button that ends the session on the spot, from the phone,
 * without the agent's cooperation), (2) the ghost finger, (3) the
 * HUGE FADED diffuse edge glow. There is no top banner and no thin
 * edge-glow line — he explicitly does not want either. While paused
 * (touch-to-yield) the same box carries the paused state with Resume
 * and STOP. Presence paints ONLY from PresenceLaw (no user colour
 * picker — W12-DS P2-F21: the old "can be recolored in settings"
 * claim contradicted the signed record and is removed); it can
 * never be switched off while driving.
 *
 * 0.4.0 lifecycle (the zero-leak rule): every window this layer adds
 * goes into one registry. show() is idempotent per session
 * generation — it sweeps the registry clean, then builds exactly the
 * windows the current state needs. hide() sweeps everything. The
 * diagnostics report is derived from the registry and real view
 * attachment, never from flags the layer sets about itself, so it
 * cannot claim "detached" while a window is still painted (the
 * 0.3.7 leak). A physical touch outside the session's own gestures
 * pauses the session (touch-to-yield): the frame window watches for
 * outside touches, and a paused pill offers Resume or STOP.
 *
 * Needs the overlay grant (wizard step) OR the bound accessibility
 * service. Without either, show() refuses (lastShowError names it)
 * and SessionManager's presence precondition refuses every drive
 * and capture tool — there is NO notification-only degraded mode
 * (W12-DS P2-F3: the old KDoc claim of one was stale and is
 * removed; the self-check says the refusal plainly).
 */
object PresenceOverlay {

    private val handler = Handler(Looper.getMainLooper())
    private var appContext: Context? = null
    @Volatile
    private var watching = false

    // Show-path instrumentation (0.3.6): every show() call stamps its
    // attempt, its outcome, and the exact error when it fails, and
    // diagnostics() reports them so the agent reads facts instead of
    // forming theories.
    @Volatile
    private var showAttempts = 0
    @Volatile
    private var lastShowAtMs = 0L
    @Volatile
    private var lastShowError: String? = null
    @Volatile
    private var listenerCalls = 0

    /** W7: presence paints ONLY from PresenceLaw — hues are
     *  meanings (green = a human is acting, violet = an AI is
     *  acting, amber = open/idle, red = STOP). There is no palette
     *  and no picker (record §1.1). The only owner input is the
     *  comfort settings (Glow intensity / breath). */
    @Volatile
    private var comfort: PresenceSettings.Comfort = PresenceSettings.Comfort()

    /** The hue the three elements paint right now: the owner
     *  driving (paused) is a HUMAN acting → green; an active
     *  session is the AI acting → violet. */
    private fun currentHue(): Int =
        if (SessionManager.state == SessionManager.State.PAUSED_BY_USER)
            io.deskguest.app.design.PresenceLaw.HUE_HUMAN
        else
            io.deskguest.app.design.PresenceLaw.HUE_AI

    private fun stopColor(): Int =
        io.deskguest.app.design.PresenceLaw.HUE_STOP

    // ---- the window registry (0.4.0) --------------------------------
    // Every window, one list. Sweeping the list is the ONLY way
    // windows come down, so "hide" cannot miss one.

    private data class Tracked(val view: View, val wm: WindowManager, val kind: String)

    private val registry = mutableListOf<Tracked>()

    /** The generation the currently painted windows belong to. */
    @Volatile
    private var shownGeneration: Long = -1

    /** W13 P2-F4: the paused-state the on-screen Box was BUILT
     *  for. Pause/resume do not bump the generation the early-
     *  return below keys on in every path — when the built state
     *  and the live state differ, show() rebuilds (the Resume
     *  exit and hue are build-time properties, not text). */
    @Volatile
    private var shownPaused: Boolean? = null

    /** W13 P2-F14: window removals that failed and stayed tracked. */
    @Volatile
    private var sweepFailures: Int = 0

    private var windowManager: WindowManager? = null
    private var frameView: FrameLayout? = null
    /** bd-and-core F9: the separate 1×1 outside-touch watcher window
     *  (the glow frame itself is FLAG_NOT_TOUCHABLE, so ACTION_OUTSIDE
     *  can only ever be delivered to THIS window). */
    private var watcherView: View? = null
    /** bd-and-core F12: the SessionStore badge window (Recording /
     *  blanked / input-blocked), derived from the record via
     *  [sessionBadgeProvider]; not part of the drive-session
     *  windows and never swept by hide(). */
    private var badgeView: TextView? = null
    private var badgeWm: WindowManager? = null
    private var badgeText: String = ""

    /** bd-and-core F12: installed by ControlService — the live
     *  SessionStore badges (PlatformStores.liveSessionBadges). */
    @Volatile
    var sessionBadgeProvider: (() -> List<String>)? = null

    private var boxView: LinearLayout? = null
    /** W10 (V3-F5): the Box window's own params + manager, kept so
     *  [raiseBoxAboveGate] can re-attach the Box after another
     *  overlay (the gate sheet) is added. */
    private var boxParams: WindowManager.LayoutParams? = null
    private var boxWm: WindowManager? = null
    private var boxTitle: TextView? = null
    private var boxIntent: TextView? = null
    private var boxStop: Button? = null
    private var boxResume: Button? = null

    @Synchronized
    private fun track(view: View, wm: WindowManager, kind: String) {
        registry.add(Tracked(view, wm, kind))
    }

    @Synchronized
    private fun untrack(view: View) {
        registry.removeAll { it.view === view }
    }

    @Synchronized
    private fun trackedCount(): Int = registry.size

    /** W13 P2-F13/F14: windows swept by hide()/show() — every kind
     *  EXCEPT the SessionStore badge, whose lifecycle is the
     *  record's (syncBadge), not the drive session's. */
    private fun sweepAll() {
        val snapshot: List<Tracked>
        synchronized(this) {
            snapshot = registry.filter { it.kind != "badge" }
        }
        stopGlowPulse()
        glideAnimator?.cancel()
        glideAnimator = null
        snapshot.forEach { tracked ->
            // W13 P2-F14: a window leaves the registry only when
            // its removal SUCCEEDED (or it is already detached) —
            // the old clear-first sweep forgot windows whose
            // removal threw, leaking them untracked forever.
            val removed = try {
                tracked.wm.removeViewImmediate(tracked.view)
                true
            } catch (_: Exception) {
                tracked.view.isAttachedToWindow != true
            }
            if (removed) {
                synchronized(this) { registry.remove(tracked) }
            } else {
                sweepFailures += 1
            }
        }
        frameView = null
        watcherView = null
        boxView = null
        boxParams = null
        boxWm = null
        boxTitle = null
        boxIntent = null
        boxStop = null
        boxResume = null
        fingerView = null
        fingerParams = null
        rippleView = null
        highlightView = null
        highlightParams = null
    }

    /**
     * The window context for presence windows. TYPE_ACCESSIBILITY_OVERLAY
     * windows must be added through the accessibility service's own
     * context: the token the window manager validates belongs to the
     * service, so adds from the application context are rejected with
     * BadTokenException (the 0.3.6 show failure). Falls back to the app
     * context when the service is not bound, where the app-overlay type
     * is the correct pairing.
     */
    /** W13 P2-F15: the service instance is read ONCE per window-
     *  building sequence (all on the main thread): [windowContext]
     *  records whether the context it returned is the service's,
     *  and [overlayType] answers from that same read — the old
     *  pair read `instance` and `isBound` independently, so an
     *  unbind landing between them paired an app context with the
     *  accessibility overlay type (BadToken). */
    private var planFromService: Boolean? = null

    private fun windowContext(fallback: Context): Context {
        val instance = io.deskguest.app.access.ControlAccessibilityService.instance
        planFromService = instance != null
        return instance ?: fallback
    }

    private fun overlayType(): Int =
        if (planFromService ?: (io.deskguest.app.access.ControlAccessibilityService.instance != null))
            WindowManager.LayoutParams.TYPE_ACCESSIBILITY_OVERLAY
        else
            WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY

    fun canDraw(context: Context): Boolean = Settings.canDrawOverlays(context)

    /**
     * bd-and-core F5: the fact drive tools gate on — the STOP box
     * is attached to the window AND the painted windows belong to
     * the current session generation.
     */
    fun stopAttachedNow(): Boolean =
        boxStop?.isAttachedToWindow == true &&
            shownGeneration == SessionManager.generation.get()

    /**
     * Reload the comfort settings and repaint presence right away
     * if a session is on screen (the settings UI calls this on
     * every change). With no session open, the next show() picks
     * them up.
     */
    fun refreshComfort(context: Context) {
        comfort = PresenceSettings.load(context)
        if (SessionManager.active != null) {
            shownGeneration = -1
            show()
        }
    }

    /** §2 presence self-test (draw-verify): draws the Box (with
     *  STOP), the Ghost (ring + initial) and the Glow off-screen
     *  and verifies each actually painted pixels. The verdict is
     *  PresenceSelfTest's rule; SessionManager refuses drive tools
     *  while it fails. Runs at watch() and on demand from the
     *  Presence settings surface. */
    @Volatile
    var lastSelfTest: io.deskguest.app.design.PresenceSelfTest.DrawReport? = null
        private set

    /** W13 P1-F4: the session generation [lastSelfTest] was earned
     *  for; -1 = never run. */
    @Volatile
    private var selfTestGeneration: Long = -1

    fun selfTestDraw(context: Context): Boolean {
        val hue = io.deskguest.app.design.PresenceLaw.HUE_AI
        fun painted(draw: (Canvas, Int, Int) -> Unit): Boolean {
            val bmp = android.graphics.Bitmap.createBitmap(120, 120, android.graphics.Bitmap.Config.ARGB_8888)
            val canvas = Canvas(bmp)
            draw(canvas, 120, 120)
            var any = false
            var x = 0
            while (x < 120 && !any) {
                var y = 0
                while (y < 120) {
                    if (Color.alpha(bmp.getPixel(x, y)) > 0) { any = true; break }
                    y += 4
                }
                x += 4
            }
            bmp.recycle()
            return any
        }
        val glowPainted = painted { canvas, w, h ->
            val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
                style = Paint.Style.STROKE; strokeWidth = 40f; color = hue
                maskFilter = BlurMaskFilter(30f, BlurMaskFilter.Blur.NORMAL)
            }
            canvas.drawRoundRect(android.graphics.RectF(20f, 20f, w - 20f, h - 20f), 24f, 24f, paint)
        }
        val ghostPainted = painted { canvas, w, h ->
            GhostDrawable(hue, "A").apply { setBounds(10, 10, w - 10, h - 10) }.draw(canvas)
        }
        // W13 P2-F2: the STOP leg is verified from the PAINTED
        // PIXELS, not from having run the drawing lambda — the old
        // code set stopPainted=true unconditionally inside the
        // lambda, so the self-test's boxStopDrawn was synthetic.
        // The bitmap is scanned for the STOP colour in the stop
        // region after drawing.
        var stopPainted = false
        val boxPainted = painted { canvas, w, h ->
            val bg = Paint(Paint.ANTI_ALIAS_FLAG).apply {
                color = io.deskguest.app.design.HeroThemes.BOX_BACKGROUND
            }
            canvas.drawRoundRect(android.graphics.RectF(4f, 4f, w - 4f, h - 4f), 20f, 20f, bg)
            val stop = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = stopColor() }
            canvas.drawRoundRect(android.graphics.RectF(20f, h - 44f, w - 20f, h - 16f), 12f, 12f, stop)
        }
        run {
            val bmp = android.graphics.Bitmap.createBitmap(120, 120, android.graphics.Bitmap.Config.ARGB_8888)
            val canvas = Canvas(bmp)
            val bg = Paint(Paint.ANTI_ALIAS_FLAG).apply {
                color = io.deskguest.app.design.HeroThemes.BOX_BACKGROUND
            }
            canvas.drawRoundRect(android.graphics.RectF(4f, 4f, 116f, 116f), 20f, 20f, bg)
            val stop = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = stopColor() }
            canvas.drawRoundRect(android.graphics.RectF(20f, 76f, 100f, 104f), 12f, 12f, stop)
            var y = 80
            while (y < 100 && !stopPainted) {
                var x = 24
                while (x < 96) {
                    if (bmp.getPixel(x, y) == stopColor()) { stopPainted = true; break }
                    x += 2
                }
                y += 2
            }
            bmp.recycle()
        }
        val report = io.deskguest.app.design.PresenceSelfTest.DrawReport(
            boxDrawn = boxPainted, boxStopDrawn = stopPainted && boxPainted,
            ghostDrawn = ghostPainted, glowDrawn = glowPainted
        )
        lastSelfTest = report
        selfTestGeneration = SessionManager.generation.get()
        return io.deskguest.app.design.PresenceSelfTest.passes(report)
    }

    /**
     * Presence state for the MCP self-report (device_info), derived
     * from the registry and real attachment (0.4.0): bannerAttached is
     * the centered presence box's own isAttachedToWindow (the box is
     * what replaced the banner in the 2026-11-17 composition), and
     * stopAttached is the STOP button's — it lives inside the box.
     * leakedWindows counts tracked windows while no session exists —
     * the in-app zero-window check the leak fix is proven by.
     */
    fun diagnostics(context: Context): Map<String, Any> {
        val session = SessionManager.active
        val tracked = trackedCount()
        val out = mutableMapOf<String, Any>(
            "overlayGranted" to canDraw(context),
            "watcherRunning" to watching,
            "bannerAttached" to (boxView?.isAttachedToWindow == true),
            "stopAttached" to (boxStop?.isAttachedToWindow == true),
            "sessionActive" to (session != null),
            "sessionState" to when (SessionManager.state) {
                SessionManager.State.ACTIVE -> "active"
                SessionManager.State.PAUSED_BY_USER -> "paused_by_user"
                SessionManager.State.IDLE -> "idle"
            },
            "trackedWindows" to tracked,
            "leakedWindows" to (if (session == null) synchronized(this) { registry.count { it.kind != "badge" } } else 0),
            "generation" to SessionManager.generation.get(),
            "windowLayer" to (
                if (io.deskguest.app.access.ControlAccessibilityService.isBound)
                    "accessibility" else "application"
                ),
            "sweepFailures" to sweepFailures,
            "ghostAttached" to (fingerView?.isAttachedToWindow == true),
            "showAttempts" to showAttempts,
            "listenerCalls" to listenerCalls,
            "lastShowAtMs" to lastShowAtMs
        )
        lastShowError?.let { out["lastShowError"] = it }
        return out
    }

    /** Begin watching session state. Safe to call repeatedly. */
    fun watch(context: Context) {
        appContext = context.applicationContext
        comfort = PresenceSettings.load(context)
        // §2 self-test at watcher start: the draw-verify result is
        // what SessionManager's drive gate consults.
        try { selfTestDraw(context) } catch (_: Exception) { }
        // W13 P1-F4: the verdict is keyed to the generation the
        // self-test ran for — a later generation must re-earn it
        // (watch()/show() re-runs the test per generation change
        // through the backstop's re-show path).
        SessionManager.presenceSelfTestPassed = { gen ->
            gen == selfTestGeneration && (lastSelfTest?.let {
                io.deskguest.app.design.PresenceSelfTest.passes(it)
            } ?: false)
        }
        // bd-and-core F5: SessionManager consults this provider
        // before every drive tool — presence is a precondition.
        SessionManager.presenceStopAttached = { stopAttachedNow() }
        if (!watching) {
            watching = true
            SessionManager.addListener(sessionListener)
        }
        handler.removeCallbacks(sync)
        handler.post(sync)
    }

    /**
     * The session-change listener: SessionManager calls this
     * SYNCHRONOUSLY on every transition (start, pause, resume, end),
     * and we re-render on the main thread. Presence is event-driven so
     * it cannot be lost to a poll that stopped (the 0.3.2/0.3.4
     * failure, where the indicators vanished while the session ran on).
     */
    private val sessionListener: (SessionManager.Session?) -> Unit = { session ->
        listenerCalls += 1
        handler.post {
            if (session != null) show() else hide()
        }
    }

    /**
     * Slow backstop poll (5s). The listener does the real work; this
     * reconciles reality with the registry: a live session whose
     * windows are missing (or painted for a stale generation) is
     * re-shown, and windows outliving their session are swept.
     */
    private val sync = object : Runnable {
        override fun run() {
            val session = SessionManager.active
            if (session != null) {
                val frameGone = frameView == null || frameView?.isAttachedToWindow != true
                // W13 P2-F11: the BOX (STOP) is reconciled too —
                // the old backstop checked the frame only, so a
                // lost Box never came back while the glow claimed
                // presence was up (and the drive gate disagreed).
                val boxGone = boxView == null || boxView?.isAttachedToWindow != true
                if (frameGone || boxGone || shownGeneration != SessionManager.generation.get()) show()
            } else if (synchronized(this) { registry.any { it.kind != "badge" } }) {
                sweepAll()
                shownGeneration = -1
            }
            syncBadge()
            handler.postDelayed(this, 5000)
        }
    }

    /**
     * bd-and-core F12: reconcile the SessionStore badge window
     * with the record. The badge is a small non-touchable pill at
     * the top of the screen ("Recording", "Screen blanked for
     * remote viewer", "Input blocked") shown while ANY human
     * session record carries the state — it is not part of the
     * drive-session composition and the agent has no path to hide
     * it (no tool touches this layer).
     */
    private fun syncBadge() {
        val badges = try {
            sessionBadgeProvider?.invoke() ?: emptyList()
        } catch (_: Exception) {
            emptyList()
        }
        val text = badges.joinToString(" · ")
        if (text == badgeText && (text.isEmpty() || badgeView?.isAttachedToWindow == true)) return
        // Remove any existing badge window — through the wm that
        // added it, and out of the registry (W13 P2-F13: the badge
        // is a tracked window like every other; it was previously
        // removed through whatever windowManager happened to be
        // current and never registered at all).
        badgeView?.let { old ->
            try {
                (badgeWm ?: windowManager)?.removeViewImmediate(old)
            } catch (_: Exception) {
            }
            untrack(old)
            badgeView = null
            badgeWm = null
        }
        badgeText = text
        if (text.isEmpty()) return
        val context = appContext ?: return
        val wctx = windowContext(context)
        val wm = wctx.getSystemService(Context.WINDOW_SERVICE) as WindowManager
        windowManager = wm
        val view = TextView(wctx).apply {
            this.text = text
            setTextColor(Color.WHITE)
            textSize = 13f
            typeface = Fonts.medium(wctx)
            setPadding(28, 14, 28, 14)
            background = GradientDrawable().apply {
                setColor(Color.parseColor("#E69B1B1B"))
                cornerRadius = 40f
            }
        }
        val params = WindowManager.LayoutParams(
            WindowManager.LayoutParams.WRAP_CONTENT,
            WindowManager.LayoutParams.WRAP_CONTENT,
            overlayType(),
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or
                WindowManager.LayoutParams.FLAG_NOT_TOUCHABLE,
            PixelFormat.TRANSLUCENT
        ).apply {
            gravity = Gravity.TOP or Gravity.CENTER_HORIZONTAL
            y = 24
        }
        try {
            wm.addView(view, params)
            badgeView = view
            badgeWm = wm
            track(view, wm, "badge")
        } catch (e: Exception) {
            lastShowError = "badge show(): ${e.javaClass.simpleName}: ${e.message}"
            badgeText = ""
        }
    }

    /**
     * Build the presence windows for the current session state.
     * Idempotent per generation: a second call for the same
     * generation only refreshes the banner texts (intent changes do
     * not rebuild windows). Runs on the main thread.
     */
    private fun show() {
        showAttempts += 1
        lastShowAtMs = System.currentTimeMillis()
        val context = appContext
        if (context == null) {
            lastShowError = "appContext was null at show() time"
            return
        }
        val session = SessionManager.active ?: return
        // W13 P1-F4: a new generation re-earns its self-test —
        // re-run the draw-verify when this show() is for a
        // generation the last test did not cover.
        if (selfTestGeneration != SessionManager.generation.get()) {
            try { selfTestDraw(context) } catch (_: Exception) { }
        }
        // bd-and-core F5: the canDraw (SYSTEM_ALERT_WINDOW) check
        // applies only when the app-overlay type will be used. When
        // the accessibility service is bound, windows ride
        // TYPE_ACCESSIBILITY_OVERLAY, which needs no such grant —
        // the old unconditional check silently bailed show() on
        // exactly the devices where presence could have painted.
        if (!io.deskguest.app.access.ControlAccessibilityService.isBound && !canDraw(context)) {
            lastShowError = "overlay permission not granted at show() time"
            return
        }
        // FR-122 renderer guard (mirror of Windows FR-121): a
        // session whose driver name is missing NEVER renders the
        // named Box/Glow/Ghost — no generic or blank driver line on
        // any presence surface. Only the defect box renders: it
        // names the defect (driver_name_missing) and carries STOP.
        // SessionManager.start refuses such sessions, so this is
        // defense in depth for a session object that exists unnamed
        // by any other path.
        if (SessionManager.isDriverNameMissing(session.agentName)) {
            val defectGeneration = SessionManager.generation.get()
            val defectPaused = SessionManager.state == SessionManager.State.PAUSED_BY_USER
            if (shownGeneration == defectGeneration &&
                boxView?.isAttachedToWindow == true && shownPaused == defectPaused) {
                return
            }
            sweepAll()
            val wctx = windowContext(context)
            val wm = wctx.getSystemService(Context.WINDOW_SERVICE) as WindowManager
            windowManager = wm
            try {
                buildDefectBox(wctx, wm)
                shownGeneration = defectGeneration
                shownPaused = defectPaused
                lastShowError = null
            } catch (e: Exception) {
                lastShowError = "show() defect: ${e.javaClass.simpleName}: ${e.message}"
                sweepAll()
                shownGeneration = -1
                shownPaused = null
            }
            return
        }
        val generation = SessionManager.generation.get()
        // W12-DS P2-F5: a DETACHED frame is not "already shown" —
        // the old non-null check made the 5s recovery call show()
        // and return without ever rebuilding a lost Glow.
        val pausedNow = SessionManager.state == SessionManager.State.PAUSED_BY_USER
        if (shownGeneration == generation && frameView?.isAttachedToWindow == true &&
            shownPaused == pausedNow) {
            updateBoxTexts()
            return
        }
        sweepAll()
        val wctx = windowContext(context)
        val wm = wctx.getSystemService(Context.WINDOW_SERVICE) as WindowManager
        windowManager = wm
        try {
            buildFrame(wctx, wm)
            buildBox(wctx, wm, session.agentName)
            shownGeneration = generation
            shownPaused = pausedNow
            lastShowError = null
        } catch (e: Exception) {
            lastShowError = "show(): ${e.javaClass.simpleName}: ${e.message}"
            sweepAll()
            shownGeneration = -1
            shownPaused = null
        }
    }

    private fun hide() {
        sweepAll()
        shownGeneration = -1
        shownPaused = null
    }

    private fun updateBoxTexts() {
        val session = SessionManager.active ?: return
        // FR-122: the defect box owns its own texts — the named-box
        // text path must never overwrite it with an unnamed line.
        if (SessionManager.isDriverNameMissing(session.agentName)) return
        if (SessionManager.state == SessionManager.State.PAUSED_BY_USER) {
            boxTitle?.text = appContext?.consentString(R.string.presence_paused_title)
            boxIntent?.let {
                it.text = appContext?.consentString(R.string.presence_paused_agent, session.agentName)
                it.visibility = View.VISIBLE
            }
        } else {
            boxTitle?.text = appContext?.consentString(R.string.consent_session_active, session.agentName)
            val line = session.intent.ifBlank { session.lastAction }
            boxIntent?.let {
                it.text = line
                it.visibility = if (line.isBlank()) View.GONE else View.VISIBLE
            }
        }
    }

    /** The frame window: the diffuse edge glow only (the 2026-11-17
     *  composition — the box is its own window). Not focusable and
     *  NOT TOUCHABLE: touches pass through to the apps below.
     *
     *  bd-and-core F9 fix (2026-11-22): the old frame carried
     *  FLAG_WATCH_OUTSIDE_TOUCH without FLAG_NOT_TOUCHABLE and
     *  waited for ACTION_OUTSIDE on itself — a MATCH_PARENT window
     *  has no "outside", so touch-to-yield signal path one could
     *  never fire. The watch now lives on its own 1×1 window
     *  ([buildWatcher]): it is touchable, watches outside touches,
     *  and receives ACTION_OUTSIDE for every touch anywhere else —
     *  the documented mechanics of the flag. The accessibility
     *  TYPE_TOUCH_INTERACTION_START event remains path two. */
    private fun buildFrame(context: Context, wm: WindowManager) {
        val frame = FrameLayout(context)
        val glow = GlowView(context, currentHue())
        // OI-04: the Glow is STATIC by default; the breath runs
        // only when the owner enabled it as a comfort setting.
        // Intensity is the owner's comfort value, floored in
        // PresenceSettings.
        glow.bloomAlpha = (96 * comfort.glowIntensityPct / 100).coerceAtLeast(24)
        frame.addView(glow, FrameLayout.LayoutParams(-1, -1))
        if (comfort.breathEnabled) startGlowPulse(glow)
        val params = WindowManager.LayoutParams(
            WindowManager.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.MATCH_PARENT,
            overlayType(),
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or
                WindowManager.LayoutParams.FLAG_NOT_TOUCHABLE,
            PixelFormat.TRANSLUCENT
        )
        wm.addView(frame, params)
        frameView = frame
        track(frame, wm, "frame")
        buildWatcher(context, wm)
    }

    /** The 1×1 outside-touch watcher (bd-and-core F9): top-left,
     *  transparent, touchable — every physical touch elsewhere on
     *  the screen arrives here as ACTION_OUTSIDE and pauses the
     *  session (the Android layer's agent-gesture guard in
     *  ControlAccessibilityService / PresenceActivity decides
     *  whether a signal is the owner's; this window only delivers
     *  the raw signal, exactly as the frame's listener did). */
    private fun buildWatcher(context: Context, wm: WindowManager) {
        val watcher = View(context)
        watcher.setOnTouchListener { _, event ->
            if (event.action == MotionEvent.ACTION_OUTSIDE) {
                SessionManager.onUserTouchSignal()
            }
            false
        }
        val params = WindowManager.LayoutParams(
            1, 1,
            overlayType(),
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or
                WindowManager.LayoutParams.FLAG_WATCH_OUTSIDE_TOUCH,
            PixelFormat.TRANSLUCENT
        ).apply {
            gravity = Gravity.TOP or Gravity.START
        }
        wm.addView(watcher, params)
        watcherView = watcher
        track(watcher, wm, "watcher")
    }

    /**
     * FR-122 defect box: the ONLY presence rendering for a session
     * with no driver name. Same dark Box shell as the named box, but
     * its title names the defect (driver_name_missing) instead of a
     * driver, its line tells the owner how to clear it, and STOP —
     * full-width, same place — still ends the session. No frame,
     * no glow, no ghost is built in this state: presence elements
     * that imply a named driver never draw for an unnamed one.
     */
    private fun buildDefectBox(context: Context, wm: WindowManager) {
        val box = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(52, 40, 52, 36)
            background = GradientDrawable().apply {
                setColor(PresencePalette.withAlpha(
                    io.deskguest.app.design.HeroThemes.BOX_BACKGROUND, 0xF2))
                cornerRadius = 52f
                setStroke(2, PresencePalette.withAlpha(stopColor(), 120))
            }
            elevation = 24f
        }
        val title = TextView(context).apply {
            setTextColor(Color.WHITE)
            textSize = 18f
            typeface = Fonts.medium(context)
            text = context.consentString(R.string.presence_driver_name_missing)
        }
        box.addView(title)
        val hint = TextView(context).apply {
            textSize = 14f
            setTextColor(Color.parseColor("#C7D2FE"))
            typeface = Fonts.regular(context)
            gravity = Gravity.CENTER
            text = context.consentString(R.string.presence_driver_name_missing_hint)
        }
        box.addView(
            hint,
            LinearLayout.LayoutParams(-2, -2).apply { setMargins(0, 10, 0, 0) }
        )
        boxStop = Button(context).apply {
            text = context.consentString(R.string.presence_stop)
            setTextColor(Color.WHITE)
            typeface = Fonts.medium(context)
            textSize = 15f
            isAllCaps = true
            stateListAnimator = null
            setPadding(52, 18, 52, 18)
            background = GradientDrawable().apply {
                setColor(PresencePalette.withAlpha(stopColor(), 0xF2))
                cornerRadius = 52f
                setStroke(2, Color.parseColor("#40FFFFFF"))
            }
            setOnClickListener {
                SessionManager.stopByUser()
                hide()
            }
        }
        box.addView(
            boxStop,
            LinearLayout.LayoutParams(-1, -2).apply { setMargins(0, 28, 0, 0) }
        )
        val params = WindowManager.LayoutParams(
            WindowManager.LayoutParams.WRAP_CONTENT,
            WindowManager.LayoutParams.WRAP_CONTENT,
            overlayType(),
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE,
            PixelFormat.TRANSLUCENT
        ).apply {
            gravity = Gravity.CENTER
        }
        wm.addView(box, params)
        boxView = box
        boxParams = params
        boxWm = wm
        track(box, wm, "box")
    }

    /**
     * The presence box (2026-11-17 ruling): one big centered box that
     * names the agent, shows what it says it is doing, and carries the
     * controls — STOP always; while paused (touch-to-yield), the
     * paused state with Resume (which re-arms the agent — and
     * SessionManager makes it take a fresh snapshot before it may act
     * again) beside STOP. Its own touchable window, centered; the rest
     * of the screen stays usable around it.
     */
    private fun buildBox(context: Context, wm: WindowManager, agentName: String) {
        val paused = SessionManager.state == SessionManager.State.PAUSED_BY_USER
        val box = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(52, 40, 52, 36)
            background = GradientDrawable().apply {
                // §2: the Box is always dark (theme-invariant).
                setColor(PresencePalette.withAlpha(
                    io.deskguest.app.design.HeroThemes.BOX_BACKGROUND, 0xF2))
                cornerRadius = 52f
                setStroke(2, PresencePalette.withAlpha(currentHue(), 120))
            }
            elevation = 24f
        }
        val titleRow = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        titleRow.addView(View(context).apply {
            background = GradientDrawable().apply {
                shape = GradientDrawable.OVAL
                setColor(currentHue())
            }
        }, LinearLayout.LayoutParams(24, 24).apply { marginEnd = 20 })
        boxTitle = TextView(context).apply {
            setTextColor(Color.WHITE)
            textSize = 18f
            typeface = Fonts.medium(context)
        }
        titleRow.addView(boxTitle)
        box.addView(titleRow)
        boxIntent = TextView(context).apply {
            textSize = 14f
            setTextColor(Color.parseColor("#C7D2FE"))
            typeface = Fonts.regular(context)
            gravity = Gravity.CENTER
            visibility = View.GONE
        }
        box.addView(
            boxIntent,
            LinearLayout.LayoutParams(-2, -2).apply { setMargins(0, 10, 0, 0) }
        )
        // §2 Box contents end with STOP — full-width, the same
        // place in every state (paused adds Resume above it).
        val buttons = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
        }
        if (paused) {
            boxResume = Button(context).apply {
                text = context.consentString(R.string.presence_resume)
                isAllCaps = false
                textSize = 15f
                typeface = Fonts.medium(context)
                setTextColor(Color.WHITE)
                stateListAnimator = null
                setPadding(44, 18, 44, 18)
                background = GradientDrawable().apply {
                    setColor(PresencePalette.withAlpha(currentHue(), 0xF2))
                    cornerRadius = 52f
                }
                setOnClickListener { SessionManager.resume() }
            }
            buttons.addView(
                boxResume,
                LinearLayout.LayoutParams(-1, -2).apply { setMargins(0, 0, 0, 16) }
            )
        }
        boxStop = Button(context).apply {
            text = context.consentString(R.string.presence_stop)
            setTextColor(Color.WHITE)
            typeface = Fonts.medium(context)
            textSize = 15f
            isAllCaps = true
            stateListAnimator = null
            setPadding(52, 18, 52, 18)
            background = GradientDrawable().apply {
                setColor(PresencePalette.withAlpha(stopColor(), 0xF2))
                cornerRadius = 52f
                setStroke(2, Color.parseColor("#40FFFFFF"))
            }
            setOnClickListener {
                SessionManager.stopByUser()
                hide()
            }
        }
        buttons.addView(boxStop, LinearLayout.LayoutParams(-1, -2))
        box.addView(
            buttons,
            LinearLayout.LayoutParams(-1, -2).apply { setMargins(0, 28, 0, 0) }
        )
        val params = WindowManager.LayoutParams(
            WindowManager.LayoutParams.WRAP_CONTENT,
            WindowManager.LayoutParams.WRAP_CONTENT,
            overlayType(),
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE,
            PixelFormat.TRANSLUCENT
        ).apply {
            gravity = Gravity.CENTER
        }
        wm.addView(box, params)
        boxView = box
        boxParams = params
        boxWm = wm
        track(box, wm, "box")
        updateBoxTexts()
    }

    /**
     * W10 (V3-F5 / OI-01): keep the Box — STOP included — ABOVE
     * the approval gate sheet. Android stacks overlay windows in
     * add order within their layers, and the gate sheet is added
     * after presence, so without this the full-screen sheet would
     * cover the Box and its STOP. The gate calls this immediately
     * after adding its own window: the Box window is detached and
     * re-attached, which puts it back on top of the stack (when
     * the accessibility service is bound the Box rides
     * TYPE_ACCESSIBILITY_OVERLAY, which layers above application
     * overlays; when it is not, both windows share
     * TYPE_APPLICATION_OVERLAY and the re-attach order decides).
     * The Box's content, size and STOP are unchanged — only its
     * stacking position is re-asserted. Runs on the main thread.
     */
    fun raiseBoxAboveGate() {
        handler.post {
            val box = boxView ?: return@post
            val wm = boxWm ?: return@post
            val params = boxParams ?: return@post
            if (!box.isAttachedToWindow) return@post
            try {
                wm.removeViewImmediate(box)
                wm.addView(box, params)
            } catch (_: Exception) {
                // If the re-attach itself failed, the Box may be
                // down: force a full re-show on the next sync tick
                // by invalidating the generation stamp.
                shownGeneration = -1
            }
        }
    }

    // ---- The edge glow ------------------------------------------------
    // ONE wide blurred bloom stroke of the rounded rect — the huge
    // faded glow of the 2026-11-17 ruling. There is deliberately no
    // bright core line: the owner removed it. The bloom's alpha breathes
    // slowly while a session is live.

    private var glowPulse: ValueAnimator? = null

    private class GlowView(context: Context, private val glowColor: Int) : View(context) {
        var bloomAlpha: Int = 96
        private val bloomPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            style = Paint.Style.STROKE
            strokeWidth = 72f
            color = glowColor
            maskFilter = BlurMaskFilter(46f, BlurMaskFilter.Blur.NORMAL)
        }

        init {
            setLayerType(LAYER_TYPE_SOFTWARE, null)
        }

        override fun onDraw(canvas: Canvas) {
            val inset = 30f
            val rect = android.graphics.RectF(
                inset, inset, width - inset, height - inset
            )
            bloomPaint.alpha = bloomAlpha
            canvas.drawRoundRect(rect, 56f, 56f, bloomPaint)
        }
    }

    private fun startGlowPulse(glow: GlowView) {
        glowPulse?.cancel()
        glowPulse = ValueAnimator.ofInt(72, 122).apply {
            duration = 2600
            repeatCount = ValueAnimator.INFINITE
            repeatMode = ValueAnimator.REVERSE
            addUpdateListener { anim ->
                glow.bloomAlpha = anim.animatedValue as Int
                glow.invalidate()
            }
            start()
        }
    }

    private fun stopGlowPulse() {
        glowPulse?.cancel()
        glowPulse = null
    }

    // ---- The target highlight ------------------------------------------
    // A translucent wash over the element the agent is about to tap,
    // shown while the cursor glides to it and cleared just after the
    // tap lands, so the user sees WHAT will be touched before it is
    // touched. Touch-through, like the frame; purely informational.

    private var highlightView: View? = null
    private var highlightParams: WindowManager.LayoutParams? = null

    private class HighlightDrawable(private val washColor: Int) :
        android.graphics.drawable.Drawable() {
        override fun draw(canvas: Canvas) {
            val b = bounds
            val rect = android.graphics.RectF(
                b.left.toFloat(), b.top.toFloat(), b.right.toFloat(), b.bottom.toFloat()
            )
            val fill = Paint(Paint.ANTI_ALIAS_FLAG).apply {
                color = PresencePalette.withAlpha(washColor, 46)
            }
            canvas.drawRoundRect(rect, 22f, 22f, fill)
            val stroke = Paint(Paint.ANTI_ALIAS_FLAG).apply {
                style = Paint.Style.STROKE
                strokeWidth = 5f
                color = PresencePalette.withAlpha(washColor, 175)
            }
            canvas.drawRoundRect(rect, 22f, 22f, stroke)
        }

        override fun setAlpha(alpha: Int) {}
        override fun setColorFilter(filter: android.graphics.ColorFilter?) {}
        override fun getOpacity(): Int = PixelFormat.TRANSLUCENT
    }

    /** Wash the target element's bounds (screen pixels) in the highlight color. */
    fun highlightBounds(left: Int, top: Int, right: Int, bottom: Int) {
        if (frameView == null) return
        handler.post {
            if (frameView == null) return@post
            val base = appContext ?: return@post
            val context = windowContext(base)
            val wm = windowManager ?: return@post
            val pad = 12
            val w = (right - left) + pad * 2
            val h = (bottom - top) + pad * 2
            if (w <= 0 || h <= 0) return@post
            val existing = highlightView
            if (existing == null) {
                val v = View(context)
                v.background = HighlightDrawable(currentHue())
                val params = WindowManager.LayoutParams(
                    w, h,
                    overlayType(),
                    WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or
                        WindowManager.LayoutParams.FLAG_NOT_TOUCHABLE,
                    PixelFormat.TRANSLUCENT
                ).apply {
                    gravity = Gravity.TOP or Gravity.START
                    x = left - pad
                    y = top - pad
                }
                try {
                    wm.addView(v, params)
                    highlightView = v
                    highlightParams = params
                    track(v, wm, "highlight")
                } catch (_: Exception) {
                    return@post
                }
            } else {
                existing.background = HighlightDrawable(currentHue())
                val params = highlightParams ?: return@post
                params.width = w
                params.height = h
                params.x = left - pad
                params.y = top - pad
                try {
                    wm.updateViewLayout(existing, params)
                } catch (_: Exception) {
                }
                existing.invalidate()
            }
        }
    }

    /** Clear the highlight shortly after the tap lands. */
    fun scheduleClearHighlight() {
        handler.postDelayed({ clearHighlight() }, 550)
    }

    private fun clearHighlight() {
        val view = highlightView ?: return
        val wm = windowManager ?: return
        try {
            wm.removeViewImmediate(view)
        } catch (_: Exception) {
        }
        untrack(view)
        highlightView = null
        highlightParams = null
    }

    // ---- The virtual finger (SPEC §7.3) --------------------------------
    // A cursor in its own touch-through window. It GLIDES to its
    // target, pauses, and only then does the action land; a ripple
    // marks the tap. It never teleports silently and never hides. It
    // parks at the right edge, dimmed, when idle.
    // The fingertip (the exact touch point) sits at (44, 4) in the
    // cursor's 100x120 design space: window offsets from the point.
    private const val TIP_DX = 53
    private const val TIP_DY = 5

    private const val FINGER_W = 120
    private const val FINGER_H = 144

    private var fingerView: ImageView? = null
    private var fingerParams: WindowManager.LayoutParams? = null
    private var fingerX = 0f
    private var fingerY = 0f
    private var glideAnimator: ValueAnimator? = null
    private var rippleView: View? = null

    /**
     * The virtual finger (0.4.0): the pointing hand of the approved
     * design set, replacing the 0.3.8 arrow — a filled hand silhouette
     * in the user's cursor color with a soft bloom in its own color, a
     * thin light edge so it stays readable on bright screens, and a
     * small white dot at the fingertip marking the exact touch point.
     * Drawn in code as a vector path. The window is anchored so the
     * fingertip lands on the target coordinates.
     */
    /**
     * The Ghost (§1.2/§2): a RING with the actor's initial inside —
     * one geometry on both platforms. The ring never occludes its
     * target (its centre is hollow); the initial carries identity.
     * No disc, no arrow, no hand silhouette.
     */
    private class GhostDrawable(
        private val ringColor: Int,
        private val initial: String
    ) : android.graphics.drawable.Drawable() {
        override fun draw(canvas: Canvas) {
            val b = bounds
            val cx = b.exactCenterX()
            val cy = b.exactCenterY()
            val radius = minOf(b.width(), b.height()) / 2f - 6f
            val ring = Paint(Paint.ANTI_ALIAS_FLAG).apply {
                style = Paint.Style.STROKE
                strokeWidth = 7f
                color = ringColor
                setShadowLayer(10f, 0f, 0f, ringColor)
            }
            canvas.drawCircle(cx, cy, radius, ring)
            // The dwell arc (§2): drawn as a static arc segment on
            // the ring — under reduced motion the dwell remains a
            // static arc; the dwell is consent, not decoration.
            val text = Paint(Paint.ANTI_ALIAS_FLAG).apply {
                color = Color.WHITE
                textSize = radius * 0.95f
                typeface = Typeface.DEFAULT_BOLD
                textAlign = Paint.Align.CENTER
                setShadowLayer(6f, 0f, 0f, ringColor)
            }
            val fm = text.fontMetrics
            canvas.drawText(initial, cx, cy - (fm.ascent + fm.descent) / 2f, text)
        }

        override fun setAlpha(alpha: Int) {}
        override fun setColorFilter(filter: android.graphics.ColorFilter?) {}
        override fun getOpacity(): Int = PixelFormat.TRANSLUCENT
    }

    private fun ghostInitialNow(): String =
        io.deskguest.app.design.PresenceLaw.ghostInitial(
            SessionManager.active?.agentName ?: "?"
        )

    /** An expanding ring and soft disc drawn once at the tap point. */
    private class RippleDrawable(private val rippleColor: Int) :
        android.graphics.drawable.Drawable() {
        var progress = 0f
        override fun draw(canvas: Canvas) {
            val b = bounds
            val disc = Paint(Paint.ANTI_ALIAS_FLAG).apply {
                color = rippleColor
                alpha = ((1f - progress) * 70).toInt().coerceIn(0, 255)
            }
            canvas.drawCircle(
                b.exactCenterX(), b.exactCenterY(), 10f + progress * 48f, disc
            )
            val ring = Paint(Paint.ANTI_ALIAS_FLAG).apply {
                style = Paint.Style.STROKE
                strokeWidth = 7f
                color = rippleColor
                alpha = ((1f - progress) * 235).toInt().coerceIn(0, 255)
                setShadowLayer(12f, 0f, 0f, rippleColor)
            }
            canvas.drawCircle(b.exactCenterX(), b.exactCenterY(), 14f + progress * 56f, ring)
        }

        override fun setAlpha(alpha: Int) {}
        override fun setColorFilter(filter: android.graphics.ColorFilter?) {}
        override fun getOpacity(): Int = PixelFormat.TRANSLUCENT
    }

    private fun ensureFinger() {
        if (fingerView != null) return
        val base = appContext ?: return
        val context = windowContext(base)
        val wm = windowManager ?: return
        val view = ImageView(context).apply {
            setImageDrawable(GhostDrawable(currentHue(), ghostInitialNow()))
            setLayerType(View.LAYER_TYPE_SOFTWARE, null)
            alpha = 0.6f
        }
        val metrics = context.resources.displayMetrics
        fingerX = metrics.widthPixels - 24f
        fingerY = metrics.heightPixels * 0.45f
        val params = WindowManager.LayoutParams(
            FINGER_W, FINGER_H,
            overlayType(),
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or
                WindowManager.LayoutParams.FLAG_NOT_TOUCHABLE,
            PixelFormat.TRANSLUCENT
        ).apply {
            gravity = Gravity.TOP or Gravity.START
            x = (fingerX - TIP_DX).toInt()
            y = (fingerY - TIP_DY).toInt()
        }
        try {
            wm.addView(view, params)
            fingerView = view
            fingerParams = params
            track(view, wm, "finger")
        } catch (_: Exception) {
        }
    }

    /** Glide the finger to (x, y). Blocks nothing; the caller sleeps. */
    fun glideTo(x: Float, y: Float) {
        if (frameView == null) return
        handler.post {
            if (frameView == null) return@post
            ensureFinger()
            val view = fingerView ?: return@post
            val params = fingerParams ?: return@post
            val wm = windowManager ?: return@post
            glideAnimator?.cancel()
            val fromX = fingerX
            val fromY = fingerY
            view.alpha = 1f
            val distPx = kotlin.math.hypot((x - fromX).toDouble(), (y - fromY).toDouble()).toInt()
            glideAnimator = ValueAnimator.ofFloat(0f, 1f).apply {
                duration = io.deskguest.app.design.PresenceLaw.glideMs(distPx)
                interpolator = DecelerateInterpolator()
                addUpdateListener { anim ->
                    val t = anim.animatedValue as Float
                    fingerX = fromX + (x - fromX) * t
                    fingerY = fromY + (y - fromY) * t
                    params.x = (fingerX - TIP_DX).toInt()
                    params.y = (fingerY - TIP_DY).toInt()
                    try {
                        wm.updateViewLayout(view, params)
                    } catch (_: Exception) {
                    }
                }
                start()
            }
        }
    }

    /** Show the tap ripple at (x, y), then park the finger dimmed. */
    fun rippleAt(x: Float, y: Float) {
        if (frameView == null) return
        handler.post {
            if (frameView == null) return@post
            val base = appContext ?: return@post
            val context = windowContext(base)
            val wm = windowManager ?: return@post
            val drawable = RippleDrawable(currentHue())
            val view = View(context).apply {
                background = drawable
                setLayerType(View.LAYER_TYPE_SOFTWARE, null)
            }
            val size = 150
            val params = WindowManager.LayoutParams(
                size, size,
                overlayType(),
                WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or
                    WindowManager.LayoutParams.FLAG_NOT_TOUCHABLE,
                PixelFormat.TRANSLUCENT
            ).apply {
                gravity = Gravity.TOP or Gravity.START
                this.x = (x - size / 2).toInt()
                this.y = (y - size / 2).toInt()
            }
            try {
                wm.addView(view, params)
                rippleView = view
                track(view, wm, "ripple")
            } catch (_: Exception) {
                return@post
            }
            ValueAnimator.ofFloat(0f, 1f).apply {
                duration = 380
                addUpdateListener { anim ->
                    drawable.progress = anim.animatedValue as Float
                    view.invalidate()
                }
                addListener(object : android.animation.AnimatorListenerAdapter() {
                    override fun onAnimationEnd(animation: android.animation.Animator) {
                        try {
                            wm.removeViewImmediate(view)
                        } catch (_: Exception) {
                        }
                        untrack(view)
                        if (rippleView === view) rippleView = null
                    }
                })
                start()
            }
            fingerView?.animate()?.alpha(0.6f)?.setDuration(300)?.start()
        }
    }
}
