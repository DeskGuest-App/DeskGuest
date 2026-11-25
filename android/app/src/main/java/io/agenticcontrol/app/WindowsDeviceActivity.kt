package io.agenticcontrol.app

import android.app.Activity
import android.graphics.BitmapFactory
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.Gravity
import android.view.MotionEvent
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import io.agenticcontrol.app.mesh.MeshClient
import io.agenticcontrol.app.mesh.MeshProtocol
import io.agenticcontrol.app.mesh.MeshStore
import io.agenticcontrol.app.strings.consentString
import io.agenticcontrol.app.ui.Fonts
import io.agenticcontrol.app.ui.UiKit

/**
 * The Windows device page (0.4.0, stage 4) — the approved mesh
 * design: live desktop preview, the companion's state, a trackpad
 * with a modifier bar, Hand off to your AI, Disconnect.
 *
 * Honesty rule: the preview shows only bytes the companion actually
 * served. Until the Windows companion exists (PLAN-WINDOWS W1–W3),
 * polls go unanswered and the page says "companion offline" — there
 * is no placeholder image and no simulated state.
 */
class WindowsDeviceActivity : Activity() {

    private lateinit var root: LinearLayout
    private val handler = Handler(Looper.getMainLooper())
    private var client: MeshClient? = null
    private var state: MeshProtocol.CompanionState? = null
    private var missedPolls = 0
    private var polling = false
    private var streamViewer: StreamViewer? = null

    private val poll = object : Runnable {
        override fun run() {
            pollOnce()
            handler.postDelayed(this, POLL_MS)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        root = UiKit.page(this)
        rebuildClient()
        refresh()
    }

    override fun onResume() {
        super.onResume()
        polling = true
        handler.removeCallbacks(poll)
        handler.post(poll)
    }

    override fun onPause() {
        super.onPause()
        polling = false
        handler.removeCallbacks(poll)
        streamViewer?.stop()
        streamViewer = null
    }

    private fun rebuildClient() {
        // W6 Task 0: every mesh request carries the pairing's bearer
        // in the Authorization header. Token source, in order: the
        // mesh store's saved companion token, then the live pairing
        // store's latest pairing token (the same store the MCP
        // surface resolves bearers against). No token → MeshClient
        // sends no header at all.
        client = MeshStore.baseUrl(this)?.let { url ->
            MeshClient(url) {
                MeshStore.bearerToken(this)
                    ?: io.agenticcontrol.app.server.ControlService.sharedPairingStore
                        ?.latest()?.token
            }
        }
    }

    private fun pollOnce() {
        val c = client ?: return
        Thread {
            val fetched = c.fetchState()
            val preview = if (fetched?.previewAvailable == true) c.fetchPreview() else null
            c.postHeartbeat("Android", watching = true)
            runOnUiThread {
                if (!polling) return@runOnUiThread
                if (fetched != null) {
                    missedPolls = 0
                    state = fetched
                } else {
                    missedPolls++
                }
                refresh(preview)
            }
        }.start()
    }

    private val online: Boolean
        get() = client != null && state != null && missedPolls < 2

    // ---------- rendering ----------

    private fun refresh(previewBytes: ByteArray? = null) {
        // While a session stream is live it owns the page: the
        // stream has its own info loop, and rebuilding the tree
        // would tear down its SurfaceView mid-stream.
        if (streamViewer != null) return
        root.removeAllViews()
        renderHeader()
        if (client == null) {
            renderSetup()
            return
        }
        renderPreview(previewBytes)
        renderState()
        renderStreamSection()
        renderTrackpad()
        renderActions()
        renderAddressRow()
    }

    /**
     * The session stream section (Block D, mesh contract v2): the
     * phone joins a Slice 3 session's real H.264 stream as a named
     * participant. The companion's stream layer enforces the floor —
     * this section only asks, and shows refusals as they come back.
     */
    private fun renderStreamSection() {
        if (!online) return
        root.addView(UiKit.sectionTitle(this, "Session stream"))
        val prefs = getSharedPreferences("mesh", MODE_PRIVATE)
        val sessionField = EditText(this).apply {
            hint = "Session ID"
            isSingleLine = true
            textSize = 15f
            typeface = Fonts.regular(this@WindowsDeviceActivity)
            setTextColor(UiKit.TEXT)
            background = null
            setText(intent.getStringExtra("sessionId") ?: prefs.getString("stream_session", ""))
        }
        val userField = EditText(this).apply {
            hint = "Your participant user ID"
            isSingleLine = true
            textSize = 15f
            typeface = Fonts.regular(this@WindowsDeviceActivity)
            setTextColor(UiKit.TEXT)
            background = null
            setText(intent.getStringExtra("userId") ?: prefs.getString("stream_user", ""))
        }
        root.addView(sessionField)
        root.addView(userField)
        root.addView(UiKit.primaryButton(this, "Watch the session stream") {
            val c = client ?: return@primaryButton
            val sessionId = sessionField.text.toString().trim()
            val userId = userField.text.toString().trim()
            if (sessionId.isEmpty() || userId.isEmpty()) {
                Toast.makeText(this, "Enter the session ID and your user ID", Toast.LENGTH_SHORT).show()
                return@primaryButton
            }
            prefs.edit()
                .putString("stream_session", sessionId)
                .putString("stream_user", userId)
                .apply()
            val viewer = StreamViewer(this, c, sessionId, userId)
            streamViewer = viewer
            viewer.onStopped = {
                if (streamViewer === viewer) {
                    streamViewer = null
                    refresh()
                }
            }
            root.removeAllViews()
            renderHeader()
            root.addView(UiKit.sectionTitle(this, "Session stream"))
            root.addView(viewer.view)
            for (v in viewer.statusViews()) root.addView(v)
            viewer.start()
        })
        root.addView(UiKit.muted(
            this,
            "The stream follows the session's floor: only the floor holder's " +
                "input is accepted, and the companion says so when it refuses."
        ))
    }

    private fun renderHeader() {
        val header = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        header.addView(TextView(this).apply {
            text = "‹"
            textSize = 30f
            setTextColor(UiKit.TEXT)
            setPadding(0, 0, UiKit.dp(this@WindowsDeviceActivity, 12), UiKit.dp(this@WindowsDeviceActivity, 4))
            isClickable = true
            setOnClickListener { finish() }
        })
        header.addView(TextView(this).apply {
            text = "Windows 11"
            textSize = 24f
            typeface = Fonts.medium(this@WindowsDeviceActivity)
            setTextColor(UiKit.TEXT)
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        })
        val pillText = when {
            client == null -> "Not set up"
            online -> "Connected · ${client?.lastRoundTripMs?.takeIf { it >= 0 }?.let { "$it ms" } ?: ""}".trim()
            else -> "Offline"
        }
        header.addView(UiKit.chip(
            this, pillText,
            if (online) UiKit.ChipKind.GOOD else UiKit.ChipKind.NEUTRAL
        ))
        root.addView(header)
        root.addView(UiKit.muted(
            this,
            // bd-and-rest F7 fix: no invented device name — the
            // page's own rule is no simulated state. Unknown is
            // shown as unknown.
            state?.deviceName?.ifBlank { null } ?: "Unknown device"
        ))
    }

    private fun renderSetup() {
        root.addView(UiKit.body(
            this,
            "This page talks to the Windows companion on your laptop over the mesh " +
                "protocol. The companion is not installed yet — when it is, enter its " +
                "address here and this page shows the live desktop, its state, and " +
                "drives it by hand."
        ))
        val field = EditText(this).apply {
            hint = "Companion address (e.g. http://100.119.105.54:8730)"
            isSingleLine = true
            textSize = 15f
            typeface = Fonts.regular(this@WindowsDeviceActivity)
            setTextColor(UiKit.TEXT)
            background = null
        }
        root.addView(field)
        root.addView(UiKit.primaryButton(this, "Save address") {
            val value = field.text.toString().trim()
            if (value.isEmpty()) {
                Toast.makeText(this, "Enter the companion address", Toast.LENGTH_SHORT).show()
                return@primaryButton
            }
            if (!MeshStore.isAcceptableBaseUrl(value)) {
                Toast.makeText(this, "That address is not a tailnet, loopback, or LAN address — the companion address was not saved", Toast.LENGTH_LONG).show()
                return@primaryButton
            }
            MeshStore.saveBaseUrl(this, value)
            rebuildClient()
            state = null
            missedPolls = 0
            refresh()
        })
    }

    private fun renderPreview(previewBytes: ByteArray?) {
        val card = UiKit.card(this)
        val bitmap = previewBytes?.let {
            try {
                BitmapFactory.decodeByteArray(it, 0, it.size)
            } catch (e: Exception) {
                null
            }
        }
        if (bitmap != null) {
            card.addView(ImageView(this).apply {
                setImageBitmap(bitmap)
                adjustViewBounds = true
                scaleType = ImageView.ScaleType.FIT_CENTER
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
                )
            })
        } else {
            card.addView(UiKit.body(
                this,
                if (online) {
                    "No preview right now — the companion is not sending one."
                } else {
                    "No preview — companion offline. The live desktop appears here " +
                        "once the companion answers."
                }
            ))
        }
        root.addView(card)
    }

    private fun renderState() {
        val s = state
        val label = when {
            !online -> "Companion offline"
            s == null -> "Waiting for the companion…"
            s.state == MeshProtocol.State.AI_DRIVING ->
                // FR-123: a blank companion agent name is stated
                // plainly as unnamed through the U8 strings door —
                // never the generic stand-in "The agent".
                (if (s.agentName.isBlank()) {
                    consentString(R.string.mesh_unnamed_agent_driving)
                } else {
                    "${s.agentName} is driving"
                }) + " · ${s.sessionSeconds}s · ${s.actions} actions"
            s.state == MeshProtocol.State.HUMAN_MANUAL -> "You are driving by hand"
            s.state == MeshProtocol.State.IDLE -> "Idle — nobody is driving"
            else -> "State unknown"
        }
        root.addView(UiKit.reportRow(this, online, "Desktop state", label))
        if (online && s?.intent?.isNotBlank() == true) {
            root.addView(UiKit.muted(this, "Intent: ${s.intent}"))
        }
    }

    private fun renderTrackpad() {
        root.addView(UiKit.sectionTitle(this, "Trackpad"))
        val pad = View(this).apply {
            background = UiKit.dashedDrawable(
                this@WindowsDeviceActivity, UiKit.HAIRLINE, UiKit.SUBTLE
            )
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, UiKit.dp(this@WindowsDeviceActivity, 190)
            )
        }
        var lastX = 0f
        var lastY = 0f
        var downAt = 0L
        var moved = 0f
        var lastSent = 0L
        pad.setOnTouchListener { view, event ->
            if (!online) return@setOnTouchListener false
            when (event.actionMasked) {
                MotionEvent.ACTION_DOWN -> {
                    lastX = event.x
                    lastY = event.y
                    downAt = System.currentTimeMillis()
                    moved = 0f
                    true
                }
                MotionEvent.ACTION_MOVE -> {
                    val dx = (event.x - lastX) / view.width.toDouble()
                    val dy = (event.y - lastY) / view.height.toDouble()
                    moved += kotlin.math.abs(event.x - lastX) + kotlin.math.abs(event.y - lastY)
                    lastX = event.x
                    lastY = event.y
                    val now = System.currentTimeMillis()
                    if (now - lastSent >= 40 && (dx != 0.0 || dy != 0.0)) {
                        lastSent = now
                        sendInput(MeshProtocol.inputPointer(dx, dy))
                    }
                    true
                }
                MotionEvent.ACTION_UP -> {
                    val quick = System.currentTimeMillis() - downAt < 300
                    if (quick && moved < 12f) {
                        sendInput(MeshProtocol.inputButton("left", "click"))
                    }
                    true
                }
                else -> false
            }
        }
        root.addView(pad)

        val bar = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER
        }
        fun barButton(label: String, action: () -> Unit): Button =
            UiKit.outlineButton(this, label, action).apply {
                layoutParams = LinearLayout.LayoutParams(
                    0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f
                )
            }
        bar.addView(barButton("Left Click") {
            sendInput(MeshProtocol.inputButton("left", "click"))
        })
        bar.addView(barButton("Right Click") {
            sendInput(MeshProtocol.inputButton("right", "click"))
        })
        bar.addView(barButton("Win Key") {
            sendInput(MeshProtocol.inputKey("win"))
        })
        bar.addView(barButton("Alt+Tab") {
            sendInput(MeshProtocol.inputKey("alt_tab"))
        })
        root.addView(bar)

        val typeField = EditText(this).apply {
            hint = "Type here, then Send Keys"
            isSingleLine = true
            textSize = 15f
            typeface = Fonts.regular(this@WindowsDeviceActivity)
            setTextColor(UiKit.TEXT)
            background = null
        }
        root.addView(typeField)
        root.addView(UiKit.outlineButton(this, "Send Keys") {
            val text = typeField.text.toString()
            if (text.isNotEmpty()) {
                sendInput(MeshProtocol.inputText(text))
                typeField.text.clear()
            }
        })
        if (!online) {
            root.addView(UiKit.muted(
                this, "Manual drive is live only while the companion is connected."
            ))
        }
    }

    private fun renderActions() {
        // bd-and-rest F7 fix: no agent is privileged by identity —
        // the handoff names the owner's AI generically (the paired
        // agent's own name lives on the companion, not here).
        root.addView(UiKit.primaryButton(this, "Hand off to your AI") {
            val c = client ?: return@primaryButton
            Thread {
                val ok = c.postHandoff()
                runOnUiThread {
                    Toast.makeText(
                        this,
                        if (ok) "Handed off — your AI has the desktop"
                        else "The companion did not answer the handoff",
                        Toast.LENGTH_SHORT
                    ).show()
                }
            }.start()
        })
        root.addView(UiKit.outlineButton(this, "Disconnect") {
            val c = client
            Thread { c?.postDisconnect() }.start()
            finish()
        })
    }

    private fun renderAddressRow() {
        root.addView(UiKit.navRow(
            this, "Companion address", MeshStore.baseUrl(this) ?: ""
        ) {
            MeshStore.clear(this)
            rebuildClient()
            state = null
            missedPolls = 0
            refresh()
        })
    }

    /** bd-and-rest F12 fix: input goes through ONE single-threaded
     *  executor per screen — a Thread-per-event could deliver a
     *  click before the pointer move that preceded it. Order on
     *  this executor is send order, by construction. */
    private val inputExecutor = java.util.concurrent.Executors.newSingleThreadExecutor()

    private fun sendInput(event: org.json.JSONObject) {
        val c = client ?: return
        inputExecutor.execute { c.postInput(event) }
    }

    companion object {
        private const val POLL_MS = 2_000L
    }
}
