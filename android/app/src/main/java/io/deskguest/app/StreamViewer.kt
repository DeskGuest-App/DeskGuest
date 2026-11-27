package io.deskguest.app

import android.content.Context
import android.graphics.Color
import android.media.MediaCodec
import android.media.MediaFormat
import android.view.Gravity
import android.view.MotionEvent
import android.view.SurfaceHolder
import android.view.SurfaceView
import android.view.ViewGroup
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.TextView
import io.deskguest.app.mesh.MeshClient
import io.deskguest.app.mesh.MeshProtocol
import io.deskguest.app.ui.Fonts
import io.deskguest.app.ui.UiKit
import java.nio.ByteBuffer

/**
 * The session-stream viewer (Block D, mesh contract v2) — renders
 * the companion's real H.264 session stream on this phone:
 *
 *  - Frames are pulled from /mesh/stream/frame and validated by the
 *    fail-closed DGSF parser BEFORE MediaCodec ever sees them; a
 *    malformed envelope is counted and dropped, never decoded.
 *  - MediaCodec ("video/avc") decodes to the SurfaceView; the
 *    decoder is (re)configured from each keyframe's own SPS/PPS.
 *  - The roster + floor line come from /mesh/stream/info and are
 *    shown as the companion reports them — including refusals: when
 *    this participant does not hold the floor, input goes out only
 *    to be answered by the stream layer's refusal, and the refusal
 *    text is shown (the floor rule lives on the companion, this
 *    view just refuses to hide it).
 *  - The floor holder's name rides the frame header's cursor
 *    position as a chip over the picture — D35's named cursor. When
 *    the AI holds the floor the chip carries the agent's name (its
 *    ghost pointer); the host's own presence stays on the host.
 *
 * Touch on the picture sends absolute pointer input in stream
 * coordinates; a tap also clicks. Everything stops the moment the
 * view detaches or the stream is stopped — no background decode.
 */
class StreamViewer(
    private val context: Context,
    private val client: MeshClient,
    private val sessionId: String,
    private val userId: String
) {
    val view: FrameLayout = FrameLayout(context)
    private val surface = SurfaceView(context)
    private val statusLine: TextView = UiKit.muted(context, "Stream: not started")
    private val floorLine: TextView = UiKit.muted(context, "")
    private val rosterView: LinearLayout = LinearLayout(context).apply {
        orientation = LinearLayout.VERTICAL
    }
    private val cursorChip: TextView = TextView(context).apply {
        textSize = 11f
        typeface = Fonts.medium(context)
        setTextColor(Color.WHITE)
        setBackgroundColor(0xCC1F6FEB.toInt())
        setPadding(UiKit.dp(context, 6), UiKit.dp(context, 2), UiKit.dp(context, 6), UiKit.dp(context, 2))
        visibility = android.view.View.GONE
    }

    /** Fires (on the main thread) when the stream ends — by the
     *  Stop control, a refusal, or the session ending — so the host
     *  page can resume its normal rendering. */
    var onStopped: (() -> Unit)? = null

    @Volatile private var running = false
    private var decoder: MediaCodec? = null
    private var decoderConfiguredFor = ""
    private var lastSeq = 0L
    private var framesShown = 0
    private var framesInvalid = 0
    private var waitingForKeyframe = true
    private var info: MeshProtocol.StreamInfo? = null
    private var frameWidth = 0
    private var frameHeight = 0

    init {
        surface.layoutParams = FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, UiKit.dp(context, 220)
        )
        view.addView(surface)
        view.addView(cursorChip)
        val stopControl = TextView(context).apply {
            text = "Stop stream"
            textSize = 12f
            typeface = Fonts.medium(context)
            setTextColor(Color.WHITE)
            // W92: STOP token hue (#DC2626) at this control's
            // pre-existing 0xCC alpha — it is a live Stop control.
            setBackgroundColor(0xCCDC2626.toInt())
            setPadding(UiKit.dp(context, 8), UiKit.dp(context, 4), UiKit.dp(context, 8), UiKit.dp(context, 4))
            layoutParams = FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT,
                Gravity.TOP or Gravity.END
            )
            setOnClickListener {
                Thread {
                    client.streamStop(sessionId)
                }.start()
                stop()
            }
        }
        view.addView(stopControl)
        surface.setOnTouchListener { v, event ->
            if (frameWidth == 0 || frameHeight == 0) return@setOnTouchListener false
            val x = (event.x / v.width * frameWidth).toInt().coerceIn(0, frameWidth - 1)
            val y = (event.y / v.height * frameHeight).toInt().coerceIn(0, frameHeight - 1)
            when (event.actionMasked) {
                MotionEvent.ACTION_DOWN, MotionEvent.ACTION_MOVE ->
                    sendStreamInput(MeshProtocol.inputPointerAbs(x, y))
                MotionEvent.ACTION_UP -> {
                    sendStreamInput(MeshProtocol.inputPointerAbs(x, y))
                    sendStreamInput(MeshProtocol.inputButton("left", "click"))
                }
            }
            true
        }
    }

    fun statusViews(): List<android.view.View> = listOf(statusLine, floorLine, rosterView)

    fun start() {
        if (running) return
        running = true
        Thread { startLoop() }.start()
    }

    fun stop() = finishStream()

    private var stopNotified = false

    @Synchronized
    private fun finishStream() {
        running = false
        releaseDecoder()
        if (!stopNotified) {
            stopNotified = true
            post { onStopped?.invoke() }
        }
    }

    private fun startLoop() {
        val reply = client.streamStart(sessionId, userId, 0)
        post {
            statusLine.text = if (reply.ok) "Stream: starting…"
            else "Stream refused: ${reply.error}"
        }
        if (!reply.ok) {
            finishStream()
            return
        }
        var lastInfoAt = 0L
        while (running) {
            val now = System.currentTimeMillis()
            if (now - lastInfoAt > 2_000) {
                lastInfoAt = now
                val fetched = client.streamInfo(sessionId)
                if (fetched != null) {
                    info = fetched
                    post { renderInfo(fetched) }
                    if (!fetched.streaming && fetched.sessionState != "active") {
                        post { statusLine.text = "Stream ended — session is ${fetched.sessionState}" }
                        break
                    }
                }
            }
            when (val result = client.streamFrame(sessionId, lastSeq)) {
                is MeshClient.FrameResult.Frame -> {
                    lastSeq = result.frame.seq
                    frameWidth = result.frame.width
                    frameHeight = result.frame.height
                    feedDecoder(result.frame)
                    framesShown++
                    post { positionCursorChip(result.frame) }
                }
                MeshClient.FrameResult.NoNewer -> Thread.sleep(15)
                MeshClient.FrameResult.Invalid -> {
                    framesInvalid++
                    post { statusLine.text = "Stream: dropped a malformed frame ($framesInvalid)" }
                }
                is MeshClient.FrameResult.Refused -> {
                    post { statusLine.text = "Stream refused: ${result.reply.error}" }
                    break
                }
            }
        }
        finishStream()
    }

    private fun renderInfo(fetched: MeshProtocol.StreamInfo) {
        floorLine.text = when {
            fetched.floorHolderId == null -> "Floor: nobody holds the floor"
            fetched.floorHolderId == userId -> "Floor: you hold the floor"
            else -> "Floor: ${fetched.floorHolderName ?: fetched.floorHolderId} holds the floor"
        } + " · ${fetched.encoder.ifBlank { "?" }}${if (fetched.hardware) " (hardware)" else ""}" +
            " · ${fetched.capture} · $framesShown frames"
        rosterView.removeAllViews()
        for (p in fetched.roster) {
            rosterView.addView(UiKit.muted(
                context,
                "${p.name} — ${p.role}${if (p.floor == "holds") " · holds the floor" else ""}"
            ))
        }
    }

    private fun positionCursorChip(frame: MeshProtocol.StreamFrame) {
        val holder = info?.floorHolderName
        if (holder.isNullOrBlank() || frame.cursorX < 0 || surface.width == 0) {
            cursorChip.visibility = android.view.View.GONE
            return
        }
        cursorChip.text = holder
        cursorChip.visibility = android.view.View.VISIBLE
        val x = (frame.cursorX.toFloat() / frame.width * surface.width).toInt()
        val y = (frame.cursorY.toFloat() / frame.height * surface.height).toInt()
        cursorChip.x = x.toFloat().coerceIn(0f, (surface.width - 40).coerceAtLeast(0).toFloat())
        cursorChip.y = y.toFloat().coerceIn(0f, (surface.height - 20).coerceAtLeast(0).toFloat())
    }

    private fun sendStreamInput(event: org.json.JSONObject) {
        Thread {
            val reply = client.streamInput(sessionId, userId, event)
            if (!reply.ok) {
                post { statusLine.text = "Input refused: ${reply.error}" }
            }
        }.start()
    }

    // ---- MediaCodec decode ----

    private fun feedDecoder(frame: MeshProtocol.StreamFrame) {
        synchronized(decoderLock) { feedDecoderLocked(frame) }
    }

    private fun feedDecoderLocked(frame: MeshProtocol.StreamFrame) {
        val holder = surface.holder
        if (!holder.surface.isValid) return
        if (frame.keyframe) {
            configureDecoder(holder, frame)
            waitingForKeyframe = false
        }
        val codec = decoder ?: return
        if (waitingForKeyframe) return
        try {
            val inIndex = codec.dequeueInputBuffer(10_000)
            if (inIndex >= 0) {
                val buffer = codec.getInputBuffer(inIndex) ?: ByteBuffer.allocate(0)
                buffer.clear()
                buffer.put(frame.accessUnit)
                codec.queueInputBuffer(
                    inIndex, 0, frame.accessUnit.size,
                    frame.ptsMs * 1000,
                    if (frame.keyframe) MediaCodec.BUFFER_FLAG_KEY_FRAME else 0
                )
            }
            val info = MediaCodec.BufferInfo()
            var outIndex = codec.dequeueOutputBuffer(info, 0)
            while (outIndex >= 0) {
                codec.releaseOutputBuffer(outIndex, true)
                outIndex = codec.dequeueOutputBuffer(info, 0)
            }
        } catch (e: Exception) {
            // A decoder error restarts from the next keyframe — the
            // stream self-heals on the keyframe cadence; the error is
            // surfaced, not hidden.
            post { statusLine.text = "Decoder error (${e.javaClass.simpleName}) — waiting for a keyframe" }
            waitingForKeyframe = true
            releaseDecoder()
        }
    }

    private fun configureDecoder(holder: SurfaceHolder, frame: MeshProtocol.StreamFrame) {
        val signature = "${frame.width}x${frame.height}"
        if (decoder != null && decoderConfiguredFor == signature) return
        releaseDecoder()
        val (sps, pps) = splitConfig(frame.accessUnit) ?: return
        try {
            val format = MediaFormat.createVideoFormat("video/avc", frame.width, frame.height).apply {
                setByteBuffer("csd-0", ByteBuffer.wrap(sps))
                setByteBuffer("csd-1", ByteBuffer.wrap(pps))
            }
            decoder = MediaCodec.createDecoderByType("video/avc").apply {
                configure(format, holder.surface, null, 0)
                start()
            }
            decoderConfiguredFor = signature
        } catch (e: Exception) {
            post { statusLine.text = "Decoder setup failed (${e.javaClass.simpleName})" }
            decoder = null
        }
    }

    /** SPS and PPS NAL payloads (without start codes) from a
     *  keyframe access unit; null when absent. */
    private fun splitConfig(au: ByteArray): Pair<ByteArray, ByteArray>? {
        var sps: ByteArray? = null
        var pps: ByteArray? = null
        var i = 0
        var nalStart = -1
        fun emit(from: Int, to: Int) {
            if (to - from < 1) return
            val type = au[from].toInt() and 0x1F
            val payload = au.copyOfRange(from, to)
            if (type == 7) sps = payload
            if (type == 8) pps = payload
        }
        while (i + 2 < au.size) {
            if (au[i].toInt() == 0 && au[i + 1].toInt() == 0 &&
                (au[i + 2].toInt() == 1 || (i + 3 < au.size && au[i + 2].toInt() == 0 && au[i + 3].toInt() == 1))
            ) {
                val scLen = if (au[i + 2].toInt() == 1) 3 else 4
                if (nalStart >= 0) emit(nalStart, i)
                nalStart = i + scLen
                i += scLen
            } else i++
        }
        if (nalStart >= 0) emit(nalStart, au.size)
        val s = sps
        val p = pps
        return if (s != null && p != null) s to p else null
    }

    /** bd-and-rest F12 fix: ONE lock guards every decoder touch —
     *  the loop thread feeds/configures it, the UI thread releases
     *  it via finishStream; before, release raced the feed with no
     *  shared lock. feedDecoder/configureDecoder hold this lock for
     *  their whole body; releaseDecoder takes it too (re-entrant
     *  for the loop thread's own error path). */
    private val decoderLock = Any()

    private fun releaseDecoder() {
        synchronized(decoderLock) {
            try {
                decoder?.stop()
            } catch (e: Exception) {
            }
            try {
                decoder?.release()
            } catch (e: Exception) {
            }
            decoder = null
            decoderConfiguredFor = ""
        }
    }

    /** bd-and-rest F12 fix: ONE main Handler for the view's whole
     *  life — post() used to allocate a new Handler per call. */
    private val mainHandler = android.os.Handler(android.os.Looper.getMainLooper())

    private fun post(action: () -> Unit) {
        mainHandler.post { action() }
    }
}
