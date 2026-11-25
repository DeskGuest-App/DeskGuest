package io.agenticcontrol.app.ui

import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Path
import android.view.View

/**
 * The app mark (0.4.0, from the approved design set): two interlinked
 * diamonds — an outer diamond outline and a smaller filled diamond
 * where they cross — drawn in code, in the ink color, on a soft
 * neutral tile. No image assets, no generator credit; the mark is
 * original to this app.
 */
class LogoView(context: Context, private val tile: Boolean = true) : View(context) {

    private val tilePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = 0xFFF3F4F6.toInt()
        style = Paint.Style.FILL
    }
    private val strokePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = UiKit.TEXT
        style = Paint.Style.STROKE
        strokeJoin = Paint.Join.ROUND
        strokeCap = Paint.Cap.ROUND
    }
    private val fillPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = UiKit.TEXT
        style = Paint.Style.FILL
    }

    // DeskGuest brand kit (A3 GREETER, decision 2026-11-23): the kit
    // character/app mark is the launch-surface mark. The drawn diamond
    // mark below remains only as a fallback if the asset is missing.
    private val kitMark: android.graphics.Bitmap? by lazy {
        try {
            val resId = context.resources.getIdentifier(
                "deskguest_mark", "drawable", context.packageName)
            if (resId != 0) android.graphics.BitmapFactory.decodeResource(context.resources, resId)
            else null
        } catch (_: Throwable) { null }
    }

    override fun onDraw(canvas: Canvas) {
        kitMark?.let { bmp ->
            val dst = android.graphics.RectF(0f, 0f, width.toFloat(), height.toFloat())
            canvas.drawBitmap(bmp, null, dst, Paint(Paint.ANTI_ALIAS_FLAG or Paint.FILTER_BITMAP_FLAG))
            return
        }
        val w = width.toFloat()
        val h = height.toFloat()
        val size = minOf(w, h)
        if (tile) {
            val r = size * 0.24f
            canvas.drawRoundRect(0f, 0f, w, h, r, r, tilePaint)
        }
        // Design space 100x100, centered.
        val scale = size / 100f
        val dx = (w - size) / 2f
        val dy = (h - size) / 2f
        fun x(v: Float) = dx + v * scale
        fun y(v: Float) = dy + v * scale

        strokePaint.strokeWidth = 6.5f * scale
        // Outer diamond, shifted left.
        val outer = Path().apply {
            moveTo(x(38f), y(16f))
            lineTo(x(62f), y(50f))
            lineTo(x(38f), y(84f))
            lineTo(x(14f), y(50f))
            close()
        }
        canvas.drawPath(outer, strokePaint)
        // Second diamond outline, shifted right — the interlink.
        val second = Path().apply {
            moveTo(x(64f), y(16f))
            lineTo(x(88f), y(50f))
            lineTo(x(64f), y(84f))
            lineTo(x(40f), y(50f))
            close()
        }
        canvas.drawPath(second, strokePaint)
        // The crossing diamond, filled.
        val core = Path().apply {
            moveTo(x(51f), y(36f))
            lineTo(x(65f), y(50f))
            lineTo(x(51f), y(64f))
            lineTo(x(37f), y(50f))
            close()
        }
        canvas.drawPath(core, fillPaint)
    }
}
