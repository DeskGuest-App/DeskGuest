package io.deskguest.app.presence

import android.graphics.Path

/**
 * Shared presence geometry (0.4.0): the pointing-hand cursor path,
 * drawn both by the live overlay (PresenceOverlay's finger) and by
 * the settings screen's live preview, so what the owner previews is
 * the shape that actually appears. Design space 100x120, fingertip
 * at (44, 4).
 */
object PresenceShapes {

    const val HAND_TIP_X = 44f
    const val HAND_TIP_Y = 4f
    const val HAND_SPACE_W = 100f
    const val HAND_SPACE_H = 120f

    /** The pointing hand: index raised, other fingers curled, thumb
     *  tucked across the palm. A fresh Path in design space. */
    fun handPath(): Path = Path().apply {
        moveTo(44f, 4f)
        cubicTo(49f, 4f, 51f, 9f, 51f, 16f)
        lineTo(51f, 42f)
        cubicTo(55f, 34f, 63f, 35f, 64f, 44f)
        lineTo(65f, 54f)
        cubicTo(69f, 49f, 75f, 52f, 75f, 60f)
        lineTo(75f, 68f)
        cubicTo(79f, 66f, 83f, 70f, 82f, 78f)
        cubicTo(81f, 92f, 74f, 104f, 62f, 109f)
        cubicTo(52f, 113f, 40f, 112f, 32f, 105f)
        cubicTo(25f, 99f, 23f, 90f, 25f, 80f)
        lineTo(27f, 68f)
        cubicTo(23f, 62f, 25f, 53f, 31f, 51f)
        cubicTo(35f, 50f, 38f, 53f, 39f, 58f)
        lineTo(40f, 44f)
        lineTo(40f, 16f)
        cubicTo(40f, 9f, 41f, 4f, 44f, 4f)
        close()
    }
}
