package io.deskguest.app

import android.app.Activity
import android.os.Bundle
import android.view.Gravity
import android.widget.LinearLayout
import android.widget.TextView
import io.deskguest.app.server.ReplayLog
import io.deskguest.app.server.ReplayTimeline
import io.deskguest.app.ui.Fonts
import io.deskguest.app.ui.UiKit

/**
 * Session replay surface (FEATURES §7, built 2026-11-23, Wave 11
 * Lane B): the in-app timeline the FEATURES entry promises —
 * recorded session events in order, with times and offsets,
 * rendered by ReplayTimeline from the same ReplayLog the
 * `session_replay_data` tool reads. One source, two readers; the
 * surface adds no data of its own.
 *
 * Limits are on the surface, in words (ReplayTimeline's header and
 * empty-state lines): this process's lifetime only, dropped
 * entries counted; the durable evidence store remains the audit
 * log, which only the owner exports.
 */
class ReplayActivity : Activity() {

    private lateinit var root: LinearLayout

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        root = UiKit.page(this)
        render()
    }

    override fun onResume() {
        super.onResume()
        render()
    }

    private fun render() {
        root.removeAllViews()
        val header = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        header.addView(TextView(this).apply {
            text = "‹"
            textSize = 30f
            setTextColor(UiKit.TEXT)
            setPadding(0, 0, UiKit.dp(this@ReplayActivity, 12), UiKit.dp(this@ReplayActivity, 4))
            isClickable = true
            setOnClickListener { finish() }
        })
        header.addView(TextView(this).apply {
            text = "Session replay"
            textSize = 24f
            typeface = Fonts.medium(this@ReplayActivity)
            setTextColor(UiKit.TEXT)
        })
        root.addView(header)

        val card = UiKit.card(this)
        for (line in ReplayTimeline.render(ReplayLog.snapshot(), ReplayLog.droppedCount())) {
            card.addView(UiKit.body(this, line))
        }
        root.addView(card)
    }
}
