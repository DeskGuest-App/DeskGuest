package io.deskguest.app

import android.app.Activity
import android.os.Bundle
import android.view.Gravity
import android.widget.LinearLayout
import android.widget.SeekBar
import android.widget.Switch
import android.widget.TextView
import io.deskguest.app.design.EffectivePolicyModel
import io.deskguest.app.design.PresenceSelfTest
import io.deskguest.app.presence.PresenceOverlay
import io.deskguest.app.presence.PresenceSettings
import io.deskguest.app.strings.consentString
import io.deskguest.app.ui.Fonts
import io.deskguest.app.ui.UiKit

/**
 * Presence settings — W7 re-skin to the design record (§1.1, §4
 * A3). The colours are MEANINGS and are not settings: green = a
 * human is acting, violet = an AI is acting, amber = a session is
 * open and idle, red = STOP. There is no colour picker on this
 * screen (the pre-W7 picker and its persisted state are gone).
 * What the owner CAN set is comfort only: the Glow's intensity
 * (above its floor) and whether the Glow breathes (static by
 * default). Below the comfort settings sits the consent floor as
 * a locked box — shown, never editable — and the presence
 * self-test (§2 draw-verify) with its honest result line.
 */
class PresenceActivity : Activity() {

    private lateinit var root: LinearLayout

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        root = UiKit.page(this)
        refresh()
    }

    private fun refresh() {
        root.removeAllViews()
        val header = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        header.addView(TextView(this).apply {
            text = "‹"
            textSize = 30f
            setTextColor(UiKit.TEXT)
            setPadding(0, 0, UiKit.dp(this@PresenceActivity, 12), UiKit.dp(this@PresenceActivity, 4))
            isClickable = true
            setOnClickListener { finish() }
        })
        header.addView(TextView(this).apply {
            text = "Presence"
            textSize = 24f
            typeface = Fonts.medium(this@PresenceActivity)
            setTextColor(UiKit.TEXT)
        })
        root.addView(header)
        root.addView(
            UiKit.muted(
                this,
                "The signs that show while your AI is controlling this phone. Their colours " +
                    "are meanings, not decoration — green means a person is acting, violet means " +
                    "your AI is acting, amber means a session is open and waiting, and red is " +
                    "STOP — so the colours are not yours to change. They never turn off during " +
                    "a session."
            )
        )

        val comfort = PresenceSettings.load(this)

        // Comfort: Glow intensity (floored) + breath (off by default).
        val comfortCard = UiKit.card(this)
        comfortCard.addView(UiKit.muted(this, "COMFORT"))
        comfortCard.addView(UiKit.body(this, "Glow intensity"))
        val intensityLabel = UiKit.muted(this, "${comfort.glowIntensityPct}%")
        val seek = SeekBar(this).apply {
            max = 100 - PresenceSettings.GLOW_INTENSITY_FLOOR_PCT
            progress = comfort.glowIntensityPct - PresenceSettings.GLOW_INTENSITY_FLOOR_PCT
            setOnSeekBarChangeListener(object : SeekBar.OnSeekBarChangeListener {
                override fun onProgressChanged(sb: SeekBar?, value: Int, fromUser: Boolean) {
                    val pct = value + PresenceSettings.GLOW_INTENSITY_FLOOR_PCT
                    intensityLabel.text = "$pct%"
                    if (fromUser) {
                        PresenceSettings.saveGlowIntensity(this@PresenceActivity, pct)
                        PresenceOverlay.refreshComfort(this@PresenceActivity)
                    }
                }
                override fun onStartTrackingTouch(sb: SeekBar?) {}
                override fun onStopTrackingTouch(sb: SeekBar?) {}
            })
        }
        comfortCard.addView(seek)
        comfortCard.addView(intensityLabel)
        val breathRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        breathRow.addView(UiKit.body(this, "Glow breathes slowly").apply {
            layoutParams = LinearLayout.LayoutParams(0, -2, 1f)
        })
        breathRow.addView(Switch(this).apply {
            isChecked = comfort.breathEnabled
            setOnCheckedChangeListener { _, checked ->
                PresenceSettings.saveBreath(this@PresenceActivity, checked)
                PresenceOverlay.refreshComfort(this@PresenceActivity)
            }
        })
        comfortCard.addView(breathRow)
        comfortCard.addView(
            UiKit.muted(this, "Off by default — the glow is steady unless you turn this on.")
        )
        root.addView(comfortCard)

        // The consent floor: a locked box, shown verbatim (§4 A3).
        val floorCard = UiKit.card(this)
        floorCard.addView(UiKit.muted(this, "ALWAYS ON — NO ONE CAN CHANGE THIS"))
        for (item in EffectivePolicyModel.CONSENT_FLOOR_ITEMS) {
            floorCard.addView(UiKit.body(this, "· $item"))
        }
        root.addView(floorCard)

        // §2 self-test: draw-verify, with the honest result line.
        val testCard = UiKit.card(this)
        testCard.addView(UiKit.muted(this, "PRESENCE CHECK"))
        val resultView = UiKit.body(this, "")
        fun runTest() {
            val passed = try {
                PresenceOverlay.selfTestDraw(this@PresenceActivity)
            } catch (_: Exception) {
                false
            }
            resultView.text = consentString(
                if (passed) R.string.presence_selftest_pass else R.string.presence_selftest_fail
            )
        }
        PresenceOverlay.lastSelfTest?.let { report ->
            resultView.text = consentString(
                if (PresenceSelfTest.passes(report)) R.string.presence_selftest_pass
                else R.string.presence_selftest_fail
            )
        }
        testCard.addView(resultView)
        testCard.addView(UiKit.primaryButton(this, "Run the presence check") { runTest() })
        root.addView(testCard)
    }
}
