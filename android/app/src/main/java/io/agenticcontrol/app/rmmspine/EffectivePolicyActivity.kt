package io.agenticcontrol.app.rmmspine

import android.app.Activity
import android.os.Bundle
import android.widget.ScrollView
import android.widget.TextView
import java.io.File

/**
 * RMM-07 on-device Effective Policy view — the honest functional
 * surface (visual design comes in the design phase). Shows the
 * last computed Effective Policy for THIS phone exactly as the
 * receipt path rendered it, or says plainly that no management
 * policy has been received. The user can always see what policy
 * governs their phone; the consent floor is shown once, in its
 * own box above the policy text (W10, V3-F4).
 */
class EffectivePolicyActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val store = EffectivePolicyStore(File(filesDir, "effective-policy.txt"))
        // W8 item 4: when the policy engine is bound on this
        // device (PolicyGate — bound by every signed receipt),
        // the receipt sentences are REGENERATED here, on-device,
        // from the live engine through EffectivePolicyModel
        // .ruleLine (EffectivePolicyView.render) — never shown
        // from pre-rendered text. The stored receipt is the
        // fallback for a process where the engine is not bound;
        // it was itself saved by the receipt path from the same
        // ruleLine render.
        val boundEngine = PolicyGate.engine
        val boundFacts = PolicyGate.facts
        val text = if (boundEngine != null && boundFacts != null) {
            EffectivePolicyView.render(boundEngine, boundFacts)
        } else {
            store.load()
        } ?: "No management policy has been received on this phone yet.\n\n" +
               "When your organisation sends a signed policy, it is verified before it applies, " +
               "and this screen will show every setting that governs this phone and where it came from."
        // W7 item 8 (§4 A8 / [R4] fold) + W10 (V3-F4): the consent
        // floor sits in its own box ABOVE the policy sentences and
        // is NEVER attributed to a setter. It is listed exactly
        // ONCE on this screen, with all four A3 items, from the
        // single source (EffectivePolicyView.floorText →
        // EffectivePolicyModel) — the policy text below carries
        // no floor line of its own.
        val floorText = EffectivePolicyView.floorText()
        val column = android.widget.LinearLayout(this).apply {
            orientation = android.widget.LinearLayout.VERTICAL
        }
        column.addView(TextView(this).apply {
            this.text = floorText
            textSize = 14f
            setPadding(32, 32, 32, 8)
            setTextIsSelectable(true)
        })
        column.addView(TextView(this).apply {
            this.text = text
            textSize = 14f
            setPadding(32, 8, 32, 32)
            setTextIsSelectable(true)
        })
        setContentView(ScrollView(this).apply { addView(column) })
        title = "Effective Policy"
    }
}
