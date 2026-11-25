package io.agenticcontrol.app.ui

import android.app.Activity
import android.content.Context
import io.agenticcontrol.app.R
import io.agenticcontrol.app.strings.consentString
import android.content.res.ColorStateList
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.Drawable
import android.graphics.drawable.GradientDrawable
import android.graphics.drawable.LayerDrawable
import android.graphics.drawable.RippleDrawable
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Switch
import android.widget.TextView

/**
 * The shared look of the app — "Daylight White" (0.4.0, the approved
 * design set): a near-white canvas, white cards with hairline
 * borders and soft 16dp corners, ink-black pill buttons for primary
 * actions, quiet gray secondary text, and color reserved for state
 * (green/amber/red) and the owner's presence palette. Inter for text,
 * JetBrains Mono for codes and addresses (bundled, OFL). Plain Views
 * only — no libraries.
 *
 * Both activities and the presence settings build every screen from
 * these helpers so the whole app reads as one product.
 */
object UiKit {

    // ---------- Daylight-White tokens (design of record) ----------

    val CANVAS = 0xFFF8F9FA.toInt()
    val CARD = Color.WHITE
    val HAIRLINE = 0xFFE5E7EB.toInt()
    val TEXT = 0xFF111827.toInt()
    val SECONDARY = 0xFF6B7280.toInt()
    val DISABLED = 0xFF9CA3AF.toInt()
    val SUBTLE = 0xFFF3F4F6.toInt()
    val INK = 0xFF111827.toInt()
    val SUCCESS = 0xFF16A34A.toInt()
    val SUCCESS_BG = 0xFFDCFCE7.toInt()
    val WARNING = 0xFFD97706.toInt()
    val WARNING_BG = 0xFFFEF3C7.toInt()
    // W92: the app-wide danger token IS the STOP token of record
    // (#DC2626, cross-platform; W72/W84/W90) — DANGER paints the
    // stopButton fill and danger text, so it carries the token, and
    // DANGER_DEEP is the token's own darken step (#B91C1C, the same
    // step the Windows pill uses for STOP hover).
    val DANGER = 0xFFDC2626.toInt()
    val DANGER_DEEP = 0xFFB91C1C.toInt()

    // Kept names from the previous kit so shared call sites read the same.
    val GOOD_BG = SUCCESS_BG
    val GOOD_TEXT = 0xFF15803D.toInt()
    val WARN_BG = WARNING_BG
    val WARN_TEXT = 0xFF92400E.toInt()
    val BAD_TEXT = DANGER

    fun primary(ctx: Context): Int = INK
    fun primarySoft(ctx: Context): Int = SUBTLE
    fun surface(ctx: Context): Int = CANVAS
    fun cardStroke(ctx: Context): Int = HAIRLINE
    fun textColor(ctx: Context): Int = TEXT
    fun mutedColor(ctx: Context): Int = SECONDARY
    fun chipBg(ctx: Context): Int = SUBTLE
    fun chipText(ctx: Context): Int = TEXT

    fun dp(ctx: Context, value: Int): Int =
        (value * ctx.resources.displayMetrics.density).toInt()

    fun dpF(ctx: Context, value: Float): Float =
        value * ctx.resources.displayMetrics.density

    private fun medium(ctx: Context): Typeface = Fonts.medium(ctx)
    private fun regular(ctx: Context): Typeface = Fonts.regular(ctx)

    // ---------- page scaffold ----------

    /** Sets the activity's content to a scrolling page and returns the column to fill. */
    fun page(activity: Activity): LinearLayout {
        val scroll = ScrollView(activity).apply {
            setBackgroundColor(CANVAS)
            isFillViewport = true
        }
        val column = LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(activity, 20), dp(activity, 20), dp(activity, 20), dp(activity, 32))
        }
        scroll.addView(column)
        activity.setContentView(scroll)
        activity.window?.statusBarColor = CANVAS
        // bd-and-ui F12 fix: edge-to-edge windows drew content
        // under the gesture bar / cutout — page() set the status
        // bar colour but never consumed window insets. The scroll
        // view now pads itself by the system-bar insets.
        if (android.os.Build.VERSION.SDK_INT >= 30) {
            scroll.setOnApplyWindowInsetsListener { v, insets ->
                val bars = insets.getInsets(android.view.WindowInsets.Type.systemBars())
                v.setPadding(bars.left, bars.top, bars.right, bars.bottom)
                insets
            }
        }
        // The canvas is near-white, so the status-bar icons must render
        // dark — without this they stay white and vanish against the
        // light bar (field report, 0.4.1).
        if (android.os.Build.VERSION.SDK_INT >= 30) {
            activity.window?.insetsController?.setSystemBarsAppearance(
                android.view.WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS,
                android.view.WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS
            )
        }
        return column
    }

    fun column(ctx: Context): LinearLayout = LinearLayout(ctx).apply {
        orientation = LinearLayout.VERTICAL
    }

    // ---------- containers and text ----------

    fun card(ctx: Context, accent: Int? = null): LinearLayout = LinearLayout(ctx).apply {
        orientation = LinearLayout.VERTICAL
        background = GradientDrawable().apply {
            setColor(CARD)
            cornerRadius = dp(ctx, 16).toFloat()
            // F12: ONE setStroke — the second call used to replace
            // the first, so the hairline branch was dead code.
            setStroke(dp(ctx, if (accent != null) 2 else 1), accent ?: HAIRLINE)
        }
        setPadding(dp(ctx, 20), dp(ctx, 20), dp(ctx, 20), dp(ctx, 20))
        layoutParams = LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
        ).apply { setMargins(0, 0, 0, dp(ctx, 16)) }
    }

    /** A dashed-border card (the idle session card in the design set). */
    fun dashedCard(ctx: Context): LinearLayout = LinearLayout(ctx).apply {
        orientation = LinearLayout.VERTICAL
        background = dashedDrawable(ctx, HAIRLINE, CARD)
        setPadding(dp(ctx, 20), dp(ctx, 20), dp(ctx, 20), dp(ctx, 20))
        layoutParams = LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
        ).apply { setMargins(0, 0, 0, dp(ctx, 16)) }
    }

    fun dashedDrawable(ctx: Context, strokeColor: Int, fillColor: Int): GradientDrawable =
        GradientDrawable().apply {
            setColor(fillColor)
            cornerRadius = dp(ctx, 16).toFloat()
            setStroke(dp(ctx, 1), strokeColor, dpF(ctx, 6f), dpF(ctx, 4f))
        }

    fun headline(ctx: Context, text: String): TextView = TextView(ctx).apply {
        this.text = text
        textSize = 26f
        typeface = medium(ctx)
        setTextColor(TEXT)
        setLineSpacing(0f, 1.15f)
        layoutParams = LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
        ).apply { setMargins(0, dp(ctx, 4), 0, dp(ctx, 10)) }
    }

    fun sectionTitle(ctx: Context, text: String): TextView = TextView(ctx).apply {
        this.text = text
        textSize = 19f
        typeface = medium(ctx)
        setTextColor(TEXT)
        layoutParams = LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
        ).apply { setMargins(0, dp(ctx, 20), 0, dp(ctx, 10)) }
    }

    fun body(ctx: Context, text: String): TextView = TextView(ctx).apply {
        this.text = text
        textSize = 16f
        typeface = regular(ctx)
        setTextColor(TEXT)
        setLineSpacing(0f, 1.25f)
        layoutParams = LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
        ).apply { setMargins(0, 0, 0, dp(ctx, 10)) }
    }

    fun muted(ctx: Context, text: String): TextView = TextView(ctx).apply {
        this.text = text
        textSize = 14f
        typeface = regular(ctx)
        setTextColor(SECONDARY)
        setLineSpacing(0f, 1.25f)
        layoutParams = LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
        ).apply { setMargins(0, 0, 0, dp(ctx, 10)) }
    }

    /** Monospace text (codes, addresses, timers). */
    fun mono(ctx: Context, text: String, sizeSp: Float = 14f, color: Int = TEXT): TextView =
        TextView(ctx).apply {
            this.text = text
            textSize = sizeSp
            typeface = Fonts.mono(ctx)
            setTextColor(color)
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply { setMargins(0, 0, 0, dp(ctx, 10)) }
        }

    // ---------- buttons ----------

    /** The black pill: the design set's primary action. */
    fun primaryButton(ctx: Context, text: String, onClick: () -> Unit): Button = Button(ctx).apply {
        this.text = text
        textSize = 16f
        typeface = medium(ctx)
        isAllCaps = false
        setTextColor(Color.WHITE)
        stateListAnimator = null
        setPadding(dp(ctx, 20), 0, dp(ctx, 20), 0)
        stylePrimary(ctx, this, true)
        setOnClickListener { onClick() }
        layoutParams = LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, dp(ctx, 56)
        ).apply { setMargins(0, dp(ctx, 6), 0, dp(ctx, 10)) }
    }

    /** Re-styles a primary button for its enabled state (a disabled one fades). */
    fun stylePrimary(ctx: Context, button: Button, enabled: Boolean) {
        val fill = if (enabled) INK else 0xFFD1D5DB.toInt()
        val bg = GradientDrawable().apply {
            cornerRadius = dp(ctx, 12).toFloat()
            setColor(fill)
        }
        button.background = RippleDrawable(
            ColorStateList.valueOf(0x2EFFFFFF.toInt()), bg, null
        )
        button.isEnabled = enabled
        button.isClickable = enabled
        button.setTextColor(if (enabled) Color.WHITE else DISABLED)
    }

    /** An outlined secondary button (Stop server, Unpair, Later). */
    fun outlineButton(ctx: Context, text: String, onClick: () -> Unit): Button = Button(ctx).apply {
        this.text = text
        textSize = 15f
        typeface = medium(ctx)
        isAllCaps = false
        setTextColor(TEXT)
        stateListAnimator = null
        background = RippleDrawable(
            ColorStateList.valueOf(0x14000000),
            GradientDrawable().apply {
                cornerRadius = dp(ctx, 12).toFloat()
                setColor(Color.WHITE)
                setStroke(dp(ctx, 1), HAIRLINE)
            },
            null
        )
        setPadding(dp(ctx, 18), dp(ctx, 12), dp(ctx, 18), dp(ctx, 12))
        setOnClickListener { onClick() }
        layoutParams = LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
        ).apply { setMargins(0, dp(ctx, 4), 0, dp(ctx, 8)) }
    }

    /** The full-width red STOP (home screen, active session). */
    fun stopButton(ctx: Context, text: String? = null, onClick: () -> Unit): Button =
        Button(ctx).apply {
            this.text = text ?: ctx.consentString(R.string.presence_stop)
            textSize = 16f
            typeface = medium(ctx)
            isAllCaps = true
            setTextColor(Color.WHITE)
            stateListAnimator = null
            background = RippleDrawable(
                ColorStateList.valueOf(0x2EFFFFFF.toInt()),
                GradientDrawable().apply {
                    cornerRadius = dp(ctx, 12).toFloat()
                    setColor(DANGER)
                },
                null
            )
            setPadding(dp(ctx, 20), 0, dp(ctx, 20), 0)
            setOnClickListener { onClick() }
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(ctx, 56)
            ).apply { setMargins(0, dp(ctx, 6), 0, dp(ctx, 6)) }
        }

    fun textButton(
        ctx: Context,
        text: String,
        color: Int = TEXT,
        onClick: () -> Unit
    ): Button = Button(ctx).apply {
        this.text = text
        textSize = 15f
        typeface = medium(ctx)
        isAllCaps = false
        setTextColor(color)
        background = null
        gravity = Gravity.CENTER
        setPadding(dp(ctx, 8), dp(ctx, 10), dp(ctx, 8), dp(ctx, 10))
        setOnClickListener { onClick() }
        layoutParams = LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
        ).apply { setMargins(0, 0, 0, dp(ctx, 6)) }
    }

    // ---------- chips / pills ----------

    enum class ChipKind { ACCENT, NEUTRAL, GOOD, WARN, BAD }

    fun chip(ctx: Context, text: String, kind: ChipKind = ChipKind.ACCENT): TextView {
        val (bg, fg) = when (kind) {
            ChipKind.ACCENT -> SUBTLE to TEXT
            ChipKind.NEUTRAL -> SUBTLE to SECONDARY
            ChipKind.GOOD -> SUCCESS_BG to GOOD_TEXT
            ChipKind.WARN -> WARN_BG to WARN_TEXT
            ChipKind.BAD -> 0xFFFEE2E2.toInt() to DANGER_DEEP
        }
        return TextView(ctx).apply {
            this.text = text
            textSize = 12f
            typeface = medium(ctx)
            setTextColor(fg)
            background = GradientDrawable().apply {
                cornerRadius = dp(ctx, 100).toFloat()
                setColor(bg)
            }
            setPadding(dp(ctx, 10), dp(ctx, 4), dp(ctx, 10), dp(ctx, 4))
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply { setMargins(0, 0, dp(ctx, 8), dp(ctx, 8)) }
        }
    }

    /** A small state dot (the Running pill's green dot, the banner's blue dot). */
    fun dot(ctx: Context, color: Int, sizeDp: Int = 8): View = View(ctx).apply {
        background = GradientDrawable().apply {
            shape = GradientDrawable.OVAL
            setColor(color)
        }
        layoutParams = LinearLayout.LayoutParams(dp(ctx, sizeDp), dp(ctx, sizeDp)).apply {
            setMargins(0, 0, dp(ctx, 6), 0)
        }
    }

    // ---------- radio cards and switches ----------

    fun radioCard(
        ctx: Context,
        title: String,
        bodyText: String,
        selected: Boolean,
        onClick: () -> Unit
    ): LinearLayout {
        val row = LinearLayout(ctx).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.TOP
            background = GradientDrawable().apply {
                cornerRadius = dp(ctx, 16).toFloat()
                setColor(Color.WHITE)
                setStroke(dp(ctx, if (selected) 2 else 1), if (selected) TEXT else HAIRLINE)
            }
            setPadding(dp(ctx, 16), dp(ctx, 16), dp(ctx, 16), dp(ctx, 16))
            isClickable = true
            isFocusable = true
            setOnClickListener { onClick() }
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply { setMargins(0, 0, 0, dp(ctx, 12)) }
        }
        // bd-and-ui F11 fix: the card IS a radio button to a
        // screen reader — class name + checkable + checked state
        // (it previously announced as a plain clickable group).
        row.accessibilityDelegate = object : View.AccessibilityDelegate() {
            override fun onInitializeAccessibilityNodeInfo(
                host: View, info: android.view.accessibility.AccessibilityNodeInfo
            ) {
                super.onInitializeAccessibilityNodeInfo(host, info)
                info.className = "android.widget.RadioButton"
                info.isCheckable = true
                info.isChecked = selected
            }
        }
        val indicator = View(ctx).apply {
            // Decorative: the state is on the row itself.
            importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
            background = radioDrawable(ctx, selected)
            layoutParams = LinearLayout.LayoutParams(dp(ctx, 22), dp(ctx, 22)).apply {
                setMargins(0, dp(ctx, 2), dp(ctx, 14), 0)
            }
        }
        row.addView(indicator)
        val texts = LinearLayout(ctx).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        }
        texts.addView(TextView(ctx).apply {
            text = title
            textSize = 16f
            typeface = medium(ctx)
            setTextColor(TEXT)
        })
        texts.addView(TextView(ctx).apply {
            text = bodyText
            textSize = 14f
            typeface = regular(ctx)
            setTextColor(SECONDARY)
            setLineSpacing(0f, 1.25f)
            setPadding(0, dp(ctx, 3), 0, 0)
        })
        row.addView(texts)
        return row
    }

    private fun radioDrawable(ctx: Context, selected: Boolean): Drawable {
        val ring = GradientDrawable().apply {
            shape = GradientDrawable.OVAL
            setStroke(dp(ctx, 2), if (selected) TEXT else DISABLED)
            setColor(Color.TRANSPARENT)
        }
        if (!selected) return ring
        val dot = GradientDrawable().apply {
            shape = GradientDrawable.OVAL
            setColor(TEXT)
        }
        val layer = LayerDrawable(arrayOf(ring, dot))
        val inset = dp(ctx, 6)
        layer.setLayerInset(1, inset, inset, inset, inset)
        return layer
    }

    fun switchRow(
        ctx: Context,
        label: String,
        checked: Boolean,
        onChange: (Boolean) -> Unit
    ): LinearLayout {
        val row = LinearLayout(ctx).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, dp(ctx, 6), 0, dp(ctx, 6))
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }
        val labelView = TextView(ctx).apply {
            text = label
            textSize = 16f
            typeface = regular(ctx)
            setTextColor(TEXT)
            id = View.generateViewId()
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        }
        row.addView(labelView)
        // F11 fix: the Switch is associated with its label
        // (labelFor + content description) — it previously
        // announced as a bare "switch" with no name.
        val toggle = Switch(ctx).apply {
            isChecked = checked
            contentDescription = label
            labelFor = labelView.id
        }
        toggle.setOnCheckedChangeListener { _, isChecked -> onChange(isChecked) }
        row.addView(toggle)
        return row
    }

    // ---------- report rows ----------

    fun reportRow(ctx: Context, ok: Boolean, label: String, note: String): LinearLayout {
        val row = LinearLayout(ctx).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.TOP
            setPadding(0, dp(ctx, 7), 0, dp(ctx, 7))
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }
        row.addView(TextView(ctx).apply {
            text = if (ok) "✓" else "○"
            textSize = 16f
            typeface = medium(ctx)
            setTextColor(if (ok) GOOD_TEXT else SECONDARY)
            layoutParams = LinearLayout.LayoutParams(dp(ctx, 30), ViewGroup.LayoutParams.WRAP_CONTENT)
        })
        val texts = LinearLayout(ctx).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        }
        texts.addView(TextView(ctx).apply {
            text = label
            textSize = 15f
            typeface = medium(ctx)
            setTextColor(TEXT)
        })
        texts.addView(TextView(ctx).apply {
            text = note
            textSize = 13f
            typeface = regular(ctx)
            setTextColor(SECONDARY)
            setLineSpacing(0f, 1.2f)
            setPadding(0, dp(ctx, 2), 0, 0)
        })
        row.addView(texts)
        return row
    }

    /** A tappable list row with a trailing chevron (home-screen rows). */
    fun navRow(ctx: Context, label: String, detail: String, onClick: () -> Unit): LinearLayout {
        val row = LinearLayout(ctx).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(ctx, 4), dp(ctx, 12), dp(ctx, 4), dp(ctx, 12))
            isClickable = true
            isFocusable = true
            setOnClickListener { onClick() }
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }
        val texts = LinearLayout(ctx).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        }
        texts.addView(TextView(ctx).apply {
            text = label
            textSize = 16f
            typeface = regular(ctx)
            setTextColor(TEXT)
        })
        if (detail.isNotBlank()) {
            texts.addView(TextView(ctx).apply {
                text = detail
                textSize = 13f
                typeface = regular(ctx)
                setTextColor(SECONDARY)
            })
        }
        row.addView(texts)
        row.addView(TextView(ctx).apply {
            text = "›"
            textSize = 22f
            setTextColor(DISABLED)
        })
        return row
    }

    fun divider(ctx: Context): View = View(ctx).apply {
        setBackgroundColor(HAIRLINE)
        layoutParams = LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, dp(ctx, 1)
        ).apply { setMargins(0, dp(ctx, 4), 0, dp(ctx, 4)) }
    }

    // ---------- the access editor (SPEC §5.3), shared by wizard and home ----------

    /** Capability keys, in display order, exactly as PairingStore.setAccess takes them. */
    val CAP_LABELS: List<Pair<String, String>> = listOf(
        "see" to "See the screen",
        "tap" to "Tap and swipe",
        "type" to "Type text",
        "apps" to "Open apps",
        "shell" to "Shell access",
        "settings" to "Change settings"
    )
    val ALL_CAPS: Set<String> = CAP_LABELS.map { it.first }.toSet()
    val DEFAULT_CAPS: Set<String> = setOf("see", "tap", "type")

    const val ACCESS_OBSERVE = "observe"
    const val ACCESS_FULL = "full"
    const val ACCESS_CUSTOM = "custom"

    const val ALWAYS_ON_LINE =
        "Asking first for payments, sending, and deleting, and never typing " +
            "passwords, are always on. They are not settings."

    /** The chip label for a pairing's access level. */
    fun accessLabel(access: String?): String = when (access) {
        ACCESS_FULL -> "Full control"
        ACCESS_CUSTOM -> "Custom"
        else -> "Look only"
    }

    /**
     * W89 / S08 parity: the "What may this AI do?" control — the
     * stepped 5-stop slider and the Fine-tune panel as two views of
     * ONE grant state (the pairing's scope set, per
     * [io.agenticcontrol.app.server.AccessControl]).
     *
     * Nothing saves as it is touched: the slider discs, the −/+
     * steppers and the Fine-tune switches all STAGE a proposed
     * scope set. Staging shows the preview — every grant that would
     * be added or removed, named — and only Apply calls [onApply].
     * Touching Fine-tune stages a set no stop equals, so the slider
     * shows "Custom"; moving the slider stages exactly that stop's
     * set. When the staged change ADDS the admin (elevation) scope,
     * the preview carries the owner's separate elevation switch and
     * Apply stays disabled until it is on — and the store refuses
     * the change without it regardless (default refused).
     *
     * [onApply] returns a refusal line to show, or null on success
     * (the caller then re-renders from the store).
     */
    fun accessEditor(
        ctx: Context,
        currentScopes: Set<String>,
        elevationConfirmLine: String,
        onApply: (proposed: Set<String>, elevationConfirmed: Boolean) -> String?
    ): View {
        val control = io.agenticcontrol.app.server.AccessControl
        val container = column(ctx)
        var staged: Set<String> = currentScopes.toSet()
        var elevationConfirmed = false
        var refusalLine: String? = null

        fun render() {
            container.removeAllViews()
            val stagedStop = control.classify(staged)
            val currentStop = control.classify(currentScopes)

            // State line: the staged classification, with the
            // Custom chip whenever the staged set is no stop.
            val stateRow = LinearLayout(ctx).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
            }
            stateRow.addView(TextView(ctx).apply {
                text = "Access level"
                textSize = 15f
                typeface = medium(ctx)
                setTextColor(TEXT)
                layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
            })
            if (stagedStop < 0) {
                stateRow.addView(chip(ctx, "Custom", ChipKind.WARN))
            }
            container.addView(stateRow)
            container.addView(
                body(
                    ctx,
                    if (stagedStop >= 0) {
                        "${control.STOPS[stagedStop].name} — ${control.STOPS[stagedStop].consequence}"
                    } else {
                        "Custom access — the switches below show exactly what this helper may do."
                    }
                )
            )
            if (stagedStop == 1) {
                // W7: the corrected look-only copy stays the
                // externalised string of record (§4 A1).
                container.addView(muted(ctx, ctx.consentString(R.string.access_look_only_copy)))
            }

            // The stepped slider: five numbered discs, filled to
            // the staged stop; tapping a disc stages that stop.
            val track = LinearLayout(ctx).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                setPadding(0, dp(ctx, 10), 0, dp(ctx, 2))
            }
            control.STOPS.forEachIndexed { index, stop ->
                val disc = TextView(ctx).apply {
                    text = if (stagedStop == index) "✓" else "${index + 1}"
                    textSize = 15f
                    typeface = medium(ctx)
                    gravity = Gravity.CENTER
                    val filled = stagedStop >= 0 && index <= stagedStop
                    setTextColor(if (filled) Color.WHITE else SECONDARY)
                    background = GradientDrawable().apply {
                        shape = GradientDrawable.OVAL
                        setColor(if (filled) INK else SUBTLE)
                        if (stagedStop == index) setStroke(dp(ctx, 2), TEXT)
                    }
                    contentDescription = stop.name
                    isClickable = true
                    isFocusable = true
                    setOnClickListener {
                        staged = stop.grants.toSet()
                        elevationConfirmed = false
                        refusalLine = null
                        render()
                    }
                    layoutParams = LinearLayout.LayoutParams(dp(ctx, 40), dp(ctx, 40))
                }
                track.addView(disc)
                if (index < control.STOPS.size - 1) {
                    track.addView(View(ctx).apply {
                        setBackgroundColor(if (stagedStop > index) INK else HAIRLINE)
                        layoutParams = LinearLayout.LayoutParams(0, dp(ctx, 3), 1f)
                    })
                }
            }
            container.addView(track)
            val namesRow = LinearLayout(ctx).apply {
                orientation = LinearLayout.HORIZONTAL
            }
            control.STOPS.forEach { stop ->
                namesRow.addView(TextView(ctx).apply {
                    text = stop.name
                    textSize = 10f
                    typeface = regular(ctx)
                    gravity = Gravity.CENTER
                    setTextColor(if (staged == stop.grants) TEXT else SECONDARY)
                    layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
                })
            }
            container.addView(namesRow)

            // −/+ steppers: the text alternative to the discs.
            val steppers = LinearLayout(ctx).apply {
                orientation = LinearLayout.HORIZONTAL
                setPadding(0, dp(ctx, 6), 0, 0)
            }
            steppers.addView(outlineButton(ctx, "− Less access") {
                val from = if (stagedStop >= 0) stagedStop else control.STOPS.size - 1
                val next = (from - 1).coerceAtLeast(0)
                staged = control.STOPS[next].grants.toSet()
                elevationConfirmed = false
                refusalLine = null
                render()
            }.apply {
                layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
                    .apply { setMargins(0, 0, dp(ctx, 6), 0) }
            })
            steppers.addView(outlineButton(ctx, "More access +") {
                val from = if (stagedStop >= 0) stagedStop else -1
                val next = (from + 1).coerceAtMost(control.STOPS.size - 1)
                staged = control.STOPS[next].grants.toSet()
                elevationConfirmed = false
                refusalLine = null
                render()
            }.apply {
                layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
            })
            container.addView(steppers)

            // The change preview: exactly which grants change,
            // named BEFORE anything applies.
            val changes = control.diff(currentScopes, staged)
            if (changes.isNotEmpty()) {
                val preview = card(ctx)
                preview.addView(sectionTitle(ctx, "This changes:"))
                changes.forEach { change ->
                    preview.addView(
                        body(ctx, (if (change.added) "+ " else "− ") + change.capability.label)
                    )
                }
                if (control.addsElevation(currentScopes, staged)) {
                    preview.addView(divider(ctx))
                    preview.addView(body(ctx, elevationConfirmLine))
                    preview.addView(
                        switchRow(
                            ctx,
                            control.ELEVATION_LABEL,
                            elevationConfirmed
                        ) { on ->
                            elevationConfirmed = on
                            render()
                        }
                    )
                    preview.addView(muted(ctx, control.PERMISSION_LINE))
                }
                if (refusalLine != null) {
                    preview.addView(TextView(ctx).apply {
                        text = refusalLine
                        textSize = 14f
                        typeface = regular(ctx)
                        setTextColor(DANGER)
                    })
                }
                preview.addView(primaryButton(ctx, "Apply changes") {
                    val refusal = onApply(staged, elevationConfirmed)
                    if (refusal != null) {
                        refusalLine = refusal
                        render()
                    }
                }.apply {
                    val canApply = !control.addsElevation(currentScopes, staged) || elevationConfirmed
                    stylePrimary(ctx, this, canApply)
                    isEnabled = canApply
                    isClickable = canApply
                })
                preview.addView(outlineButton(ctx, "Cancel") {
                    staged = currentScopes.toSet()
                    elevationConfirmed = false
                    refusalLine = null
                    render()
                })
                container.addView(preview)
            } else if (currentStop < 0) {
                container.addView(muted(ctx, "This pairing's access is Custom — it matches no preset level."))
            }

            // Fine-tune: the same staged set, one switch per real
            // Android scope; the elevation class last, separated,
            // with the standing permission-popup line.
            container.addView(sectionTitle(ctx, "Fine-tune"))
            val panel = card(ctx)
            control.CAPABILITIES.filter { !it.isElevation }.forEach { cap ->
                panel.addView(switchRow(ctx, cap.label, cap.scope in staged) { on ->
                    staged = if (on) staged + cap.scope else staged - cap.scope
                    elevationConfirmed = false
                    refusalLine = null
                    render()
                })
            }
            panel.addView(divider(ctx))
            val elevation = control.CAPABILITIES.first { it.isElevation }
            panel.addView(switchRow(ctx, elevation.label, elevation.scope in staged) { on ->
                staged = if (on) staged + elevation.scope else staged - elevation.scope
                elevationConfirmed = false
                refusalLine = null
                render()
            })
            panel.addView(muted(ctx, control.PERMISSION_LINE))
            container.addView(panel)
            container.addView(muted(ctx, ALWAYS_ON_LINE))
            container.addView(muted(ctx, "Every change is recorded in the audit log."))
        }
        render()
        return container
    }

    // ---------- the connection-path editor (W98 / S09(b)), shared by home + wizard ----------

    /**
     * W98 / S09(b) parity: the "How this helper connects" control —
     * the three-mode connection-path setting over Android's REAL
     * arrival paths ([io.agenticcontrol.app.server.ConnectionPath]:
     * mesh + loopback only; Android has no pairing-bearing LAN/hub/
     * ipv6/ownpath/tor listener, so none is offered).
     *
     * Same staging discipline as [accessEditor] (W89): the mode
     * cards, subset switches and pin cards STAGE a proposed
     * setting; staging shows the preview ("This changes: old ->
     * new" + the never-widens line) and only Apply calls [onApply]
     * (PairingStore.updateConnectionPath — the store validates and
     * refuses invalid values regardless, and audits change AND
     * refusal). [currentPathLine] is the live current-path label,
     * built by the caller from PairingStore.lastConnection — real
     * run state, never a stored claim.
     *
     * [onApply] returns a refusal line to show, or null on success.
     */
    fun connectionPathEditor(
        ctx: Context,
        current: io.agenticcontrol.app.server.ConnectionPath.Setting,
        currentPathLine: String,
        onApply: (io.agenticcontrol.app.server.ConnectionPath.Setting) -> String?
    ): View {
        val paths = io.agenticcontrol.app.server.ConnectionPath
        val container = column(ctx)
        var staged: io.agenticcontrol.app.server.ConnectionPath.Setting =
            paths.normalize(current)
        var refusalLine: String? = null

        fun render() {
            container.removeAllViews()
            container.addView(sectionTitle(ctx, "How this helper connects"))
            container.addView(body(ctx, currentPathLine))
            container.addView(muted(ctx, "Path setting now: ${paths.describe(current)}"))
            // W108 / W105-C5: a corrupt stored setting restored
            // fail-closed says so plainly — it never presents as a
            // mode the owner chose. No path is allowed until the
            // owner picks a setting below and applies it.
            if (current.needsAttention) {
                container.addView(muted(ctx,
                    "The stored connection setting could not be read, so no path is " +
                        "allowed until you choose a setting and apply it."))
            }

            // The three modes, as radio cards.
            container.addView(
                radioCard(
                    ctx, "Auto",
                    "Any working path. The helper uses the best path that works, " +
                        "and switches without pairing again.",
                    staged.mode == paths.MODE_AUTO
                ) {
                    staged = io.agenticcontrol.app.server.ConnectionPath.Setting(paths.MODE_AUTO)
                    refusalLine = null
                    render()
                }
            )
            container.addView(
                radioCard(
                    ctx, "Auto, restricted",
                    "Only the paths you tick below. Nothing else is ever used.",
                    staged.mode == paths.MODE_RESTRICTED
                ) {
                    staged = io.agenticcontrol.app.server.ConnectionPath.Setting(
                        paths.MODE_RESTRICTED,
                        staged.rungs.ifEmpty { paths.PATH_IDS }
                    )
                    refusalLine = null
                    render()
                }
            )
            container.addView(
                radioCard(
                    ctx, "Manual — one pinned path",
                    "Exactly one path, the one you pick below. No failover.",
                    staged.mode == paths.MODE_MANUAL
                ) {
                    staged = io.agenticcontrol.app.server.ConnectionPath.Setting(
                        paths.MODE_MANUAL,
                        pin = staged.pin ?: paths.PATH_MESH
                    )
                    refusalLine = null
                    render()
                }
            )

            // Restricted: the subset, one switch per real path.
            if (staged.mode == paths.MODE_RESTRICTED) {
                val panel = card(ctx)
                panel.addView(sectionTitle(ctx, "Allowed paths"))
                paths.PATHS.forEach { path ->
                    panel.addView(switchRow(ctx, path.name, path.id in staged.rungs) { on ->
                        staged = staged.copy(
                            rungs = if (on) staged.rungs + path.id else staged.rungs - path.id
                        )
                        refusalLine = null
                        render()
                    })
                    panel.addView(muted(ctx, path.blurb))
                }
                container.addView(panel)
            }

            // Manual: the pin picker, one radio card per real path.
            if (staged.mode == paths.MODE_MANUAL) {
                container.addView(sectionTitle(ctx, "Pinned path"))
                paths.PATHS.forEach { path ->
                    container.addView(
                        radioCard(ctx, path.name, path.blurb, staged.pin == path.id) {
                            staged = staged.copy(pin = path.id)
                            refusalLine = null
                            render()
                        }
                    )
                }
            }

            // The staged preview + Apply (nothing applies on touch).
            val normalizedCurrent = paths.normalize(current)
            if (staged != normalizedCurrent) {
                val preview = card(ctx)
                preview.addView(sectionTitle(ctx, "This changes:"))
                preview.addView(
                    body(ctx, "${paths.describe(normalizedCurrent)} → ${paths.describe(staged)}")
                )
                preview.addView(muted(ctx, paths.NEVER_WIDEN_LINE))
                val invalid = paths.validate(staged)
                if (invalid != null) {
                    preview.addView(TextView(ctx).apply {
                        text = invalid
                        textSize = 14f
                        typeface = regular(ctx)
                        setTextColor(DANGER)
                    })
                }
                if (refusalLine != null) {
                    preview.addView(TextView(ctx).apply {
                        text = refusalLine
                        textSize = 14f
                        typeface = regular(ctx)
                        setTextColor(DANGER)
                    })
                }
                preview.addView(primaryButton(ctx, "Apply changes") {
                    val refusal = onApply(staged)
                    if (refusal != null) {
                        refusalLine = refusal
                        render()
                    }
                }.apply {
                    stylePrimary(ctx, this, invalid == null)
                    isEnabled = invalid == null
                    isClickable = invalid == null
                })
                preview.addView(outlineButton(ctx, "Cancel") {
                    staged = normalizedCurrent
                    refusalLine = null
                    render()
                })
                container.addView(preview)
            }
            container.addView(muted(ctx, "Every change is recorded in the audit log."))
        }
        render()
        return container
    }

    /**
     * W98 / S09(b): the mint-time connection choice for the pairing
     * flow — the compact three-mode picker shown where a pairing
     * code is made (home Connect card + wizard pair step). Default
     * AUTO. The choice is reported through [onChange] on every
     * touch; the caller binds it via PairingStore.beginPairing's
     * connection parameter, which refuses an invalid setting
     * rather than widening it. [initial] is the picker's starting
     * setting (the caller's current choice).
     */
    fun connectionPathMintPicker(
        ctx: Context,
        initial: io.agenticcontrol.app.server.ConnectionPath.Setting,
        onChange: (io.agenticcontrol.app.server.ConnectionPath.Setting) -> Unit
    ): View {
        val paths = io.agenticcontrol.app.server.ConnectionPath
        val container = column(ctx)
        var staged: io.agenticcontrol.app.server.ConnectionPath.Setting =
            paths.normalize(initial)

        fun render() {
            container.removeAllViews()
            container.addView(sectionTitle(ctx, "How this helper may connect"))
            container.addView(
                radioCard(
                    ctx, "Auto",
                    "Any working path (the usual choice).",
                    staged.mode == paths.MODE_AUTO
                ) {
                    staged = io.agenticcontrol.app.server.ConnectionPath.Setting(paths.MODE_AUTO)
                    onChange(staged)
                    render()
                }
            )
            container.addView(
                radioCard(
                    ctx, "Auto, restricted",
                    "Only the paths you tick.",
                    staged.mode == paths.MODE_RESTRICTED
                ) {
                    staged = io.agenticcontrol.app.server.ConnectionPath.Setting(
                        paths.MODE_RESTRICTED,
                        staged.rungs.ifEmpty { paths.PATH_IDS }
                    )
                    onChange(staged)
                    render()
                }
            )
            container.addView(
                radioCard(
                    ctx, "Manual — one pinned path",
                    "Exactly one path, no failover.",
                    staged.mode == paths.MODE_MANUAL
                ) {
                    staged = io.agenticcontrol.app.server.ConnectionPath.Setting(
                        paths.MODE_MANUAL,
                        pin = staged.pin ?: paths.PATH_MESH
                    )
                    onChange(staged)
                    render()
                }
            )
            if (staged.mode == paths.MODE_RESTRICTED) {
                val panel = card(ctx)
                paths.PATHS.forEach { path ->
                    panel.addView(switchRow(ctx, path.name, path.id in staged.rungs) { on ->
                        staged = staged.copy(
                            rungs = if (on) staged.rungs + path.id else staged.rungs - path.id
                        )
                        onChange(staged)
                        render()
                    })
                }
                container.addView(panel)
            }
            if (staged.mode == paths.MODE_MANUAL) {
                paths.PATHS.forEach { path ->
                    container.addView(
                        radioCard(ctx, path.name, path.blurb, staged.pin == path.id) {
                            staged = staged.copy(pin = path.id)
                            onChange(staged)
                            render()
                        }
                    )
                }
            }
            container.addView(muted(ctx, paths.NEVER_WIDEN_LINE))
        }
        render()
        return container
    }
}
