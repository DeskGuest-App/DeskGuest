package io.agenticcontrol.app

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.view.Gravity
import android.view.ViewGroup
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import io.agenticcontrol.app.enrollment.EnrollPayload
import io.agenticcontrol.app.enrollment.EnrollmentStore
import io.agenticcontrol.app.ui.Fonts
import io.agenticcontrol.app.ui.UiKit
import io.agenticcontrol.app.wiring.PlatformRuntime
import io.agenticcontrol.app.wiring.PlatformStores
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * "This device" — the endpoint surface (Slice 1 + D2, wired 0.4.6).
 *
 * Everything roster-shaped on this screen comes from ONE call:
 * PlatformStores.endpointSnapshot(), which is built only from the
 * store's endpoint view of THIS device's own id. This screen has no
 * path to any other device's record, any group roster, or any fleet
 * list — that data is absent here, not hidden (D2). Enrollment acts
 * are this device's own: mint a code for another device to join, or
 * redeem a code with this device's own identity.
 *
 * Opening this screen is what loads (or first creates) the device
 * identity — lazily, here, never on the service startup path.
 */
class EndpointActivity : Activity() {

    private lateinit var root: LinearLayout
    private lateinit var stores: PlatformStores

    private var mintScope: String = EnrollmentStore.SCOPE_PERSONAL
    private var mintMode: String = EnrollmentStore.TRANSPORT_MODE_INHERIT
    private var mintedCode: String? = null
    private var mintedPayload: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        stores = PlatformRuntime.get(this)
        root = UiKit.page(this)
        refresh()
    }

    private fun refresh() {
        root.removeAllViews()
        renderHeader()
        section("identity") { renderIdentity() }
        section("enrollment") { renderEnrollmentState() }
        section("mint") { renderMint() }
        section("redeem") { renderRedeem() }
        section("receipts") { renderReceipts() }
        section("operators") { renderOperators() }
    }

    private fun section(name: String, block: () -> Unit) {
        try {
            block()
        } catch (t: Throwable) {
            CrashTrap.record(this, "endpoint section '$name'", t)
            try {
                root.addView(UiKit.muted(this, "One part of this screen failed to load ($name). The failure was recorded."))
            } catch (_: Throwable) {
            }
        }
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
            setPadding(0, 0, UiKit.dp(this@EndpointActivity, 12), UiKit.dp(this@EndpointActivity, 4))
            isClickable = true
            setOnClickListener { finish() }
        })
        header.addView(TextView(this).apply {
            text = "This device"
            textSize = 24f
            typeface = Fonts.medium(this@EndpointActivity)
            setTextColor(UiKit.TEXT)
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        })
        root.addView(header)
    }

    private fun renderIdentity() {
        val snapshot = stores.endpointSnapshot()
        root.addView(UiKit.sectionTitle(this, "Device identity"))
        val card = UiKit.card(this)
        card.addView(UiKit.muted(this, "Device ID"))
        card.addView(UiKit.mono(this, snapshot.deviceId, 13f))
        card.addView(UiKit.muted(this, "Public key"))
        card.addView(UiKit.mono(this, snapshot.publicKeyBase64, 11f))
        card.addView(
            UiKit.muted(
                this,
                "This device's identity key never leaves the phone. The ID above is " +
                    "derived from the public key — anyone can check a signature against it."
            )
        )
        root.addView(card)
    }

    private fun renderEnrollmentState() {
        val snapshot = stores.endpointSnapshot()
        root.addView(UiKit.sectionTitle(this, "Enrollment"))
        val card = UiKit.card(this)
        val record = snapshot.ownRecord
        if (record == null) {
            card.addView(UiKit.body(this, "This device is not enrolled yet."))
            card.addView(
                UiKit.muted(
                    this,
                    "Redeem a one-time code below, or mint one here for another device."
                )
            )
        } else {
            val date = SimpleDateFormat("d MMM yyyy, HH:mm", Locale.US).format(Date(record.enrolledAtMs))
            card.addView(UiKit.body(this, "Enrolled as ${record.displayName}"))
            card.addView(UiKit.muted(this, "Scope: ${record.scope} · Group: ${record.groupName} · $date"))
            card.addView(
                UiKit.muted(
                    this,
                    if (record.revoked) "This enrollment has been revoked." else "Transport mode: ${record.transportMode}"
                )
            )
        }
        root.addView(card)
    }

    private fun renderMint() {
        root.addView(UiKit.sectionTitle(this, "Mint an enrollment code"))
        val card = UiKit.card(this)
        card.addView(
            UiKit.muted(
                this,
                "A code works once and expires in 10 minutes. The scope and group are " +
                    "decided here, at mint — the device that redeems it cannot change them."
            )
        )
        card.addView(UiKit.navRow(this, "Scope", mintScope) {
            mintScope = when (mintScope) {
                EnrollmentStore.SCOPE_LOCAL -> EnrollmentStore.SCOPE_PERSONAL
                EnrollmentStore.SCOPE_PERSONAL -> EnrollmentStore.SCOPE_COMPANY
                else -> EnrollmentStore.SCOPE_LOCAL
            }
            refresh()
        })
        val groupIdField = field("Group ID (e.g. home-devices)")
        val groupNameField = field("Group name")
        card.addView(groupIdField)
        card.addView(groupNameField)
        card.addView(UiKit.navRow(this, "Transport mode", mintMode) {
            mintMode = when (mintMode) {
                EnrollmentStore.TRANSPORT_MODE_INHERIT -> EnrollmentStore.TRANSPORT_MODE_AUTO
                EnrollmentStore.TRANSPORT_MODE_AUTO -> EnrollmentStore.TRANSPORT_MODE_MANUAL
                else -> EnrollmentStore.TRANSPORT_MODE_INHERIT
            }
            refresh()
        })
        card.addView(UiKit.primaryButton(this, "Mint code") {
            val groupId = groupIdField.text.toString().trim()
            val groupName = groupNameField.text.toString().trim()
            if (groupId.isEmpty() || groupName.isEmpty()) {
                toast("Enter the group ID and name the code files devices into.")
                return@primaryButton
            }
            mintedCode = stores.mintEnrollment(mintScope, groupId, groupName, mintMode)
            // bd-and-rest F11 fix: the payload now binds THIS
            // device as the minter (id + public key), so the
            // redeeming side derives who enrolled it — verified by
            // fingerprint — instead of typing a name by hand.
            val own = stores.ownIdentity()
            mintedPayload = EnrollPayload.build(mintedCode!!, mintScope, groupId, own.deviceId, own.publicKeyBase64)
            toast("Code minted. It works once and expires in 10 minutes.")
            refresh()
        })
        val code = mintedCode ?: stores.currentEnrollmentCode()
        if (code != null) {
            card.addView(UiKit.muted(this, "Live code"))
            card.addView(TextView(this).apply {
                text = code
                textSize = 30f
                typeface = Fonts.monoBold(this@EndpointActivity)
                letterSpacing = 0.14f
                setTextColor(UiKit.TEXT)
            })
            val payload = mintedPayload
            if (payload != null) {
                card.addView(UiKit.muted(this, "QR payload: $payload"))
                card.addView(UiKit.outlineButton(this, "Copy the payload") {
                    val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                    clipboard.setPrimaryClip(ClipData.newPlainText("DeskGuest enrollment payload", payload))
                    toast("Copied.")
                })
            }
        }
        root.addView(card)
    }

    private fun renderRedeem() {
        root.addView(UiKit.sectionTitle(this, "Redeem a code"))
        val card = UiKit.card(this)
        card.addView(
            UiKit.muted(
                this,
                "Enter the one-time code an operator minted for this device. Redeeming " +
                    "uses this device's own identity — the code decides the scope and group."
            )
        )
        val codeField = field("Enrollment code (XXXXX-XXXXX)")
        val nameField = field("This device's name")
        // bd-and-rest F11 fix: when the operator hands over the QR
        // payload, the minter's identity comes FROM the payload —
        // fingerprint-verified — and the receipt is built from it.
        // The free-text fields remain only for the legacy bare-code
        // path, and say so.
        val payloadField = field("Enrollment payload (acp://enroll/1?…) — carries who minted it")
        val enrollerNameField = field("Enrolled by (their name) — bare-code path only")
        val enrollerIdField = field("Enrolled by (their device ID) — bare-code path only")
        card.addView(codeField)
        card.addView(nameField)
        card.addView(payloadField)
        card.addView(enrollerNameField)
        card.addView(enrollerIdField)
        card.addView(UiKit.primaryButton(this, "Redeem") {
            val payloadText = payloadField.text.toString().trim()
            val parsed = if (payloadText.isEmpty()) null else EnrollPayload.parse(payloadText)
            if (payloadText.isNotEmpty() && parsed == null) {
                toast("That payload did not parse — check it, or clear it and use the bare code.")
                return@primaryButton
            }
            val code = if (parsed != null) parsed.displayCode else codeField.text.toString().trim()
            val name = nameField.text.toString().trim()
            if (code.isEmpty() || name.isEmpty()) {
                toast("Enter the code and this device's name.")
                return@primaryButton
            }
            val enrolled = if (parsed?.minterVerified == true) {
                stores.redeemOwn(
                    code, name,
                    "Enroller ${parsed.minterDeviceId!!.take(8)}",
                    parsed.minterDeviceId!!
                )
            } else {
                stores.redeemOwn(
                    code, name,
                    enrollerNameField.text.toString().trim(),
                    enrollerIdField.text.toString().trim()
                )
            }
            if (enrolled == null) {
                toast("That code was not accepted — wrong, expired, already used, or this device is revoked.")
            } else {
                toast("Enrolled into ${enrolled.groupName} (${enrolled.scope}).")
            }
            refresh()
        })
        root.addView(card)
    }

    private fun renderReceipts() {
        val snapshot = stores.endpointSnapshot()
        if (snapshot.receipts.isEmpty()) return
        root.addView(UiKit.sectionTitle(this, "Enrollment receipts"))
        val card = UiKit.card(this)
        snapshot.receipts.forEach { receipt ->
            val date = SimpleDateFormat("d MMM yyyy, HH:mm", Locale.US).format(Date(receipt.enrolledAtMs))
            card.addView(UiKit.body(this, "Enrolled by ${receipt.enrollerName}"))
            card.addView(UiKit.muted(this, "${receipt.scope} · ${receipt.groupName} · $date"))
        }
        root.addView(card)
    }

    private fun renderOperators() {
        val snapshot = stores.endpointSnapshot()
        root.addView(UiKit.sectionTitle(this, "Who may operate this device"))
        val card = UiKit.card(this)
        if (snapshot.allowedOperators.isEmpty()) {
            card.addView(
                UiKit.muted(
                    this,
                    "Nobody yet. When an operator enrolls this device, they appear here " +
                        "from the enrollment receipt — this list comes from this device's " +
                        "own records only."
                )
            )
        } else {
            snapshot.allowedOperators.forEach { op ->
                card.addView(UiKit.body(this, op.enrollerName))
                card.addView(UiKit.muted(this, "${op.scope} · ${op.groupName}"))
            }
        }
        root.addView(card)
    }

    private fun field(hint: String): EditText = EditText(this).apply {
        this.hint = hint
        isSingleLine = true
        textSize = 16f
        typeface = Fonts.regular(this@EndpointActivity)
        setTextColor(UiKit.TEXT)
        setHintTextColor(UiKit.SECONDARY)
        background = null
    }

    private fun toast(text: String) =
        Toast.makeText(this, text, Toast.LENGTH_LONG).show()
}
