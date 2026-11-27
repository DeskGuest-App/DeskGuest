package io.deskguest.app

import android.app.Activity
import android.os.Bundle
import android.view.Gravity
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import io.deskguest.app.backup.BackupCrypto
import io.deskguest.app.design.BackupKeySheetModel
import io.deskguest.app.design.MdmSurfaceModel
import io.deskguest.app.server.EventSubscriptions
import io.deskguest.app.strings.consentString
import io.deskguest.app.ui.Fonts
import io.deskguest.app.ui.UiKit
import java.io.File

/**
 * W7 item 9 — the RMM owner surfaces (§5): (a) MDM device
 * notices — every organisation action recorded on this phone,
 * rendered from the durable notice store the MdmService writes
 * (a notice is recorded BEFORE execution; a refusal is a notice
 * too, never silent); (b) the event-subscription list —
 * SessionEvents.listAll() rendered completely via
 * MdmSurfaceModel (which pairings watch which event kinds,
 * nothing hidden); (c) the backup key sheet for the W5-B
 * encryption — the owner enters their backup passphrase and is
 * shown the key sheet ONCE: the derived key, with the warning
 * that without it an encrypted backup cannot be opened. The
 * surface stores nothing (BackupKeySheetModel.keyStoredBySurface
 * is false — the sheet is a hand-off to the owner's keeping).
 */
class RmmNoticesActivity : Activity() {

    private lateinit var root: LinearLayout

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        root = UiKit.page(this)
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
            setPadding(0, 0, UiKit.dp(this@RmmNoticesActivity, 12), UiKit.dp(this@RmmNoticesActivity, 4))
            isClickable = true
            setOnClickListener { finish() }
        })
        header.addView(TextView(this).apply {
            text = "Management & backup"
            textSize = 24f
            typeface = Fonts.medium(this@RmmNoticesActivity)
            setTextColor(UiKit.TEXT)
        })
        root.addView(header)

        // (a) MDM notices — W8 item 2: from the LIVE MdmService
        // when ControlService has constructed one (its in-memory
        // list is backed by the same durable file, so a notice
        // recorded this process is visible immediately); the
        // persisted store is the fallback when no live service
        // exists, and an absent/empty source still honestly
        // renders "No organisation actions…" below.
        root.addView(UiKit.sectionTitle(this, consentString(R.string.mdm_notice_title)))
        val noticeCard = UiKit.card(this)
        val liveService = io.deskguest.app.server.ControlService.sharedMdmService
        val notices: List<List<String>> = if (liveService != null) {
            io.deskguest.app.rmmspine.MdmWiring.liveNoticeRows(liveService)
        } else {
            val noticeFile = File(filesDir, "mdm-notices.tsv")
            if (noticeFile.isFile) {
                noticeFile.readLines().mapNotNull { line ->
                    val p = line.split('|')
                    if (p.size == 5) p else null
                }
            } else {
                emptyList()
            }
        }
        if (notices.isEmpty()) {
            noticeCard.addView(
                UiKit.muted(this, "No organisation actions have been recorded on this phone.")
            )
        } else {
            for (n in notices) {
                noticeCard.addView(UiKit.body(this, MdmSurfaceModel.noticeLine(n[2], n[3])))
            }
        }
        root.addView(noticeCard)

        // (b) Event subscriptions — listAll(), rendered in full.
        root.addView(UiKit.sectionTitle(this, "Who is watching events"))
        val eventCard = UiKit.card(this)
        val lines = MdmSurfaceModel.eventLines(EventSubscriptions.listAll())
        if (lines.isEmpty()) {
            eventCard.addView(UiKit.muted(this, "No pairing is subscribed to events."))
        } else {
            for (line in lines) eventCard.addView(UiKit.muted(this, line))
        }
        root.addView(eventCard)

        // (c) Backup key sheet (W5-B encryption path).
        root.addView(UiKit.sectionTitle(this, BackupKeySheetModel.title()))
        val keyCard = UiKit.card(this)
        keyCard.addView(UiKit.muted(this, BackupKeySheetModel.body()))
        val passphrase = EditText(this).apply {
            hint = "Backup passphrase"
            textSize = 15f
            typeface = Fonts.regular(this@RmmNoticesActivity)
            setTextColor(UiKit.TEXT)
            inputType = android.text.InputType.TYPE_CLASS_TEXT or
                android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
        }
        keyCard.addView(passphrase)
        val sheetView = UiKit.body(this, "")
        keyCard.addView(
            UiKit.primaryButton(this, "Show my backup key sheet") {
                val pass = passphrase.text.toString()
                if (pass.isBlank()) {
                    sheetView.text = "Enter the passphrase first — the sheet is derived from it."
                } else {
                    // The sheet is complete only with its salt:
                    // key = deriveKey(passphrase, salt) (W5-B),
                    // so both are shown, once, for the owner to
                    // keep together.
                    val salt = BackupCrypto.newSalt()
                    val key = BackupCrypto.deriveKey(pass, salt)
                    val keyHex = key.joinToString("") { "%02x".format(it) }
                        .chunked(4).joinToString(" ")
                    val saltHex = salt.joinToString("") { "%02x".format(it) }
                    sheetView.text = "Key: $keyHex\nSalt: $saltHex"
                }
            }
        )
        keyCard.addView(sheetView)
        root.addView(keyCard)
    }
}
