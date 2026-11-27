package io.deskguest.app

import android.app.Activity
import android.os.Bundle
import android.view.Gravity
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import io.deskguest.app.chat.AgentChatStore
import io.deskguest.app.design.AgentChatModel
import io.deskguest.app.design.SessionDetailModel
import io.deskguest.app.server.ApprovalGate
import io.deskguest.app.server.ApprovalOverlay
import io.deskguest.app.server.ControlService
import io.deskguest.app.server.GateDenyAndEnd
import io.deskguest.app.server.SessionEvents
import io.deskguest.app.strings.consentString
import io.deskguest.app.ui.Fonts
import io.deskguest.app.ui.UiKit
import java.io.File

/**
 * W7 item 6 — Agent chat (§4 A17 / Addendum A). The thread lives
 * on the agent card; this is its surface. It is NOT a session:
 * no presence is shown, nothing here grants a capability, and
 * sending a message starts nothing. A standing destination line
 * under the composer states where messages go. "Ask to act"
 * routes the ask through the ordinary approval gate with the
 * chat origin line — chat cannot approve. Off-device messages
 * count as Sent in the data-flow ledger (AgentChatStore →
 * DataFlows). Unpairing ends the thread (MainActivity's Unpair
 * removes it); a missing pairing renders the thread-ended line.
 */
class AgentChatActivity : Activity() {

    private lateinit var root: LinearLayout
    private var pairingToken: String = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        pairingToken = intent.getStringExtra(EXTRA_PAIRING_TOKEN) ?: ""
        root = UiKit.page(this)
        render()
    }

    private fun chatDir(): File = File(filesDir, "agent-chat")

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
            setPadding(0, 0, UiKit.dp(this@AgentChatActivity, 12), UiKit.dp(this@AgentChatActivity, 4))
            isClickable = true
            setOnClickListener { finish() }
        })
        header.addView(TextView(this).apply {
            text = "Agent chat"
            textSize = 24f
            typeface = Fonts.medium(this@AgentChatActivity)
            setTextColor(UiKit.TEXT)
        })
        root.addView(header)

        val pairing = ControlService.sharedPairingStore?.pairingForToken(pairingToken)
        if (pairing == null) {
            // Unpaired (or never paired): the thread has ended.
            root.addView(UiKit.body(this, consentString(R.string.chat_thread_ended)))
            return
        }
        // FR-123: an unnamed pairing is labelled truthfully through
        // the U8 strings door — never a generic name, never blank
        // (this value also names the caller at the chat gate below).
        val agentName = pairing.agentName.ifBlank { pairing.name }
            .ifBlank { consentString(R.string.pairing_unnamed_label) }
        val pairingId = pairing.id

        val sent = AgentChatStore.sentCount(pairingId)
        if (sent > 0) {
            root.addView(UiKit.muted(this, SessionDetailModel.chatSentLine(sent.toInt())))
        }

        val messages = AgentChatStore.load(chatDir(), pairingId)
        if (messages.isEmpty()) {
            root.addView(UiKit.muted(this, "No messages yet."))
        }
        for (message in messages) {
            val who = if (message.direction == AgentChatStore.DIR_OWNER) "You" else agentName
            root.addView(UiKit.body(this, "$who: ${message.body}"))
        }

        val composer = EditText(this).apply {
            hint = "Message $agentName"
            textSize = 15f
            typeface = Fonts.regular(this@AgentChatActivity)
            setTextColor(UiKit.TEXT)
            minLines = 2
        }
        root.addView(composer)
        // The standing destination line under the composer (A17).
        root.addView(
            UiKit.muted(
                this,
                AgentChatModel.destinationLine(agentName, "its own device")
            )
        )
        root.addView(UiKit.primaryButton(this, "Send") {
            val text = composer.text.toString().trim()
            if (text.isNotBlank()) {
                val event = AgentChatStore.append(
                    chatDir(), pairingId, AgentChatStore.DIR_OWNER,
                    text, System.currentTimeMillis(), agentOffDevice = true
                )
                SessionEvents.emit("chat_message_sent", event)
                render()
            }
        })
        root.addView(UiKit.muted(this, AgentChatModel.gateNoteLine()))
        root.addView(UiKit.outlineButton(this, consentString(R.string.chat_ask_to_act)) {
            val ask = composer.text.toString().trim()
            if (ask.isNotBlank()) {
                Thread {
                    // W10 (V3-F2): the gate's answer now has a
                    // consequence. An APPROVED ask is appended to
                    // the thread as the owner's own message — that
                    // is what the agent reads (chat_read) and acts
                    // on through its ordinary gated tools. A denied
                    // or timed-out ask appends nothing: the thread
                    // never carries an ask the owner refused at
                    // the gate. (Previously the result was discarded
                    // and approval changed nothing at all.)
                    val approved = ApprovalOverlay.requestApproval(
                        applicationContext,
                        ApprovalGate.ActionClass.CHAT_REQUEST,
                        "Act on a request from Agent chat",
                        agentName,
                        payload = ask,
                        fromChat = true,
                        onDenyAndEnd = GateDenyAndEnd.handler(
                            ApprovalGate.ActionClass.CHAT_REQUEST
                        )
                    )
                    if (approved) {
                        val event = AgentChatStore.append(
                            chatDir(), pairingId, AgentChatStore.DIR_OWNER,
                            ask, System.currentTimeMillis(), agentOffDevice = true
                        )
                        SessionEvents.emit("chat_message_sent", event)
                        runOnUiThread { render() }
                    }
                }.start()
            }
        })
    }

    companion object {
        const val EXTRA_PAIRING_TOKEN = "pairing_token"
    }
}
