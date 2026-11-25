package io.agenticcontrol.app

import android.app.Activity
import android.os.Bundle
import android.view.Gravity
import android.view.ViewGroup
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import io.agenticcontrol.app.session.SessionStore
import io.agenticcontrol.app.ui.Fonts
import io.agenticcontrol.app.ui.UiKit
import io.agenticcontrol.app.wiring.PlatformRuntime
import io.agenticcontrol.app.wiring.PlatformStores
import java.util.UUID

/**
 * "Sessions" — the Slice 3 human session model, live (wired 0.4.6).
 * The list and detail read the same SessionStore the MCP surface
 * exposes to a paired agent, so what is here is what the agent sees.
 *
 * Consent on this screen: Accept calls the wiring layer's local
 * accept ONLY — this screen IS the endpoint's own local UI, the one
 * origin the store honors (RULING 2026-11-19). There is no other
 * accept path in this screen or beneath it. STOP is offered for
 * every session that has not ended, and terminates it from
 * whatever state it is in.
 *
 * Recording state is shown from the record's derived isRecording —
 * a session that is recording says so here, always; there is no
 * state in which recording is on and this screen does not show it.
 */
class SessionsActivity : Activity() {

    private lateinit var root: LinearLayout
    private lateinit var stores: PlatformStores

    private var selectedSessionId: String? = null
    private var actorId: String = ""
    private var newKind: String = SessionStore.KIND_ATTENDED
    private var newRecording: String = SessionStore.RECORDING_NONE

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        stores = PlatformRuntime.get(this)
        root = UiKit.page(this)
        refresh()
    }

    private fun refresh() {
        root.removeAllViews()
        renderHeader()
        section("list") { renderList() }
        section("create") { renderCreate() }
        val selected = selectedSessionId
        if (selected != null && stores.sessionDetail(selected) != null) {
            section("detail") { renderDetail(selected) }
        }
    }

    private fun section(name: String, block: () -> Unit) {
        try {
            block()
        } catch (t: Throwable) {
            CrashTrap.record(this, "sessions section '$name'", t)
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
            setPadding(0, 0, UiKit.dp(this@SessionsActivity, 12), UiKit.dp(this@SessionsActivity, 4))
            isClickable = true
            setOnClickListener { finish() }
        })
        header.addView(TextView(this).apply {
            text = "Sessions"
            textSize = 24f
            typeface = Fonts.medium(this@SessionsActivity)
            setTextColor(UiKit.TEXT)
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        })
        root.addView(header)
    }

    private fun renderList() {
        root.addView(UiKit.sectionTitle(this, "Remote sessions"))
        val all = stores.allSessions()
        if (all.isEmpty()) {
            root.addView(UiKit.muted(this, "No sessions yet. Create one below, or one appears here when a session is requested."))
            return
        }
        all.forEach { session ->
            val detail = stores.sessionDetail(session.id)
            val card = UiKit.card(this)
            val row = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
            }
            row.addView(TextView(this).apply {
                text = session.id
                textSize = 16f
                typeface = Fonts.medium(this@SessionsActivity)
                setTextColor(UiKit.TEXT)
                layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
            })
            row.addView(UiKit.chip(this, session.state, when (session.state) {
                SessionStore.STATE_ACTIVE -> UiKit.ChipKind.GOOD
                SessionStore.STATE_BLOCKED -> UiKit.ChipKind.BAD
                SessionStore.STATE_ENDED -> UiKit.ChipKind.NEUTRAL
                else -> UiKit.ChipKind.WARN
            }))
            card.addView(row)
            card.addView(UiKit.muted(this, "${session.kind} · host ${session.hostDeviceId.take(12)}… · on ${session.transportRung}"))
            if (detail?.isRecording == true) {
                card.addView(UiKit.chip(this, "Recording: ${session.recording}", UiKit.ChipKind.BAD))
            }
            val floor = detail?.floorHolderUserId
            card.addView(UiKit.muted(this, if (floor != null) "Floor held by $floor" else "Nobody holds the floor"))
            card.addView(UiKit.outlineButton(this, if (session.id == selectedSessionId) "Close" else "Open") {
                selectedSessionId = if (session.id == selectedSessionId) null else session.id
                val host = stores.sessionDetail(session.id)?.participants
                    ?.firstOrNull { it.role == SessionStore.ROLE_HOST }?.userId
                if (actorId.isBlank() && host != null) actorId = host
                refresh()
            })
            root.addView(card)
        }
    }

    private fun renderCreate() {
        root.addView(UiKit.sectionTitle(this, "New session"))
        val card = UiKit.card(this)
        card.addView(
            UiKit.muted(
                this,
                "A session starts in Requested. An attended session can only start after " +
                    "the host accepts it here, on this device. An unattended session needs " +
                    "the initiator to hold the Use right on the host's device group."
            )
        )
        val scopeField = field("Scope ID")
        val deviceField = field("Host device ID")
        val initiatorField = field("Initiator user ID")
        val hostUserField = field("Host user ID (the person at the host device)")
        val rungField = field("Transport rung (e.g. lan)")
        card.addView(scopeField)
        card.addView(deviceField)
        card.addView(initiatorField)
        card.addView(hostUserField)
        card.addView(rungField)
        card.addView(UiKit.navRow(this, "Kind", newKind) {
            newKind = if (newKind == SessionStore.KIND_ATTENDED) {
                SessionStore.KIND_UNATTENDED
            } else {
                SessionStore.KIND_ATTENDED
            }
            refresh()
        })
        card.addView(UiKit.navRow(this, "Recording", newRecording) {
            newRecording = when (newRecording) {
                SessionStore.RECORDING_NONE -> SessionStore.RECORDING_VIDEO
                SessionStore.RECORDING_VIDEO -> SessionStore.RECORDING_REPLAY
                SessionStore.RECORDING_REPLAY -> SessionStore.RECORDING_BOTH
                else -> SessionStore.RECORDING_NONE
            }
            refresh()
        })
        card.addView(UiKit.primaryButton(this, "Create session") {
            val scopeId = scopeField.text.toString().trim()
            val deviceId = deviceField.text.toString().trim()
            val initiator = initiatorField.text.toString().trim()
            val hostUser = hostUserField.text.toString().trim()
            val rung = rungField.text.toString().trim()
            if (scopeId.isEmpty() || deviceId.isEmpty() || initiator.isEmpty() || hostUser.isEmpty() || rung.isEmpty()) {
                toast("Fill in the scope, host device, initiator, host user, and rung.")
                return@primaryButton
            }
            val id = "s-" + UUID.randomUUID().toString().take(8)
            val ok = stores.createSession(id, scopeId, deviceId, initiator, hostUser, newKind, rung, newRecording)
            if (ok) {
                selectedSessionId = id
                actorId = hostUser
                toast("Session $id created — requested.")
            } else {
                toast("That session was refused — check the scope, the device's group membership and transports, the users, and (for unattended) the Use right.")
            }
            refresh()
        })
        // Block C transport core: start over the transport layer.
        // The engine walks the device's resolved transport set in
        // order (D32); an address here is connect-by-address on the
        // lan rung (D19). The rung field above, when filled, pins
        // the walk to that rung (manual mode, within the set only).
        val addressField = field("Device address (host or host:port) — for LAN / connect-by-address")
        card.addView(addressField)
        // Block C part 3: the peer's tailnet address serves both
        // mesh-carried rungs — `hub` (the ACP hub) and `mesh` (the
        // operator's own Tailscale tailnet, setup-gated).
        val tailnetField = field("Peer tailnet address (100.64.x.x) — for the hub / mesh rungs")
        card.addView(tailnetField)
        card.addView(UiKit.outlineButton(this, "Create + start over the transport layer") {
            val scopeId = scopeField.text.toString().trim()
            val deviceId = deviceField.text.toString().trim()
            val initiator = initiatorField.text.toString().trim()
            val hostUser = hostUserField.text.toString().trim()
            val rung = rungField.text.toString().trim()
            if (scopeId.isEmpty() || deviceId.isEmpty() || initiator.isEmpty() || hostUser.isEmpty()) {
                toast("Fill in the scope, host device, initiator, and host user.")
                return@outlineButton
            }
            val tailnet = tailnetField.text.toString().trim().ifEmpty { null }
            val newId = stores.startTransportSession(
                scopeId, deviceId, initiator, hostUser, newKind,
                address = addressField.text.toString().trim().ifEmpty { null },
                hubAddress = tailnet,
                meshAddress = tailnet,
                recording = newRecording,
                manualPins = if (rung.isEmpty()) null else listOf(rung)
            )
            if (newId != null) {
                selectedSessionId = newId
                actorId = initiator
                toast("Session $newId started over the transport layer.")
            } else {
                val last = stores.transportEvents().lastOrNull()
                toast("Transport start failed${last?.let { " — ${it.kind}: ${it.detail}" } ?: ""}")
            }
            refresh()
        })
        root.addView(card)
    }

    private fun renderDetail(sessionId: String) {
        val detail = stores.sessionDetail(sessionId) ?: return
        val session = detail.session
        root.addView(UiKit.sectionTitle(this, "Session ${session.id}"))
        val card = UiKit.card(this)
        val chips = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        chips.addView(UiKit.chip(this, session.state, UiKit.ChipKind.ACCENT))
        chips.addView(UiKit.chip(this, session.kind, UiKit.ChipKind.NEUTRAL))
        if (detail.isRecording) chips.addView(UiKit.chip(this, "Recording: ${session.recording}", UiKit.ChipKind.BAD))
        card.addView(chips)
        // W6 design record §4 A4: the detail opens with the verdict
        // sentence, then the three counts as separate labelled
        // numbers (never an equation), destinations, the fixed
        // provider line, the vendor line, gaps, and the presence /
        // replay honesty lines — built by SessionDetailModel from
        // the real DataFlows counters.
        run {
            val report = io.agenticcontrol.app.server.DataFlows.report()
            fun calls(cls: String): Int = report.agents.sumOf { a ->
                (a.byClass(cls)?.calls ?: 0L).toInt()
            }
            // W7 item 4 (§4 A4): Sent counts DELIVERED FRAMES
            // (counted at the frame source in McpCore/DataFlows),
            // plus chat messages sent off-device — never calls.
            val framesSent = io.agenticcontrol.app.server.DataFlows.totalFramesDelivered()
            val chatSent = io.agenticcontrol.app.server.DataFlows.totalChatSent()
            val counts = io.agenticcontrol.app.design.SessionDetailModel.Counts(
                read = calls(io.agenticcontrol.app.server.DataFlows.READ),
                sent = (framesSent + chatSent).toInt(),
                changed = calls(io.agenticcontrol.app.server.DataFlows.CHANGED)
            )
            val agentName = report.agents.firstOrNull()?.agentName
                ?.ifBlank { null } ?: session.initiatorUserId
            val model = io.agenticcontrol.app.design.SessionDetailModel.build(
                verdict = "Session ${session.id} — ${session.state.lowercase()}",
                counts = counts,
                agentName = agentName,
                agentDevice = session.hostDeviceId,
                screens = counts.read + counts.sent,
                gaps = report.gaps
            )
            card.addView(UiKit.body(this, model.verdict))
            for ((label, n) in model.counts.labelled()) {
                card.addView(UiKit.muted(this, "$label: $n"))
            }
            card.addView(
                UiKit.muted(
                    this,
                    io.agenticcontrol.app.design.FrameAccounting.detailLine(
                        framesSent, agentName, hadUncountableSource = false
                    )
                )
            )
            card.addView(UiKit.muted(this, model.destinationLine))
            card.addView(UiKit.muted(this, model.providerLine))
            card.addView(UiKit.muted(this, model.vendorLine))
            model.gapsLine?.let { card.addView(UiKit.muted(this, it)) }
            card.addView(UiKit.muted(this, model.presenceOnFramesLine))
            card.addView(UiKit.muted(this, model.replayLine))
        }
        card.addView(UiKit.muted(this, "Scope ${session.scopeId} · host device ${session.hostDeviceId}"))
        card.addView(UiKit.muted(this, "Initiator ${session.initiatorUserId} · transport ${session.transportRung}"))
        card.addView(UiKit.muted(this, "Recording setting: ${session.recording}" + (session.recordingRef?.let { " · stored at $it" } ?: "")))
        if (session.acceptBy != null) {
            card.addView(UiKit.muted(this, "Accepted by ${session.acceptBy} at this device, locally"))
        }
        if (session.endReason != null) {
            card.addView(UiKit.muted(this, "Ended: ${session.endReason}"))
        }
        // participants + floor
        card.addView(UiKit.body(this, "Participants"))
        detail.participants.forEach { participant ->
            val row = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
            }
            row.addView(TextView(this).apply {
                text = participant.userId
                textSize = 15f
                typeface = Fonts.regular(this@SessionsActivity)
                setTextColor(UiKit.TEXT)
                layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
            })
            row.addView(UiKit.chip(this, participant.role, UiKit.ChipKind.NEUTRAL))
            row.addView(UiKit.chip(
                this,
                if (participant.floor == SessionStore.FLOOR_HOLDS) "holds the floor" else "watching",
                if (participant.floor == SessionStore.FLOOR_HOLDS) UiKit.ChipKind.GOOD else UiKit.ChipKind.NEUTRAL
            ))
            // D35 (Block F): the transport this participant's
            // traffic rides — the session's rung, named per row.
            row.addView(UiKit.chip(this, "via ${session.transportRung}", UiKit.ChipKind.NEUTRAL))
            card.addView(row)
            if (session.state == SessionStore.STATE_ACTIVE || session.state == SessionStore.STATE_PAUSED) {
                val actions = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
                if (participant.floor != SessionStore.FLOOR_HOLDS) {
                    actions.addView(UiKit.textButton(this, "Give floor") {
                        act(stores.grantFloor(sessionId, actorId, participant.userId), "Floor granted.", "Refused — floor acts belong to the host or a company admin, and watchers cannot hold the floor.")
                    })
                }
                actions.addView(UiKit.textButton(this, "Watch only") {
                    act(stores.setWatchOnly(sessionId, actorId, participant.userId), "Set to watch-only.", "Refused — that act belongs to the host or a company admin.")
                })
                actions.addView(UiKit.textButton(this, "Remove") {
                    act(stores.removeParticipant(sessionId, actorId, participant.userId), "Participant removed.", "Refused — that act belongs to the host or a company admin.")
                })
                card.addView(actions)
            }
        }
        if (detail.participants.any { it.floor == SessionStore.FLOOR_HOLDS }) {
            card.addView(UiKit.textButton(this, "Take the floor back") {
                act(stores.takeFloorBack(sessionId, actorId), "Floor is back with the host.", "Refused — that act belongs to the host or a company admin.")
            })
        }
        // actor + session acts
        val actorField = field("Acting as (user ID)").apply { setText(actorId) }
        card.addView(actorField)
        card.addView(UiKit.outlineButton(this, "Use this actor") {
            actorId = actorField.text.toString().trim()
            refresh()
        })
        if (session.kind == SessionStore.KIND_ATTENDED && session.state == SessionStore.STATE_REQUESTED && session.acceptBy == null) {
            val hostUserId = detail.participants.firstOrNull { it.role == SessionStore.ROLE_HOST }?.userId
            card.addView(
                UiKit.muted(
                    this,
                    "Accepting happens here, on this device, by the person at it. " +
                        "An accept sent from anywhere else is refused."
                )
            )
            card.addView(UiKit.primaryButton(this, "Accept this session here") {
                if (hostUserId == null) {
                    toast("This session has no host participant to accept as.")
                    return@primaryButton
                }
                act(stores.acceptLocal(sessionId, hostUserId), "Accepted at this device.", "Refused — only the host participant can accept, and only here.")
            })
        }
        if (session.state != SessionStore.STATE_ENDED) {
            if (session.state == SessionStore.STATE_REQUESTED) {
                card.addView(UiKit.primaryButton(this, "Start session") {
                    act(stores.startSession(sessionId, actorId), "Session started.", "Refused — an attended session needs the host's accept here first; an unattended one needs its Use right still in place.")
                })
            }
            if (session.state == SessionStore.STATE_ACTIVE) {
                card.addView(UiKit.outlineButton(this, "Pause") {
                    act(stores.pauseSession(sessionId, actorId), "Session paused.", "Refused.")
                })
            }
            if (session.state == SessionStore.STATE_PAUSED) {
                card.addView(UiKit.primaryButton(this, "Resume") {
                    act(stores.startSession(sessionId, actorId), "Session resumed.", "Refused — the grant, device, and rung are re-checked on resume.")
                })
            }
            if (session.state == SessionStore.STATE_ACTIVE || session.state == SessionStore.STATE_PAUSED) {
                card.addView(UiKit.outlineButton(this, "Block") {
                    act(stores.blockSession(sessionId, actorId), "Session blocked. From here it can only be ended — STOP still works.", "Refused.")
                })
            }
            if (session.state == SessionStore.STATE_ACTIVE || session.state == SessionStore.STATE_PAUSED) {
                // Block C part 3: when the next rung is hub or mesh,
                // the peer's tailnet address is needed to reach it.
                val failoverTailnetField = field("Next rung tailnet address (100.64.x.x) — when failing over to hub / mesh")
                card.addView(failoverTailnetField)
                card.addView(UiKit.outlineButton(this, "Fail over to the next rung") {
                    // Block C: the current session ENDS (transport_failover)
                    // and a new one re-establishes on the next rung of its
                    // set — a reconnect, linked by events. Only works for
                    // sessions this device started over the transport layer.
                    val tailnet = failoverTailnetField.text.toString().trim().ifEmpty { null }
                    val newId = stores.reestablishTransportSession(sessionId, hubAddress = tailnet, meshAddress = tailnet)
                    if (newId != null) {
                        selectedSessionId = newId
                        toast("Re-established as session $newId on the next rung. The previous session ended (transport failover).")
                    } else {
                        toast("No failover — this session was not started over the transport layer here, or no next rung remains in its set.")
                    }
                    refresh()
                })
            }
            card.addView(UiKit.outlineButton(this, "End session") {
                act(stores.endSession(sessionId, actorId), "Session ended.", "Refused.")
            })
            card.addView(UiKit.stopButton(this) {
                // bd-and-rest F2 fix: STOP on this device's own
                // screen is a LOCAL-origin stop — it needs no typed
                // actor and can never come back refused over one.
                // (The actor-gated STOP keeps its host/admin gate
                // in the store; this button is the person holding
                // the phone, and STOP outranks everything for them.)
                act(stores.stopSessionLocal(sessionId), "Session stopped.", "Refused — this session could not be stopped locally.")
            })
        }
        root.addView(card)
        // U5 data-flow transparency (fields only, no new screen):
        // per-agent flows counted at the MCP dispatch choke point +
        // standalone-transfer bytes per target device, cross-checked
        // against the audit counts this device already keeps. Gaps
        // print as gaps — nothing here estimates a byte.
        val flowsCard = UiKit.card(this)
        flowsCard.addView(UiKit.body(this, "Data flows (this device)"))
        io.agenticcontrol.app.server.DataFlows.summaryLines()
            .forEach { line -> flowsCard.addView(UiKit.muted(this, line)) }
        root.addView(flowsCard)
        // events (the replay source, D36 form 2)
        val eventsCard = UiKit.card(this)
        eventsCard.addView(UiKit.body(this, "Events"))
        if (detail.events.isEmpty()) eventsCard.addView(UiKit.muted(this, "No events yet."))
        detail.events.forEach { event ->
            eventsCard.addView(UiKit.muted(this, "${event.type} — ${event.actorUserId} ${event.detail}"))
        }
        root.addView(eventsCard)
    }

    private fun act(ok: Boolean, success: String, refusal: String) {
        toast(if (ok) success else refusal)
        refresh()
    }

    private fun field(hint: String): EditText = EditText(this).apply {
        this.hint = hint
        isSingleLine = true
        textSize = 16f
        typeface = Fonts.regular(this@SessionsActivity)
        setTextColor(UiKit.TEXT)
        setHintTextColor(UiKit.SECONDARY)
        background = null
    }

    private fun toast(text: String) =
        Toast.makeText(this, text, Toast.LENGTH_LONG).show()
}
