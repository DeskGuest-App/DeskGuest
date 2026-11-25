package io.agenticcontrol.app.server

import android.os.Build
import org.json.JSONObject

/**
 * The S1 tool set (SPEC §6 observe class), implemented against the
 * phone itself. Drive-class tools arrive in S2 behind the presence
 * layer; nothing here can change device state.
 */
class PhoneToolHost(
    private val serverStartedAtMs: Long,
    private val appVersion: String,
    private val appContext: android.content.Context? = null
) : McpCore.ToolHost {

    override fun tools(): List<McpCore.ToolDef> = listOf(
        McpCore.ToolDef(
            name = "device_info",
            description = "Model, maker, Android version, and host app state of this phone.",
            scope = "observe",
            inputSchema = emptySchema(),
            run = { deviceInfo() }
        ),
        McpCore.ToolDef(
            name = "session_status",
            description = "Whether a control session is active, which agent is paired, and server uptime.",
            scope = "observe",
            inputSchema = emptySchema(),
            run = { sessionStatus() }
        )
    )

    private fun deviceInfo(): String {
        val info = JSONObject()
            .put("manufacturer", Build.MANUFACTURER)
            .put("model", Build.MODEL)
            .put("device", Build.DEVICE)
            .put("androidVersion", Build.VERSION.RELEASE)
            .put("sdkInt", Build.VERSION.SDK_INT)
            .put("hostAppVersion", appVersion)
        appContext?.let { ctx ->
            val presence = io.agenticcontrol.app.presence.PresenceOverlay.diagnostics(ctx)
            val presenceJson = JSONObject()
            presence.forEach { (k, v) -> presenceJson.put(k, v) }
            info.put("presence", presenceJson)
        }
        return info.toString(2)
    }

    private fun sessionStatus(): String {
        val uptimeSec = (System.currentTimeMillis() - serverStartedAtMs) / 1000
        val status = JSONObject().put("serverUptimeSeconds", uptimeSec)
        val session = SessionManager.active
        if (session == null) {
            status.put("sessionActive", false)
                .put("state", "idle")
        } else {
            status.put("sessionActive", SessionManager.state == SessionManager.State.ACTIVE)
                .put("state", when (SessionManager.state) {
                    SessionManager.State.PAUSED_BY_USER -> "paused_by_user"
                    SessionManager.State.ACTIVE -> "active"
                    SessionManager.State.IDLE -> "idle"
                })
                .put("agent", session.agentName)
                .put("sessionSeconds", (System.currentTimeMillis() - session.startedAtMs) / 1000)
                .put("actions", session.actions)
                .put("lastAction", session.lastAction)
            // U4: owner-visible budget state — caps, counts, and
            // the tripwire pause reason ride the existing status.
            val budgetSnap = SessionBudget.snapshot()
            status.put("budget", JSONObject()
                .put("caps", JSONObject(budgetSnap["caps"] as Map<*, *>))
                .put("counts", JSONObject(budgetSnap["counts"] as Map<*, *>))
                .put("tripped", budgetSnap["tripped"] as Boolean))
            SessionManager.budgetPauseReason?.let { status.put("budgetPauseReason", it) }
            if (session.intent.isNotBlank()) status.put("intent", session.intent)
        }
        return status.toString(2)
    }

    private fun emptySchema(): JSONObject =
        JSONObject().put("type", "object").put("properties", JSONObject())
}
