package io.agenticcontrol.app.server

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.media.AudioAttributes
import android.media.MediaPlayer
import android.media.RingtoneManager
import android.os.Handler
import android.os.Looper
import android.util.Base64
import io.agenticcontrol.app.CrashTrap
import io.agenticcontrol.app.R
import io.agenticcontrol.app.strings.consentString
import io.agenticcontrol.app.access.AppCards
import io.agenticcontrol.app.notify.AcpNotificationListener
import io.agenticcontrol.app.notify.NotificationCache
import io.agenticcontrol.app.notify.NotificationTriage
import io.agenticcontrol.app.safety.InvisibleAppStore
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.concurrent.atomic.AtomicInteger

/**
 * The BD-XCHECK owed Android tools (2026-11-22): the SPEC §6 names
 * that had no Android tool — notify_user, notifications_read,
 * file_list / file_pull / file_push, session_replay_data — plus
 * camera_capture, which is DE-SCOPED on Android and registered only
 * as an honest refusal (see its tool text and the lane log).
 *
 * Discipline, identical to the existing hosts:
 * - every tool is session/presence-bound exactly as its class
 *   requires: file tools and session_replay_data pass the drive /
 *   admin gates; notifications_read requires a live session
 *   (FEATURES §6: no ambient capture outside a session) on top of
 *   the user's own notification-listener grant; notify_user is the
 *   voice-grade exception the driving lockout deliberately leaves
 *   open (SPEC §7.7) — it posts a visible notification and nothing
 *   else, and works with or without a session because telling the
 *   user something is never a silent act.
 * - unavailable states report UNAVAILABLE with the reason and the
 *   user-side fix; nothing fakes a result.
 */
class OwedToolHost(context: Context) : McpCore.ToolHost {

    private val appContext = context.applicationContext

    override fun tools(): List<McpCore.ToolDef> = listOf(
        McpCore.ToolDef(
            "notify_user",
            "Post a message to the user's notification shade (a question, a completion, " +
                "a warning). Visible by design; capped at $MAX_NOTIFY_CHARS characters. " +
                "This is a voice-grade interaction: it stays available during the driving " +
                "lockout and needs no drive session.",
            "observe",
            schema("message" to "string", "title" to "string"),
            run = { args -> notifyUser(args) }
        ),
        McpCore.ToolDef(
            "notifications_read",
            "Read the phone's currently active notifications (app, title, text). Requires " +
                "a live session and the user's notification-access grant for this app " +
                "(system Settings → Notifications → Device & app notifications). Without " +
                "the grant it reports UNAVAILABLE — Android gives no other route.",
            "observe",
            emptySchema(),
            run = { notificationsRead() }
        ),
        McpCore.ToolDef(
            "file_list",
            "List the agent-files folder — the one folder the file tools may touch " +
                "(the app's own external-files folder, visible to the user in a file " +
                "manager). Requires an active session and the shell scope.",
            "shell",
            schema("subfolder" to "string"),
            run = { args -> fileList(args) }
        ),
        McpCore.ToolDef(
            "file_pull",
            "Read a file from the agent-files folder, returned base64. Capped at " +
                "${FileScope.MAX_FILE_BYTES} bytes. Requires an active session and the shell scope.",
            "shell",
            schema("name" to "string"),
            run = { args -> filePull(args) }
        ),
        McpCore.ToolDef(
            "file_push",
            "Write a file into the agent-files folder from base64 content. Capped at " +
                "${FileScope.MAX_FILE_BYTES} bytes; subject to the user's file-write " +
                "approval policy. Requires an active session and the shell scope.",
            "shell",
            schema("name" to "string", "content_base64" to "string"),
            run = { args -> filePush(args) }
        ),
        McpCore.ToolDef(
            "session_replay_data",
            "The recorded session-event timeline for replay (SPEC §7.6): session start, " +
                "pause, resume, end, budget and approval events with timestamps, for this " +
                "process's lifetime. Requires the admin scope. The durable evidence store " +
                "remains the audit log, which only the user exports in-app.",
            "admin",
            emptySchema(),
            run = { sessionReplayData() }
        ),
        McpCore.ToolDef(
            "crash_report_read",
            "Read this app's own most recent crash/failure report as structured data " +
                "(when, where it was caught, the top exception, frame count, full text). " +
                "Requires a live session. This is DeskGuest's own record only — " +
                "Android gives no route to other apps' crashes and none is offered.",
            "observe",
            emptySchema(),
            run = { crashReportRead() }
        ),
        McpCore.ToolDef(
            "app_card_read",
            "Read the per-app guidance card for a package (known quirks, preferred " +
                "flows) recorded on this device, or list which packages have cards " +
                "when no package is given. Requires a live session. Cards for apps on " +
                "the user's invisible-apps list are refused by rule.",
            "observe",
            schema("package" to "string"),
            run = { args -> appCardRead(args) }
        ),
        McpCore.ToolDef(
            "app_card_write",
            "Record or replace the per-app guidance card for a package, so a future " +
                "session consults it before driving that app. One note per app, capped " +
                "at ${AppCards.MAX_NOTE_CHARS} characters; a write replaces the note " +
                "whole. Requires an active drive session. Cards for invisible apps " +
                "are refused by rule.",
            "drive",
            schema("package" to "string", "note" to "string"),
            run = { args -> appCardWrite(args) }
        ),
        McpCore.ToolDef(
            "find_my_phone",
            "Ring this phone at full volume (even on silent) for a capped time and " +
                "show owner text on a notification — the owner asked for this through " +
                "you. Requires an active session; rate-limited to once a minute; the " +
                "ring always stops on its own. Text is capped at " +
                "${FindMyPhonePolicy.MAX_TEXT_CHARS} characters and is only ever shown, " +
                "never acted on.",
            "drive",
            schema("text" to "string", "seconds" to "integer"),
            run = { args -> findMyPhone(args) }
        ),
        McpCore.ToolDef(
            "camera_capture",
            "DE-SCOPED on Android (2026-11-22): there is no agent-triggered still-photo " +
                "tool on this host. Calling it returns the reason and the shipped " +
                "alternative (the owner-initiated camera share).",
            "observe",
            emptySchema(),
            run = {
                "UNAVAILABLE — de-scoped on Android (2026-11-22): an agent-triggered, " +
                    "full-resolution still photo cannot be taken within this product's " +
                    "consent law. Android requires a foreground camera session for " +
                    "capture; a photo taken by an agent call, outside an owner-started " +
                    "camera surface, would be ambient capture, which this product never " +
                    "does (FEATURES §6). The shipped camera path is the owner-initiated " +
                    "camera share / camera view (RMM-22): the user starts it, presence " +
                    "shows throughout, and the agent sees only what that session shows. " +
                    "Ask the user to start a camera share if you need to see something."
            }
        )
    )

    // ---- notify_user ----

    private fun notifyUser(args: JSONObject): String {
        SessionManager.observeRefusal()?.let { return it }
        val message = args.optString("message", "").trim()
        if (message.isEmpty()) return "notify_user needs a message."
        if (message.length > MAX_NOTIFY_CHARS) {
            return "notify_user message is capped at $MAX_NOTIFY_CHARS characters (got ${message.length})."
        }
        val now = System.currentTimeMillis()
        synchronized(notifyLock) {
            if (now - lastNotifyAtMs < MIN_NOTIFY_INTERVAL_MS) {
                return "Refused: notifications are rate-limited (one per " +
                    "${MIN_NOTIFY_INTERVAL_MS / 1000} seconds) so an agent cannot flood the shade."
            }
            lastNotifyAtMs = now
        }
        val title = args.optString("title", "").trim()
            .ifBlank { SessionManager.active?.agentName ?: "DeskGuest" }
        val manager = appContext.getSystemService(NotificationManager::class.java)
            ?: return "UNAVAILABLE: the notification service is not reachable."
        val channel = NotificationChannel(
            CHANNEL_ID, "Agent messages", NotificationManager.IMPORTANCE_HIGH
        ).apply { description = "Messages a paired agent posts for the user with notify_user" }
        manager.createNotificationChannel(channel)
        val notification = Notification.Builder(appContext, CHANNEL_ID)
            .setContentTitle(title)
            .setContentText(message)
            .setStyle(Notification.BigTextStyle().bigText(message))
            .setSmallIcon(android.R.drawable.ic_dialog_email)
            .setAutoCancel(true)
            .build()
        manager.notify(notifyIds.incrementAndGet(), notification)
        SessionManager.active?.let { SessionManager.noteAction("notify_user") }
        SessionEvents.emit("notification_posted", mapOf("chars" to message.length))
        return "Posted to the notification shade."
    }

    // ---- notifications_read ----

    private fun notificationsRead(): String {
        if (!SessionManager.isOpen) {
            return "Refused: notifications are only readable inside a live control " +
                "session — this product has no ambient capture (FEATURES §6)."
        }
        SessionManager.observeRefusal()?.let { return it }
        if (!AcpNotificationListener.connected) {
            return "UNAVAILABLE: notification access is not granted to DeskGuest. " +
                "The user grants it in system Settings → Notifications → Device & app " +
                "notifications → DeskGuest. Android gives no other route to " +
                "notifications, and this product uses no other route."
        }
        val active = NotificationCache.active()
        if (active.isEmpty()) return "No active notifications."
        val out = JSONArray()
        active.forEach { e ->
            val verdict = NotificationTriage.judge(e)
            out.put(
                JSONObject()
                    .put("app", e.packageName)
                    .put("title", e.title)
                    .put("text", e.text)
                    .put("postedAtMs", e.postedAtMs)
                    .put("urgency", verdict.urgency.name.lowercase())
                    .put("urgencyRule", verdict.rule)
            )
        }
        SessionManager.noteAction("notifications_read")
        return JSONObject().put("notifications", out).toString(2)
    }

    // ---- file tools ----

    private fun fileRoot(): File {
        val dir = appContext.getExternalFilesDir("agent-files")
            ?: File(appContext.filesDir, "agent-files")
        dir.mkdirs()
        return dir
    }

    private fun fileList(args: JSONObject): String {
        SessionManager.driveRefusal()?.let { return it }
        val root = fileRoot()
        val sub = args.optString("subfolder", "").trim()
        val dir = if (sub.isEmpty()) root else FileScope.resolve(root, sub)
            ?: return "Refused: '$sub' is not a folder inside the agent-files folder."
        if (!dir.exists()) return "The agent-files folder is empty (nothing has been pushed yet)."
        if (!dir.isDirectory) return "Refused: '$sub' is a file, not a folder."
        val entries = dir.listFiles()?.sortedBy { it.name } ?: emptyList()
        if (entries.isEmpty()) return "No files in ${if (sub.isEmpty()) "the agent-files folder" else sub}."
        val out = JSONArray()
        entries.forEach { f ->
            out.put(
                JSONObject()
                    .put("name", f.name)
                    .put("type", if (f.isDirectory) "folder" else "file")
                    .put("bytes", if (f.isDirectory) 0 else f.length())
            )
        }
        return JSONObject().put("files", out).toString(2)
    }

    private fun filePull(args: JSONObject): String {
        SessionManager.driveRefusal()?.let { return it }
        val name = args.optString("name", "")
        val file = FileScope.resolve(fileRoot(), name)
            ?: return "Refused: '$name' is not a plain name inside the agent-files folder " +
                "(no absolute paths, no '..', no paths outside the folder)."
        if (!file.exists() || !file.isFile) return "No such file in the agent-files folder: $name"
        if (file.length() > FileScope.MAX_FILE_BYTES) {
            return "Refused: $name is ${file.length()} bytes, over the ${FileScope.MAX_FILE_BYTES}-byte pull cap."
        }
        val bytes = try {
            file.readBytes()
        } catch (e: Exception) {
            return "UNAVAILABLE: could not read $name (${e.message ?: "read failed"})."
        }
        SessionManager.noteAction("file_pull $name")
        return JSONObject()
            .put("name", name)
            .put("bytes", bytes.size)
            .put("content_base64", Base64.encodeToString(bytes, Base64.NO_WRAP))
            .toString()
    }

    private fun filePush(args: JSONObject): String {
        SessionManager.driveRefusal()?.let { return it }
        val name = args.optString("name", "")
        val file = FileScope.resolve(fileRoot(), name)
            ?: return "Refused: '$name' is not a plain name inside the agent-files folder " +
                "(no absolute paths, no '..', no paths outside the folder)."
        val encoded = args.optString("content_base64", "")
        if (encoded.isEmpty()) return "file_push needs content_base64."
        val bytes = try {
            Base64.decode(encoded, Base64.DEFAULT)
        } catch (_: Exception) {
            return "Refused: content_base64 is not valid base64."
        }
        if (bytes.size > FileScope.MAX_FILE_BYTES) {
            return "Refused: content is ${bytes.size} bytes, over the ${FileScope.MAX_FILE_BYTES}-byte push cap."
        }
        gateRefusal(
            ApprovalGate.ActionClass.FILE_WRITE,
            "Write $name (${bytes.size} bytes) into the agent-files folder",
            // OI-12: the gate quotes the exact submitted encoding
            // of the bytes that will be written.
            payload = encoded
        )?.let { return it }
        return try {
            file.parentFile?.mkdirs()
            file.writeBytes(bytes)
            val readBack = file.readBytes()
            if (!readBack.contentEquals(bytes)) {
                "The write did not verify: read-back of $name differs from the content sent."
            } else {
                SessionManager.noteAction("file_push $name")
                "Wrote $name (${bytes.size} bytes) into the agent-files folder (verified by read-back)."
            }
        } catch (e: Exception) {
            "UNAVAILABLE: could not write $name (${e.message ?: "write failed"})."
        }
    }

    // ---- crash_report_read (W11-B: FEATURES §1 surfacing leg) ----

    private fun crashReportRead(): String {
        if (!SessionManager.isOpen) {
            return "Refused: the crash report is only readable inside a live control " +
                "session — this product has no ambient capture (FEATURES §6)."
        }
        SessionManager.observeRefusal()?.let { return it }
        val parsed = CrashReport.parse(CrashTrap.read(appContext))
            ?: return "No readable crash report: this app has not recorded a failure, " +
                "or the report was cleared by the user."
        SessionManager.noteAction("crash_report_read")
        return JSONObject()
            .put("recordedAt", parsed.recordedAt)
            .put("where", parsed.where)
            .put("exception", parsed.exceptionLine)
            .put("stackFrames", parsed.frameCount)
            .put("report", parsed.raw)
            .put(
                "scope",
                "DeskGuest's own most recent failure report only (the record " +
                    "keeps one). Other apps' crashes are not readable by a normal app."
            )
            .toString(2)
    }

    // ---- app cards (W11-B: FEATURES §2) ----

    private fun appCardsFile(): File = File(appContext.filesDir, "app-cards.json")

    private fun loadAppCards(): AppCards? {
        val file = appCardsFile()
        if (!file.exists()) return AppCards()
        return AppCards.decode(try { file.readText() } catch (_: Exception) { return null })
    }

    private fun appCardRead(args: JSONObject): String {
        if (!SessionManager.isOpen) {
            return "Refused: app cards are only readable inside a live control session."
        }
        SessionManager.observeRefusal()?.let { return it }
        val cards = loadAppCards()
            ?: return "UNAVAILABLE: the app-cards store on this phone is unreadable " +
                "(corrupt file). Nothing was guessed from it; the user can clear it " +
                "by deleting the app's data for cards, or a fresh write replaces it."
        val pkg = args.optString("package", "").trim()
        if (pkg.isEmpty()) {
            val known = cards.packages()
            return if (known.isEmpty()) {
                "No app cards recorded on this device yet."
            } else {
                JSONObject().put("packagesWithCards", JSONArray(known)).toString(2)
            }
        }
        if (InvisibleAppStore.isBlocked(appContext, pkg)) {
            return io.agenticcontrol.app.safety.InvisibleAppRules.refusal()
        }
        val note = cards.get(pkg)
            ?: return "No card recorded for $pkg on this device."
        SessionManager.noteAction("app_card_read")
        return JSONObject().put("package", pkg.lowercase()).put("note", note).toString(2)
    }

    private fun appCardWrite(args: JSONObject): String {
        SessionManager.driveRefusal()?.let { return it }
        val pkg = args.optString("package", "").trim()
        val note = args.optString("note", "")
        if (InvisibleAppStore.isBlocked(appContext, pkg)) {
            return io.agenticcontrol.app.safety.InvisibleAppRules.refusal()
        }
        val cards = loadAppCards()
            ?: return "UNAVAILABLE: the app-cards store on this phone is unreadable " +
                "(corrupt file); the write was refused rather than overwriting it blind."
        val key = cards.put(pkg, note)
            ?: return "Refused: '$pkg' is not a valid package name, the note is blank " +
                "or over ${AppCards.MAX_NOTE_CHARS} characters, or the store already " +
                "holds ${AppCards.MAX_CARDS} cards."
        return try {
            appCardsFile().writeText(cards.encode())
            SessionManager.noteAction("app_card_write $key")
            "Card recorded for $key (${note.trim().length} characters)."
        } catch (e: Exception) {
            "UNAVAILABLE: could not save the card (${e.message ?: "write failed"})."
        }
    }

    // ---- find_my_phone (W11-B: FEATURES §9) ----

    private fun findMyPhone(args: JSONObject): String {
        SessionManager.driveRefusal()?.let { return it }
        val text = FindMyPhonePolicy.ownerText(args.optString("text", ""))
            ?: return "Refused: owner text is capped at ${FindMyPhonePolicy.MAX_TEXT_CHARS} " +
                "characters (it is shown on a notification, never truncated silently)."
        val seconds = FindMyPhonePolicy.ringSeconds(args.optInt("seconds", 0))
        val now = System.currentTimeMillis()
        synchronized(ringLock) {
            if (!FindMyPhonePolicy.allowedNow(lastRingAtMs, now)) {
                return "Refused: find-my-phone is rate-limited to one ring per " +
                    "${FindMyPhonePolicy.MIN_INTERVAL_MS / 1000} seconds."
            }
            lastRingAtMs = now
        }
        val uri = RingtoneManager.getDefaultUri(RingtoneManager.TYPE_RINGTONE)
            ?: return "UNAVAILABLE: this phone has no default ringtone to play."
        val player = MediaPlayer()
        try {
            player.setDataSource(appContext, uri)
            player.setAudioAttributes(
                AudioAttributes.Builder()
                    .setUsage(AudioAttributes.USAGE_ALARM)
                    .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION)
                    .build()
            )
            player.isLooping = true
            player.prepare()
            player.start()
        } catch (e: Exception) {
            try { player.release() } catch (_: Exception) {}
            return "UNAVAILABLE: the ringtone could not be played (${e.message ?: "playback failed"})."
        }
        synchronized(ringLock) { activePlayer = player }
        Handler(Looper.getMainLooper()).postDelayed({
            synchronized(ringLock) {
                if (activePlayer === player) activePlayer = null
            }
            try { player.stop() } catch (_: Exception) {}
            try { player.release() } catch (_: Exception) {}
        }, seconds * 1000L)
        // The owner text rides a visible high-importance notification —
        // shown, never acted on (FindMyPhonePolicy).
        val manager = appContext.getSystemService(NotificationManager::class.java)
        if (manager != null) {
            val channel = NotificationChannel(
                FIND_CHANNEL_ID, "Find my phone", NotificationManager.IMPORTANCE_HIGH
            ).apply { description = "Owner text shown while find-my-phone rings" }
            manager.createNotificationChannel(channel)
            manager.notify(
                notifyIds.incrementAndGet(),
                Notification.Builder(appContext, FIND_CHANNEL_ID)
                    .setContentTitle("Find my phone")
                    .setContentText(text)
                    .setStyle(Notification.BigTextStyle().bigText(text))
                    .setSmallIcon(android.R.drawable.ic_dialog_alert)
                    .setAutoCancel(true)
                    .build()
            )
        }
        SessionManager.noteAction("find_my_phone")
        SessionEvents.emit("find_my_phone_ring", mapOf("seconds" to seconds))
        return "Ringing at full volume for $seconds seconds with the owner text shown. " +
            "The ring stops on its own; it cannot be looped or extended by another call " +
            "inside a minute."
    }

    // ---- session_replay_data ----

    private fun sessionReplayData(): String {
        val entries = ReplayLog.snapshot()
        val out = JSONArray()
        entries.forEach { e ->
            val obj = JSONObject()
                .put("atMs", e.atMs)
                .put("state", e.state)
            e.detail.forEach { (k, v) -> obj.put(k, v) }
            out.put(obj)
        }
        return JSONObject()
            .put("events", out)
            .put("droppedOldest", ReplayLog.droppedCount())
            .put(
                "scope",
                "This process's lifetime, in memory. The durable evidence store is the " +
                    "audit log, exported by the user in-app."
            )
            .toString(2)
    }

    // ---- helpers (mirrors AccessToolHost's gate) ----

    private fun gateRefusal(
        actionClass: ApprovalGate.ActionClass, summary: String,
        // W7 item 2 (§3/OI-12): the REAL submitted payload.
        payload: String? = null,
        fromChat: Boolean = false
    ): String? {
        val policy = ApprovalSettings.load(appContext, actionClass)
        return when (ApprovalGate.decide(policy)) {
            ApprovalGate.Decision.ALLOW -> null
            ApprovalGate.Decision.DENY ->
                "Refused: the user's approval policy blocks ${actionClass.label.lowercase()} " +
                    "actions. They can change it in the app, under Approvals."
            ApprovalGate.Decision.ASK -> {
                // FR-123: a session-less caller is named plainly as
                // unnamed through the U8 strings door — never the
                // fabricated generic "Your AI".
                val agent = SessionManager.active?.agentName?.takeIf { it.isNotBlank() }
                    ?: appContext.consentString(R.string.gate_unnamed_caller)
                if (ApprovalOverlay.requestApproval(
                        appContext, actionClass, summary, agent,
                        payload = payload, fromChat = fromChat,
                        onDenyAndEnd = GateDenyAndEnd.handler(actionClass)
                    )
                ) {
                    null
                } else {
                    "Not approved: the user did not approve this ${actionClass.label.lowercase()} " +
                        "action (denied, timed out, or the prompt could not be shown)."
                }
            }
        }
    }

    private fun emptySchema(): JSONObject =
        JSONObject().put("type", "object").put("properties", JSONObject())

    private fun schema(vararg fields: Pair<String, String>): JSONObject {
        val props = JSONObject()
        fields.forEach { (name, type) -> props.put(name, JSONObject().put("type", type)) }
        return JSONObject().put("type", "object").put("properties", props)
    }

    companion object {
        private const val CHANNEL_ID = "agent_messages"
        private const val FIND_CHANNEL_ID = "find_my_phone"
        private val ringLock = Any()

        @Volatile
        private var lastRingAtMs = 0L

        @Volatile
        private var activePlayer: MediaPlayer? = null
        private const val MAX_NOTIFY_CHARS = 1_000
        private const val MIN_NOTIFY_INTERVAL_MS = 5_000L
        private val notifyIds = AtomicInteger(2000)
        private val notifyLock = Any()

        @Volatile
        private var lastNotifyAtMs = 0L
    }
}
