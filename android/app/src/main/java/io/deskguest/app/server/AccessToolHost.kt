package io.deskguest.app.server

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import io.deskguest.app.AppForeground
import io.deskguest.app.R
import io.deskguest.app.strings.consentString
import io.deskguest.app.access.ControlAccessibilityService
import io.deskguest.app.access.SnapshotStore
import io.deskguest.app.access.WaitCondition
import io.deskguest.app.presence.PresenceSettings
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * The screen tools (SPEC §6), backed by the accessibility service.
 * Observe tools (snapshot, screenshot, current_app) need the
 * accessibility grant to see anything; drive tools additionally need
 * an active session and the drive scope. When the service is not
 * bound, tools answer honestly with the reason and the fix — they are
 * never hidden and never fake a result.
 *
 * 0.4.0 consent hardening, enforced here on the host (never left to
 * the agent's manners): every drive tool checks SessionManager's
 * refusal first (no session / paused-by-user / stale screen after a
 * resume); capture suspends while the user has taken over; password
 * fields are refused as type_text targets and their content is
 * redacted at collection; secure windows refuse capture; and drive
 * tools accept an optional `intent` — what the agent is about to do,
 * in plain words — which the banner shows the user.
 */
class AccessToolHost(private val appContext: Context) : McpCore.ToolHost {

    @Volatile
    private var core: McpCore? = null

    override fun attach(core: McpCore) {
        this.core = core
    }

    /**
     * The approval gate (0.4.0): returns a refusal string when the
     * action may not proceed — policy Blocked, or Ask First without
     * an explicit Approve on the phone — and null when it may. The
     * prompt is shown by the host (ApprovalOverlay); the agent only
     * ever sees the outcome.
     */
    private fun gateRefusal(
        actionClass: ApprovalGate.ActionClass, summary: String,
        // W7 item 2 (§3/OI-12): the REAL submitted payload, quoted
        // verbatim by the gate — never a re-typed rendering.
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
                // unnamed through the U8 strings door — the gate
                // never presents the fabricated generic "Your AI".
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

    private val unavailable =
        "Unavailable: the DeskGuest accessibility service is not enabled on this phone. " +
            "The user enables it in the app's setup guide (Accessibility step). Until then I cannot see or touch the screen."

    /** The caller's stated intent, shown on the banner (SPEC §7). */
    private fun noteIntent(args: JSONObject) {
        val intent = args.optString("intent", "").trim()
        if (intent.isNotBlank()) SessionManager.setIntent(intent)
    }

    /** The calling pairing's key for this request (bd-and-core
     *  F4): drive tools check the session against it, so a pairing
     *  can only ever drive its own session. */
    private fun callerKey(): String? = core?.currentPairingKey?.get()

    override fun tools(): List<McpCore.ToolDef> = listOf(
        McpCore.ToolDef(
            "current_app", "Package name of the app currently in front of the user.", "observe",
            emptySchema(),
            run = {
                SessionManager.observeRefusal()?.let { return@ToolDef it }
                val svc = service() ?: return@ToolDef unavailable
                // Invisible apps are not listed either (§7.5): a
                // blocked foreground app reports the rule, never its name.
                invisibleRefusal(svc)?.let { return@ToolDef it }
                svc.currentAppPackage() ?: "No active window right now (the phone may be locked or on the home screen)."
            }
        ),
        McpCore.ToolDef(
            "snapshot", "The current screen as a list of elements with refs (e1, e2, …). " +
                "Refs are valid only for the returned snapshot id.", "observe",
            emptySchema(),
            run = {
                SessionManager.observeRefusal()?.let { return@ToolDef it }
                val svc = service() ?: return@ToolDef unavailable
                invisibleRefusal(svc)?.let { return@ToolDef it }
                if (svc.activeWindowSecure()) {
                    return@ToolDef "UNAVAILABLE: the current screen is a secure surface (FLAG_SECURE) — capture is refused."
                }
                val (id, entries) = svc.takeSnapshot()
                SessionManager.noteSnapshotTaken()
                val store = svc.snapshotStore
                val sb = StringBuilder()
                sb.append("snapshot $id — ${entries.size} elements")
                if (store.lastTruncated) {
                    sb.append(" — TRUNCATED at the ${SnapshotStore.MAX_NODES}-element / " +
                        "${SnapshotStore.MAX_DEPTH}-depth budget: part of the screen is NOT shown. " +
                        "Do not assume an element that is missing here does not exist.")
                }
                sb.append(" (${store.lastDurationMs} ms)\n")
                entries.forEach { e ->
                    sb.append(e.ref)
                        .append(" [").append(e.className.substringAfterLast('.')).append("]")
                    if (e.label.isNotBlank()) sb.append(" \"").append(e.label).append("\"")
                    sb.append(" @").append(e.centerX).append(",").append(e.centerY)
                    if (e.clickable) sb.append(" clickable")
                    if (e.editable) sb.append(" editable")
                    if (e.password) sb.append(" password")
                    sb.append("\n")
                }
                sb.toString()
            }
        ),
        McpCore.ToolDef(
            "structured_extract", "The current screen read into structured fields: every " +
                "labelled element as a field (inputs with their current value — password " +
                "values always REDACTED — actions, and text), by snapshot ref. Elements " +
                "with no visible label are counted as skipped, never silently dropped. " +
                "If the screen's accessibility tree is empty (canvas/custom-drawn UI), " +
                "this returns zero fields and says so — there is no visual fallback.", "observe",
            emptySchema(),
            run = {
                SessionManager.observeRefusal()?.let { return@ToolDef it }
                val svc = service() ?: return@ToolDef unavailable
                invisibleRefusal(svc)?.let { return@ToolDef it }
                if (svc.activeWindowSecure()) {
                    return@ToolDef "UNAVAILABLE: the current screen is a secure surface (FLAG_SECURE) — capture is refused."
                }
                val (id, entries) = svc.takeSnapshot()
                SessionManager.noteSnapshotTaken()
                val result = io.deskguest.app.access.StructuredExtraction.extract(entries)
                val fields = JSONArray()
                result.fields.forEach { f ->
                    val obj = JSONObject()
                        .put("ref", f.ref)
                        .put("label", f.label)
                        .put("kind", f.kind)
                        .put("class", f.className)
                    if (f.value != null) obj.put("value", f.value)
                    fields.put(obj)
                }
                JSONObject()
                    .put("snapshot", id)
                    .put("fields", fields)
                    .put("skippedUnlabelled", result.skippedUnlabelled)
                    .put(
                        "note",
                        if (result.fields.isEmpty()) {
                            "Zero fields: this screen exposed no labelled elements to the " +
                                "accessibility tree (canvas/custom-drawn UI reads this way). " +
                                "No visual fallback exists on this host."
                        } else {
                            "Structured from the accessibility tree of snapshot $id; refs " +
                                "are valid only for that snapshot."
                        }
                    )
                    .toString(2)
            }
        ),
        McpCore.ToolDef(
            "screenshot", "A PNG screenshot of the current screen.", "observe",
            emptySchema(),
            run = { "" },
            runContent = {
                SessionManager.observeRefusal()?.let {
                    return@ToolDef JSONArray().put(text(it))
                }
                val svc = service()
                    ?: return@ToolDef JSONArray().put(text("Unavailable: accessibility service not enabled."))
                invisibleRefusal(svc)?.let {
                    return@ToolDef JSONArray().put(text(it))
                }
                if (svc.activeWindowSecure()) {
                    return@ToolDef JSONArray().put(
                        text("UNAVAILABLE: the current screen is a secure surface (FLAG_SECURE) — capture is refused.")
                    )
                }
                val base64 = svc.takeScreenshotBase64()
                    ?: return@ToolDef JSONArray().put(
                        text("Screenshot unavailable right now (secure screen, lock screen, or capture refused by the system).")
                    )
                JSONArray().put(
                    JSONObject().put("type", "image").put("data", base64).put("mimeType", "image/png")
                )
            }
        ),
        McpCore.ToolDef(
            "start_session", "Open a drive session. Presence (banner, glow, STOP) shows on the phone " +
                "while a session is open. Required before any drive tool works.", "drive",
            emptySchema(),
            run = {
                val caller = core?.currentCaller?.get()
                // FR-122 (mirror of Windows FR-121, fail-closed):
                // the driver name is the caller's SPECIFIC name —
                // its clientInfo agent name, else its pairing name.
                // No generic name is ever fabricated here (the old
                // generic My AI fallback is abolished): with neither
                // name present the start
                // is refused as the driver_name_missing defect and
                // no session opens, so presence can never render an
                // unnamed or generic driver.
                val who = caller?.displayName?.trim().orEmpty()
                if (SessionManager.isDriverNameMissing(who)) {
                    return@ToolDef "Refused (${SessionManager.DEFECT_DRIVER_NAME_MISSING}): " +
                        "this pairing has no driver name — neither an agent name from " +
                        "initialize nor a pairing name — so a session cannot start. " +
                        "Presence must name the specific driver; pair again with a " +
                        "named agent (clientInfo name) and retry."
                }
                // bd-and-core F4: the session is BOUND to the
                // pairing that opened it.
                val session = SessionManager.start(who, callerKey())
                    ?: return@ToolDef "A session is already open. End it before starting another."
                // bd-and-core F5: report the REAL presence state —
                // presence shows asynchronously on the main thread,
                // so give it a brief moment, then say what is true.
                // Drive tools refuse until the STOP box is attached,
                // whether or not this text could confirm it.
                var attached = io.deskguest.app.presence.PresenceOverlay.stopAttachedNow()
                var waited = 0
                while (!attached && waited < 600) {
                    Thread.sleep(50); waited += 50
                    attached = io.deskguest.app.presence.PresenceOverlay.stopAttachedNow()
                }
                if (attached) {
                    "Session open since ${session.startedAtMs}. Drive tools are live; presence is showing on the phone."
                } else {
                    "Session open since ${session.startedAtMs}, but presence could not be confirmed on screen yet — drive tools will refuse until the presence STOP box is attached."
                }
            }
        ),
        McpCore.ToolDef(
            "end_session", "Close the current drive session and clear presence.", "drive",
            emptySchema(),
            run = {
                val ended = SessionManager.end()
                    ?: return@ToolDef "No session is open."
                "Session closed. ${ended.actions} action(s) were taken."
            }
        ),
        McpCore.ToolDef(
            "tap", "Tap an element from the latest snapshot, by ref. Requires its snapshot id; " +
                "a stale ref is refused. Optional intent: one plain sentence saying what you are doing, shown to the user.", "drive",
            schema(
                "ref" to "string", "snapshot" to "integer", "intent" to "string"
            ),
            run = { args ->
                val svc = service() ?: return@ToolDef unavailable
                SessionManager.driveRefusal(callerKey())?.let { return@ToolDef it }
                // bd-and-core F3: capture the generation BEFORE the
                // glide sleep; revalidate immediately before the
                // gesture dispatches — a STOP or owner grab during
                // the glide must stop the tap landing.
                val genAtEntry = SessionManager.generation.get()
                invisibleRefusal(svc)?.let { return@ToolDef it }
                noteIntent(args)
                val ref = args.optString("ref", "")
                val snapshotId = args.optInt("snapshot", -1)
                if (ref.isBlank() || snapshotId < 0) return@ToolDef "tap needs a ref and its snapshot id."
                svc.refBounds(ref, snapshotId)?.let { b ->
                    io.deskguest.app.presence.PresenceOverlay.highlightBounds(
                        b.left, b.top, b.right, b.bottom
                    )
                }
                svc.refCenter(ref, snapshotId)?.let { (cx, cy) ->
                    io.deskguest.app.presence.PresenceOverlay.glideTo(cx, cy)
                    Thread.sleep(1050)
                }
                SessionManager.refusalIfChangedSince(genAtEntry, callerKey())?.let { return@ToolDef it }
                val ok = svc.tapByRef(ref, snapshotId)
                if (ok) {
                    svc.refCenter(ref, snapshotId)?.let { (cx, cy) ->
                        io.deskguest.app.presence.PresenceOverlay.rippleAt(cx, cy)
                    }
                    io.deskguest.app.presence.PresenceOverlay.scheduleClearHighlight()
                    SessionManager.noteAction("tap $ref")
                }
                if (ok) "Tapped $ref." else "Refused: $ref is stale or its element moved. Take a fresh snapshot."
            }
        ),
        McpCore.ToolDef(
            "tap_point", "Tap raw screen coordinates (x, y). Prefer tap-by-ref; use this only " +
                "when no element matches. Optional intent: one plain sentence shown to the user.", "drive",
            schema("x" to "integer", "y" to "integer", "intent" to "string"),
            run = { args ->
                val svc = service() ?: return@ToolDef unavailable
                SessionManager.driveRefusal(callerKey())?.let { return@ToolDef it }
                invisibleRefusal(svc)?.let { return@ToolDef it }
                noteIntent(args)
                val x = args.optInt("x", -1); val y = args.optInt("y", -1)
                if (x < 0 || y < 0) return@ToolDef "tap_point needs x and y."
                // bd-and-core F3: revalidate after the glide sleep,
                // immediately before dispatch.
                val genAtEntry = SessionManager.generation.get()
                io.deskguest.app.presence.PresenceOverlay.highlightBounds(
                    x - 70, y - 70, x + 70, y + 70
                )
                io.deskguest.app.presence.PresenceOverlay.glideTo(x.toFloat(), y.toFloat())
                Thread.sleep(1050)
                SessionManager.refusalIfChangedSince(genAtEntry, callerKey())?.let { return@ToolDef it }
                val ok = svc.tapAt(x.toFloat(), y.toFloat())
                if (ok) {
                    io.deskguest.app.presence.PresenceOverlay.rippleAt(x.toFloat(), y.toFloat())
                    io.deskguest.app.presence.PresenceOverlay.scheduleClearHighlight()
                    SessionManager.noteAction("tap_point $x,$y")
                }
                if (ok) "Tapped $x,$y." else "Gesture was not dispatched."
            }
        ),
        McpCore.ToolDef(
            "swipe", "Swipe from (x1, y1) to (x2, y2). Optional intent: one plain sentence shown to the user.", "drive",
            schema(
                "x1" to "integer", "y1" to "integer", "x2" to "integer", "y2" to "integer",
                "intent" to "string"
            ),
            run = { args ->
                val svc = service() ?: return@ToolDef unavailable
                SessionManager.driveRefusal(callerKey())?.let { return@ToolDef it }
                invisibleRefusal(svc)?.let { return@ToolDef it }
                noteIntent(args)
                // bd-and-core F3: revalidate after the glide sleeps.
                val genAtEntry = SessionManager.generation.get()
                io.deskguest.app.presence.PresenceOverlay.glideTo(
                    args.optInt("x1").toFloat(), args.optInt("y1").toFloat())
                Thread.sleep(800)
                io.deskguest.app.presence.PresenceOverlay.glideTo(
                    args.optInt("x2").toFloat(), args.optInt("y2").toFloat())
                SessionManager.refusalIfChangedSince(genAtEntry, callerKey())?.let { return@ToolDef it }
                val ok = svc.swipe(
                    args.optInt("x1").toFloat(), args.optInt("y1").toFloat(),
                    args.optInt("x2").toFloat(), args.optInt("y2").toFloat()
                )
                if (ok) SessionManager.noteAction("swipe")
                if (ok) "Swiped." else "Gesture was not dispatched."
            }
        ),
        McpCore.ToolDef(
            "type_text", "Type text into the focused field, or into the element given by ref + snapshot. " +
                "Password fields are refused — the agent never types credentials.", "drive",
            schema("text" to "string", "intent" to "string"),
            run = { args ->
                val svc = service() ?: return@ToolDef unavailable
                SessionManager.driveRefusal(callerKey())?.let { return@ToolDef it }
                invisibleRefusal(svc)?.let { return@ToolDef it }
                noteIntent(args)
                val textToType = args.optString("text", "")
                if (textToType.isBlank()) return@ToolDef "type_text needs text."
                val ref = if (args.has("ref")) args.optString("ref") else null
                val snapshotId = if (args.has("snapshot")) args.optInt("snapshot") else null
                // Host-enforced credential refusal (SPEC §7): a
                // password target — by ref or by focus — is refused
                // no matter what the text is.
                if (ref != null && snapshotId != null) {
                    val entry = svc.entryFor(ref, snapshotId)
                        ?: return@ToolDef "Refused: $ref is stale. Take a fresh snapshot."
                    if (entry.password) {
                        return@ToolDef "Refused: $ref is a password field. The agent never types credentials — the user enters passwords themselves."
                    }
                } else if (svc.focusedInputIsPassword()) {
                    return@ToolDef "Refused: the focused field is a password field. The agent never types credentials — the user enters passwords themselves."
                }
                val ok = svc.typeText(textToType, ref, snapshotId)
                if (ok) SessionManager.noteAction("type_text")
                if (ok) "Typed." else "Could not type — no editable field is focused or the ref is stale."
            }
        ),
        McpCore.ToolDef(
            "press", "Press a system button: back, home, or recents.", "drive",
            schema("button" to "string", "intent" to "string"),
            run = { args ->
                val svc = service() ?: return@ToolDef unavailable
                SessionManager.driveRefusal(callerKey())?.let { return@ToolDef it }
                invisibleRefusal(svc)?.let { return@ToolDef it }
                noteIntent(args)
                val ok = when (args.optString("button", "")) {
                    "back" -> svc.pressBack()
                    "home" -> svc.pressHome()
                    "recents" -> svc.pressRecents()
                    else -> return@ToolDef "button must be back, home, or recents."
                }
                if (ok) SessionManager.noteAction("press ${args.optString("button")}")
                if (ok) "Pressed." else "The system did not accept the action."
            }
        ),
        McpCore.ToolDef(
            "launch_app", "Open an app by package name (its main activity). Subject to the " +
                "user's approval policy for opening apps.", "drive",
            schema("package" to "string", "intent" to "string"),
            run = { args ->
                val svc = service() ?: return@ToolDef unavailable
                SessionManager.driveRefusal(callerKey())?.let { return@ToolDef it }
                invisibleRefusal(svc)?.let { return@ToolDef it }
                noteIntent(args)
                val pkg = args.optString("package", "").trim()
                if (pkg.isBlank()) return@ToolDef "launch_app needs a package name."
                if (io.deskguest.app.safety.InvisibleAppStore.isBlocked(appContext, pkg)) {
                    return@ToolDef io.deskguest.app.safety.InvisibleAppRules.refusalForLaunch()
                }
                // bd-and-core F3: the approval wait can block up to
                // 30 s — revalidate the session before launching.
                val genAtEntry = SessionManager.generation.get()
                gateRefusal(ApprovalGate.ActionClass.LAUNCH_APP, "Open $pkg")?.let { return@ToolDef it }
                SessionManager.refusalIfChangedSince(genAtEntry, callerKey())?.let { return@ToolDef it }
                val ok = svc.launchApp(pkg)
                if (ok) SessionManager.noteAction("launch_app $pkg")
                if (ok) "Launched $pkg." else "Could not launch $pkg — it is not installed or has no main screen."
            }
        ),
        McpCore.ToolDef(
            "wait_for", "Wait until the screen matches: an element containing the given text " +
                "is visible and/or the given package is in front. Event-driven (accessibility " +
                "events), up to timeout_ms (default 10000, max 30000).", "observe",
            schema("text" to "string", "package" to "string", "timeout_ms" to "integer"),
            run = { args ->
                SessionManager.observeRefusal()?.let { return@ToolDef it }
                val svc = service() ?: return@ToolDef unavailable
                val condition = WaitCondition(
                    text = args.optString("text", "").ifBlank { null },
                    packageName = args.optString("package", "").ifBlank { null }
                )
                if (condition.isEmpty) return@ToolDef "wait_for needs a text and/or a package to wait for."
                val timeoutMs = args.optInt("timeout_ms", 10_000).coerceIn(500, 30_000).toLong()
                if (condition.matches(svc.currentAppPackage(), snapshotLabels(svc))) {
                    return@ToolDef "Matched: the screen already matches."
                }
                val latch = CountDownLatch(1)
                val listener: (android.view.accessibility.AccessibilityEvent) -> Unit = { latch.countDown() }
                svc.addWaitListener(listener)
                try {
                    val deadline = System.currentTimeMillis() + timeoutMs
                    while (System.currentTimeMillis() < deadline) {
                        val remaining = deadline - System.currentTimeMillis()
                        latch.await(remaining.coerceAtMost(2000), TimeUnit.MILLISECONDS)
                        if (condition.matches(svc.currentAppPackage(), snapshotLabels(svc))) {
                            return@ToolDef "Matched after waiting."
                        }
                    }
                    "Timed out after ${timeoutMs} ms — the screen did not match."
                } finally {
                    svc.removeWaitListener(listener)
                }
            }
        ),
        McpCore.ToolDef(
            "annotated_screenshot", "A screenshot with numbered badges on the elements of a " +
                "fresh snapshot (badge N = ref eN in that snapshot). Use it to ground a target " +
                "visually before tapping.", "observe",
            emptySchema(),
            run = { "" },
            runContent = {
                SessionManager.observeRefusal()?.let {
                    return@ToolDef JSONArray().put(text(it))
                }
                val svc = service()
                    ?: return@ToolDef JSONArray().put(text("Unavailable: accessibility service not enabled."))
                invisibleRefusal(svc)?.let {
                    return@ToolDef JSONArray().put(text(it))
                }
                if (svc.activeWindowSecure()) {
                    return@ToolDef JSONArray().put(
                        text("UNAVAILABLE: the current screen is a secure surface (FLAG_SECURE) — capture is refused.")
                    )
                }
                val (snapshotId, entries) = svc.takeSnapshot()
                SessionManager.noteSnapshotTaken()
                val bitmap = svc.takeScreenshotBitmap()
                    ?: return@ToolDef JSONArray().put(
                        text("Screenshot unavailable right now (secure screen, lock screen, or capture refused by the system).")
                    )
                val annotated = annotate(bitmap, entries)
                val stream = ByteArrayOutputStream()
                annotated.compress(Bitmap.CompressFormat.JPEG, 80, stream)
                val base64 = android.util.Base64.encodeToString(stream.toByteArray(), android.util.Base64.NO_WRAP)
                JSONArray()
                    .put(text("Annotated screenshot for snapshot $snapshotId — ${entries.size} elements, badge N = ref eN."))
                    .put(JSONObject().put("type", "image").put("data", base64).put("mimeType", "image/jpeg"))
            }
        ),
        McpCore.ToolDef(
            "clipboard_set", "Set the clipboard to the given text, for the current session. " +
                "The clipboard is cleared when the session ends. Subject to the user's " +
                "clipboard approval policy and the clipboard direction policy (policy " +
                "may forbid agent → host transfer).", "drive",
            schema("text" to "string", "intent" to "string"),
            run = { args ->
                SessionManager.driveRefusal(callerKey())?.let { return@ToolDef it }
                noteIntent(args)
                val value = args.optString("text", "")
                if (value.isEmpty()) return@ToolDef "clipboard_set needs text."
                // U1 direction policy: a direction policy forbids
                // outright — it is checked before the approval gate
                // so the owner is never asked to approve an action
                // policy already refuses.
                ClipboardPolicy.current()?.let { pol ->
                    ClipboardPolicy.checkWrite(pol)?.let { return@ToolDef it }
                }
                gateRefusal(ApprovalGate.ActionClass.CLIPBOARD, "Set the clipboard (${value.length} chars)", payload = value)?.let {
                    return@ToolDef it
                }
                val clipboard = appContext.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                clipboard.setPrimaryClip(ClipData.newPlainText("DeskGuest", value))
                val readBack = clipboard.primaryClip?.takeIf { it.itemCount > 0 }
                    ?.getItemAt(0)?.text?.toString()
                if (readBack != value) {
                    return@ToolDef "UNAVAILABLE: the clipboard did not hold the value on read-back (another app may have changed it, or the system refused the write)."
                }
                clipboardOwned = true
                SessionManager.noteAction("clipboard_set")
                "Clipboard set (${value.length} chars). It clears when this session ends."
            }
        ),
        McpCore.ToolDef(
            "clipboard_get", "Read the clipboard's text. Android only lets the foreground app " +
                "read the clipboard, so this works only while the DeskGuest app is in " +
                "front of the user; otherwise it reports UNAVAILABLE. Subject to the user's " +
                "clipboard approval policy and the clipboard direction policy (policy may " +
                "forbid host → agent transfer, and a sensitive-class clip is refused by " +
                "name, never returned).", "observe",
            emptySchema(),
            run = {
                SessionManager.observeRefusal()?.let { return@ToolDef it }
                // U1 direction policy first: a forbidden direction
                // never prompts, never reads, and its refusal does
                // not depend on foreground state.
                val clipPolicy = ClipboardPolicy.current()
                if (clipPolicy != null) {
                    ClipboardPolicy.denyReason(clipPolicy, "clipboard_get")?.let { return@ToolDef it }
                }
                if (!AppForeground.isForeground) {
                    return@ToolDef "UNAVAILABLE: the clipboard can only be read while the DeskGuest app is in the foreground — Android blocks background clipboard reads. Ask the user to open the app, then try again."
                }
                gateRefusal(ApprovalGate.ActionClass.CLIPBOARD, "Read the clipboard")?.let {
                    return@ToolDef it
                }
                val clipboard = appContext.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                val clip = clipboard.primaryClip
                if (clip == null || clip.itemCount == 0) return@ToolDef "The clipboard is empty."
                val value = clip.getItemAt(0)?.text?.toString()
                    ?: return@ToolDef "The clipboard holds non-text data, which this tool does not read."
                // U1 sensitive-item skip: the clip text is
                // classified BEFORE it can be returned; on a hit the
                // named refusal goes back instead of the content,
                // and the refusal itself is a session event (class
                // named, content never).
                if (clipPolicy != null && clipPolicy.sensitiveSkip) {
                    ClipboardPolicy.Sensitive.classifierFor(value)?.let { classifierId ->
                        SessionEvents.emit(
                            "clipboard_read_refused",
                            mapOf("classifier" to classifierId)
                        )
                        return@ToolDef ClipboardPolicy.Sensitive.refusal(classifierId)
                    }
                }
                SessionManager.noteAction("clipboard_get")
                // U1 per-read indicator: the read is a presence
                // fact — a clipboard_read session event (count only)
                // and the intent line the presence overlay shows.
                SessionEvents.emit("clipboard_read", mapOf("chars" to value.length))
                SessionManager.setIntent("Clipboard read (${value.length} chars)")
                value
            }
        )
    )

    /** Labels of the current screen, for wait_for matching. Takes a
     *  fresh snapshot (which also refreshes the agent's refs). */
    private fun snapshotLabels(svc: ControlAccessibilityService): List<String> {
        val (_, entries) = svc.takeSnapshot()
        return entries.map { it.label }
    }

    /** Draw numbered badges (ref numbers) onto a screenshot copy,
     *  scaled to at most 1080 px wide. */
    private fun annotate(source: Bitmap, entries: List<SnapshotStore.Entry>): Bitmap {
        val scale = if (source.width > 1080) 1080f / source.width else 1f
        val out = Bitmap.createScaledBitmap(
            source, (source.width * scale).toInt().coerceAtLeast(1),
            (source.height * scale).toInt().coerceAtLeast(1), true
        )
        val mutable = out.copy(Bitmap.Config.ARGB_8888, true)
        val accent = io.deskguest.app.design.PresenceLaw.HUE_AI
        val canvas = Canvas(mutable)
        val fill = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = accent }
        val labelPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = Color.WHITE
            textSize = 22f * scale.coerceAtLeast(0.6f)
            typeface = android.graphics.Typeface.DEFAULT_BOLD
            textAlign = Paint.Align.CENTER
        }
        entries.forEachIndexed { index, entry ->
            val cx = entry.left * scale
            val cy = entry.top * scale
            val r = 15f * scale.coerceAtLeast(0.6f)
            canvas.drawCircle(cx + r, cy + r, r, fill)
            val label = (index + 1).toString()
            val baseline = cy + r - (labelPaint.descent() + labelPaint.ascent()) / 2
            canvas.drawText(label, cx + r, baseline, labelPaint)
        }
        return mutable
    }

    companion object {
        /** True while the clipboard holds a value this host set for
         *  the live session; ControlService clears it at session end
         *  (the session-scoped clipboard rule). */
        @Volatile
        var clipboardOwned: Boolean = false
    }

    /**
     * Invisible apps (SPEC §7.5, BD-XCHECK owed item): the refusal
     * for the CURRENT foreground app when the user has marked it
     * invisible, or null. Checked before every capture and every
     * drive action; the refusal never names the package.
     */
    private fun invisibleRefusal(svc: ControlAccessibilityService): String? {
        val pkg = svc.currentAppPackage() ?: return null
        return if (io.deskguest.app.safety.InvisibleAppStore.isBlocked(appContext, pkg)) {
            io.deskguest.app.safety.InvisibleAppRules.refusal()
        } else {
            null
        }
    }

    private fun service(): ControlAccessibilityService? = ControlAccessibilityService.instance

    private fun text(s: String): JSONObject = JSONObject().put("type", "text").put("text", s)

    private fun emptySchema(): JSONObject =
        JSONObject().put("type", "object").put("properties", JSONObject())

    private fun schema(vararg fields: Pair<String, String>): JSONObject {
        val props = JSONObject()
        fields.forEach { (name, type) -> props.put(name, JSONObject().put("type", type)) }
        return JSONObject().put("type", "object").put("properties", props)
    }
}
