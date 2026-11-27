package io.deskguest.app.access

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.GestureDescription
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Path
import android.graphics.Rect
import android.os.Build
import android.os.Bundle
import android.util.Base64
import android.view.Display
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import io.deskguest.app.server.SessionManager
import java.io.ByteArrayOutputStream
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * The eyes and hands (SPEC §4.2): window-tree snapshots with refs,
 * screenshots, gesture dispatch, and text entry. Every action first
 * re-validates its target against the live tree when a ref is used —
 * the service refuses rather than taps the wrong thing (§7 honesty).
 *
 * This service is the reason the wizard's accessibility step exists;
 * without the user's grant the service simply never binds and every
 * tool reports itself unavailable with the reason.
 *
 * 0.4.0: snapshots walk breadth-first under the SPEC §6 budgets
 * (SnapshotStore.MAX_NODES / MAX_DEPTH) and report truncation LOUDLY
 * through the store; invisible subtrees are pruned; nodes obtained
 * from getChild are recycled; password fields are redacted at
 * collection (their content never enters a snapshot); FLAG_SECURE
 * windows are detectable so capture can refuse; and a physical
 * touch-interaction event pauses the session (touch-to-yield).
 */
class ControlAccessibilityService : AccessibilityService() {

    val snapshotStore = SnapshotStore()

    override fun onServiceConnected() {
        super.onServiceConnected()
        instance = this
    }

    override fun onUnbind(intent: Intent?): Boolean {
        if (instance === this) instance = null
        return super.onUnbind(intent)
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        // Touch-to-yield: a physical touch interaction starting well
        // after the agent's last dispatched gesture means the owner
        // has taken the phone — pause the session (SessionManager
        // turns that into refusals + the paused pill). The guard
        // window covers the echo of the agent's own gestures.
        if (event?.eventType == AccessibilityEvent.TYPE_TOUCH_INTERACTION_START) {
            val sinceAgent = System.currentTimeMillis() - SessionManager.lastAgentGestureAtMs
            if (sinceAgent > TOUCH_GUARD_MS) SessionManager.onUserTouchSignal()
        }
        // wait_for subscribers (0.4.0) see every event type.
        event?.let { dispatchWaitEvent(it) }
        // U2 producers: window changes are the screen_change /
        // foreground_app facts; a notification-state change is
        // notification_posted. Detail carries the package name
        // only — never notification text or window content.
        if (event != null) {
            when (event.eventType) {
                AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED -> {
                    val pkg = event.packageName?.toString() ?: currentAppPackage() ?: ""
                    if (pkg != lastForegroundPackage) {
                        lastForegroundPackage = pkg
                        io.deskguest.app.server.SessionEvents.emitKind(
                            io.deskguest.app.server.SessionEvents.KIND_FOREGROUND_APP,
                            mapOf("package" to pkg)
                        )
                        io.deskguest.app.server.SessionEvents.emitKind(
                            io.deskguest.app.server.SessionEvents.KIND_SCREEN_CHANGE,
                            mapOf("package" to pkg)
                        )
                    }
                }
                AccessibilityEvent.TYPE_NOTIFICATION_STATE_CHANGED -> {
                    io.deskguest.app.server.SessionEvents.emitKind(
                        io.deskguest.app.server.SessionEvents.KIND_NOTIFICATION_POSTED,
                        mapOf("package" to (event.packageName?.toString() ?: ""))
                    )
                }
            }
        }
    }

    @Volatile
    private var lastForegroundPackage: String? = null

    override fun onInterrupt() { /* no continuous work to interrupt */ }

    // ---------- observation ----------

    /** Build a snapshot of the active window; returns (id, entries). */
    fun takeSnapshot(): Pair<Int, List<SnapshotStore.Entry>> {
        val started = System.currentTimeMillis()
        val root = rootInActiveWindow
        val id = snapshotStore.beginSnapshot()
        if (root == null) {
            snapshotStore.finish(0)
            return id to emptyList()
        }
        val out = mutableListOf<SnapshotStore.Entry>()
        // Breadth-first walk under the snapshot budgets. Children are
        // recycled after use (the root is system-owned and is not).
        val queue = ArrayDeque<Pair<AccessibilityNodeInfo, Int>>()
        queue.add(root to 0)
        var visitedCount = 0
        while (queue.isNotEmpty()) {
            val (node, depth) = queue.removeFirst()
            visitedCount++
            snapshotStore.noteVisited()
            if (!node.isVisibleToUser) {
                if (node !== root) node.recycle()
                continue
            }
            val bounds = Rect()
            node.getBoundsInScreen(bounds)
            val password = node.isPassword
            val interesting = node.isClickable || node.isEditable ||
                !node.text.isNullOrBlank() || !node.contentDescription.isNullOrBlank()
            if (interesting && bounds.width() > 0 && bounds.height() > 0) {
                val entry = SnapshotStore.Entry(
                    ref = snapshotStore.nextRef(out.size),
                    text = if (password) SnapshotStore.REDACTED else node.text?.toString() ?: "",
                    contentDescription = if (password) {
                        SnapshotStore.REDACTED
                    } else {
                        node.contentDescription?.toString() ?: ""
                    },
                    className = node.className?.toString() ?: "",
                    left = bounds.left, top = bounds.top,
                    right = bounds.right, bottom = bounds.bottom,
                    clickable = node.isClickable,
                    editable = node.isEditable,
                    password = password
                )
                if (snapshotStore.put(entry)) out.add(entry)
            }
            if (depth >= SnapshotStore.MAX_DEPTH) {
                if (node.childCount > 0) snapshotStore.noteDepthTruncated()
            } else {
                for (i in 0 until node.childCount) {
                    // F6(c): the budget is checked BEFORE the
                    // child is fetched/queued — one very wide
                    // node cannot force unbounded IPC calls or
                    // queue entries past MAX_NODES.
                    if (visitedCount + queue.size >= SnapshotStore.MAX_NODES) break
                    node.getChild(i)?.let { queue.add(it to depth + 1) }
                }
            }
            if (node !== root) node.recycle()
        }
        snapshotStore.finish(System.currentTimeMillis() - started)
        return id to out
    }

    fun currentAppPackage(): String? = rootInActiveWindow?.packageName?.toString()

    /**
     * Best available FLAG_SECURE signal. Android gives accessibility
     * services no getter for another window's flags; what it does
     * give is a hard refusal: takeScreenshot fails on secure windows.
     * So: when a screenshot attempt against the current foreground
     * package has been refused, this reports secure while that same
     * package stays in front. The screenshot path itself is always
     * safe — the system refuses the capture and the tool reports it
     * unavailable; this check lets the snapshot tool refuse too once
     * a secure surface has identified itself.
     */
    @Volatile
    private var secureRefusalPackage: String? = null

    fun activeWindowSecure(): Boolean {
        val pkg = currentAppPackage() ?: return false
        return secureRefusalPackage == pkg
    }

    /** PNG screenshot as base64, or null when capture is unavailable. */
    fun takeScreenshotBase64(): String? {
        val bitmap = takeScreenshotBitmap() ?: return null
        val stream = ByteArrayOutputStream()
        bitmap.compress(Bitmap.CompressFormat.PNG, 100, stream)
        val encoded = Base64.encodeToString(stream.toByteArray(), Base64.NO_WRAP)
        bitmap.recycle()
        return encoded
    }

    /** Screenshot as a Bitmap (the annotated-screenshot tool draws on
     *  a copy of this), or null when capture is unavailable/refused. */
    fun takeScreenshotBitmap(): Bitmap? {
        if (Build.VERSION.SDK_INT < 30) return null
        val latch = CountDownLatch(1)
        var captured: Bitmap? = null
        takeScreenshot(Display.DEFAULT_DISPLAY, mainExecutor, object : TakeScreenshotCallback {
            override fun onSuccess(result: ScreenshotResult) {
                try {
                    captured = Bitmap.wrapHardwareBuffer(result.hardwareBuffer, result.colorSpace)
                } catch (_: Exception) {
                    captured = null
                } finally {
                    try { result.hardwareBuffer.close() } catch (_: Exception) {}
                    latch.countDown()
                }
            }

            override fun onFailure(errorCode: Int) {
                // A capture refusal against the foreground app marks
                // that app secure until a capture succeeds elsewhere
                // (see activeWindowSecure).
                secureRefusalPackage = currentAppPackage()
                latch.countDown()
            }
        })
        latch.await(5, TimeUnit.SECONDS)
        if (captured != null && secureRefusalPackage != null &&
            secureRefusalPackage == currentAppPackage()
        ) {
            // A capture just succeeded in the marked app, so the mark
            // is stale (the secure surface went away) — clear it.
            secureRefusalPackage = null
        }
        return captured
    }

    // ---------- action ----------

    /**
     * Tap the element a ref points at. The ref's snapshot must be the
     * current one AND a live node with the same label must still sit at
     * the recorded bounds — otherwise refuse (returns false).
     */
    /** W8 item 5 (OI-13): the action-layer refusal — an agent
     *  action whose target is DeskGuest's own window is refused here,
     *  at the service, on the gesture and node-action paths.
     *  W15 P1-F2: this is the ACTION decision, so it is the
     *  fail-closed [io.deskguest.app.design.GateModel.nodeTargetRefused],
     *  not the bare classification — a non-null node can expose a
     *  null packageName, and a null/blank target package refuses
     *  here (tap / type / launch) just as an own-package one does. */
    private fun targetIsOwnWindow(targetPackage: String?): Boolean =
        io.deskguest.app.design.GateModel.nodeTargetRefused(targetPackage, packageName)

    fun tapByRef(ref: String, snapshotId: Int): Boolean {
        val entry = snapshotStore.resolve(ref, snapshotId) ?: return false
        val live = findLiveNode(entry) ?: return false
        // NODE_ACTION path: the live node's own package decides —
        // fail-closed: a live node whose packageName is null
        // refuses too (W15 P1-F2), on both the clickable branch
        // below and the tapAt fallback (itself fail-closed).
        if (targetIsOwnWindow(live.packageName?.toString())) return false
        if (live.isClickable) {
            SessionManager.noteAgentGesture()
            return live.performAction(AccessibilityNodeInfo.ACTION_CLICK)
        }
        return tapAt(entry.centerX.toFloat(), entry.centerY.toFloat())
    }

    /** Screen centre for a snapshot ref, or null when stale. The
     *  presence layer glides the virtual finger to this point before
     *  the tap lands. */
    fun refCenter(ref: String, snapshotId: Int): Pair<Float, Float>? {
        val entry = snapshotStore.resolve(ref, snapshotId) ?: return null
        return entry.centerX.toFloat() to entry.centerY.toFloat()
    }

    /** Screen bounds for a snapshot ref, or null when stale. The
     *  presence layer washes these bounds with the target highlight
     *  while the cursor glides, so the user sees what will be tapped. */
    fun refBounds(ref: String, snapshotId: Int): Rect? {
        val entry = snapshotStore.resolve(ref, snapshotId) ?: return null
        return Rect(entry.left, entry.top, entry.right, entry.bottom)
    }

    /** The snapshot entry behind a ref (redaction / password checks),
     *  or null when stale. */
    fun entryFor(ref: String, snapshotId: Int): SnapshotStore.Entry? =
        snapshotStore.resolve(ref, snapshotId)

    /** Find the live node matching a snapshot entry (label + bounds). */
    private fun findLiveNode(entry: SnapshotStore.Entry): AccessibilityNodeInfo? {
        val root = rootInActiveWindow ?: return null
        val candidates = LiveTreeSearch.collectByLabel(NodeAdapter(root), entry.label)
        return candidates.firstOrNull { candidate ->
            val node = (candidate as NodeAdapter).node
            val b = Rect(); node.getBoundsInScreen(b)
            kotlin.math.abs(b.centerX() - entry.centerX) <= 4 &&
                kotlin.math.abs(b.centerY() - entry.centerY) <= 4
        }?.let { (it as NodeAdapter).node }
        // D38 Block H review F6(a): NO label-only fallback. The
        // class doc's rule stands as written — the service
        // REFUSES rather than taps the wrong thing: when no
        // candidate still sits at the recorded bounds, the ref
        // is stale and the tap does not happen.
    }

    /** AccessibilityNodeInfo in the [LiveTreeNode] shape the
     *  pure search walks. The search itself (iterative DFS,
     *  invisible-subtree pruning, budget-before-push) lives in
     *  [LiveTreeSearch] — DG-H-A14 and its F6 residuals. */
    private class NodeAdapter(val node: AccessibilityNodeInfo) : LiveTreeNode {
        override val text: String? get() = node.text?.toString()
        override val contentDescription: String? get() = node.contentDescription?.toString()
        override val isVisibleToUser: Boolean get() = node.isVisibleToUser
        override val childCount: Int get() = node.childCount
        override fun child(index: Int): LiveTreeNode? = node.getChild(index)?.let { NodeAdapter(it) }
    }

    fun tapAt(x: Float, y: Float): Boolean {
        // GESTURE path: raw coordinates resolve to the foreground
        // window — when DeskGuest itself is in front, the gesture is
        // refused rather than dispatched at our own windows.
        // W13 P1-F2: an UNKNOWN foreground (null mid-transition)
        // also refuses — the coordinate path is fail-closed.
        if (io.deskguest.app.design.GateModel.coordinateTargetRefused(currentAppPackage(), packageName)) return false
        SessionManager.noteAgentGesture()
        val path = Path().apply { moveTo(x, y) }
        val gesture = GestureDescription.Builder()
            .addStroke(GestureDescription.StrokeDescription(path, 0, 60))
            .build()
        return dispatchGesture(gesture, null, null)
    }

    fun swipe(x1: Float, y1: Float, x2: Float, y2: Float, durationMs: Long = 300): Boolean {
        // GESTURE path, same OI-13 refusal as tapAt (W13 P1-F2:
        // unknown foreground refuses too).
        if (io.deskguest.app.design.GateModel.coordinateTargetRefused(currentAppPackage(), packageName)) return false
        SessionManager.noteAgentGesture()
        val path = Path().apply { moveTo(x1, y1); lineTo(x2, y2) }
        val gesture = GestureDescription.Builder()
            .addStroke(GestureDescription.StrokeDescription(path, 0, durationMs))
            .build()
        return dispatchGesture(gesture, null, null)
    }

    /** Type into the focused editable node (or the ref's node). */
    fun typeText(text: String, ref: String?, snapshotId: Int?): Boolean {
        val target: AccessibilityNodeInfo? = when {
            ref != null && snapshotId != null -> {
                val entry = snapshotStore.resolve(ref, snapshotId) ?: return false
                findLiveNode(entry)
            }
            else -> findFocus(AccessibilityNodeInfo.FOCUS_INPUT)
        }
        val node = target ?: return false
        // NODE_ACTION path (OI-13): never type into our own
        // windows — and never into a node whose package is null
        // (fail-closed, W15 P1-F2).
        if (targetIsOwnWindow(node.packageName?.toString())) return false
        val args = Bundle().apply {
            putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, text)
        }
        return node.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, args)
    }

    /** Is the currently focused input a password field? The
     *  type_text tool refuses on true — the agent never types
     *  credentials (SPEC §7, host-enforced). */
    fun focusedInputIsPassword(): Boolean {
        val focus = findFocus(AccessibilityNodeInfo.FOCUS_INPUT) ?: return false
        return try {
            focus.isPassword
        } catch (e: Exception) {
            false
        }
    }

    fun pressBack(): Boolean = performGlobalAction(GLOBAL_ACTION_BACK)
    fun pressHome(): Boolean = performGlobalAction(GLOBAL_ACTION_HOME)
    fun pressRecents(): Boolean = performGlobalAction(GLOBAL_ACTION_RECENTS)

    /** Launch an app's main activity by package name (0.4.0).
     *  False when the package has no launchable activity (not
     *  installed, or a background-only package). */
    fun launchApp(packageName: String): Boolean {
        // OI-13: the agent cannot launch the app that hosts it —
        // and a blank package name refuses rather than probing the
        // package manager with it (fail-closed, W15 P1-F2).
        if (targetIsOwnWindow(packageName)) return false
        return try {
            val intent = packageManager.getLaunchIntentForPackage(packageName) ?: return false
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            startActivity(intent)
            true
        } catch (e: Exception) {
            false
        }
    }

    // ---------- wait_for plumbing (0.4.0, stage 2) ----------

    /** One-shot accessibility-event subscribers for wait_for. */
    private val waitListeners = mutableListOf<(AccessibilityEvent) -> Unit>()

    fun addWaitListener(listener: (AccessibilityEvent) -> Unit) {
        synchronized(waitListeners) { waitListeners.add(listener) }
    }

    fun removeWaitListener(listener: (AccessibilityEvent) -> Unit) {
        synchronized(waitListeners) { waitListeners.remove(listener) }
    }

    private fun dispatchWaitEvent(event: AccessibilityEvent) {
        val snapshot: List<(AccessibilityEvent) -> Unit>
        synchronized(waitListeners) { snapshot = waitListeners.toList() }
        snapshot.forEach { listener ->
            try {
                listener(event)
            } catch (_: Exception) {
            }
        }
    }

    companion object {
        @Volatile
        var instance: ControlAccessibilityService? = null
            private set

        val isBound: Boolean get() = instance != null

        /** Window after an agent gesture during which a physical
         *  touch-interaction event is treated as the gesture's echo,
         *  not the owner taking over. */
        const val TOUCH_GUARD_MS = 700L
    }
}
