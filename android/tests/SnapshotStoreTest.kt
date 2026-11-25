import io.agenticcontrol.app.access.SnapshotStore

/**
 * JVM tests for snapshot ref discipline (SPEC §6): refs live and die
 * with their snapshot; a stale ref must never resolve.
 */
private var failures = 0

private fun check(name: String, condition: Boolean) {
    if (condition) println("PASS  $name")
    else {
        println("FAIL  $name")
        failures++
    }
}

private fun entry(ref: String, label: String) = SnapshotStore.Entry(
    ref = ref, text = label, contentDescription = "", className = "android.widget.Button",
    left = 0, top = 0, right = 100, bottom = 50, clickable = true, editable = false
)

fun main() {
    val store = SnapshotStore()
    val id1 = store.beginSnapshot()
    store.put(entry(store.nextRef(0), "OK"))
    store.put(entry(store.nextRef(1), "Cancel"))
    check("refs resolve in their own snapshot", store.resolve("e1", id1)?.label == "OK")
    check("second ref resolves", store.resolve("e2", id1)?.label == "Cancel")
    check("center math", store.resolve("e1", id1)?.centerX == 50 && store.resolve("e1", id1)?.centerY == 25)

    val id2 = store.beginSnapshot()
    check("snapshot ids increase", id2 > id1)
    check("stale ref refused after new snapshot", store.resolve("e1", id1) == null)
    check("old id rejected even for current entries", store.resolve("e1", id2) == null)
    store.put(entry(store.nextRef(0), "Send"))
    check("new snapshot refs work", store.resolve("e1", id2)?.label == "Send")
    check("unknown ref refused", store.resolve("e99", id2) == null)

    // 0.4.0 budgets: the node cap refuses loudly, never silently.
    val capped = SnapshotStore()
    capped.beginSnapshot()
    var accepted = 0
    var refusedAt = -1
    for (i in 0 until SnapshotStore.MAX_NODES + 50) {
        if (capped.put(entry(capped.nextRef(i), "n$i"))) accepted++ else if (refusedAt < 0) refusedAt = i
    }
    check("cap keeps exactly MAX_NODES", accepted == SnapshotStore.MAX_NODES)
    check("cap refuses beyond MAX_NODES", refusedAt == SnapshotStore.MAX_NODES)
    check("truncation is flagged", capped.lastTruncated)
    check("size reports kept entries", capped.size() == SnapshotStore.MAX_NODES)

    // Depth truncation flags too, and a fresh snapshot resets the flags.
    val depthStore = SnapshotStore()
    depthStore.beginSnapshot()
    check("fresh snapshot is not truncated", !depthStore.lastTruncated)
    depthStore.noteDepthTruncated()
    check("depth truncation flags", depthStore.lastTruncated)
    depthStore.beginSnapshot()
    check("new snapshot clears truncation", !depthStore.lastTruncated)

    // Visited counting + duration bookkeeping.
    val stats = SnapshotStore()
    stats.beginSnapshot()
    repeat(7) { stats.noteVisited() }
    stats.finish(42)
    check("visited counted", stats.lastVisited == 7)
    check("duration recorded", stats.lastDurationMs == 42L)

    // Password entries carry the flag; the redaction marker is stable.
    val pw = SnapshotStore()
    val pwId = pw.beginSnapshot()
    pw.put(
        SnapshotStore.Entry(
            ref = pw.nextRef(0), text = SnapshotStore.REDACTED, contentDescription = "",
            className = "android.widget.EditText", left = 0, top = 0, right = 10, bottom = 10,
            clickable = false, editable = true, password = true
        )
    )
    check("password entry flagged", pw.resolve("e1", pwId)?.password == true)
    check("redaction marker", SnapshotStore.REDACTED == "[REDACTED]")
    check("budgets are the SPEC values", SnapshotStore.MAX_NODES == 1500 && SnapshotStore.MAX_DEPTH == 35)

    println(if (failures == 0) "ALL SNAPSHOT TESTS PASSED" else "$failures SNAPSHOT TEST(S) FAILED")
    if (failures > 0) kotlin.system.exitProcess(1)
}
