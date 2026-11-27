package io.deskguest.app.access

/**
 * Snapshot bookkeeping (SPEC §6): every screen snapshot assigns short
 * refs (e1, e2, …) to its elements. Refs are valid ONLY for the
 * snapshot that issued them — acting on a stale ref is refused, never
 * guessed (the census's agent-desktop pattern). Pure logic: the
 * Android layer fills entries from live nodes, tests fill them by hand.
 *
 * 0.4.0: snapshots are budget-capped (SPEC §6 performance budget:
 * [MAX_NODES] elements, [MAX_DEPTH] levels). The caps are LOUD: when
 * a snapshot is cut, [lastTruncated] says so and the tool result
 * reports it — a silently pruned snapshot could hide the very
 * element a task needs. Password fields arrive pre-redacted from
 * the Android layer and carry [Entry.password] so typing into them
 * can be refused by name.
 */
class SnapshotStore {

    data class Entry(
        val ref: String,
        val text: String,
        val contentDescription: String,
        val className: String,
        val left: Int, val top: Int, val right: Int, val bottom: Int,
        val clickable: Boolean,
        val editable: Boolean,
        val password: Boolean = false
    ) {
        val centerX: Int get() = (left + right) / 2
        val centerY: Int get() = (top + bottom) / 2
        val label: String get() = text.ifBlank { contentDescription }
    }

    private var currentId: Int = 0
    private var entries: Map<String, Entry> = emptyMap()

    /** Elements kept in the snapshot that just finished. */
    @Volatile var lastTruncated: Boolean = false
        private set

    /** Nodes the walk visited (kept + pruned) in the last snapshot. */
    @Volatile var lastVisited: Int = 0
        private set

    /** Wall time the last snapshot walk took, milliseconds. */
    @Volatile var lastDurationMs: Long = 0
        private set

    /** Start a new snapshot; returns its id. All older refs die here. */
    @Synchronized
    fun beginSnapshot(): Int {
        currentId += 1
        entries = emptyMap()
        lastTruncated = false
        lastVisited = 0
        lastDurationMs = 0
        return currentId
    }

    /**
     * Add an entry to the snapshot being built. Returns false when
     * the node cap is already reached — the entry is dropped and the
     * snapshot marks itself truncated.
     */
    @Synchronized
    fun put(entry: Entry): Boolean {
        if (entries.size >= MAX_NODES) {
            lastTruncated = true
            return false
        }
        entries = entries + (entry.ref to entry)
        return true
    }

    /** The walk visited one more node (kept, pruned, or capped). */
    @Synchronized
    fun noteVisited() {
        lastVisited += 1
    }

    /** The walk hit the depth cap: part of the tree was not walked. */
    @Synchronized
    fun noteDepthTruncated() {
        lastTruncated = true
    }

    /** Record the finished walk's duration. */
    @Synchronized
    fun finish(durationMs: Long) {
        lastDurationMs = durationMs
    }

    @Synchronized
    fun currentSnapshotId(): Int = currentId

    @Synchronized
    fun size(): Int = entries.size

    /**
     * Resolve a ref against the CURRENT snapshot only.
     * Returns null for stale or unknown refs — callers must refuse.
     */
    @Synchronized
    fun resolve(ref: String, snapshotId: Int): Entry? {
        if (snapshotId != currentId) return null
        return entries[ref]
    }

    /** Next ref for the snapshot being built: e1, e2, … in fill order. */
    fun nextRef(index: Int): String = "e${index + 1}"

    companion object {
        /** Element budget per snapshot (SPEC §6). */
        const val MAX_NODES = 1500

        /** Tree-depth budget per snapshot (SPEC §6). */
        const val MAX_DEPTH = 35

        /** What a redacted password field shows in place of its content. */
        const val REDACTED = "[REDACTED]"
    }
}

/** A node of a live view tree, abstracted for the JVM suite
 *  (D38 Block H review F6 / DG-H-A14): the accessibility service
 *  adapts AccessibilityNodeInfo to this shape. */
interface LiveTreeNode {
    val text: String?
    val contentDescription: String?
    val isVisibleToUser: Boolean
    val childCount: Int
    fun child(index: Int): LiveTreeNode?
}

/**
 * Label search over a live tree (DG-H-A14 residuals, F6):
 * - ITERATIVE depth-first walk on an explicit stack — no
 *   recursion (the stack-overflow fix stands) AND the original
 *   pre-BFS traversal order, so the candidate order a caller
 *   sees is the order the recursive walk produced.
 * - Invisible subtrees are PRUNED, exactly like the snapshot
 *   walk: an invisible node is never collected and its children
 *   are never visited — a hostile app cannot pad the budget
 *   with invisible nodes or plant an invisible label twin.
 * - The node budget is checked BEFORE a child is pushed, so
 *   one very wide node cannot force an unbounded number of
 *   child fetches or queue entries.
 */
object LiveTreeSearch {
    fun collectByLabel(
        root: LiveTreeNode, label: String,
        maxNodes: Int = SnapshotStore.MAX_NODES,
        maxDepth: Int = SnapshotStore.MAX_DEPTH
    ): List<LiveTreeNode> {
        val out = ArrayList<LiveTreeNode>()
        val stack = ArrayDeque<Pair<LiveTreeNode, Int>>()
        stack.addLast(root to 0)
        var visited = 0
        while (stack.isNotEmpty()) {
            val (node, depth) = stack.removeLast()
            if (++visited > maxNodes) break
            if (!node.isVisibleToUser) continue // prune the whole subtree
            if (label.isNotBlank()) {
                val text = node.text ?: ""
                val desc = node.contentDescription ?: ""
                if (text == label || desc == label) out.add(node)
            }
            if (depth >= maxDepth) continue
            // Push children in reverse so pops run in original
            // (left-to-right) order; budget checked per push.
            for (i in node.childCount - 1 downTo 0) {
                if (visited + stack.size >= maxNodes) break
                node.child(i)?.let { stack.addLast(it to depth + 1) }
            }
        }
        return out
    }
}
