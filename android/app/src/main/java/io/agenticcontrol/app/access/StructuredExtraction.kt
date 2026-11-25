package io.agenticcontrol.app.access

/**
 * Structured extraction (FEATURES §1, built 2026-11-23, Wave 11
 * Lane B): "read this screen into data" — the visible content of
 * the current snapshot as structured fields, not prose and not the
 * raw element list.
 *
 * The extraction is a pure transform over the snapshot the
 * accessibility layer already took (SnapshotStore.Entry list):
 * - every element with a visible label becomes one field;
 * - editable elements are fields of kind "input" whose value is
 *   their current text — a password field's value is the store's
 *   REDACTED marker, never its content (collection redacts it
 *   before it reaches the store, and this transform never
 *   un-redacts);
 * - clickable non-editable elements are kind "action";
 * - everything else labelled is kind "text";
 * - unlabelled elements carry no visible content and are skipped,
 *   and the skip count is reported with the result — extraction
 *   never silently drops part of the screen.
 *
 * Honest limit: this structures what the accessibility tree
 * exposes. A canvas/custom-drawn screen whose tree is empty
 * extracts to zero fields and says so; there is no visual
 * fallback (vision grounding is de-scoped in FEATURES §1 —
 * no on-device vision model ships with this product).
 *
 * Pure JVM — runs in the JVM suite.
 */
object StructuredExtraction {

    data class Field(
        val ref: String,
        val label: String,
        val kind: String,
        val value: String?,
        val className: String
    )

    data class Result(
        val fields: List<Field>,
        val skippedUnlabelled: Int
    )

    const val KIND_INPUT = "input"
    const val KIND_ACTION = "action"
    const val KIND_TEXT = "text"

    fun extract(entries: List<SnapshotStore.Entry>): Result {
        val fields = mutableListOf<Field>()
        var skipped = 0
        for (e in entries) {
            val label = e.label.trim()
            if (label.isEmpty()) {
                skipped++
                continue
            }
            val kind = when {
                e.editable -> KIND_INPUT
                e.clickable -> KIND_ACTION
                else -> KIND_TEXT
            }
            val value = when {
                e.password -> SnapshotStore.REDACTED
                e.editable -> e.text
                else -> null
            }
            fields.add(
                Field(
                    ref = e.ref,
                    label = label,
                    kind = kind,
                    value = value,
                    className = e.className.substringAfterLast('.')
                )
            )
        }
        return Result(fields, skipped)
    }
}
