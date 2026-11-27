package io.deskguest.app.server

import java.io.File

/**
 * The file-tool scope (SPEC §6 file_push / file_pull / file_list) —
 * BD-XCHECK owed item, built 2026-11-22.
 *
 * Platform law and product discipline: a normal Android app has no
 * general filesystem reach, and this product asks for none (no
 * MANAGE_EXTERNAL_STORAGE, no broad storage permission). The file
 * tools are therefore scoped to ONE folder: the app's own
 * external-files folder ("agent-files"), which the user can inspect
 * and clear from any file manager, and which holds only what an
 * agent pushed or the user placed there for the agent. Every name
 * is resolved against that root and refused when it escapes —
 * absolute paths, `..`, and separators are all refused, so a tool
 * call can never name a path outside the folder. Sizes are capped
 * in both directions and the caps are stated in the tool text.
 *
 * Pure JVM (java.io.File only) — runs in the JVM suite.
 */
object FileScope {

    const val MAX_FILE_BYTES = 256 * 1024

    /**
     * Resolve [name] inside [root]; the resulting File, or null when
     * the name is not a plain in-folder name. A name may contain one
     * level of subfolder ("sub/file.txt") but never `..`, never a
     * leading slash, never a backslash, and the canonical result
     * must stay under the canonical root.
     */
    fun resolve(root: File, name: String): File? {
        val trimmed = name.trim()
        if (trimmed.isEmpty() || trimmed.startsWith("/") || trimmed.contains("\\")) return null
        val parts = trimmed.split("/")
        if (parts.any { it.isEmpty() || it == "." || it == ".." }) return null
        return try {
            val rootCanonical = root.canonicalPath
            val candidate = File(root, trimmed).canonicalFile
            if (candidate.path == rootCanonical) null
            else if (candidate.path.startsWith(rootCanonical + File.separator)) candidate
            else null
        } catch (_: Exception) {
            null
        }
    }

    /** A plain single-segment name (install_package's argument). */
    fun isPlainName(name: String): Boolean {
        val trimmed = name.trim()
        return trimmed.isNotEmpty() && !trimmed.contains("/") && !trimmed.contains("\\") &&
            trimmed != "." && trimmed != ".."
    }
}
