package io.agenticcontrol.app

import android.content.Context
import java.io.File
import java.io.FileOutputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Synchronous on-disk breadcrumbs (0.4.2, diagnostic). The wizard's
 * step-2 death on the owner's phone writes no JVM crash report at
 * all, which means the process dies below the managed layer — so
 * each stage of the fragile paths marks itself on disk, flushed
 * with fd.sync(), BEFORE and AFTER it runs. After a hard native
 * kill, the last mark on disk names the stage that never returned.
 *
 * Marks are appended to a small file in the app's private storage
 * and surfaced in the UI (wizard welcome, home footer) so the owner
 * can read the result without any tooling. Nothing here can throw:
 * a diagnostic that crashes would be worse than the disease.
 */
object Breadcrumb {

    private const val FILE_NAME = "breadcrumb.txt"
    private const val MAX_LINES = 60

    fun mark(context: Context, tag: String) {
        try {
            val stamp = SimpleDateFormat("HH:mm:ss.SSS", Locale.US).format(Date())
            val file = File(context.applicationContext.filesDir, FILE_NAME)
            FileOutputStream(file, true).use { out ->
                out.write("$stamp $tag\n".toByteArray(Charsets.UTF_8))
                out.fd.sync()
            }
            trim(file)
        } catch (_: Throwable) {
            // Diagnostics stay silent rather than become a failure.
        }
    }

    /** The most recent mark ("HH:mm:ss.SSS tag"), or null when none. */
    fun last(context: Context): String? = try {
        val file = File(context.applicationContext.filesDir, FILE_NAME)
        if (file.exists()) {
            file.readLines().lastOrNull { it.isNotBlank() }
        } else {
            null
        }
    } catch (_: Throwable) {
        null
    }

    private fun trim(file: File) {
        try {
            val lines = file.readLines()
            if (lines.size > MAX_LINES) {
                file.writeText(lines.takeLast(MAX_LINES).joinToString("\n") + "\n")
            }
        } catch (_: Throwable) {
        }
    }
}
