package io.agenticcontrol.app

import android.content.Context
import java.io.File
import java.io.PrintWriter
import java.io.StringWriter
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Last-resort crash recorder (0.4.1, after the 0.4.0 startup crash
 * reached the owner with no evidence attached). An uncaught exception
 * anywhere in the process is written — timestamp, thread, full stack —
 * to a small file before the system handler runs, and MainActivity
 * shows that report on the next open instead of a black box. Startup
 * code also records caught failures here (see [record]), so a section
 * that had to be skipped says why.
 *
 * The file keeps only the most recent report; the owner clears it
 * from the report screen. Nothing here can throw: every entry point
 * swallows its own failures, because a crashing crash-handler would
 * be worse than none.
 */
object CrashTrap {

    private const val FILE_NAME = "last-crash.txt"
    @Volatile
    private var installed = false

    fun install(context: Context) {
        if (installed) return
        installed = true
        val appContext = context.applicationContext
        val previous = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, error ->
            write(appContext, "uncaught on ${thread.name}", error)
            previous?.uncaughtException(thread, error)
        }
    }

    /** Record a caught failure (startup step, home-screen section). */
    fun record(context: Context, where: String, error: Throwable) {
        write(context.applicationContext, "caught at $where", error)
    }

    /** The saved report, or null when there is none. */
    fun read(context: Context): String? = try {
        val file = File(context.applicationContext.filesDir, FILE_NAME)
        if (file.exists()) file.readText().ifBlank { null } else null
    } catch (_: Exception) {
        null
    }

    fun clear(context: Context) {
        try {
            File(context.applicationContext.filesDir, FILE_NAME).delete()
        } catch (_: Exception) {
        }
    }

    private fun write(context: Context, where: String, error: Throwable) {
        // bd-and-rest F10 fix: the report FILE is written FIRST and
        // every catch is Throwable-wide. The old order called into
        // server code (SessionEvents.emitKind) before the write and
        // caught only Exception — a lock held by the crashing
        // thread, or an Error (OOM, NoClassDefFoundError), could
        // lose the very report this class exists to guarantee. The
        // app_crash fact now goes out only after the file is safe,
        // and only from this handler's best-effort tail.
        try {
            val trace = StringWriter().also { sw ->
                error.printStackTrace(PrintWriter(sw))
            }.toString()
            val stamp = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())
            File(context.filesDir, FILE_NAME).writeText(
                "Agentic Control failure report\n$stamp — $where\n\n$trace"
            )
        } catch (_: Throwable) {
            // Nowhere left to report to; stay silent rather than crash.
        }
        // U2: an app_crash fact for subscribed pairings (kind +
        // where only — the stack stays in the owner's report file).
        try {
            io.agenticcontrol.app.server.SessionEvents.emitKind(
                io.agenticcontrol.app.server.SessionEvents.KIND_APP_CRASH,
                mapOf("where" to where)
            )
        } catch (_: Throwable) {
        }
    }
}
