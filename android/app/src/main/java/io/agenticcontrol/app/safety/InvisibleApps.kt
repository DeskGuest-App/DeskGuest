package io.agenticcontrol.app.safety

/**
 * Invisible apps (SPEC §7.5, FEATURES §6) — BD-XCHECK owed item,
 * built 2026-11-22. The user marks apps (banking, password managers,
 * anything) as invisible: the host will not snapshot, screenshot,
 * drive, or list them. A session that encounters one treats it as a
 * locked door and reports `blocked_by_user_rule` — the refusal never
 * names the package back to the agent (naming it would list it).
 *
 * This file is the pure core: package-name validation, the blocklist
 * itself, and its persistence encoding. The Android storage wrapper
 * is InvisibleAppStore (same package); enforcement lives in
 * AccessToolHost, which checks the foreground package before every
 * capture and every drive action, and the launch target before
 * launch_app. Pure JVM — runs in the JVM suite.
 */
object InvisibleAppRules {

    const val BLOCKED_CODE = "blocked_by_user_rule"

    /** Android package-name shape: dot-separated segments, each
     *  starting with a letter, letters/digits/underscore after. */
    private val PACKAGE_PATTERN = Regex("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+")

    /** A normalized package name, or null when the input is not a
     *  plausible package name (never stored, never matched). */
    fun normalize(raw: String?): String? {
        val candidate = raw?.trim()?.lowercase() ?: return null
        return candidate.takeIf { PACKAGE_PATTERN.matches(it) }
    }

    /** The refusal every surface returns for a blocked app. It
     *  carries the SPEC §7.5 code and no package name. */
    fun refusal(): String =
        "$BLOCKED_CODE: the current app is on the user's invisible-apps list. " +
            "It cannot be seen, listed, or driven. Treat it as a locked door: " +
            "stop, and ask the user to handle this app themselves."

    fun refusalForLaunch(): String =
        "$BLOCKED_CODE: that app is on the user's invisible-apps list and " +
            "cannot be opened by an agent."
}

/**
 * The blocklist: a set of normalized package names the owner marked.
 * Thread-safe; the owner edits it in the app (MainActivity's
 * Invisible apps section), the tool hosts only read it.
 */
class InvisibleAppBlocklist(initial: Collection<String> = emptyList()) {

    private val lock = Any()
    private val packages = mutableSetOf<String>()

    init {
        initial.forEach { p -> InvisibleAppRules.normalize(p)?.let { packages.add(it) } }
    }

    fun isBlocked(packageName: String?): Boolean {
        val normalized = InvisibleAppRules.normalize(packageName) ?: return false
        synchronized(lock) { return normalized in packages }
    }

    /** Mark an app invisible. Returns the normalized name, or null
     *  when the input is not a valid package name. */
    fun mark(raw: String?): String? {
        val normalized = InvisibleAppRules.normalize(raw) ?: return null
        synchronized(lock) { packages.add(normalized) }
        return normalized
    }

    /** Remove a mark. Returns true when it was present. */
    fun unmark(raw: String?): Boolean {
        val normalized = InvisibleAppRules.normalize(raw) ?: return false
        synchronized(lock) { return packages.remove(normalized) }
    }

    fun list(): List<String> = synchronized(lock) { packages.sorted() }

    fun encode(): String = list().joinToString("\n")

    companion object {
        fun decode(encoded: String?): InvisibleAppBlocklist =
            InvisibleAppBlocklist(encoded?.split("\n") ?: emptyList())
    }
}
