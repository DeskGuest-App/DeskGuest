package io.agenticcontrol.app.server

import android.content.Context
import io.agenticcontrol.app.R
import io.agenticcontrol.app.adb.AdbClient
import io.agenticcontrol.app.strings.consentString
import io.agenticcontrol.app.adb.AndroidAdbIdentity
import org.json.JSONObject

/**
 * The self-paired wireless ADB shell channel (0.4.0, stage 3): the
 * app pairs with the phone's own adbd once (Shell section in the
 * app), then shell_exec / settings_get / settings_put /
 * package_info run through it. Every tool requires an active
 * session (the same drive gate as the other drive tools), the
 * "shell" MCP scope, and — for shell_exec and settings_put — the
 * approval policy. settings_put proves itself with a read-back:
 * a put that does not read back equal is reported as failed.
 *
 * The endpoint is the device's own wireless-debugging address,
 * found by mDNS or entered by hand; it is stored locally and never
 * leaves the phone.
 */
class ShellToolHost(context: Context) : McpCore.ToolHost {

    private val appContext = context.applicationContext
    private val sessions = SessionManager
    private var client: AdbClient? = null

    @Volatile
    private var core: McpCore? = null

    override fun attach(core: McpCore) {
        this.core = core
    }

    /** The calling pairing's key (bd-and-core F4): shell tools
     *  check the session against it, like the access tools. */
    private fun callerKey(): String? = core?.currentPairingKey?.get()

    /** bd-and-core F3: after a blocking approval wait, the session
     *  must still be the one that was live at entry — a STOP or an
     *  owner grab during the wait stops the command running. */
    private fun refusalIfChangedSince(genAtEntry: Long): String? =
        sessions.refusalIfChangedSince(genAtEntry, callerKey())

    init {
        // bd-and-core F3, second leg: when the session ends, the
        // shell channel closes with it — no live AdbClient outlives
        // the session it served. (In-flight execs additionally
        // revalidate via refusalIfChangedSince before dispatch;
        // a command already on the wire when STOP lands is bounded
        // by its exec timeout, named here honestly.)
        SessionManager.addListener { session ->
            if (session == null) {
                try {
                    client?.close()
                } catch (_: Exception) {
                }
                client = null
            }
        }
    }

    override fun tools(): List<McpCore.ToolDef> = listOf(
        McpCore.ToolDef(
            "shell_exec",
            "Run a shell command on this phone through the self-paired wireless " +
                "ADB channel. Requires an active session and the shell scope. Output is " +
                "capped; the exit code is appended. Fails with UNAVAILABLE until the " +
                "channel is paired in the app.",
            "shell",
            schema("command" to "string"),
            run = { args -> shellExec(args) }
        ),
        McpCore.ToolDef(
            "settings_get",
            "Read an Android setting (namespace: system, secure, or global) " +
                "through the shell channel. Requires an active session.",
            "shell",
            schema("namespace" to "string", "key" to "string"),
            run = { args -> settingsGet(args) }
        ),
        McpCore.ToolDef(
            "settings_put",
            "Write an Android setting through the shell channel and verify it " +
                "by reading it back. Requires an active session and approval per policy.",
            "shell",
            schema("namespace" to "string", "key" to "string", "value" to "string"),
            run = { args -> settingsPut(args) }
        ),
        McpCore.ToolDef(
            "logcat_read",
            "Read recent device log lines (logcat) through the self-paired shell channel, " +
                "for diagnosis. Optionally filter to one tag. Capped lines; requires an " +
                "active session, the shell scope, and approval per policy. (A normal app " +
                "cannot read the log directly — Android reserves READ_LOGS to system apps — " +
                "so this goes through the user's own paired shell channel, the lawful route.)",
            "shell",
            schema("tag" to "string", "lines" to "integer"),
            run = { args -> logcatRead(args) }
        ),
        McpCore.ToolDef(
            "grant_permission",
            "Grant a runtime permission to an app through the shell channel " +
                "(pm grant), verified by read-back where the system reports it. Only " +
                "grantable runtime permissions can be granted this way; special/appop " +
                "permissions are the user's to grant in Settings. Requires an active " +
                "session and the user's app-changes approval.",
            "shell",
            schema("package" to "string", "permission" to "string"),
            run = { args -> grantPermission(args) }
        ),
        McpCore.ToolDef(
            "install_package",
            "Install an APK that is already in the agent-files folder (push it with " +
                "file_push first) through the shell channel (pm install). Requires an " +
                "active session and the user's app-changes approval. The system " +
                "installer rules still apply: a downgrade or signature mismatch fails " +
                "and is reported, never forced.",
            "shell",
            schema("file" to "string"),
            run = { args -> installPackage(args) }
        ),
        McpCore.ToolDef(
            "reboot_device",
            "Reboot the phone through the shell channel. Requires an active session " +
                "and approval per policy. The control channel is expected to return " +
                "after the user unlocks the phone (the boot chain), and this session ends " +
                "with the reboot.",
            "shell",
            schema(),
            run = { rebootDevice() }
        ),
        McpCore.ToolDef(
            "package_info",
            "Read an installed package's version (versionName, versionCode, " +
                "first/last install times) through the shell channel. Requires an active session.",
            "shell",
            schema("package" to "string"),
            run = { args -> packageInfo(args) }
        )
    )

    private fun schema(vararg fields: Pair<String, String>): JSONObject {
        val props = JSONObject()
        fields.forEach { (name, type) -> props.put(name, JSONObject().put("type", type)) }
        return JSONObject().put("type", "object").put("properties", props)
    }

    // ---- tools ----

    private fun shellExec(args: JSONObject): String {
        sessions.driveRefusal(callerKey())?.let { return it }
        val command = args.optString("command").trim()
        if (command.isEmpty()) return "shell_exec needs a command."
        // W8 item 5 (OI-13, SHELL_INPUT path): synthetic-input
        // verbs and ACP-targeting launches refuse BEFORE the gate
        // — the gate never sees a command this path must refuse.
        if (io.agenticcontrol.app.design.GateModel.shellInputRefused(command, OWN_PACKAGE)) {
            return io.agenticcontrol.app.design.GateModel.injectionRefusalLine(
                io.agenticcontrol.app.design.GateModel.InjectionPath.SHELL_INPUT
            )
        }
        val genAtEntry = sessions.generation.get()
        gate(ApprovalGate.ActionClass.SHELL, command, payload = command)?.let { return it }
        refusalIfChangedSince(genAtEntry)?.let { return it }
        val (ok, output) = execRaw("$command; echo $EXIT_MARKER\$?", 25_000)
        if (!ok) return output
        val markerAt = output.lastIndexOf(EXIT_MARKER)
        if (markerAt < 0) return output.trimEnd()
        val body = output.substring(0, markerAt).trimEnd('\n', '\r', ' ')
        val code = output.substring(markerAt + EXIT_MARKER.length)
            .lineSequence().firstOrNull()?.trim() ?: "?"
        val capped = if (body.length > MAX_OUTPUT) {
            body.substring(0, MAX_OUTPUT) + "\n[output truncated at $MAX_OUTPUT chars]"
        } else {
            body
        }
        return if (capped.isEmpty()) "(exit $code)" else "$capped\n(exit $code)"
    }

    private fun settingsGet(args: JSONObject): String {
        sessions.driveRefusal(callerKey())?.let { return it }
        val ns = namespace(args) ?: return "namespace must be system, secure, or global."
        val key = args.optString("key").trim()
        if (!KEY_PATTERN.matches(key)) return "That setting key is not valid."
        val (ok, output) = execRaw("settings get $ns $key", 12_000)
        if (!ok) return output
        val value = output.trim()
        return if (value.isEmpty() || value == "null") {
            "$ns/$key is not set"
        } else {
            "$ns/$key = $value"
        }
    }

    private fun settingsPut(args: JSONObject): String {
        sessions.driveRefusal(callerKey())?.let { return it }
        val ns = namespace(args) ?: return "namespace must be system, secure, or global."
        val key = args.optString("key").trim()
        if (!KEY_PATTERN.matches(key)) return "That setting key is not valid."
        val value = args.optString("value")
        if (!VALUE_PATTERN.matches(value)) {
            return "That setting value contains characters the shell channel will not carry."
        }
        val genAtEntry = sessions.generation.get()
        gate(ApprovalGate.ActionClass.SETTINGS_CHANGE, "settings put $ns $key $value", payload = "settings put $ns $key $value")
            ?.let { return it }
        refusalIfChangedSince(genAtEntry)?.let { return it }
        val (ok, output) = execRaw("settings put $ns $key $value", 12_000)
        if (!ok) return output
        // Mandatory read-back verification.
        val (okBack, back) = execRaw("settings get $ns $key", 12_000)
        if (!okBack) return "The put ran, but the read-back failed: $back"
        val readBack = back.trim()
        return if (readBack == value) {
            "Set $ns/$key = $value (verified by read-back)."
        } else {
            "The put did not take: read-back shows $ns/$key = $readBack, not $value."
        }
    }

    private fun packageInfo(args: JSONObject): String {
        sessions.driveRefusal(callerKey())?.let { return it }
        val pkg = args.optString("package").trim()
        if (!KEY_PATTERN.matches(pkg)) return "That package name is not valid."
        val (ok, output) = execRaw("dumpsys package $pkg", 15_000)
        if (!ok) return output
        if (!output.contains("Package [$pkg]")) {
            return "UNAVAILABLE: package $pkg is not installed (or dumpsys has no record of it)."
        }
        val lines = mutableListOf("Package $pkg:")
        for (line in output.lineSequence()) {
            val trimmed = line.trim()
            when {
                trimmed.startsWith("versionCode=") ->
                    lines.add("  " + trimmed.replace(" minSdk", " · minSdk")
                        .replace(" targetSdk", " · targetSdk"))
                trimmed.startsWith("versionName=") -> lines.add("  $trimmed")
                trimmed.startsWith("firstInstallTime=") -> lines.add("  $trimmed")
                trimmed.startsWith("lastUpdateTime=") -> lines.add("  $trimmed")
            }
        }
        return lines.joinToString("\n")
    }

    // ---- BD-XCHECK owed tools (2026-11-22) ----

    private fun logcatRead(args: JSONObject): String {
        sessions.driveRefusal(callerKey())?.let { return it }
        val tag = args.optString("tag").trim()
        if (tag.isNotEmpty() && !TAG_PATTERN.matches(tag)) {
            return "That log tag is not valid (letters, digits, '.', '_' or '-' only)."
        }
        val lines = args.optInt("lines", 200).coerceIn(1, MAX_LOGCAT_LINES)
        val genAtEntry = sessions.generation.get()
        gate(ApprovalGate.ActionClass.SHELL, "Read the device log (logcat, $lines lines)")?.let { return it }
        refusalIfChangedSince(genAtEntry)?.let { return it }
        val filter = if (tag.isEmpty()) "" else " $tag:V *:S"
        val (ok, output) = execRaw("logcat -d -t $lines$filter", 15_000)
        if (!ok) return output
        val capped = if (output.length > MAX_OUTPUT) {
            output.substring(0, MAX_OUTPUT) + "\n[output truncated at $MAX_OUTPUT chars]"
        } else {
            output.trimEnd()
        }
        return if (capped.isBlank()) "The log buffer held no matching lines." else capped
    }

    private fun grantPermission(args: JSONObject): String {
        sessions.driveRefusal(callerKey())?.let { return it }
        val pkg = args.optString("package").trim()
        if (!KEY_PATTERN.matches(pkg)) return "That package name is not valid."
        val permission = args.optString("permission").trim()
        if (!PERMISSION_PATTERN.matches(permission)) return "That permission name is not valid."
        val genAtEntry = sessions.generation.get()
        gate(ApprovalGate.ActionClass.PACKAGE_CHANGE, "Grant $permission to $pkg", payload = "pm grant $pkg $permission")?.let { return it }
        refusalIfChangedSince(genAtEntry)?.let { return it }
        val (ok, output) = execRaw("pm grant $pkg $permission", 12_000)
        if (!ok) return output
        if (output.isNotBlank() && !output.contains("Success")) {
            // pm grant prints an exception for non-grantable permissions.
            return "The grant did not take: ${output.trim()}. Only grantable runtime " +
                "permissions can be granted this way; special permissions are the " +
                "user's to grant in Settings."
        }
        // Read-back: dumpsys reports runtime permissions with granted=true.
        val (okBack, back) = execRaw("dumpsys package $pkg", 15_000)
        if (okBack && back.contains("$permission: granted=true")) {
            sessions.noteAction("grant_permission $pkg")
            return "Granted $permission to $pkg (verified by read-back)."
        }
        return "The grant command ran for $permission on $pkg, but the read-back could " +
            "not confirm it (the permission may not be a runtime permission this " +
            "device reports, or the package may not declare it)."
    }

    private fun installPackage(args: JSONObject): String {
        sessions.driveRefusal(callerKey())?.let { return it }
        val file = args.optString("file").trim()
        if (!FileScope.isPlainName(file) || !file.endsWith(".apk", ignoreCase = true)) {
            return "install_package needs the plain file name of an .apk in the agent-files folder."
        }
        val dir = appContext.getExternalFilesDir("agent-files")
            ?: java.io.File(appContext.filesDir, "agent-files")
        val apk = java.io.File(dir, file)
        if (!apk.exists() || !apk.isFile) {
            return "No such file in the agent-files folder: $file (push it with file_push first)."
        }
        val genAtEntry = sessions.generation.get()
        gate(ApprovalGate.ActionClass.PACKAGE_CHANGE, "Install $file", payload = "pm install -r $file")?.let { return it }
        refusalIfChangedSince(genAtEntry)?.let { return it }
        val (ok, output) = execRaw("pm install -r \"${apk.absolutePath}\"", 60_000)
        if (!ok) return output
        return if (output.contains("Success")) {
            sessions.noteAction("install_package $file")
            "Installed $file (pm install reported Success)."
        } else {
            "The install did not complete: ${output.trim().ifBlank { "pm install gave no output" }}. " +
                "System installer rules (signature, downgrade, policy) are reported, never forced."
        }
    }

    private fun rebootDevice(): String {
        sessions.driveRefusal(callerKey())?.let { return it }
        val genAtEntry = sessions.generation.get()
        gate(ApprovalGate.ActionClass.SHELL, "Reboot the device")?.let { return it }
        refusalIfChangedSince(genAtEntry)?.let { return it }
        sessions.noteAction("reboot_device")
        // The reboot drops the shell channel mid-command by design;
        // either outcome (a reply, or the channel dying) means the
        // command was dispatched — a channel that was never paired
        // has already refused above via execRaw's pairing check on
        // earlier calls, and a live refusal is distinguished by the
        // UNAVAILABLE pairing text.
        val (ok, output) = execRaw("reboot", 8_000)
        if (!ok && output.contains("not paired")) return output
        return "Reboot command dispatched through the shell channel. This session ends " +
            "with the reboot; the control channel is expected to return after the " +
            "user unlocks the phone (the boot chain)."
    }

    private fun namespace(args: JSONObject): String? =
        args.optString("namespace").trim().lowercase()
            .takeIf { it == "system" || it == "secure" || it == "global" }

    // ---- channel plumbing ----

    /**
     * Run a raw command; (true, output) or (false, ready-made
     * refusal text). Connection is lazy and reused; a dead
     * connection is retried once with a fresh connect.
     */
    @Synchronized
    private fun execRaw(command: String, timeoutMs: Long): Pair<Boolean, String> {
        val endpoint = ShellStore.endpoint(appContext)
            ?: return false to "UNAVAILABLE: the shell channel is not paired yet. " +
                "Pair it from the Shell section in the app first."
        for (attempt in 0..1) {
            try {
                val c = client?.takeIf { it.isConnected } ?: connect(endpoint).also { client = it }
                return true to c.exec(command, timeoutMs)
            } catch (e: Exception) {
                client?.close()
                client = null
                if (attempt == 1) {
                    return false to "UNAVAILABLE: the shell channel did not answer " +
                        "(${e.message ?: "connection failed"}). Wireless debugging may be " +
                        "off, or the endpoint changed — check the Shell section in the app."
                }
            }
        }
        return false to "UNAVAILABLE: the shell channel is not reachable."
    }

    private fun connect(endpoint: ShellStore.Endpoint): AdbClient {
        val identity = AndroidAdbIdentity.getOrCreate()
        val c = AdbClient(identity)
        c.connect(endpoint.host, endpoint.port, useTls = endpoint.tls)
        return c
    }

    private fun gate(
        cls: ApprovalGate.ActionClass, summary: String,
        // W7 item 2 (§3/OI-12): the REAL submitted payload (the
        // exact command string the channel will carry).
        payload: String? = null,
        fromChat: Boolean = false
    ): String? {
        val policy = ApprovalSettings.load(appContext, cls)
        return when (ApprovalGate.decide(policy)) {
            ApprovalGate.Decision.ALLOW -> null
            ApprovalGate.Decision.DENY ->
                "Refused: the user's approval policy blocks ${cls.label.lowercase()} " +
                    "actions. They can change it in the app, under Approvals."
            ApprovalGate.Decision.ASK -> {
                // FR-123: a session-less caller is named plainly as
                // unnamed through the U8 strings door — never the
                // fabricated generic "Your AI".
                val agent = SessionManager.active?.agentName?.takeIf { it.isNotBlank() }
                    ?: appContext.consentString(R.string.gate_unnamed_caller)
                if (ApprovalOverlay.requestApproval(
                        appContext, cls, summary, agent,
                        payload = payload, fromChat = fromChat,
                        onDenyAndEnd = GateDenyAndEnd.handler(cls)
                    )
                ) {
                    null
                } else {
                    "Not approved: the user did not approve this ${cls.label.lowercase()} " +
                        "action (denied, timed out, or the prompt could not be shown)."
                }
            }
        }
    }

    /** Forget the channel: drop the endpoint and close any socket. */
    @Synchronized
    fun forget() {
        client?.close()
        client = null
        ShellStore.clear(appContext)
    }

    companion object {
        /** ACP's own package (AndroidManifest package=) — the
         *  OI-13 shell-path refusal target. */
        const val OWN_PACKAGE = "io.agenticcontrol.app"
        private const val EXIT_MARKER = "__ACP_EXIT__"
        private const val MAX_OUTPUT = 64_000
        private val KEY_PATTERN = Regex("[A-Za-z0-9_.]+")
        private val VALUE_PATTERN = Regex("[A-Za-z0-9_.\\-:/ ]*")
        private val TAG_PATTERN = Regex("[A-Za-z0-9_.\\-]+")
        private val PERMISSION_PATTERN = Regex("[A-Za-z0-9_.]+")
        private const val MAX_LOGCAT_LINES = 1_000
    }
}

/** Local storage for the paired shell endpoint. */
object ShellStore {
    data class Endpoint(val host: String, val port: Int, val tls: Boolean)

    private const val PREFS = "shell"

    fun endpoint(context: Context): Endpoint? {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val host = prefs.getString("host", null)?.takeIf { it.isNotBlank() } ?: return null
        val port = prefs.getInt("port", 0)
        if (port <= 0) return null
        return Endpoint(host, port, prefs.getBoolean("tls", true))
    }

    fun save(context: Context, endpoint: Endpoint) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString("host", endpoint.host)
            .putInt("port", endpoint.port)
            .putBoolean("tls", endpoint.tls)
            .apply()
    }

    fun clear(context: Context) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().clear().apply()
    }

    fun markPaired(context: Context, paired: Boolean) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putBoolean("identity_paired", paired)
            .apply()
    }

    fun identityPaired(context: Context): Boolean =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getBoolean("identity_paired", false)
}
