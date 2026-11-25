package io.agenticcontrol.app.bgtools

import io.agenticcontrol.app.cameraview.ChainedAudit

/**
 * RMM-10 (Android completion) — background tools as a first-class
 * governed thing: fix without taking the screen. A NAMED catalogue
 * over the existing tool hosts (PhoneToolHost / ShellToolHost /
 * AccessToolHost), distinct from session tools in contract, gating
 * and audit shape (entries are typed `bgtool_*`, never `tool_*`).
 *
 * Gating contract is RMM-03-shaped: every invocation must carry a
 * signed-command envelope (command class, nonce, expiry, payload
 * hash) verified against the enrolled hub key BEFORE execution.
 * INTEGRATION POINT (flagged): Lane B1's Android RMM-03 gate had
 * NOT landed when this was built, so verification sits behind
 * [SignedCommandVerifier] — the Windows model's interface shape.
 * BOUND by Lane INT (2026-11-21): [B1SignedCommandVerifier] binds
 * this interface to B1's rmmspine verifier; no caller changes.
 *
 * Journaling is RMM-15-shaped: each job checkpoints before its
 * non-idempotent step and resume re-validates the envelope.
 * Backstage streaming is NOT BUILT (completion decision, 2026-11-21):
 * the policy key exists, default OFF, governing nothing.
 */
object BgToolsPolicy {
    // bd-and-rmm F2 fix (2026-11-22): the registry seeds
    // rmm.background_tools.enabled default OFF — the code default
    // now matches it (was ON, contradicting the registry), and a
    // bound ManagementPolicyEngine governs through PolicyGate.
    @Volatile var enabled: Boolean = false // rmm.background_tools.enabled (registry default OFF)
    fun isEnabled(): Boolean =
        io.agenticcontrol.app.rmmspine.PolicyGate.enabledFor("rmm.background_tools.enabled", enabled)
    @Volatile var backstageStreaming: Boolean = false // key only; no streaming code path ships
    private val perTool = mutableMapOf<String, Boolean>()
    @Synchronized fun setToolEnabled(tool: String, on: Boolean) { perTool[tool] = on }
    @Synchronized fun toolEnabled(tool: String): Boolean = perTool[tool] ?: true
}

data class SignedEnvelope(
    val commandClass: String, val nonce: String, val expiresMs: Long, val payloadHash: String, val signature: String,
    // B1 binding fields (Lane INT, 2026-11-21): the key id and issued
    // time of the RMM-03 envelope this invocation carries. Defaulted,
    // so every existing caller/test construction is unchanged; the
    // B1-backed verifier below refuses when they are absent, because
    // a real RMM-03 canonical body cannot be rebuilt without them.
    val keyId: String = "", val issuedMs: Long = 0L
)
fun interface SignedCommandVerifier { fun verify(env: SignedEnvelope, payload: ByteArray): Boolean }

/**
 * Lane INT binding (2026-11-21) — B3's [SignedCommandVerifier] bound
 * to Lane B1's real RMM-03 verifier (rmmspine/SignedCommands.kt).
 * Fully-qualified names throughout: rmmspine's verifier class carries
 * the same simple name as this package's fun interface.
 *
 * Translation: this package's class name `background_tool` is the
 * catalogue name; the RMM-03 class it executes as is
 * `background_action`. The B1 envelope is rebuilt from the carried
 * fields — version 1, key id, issued/expiry rendered by B1's IsoTime,
 * nonce, payload hash, the payload itself (base64), and the carried
 * signature (base64 Ed25519 over B1's canonical body, exactly as
 * B1's SignedCommandSigner mints it). B1's verifier then applies its
 * full gate: class, expiry, issued-not-in-future, payload hash,
 * key-ring/retirement, Ed25519 signature, payload binding and its
 * replay guard. Any refusal maps to false — fail closed, and
 * BgToolService's own nonce/expiry checks still run first, unchanged.
 * No caller changes: BgToolService takes this class wherever it took
 * the interface.
 */
class B1SignedCommandVerifier(
    private val delegate: io.agenticcontrol.app.rmmspine.SignedCommandVerifier,
    private val clockMs: () -> Long = { System.currentTimeMillis() }
) : SignedCommandVerifier {
    override fun verify(env: SignedEnvelope, payload: ByteArray): Boolean {
        if (env.keyId.isBlank() || env.issuedMs <= 0L) return false
        val b1Class = if (env.commandClass == BgToolCatalogue.COMMAND_CLASS)
            io.agenticcontrol.app.rmmspine.SignedCommandClasses.BACKGROUND_ACTION else env.commandClass
        val b1Env = io.agenticcontrol.app.rmmspine.SignedCommandEnvelope(
            version = 1,
            commandClass = b1Class,
            keyId = env.keyId,
            issuedUtc = io.agenticcontrol.app.rmmspine.IsoTime.format(env.issuedMs),
            expiresUtc = io.agenticcontrol.app.rmmspine.IsoTime.format(env.expiresMs),
            nonce = env.nonce,
            payloadHash = env.payloadHash,
            payloadBase64 = java.util.Base64.getEncoder().encodeToString(payload),
            signatureBase64 = env.signature
        )
        // Expected class is PINNED to background_action: an envelope
        // signed for any other class refuses here, never widens.
        return delegate.verify(b1Env, clockMs(),
            io.agenticcontrol.app.rmmspine.SignedCommandClasses.BACKGROUND_ACTION, payload).allowed
    }
}
fun interface BgToolExecutor { fun execute(tool: String, args: Map<String, String>): String }

object BgToolCatalogue {
    /** name -> (host, mutating?) — the closed catalogue. */
    val TOOLS: Map<String, Pair<String, Boolean>> = mapOf(
        "device_info" to ("phone" to false),
        "storage_report" to ("phone" to false),
        "app_cache_clear" to ("phone" to true),
        "service_restart" to ("shell" to true),
        "policy_reapply" to ("phone" to true),
        "log_bundle_collect" to ("shell" to false),
        "network_probe" to ("shell" to false),
        "access_snapshot" to ("access" to false)
    )
    const val COMMAND_CLASS = "background_tool"
}

class BgToolService(
    private val verifier: SignedCommandVerifier,
    private val executor: BgToolExecutor,
    val audit: ChainedAudit = ChainedAudit(),
    private val clockMs: () -> Long = { System.currentTimeMillis() },
    /** bd-and-rmm F3: device-visible notice sink — invoked with a
     *  plain-words notice BEFORE any execution (the Android layer
     *  posts it as a notification / presence entry). Every notice
     *  is also kept in [notices] and chained in the audit. */
    private val noticeSink: ((String) -> Unit)? = null,
    /** bd-and-rmm F3: approval gate for MUTATING catalogue tools.
     *  When wired, a mutating tool runs only when this returns
     *  true. When null, mutating tools run under the signed
     *  envelope alone and the audit says so (named, not hidden). */
    private val mutatingApproval: ((tool: String) -> Boolean)? = null,
    /** bd-and-rmm F3: durable job store. When supplied, jobs
     *  (tool, args, state, envelope binding) persist across
     *  process restarts — the old in-memory map lost every job. */
    private val jobStoreFile: java.io.File? = null
) {
    data class Job(
        val id: String, val tool: String, var state: String, var checkpoint: String?, var result: String?,
        /** bd-and-rmm F1: the job's ORIGINAL args and the envelope
         *  payload hash it was authorised under. Resume replays
         *  THESE args and requires the new envelope to bind to the
         *  same canonical payload — never emptyMap(), never an
         *  unrelated envelope. */
        val args: Map<String, String> = emptyMap(),
        val envelopePayloadHash: String = ""
    )

    private val usedNonces = mutableSetOf<String>()
    private val jobs = mutableMapOf<String, Job>()
    private var nextId = 1
    private val noticeList = mutableListOf<String>()

    init {
        loadJobs()
    }

    /** Every device-visible notice this service has recorded. */
    @Synchronized
    fun notices(): List<String> = noticeList.toList()

    private fun notice(text: String) {
        noticeList += text
        audit.append("bgtool_notice", text)
        try {
            noticeSink?.invoke(text)
        } catch (_: Exception) {
        }
    }

    companion object {
        /**
         * bd-and-rmm F1 fix: THE canonical bgtool payload, in the
         * platform's established background_action convention —
         * `tool=<name>` with args appended as `|key=value;key=value`
         * (keys sorted) when present. These are the same bytes
         * McpCore binds for background_action envelopes and the hub
         * signs (LaneINT's binding proof carries exactly
         * "tool=device_info"). The service rebuilds the payload
         * from (tool, args) and verifies the envelope against IT:
         * the caller-supplied payload bytes are never trusted as
         * both the payload and its own expectation (the old B1
         * binding passed the same caller bytes as both, so the
         * check always passed and any envelope authorised any tool
         * with any arguments).
         */
        fun canonicalPayload(tool: String, args: Map<String, String>): ByteArray {
            val sb = StringBuilder("tool=").append(tool)
            if (args.isNotEmpty()) {
                sb.append('|')
                sb.append(args.toSortedMap().entries.joinToString(";") { "${it.key}=${it.value}" })
            }
            return sb.toString().toByteArray(Charsets.UTF_8)
        }

        fun payloadHashHex(payload: ByteArray): String =
            java.security.MessageDigest.getInstance("SHA-256").digest(payload)
                .joinToString("") { "%02x".format(it) }
    }

    @Synchronized
    fun invoke(tool: String, args: Map<String, String>, env: SignedEnvelope, payload: ByteArray): Result<Job> {
        fun refuse(r: String): Result<Job> { audit.append("bgtool_refused", "tool=$tool reason=$r"); return Result.failure(IllegalStateException(r)) }
        if (!BgToolsPolicy.isEnabled()) return refuse("policy rmm.background_tools.enabled is OFF")
        if (tool !in BgToolCatalogue.TOOLS) return refuse("tool not in the named catalogue")
        if (!BgToolsPolicy.toolEnabled(tool)) return refuse("tool disabled by policy toggle")
        if (env.commandClass != BgToolCatalogue.COMMAND_CLASS) return refuse("wrong command class: ${env.commandClass}")
        if (env.expiresMs <= clockMs()) return refuse("envelope expired")
        if (env.nonce in usedNonces) return refuse("nonce replay refused")
        // bd-and-rmm F1: bind the envelope to THIS tool + THESE
        // args. The canonical payload is rebuilt here; the
        // envelope must carry its hash, and the verifier checks
        // the signature over the canonical bytes. The [payload]
        // parameter is retained for interface compatibility and
        // must equal the canonical bytes when supplied non-empty —
        // a mismatched supplied payload refuses rather than being
        // silently substituted.
        val canonical = canonicalPayload(tool, args)
        if (payload.isNotEmpty() && !payload.contentEquals(canonical))
            return refuse("supplied payload does not match the canonical tool/args payload (binding refused)")
        if (env.payloadHash != payloadHashHex(canonical))
            return refuse("envelope payload hash does not bind this tool and arguments")
        if (!verifier.verify(env, canonical)) return refuse("signature verification failed")
        // bd-and-rmm F3: the catalogue's mutating flag now GATES.
        val mutating = BgToolCatalogue.TOOLS.getValue(tool).second
        if (mutating && mutatingApproval != null && !mutatingApproval.invoke(tool))
            return refuse("mutating tool '$tool' refused by the approval gate")
        usedNonces.add(env.nonce)
        val job = Job(
            "bgjob-${nextId++}", tool, "running", checkpoint = "pre_execute", result = null,
            args = args, envelopePayloadHash = env.payloadHash
        )
        jobs[job.id] = job
        // bd-and-rmm F3: a device-visible notice BEFORE execution —
        // background tools never run invisibly on the user's phone.
        notice("Background tool ${job.id}: '$tool' is running on this phone (signed hub command).")
        audit.append("bgtool_started", "job=${job.id} tool=$tool nonce=${env.nonce} mutating=$mutating")
        persistJobs()
        return try {
            val out = executor.execute(tool, args)
            job.state = "succeeded"; job.checkpoint = "done"; job.result = out
            audit.append("bgtool_succeeded", "job=${job.id} tool=$tool")
            persistJobs()
            Result.success(job)
        } catch (e: Exception) {
            job.state = "failed_checkpointed" // RMM-15 shape: resumable from the checkpoint
            audit.append("bgtool_failed", "job=${job.id} tool=$tool reason=${e.message}")
            persistJobs()
            Result.success(job)
        }
    }

    /**
     * Resume a failed job. bd-and-rmm F1/F3 fix: the new envelope
     * must bind to the job's ORIGINAL canonical payload (same tool,
     * same args, same payload hash), the ORIGINAL args replay —
     * and a MUTATING (non-idempotent) tool is never blindly
     * re-executed: it PARKS for a human decision, exactly as
     * JobJournal.resumeAll parks non-idempotent steps.
     */
    @Synchronized
    fun resume(jobId: String, env: SignedEnvelope, payload: ByteArray): Result<Job> {
        val job = jobs[jobId] ?: return Result.failure(IllegalStateException("unknown job"))
        if (job.state != "failed_checkpointed") return Result.failure(IllegalStateException("job is not resumable (state=${job.state})"))
        val canonical = canonicalPayload(job.tool, job.args)
        if (env.expiresMs <= clockMs() || env.nonce in usedNonces ||
            env.payloadHash != job.envelopePayloadHash || env.payloadHash != payloadHashHex(canonical) ||
            (payload.isNotEmpty() && !payload.contentEquals(canonical)) ||
            !verifier.verify(env, canonical)
        ) {
            audit.append("bgtool_refused", "tool=${job.tool} reason=resume envelope does not bind the job's original tool/args")
            return Result.failure(IllegalStateException("resume re-validation failed: envelope is not bound to this job's original tool and arguments"))
        }
        usedNonces.add(env.nonce)
        val mutating = BgToolCatalogue.TOOLS[job.tool]?.second == true
        if (mutating) {
            job.state = "parked_non_idempotent"
            audit.append("bgtool_parked", "job=$jobId tool=${job.tool} reason=mutating tool is non-idempotent; resume parks for a human decision instead of re-executing")
            persistJobs()
            return Result.success(job)
        }
        audit.append("bgtool_resumed", "job=$jobId tool=${job.tool}")
        notice("Background tool ${job.id}: '${job.tool}' resumed on this phone (signed hub command).")
        return try {
            job.result = executor.execute(job.tool, job.args); job.state = "succeeded"; job.checkpoint = "done"
            audit.append("bgtool_succeeded", "job=$jobId tool=${job.tool}"); persistJobs(); Result.success(job)
        } catch (e: Exception) {
            job.state = "failed_checkpointed"
            audit.append("bgtool_failed", "job=$jobId reason=${e.message}"); persistJobs(); Result.success(job)
        }
    }

    @Synchronized fun job(id: String): Job? = jobs[id]

    // ---- durable job store (bd-and-rmm F3) ----

    private fun persistJobs() {
        val file = jobStoreFile ?: return
        try {
            val root = org.json.JSONObject()
            val arr = org.json.JSONArray()
            for (j in jobs.values) {
                val argsObj = org.json.JSONObject()
                for ((k, v) in j.args) argsObj.put(k, v)
                arr.put(
                    org.json.JSONObject()
                        .put("id", j.id).put("tool", j.tool).put("state", j.state)
                        .put("checkpoint", j.checkpoint ?: org.json.JSONObject.NULL)
                        .put("result", j.result ?: org.json.JSONObject.NULL)
                        .put("args", argsObj).put("envelopePayloadHash", j.envelopePayloadHash)
                )
            }
            root.put("jobs", arr)
            file.parentFile?.mkdirs()
            val tmp = java.io.File(file.parentFile, file.name + ".tmp")
            tmp.writeText(root.toString())
            if (!tmp.renameTo(file)) tmp.delete()
        } catch (_: Exception) {
            // Persistence failure never breaks a tool call; the
            // in-memory job stands and the audit records the run.
        }
    }

    private fun loadJobs() {
        val file = jobStoreFile ?: return
        try {
            if (!file.exists()) return
            val root = org.json.JSONObject(file.readText())
            val arr = root.getJSONArray("jobs")
            for (i in 0 until arr.length()) {
                val o = arr.getJSONObject(i)
                val argsObj = o.getJSONObject("args")
                val args = mutableMapOf<String, String>()
                val keys = argsObj.keys()
                while (keys.hasNext()) {
                    val k = keys.next()
                    args[k] = argsObj.getString(k)
                }
                val job = Job(
                    o.getString("id"), o.getString("tool"), o.getString("state"),
                    if (o.isNull("checkpoint")) null else o.getString("checkpoint"),
                    if (o.isNull("result")) null else o.getString("result"),
                    args, o.optString("envelopePayloadHash", "")
                )
                jobs[job.id] = job
                val n = job.id.removePrefix("bgjob-").toIntOrNull()
                if (n != null && n >= nextId) nextId = n + 1
            }
        } catch (_: Exception) {
            // A corrupt job store loads NOTHING rather than partial
            // jobs (fail closed, named here).
            jobs.clear()
        }
    }
}
