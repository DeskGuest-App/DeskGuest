package io.deskguest.app.enterprise

import io.deskguest.app.enrollment.DeviceIdentity
import java.security.MessageDigest
import java.util.Base64

/**
 * Block E — enterprise pack, Android mirror (model layer only, not
 * wired into any live surface — the Slice 1 precedent). Mirrors the
 * Windows semantics in DeskGuest.Shared/Enterprise: hash-chained audit with
 * verifying exports (DIR-25/DIR-23/DIR-56), signed policy bundle with
 * pin/defer/ceiling enforcement (DIR-22/DIR-65), first-seen-operator
 * friction (SCAM-01/04/05/08/13/15), and the session-end receipt whose
 * categories are never silently omitted (HELP-09/SCAM-18).
 * Fail-closed throughout: tamper, expiry, or unknown values refuse.
 */

fun sha256Hex(s: String): String =
    MessageDigest.getInstance("SHA-256").digest(s.toByteArray(Charsets.UTF_8))
        .joinToString("") { "%02x".format(it) }

// ---- DIR-25 / DIR-56 chained audit ----

data class ChainedEntry(
    val seq: Long, val atMillis: Long, val kind: String, val actor: String,
    val detail: String, val prevHash: String, val hash: String, val clockSkewFlagged: Boolean
)

class ChainedAuditLog {
    private val entries = mutableListOf<ChainedEntry>()
    private var lastAt = Long.MIN_VALUE

    // bd-and-rmm F12 fixes (2026-11-22): entries()/headHash() are
    // now @Synchronized (they raced append from other threads);
    // hash bodies escape '\\' and '|' in kind/actor/detail so a
    // field cannot forge body boundaries; exportCsv escapes EVERY
    // field and formula-guards leading =,+,-,@; and the chain can
    // be persisted/restored as JSON (saveToFile/loadFromFile) —
    // services previously defaulted to fresh in-memory chains that
    // died with the process.
    @Synchronized fun entries(): List<ChainedEntry> = entries.toList()
    @Synchronized fun headHash(): String = if (entries.isEmpty()) "GENESIS" else entries.last().hash

    @Synchronized
    fun append(kind: String, actor: String, detail: String, atMillis: Long): ChainedEntry {
        val seq = entries.size + 1L
        val prev = if (entries.isEmpty()) "GENESIS" else entries.last().hash
        val skew = atMillis < lastAt
        if (atMillis > lastAt) lastAt = atMillis
        val hash = sha256Hex(bodyOf(seq, atMillis, kind, actor, detail, prev))
        val e = ChainedEntry(seq, atMillis, kind, actor, detail, prev, hash, skew)
        entries.add(e)
        return e
    }

    @Synchronized
    fun verify(): Pair<Boolean, String> {
        var prev = "GENESIS"
        for (e in entries) {
            if (e.prevHash != prev) return false to "BROKEN at seq ${e.seq}: prev-hash link mismatch"
            if (e.hash != sha256Hex(bodyOf(e.seq, e.atMillis, e.kind, e.actor, e.detail, e.prevHash)))
                return false to "BROKEN at seq ${e.seq}: entry hash mismatch (content altered)"
            prev = e.hash
        }
        return true to "OK: ${entries.size} entries, chain intact, head $prev"
    }

    /** CSV-escape one field: quote + double internal quotes, and
     *  neutralise spreadsheet formula injection (a field starting
     *  with =, +, - or @ gets a leading apostrophe). */
    private fun csvField(v: String): String {
        val guarded = if (v.isNotEmpty() && v[0] in "=+-@") "'$v" else v
        return "\"" + guarded.replace("\"", "\"\"") + "\""
    }

    /** DIR-23: the export itself is audited first; the header states the verdict. */
    @Synchronized
    fun exportCsv(exportedBy: String, nowMillis: Long): String {
        append("audit_export", exportedBy, "format=csv", nowMillis)
        val (ok, summary) = verify()
        val sb = StringBuilder()
        sb.appendLine("# DeskGuest audit export | format=csv | chainVerification=${if (ok) "OK" else "BROKEN"} | $summary")
        sb.appendLine("seq,atMillis,kind,actor,detail,prevHash,hash,clockSkewFlagged")
        for (e in entries) sb.appendLine(listOf(e.seq.toString(), e.atMillis.toString(), csvField(e.kind), csvField(e.actor), csvField(e.detail), e.prevHash, e.hash, e.clockSkewFlagged.toString()).joinToString(","))
        return sb.toString()
    }

    /** Persist the chain (entries only) as JSON; restore verifies
     *  the chain and refuses a broken one whole. */
    @Synchronized
    fun saveToFile(file: java.io.File) {
        val arr = org.json.JSONArray()
        for (e in entries) arr.put(org.json.JSONObject()
            .put("seq", e.seq).put("atMillis", e.atMillis).put("kind", e.kind).put("actor", e.actor)
            .put("detail", e.detail).put("prevHash", e.prevHash).put("hash", e.hash)
            .put("clockSkewFlagged", e.clockSkewFlagged))
        file.parentFile?.mkdirs()
        val tmp = java.io.File(file.parentFile, file.name + ".tmp")
        tmp.writeText(org.json.JSONObject().put("entries", arr).toString())
        if (!tmp.renameTo(file)) tmp.delete()
    }

    @Synchronized
    fun loadFromFile(file: java.io.File): Pair<Boolean, String> {
        if (!file.exists()) return false to "audit chain file absent — nothing loaded (named, not an empty chain)"
        return try {
            val arr = org.json.JSONObject(file.readText()).getJSONArray("entries")
            val loaded = mutableListOf<ChainedEntry>()
            for (i in 0 until arr.length()) {
                val o = arr.getJSONObject(i)
                loaded += ChainedEntry(o.getLong("seq"), o.getLong("atMillis"), o.getString("kind"),
                    o.getString("actor"), o.getString("detail"), o.getString("prevHash"), o.getString("hash"),
                    o.optBoolean("clockSkewFlagged", false))
            }
            entries.clear(); entries.addAll(loaded)
            lastAt = loaded.maxOfOrNull { it.atMillis } ?: Long.MIN_VALUE
            val (ok, summary) = verify()
            if (!ok) { entries.clear(); lastAt = Long.MIN_VALUE }
            ok to summary
        } catch (ex: Exception) {
            false to "audit chain load failed: ${ex.message}"
        }
    }

    companion object {
        fun esc(s: String): String = s.replace("\\", "\\\\").replace("|", "\\|")
        fun bodyOf(seq: Long, atMillis: Long, kind: String, actor: String, detail: String, prev: String): String =
            "$seq|$atMillis|${esc(kind)}|${esc(actor)}|${esc(detail)}|$prev"
    }
}

// ---- DIR-22 signed policy bundle + enforcement ----

/** The closed set of policy-toggleable feature keys (TOTAL POLICY
 * CONTROL, 2026-11-20). Mirrors PolicyFeatures in the Windows
 * DeskGuest.Shared model exactly — same keys, same normalization. The
 * §7.10 consent floor is not a key and can never become one. */
object PolicyFeatures {
    const val WAKE_ON_LAN = "wake_on_lan"                 // G-01
    const val BLANK_SCREEN = "blank_screen"               // G-02
    const val INPUT_BLOCK = "input_block"                 // G-03
    const val STANDALONE_FILE_TRANSFER = "standalone_file_transfer" // G-04
    const val VOICE_VIDEO = "voice_video"                 // G-05
    const val LOCAL_SECOND_FACTOR = "local_second_factor" // G-06
    const val WATERMARK = "watermark"                     // G-07
    const val TCP_TUNNEL = "tcp_tunnel"                   // G-08
    val ALL = setOf(WAKE_ON_LAN, BLANK_SCREEN, INPUT_BLOCK, STANDALONE_FILE_TRANSFER,
        VOICE_VIDEO, LOCAL_SECOND_FACTOR, WATERMARK, TCP_TUNNEL)
    fun normalize(keys: List<String>?): List<String> =
        (keys ?: emptyList()).map { it.trim().lowercase() }.filter { it.isNotEmpty() }.distinct().sorted()
}

data class PolicyBundle(
    val version: Int, val scopeId: String, val transportCeiling: List<String>,
    val transportMode: String, val pinnedVersion: String?, val updateDeferUntilMillis: Long?,
    val forbidAiPairings: Boolean, val disableRecording: Boolean, val unattendedTier: String,
    val issuedMillis: Long, val expiresMillis: Long, val signatureBase64: String,
    // TOTAL POLICY CONTROL, format v2: per-feature toggles, inside
    // the signed body for version >= 2. A v1 bundle carrying them
    // refuses — unsigned toggles are never honored.
    val disabledFeatures: List<String> = emptyList(),
    val requiredFeatures: List<String> = emptyList()
) {
    val disabled: List<String> get() = PolicyFeatures.normalize(disabledFeatures)
    val required: List<String> get() = PolicyFeatures.normalize(requiredFeatures)

    fun canonicalBody(): String {
        var body = listOf(
            version.toString(), scopeId, transportCeiling.joinToString(","), transportMode,
            pinnedVersion ?: "-", updateDeferUntilMillis?.toString() ?: "-",
            forbidAiPairings.toString(), disableRecording.toString(), unattendedTier,
            issuedMillis.toString(), expiresMillis.toString()
        ).joinToString("|")
        if (version >= 2)
            body += "|disabled:" + disabled.joinToString(",") + "|required:" + required.joinToString(",")
        return body
    }

    companion object {
        private val validRungs = setOf("lan", "hub", "mesh", "ipv6", "ownpath", "tor")
        fun verify(b: PolicyBundle, orgPublicKey: ByteArray, nowMillis: Long): Pair<Boolean, String> {
            if (b.expiresMillis <= nowMillis) return false to "policy bundle expired — refused (fail closed)"
            if (b.transportMode !in setOf("auto", "manual")) return false to "unknown transport mode — refused"
            if (b.transportMode == "manual" && b.transportCeiling.size != 1)
                return false to "manual policy must name exactly one approved rung (D10/D29) — refused"
            if (b.transportCeiling.any { it !in validRungs }) return false to "unknown rung in ceiling — refused"
            if (b.version < 2 && (b.disabled.isNotEmpty() || b.required.isNotEmpty()))
                return false to "feature toggles require policy format v2 — a v1 bundle carrying them is refused (unsigned toggles are never honored)"
            if ((b.disabled + b.required).any { it !in PolicyFeatures.ALL })
                return false to "unknown feature key in policy toggles — refused"
            if (b.disabled.intersect(b.required.toSet()).isNotEmpty())
                return false to "a feature cannot be both disabled and required by policy — refused as contradictory"
            val sig = try { Base64.getDecoder().decode(b.signatureBase64) } catch (e: Exception) { return false to "signature undecodable — refused" }
            val ok = DeviceIdentity.verify(orgPublicKey, b.canonicalBody().toByteArray(Charsets.UTF_8), sig)
            return if (ok) true to "policy bundle verified" else false to "policy bundle signature invalid — refused (fail closed)"
        }
    }
}

class PolicyEnforcer(private val bundle: PolicyBundle) {
    /** The ONE scope this enforcer's bundle governs (Block H,
     *  design 5: the wiring layer's teardown sweeps run for
     *  exactly this scope when the enforcer is installed). */
    val scopeId: String get() = bundle.scopeId
    fun checkUpdate(candidateVersion: String, nowMillis: Long): Pair<Boolean, String> {
        bundle.pinnedVersion?.let { pin ->
            if (pin != candidateVersion) return false to "update to $candidateVersion refused: policy pins version $pin (DIR-22)"
        }
        bundle.updateDeferUntilMillis?.let { until ->
            if (nowMillis < until) return false to "update to $candidateVersion refused: updates deferred by policy (DIR-22)"
        }
        return true to "update permitted by policy"
    }
    fun checkTransport(rung: String): Pair<Boolean, String> =
        if (rung in bundle.transportCeiling) true to "rung within policy ceiling"
        else false to "rung '$rung' is outside the policy ceiling — refused (D10)"
    fun checkAiPairing(): Pair<Boolean, String> =
        if (bundle.forbidAiPairings) false to "AI pairings are forbidden in this scope by policy (DIR-65)"
        else true to "AI pairing permitted by policy"
    /** Three-state feature posture (TOTAL POLICY CONTROL):
     * "disabled" | "required" | "allowed". Unknown keys read
     * "disabled" — policy never silently allows an unknown feature. */
    fun featureState(featureKey: String): String {
        val key = featureKey.trim().lowercase()
        if (key !in PolicyFeatures.ALL) return "disabled"
        if (key in bundle.disabled) return "disabled"
        if (key in bundle.required) return "required"
        return "allowed"
    }
    fun checkFeature(featureKey: String): Pair<Boolean, String> {
        val key = featureKey.trim().lowercase()
        if (key !in PolicyFeatures.ALL) return false to "unknown feature key '$featureKey' — refused (fail closed)"
        return if (key in bundle.disabled)
            false to "feature '$key' is disabled by policy for this scope (TOTAL POLICY CONTROL)"
        else true to "feature '$key' permitted by policy"
    }
    fun featureRequired(featureKey: String): Boolean {
        val key = featureKey.trim().lowercase()
        return key in PolicyFeatures.ALL && key in bundle.required
    }
    /** SCOPE-AWARE feature check (D38-G review F2): the bundle
     *  governs ONLY its own scope; any other scope reads the
     *  no-bundle posture, never this scope's rules. */
    fun checkFeature(scopeId: String, featureKey: String): Pair<Boolean, String> =
        if (!bundle.scopeId.equals(scopeId, ignoreCase = true))
            true to "no policy bundle loaded for this scope — feature not policy-gated"
        else checkFeature(featureKey)
    /** SCOPE-AWARE required check (D38-G review F2). */
    fun featureRequired(scopeId: String, featureKey: String): Boolean =
        bundle.scopeId.equals(scopeId, ignoreCase = true) && featureRequired(featureKey)
}

// ---- SCAM friction (model layer) ----

data class OperatorHistory(
    val completedCleanSessions: Int, val stoppedSessions: Int, val sensitiveContextTriggers: Int,
    val lastStopMillis: Long?, val markedKnownTrustedLocally: Boolean
)

data class FrictionDecision(
    val level: String, val startsViewOnly: Boolean, val secondConsentRequired: Boolean,
    val secondConsentEarliestSeconds: Int, val warningRequired: Boolean, val presenceLabel: String, val reason: String
)

object ScamFriction {
    private val impersonationTerms = listOf(
        "microsoft", "apple", "support", "fraud department", "irs", "fbi", "police", "bank", "amazon", "paypal", "tech support"
    )
    /** bd-and-rmm F12 fix: terms match on WORD BOUNDARIES — the
     *  old substring match flagged 'irs' inside "First"/"Kirsten"
     *  (and 'bank' inside any longer word). Multi-word terms
     *  ("fraud department", "tech support") match as phrases with
     *  boundaries at both ends. */
    fun hasImpersonationTerm(name: String?): Boolean {
        if (name == null) return false
        val lower = name.lowercase()
        return impersonationTerms.any { term ->
            Regex("(?<![a-z])" + Regex.escape(term) + "(?![a-z])").containsMatchIn(lower)
        }
    }

    fun isEstablished(h: OperatorHistory): Boolean =
        h.completedCleanSessions >= 3 && h.stoppedSessions == 0 && h.sensitiveContextTriggers == 0

    fun evaluate(operatorKey: String, displayName: String?, h: OperatorHistory, installFirstRunMillis: Long?, nowMillis: Long, callActive: Boolean): FrictionDecision {
        val freshInstall = installFirstRunMillis != null && nowMillis - installFirstRunMillis < 24L * 3600 * 1000
        val inCooldown = h.lastStopMillis != null && nowMillis - h.lastStopMillis < 30L * 60 * 1000
        val impersonation = hasImpersonationTerm(displayName) && !h.markedKnownTrustedLocally
        // bd-and-rmm F12 fix: an active voice call is itself a
        // scam-context signal (SCAM-14) — the old fast path skipped
        // it entirely for established operators, so "your established
        // helper, mid-call, first contact after reinstall" sailed
        // through. callActive now blocks the fast path for everyone.
        val established = isEstablished(h) && !freshInstall && !inCooldown && !impersonation && !callActive
        val label = if (established) (displayName ?: operatorKey)
            else "Unverified helper calling themselves '${displayName ?: operatorKey}'"
        if (established) return FrictionDecision("established", false, false, 0, false, label, "earned fast path (SCAM-15)")
        val reasons = mutableListOf<String>()
        if (h.completedCleanSessions == 0) reasons.add("first session from this operator (SCAM-01)")
        if (freshInstall) reasons.add("fresh install within 24h (SCAM-13)")
        if (inCooldown) reasons.add("cooldown after a stopped session (SCAM-08)")
        if (impersonation) reasons.add("impersonation-term display name (SCAM-05)")
        if (callActive) reasons.add("voice call active during first-contact request (SCAM-14 model)")
        if (h.sensitiveContextTriggers > 0) reasons.add("repeat sensitive-context trigger (SCAM-22)")
        return FrictionDecision("high_friction", true, true, 60, true, label, reasons.joinToString("; "))
    }

    fun sensitiveContextPauses(foregroundContext: String, h: OperatorHistory): Boolean =
        !isEstablished(h) && foregroundContext in setOf("banking", "password_field", "password_manager", "otp_prompt")
}

// ---- HELP-09 / SCAM-18 session-end receipt ----

object SessionReceipt {
    fun generate(
        operatorName: String, startedText: String, endedText: String, durationMinutes: Int,
        controlMinutes: Int, viewingMinutes: Int, filesCopied: List<String>,
        programsOpened: List<String>, wasRecorded: Boolean, endReason: String
    ): String = listOf(
        "$operatorName connected at $startedText and finished at $endedText ($durationMinutes minutes).",
        "$operatorName controlled this device for $controlMinutes minutes and watched for $viewingMinutes minutes.",
        if (filesCopied.isNotEmpty()) "Files copied to $operatorName: ${filesCopied.joinToString(", ")}."
        else "No files were copied.",
        if (programsOpened.isNotEmpty()) "Programs opened: ${programsOpened.joinToString(", ")}."
        else "No programs were opened.",
        if (wasRecorded) "This session was recorded." else "We did not record this session.",
        "How it ended: $endReason."
    ).joinToString("\n")
}
