package io.agenticcontrol.app.server

/**
 * U1 — Clipboard transfer direction policy + sensitive-item skip +
 * per-read indicator, Android mirror of the Windows ClipboardPolicy
 * (Acp.Shared/Policy/ClipboardPolicy.cs). Same keys, same direction
 * names, same defaults, same refusal shapes:
 *
 *  * DIRECTION is a TOTAL POLICY CONTROL setting (RMM-07 pattern,
 *    same as U4's session budgets): the toggle
 *    "rmm.clipboard_policy.enabled" is registered in the Android
 *    FeatureToggleRegistry seed (Rmm07Policy.kt, default ON) and the
 *    direction itself is the plain settings key
 *    "clipboard.direction": both | host_to_agent | agent_to_host |
 *    off. Unset → both (the pre-U1 behaviour); an unparsable value
 *    is ignored (the default stands).
 *  * SENSITIVE SKIP is the plain settings key
 *    "clipboard.sensitive_skip" (default ON): clipboard_get runs
 *    the mirror of the closed built-in DLP classifier set over the
 *    clip text before returning it; on a hit the tool returns a
 *    NAMED refusal — never the content.
 *  * PLATFORM DIFFERENCE (recorded, same as U4): the Android MCP
 *    server has no live ManagementPolicyEngine instance wired into
 *    its dispatch path today, so [provider] defaults to the named
 *    code defaults; wiring a live engine only changes this one
 *    lambda. A null provider result = the layer is toggled OFF and
 *    the clipboard behaves exactly as it did before U1.
 *  * PER-READ INDICATOR: a successful read emits a "clipboard_read"
 *    SessionEvent (character count only) and sets the session
 *    intent line the presence overlay shows, so the read is visible
 *    on the phone as it happens. The consent floor is untouched:
 *    session state and the CLIPBOARD approval gate are consulted
 *    before this layer and outrank it.
 */
object ClipboardPolicy {

    enum class Direction { BOTH, HOST_TO_AGENT, AGENT_TO_HOST, OFF }

    /** The resolved policy: one direction + the skip switch. */
    data class Resolved(
        val direction: Direction = Direction.BOTH,
        val sensitiveSkip: Boolean = true
    ) {
        val allowsRead: Boolean
            get() = direction == Direction.BOTH || direction == Direction.HOST_TO_AGENT
        val allowsWrite: Boolean
            get() = direction == Direction.BOTH || direction == Direction.AGENT_TO_HOST
    }

    /** The named defaults: both directions, sensitive skip ON. */
    val DEFAULT = Resolved()

    const val FEATURE_TOGGLE = "rmm.clipboard_policy.enabled"
    const val DIRECTION_KEY = "clipboard.direction"
    const val SENSITIVE_SKIP_KEY = "clipboard.sensitive_skip"

    /** The policy seam: returns the resolved policy, or null when
     *  policy disables the clipboard layer. Default = enabled with
     *  the named defaults. */
    @Volatile
    var provider: () -> Resolved? = { DEFAULT }

    fun current(): Resolved? = provider()

    fun directionName(direction: Direction): String = when (direction) {
        Direction.BOTH -> "both"
        Direction.HOST_TO_AGENT -> "host_to_agent"
        Direction.AGENT_TO_HOST -> "agent_to_host"
        Direction.OFF -> "off"
    }

    /** Parse a settings value; null when it names no direction
     *  (the caller keeps the default). */
    fun parseDirection(raw: String?): Direction? = when (raw?.trim()?.lowercase()) {
        "both" -> Direction.BOTH
        "host_to_agent" -> Direction.HOST_TO_AGENT
        "agent_to_host" -> Direction.AGENT_TO_HOST
        "off" -> Direction.OFF
        else -> null
    }

    /** Resolve from an effective-policy settings map: each key
     *  overrides its named default; unparsable values are ignored
     *  (the default stands) — same rule as the Windows resolver. */
    fun fromSettings(settings: Map<String, String>): Resolved {
        val direction = parseDirection(settings[DIRECTION_KEY]) ?: DEFAULT.direction
        val skip = settings[SENSITIVE_SKIP_KEY]?.trim()?.toBooleanStrictOrNull() ?: DEFAULT.sensitiveSkip
        return Resolved(direction, skip)
    }

    /** The named refusal for a direction-forbidden tool, or null
     *  when the direction permits it. Identical wording to the
     *  Windows DenyReasonFor. */
    fun denyReason(resolved: Resolved, tool: String): String? = when {
        tool == "clipboard_get" && !resolved.allowsRead ->
            "clipboard_direction: policy direction is '${directionName(resolved.direction)}' — clipboard_get moves clipboard content host → agent, which this policy does not permit ($DIRECTION_KEY)"
        tool == "clipboard_set" && !resolved.allowsWrite ->
            "clipboard_direction: policy direction is '${directionName(resolved.direction)}' — clipboard_set moves clipboard content agent → host, which this policy does not permit ($DIRECTION_KEY)"
        else -> null
    }

    /** Verdict for a read of [clipText]: null = hand the text over;
     *  non-null = return this named refusal instead of the content.
     *  Direction is checked before content. */
    fun checkRead(resolved: Resolved, clipText: String): String? {
        denyReason(resolved, "clipboard_get")?.let { return it }
        if (resolved.sensitiveSkip) {
            Sensitive.classifierFor(clipText)?.let { return Sensitive.refusal(it) }
        }
        return null
    }

    /** Verdict for a write: null = proceed. */
    fun checkWrite(resolved: Resolved): String? = denyReason(resolved, "clipboard_set")

    /**
     * The sensitive-item classifier for clipboard reads: a mirror
     * of the Windows closed built-in DLP set (payment_card /
     * national_id / credential_secret), same shapes and the same
     * named limitations. Returns the first hitting classifier id,
     * or null when the text is clean.
     */
    object Sensitive {

        fun refusal(classifierId: String): String =
            "clipboard_sensitive: the clipboard holds a sensitive-class item ($classifierId) — not read; the content was not returned ($SENSITIVE_SKIP_KEY)"

        fun classifierFor(text: String?): String? {
            if (text.isNullOrEmpty()) return null
            if (isPaymentCard(text)) return "payment_card"
            if (isNationalId(text)) return "national_id"
            if (isCredentialSecret(text)) return "credential_secret"
            return null
        }

        // ---- payment_card: 13–19 digits (single space/dash
        // separators), Luhn-validated; group-range retry mirrors
        // the Windows D38 F4 rule.
        private val cardCandidate = Regex("""\d(?:[ -]?\d){12,18}""")

        private fun luhnValid(digits: String): Boolean {
            if (digits.length !in 13..19 || !digits.all { it.isDigit() }) return false
            var sum = 0
            var alt = false
            for (i in digits.length - 1 downTo 0) {
                var d = digits[i] - '0'
                if (alt) {
                    d *= 2
                    if (d > 9) d -= 9
                }
                sum += d
                alt = !alt
            }
            return sum % 10 == 0
        }

        private fun isPaymentCard(text: String): Boolean {
            for (m in cardCandidate.findAll(text)) {
                val digits = m.value.filter { it.isDigit() }
                if (luhnValid(digits)) return true
                val groups = m.value.split(' ', '-').filter { it.isNotEmpty() }
                if (groups.size < 2) continue
                var total = minOf(19, digits.length)
                while (total >= 13) {
                    for (start in groups.indices) {
                        var len = 0
                        var end = start
                        while (end < groups.size && len < total) {
                            len += groups[end].length
                            end++
                        }
                        if (len != total) continue
                        if (luhnValid(groups.subList(start, end).joinToString(""))) return true
                    }
                    total--
                }
            }
            return false
        }

        // ---- national_id: dashed US SSN shape with SSA validity
        // rules; the circulated sample numbers are never findings.
        private val ssnCandidate = Regex("""\b(\d{3})-(\d{2})-(\d{4})\b""")
        private val ssnSamples = setOf("123-45-6789", "078-05-1120", "219-09-9999")

        private fun isNationalId(text: String): Boolean {
            for (m in ssnCandidate.findAll(text)) {
                if (m.value in ssnSamples) continue
                val area = m.groupValues[1].toInt()
                if (area == 0 || area == 666 || area >= 900) continue
                if (m.groupValues[2] == "00" || m.groupValues[3] == "0000") continue
                return true
            }
            return false
        }

        // ---- credential_secret: AWS key ids, PEM headers, keyword
        // assignments (password/passwd/api_key/secret/token = 8+).
        private val awsKey = Regex("""\b(?:AKIA|ASIA)[0-9A-Z]{16}\b""")
        private val pemHeader = Regex("""-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----""")
        private val assignment = Regex(
            """\b(?:password|passwd|api[_-]?key|secret|token)\b\s*[:=]\s*["']?\S{8,}""",
            RegexOption.IGNORE_CASE
        )

        private fun isCredentialSecret(text: String): Boolean =
            awsKey.containsMatchIn(text) || pemHeader.containsMatchIn(text) ||
                assignment.containsMatchIn(text)
    }
}
