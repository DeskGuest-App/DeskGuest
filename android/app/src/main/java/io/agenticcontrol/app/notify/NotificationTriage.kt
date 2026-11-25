package io.agenticcontrol.app.notify

/**
 * Notification triage (FEATURES §9, judgement leg built
 * 2026-11-23, Wave 11 Lane B): with the owner's notification-access
 * grant, classify each active notification URGENT or ROUTINE
 * against a small, named, inspectable rule set, so an agent inside
 * a session can tell the user "this one matters" instead of
 * dumping the whole shade.
 *
 * The rules are deliberately dumb and say what they are — no
 * learned model, no hidden scoring:
 * - a missed/declined call (the system dialer and common dialers
 *   post these with "missed call" in the title/text);
 * - an alarm or timer firing;
 * - a security or verification notice (sign-in alert, 2-step
 *   verification, account security);
 * - a payment failure / fraud alert wording.
 * Everything else is ROUTINE. Each verdict carries the rule that
 * produced it, so a wrong verdict is explainable and the rule set
 * is the whole behaviour — there is nothing else to audit.
 *
 * NOT built (de-scoped in FEATURES §9): owner-authored rules
 * ("always urgent from <person>"). No owner rules UI exists in the
 * shipped surfaces; a rules layer the owner cannot see or edit
 * would be exactly the hidden behaviour this product refuses.
 * The built-in rules above are the whole shipped triage.
 *
 * Pure JVM — runs in the JVM suite.
 */
object NotificationTriage {

    enum class Urgency { URGENT, ROUTINE }

    data class Verdict(val urgency: Urgency, val rule: String)

    private val urgentRules: List<Pair<String, List<String>>> = listOf(
        "missed call" to listOf("missed call", "missed video call"),
        "alarm firing" to listOf("alarm", "timer done", "timer finished"),
        "security or verification notice" to listOf(
            "verification", "security alert", "sign-in", "sign in alert",
            "suspicious", "2-step", "two-step", "one-time passcode"
        ),
        "payment problem" to listOf(
            "payment failed", "payment declined", "fraud", "charge disputed"
        )
    )

    fun judge(entry: NotificationCache.Entry): Verdict {
        val haystack = (entry.title + " " + entry.text).lowercase()
        for ((rule, needles) in urgentRules) {
            if (needles.any { it in haystack }) {
                return Verdict(Urgency.URGENT, rule)
            }
        }
        return Verdict(Urgency.ROUTINE, "no urgent rule matched")
    }
}
