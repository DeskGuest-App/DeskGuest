import io.deskguest.app.rmmspine.FeatureToggleRegistry
import io.deskguest.app.server.ClipboardPolicy

/**
 * U1 JVM tests: clipboard direction policy + sensitive-item skip,
 * the Android mirror of the Windows ClipboardPolicyTests. Direction
 * matrix, policy-key resolution, seeded sensitive strings, benign
 * pass-through, and the registry toggle.
 */
private var failures = 0

private fun check(name: String, condition: Boolean) {
    if (condition) println("PASS  $name")
    else {
        println("FAIL  $name")
        failures++
    }
}

fun main() {
    // ---------- direction matrix ----------
    val matrix = listOf(
        Triple(ClipboardPolicy.Direction.BOTH, true, true),
        Triple(ClipboardPolicy.Direction.HOST_TO_AGENT, true, false),
        Triple(ClipboardPolicy.Direction.AGENT_TO_HOST, false, true),
        Triple(ClipboardPolicy.Direction.OFF, false, false)
    )
    for ((direction, read, write) in matrix) {
        val pol = ClipboardPolicy.Resolved(direction, true)
        check("matrix $direction read=$read", pol.allowsRead == read)
        check("matrix $direction write=$write", pol.allowsWrite == write)
        check(
            "matrix $direction checkRead",
            (ClipboardPolicy.checkRead(pol, "benign text") == null) == read
        )
        check(
            "matrix $direction checkWrite",
            (ClipboardPolicy.checkWrite(pol) == null) == write
        )
        if (!read) {
            check(
                "matrix $direction read refusal names direction + key",
                ClipboardPolicy.checkRead(pol, "benign text")
                    ?.let { it.contains("clipboard_direction") && it.contains("clipboard.direction") } == true
            )
        }
    }
    check(
        "non-clipboard tools are never denied",
        ClipboardPolicy.denyReason(ClipboardPolicy.Resolved(ClipboardPolicy.Direction.OFF, true), "screenshot") == null
    )

    // ---------- policy-key resolution ----------
    val resolved = ClipboardPolicy.fromSettings(
        mapOf("clipboard.direction" to "agent_to_host", "clipboard.sensitive_skip" to "false")
    )
    check("settings: direction parsed", resolved.direction == ClipboardPolicy.Direction.AGENT_TO_HOST)
    check("settings: skip parsed", !resolved.sensitiveSkip)
    val malformed = ClipboardPolicy.fromSettings(
        mapOf("clipboard.direction" to "sideways", "clipboard.sensitive_skip" to "sometimes")
    )
    check("settings: malformed values ignored, defaults stand", malformed == ClipboardPolicy.DEFAULT)
    check("settings: unset = defaults", ClipboardPolicy.fromSettings(emptyMap()) == ClipboardPolicy.DEFAULT)

    // ---------- sensitive-item skip (seeded strings) ----------
    check(
        "sensitive: password assignment is credential_secret",
        ClipboardPolicy.Sensitive.classifierFor("password = hunter2hunter2") == "credential_secret"
    )
    check(
        "sensitive: AWS key id is credential_secret",
        ClipboardPolicy.Sensitive.classifierFor("AKIAIOSFODNN7EXAMPLE") == "credential_secret"
    )
    check(
        "sensitive: Luhn-valid card is payment_card",
        ClipboardPolicy.Sensitive.classifierFor("card 4111 1111 1111 1111 exp 12/29") == "payment_card"
    )
    check(
        "sensitive: valid SSN shape is national_id",
        ClipboardPolicy.Sensitive.classifierFor("ssn 219-09-9998") == "national_id"
    )
    check(
        "sensitive: circulated sample SSN is NOT a finding",
        ClipboardPolicy.Sensitive.classifierFor("ssn 219-09-9999") == null
    )
    check(
        "sensitive: Luhn-invalid digit run is NOT a finding",
        ClipboardPolicy.Sensitive.classifierFor("order 4111 1111 1111 1112 shipped") == null
    )
    check(
        "sensitive: benign text is clean",
        ClipboardPolicy.Sensitive.classifierFor("meeting notes for Tuesday — bring the Q3 figures") == null
    )
    val refusal = ClipboardPolicy.checkRead(ClipboardPolicy.DEFAULT, "password = hunter2hunter2")
    check(
        "sensitive: read refused by class, content never echoed",
        refusal != null && refusal.contains("clipboard_sensitive") &&
            refusal.contains("credential_secret") && !refusal.contains("hunter2hunter2")
    )
    check(
        "sensitive: skip disabled by policy lets text through",
        ClipboardPolicy.checkRead(
            ClipboardPolicy.Resolved(ClipboardPolicy.Direction.BOTH, false),
            "password = hunter2hunter2"
        ) == null
    )
    val offRefusal = ClipboardPolicy.checkRead(
        ClipboardPolicy.Resolved(ClipboardPolicy.Direction.OFF, true),
        "password = hunter2hunter2"
    )
    check(
        "sensitive: direction denial outranks the classifier",
        offRefusal != null && offRefusal.contains("clipboard_direction") &&
            !offRefusal.contains("credential_secret")
    )

    // ---------- registry toggle ----------
    val toggle = FeatureToggleRegistry.seeded().get("rmm.clipboard_policy.enabled")
    check("registry: U1 toggle registered, default ON", toggle != null && toggle.defaultEnabled)

    // ---------- provider seam ----------
    val saved = ClipboardPolicy.provider
    try {
        ClipboardPolicy.provider = { null }
        check("provider: null = layer off (legacy behaviour)", ClipboardPolicy.current() == null)
        ClipboardPolicy.provider = { ClipboardPolicy.Resolved(ClipboardPolicy.Direction.OFF, true) }
        check("provider: resolved policy flows through", ClipboardPolicy.current()?.direction == ClipboardPolicy.Direction.OFF)
    } finally {
        ClipboardPolicy.provider = saved
    }

    println(if (failures == 0) "ALL PASS" else "$failures FAILURES")
    if (failures > 0) kotlin.system.exitProcess(1)
}
