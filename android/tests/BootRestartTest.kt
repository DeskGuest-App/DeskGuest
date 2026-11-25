import io.agenticcontrol.app.server.BootRestartPolicy
import java.io.File

/**
 * C19 — Android channel self-healing: permanent JVM regression
 * tests for the boot receiver's decision logic (BootRestartPolicy,
 * pure JVM), plus manifest/source assertions that the receiver,
 * the permission, and the routing to ControlService.start are
 * actually wired in the shipped tree.
 *
 * On-device reboot proof is A5-class (named remainder channel) —
 * this suite is the proof this lane can honestly close.
 *
 * Arg 0: the android/ project dir (for manifest/source reads).
 */
private var failures = 0

private fun check(name: String, condition: Boolean) {
    if (condition) println("PASS  $name")
    else {
        println("FAIL  $name")
        failures++
    }
}

private fun facts(
    settingEnabled: Boolean = true,
    action: String? = BootRestartPolicy.ACTION_BOOT_COMPLETED,
    hasOpenedAppBefore: Boolean = true,
    sdkInt: Int = 35,
    batteryOptimizationExempt: Boolean = false,
    systemAlertWindowGranted: Boolean = false
) = BootRestartPolicy.Facts(
    settingEnabled, action, hasOpenedAppBefore, sdkInt,
    batteryOptimizationExempt, systemAlertWindowGranted
)

fun main(args: Array<String>) {
    val root = File(args.getOrElse(0) { "." })
    val d = BootRestartPolicy.Decision.values()
    fun decide(f: BootRestartPolicy.Facts) = BootRestartPolicy.decide(f)

    // ---- the decision table ----
    check("setting default is ON", BootRestartPolicy.DEFAULT_ENABLED)
    check(
        "boot + setting on + opened before -> START",
        decide(facts()) == BootRestartPolicy.Decision.START_CHANNEL
    )
    check(
        "setting OFF -> receiver no-ops",
        decide(facts(settingEnabled = false)) == BootRestartPolicy.Decision.SKIP_SETTING_OFF
    )
    check(
        "never opened -> no silent start",
        decide(facts(hasOpenedAppBefore = false)) == BootRestartPolicy.Decision.SKIP_NEVER_OPENED
    )
    check(
        "wrong action -> ignored",
        decide(facts(action = "android.intent.action.MY_PACKAGE_REPLACED")) ==
            BootRestartPolicy.Decision.SKIP_WRONG_ACTION
    )
    check(
        "null action -> ignored",
        decide(facts(action = null)) == BootRestartPolicy.Decision.SKIP_WRONG_ACTION
    )
    check(
        "wrong action outranks setting-off (no spurious skip record)",
        decide(facts(action = "x", settingEnabled = false)) ==
            BootRestartPolicy.Decision.SKIP_WRONG_ACTION
    )
    check(
        "setting-off outranks never-opened",
        decide(facts(settingEnabled = false, hasOpenedAppBefore = false)) ==
            BootRestartPolicy.Decision.SKIP_SETTING_OFF
    )

    // ---- Android 12+ honesty: the boot broadcast is itself a
    // named exemption, so SDK level and the extra exemption legs
    // must NOT gate the attempt (they are context, not gates) ----
    for (sdk in listOf(30, 31, 34, 35, 36)) {
        check(
            "sdk $sdk without extra exemptions still STARTs on boot",
            decide(facts(sdkInt = sdk)) == BootRestartPolicy.Decision.START_CHANNEL
        )
        check(
            "sdk $sdk with battery exemption STARTs",
            decide(facts(sdkInt = sdk, batteryOptimizationExempt = true)) ==
                BootRestartPolicy.Decision.START_CHANNEL
        )
        check(
            "sdk $sdk with overlay exemption STARTs",
            decide(facts(sdkInt = sdk, systemAlertWindowGranted = true)) ==
                BootRestartPolicy.Decision.START_CHANNEL
        )
    }

    // ---- failure classification: a platform refusal is a named
    // state, not a crash and not a silent success ----
    check(
        "ForegroundServiceStartNotAllowedException -> platform refusal",
        BootRestartPolicy.classifyFailure("android.app.ForegroundServiceStartNotAllowedException") ==
            BootRestartPolicy.Outcome.REFUSED_BY_PLATFORM
    )
    check(
        "IllegalStateException -> platform refusal",
        BootRestartPolicy.classifyFailure("java.lang.IllegalStateException") ==
            BootRestartPolicy.Outcome.REFUSED_BY_PLATFORM
    )
    check(
        "other failures stay generic",
        BootRestartPolicy.classifyFailure("java.lang.SecurityException") ==
            BootRestartPolicy.Outcome.FAILED_OTHER
    )
    check(
        "null failure name stays generic",
        BootRestartPolicy.classifyFailure(null) == BootRestartPolicy.Outcome.FAILED_OTHER
    )

    // ---- breadcrumbs: every decision and outcome has its own
    // distinct on-disk tag, so the next app open can show what
    // the boot attempt actually did ----
    val decisionTags = d.map { BootRestartPolicy.breadcrumbFor(it) }
    check("decision breadcrumb tags are distinct", decisionTags.toSet().size == d.size)
    check("decision tags are boot_-prefixed", decisionTags.all { it.startsWith("boot_restart_") })
    val outcomeTags = BootRestartPolicy.Outcome.values().map { BootRestartPolicy.breadcrumbFor(it) }
    check(
        "outcome breadcrumb tags are distinct",
        outcomeTags.toSet().size == BootRestartPolicy.Outcome.values().size
    )
    check(
        "started outcome is named as a request, never as running",
        BootRestartPolicy.breadcrumbFor(BootRestartPolicy.Outcome.START_REQUESTED) ==
            "boot_restart_start_requested"
    )
    check(
        "attempt note always carries the boot exemption leg",
        BootRestartPolicy.attemptNote(facts()).contains("boot")
    )
    check(
        "attempt note records the battery leg when held",
        BootRestartPolicy.attemptNote(facts(batteryOptimizationExempt = true)).contains("battery_exempt")
    )
    check(
        "attempt note records the overlay leg when held",
        BootRestartPolicy.attemptNote(facts(systemAlertWindowGranted = true)).contains("overlay")
    )
    check(
        "attempt note omits legs not held",
        !BootRestartPolicy.attemptNote(facts()).contains("battery_exempt") &&
            !BootRestartPolicy.attemptNote(facts()).contains("overlay")
    )

    // ---- manifest wiring (the shipped declaration) ----
    val manifest = File(root, "app/src/main/AndroidManifest.xml").readText()
    check(
        "manifest holds RECEIVE_BOOT_COMPLETED",
        manifest.contains("android.permission.RECEIVE_BOOT_COMPLETED")
    )
    check("manifest declares the boot receiver", manifest.contains(".server.BootReceiver"))
    check(
        "receiver listens for BOOT_COMPLETED",
        manifest.contains("android.intent.action.BOOT_COMPLETED")
    )
    val receiverBlock = manifest.substringAfter(".server.BootReceiver")
        .substringBefore("</receiver>")
    check("receiver is not exported", receiverBlock.contains("android:exported=\"false\""))
    check(
        "no LOCKED_BOOT_COMPLETED leg (storage is credential-protected pre-unlock)",
        !manifest.contains("<action android:name=\"android.intent.action.LOCKED_BOOT_COMPLETED\"")
    )

    // ---- source wiring: the receiver routes through the policy
    // to the existing guarded start, and the boot path carries
    // no Keystore work (0.4.3 lesson) ----
    val serverDir = File(root, "app/src/main/java/io/agenticcontrol/app/server")
    val receiverSrc = File(serverDir, "BootReceiver.kt").readText()
    check("receiver consults the policy", receiverSrc.contains("BootRestartPolicy.decide"))
    check("receiver routes to ControlService.start", receiverSrc.contains("ControlService.start"))
    check(
        "receiver records its decision on the breadcrumb",
        receiverSrc.contains("Breadcrumb.mark")
    )
    // Usage identifiers only — the word "Keystore" appears in
    // these files' comments precisely to state that none is used.
    val keystoreUsage = listOf("KeystoreKeys", "AesGcmLineCipher", "java.security.KeyStore", "SecretKey")
    check(
        "boot receiver does NO Keystore work",
        keystoreUsage.none { receiverSrc.contains(it) }
    )
    val settingsSrc = File(serverDir, "BootRestartSettings.kt").readText()
    check(
        "settings do NO Keystore work",
        keystoreUsage.none { settingsSrc.contains(it) }
    )
    check(
        "settings default comes from the policy",
        settingsSrc.contains("BootRestartPolicy.DEFAULT_ENABLED")
    )
    val policySrc = File(serverDir, "BootRestartPolicy.kt").readText()
    check(
        "policy action literal matches the platform action",
        BootRestartPolicy.ACTION_BOOT_COMPLETED == "android.intent.action.BOOT_COMPLETED" &&
            policySrc.contains("android.intent.action.BOOT_COMPLETED")
    )
    val serviceSrc = File(serverDir, "ControlService.kt").readText()
    check(
        "ControlService.start reports its outcome for the boot record",
        serviceSrc.contains("fun start(context: Context): Boolean")
    )
    val mainSrc = File(root, "app/src/main/java/io/agenticcontrol/app/MainActivity.kt").readText()
    check(
        "home screen carries the honest setting label",
        mainSrc.contains("Restart the control channel after reboot")
    )
    check(
        "opening the app records the opened-once marker",
        mainSrc.contains("BootRestartSettings.markOpened")
    )

    if (failures > 0) {
        println("BootRestartTest: $failures FAILURE(S)")
        kotlin.system.exitProcess(1)
    }
    println("BootRestartTest: ALL PASS")
}
