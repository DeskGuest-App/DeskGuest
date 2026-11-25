import io.agenticcontrol.app.server.AccessControl
import io.agenticcontrol.app.server.PairingStore
import java.io.File
import java.nio.file.Files

/**
 * W89 / S08 Android parity pins: the 5-stop ladder over Android's
 * real scope set, Custom classification, preview diff accuracy,
 * elevation default-refused at the store, and audit-on-change —
 * the Android mirror of the Windows W79 AccessControl pins.
 */
private var failures = 0

private fun check(name: String, condition: Boolean) {
    if (condition) println("PASS  $name") else { println("FAIL  $name"); failures++ }
}

fun main(args: Array<String>) {
    val ac = AccessControl

    // ---- Stop-set mapping (over Android's real scopes) ----
    check("stops: exactly five, signed names in order",
        ac.STOPS.map { it.name } == listOf(
            "No access", "Watch only", "Suggest first", "Ask before acting", "Full help"))
    check("stop 0 No access = {}",
        ac.STOPS[0].grants == emptySet<String>())
    check("stop 1 Watch only = observe preset verbatim",
        ac.STOPS[1].grants == setOf("observe"))
    check("stop 2 Suggest first = {observe, drive}",
        ac.STOPS[2].grants == setOf("observe", "drive"))
    check("stop 3 Ask before acting = {observe, drive, shell}",
        ac.STOPS[3].grants == setOf("observe", "drive", "shell"))
    check("stop 4 Full help = full preset verbatim (ALL_SCOPES)",
        ac.STOPS[4].grants == PairingStore.ALL_SCOPES &&
            ac.STOPS[4].grants == setOf("observe", "drive", "shell", "admin"))
    check("stops are cumulative and distinct",
        (0 until 4).all { ac.STOPS[it].grants.size < ac.STOPS[it + 1].grants.size &&
            ac.STOPS[it + 1].grants.containsAll(ac.STOPS[it].grants) })
    check("fine-tune carries exactly Android's four real scopes (no Windows-only classes)",
        ac.CAPABILITIES.map { it.scope } == listOf("observe", "drive", "shell", "admin"))
    check("elevation capability is admin, flagged, and last",
        ac.CAPABILITIES.last().scope == "admin" && ac.CAPABILITIES.last().isElevation &&
            ac.CAPABILITIES.dropLast(1).none { it.isElevation })

    // ---- Custom classification ----
    check("classify: every stop set classifies to its own index",
        ac.STOPS.indices.all { ac.classify(ac.STOPS[it].grants) == it })
    check("classify: non-cumulative ladder subset {observe, shell} is Custom",
        ac.classify(setOf("observe", "shell")) == -1 && ac.isCustom(setOf("observe", "shell")))
    check("classify: {drive} alone is Custom",
        ac.classify(setOf("drive")) == -1)
    check("classify: {admin} alone is Custom",
        ac.classify(setOf("admin")) == -1)
    check("classify: a set holding an unknown scope is Custom, never rounded",
        ac.classify(setOf("observe", "drive", "terminal")) == -1)
    check("classifyName: stop names and Custom",
        ac.classifyName(setOf("observe")) == "Watch only" &&
            ac.classifyName(setOf("observe", "shell")) == "Custom")

    // ---- Preview diff accuracy ----
    val d1 = ac.diff(setOf("observe", "drive", "shell", "admin"), setOf("observe"))
    check("diff: Full help -> Watch only names exactly drive, shell, admin removed, in panel order",
        d1.map { it.capability.scope } == listOf("drive", "shell", "admin") && d1.all { !it.added })
    val d2 = ac.diff(setOf("observe"), setOf("observe", "drive", "shell"))
    check("diff: Watch only -> Ask before acting names exactly drive, shell added",
        d2.map { it.capability.scope } == listOf("drive", "shell") && d2.all { it.added })
    check("diff: identical sets diff empty",
        ac.diff(setOf("observe", "drive"), setOf("drive", "observe")).isEmpty())
    check("diff: empty -> empty diffs empty",
        ac.diff(emptySet(), emptySet()).isEmpty())
    val d3 = ac.diff(setOf("observe", "mystery"), setOf("observe"))
    check("diff: unknown current scope is named as a removal, never dropped silently",
        d3.size == 1 && d3[0].capability.scope == "mystery" && !d3[0].added)
    check("diff labels are the capability labels the panel shows",
        ac.diff(emptySet(), setOf("shell")).single().capability.label == "Run commands")

    // ---- Elevation: default refused at the model ----
    check("addsElevation: adding admin detected; removing or holding it is not an add",
        ac.addsElevation(setOf("observe"), setOf("observe", "admin")) &&
            !ac.addsElevation(setOf("observe", "admin"), setOf("observe")) &&
            !ac.addsElevation(setOf("admin"), setOf("admin", "observe")))
    check("validate: adding admin without confirmation is refused (default refused)",
        ac.validateProposal(setOf("observe"), setOf("observe", "admin"), false) != null)
    check("validate: adding admin WITH the owner's confirmation passes",
        ac.validateProposal(setOf("observe"), setOf("observe", "admin"), true) == null)
    check("validate: removing admin never needs confirmation",
        ac.validateProposal(setOf("observe", "admin"), setOf("observe"), false) == null)
    check("validate: unknown grant refused even with confirmation",
        ac.validateProposal(emptySet(), setOf("terminal"), true) != null)
    check("validate: Full help from Watch only needs confirmation (admin rides the preset)",
        ac.validateProposal(setOf("observe"), PairingStore.ALL_SCOPES, false) != null &&
            ac.validateProposal(setOf("observe"), PairingStore.ALL_SCOPES, true) == null)

    // ---- Caps derivation matches the existing presets ----
    check("capsForScopes: observe preset parity (caps {see})",
        ac.capsForScopes(setOf("observe")) == PairingStore.OBSERVE_CAPS)
    check("capsForScopes: full preset parity (all caps)",
        ac.capsForScopes(PairingStore.ALL_SCOPES) == PairingStore.ALL_CAPS)
    check("capsForScopes: no access = no caps; drive = the drive caps",
        ac.capsForScopes(emptySet()).isEmpty() &&
            ac.capsForScopes(setOf("observe", "drive")) ==
            setOf("see", "tap", "type", "apps"))
    check("accessLabelForScopes: full / observe floor / custom",
        ac.accessLabelForScopes(PairingStore.ALL_SCOPES) == PairingStore.ACCESS_FULL &&
            ac.accessLabelForScopes(emptySet()) == PairingStore.ACCESS_OBSERVE &&
            ac.accessLabelForScopes(setOf("observe")) == PairingStore.ACCESS_OBSERVE &&
            ac.accessLabelForScopes(setOf("observe", "drive")) == PairingStore.ACCESS_CUSTOM)

    // ---- Store: updateScopes apply, refusal, and audit-on-change ----
    val dir = Files.createTempDirectory("acp-w89-test").toFile()
    val file = File(dir, "pairings.tsv")
    val store = PairingStore(file)
    val audits = mutableListOf<Triple<String, Boolean, String>>()
    store.onAccessAudit = { name, ok, detail -> audits.add(Triple(name, ok, detail)) }
    val code = store.beginPairing("W89 Agent")
    val pairing = store.redeem(code, setOf("observe"))!!
    check("fresh pairing starts at Watch only",
        ac.classify(pairing.scopes) == 1 && pairing.scopes == setOf("observe"))

    // Elevation refused at the store without confirmation: state untouched, refusal audited.
    val refused = store.updateScopes(pairing.token, PairingStore.ALL_SCOPES, elevationConfirmed = false)
    check("store: Full help without elevation confirmation is refused",
        refused.pairing == null && refused.refusal != null)
    check("store: refusal leaves the grant state untouched",
        store.pairingForToken(pairing.token)?.scopes == setOf("observe"))
    check("store: the refusal itself is audited (ok=false, reason named)",
        audits.any { !it.second && it.third.contains("admin") })

    // With the owner's confirmation: applied, caps derived, audited old -> new.
    val applied = store.updateScopes(pairing.token, PairingStore.ALL_SCOPES, elevationConfirmed = true)
    check("store: Full help with confirmation applies",
        applied.pairing?.scopes == PairingStore.ALL_SCOPES &&
            applied.pairing?.caps == PairingStore.ALL_CAPS &&
            applied.pairing?.access == PairingStore.ACCESS_FULL)
    check("store: the apply is audited with old -> new scope sets named",
        audits.any { it.second && it.third.contains("observe") && it.third.contains("admin") })

    // A ladder stop applies without any confirmation (no elevation involved).
    val stop2 = store.updateScopes(pairing.token, setOf("observe", "drive"), elevationConfirmed = false)
    check("store: removing admin + landing on Suggest first needs no confirmation",
        stop2.pairing?.scopes == setOf("observe", "drive") &&
            ac.classify(stop2.pairing!!.scopes) == 2 &&
            stop2.pairing?.caps == setOf("see", "tap", "type", "apps"))
    check("store: that change is audited too",
        audits.count { it.second } == 2)

    // Fine-tune to a non-ladder set: classifies Custom, caps follow the scopes.
    val custom = store.updateScopes(pairing.token, setOf("observe", "shell"), elevationConfirmed = false)
    check("store: fine-tune set {observe, shell} applies and classifies Custom",
        custom.pairing != null && ac.isCustom(custom.pairing!!.scopes) &&
            custom.pairing?.access == PairingStore.ACCESS_CUSTOM &&
            custom.pairing?.caps == setOf("see", "shell"))

    // No access: stop 0 is a real, applicable state.
    val none = store.updateScopes(pairing.token, emptySet(), elevationConfirmed = false)
    check("store: No access {} applies — no caps, observe-floor label",
        none.pairing?.scopes?.isEmpty() == true && none.pairing?.caps?.isEmpty() == true)

    // Unknown scopes and unknown tokens fail closed.
    val unknown = store.updateScopes(pairing.token, setOf("observe", "backstage"), elevationConfirmed = true)
    check("store: a Windows-only scope name is refused on Android, never honored",
        unknown.pairing == null && unknown.refusal != null &&
            store.pairingForToken(pairing.token)?.scopes?.isEmpty() == true)
    val miss = store.updateScopes("deadbeef", setOf("observe"), elevationConfirmed = false)
    check("store: unknown token is a clean miss (no pairing, no refusal)",
        miss.pairing == null && miss.refusal == null)

    // Persistence: the applied state survives a reload byte-for-byte.
    store.updateScopes(pairing.token, setOf("observe", "drive", "shell"), elevationConfirmed = false)
    val reloaded = PairingStore(file)
    check("store: applied scopes/caps/access survive reload",
        reloaded.pairingForToken(pairing.token)?.let {
            it.scopes == setOf("observe", "drive", "shell") &&
                it.caps == setOf("see", "tap", "type", "apps", "shell") &&
                ac.classify(it.scopes) == 3
        } == true)

    // The legacy setAccess path audits its changes too.
    val auditsBefore = audits.size
    store.setAccess(pairing.token, "observe", emptySet())
    check("store: legacy setAccess change is audited (every change, any surface)",
        audits.size == auditsBefore + 1 && audits.last().second)

    // Source pins: the surface is wired as built, not just modelled.
    val root = args.getOrElse(0) { "." }
    val uikit = File(root, "app/src/main/java/io/agenticcontrol/app/ui/UiKit.kt").readText()
    val main = File(root, "app/src/main/java/io/agenticcontrol/app/MainActivity.kt").readText()
    val wizard = File(root, "app/src/main/java/io/agenticcontrol/app/WizardActivity.kt").readText()
    val service = File(root, "app/src/main/java/io/agenticcontrol/app/server/ControlService.kt").readText()
    check("surface: editor stages via AccessControl and applies only through the preview",
        uikit.contains("AccessControl") && uikit.contains("This changes:") &&
            uikit.contains("Apply changes"))
    check("surface: both homes (pairing card + wizard) use updateScopes",
        main.contains("updateScopes") && wizard.contains("updateScopes"))
    check("surface: audit hook wired to the AuditStore as pairing_access",
        service.contains("onAccessAudit") && service.contains("\"pairing_access\""))

    if (failures > 0) {
        println("W89: $failures FAILURES")
        kotlin.system.exitProcess(1)
    }
    println("W89: ALL CHECKS PASS")
}
