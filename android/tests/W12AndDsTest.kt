// Wave 12 Lane B — round-1 disposition regression pins (Android).
// Each check names the packet/finding it pins. Pure/model layer only.
import io.agenticcontrol.app.backup.BackupCrypto
import io.agenticcontrol.app.backup.BackupPolicy
import io.agenticcontrol.app.backup.BackupService
import io.agenticcontrol.app.backup.SafTree
import io.agenticcontrol.app.backup.StoreSource
import io.agenticcontrol.app.cameraview.ChainedAudit
import io.agenticcontrol.app.design.PresenceLaw
import io.agenticcontrol.app.design.GateModel
import io.agenticcontrol.app.enrollment.PairingSas
import io.agenticcontrol.app.rmm.RmmToggles
import io.agenticcontrol.app.rmmspine.ConsentFloorGuard
import io.agenticcontrol.app.rmmspine.GroupDefinition
import io.agenticcontrol.app.rmmspine.GroupRule
import io.agenticcontrol.app.rmmspine.ManagementPolicyDocument
import io.agenticcontrol.app.rmmspine.ManagementPolicyEngine
import io.agenticcontrol.app.rmmspine.PolicyLevels
import io.agenticcontrol.app.rmmspine.StaticDeviceFacts
import io.agenticcontrol.app.server.ApprovalPending
import io.agenticcontrol.app.update.UpdateGuards
import org.json.JSONObject
import java.io.File

private var failures = 0
private var passes = 0
private fun check(name: String, cond: Boolean) {
    if (cond) { passes++; println("PASS $name") } else { failures++; println("FAIL $name") }
}

private class W12MemTree : SafTree {
    val files = mutableMapOf<String, ByteArray>()
    override fun granted() = true
    override fun write(name: String, bytes: ByteArray) = true.also { files[name] = bytes.copyOf() }
    override fun read(name: String) = files[name]
}

fun main() {
    val own = "io.agenticcontrol.app"

    // ---- P1 F1 (BLOCKER): shell synthetic-input filter bypasses ----
    check("W12 P1-F1 path-prefixed input refused", GateModel.shellInputRefused("/system/bin/input tap 1 1", own))
    check("W12 P1-F1 tab-separated input refused", GateModel.shellInputRefused("input\ttap 1 1", own))
    check("W12 P1-F1 quoted sh -c input refused", GateModel.shellInputRefused("sh -c 'input tap 1 1'", own))
    check("W12 P1-F1 substitution input refused", GateModel.shellInputRefused("echo \$(input tap 1 1)", own))
    check("W12 P1-F1 flagged input refused", GateModel.shellInputRefused("input -d 0 tap 1 1", own))
    check("W12 P1-F1 unlisted verb draganddrop refused", GateModel.shellInputRefused("input draganddrop 1 2 3 4", own))
    check("W12 P1-F1 unlisted verb keycombination refused", GateModel.shellInputRefused("input keycombination 29 42", own))
    check("W12 P1-F1 pm clear own package refused", GateModel.shellInputRefused("pm clear $own", own))
    check("W12 P1-F1 pm uninstall own package refused", GateModel.shellInputRefused("pm uninstall $own", own))
    check("W12 P1-F1 am force-stop own package refused", GateModel.shellInputRefused("am force-stop $own", own))
    check("W12 P1-F1 am kill own package refused", GateModel.shellInputRefused("am kill $own", own))
    check("W12 P1-F1 monkey refused", GateModel.shellInputRefused("monkey -p $own 10", own))
    check("W12 P1-F1 ordinary shell still allowed",
        !GateModel.shellInputRefused("settings get global device_name", own) &&
            !GateModel.shellInputRefused("dumpsys battery", own) &&
            !GateModel.shellInputRefused("pm list packages", own) &&
            !GateModel.shellInputRefused("am start -n com.other/.Main", own))

    // ---- P1 F16/F17 ----
    check("W12 P1-F17 FOLD mirror name is hue-legal", PresenceLaw.hueLegalOn("BOX (mirror)"))
    val boxThrew = try { PresenceLaw.BoxModel("a", "s", "0:00", 0, alwaysDark = false); false } catch (_: IllegalArgumentException) { true }
    check("W12 P1-F16 BoxModel refuses a non-dark box", boxThrew)

    // ---- P2 F1 (BLOCKER): approval latch refcount ----
    ApprovalPending.begin(); ApprovalPending.begin()
    ApprovalPending.end()
    check("W12 P2-F1 one end() does not clear a second prompt's latch", ApprovalPending.isPending && ApprovalPending.pendingDepth() == 1)
    ApprovalPending.end()
    check("W12 P2-F1 latch clears when depth reaches zero", !ApprovalPending.isPending)
    ApprovalPending.end()
    check("W12 P2-F1 end() never drives depth negative", ApprovalPending.pendingDepth() == 0 && !ApprovalPending.isPending)

    // ---- P3 F7/F23: SAS unsigned + verbatim transcript ----
    val k1 = ByteArray(32) { it.toByte() }; val k2 = ByteArray(32) { (it * 7).toByte() }
    var sawPositive = false; var allWellFormed = true
    for (i in 0 until 40) {
        val t = "transcript-$i"
        val sas = PairingSas.compute(k1, k2, t)!!
        if (!sas.digits.matches(Regex("\\d{6}"))) allWellFormed = false
        if (sas.digits != "000000") sawPositive = true
    }
    check("W12 P3-F7 SAS digits always 6 ASCII digits, never negative", allWellFormed && sawPositive)
    check("W12 P3-F23 SAS transcript is verbatim (no trim)",
        PairingSas.compute(k1, k2, " code ")!!.display != PairingSas.compute(k1, k2, "code")!!.display)

    // ---- P7 F3/F4/F5/F6/F7/F9/F10 (Android half) ----
    check("W12 P7-F3 floor guard denies compound kill_switch", ConsentFloorGuard.isDenied("rmm.kill_switch"))
    check("W12 P7-F3 floor guard denies hyphenated kill-switch", ConsentFloorGuard.isDenied("rmm.kill-switch"))
    check("W12 P7-F3 floor guard denies audit_chain", ConsentFloorGuard.isDenied("rmm.audit_chain"))
    check("W12 P7-F3 floor guard denies underscored stop", ConsentFloorGuard.isDenied("rmm_stop_enabled"))
    check("W12 P7-F3 floor guard still allows ordinary keys", !ConsentFloorGuard.isDenied("rmm.monitoring.enabled"))
    val eng = ManagementPolicyEngine()
    check("W12 P7-F6 browser_hardening + mobile_operator have own toggles",
        eng.registry.get("rmm.browser_hardening.enabled") != null && eng.registry.get("rmm.mobile_operator.enabled") != null)
    val facts = StaticDeviceFacts("dev-1", "co", attributes = mapOf("site" to "site-one"))
    check("W12 P7-F4 attribute_contains with blank value matches nothing",
        !GroupRule("attribute_contains", "site", "").matches(facts) &&
            !GroupRule("attribute_contains", "site", null).matches(facts) &&
            GroupRule("attribute_contains", "site", "site").matches(facts))
    val eng2 = ManagementPolicyEngine()
    check("W12 P7-F5 addGroup refuses blank id and non-identical redefinition",
        !eng2.addGroup(GroupDefinition("", "x", emptyList())) &&
            eng2.addGroup(GroupDefinition("g", "G", emptyList())) &&
            !eng2.addGroup(GroupDefinition("g", "G", listOf(GroupRule("tag", null, "x")))))
    // F9/F10: org lock + revision order
    val eng3 = ManagementPolicyEngine()
    eng3.addDocument(ManagementPolicyDocument("orgdoc", PolicyLevels.ORG, "co",
        mapOf("policy.lock.clipboard.direction" to "true", "clipboard.direction" to "both"), 1))
    eng3.addDocument(ManagementPolicyDocument("devdoc", PolicyLevels.DEVICE, "dev-1",
        mapOf("clipboard.direction" to "off"), 1))
    check("W12 P7-F9 org lock makes the device-level override inert",
        eng3.computeEffective(facts).get("clipboard.direction")?.value == "both")
    val eng4 = ManagementPolicyEngine()
    eng4.addDocument(ManagementPolicyDocument("zzz-stale-name", PolicyLevels.ORG, "co", mapOf("k1" to "new"), 10))
    eng4.addDocument(ManagementPolicyDocument("aaa-old", PolicyLevels.ORG, "co", mapOf("k1" to "old"), 9))
    // same target+level: both admitted under different ids; revision sort applies within apply()
    check("W12 P7-F10 higher revision wins over later-sorting stale id",
        eng4.computeEffective(facts).get("k1")?.value == "new")

    // ---- P8 F1/F2/F5/F16/F18 ----
    BackupPolicy.enabled = true
    val stores = StoreSource { mapOf("roster.tsv" to "secret".toByteArray()) }
    val unconf = BackupService(stores, ChainedAudit(), { 1L })
    check("W12 P8-F1 unconfigured service refuses to back up (no silent plaintext)",
        unconf.backup(W12MemTree()).isFailure)
    val manOnly = BackupService(stores, ChainedAudit(), { 1L }, ByteArray(32) { 1 })
    check("W12 P8-F1 manifest-only service refuses to back up (no payload key)",
        manOnly.backup(W12MemTree()).isFailure)
    val full = BackupService(stores, ChainedAudit(), { 1L }, ByteArray(32) { 1 }, ByteArray(32) { 2 })
    val dest = W12MemTree(); val m = full.backup(dest).getOrThrow()
    check("W12 P8 configured service backs up + verifies + restores",
        full.verify(dest, m.id).isSuccess && full.restore(dest, m.id, W12MemTree()).isSuccess)
    check("W12 P8-F2 keyless service cannot verify (manifest unauthenticated)",
        BackupService(stores, ChainedAudit(), { 1L }, null, ByteArray(32) { 2 }).verify(dest, m.id).isFailure)
    check("W12 P8-F5 AAD length-prefixing separates swapped components",
        !BackupCrypto.aad("a", "b|c").contentEquals(BackupCrypto.aad("a|b", "c")))
    check("W12 P8-F18 truncated encrypted form is not 'encrypted'",
        !BackupCrypto.isEncrypted(BackupCrypto.MAGIC + ByteArray(5)))
    check("W12 P8-F16 staged APK name is always the fixed name",
        UpdateGuards.safeApkFileName("anything-else.apk") == UpdateGuards.FIXED_APK_NAME)
    BackupPolicy.enabled = false

    // ---- P1 F11/F20: chat thread file injectivity + endThread ----
    val dir = File(System.getProperty("java.io.tmpdir"), "w12chat-${System.nanoTime()}"); dir.mkdirs()
    io.agenticcontrol.app.chat.AgentChatStore.append(dir, "a:b", "agent", "one", 1L)
    io.agenticcontrol.app.chat.AgentChatStore.append(dir, "a/b", "agent", "two", 2L)
    check("W12 P1-F11 colliding sanitised ids keep separate threads",
        io.agenticcontrol.app.chat.AgentChatStore.load(dir, "a:b").size == 1 &&
            io.agenticcontrol.app.chat.AgentChatStore.load(dir, "a/b").size == 1 &&
            io.agenticcontrol.app.chat.AgentChatStore.load(dir, "a:b")[0].body == "one")
    check("W12 P1-F20 endThread reports success and the thread is gone",
        io.agenticcontrol.app.chat.AgentChatStore.endThread(dir, "a:b") &&
            !io.agenticcontrol.app.chat.AgentChatStore.threadExists(dir, "a:b") &&
            io.agenticcontrol.app.chat.AgentChatStore.threadExists(dir, "a/b"))
    dir.deleteRecursively()

    println("W12AndDsTest: $passes PASS / $failures FAIL")
    if (failures > 0) kotlin.system.exitProcess(1)
}
