// Wave 19 Lane B — P1-F1 verb-slot LITERAL rule pins (Android).
// round-3 (W18 confirmation) evaded the W17 structural
// fix with a NON-empty expansion in the cmd verb slot:
//   X=a; cmd ${X}ctivity start-activity -n io.agenticcontrol.app/.MainActivity
// ${X} contributes the missing 'a'; empty-expansion normalisation
// yields `ctivity`, so the W17 slot branch (fail-closed only when
// the slot normalised to empty) was skipped and the shell ran
// `cmd activity …`. The W19 completion: verb slots are PURE
// LITERALS — the slot following cmd/am/pm/monkey refuses on ANY
// expansion construct in its raw token, regardless of what the
// expansion might produce and regardless of context. Argument
// positions keep the W17 posture (normalisation + the pinned
// ordinary floor). This suite pins:
//  - the review's exact string, permanently;
//  - the rule's context-freedom (other-package tails refuse too);
//  - a generated corpus: slot words x expansion placements
//    (prefix / suffix / infix, ${}, $(), backticks, quotes)
//    x slot parents — every generated case must refuse;
//  - split spellings of the slot-parent word itself;
//  - the ordinary-shell floor, unchanged (zero flips expected).
// Pure/model layer only.
import io.agenticcontrol.app.design.GateModel

private var failures = 0
private var passes = 0
private fun check(name: String, cond: Boolean) {
    if (cond) { passes++; println("PASS $name") } else { failures++; println("FAIL $name") }
}

fun main(args: Array<String>) {
    val own = "io.agenticcontrol.app"
    fun refused(cmd: String) = GateModel.shellInputRefused(cmd, own)
    fun allowed(cmd: String) = !GateModel.shellInputRefused(cmd, own)

    // ============ round-3 exact evasion (permanent pin) ============
    check("W19 DS exact X=a; cmd \${X}ctivity start-activity own refused",
        refused("X=a; cmd \${X}ctivity start-activity -n io.agenticcontrol.app/.MainActivity"))
    check("W19 DS evasion without assignment refused",
        refused("cmd \${X}ctivity start-activity -n $own/.MainActivity"))
    check("W19 DS evasion is context-free (other-package tail still refused)",
        refused("cmd \${X}ctivity start-activity -n com.other/.Main"))
    check("W19 DS evasion suffix contribution activit\${X} refused",
        refused("cmd activit\${X} start-activity -n $own/.MainActivity"))

    // ============ Verb-slot literal rule: named forms ============
    check("W19 slot \$(...) whole-slot refused",
        refused("cmd \$(echo activity) start-activity -n $own/.MainActivity"))
    check("W19 slot backtick whole-slot refused",
        refused("cmd `echo activity` start-activity -n $own/.MainActivity"))
    check("W19 slot quoted expansion refused",
        refused("cmd \"\${X}ctivity\" start-activity -n $own/.MainActivity"))
    check("W19 slot am \${X}orce-stop own refused", refused("am \${X}orce-stop $own"))
    check("W19 slot pm cl\${X}ar own refused", refused("pm cl\${X}ar $own"))
    check("W19 slot monkey expansion refused", refused("monkey \${X} -p $own 10"))
    check("W19 slot benign word with expansion still refused (cmd li\${X}st)",
        refused("cmd li\${X}st packages"))
    check("W19 assignment-carried slot X=activity; cmd \$X refused",
        refused("X=activity; cmd \$X start-activity -n $own/.MainActivity"))
    check("W19 assignment-carried slot X=activity; cmd \${X} refused",
        refused("X=activity; cmd \${X} start-activity -n $own/.MainActivity"))

    // ============ Generated corpus: slot words x placements x parents ============
    val parents = listOf("cmd", "am", "pm", "monkey")
    val slotWords = listOf("activity", "package", "input", "list", "start")
    var generated = 0
    var generatedRefused = 0
    val generatedEscapes = mutableListOf<String>()
    fun genCase(parent: String, slotTok: String) {
        val cmd = "$parent $slotTok 1 2"
        generated++
        if (refused(cmd)) generatedRefused++ else generatedEscapes += cmd
    }
    for (parent in parents) {
        for (w in slotWords) {
            // prefix placements
            genCase(parent, "\${X}$w")
            genCase(parent, "\$X$w")
            genCase(parent, "\$(true)$w")
            genCase(parent, "`true`$w")
            genCase(parent, "\"\${X}\"$w")
            // suffix placements
            genCase(parent, "$w\${X}")
            genCase(parent, "$w\$X")
            genCase(parent, "$w\$(true)")
            genCase(parent, "$w`true`")
            // infix placements at every split
            for (split in 1 until w.length) {
                val a = w.substring(0, split)
                val b = w.substring(split)
                genCase(parent, "$a\${X}$b")
                genCase(parent, "$a\$X$b")
                genCase(parent, "$a\$(echo)$b")
                genCase(parent, "$a`true`$b")
                genCase(parent, "$a\"\${X}\"$b")
            }
        }
    }
    println("W19 generated verb-slot corpus: $generated cases, $generatedRefused refused")
    for (e in generatedEscapes) println("FAIL W19 generated escape $e")
    check("W19 generated verb-slot corpus all refuse ($generated cases)",
        generatedEscapes.isEmpty() && generated == generatedRefused)

    // ============ Generated corpus: split spellings of the parent word ============
    val parentTails: List<Pair<String, String>> = listOf(
        "cmd" to " activity force-stop $own",
        "am" to " force-stop $own",
        "pm" to " clear $own"
    )
    val parentJoins: List<(String, String) -> String> = listOf(
        { a: String, b: String -> a + "\${X}" + b },
        { a: String, b: String -> a + "\$(true)" + b },
        { a: String, b: String -> a + "`true`" + b }
    )
    var genParents = 0
    var genParentsRefused = 0
    val genParentEscapes = mutableListOf<String>()
    for ((word, tail) in parentTails) {
        for (split in 1 until word.length) {
            val a = word.substring(0, split)
            val b = word.substring(split)
            for (join in parentJoins) {
                val cmd = join(a, b) + tail
                genParents++
                if (refused(cmd)) genParentsRefused++ else genParentEscapes += cmd
            }
        }
    }
    println("W19 generated parent-split corpus: $genParents cases, $genParentsRefused refused")
    for (e in genParentEscapes) println("FAIL W19 generated parent-split escape $e")
    check("W19 generated parent-split corpus all refuse ($genParents cases)",
        genParentEscapes.isEmpty() && genParents == genParentsRefused)

    // ============ Ordinary-shell floor (W12/W15/W17 pins, unchanged) ============
    check("W19 floor literal cmd/am/pm forms naming another package still allowed",
        allowed("cmd activity start -n com.other/.Main") &&
            allowed("cmd package path com.other") &&
            allowed("cmd package list packages") &&
            allowed("cmd activity top") &&
            allowed("cmd statusbar expand") &&
            allowed("pm list packages") &&
            allowed("am start -n com.other/.Main") &&
            allowed("settings get global device_name") &&
            allowed("dumpsys battery") &&
            allowed("logcat -d"))
    check("W19 floor ordinary expansions in argument position still allowed",
        allowed("echo \$HOME") &&
            allowed("ls \${HOME}/docs") &&
            allowed("echo \$PATH") &&
            allowed("echo \$FOO") &&
            allowed("FOO=bar; echo \$FOO") &&
            allowed("echo \$(date)") &&
            allowed("echo `date`"))
    check("W19 floor benign literal command path still allowed (\$HOME/bin/tool)",
        allowed("\$HOME/bin/tool run"))
    check("W19 floor argument expansion after a literal slot still allowed",
        allowed("cmd activity start -n \$PKG/.Main") &&
            allowed("am start -n \${PKG}/.Main") &&
            allowed("pm list \$FOO"))

    // ============ Prior-wave refusal pins (spot re-pin) ============
    check("W19 regression W12/W15/W17 refusals still refuse",
        refused("/system/bin/input tap 1 1") &&
            refused("input tap 1 1") &&
            refused("pm clear $own") &&
            refused("am force-stop $own") &&
            refused("cmd activity force-stop $own") &&
            refused("cmd input tap 1 1") &&
            refused("cmd \$SUB start-activity $own") &&
            refused("in\${X}put tap 1 2") &&
            refused("V=input; \$V tap 1 1") &&
            refused("\$X \$Y"))

    println("W19AndVerbTest: $passes PASS / $failures FAIL")
    if (failures > 0) kotlin.system.exitProcess(1)
}
