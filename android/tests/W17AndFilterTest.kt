// Wave 17 Lane B — P1-F1 STRUCTURAL fix pins (Android).
// round-2 + W16 confirmation found the W12/W15 denylist
// still evaded by expansion-boundary joins. The fix is structural:
// expansion normalisation (removal that JOINS surrounding literal
// text) with denied-verb matching on BOTH raw and normalised
// streams, plus a verb-position expansion rule that fails closed
// on an unresolvable verb position. This suite pins:
//  - the review's exact evasion corpus, verbatim;
//  - a generated corpus: denied verbs x join techniques x split
//    positions — every generated case must refuse;
//  - the ordinary-shell floor: every W12/W15 allowed pin still
//    allowed (no pin flips were needed; see lane log).
// Pure/model layer only.
import io.deskguest.app.design.GateModel

private var failures = 0
private var passes = 0
private fun check(name: String, cond: Boolean) {
    if (cond) { passes++; println("PASS $name") } else { failures++; println("FAIL $name") }
}

fun main(args: Array<String>) {
    val own = "io.deskguest.app"
    fun refused(cmd: String) = GateModel.shellInputRefused(cmd, own)
    fun allowed(cmd: String) = !GateModel.shellInputRefused(cmd, own)

    // ============ Exact evasion corpus (W16 Part 1) ============
    check("W17 DS corpus in\${X}put tap refused", refused("in\${X}put tap 1 2"))
    check("W17 DS corpus a\${X}m force-stop own refused", refused("a\${X}m force-stop $own"))
    check("W17 DS corpus in\$(true)put tap refused", refused("in\$(true)put tap 1 2"))
    check("W17 DS corpus cmd \$SUB start-activity own refused",
        refused("cmd \$SUB start-activity $own"))
    check("W17 DS corpus cmd \$SUB start-activity own component refused",
        refused("cmd \$SUB start-activity -n $own/.MainActivity"))
    check("W17 DS corpus \$X \$Y refused (both positions expansions)", refused("\$X \$Y"))
    // B-14 named corpus extras
    check("W17 B-14 corpus cm\${X}d activity force-stop own refused",
        refused("cm\${X}d activity force-stop $own"))
    check("W17 B-14 corpus cmd act\${X}ivity force-stop own refused",
        refused("cmd act\${X}ivity force-stop $own"))
    check("W17 B-14 corpus io.deskguest\${X}.app via am refused",
        refused("am force-stop io.deskguest\${X}.app"))
    check("W17 B-14 corpus p\${X}m clear own refused", refused("p\${X}m clear $own"))
    check("W17 B-14 corpus mon\${X}key own refused", refused("mon\${X}key -p $own 10"))
    check("W17 B-14 corpus in`true`put tap refused", refused("in`true`put tap 1 2"))
    check("W17 B-14 corpus in\$(echo)put tap refused", refused("in\$(echo)put tap 1 2"))

    // ============ Verb-position expansion rule ============
    check("W17 verb-pos \$X tap refused", refused("\$X tap 1 1"))
    check("W17 verb-pos \${X} swipe refused", refused("\${X} swipe 1 2 3 4"))
    check("W17 verb-pos \$X force-stop own refused", refused("\$X force-stop $own"))
    check("W17 verb-pos cmd \$SUB tap refused (cmd slot expansion + input verb)",
        refused("cmd \$SUB tap 1 1"))
    check("W17 verb-pos am \$SUB own refused (am slot expansion + own)",
        refused("am \$SUB $own"))
    check("W17 verb-pos pm \$SUB own refused (pm slot expansion + own)",
        refused("pm \$SUB $own"))
    check("W17 verb-pos assignment-carried activity via cmd refused",
        refused("SUB=activity; cmd \$SUB start-activity $own"))

    // ============ Generated corpus: denied verbs x joins x splits ============
    val joins: List<Pair<String, (String, String) -> String>> = listOf(
        "brace-exp" to { a: String, b: String -> a + "\${X}" + b },
        "subst-true" to { a: String, b: String -> a + "\$(true)" + b },
        "subst-echo" to { a: String, b: String -> a + "\$(echo)" + b },
        "backtick" to { a: String, b: String -> a + "`true`" + b },
        "dquote" to { a: String, b: String -> a + "\"" + b + "\"" },
        "squote" to { a: String, b: String -> a + "'" + b + "'" },
        "backslash" to { a: String, b: String -> a + "\\" + b },
        "mixed-exp-quote" to { a: String, b: String -> a + "\${X}" + "\"" + b }
    )
    // (word to split, prefix, suffix) — each builds a denied command.
    val templates: List<Triple<String, String, String>> = listOf(
        Triple("input", "", " tap 1 2"),
        Triple("am", "", " force-stop $own"),
        Triple("pm", "", " clear $own"),
        Triple("cmd", "", " activity force-stop $own"),
        Triple("activity", "cmd ", " force-stop $own"),
        Triple("monkey", "", " -p $own 10")
    )
    var generated = 0
    var generatedRefused = 0
    val generatedEscapes = mutableListOf<String>()
    for ((word, prefix, suffix) in templates) {
        for (split in 1 until word.length) {
            val a = word.substring(0, split)
            val b = word.substring(split)
            for ((joinName, join) in joins) {
                val cmd = prefix + join(a, b) + suffix
                generated++
                if (refused(cmd)) generatedRefused++ else generatedEscapes += "$joinName: $cmd"
            }
        }
    }
    // Generated verb-position corpus: unresolvable command words x
    // literal input verbs.
    val expWords = listOf("\$X", "\${X}", "\$V", "\${CMD2}")
    val inputVerbArgs = listOf("tap 1 2", "swipe 1 2 3 4", "text hi", "keyevent 66")
    for (w in expWords) {
        for (v in inputVerbArgs) {
            val cmd = "$w $v"
            generated++
            if (refused(cmd)) generatedRefused++ else generatedEscapes += "verb-pos: $cmd"
        }
    }
    println("W17 generated corpus: $generated cases, $generatedRefused refused")
    for (e in generatedEscapes) println("FAIL W17 generated escape $e")
    check("W17 generated corpus all refuse ($generated cases)", generatedEscapes.isEmpty() && generated == generatedRefused)

    // ============ Ordinary-shell floor (W12/W15 pins, unchanged) ============
    check("W17 floor settings/dumpsys/pm-list/am-other still allowed",
        allowed("settings get global device_name") &&
            allowed("dumpsys battery") &&
            allowed("pm list packages") &&
            allowed("am start -n com.other/.Main") &&
            allowed("logcat -d"))
    check("W17 floor cmd forms naming another package still allowed",
        allowed("cmd activity start -n com.other/.Main") &&
            allowed("cmd package path com.other") &&
            allowed("cmd package list packages") &&
            allowed("cmd activity top") &&
            allowed("cmd statusbar expand"))
    check("W17 floor ordinary expansions in argument position still allowed",
        allowed("echo \$HOME") &&
            allowed("ls \${HOME}/docs") &&
            allowed("echo \$PATH") &&
            allowed("echo \$FOO") &&
            allowed("FOO=bar; echo \$FOO"))
    check("W17 floor benign literal command path still allowed (\$HOME/bin/tool)",
        allowed("\$HOME/bin/tool run"))
    check("W17 floor ordinary substitution in argument position still allowed",
        allowed("echo \$(date)") && allowed("echo \$((1+2))") && allowed("echo `date`"))

    // ============ Prior-wave shell pins (spot re-pin of the classes) ============
    check("W17 regression W12/W15 shell pins still refuse",
        refused("/system/bin/input tap 1 1") &&
            refused("sh -c 'input tap 1 1'") &&
            refused("input -d 0 tap 1 1") &&
            refused("pm clear $own") &&
            refused("am force-stop $own") &&
            refused("cmd activity force-stop $own") &&
            refused("cmd input tap 1 1") &&
            refused("V=input; \$V tap 1 1") &&
            refused("in\"put\" tap 1 1") &&
            refused("in\\put tap 1 1") &&
            refused("`\$X tap 1 1`") &&
            refused("echo \$(input tap 1 1)"))

    println("W17AndFilterTest: $passes PASS / $failures FAIL")
    if (failures > 0) kotlin.system.exitProcess(1)
}
