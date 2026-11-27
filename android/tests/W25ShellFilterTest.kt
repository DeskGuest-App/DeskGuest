// Wave 25 Lane B — P1-F1 ASSEMBLED-WORD pins (Android).
// round-5 (W23 confirmation) evaded the W22 grammar
// model inside a CASE arm: the `case` starter marked the whole
// segment unparseable, the scan skipped it, and BOTH the denied
// verb and the own package were assembled by command
// substitution at expansion time:
//   case x in x) "$(printf %s a)m" start -n
//     "io.deskguest.ap$(printf %s p)/.MainActivity";; esac
// The W25 closure is structural, in GateModel:
//  (a) an ASSEMBLED word (an expansion joined with literal
//      text, or several expansions in one word) inside an
//      unparseable segment — or an if/while/until/elif
//      CONDITION segment — refuses unconditionally; a PURE
//      word (exactly one expansion, no literal join) stays
//      allowed, so `case x in x) echo $(date);; esac` works.
//  (b) case-arm bodies after a `)` marker are re-scanned as
//      their own commands (arm context: a pure-substitution
//      command word, or any substitution in the tail of a
//      literal slot parent, refuses there).
//  (c) PROVEN HOLE outside every construct (probe, pre-fix):
//      a literal slot parent with a SUBSTITUTION-ASSEMBLED
//      tail word assembled the own package past every view —
//      `am start -n "io.deskguest.ap$(printf %s p)/…"`
//      was ALLOWED pre-W25. That shape now refuses on any
//      segment. Variable-assembled tails keep the W17 posture.
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

    // ============ round-5 exact evasion (permanent pin) ============
    check("W25 DS round-5 exact case-arm evasion refused",
        refused("case x in x) \"\$(printf %s a)m\" start -n \"io.deskguest.ap\$(printf %s p)/.MainActivity\";; esac"))

    // ============ Round-5 variants ============
    check("W25 variant backtick-assembled verb in case arm refused",
        refused("case x in x) `printf %s a`m start -n $own/.MainActivity;; esac"))
    check("W25 variant backtick-assembled verb + assembled package refused",
        refused("case x in x) \"`printf %s a`m\" start -n \"io.deskguest.ap`printf %s p`/.MainActivity\";; esac"))
    check("W25 variant brace-expansion assembled verb in case arm refused",
        refused("case x in x) a\${Y}m start -n $own/.MainActivity;; esac"))
    check("W25 variant brace-expansion assembled package, literal verb, in case arm refused",
        refused("case x in x) am start -n io.deskguest.ap\${Z}p/.MainActivity;; esac"))
    check("W25 variant nested case with round-5 arm refused",
        refused("case a in a) case b in b) \"\$(printf %s a)m\" start -n \"io.deskguest.ap\$(printf %s p)/.MainActivity\";; esac;; esac"))
    check("W25 variant assembled package with a benign verb inside a case arm refused",
        refused("case x in x) echo \"io.deskguest.ap\$(printf %s p)/.MainActivity\";; esac"))
    check("W25 variant assembled word as a harmless-looking arm argument refused (arm is unparseable)",
        refused("case x in x) echo \"\$(printf %s a)m\";; esac"))
    check("W25 variant pure-substitution command word in case arm refused (arm context)",
        refused("case x in x) \$(printf %s am) start -n $own/.MainActivity;; esac"))
    check("W25 variant pure-substitution package argument to literal am in case arm refused (arm context)",
        refused("case x in x) am start -n \$(cat /sdcard/c);; esac"))
    check("W25 variant assembled verb in a while condition refused",
        refused("while \"\$(printf %s a)m\" start -n \"io.deskguest.ap\$(printf %s p)/.MainActivity\"; do :; done"))
    check("W25 variant assembled verb in a for header refused",
        refused("for v in a\$(printf %s m); do echo \$v; done"))
    check("W25 variant assembled word in a [[ ]] test refused",
        refused("[[ \"\$(printf %s a)m\" = am ]] && echo hi"))
    check("W25 variant assembled word in a function body refused",
        refused("function f { echo \"\$(printf %s a)m\"; }"))
    check("W25 variant literal denied command in a case arm refused (arm parsing)",
        refused("case x in x) cmd \${X}ctivity start-activity -n $own/.MainActivity;; esac"))
    check("W25 variant second arm carries the evasion refused",
        refused("case x in a) echo hi;; x) \"\$(printf %s a)m\" start -n \"io.deskguest.ap\$(printf %s p)/.MainActivity\";; esac"))

    // ============ Generated corpus: assembled shapes inside case arms ============
    // Verb assembly: literal split x join technique; package literal.
    val verbJoins: List<Pair<String, (String, String) -> String>> = listOf(
        "subst" to { a: String, b: String -> "\"\$(printf %s $a)$b\"" },
        "subst-suffix" to { a: String, b: String -> "\"$a\$(printf %s $b)\"" },
        "backtick" to { a: String, b: String -> "\"`printf %s $a`$b\"" },
        "brace" to { a: String, b: String -> "$a\${Y}$b" },
        "dollar-var" to { a: String, b: String -> "$a\$Y$b" }
    )
    var genArm = 0
    val genArmEscapes = mutableListOf<String>()
    for ((jname, join) in verbJoins) {
        for (split in 1 until "am".length) {
            val cmd = "case x in x) ${join("am".substring(0, split), "am".substring(split))} start -n $own/.MainActivity;; esac"
            genArm++
            if (!refused(cmd)) genArmEscapes += "$jname/$split: $cmd"
        }
        // Package assembly with a literal denied verb.
        val pkg = "io.deskguest.ap"
        for (split in listOf(2, 10, pkg.length - 1)) {
            val joined = join(pkg.substring(0, split), pkg.substring(split))
            val cmd = "case x in x) am start -n $joined/.MainActivity;; esac"
            genArm++
            if (!refused(cmd)) genArmEscapes += "$jname/pkg$split: $cmd"
        }
    }
    println("W25 generated case-arm corpus: $genArm cases, ${genArm - genArmEscapes.size} refused")
    for (e in genArmEscapes) println("FAIL W25 generated case-arm escape $e")
    check("W25 generated case-arm corpus all refuse ($genArm cases)", genArmEscapes.isEmpty())

    // ============ Item-3 extension: substitution-assembled tail, outside any construct ============
    // Each of these was probed ALLOWED on the pre-W25 code.
    check("W25 outside am + substitution-assembled package refused (probe-proven hole)",
        refused("am start -n \"io.deskguest.ap\$(printf %s p)/.MainActivity\""))
    check("W25 outside pm + substitution-assembled package refused (probe-proven hole)",
        refused("pm clear \"io.deskguest.ap\$(printf %s p)\""))
    check("W25 outside cmd activity + substitution-assembled package refused (probe-proven hole)",
        refused("cmd activity start -n \"io.deskguest.ap\$(printf %s p)/.MainActivity\""))
    check("W25 outside backtick-assembled package refused",
        refused("am start -n \"io.deskguest.ap`printf %s p`/.MainActivity\""))
    check("W25 outside multi-substitution package (no literal join) refused",
        refused("am start -n \"\$(printf %s io.deskguest.ap)\$(printf %s p)/.MainActivity\""))

    // ============ Benign controls: pure words and ordinary shell stay allowed ============
    check("W25 benign pure-substitution arm argument allowed (brief's control)",
        allowed("case x in x) echo \$(date);; esac"))
    check("W25 benign pure backtick arm argument allowed",
        allowed("case x in x) echo `date`;; esac"))
    check("W25 benign pure variable arm subject + argument allowed",
        allowed("case \$X in a) echo \$HOME;; esac"))
    check("W25 benign literal arm commands allowed",
        allowed("case x in x) echo hi;; esac") &&
            allowed("case x in x) dumpsys battery;; esac"))
    // NOT a W25 flip: a literal cmd/pm word inside a case arm
    // already refused pre-W25 under the W22 sensitive-context
    // starter boundary (a slot-parent word in an unparseable
    // segment is sensitive context, own-package or not). Pinned
    // here so the posture is explicit, not rediscovered.
    check("W25 pre-existing W22 boundary literal cmd/pm inside a case arm refuse",
        refused("case x in x) pm list packages;; esac") &&
            refused("case x in x) cmd activity start -n com.other/.Main;; esac"))
    check("W25 benign ordinary shell floor unchanged",
        allowed("echo \$(date)") &&
            allowed("echo `date`") &&
            allowed("echo \$((1+2))") &&
            allowed("ls \${HOME}/docs") &&
            allowed("\$HOME/bin/tool run") &&
            allowed("cmd activity start -n \$PKG/.Main") &&
            allowed("am start -n com.other/.Main > /dev/null"))
    check("W25 benign loops and conditions unchanged",
        allowed("for i in 1 2; do echo \$i > /sdcard/f; done") &&
            allowed("select opt in a b; do echo \$opt; done") &&
            allowed("if true; then echo hi > /sdcard/x; fi") &&
            allowed("while false; do echo hi; done") &&
            allowed("if dumpsys battery > /sdcard/b; then echo ok; fi"))
    // W28 FLIP (justified, round-6 residual closure):
    // the W25 named residual — a PURE single substitution in
    // argument position outside an arm/condition — is CLOSED.
    // Any command substitution in a literal slot parent's tail
    // now refuses; the slot value is unknown and fails closed.
    // The W28 suite pins the closure per slot parent.
    check("W28 flip W25 named residual pure-substitution package argument now refused",
        refused("am start -n \$(cat /sdcard/c)"))

    // ============ Prior-wave spot re-pins (unchanged) ============
    check("W25 regression prior refusals still refuse",
        refused("input tap 1 1") &&
            refused("pm clear $own") &&
            refused("am force-stop $own") &&
            refused("cmd \${X}ctivity start-activity -n $own/.MainActivity") &&
            refused("if cmd \${X}ctivity start-activity -n $own/.MainActivity; then :; fi") &&
            refused("cmd >/dev/null \${X}ctivity start-activity -n $own/.MainActivity"))
    check("W25 regression prior benign pins still allowed",
        allowed("case \$X in a) echo hi;; esac") &&
            allowed("cmd activity start -n com.other/.Main") &&
            allowed("echo hi > /sdcard/x") &&
            allowed("dumpsys > file"))

    println("W25ShellFilterTest: $passes PASS / $failures FAIL")
    if (failures > 0) kotlin.system.exitProcess(1)
}
