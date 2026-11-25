// Wave 22 Lane B — P1-F1 GRAMMAR-AWARENESS pins (Android).
// round-4 (W21 confirmation) evaded the W19 pure-literal
// verb-slot rule by desyncing the scanner's command word from
// the shell's, in two classes:
//  (a) REDIRECTIONS: `X=a; cmd >/dev/null ${X}ctivity …` — the
//      scanner tokenised `>` as a separator and took /dev/null
//      as the verb slot; the shell consumed it as a redirection
//      target and ran `cmd activity …`.
//  (b) RESERVED-WORD PREFIXES: `if cmd ${X}ctivity …; then :; fi`
//      (also while/until/!/exec/command/{/}/time) — the command
//      word was consumed by grammar, the cmd slot never examined.
// The W22 fix is a grammar model in GateModel's shell analysis:
// redirection operators consume their target token (targets are
// never command words, verb slots, or self-target arguments,
// wherever the redirection sits), and grammar/transparent
// prefixes are unwrapped recursively per segment before the
// command position is located. The W17/W19 rules then apply on
// the corrected positions. Fail-closed boundary (pinned below):
// an unparseable COMMAND POSITION refuses only in an input-verb
// / self-target context; redirections alone never refuse —
// benign redirected commands stay allowed. Pure/model layer only.
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

    // ============ round-4 exact evasions (permanent pins) ============
    check("W22 DS exact (a) X=a; cmd >/dev/null \${X}ctivity own refused",
        refused("X=a; cmd >/dev/null \${X}ctivity start-activity -n io.agenticcontrol.app/.MainActivity"))
    check("W22 DS exact (a) without assignment refused",
        refused("cmd >/dev/null \${X}ctivity start-activity -n $own/.MainActivity"))
    check("W22 DS exact (b) X=a; if cmd \${X}ctivity own refused",
        refused("X=a; if cmd \${X}ctivity start-activity -n io.agenticcontrol.app/.MainActivity; then :; fi"))
    check("W22 DS exact (b) without assignment refused",
        refused("if cmd \${X}ctivity start-activity -n $own/.MainActivity; then :; fi"))
    check("W22 DS combined if + redirection refused",
        refused("if cmd >/dev/null \${X}ctivity start-activity -n $own/.MainActivity; then :; fi"))

    // ============ Denied base forms used by the generated corpora ============
    val deniedCmdSlotExp = "cmd \${X}ctivity start-activity -n $own/.MainActivity"
    val deniedCmdSlotLit = "cmd activity start-activity -n $own/.MainActivity"
    val deniedAmSlotExp = "am \${X}orce-stop $own"
    val deniedPmSlotExp = "pm cl\${X}ar $own"
    check("W22 base forms refuse (sanity)",
        refused(deniedCmdSlotExp) && refused(deniedCmdSlotLit) &&
            refused(deniedAmSlotExp) && refused(deniedPmSlotExp))

    // ============ Generated corpus: redirection placements x denied forms ============
    val redirForms = listOf(
        ">/dev/null", "> /dev/null", "2>/dev/null", "2> /dev/null",
        ">>/dev/null", "&>/dev/null", "< /dev/null", "2>&1",
        ">/dev/null 2>&1", "> /sdcard/out.txt", "1>>/sdcard/log.txt"
    )
    var genRedir = 0
    var genRedirRefused = 0
    val genRedirEscapes = mutableListOf<String>()
    // Placements around a `parent slot tail` triple.
    fun redirPlacements(parent: String, slot: String, tail: String): List<String> {
        val out = mutableListOf<String>()
        for (r in redirForms) {
            out += "$r $parent $slot $tail"           // before the command word
            out += "$parent $r $slot $tail"           // between parent and slot
            out += "$parent $slot $r $tail"           // between slot and tail
            out += "$parent $slot $tail $r"           // after the tail
            out += "$r $parent $r $slot $tail"        // before + between
        }
        return out
    }
    val redirCases = mutableListOf<String>()
    redirCases += redirPlacements("cmd", "\${X}ctivity", "start-activity -n $own/.MainActivity")
    redirCases += redirPlacements("cmd", "activity", "start-activity -n $own/.MainActivity")
    redirCases += redirPlacements("cmd", "input", "tap 100 200")
    redirCases += redirPlacements("am", "\${X}orce-stop", own)
    redirCases += redirPlacements("pm", "cl\${X}ar", own)
    for (cmd in redirCases) {
        genRedir++
        if (refused(cmd)) genRedirRefused++ else genRedirEscapes += cmd
    }
    println("W22 generated redirection corpus: $genRedir cases, $genRedirRefused refused")
    for (e in genRedirEscapes) println("FAIL W22 generated redirection escape $e")
    check("W22 generated redirection corpus all refuse ($genRedir cases)",
        genRedirEscapes.isEmpty() && genRedir == genRedirRefused)

    // ============ Generated corpus: reserved-word prefixes x denied forms ============
    val wrappers: List<Pair<String, (String) -> String>> = listOf(
        "if" to { s: String -> "if $s; then :; fi" },
        "while" to { s: String -> "while $s; do :; done" },
        "until" to { s: String -> "until $s; do :; done" },
        "not" to { s: String -> "! $s" },
        "exec" to { s: String -> "exec $s" },
        "command" to { s: String -> "command $s" },
        "time" to { s: String -> "time $s" },
        "time-p" to { s: String -> "time -p $s" },
        "brace" to { s: String -> "{ $s; }" },
        "then" to { s: String -> "if true; then $s; fi" },
        "else" to { s: String -> "if false; then :; else $s; fi" },
        "elif" to { s: String -> "if false; then :; elif $s; then :; fi" },
        "do" to { s: String -> "while false; do $s; done" },
        "xargs" to { s: String -> "echo x | xargs $s" },
        "nested-if-exec" to { s: String -> "if exec $s; then :; fi" },
        "nested-while-not" to { s: String -> "while ! $s; do :; done" },
        "nested-brace-time-command" to { s: String -> "{ time command $s; }" },
        "nested-if-not-exec" to { s: String -> "if ! exec $s; then :; fi" },
        "nested-double-if" to { s: String -> "if if $s; then :; fi; then :; fi" }
    )
    val deniedForms = listOf(
        deniedCmdSlotExp, deniedCmdSlotLit, deniedAmSlotExp, deniedPmSlotExp,
        "cmd act\${X}ivity start-activity -n $own/.MainActivity",
        "cmd act\$(true)ivity start-activity -n $own/.MainActivity",
        "cmd input tap 100 200"
    )
    var genPrefix = 0
    var genPrefixRefused = 0
    val genPrefixEscapes = mutableListOf<String>()
    for ((wname, wrap) in wrappers) {
        for (form in deniedForms) {
            val cmd = wrap(form)
            genPrefix++
            if (refused(cmd)) genPrefixRefused++ else genPrefixEscapes += "$wname: $cmd"
        }
    }
    println("W22 generated prefix corpus: $genPrefix cases, $genPrefixRefused refused")
    for (e in genPrefixEscapes) println("FAIL W22 generated prefix escape $e")
    check("W22 generated prefix corpus all refuse ($genPrefix cases)",
        genPrefixEscapes.isEmpty() && genPrefix == genPrefixRefused)

    // ============ Generated corpus: prefixes x redirections x expansion slot ============
    var genCross = 0
    var genCrossRefused = 0
    val genCrossEscapes = mutableListOf<String>()
    val crossWrappers = wrappers.filter { it.first in listOf("if", "exec", "while", "brace", "xargs") }
    val crossRedirs = listOf(">/dev/null", "2>/dev/null", "> /dev/null")
    for ((wname, wrap) in crossWrappers) {
        for (r in crossRedirs) {
            val forms = listOf(
                "cmd $r \${X}ctivity start-activity -n $own/.MainActivity",
                "$r cmd \${X}ctivity start-activity -n $own/.MainActivity",
                "cmd \${X}ctivity $r start-activity -n $own/.MainActivity",
                "cmd $r activity start-activity -n $own/.MainActivity"
            )
            for (form in forms) {
                val cmd = wrap(form)
                genCross++
                if (refused(cmd)) genCrossRefused++ else genCrossEscapes += "$wname/$r: $cmd"
            }
        }
    }
    println("W22 generated prefix x redirection corpus: $genCross cases, $genCrossRefused refused")
    for (e in genCrossEscapes) println("FAIL W22 generated cross escape $e")
    check("W22 generated prefix x redirection corpus all refuse ($genCross cases)",
        genCrossEscapes.isEmpty() && genCross == genCrossRefused)

    // ============ Named grammar forms ============
    check("W22 attached digit form 2>/dev/null between cmd and slot (expansion) refused",
        refused("cmd 2>/dev/null \${X}ctivity start-activity -n $own/.MainActivity"))
    check("W22 redirection before command word (literal self-target) refused",
        refused(">/dev/null cmd activity start-activity -n $own/.MainActivity"))
    check("W22 redirection target carrying expansion is not the slot refused",
        refused("cmd >\${X} \${X}ctivity start-activity -n $own/.MainActivity"))
    check("W22 own package inside a redirection target path does not arm the slot rule (other tail)",
        allowed("cmd activity start -n com.other/.Main > /sdcard/$own.log"))
    check("W22 exec flag argument skipped (exec -a name cmd slot-exp) refused",
        refused("exec -a name cmd \${X}ctivity start-activity -n $own/.MainActivity"))
    check("W22 xargs flag argument skipped (xargs -n 1 cmd slot-exp) refused",
        refused("echo x | xargs -n 1 cmd \${X}ctivity start-activity -n $own/.MainActivity"))
    check("W22 command -v is a lookup, not an execution (allowed)",
        allowed("command -v cmd"))
    check("W22 expansion command word after redirection refused",
        refused(">/dev/null \$X tap 1 1"))
    check("W22 expansion command word after if refused",
        refused("if \$X tap 1 1; then :; fi"))
    check("W22 subshell substitution body still re-checked (echo \$(cmd slot-exp own)) refused",
        refused("echo \$(cmd \${X}ctivity start-activity -n $own/.MainActivity)"))

    // ============ Fail-closed boundary: unparseable command position ============
    check("W22 unparseable starter (function) with self-target context refused",
        refused("function f { cmd \${X}ctivity start-activity -n $own/.MainActivity; }"))
    check("W22 unparseable starter (select) with self-target context refused",
        refused("select opt in cmd \${X}ctivity $own; do :; done"))
    check("W22 unparseable starter (for) with cmd/activity/own context refused",
        refused("for x in cmd activity $own; do :; done"))
    check("W22 unparseable starter (for) in a benign loop stays allowed",
        allowed("for i in 1 2; do echo \$i > /sdcard/f; done"))
    check("W22 unparseable starter (select) in a benign loop stays allowed",
        allowed("select opt in a b; do echo \$opt; done"))
    check("W22 unparseable starter (case) in a benign switch stays allowed",
        allowed("case \$X in a) echo hi;; esac"))
    check("W22 dangling redirection is a shell syntax error, not a refusal (boundary)",
        allowed("echo hi >"))

    // ============ Benign corpus: redirections + keywords in harmless commands ============
    val benignSingles = listOf(
        "echo hi > /sdcard/x",
        "dumpsys > file",
        "dumpsys battery > /sdcard/batt.txt 2>&1",
        "echo hi >> /sdcard/log.txt",
        "cat < /sdcard/x",
        "cmd activity top >/dev/null",
        "cmd package list packages > /sdcard/p.txt",
        "pm list packages 2>/dev/null",
        "am start -n com.other/.Main > /dev/null",
        "cmd >/dev/null activity start -n com.other/.Main",
        "cmd 2>/dev/null activity top",
        "settings get global device_name > /sdcard/n.txt",
        "echo hi > \$HOME/x",
        "dumpsys > \${HOME}/dump.txt",
        "echo x | xargs echo",
        "if true; then echo hi > /sdcard/x; fi",
        "while false; do echo hi; done",
        "! echo hi",
        "exec echo hi",
        "command echo hi",
        "command -v echo",
        "time echo hi",
        "time -p ls > /sdcard/l.txt",
        "{ echo hi > /sdcard/x; }",
        "if dumpsys battery > /sdcard/b; then echo ok; fi",
        "until false; do echo hi > /sdcard/u; done"
    )
    var benignOk = 0
    val benignFlips = mutableListOf<String>()
    for (cmd in benignSingles) {
        if (allowed(cmd)) benignOk++ else benignFlips += cmd
    }
    for (e in benignFlips) println("FAIL W22 benign single refused $e")
    check("W22 benign singles all allowed (${benignSingles.size} cases)", benignFlips.isEmpty())

    // Generated benign: redirection placements x harmless bases.
    val benignBases: List<Triple<String, String, String>> = listOf(
        Triple("echo", "hi", ""),
        Triple("dumpsys", "battery", ""),
        Triple("cmd", "activity", "top"),
        Triple("pm", "list", "packages"),
        Triple("ls", "/sdcard", "")
    )
    var genBenign = 0
    val genBenignFlips = mutableListOf<String>()
    for ((cw, a1, a2) in benignBases) {
        for (r in redirForms) {
            val variants = listOf(
                "$r $cw $a1 $a2",
                "$cw $r $a1 $a2",
                "$cw $a1 $r $a2",
                "$cw $a1 $a2 $r"
            )
            for (cmd in variants) {
                genBenign++
                if (!allowed(cmd)) genBenignFlips += cmd
            }
        }
    }
    // Generated benign: prefix wrappers x harmless bases.
    val benignInners = listOf("echo hi", "dumpsys battery", "cmd activity top", "ls /sdcard")
    for ((wname, wrap) in wrappers) {
        for (inner in benignInners) {
            val cmd = wrap(inner)
            genBenign++
            if (!allowed(cmd)) genBenignFlips += "$wname: $cmd"
        }
    }
    println("W22 generated benign corpus: $genBenign cases, ${genBenign - genBenignFlips.size} allowed")
    for (e in genBenignFlips) println("FAIL W22 generated benign refused $e")
    check("W22 generated benign corpus all allowed ($genBenign cases)", genBenignFlips.isEmpty())

    // ============ Prior-wave floor / refusal spot re-pins (unchanged) ============
    check("W22 floor W12/W15/W17/W19 allowed pins still allowed",
        allowed("settings get global device_name") &&
            allowed("dumpsys battery") &&
            allowed("logcat -d") &&
            allowed("cmd activity start -n com.other/.Main") &&
            allowed("cmd package list packages") &&
            allowed("echo \$HOME") &&
            allowed("ls \${HOME}/docs") &&
            allowed("\$HOME/bin/tool run") &&
            allowed("cmd activity start -n \$PKG/.Main"))
    check("W22 regression W12/W15/W17/W19 refusals still refuse",
        refused("/system/bin/input tap 1 1") &&
            refused("input tap 1 1") &&
            refused("pm clear $own") &&
            refused("am force-stop $own") &&
            refused("cmd activity force-stop $own") &&
            refused("cmd input tap 1 1") &&
            refused("cmd \${X}ctivity start-activity -n $own/.MainActivity") &&
            refused("in\${X}put tap 1 2") &&
            refused("\$X \$Y") &&
            refused("cmd \$SUB start-activity $own"))

    println("W22AndGrammarTest: $passes PASS / $failures FAIL")
    if (failures > 0) kotlin.system.exitProcess(1)
}
