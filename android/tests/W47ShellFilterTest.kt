// Wave 47 Lane A — P1-F1 ROUND-10 pins (Android).
// round-10 (W46 confirmation) returned FIX-INADEQUATE on
// the W45 filter on two points; every DeepSeek claim was
// PROBED against pre-W47 code before fixing (W47 lane log
// has the full probe tables — all claims reproduced):
//  (1) RESOLVED-NAME COMPLETENESS: `xargs` was dispatched
//      by the command-position locator (prefixWords /
//      flagArgWords) but absent from the resolved-name
//      set, so `HOME=/system; $HOME/bin/xargs sh -c
//      "$(echo in)put tap 1 1"` was ALLOWED — the nested
//      payload was never scanned. Probing the neighbourhood
//      found the same hole for `exec`, `command`, `time`,
//      `builtin` (assembled payloads, all ALLOWED pre-W47).
//      Root fix: the name tables are hoisted to ONE
//      GateModel-level source read by every pass, the
//      resolved-name set is DERIVED from them, the
//      resolution also runs in the locator, and this suite
//      carries a SOURCE CROSS-CHECK (below) that enumerates
//      the dispatch branches/tables from HeroDesign.kt and
//      fails if any recognised program name is outside the
//      derived set or lacks a behavioural pin here.
//  (2) AWK NON-LITERAL system() ARGUMENTS (residual R3):
//      the W45 count check was satisfied by a literal
//      PREFIX — `system("in" x)` and `system("in"
//      substr("put tap 1 1",1))` were ALLOWED, the suffix
//      never judged. Now each system() argument is parsed:
//      after adjacent-literal joining it must be ONE pure
//      string literal followed by `)`; anything else
//      refuses as unextractable. The same purity rule
//      covers a literal that is only part of a pipe
//      command expression. Pure-literal arguments keep the
//      exact prior treatment. Pure/model layer only.
import io.deskguest.app.design.GateModel
import java.io.File

private var failures = 0
private var passes = 0
private fun check(name: String, cond: Boolean) {
    if (cond) { passes++; println("PASS $name") } else { failures++; println("FAIL $name") }
}

fun main(args: Array<String>) {
    val own = "io.deskguest.app"
    fun refused(cmd: String) = GateModel.shellInputRefused(cmd, own)
    fun allowed(cmd: String) = !GateModel.shellInputRefused(cmd, own)

    // ============ Point 1: resolved-name completeness ============
    check("W47 round-10 xargs verbatim refused",
        refused("HOME=/system; \$HOME/bin/xargs sh -c \"\$(echo in)put tap 1 1\""))
    check("W47 variable-path xargs with flag and assembled payload refused",
        refused("\$HOME/bin/xargs -0 sh -c '\$(echo in)put tap 1 1'"))
    check("W47 variable-path prefix names with assembled payload refused (exec/command/time/builtin)",
        refused("\$HOME/bin/exec sh -c '\$(echo in)put tap 1 1'") &&
            refused("\$HOME/bin/command sh -c '\$(echo in)put tap 1 1'") &&
            refused("\$HOME/bin/time sh -c '\$(echo in)put tap 1 1'") &&
            refused("\$HOME/bin/builtin sh -c '\$(echo in)put tap 1 1'"))
    check("W47 variable-path shells with assembled payload refused (all seven)",
        refused("\$HOME/bin/sh -c '\$(echo in)put tap 1 1'") &&
            refused("\$HOME/bin/bash -c '\$(echo in)put tap 1 1'") &&
            refused("\$HOME/bin/dash -c '\$(echo in)put tap 1 1'") &&
            refused("\$HOME/bin/ash -c '\$(echo in)put tap 1 1'") &&
            refused("\$HOME/bin/zsh -c '\$(echo in)put tap 1 1'") &&
            refused("\$HOME/bin/ksh -c '\$(echo in)put tap 1 1'") &&
            refused("\$HOME/bin/mksh -c '\$(echo in)put tap 1 1'"))
    check("W47 variable-path multicall shells with assembled payload refused",
        refused("\$HOME/bin/busybox sh -c '\$(echo in)put tap 1 1'") &&
            refused("\$HOME/bin/toybox sh -c '\$(echo in)put tap 1 1'"))
    check("W47 variable-path wrappers with assembled payload refused (env/setsid/timeout/stdbuf/doas/nice)",
        refused("\$HOME/bin/env sh -c '\$(echo in)put tap 1 1'") &&
            refused("\$HOME/bin/setsid sh -c '\$(echo in)put tap 1 1'") &&
            refused("\$HOME/bin/timeout 5 sh -c '\$(echo in)put tap 1 1'") &&
            refused("\$HOME/bin/stdbuf -o0 sh -c '\$(echo in)put tap 1 1'") &&
            refused("\$HOME/bin/doas sh -c '\$(echo in)put tap 1 1'") &&
            refused("\$HOME/bin/nice sh -c '\$(echo in)put tap 1 1'"))
    check("W47 variable-path su/nohup/eval/find with assembled payload refused",
        refused("\$HOME/bin/su -c '\$(echo in)put tap 1 1'") &&
            refused("\$HOME/bin/nohup sh -c '\$(echo in)put tap 1 1'") &&
            refused("\$HOME/bin/eval '\$(echo in)put tap 1 1'") &&
            refused("\$HOME/bin/find /sdcard -exec sh -c '\$(echo in)put tap 1 1' ;"))
    check("W47 variable-path awk with assembled embedded command refused",
        refused("\$HOME/bin/awk 'BEGIN{system(\"i=in; \${i}put tap 1 1\")}'"))
    check("W47 variable-path awk -f refused (re-pin)",
        refused("\$HOME/bin/awk -f prog"))
    check("W47 variable-path slot parents and denied verbs by name refused",
        refused("\$HOME/bin/cmd input tap 1 1") &&
            refused("\$HOME/bin/am start -n io.deskguest.app/.MainActivity") &&
            refused("\$HOME/bin/pm install io.deskguest.app") &&
            refused("\$HOME/bin/monkey -p com.other") &&
            refused("\$HOME/bin/input tap 1 1"))
    // Benign directions: every resolved name with a benign
    // use keeps it (probed per name pre/post fix).
    check("W47 benign variable-path prefix names allowed",
        allowed("\$HOME/bin/xargs echo hi") &&
            allowed("\$HOME/bin/exec echo hi") &&
            allowed("\$HOME/bin/command echo hi") &&
            allowed("\$HOME/bin/time echo hi") &&
            allowed("\$HOME/bin/builtin echo hi"))
    check("W47 benign variable-path shells and multicall allowed",
        allowed("\$HOME/bin/sh -c 'echo hi'") &&
            allowed("\$HOME/bin/bash -c 'echo hi'") &&
            allowed("\$HOME/bin/mksh -c 'echo hi'") &&
            allowed("\$HOME/bin/busybox echo hi") &&
            allowed("\$HOME/bin/toybox echo hi"))
    check("W47 benign variable-path wrappers allowed",
        allowed("\$HOME/bin/env sh -c 'echo hi'") &&
            allowed("\$HOME/bin/setsid echo hi") &&
            allowed("\$HOME/bin/timeout 5 echo hi") &&
            allowed("\$HOME/bin/stdbuf -o0 echo hi") &&
            allowed("\$HOME/bin/doas echo hi") &&
            allowed("\$HOME/bin/nice echo hi"))
    check("W47 benign variable-path su/nohup/eval/find/awk allowed",
        allowed("\$HOME/bin/su -c 'echo hi'") &&
            allowed("\$HOME/bin/nohup echo hi") &&
            allowed("\$HOME/bin/eval 'echo hi'") &&
            allowed("\$HOME/bin/find /sdcard -name x") &&
            allowed("\$HOME/bin/awk -F: '{print \$1}' /etc/passwd"))
    check("W47 benign variable-path slot parent with benign slot allowed",
        allowed("\$HOME/bin/cmd echo hi") &&
            allowed("\$HOME/bin/am start -n com.other/.Main"))
    check("W47 benign variable-path unregulated tool still allowed (re-pin)",
        allowed("\$HOME/bin/tool run") && allowed("\$HOME/bin/tool tap 1 1"))

    // ============ Point 2: awk non-literal system() arguments ============
    check("W47 round-10 awk variable-suffix system argument refused (DeepSeek form 1)",
        refused("awk 'BEGIN{x=\"put tap 1 1\"; system(\"in\" x)}'"))
    check("W47 round-10 awk substr system argument refused (DeepSeek form 2)",
        refused("awk 'BEGIN{system(\"in\" substr(\"put tap 1 1\",1))}'"))
    check("W47 awk variable-first system argument refused",
        refused("awk 'BEGIN{y=\"in\"; system(y \"put tap 1 1\")}'"))
    check("W47 awk literal-then-variable system argument refused",
        refused("awk 'BEGIN{system(\"in\" \"put\" x)}'"))
    check("W47 awk parenthesised system argument refused as unextractable",
        refused("awk 'BEGIN{system((\"echo hi\"))}'"))
    check("W47 awk second system call with non-literal argument refused",
        refused("awk 'BEGIN{system(\"echo hi\"); system(\"in\" x)}'"))
    check("W47 awk compound pipe command refused (literal first)",
        refused("awk 'BEGIN{\"in\" x | getline}'"))
    check("W47 awk compound pipe command refused (literal last)",
        refused("awk 'BEGIN{print x | \"in\" y}'") &&
            refused("awk 'BEGIN{print x | y \"in\"}'"))
    // Benign controls: pure-literal system() arguments keep
    // the exact prior treatment, and programs with no
    // system() / no compound pipe literal are untouched.
    check("W47 benign awk pure-literal system arguments allowed (re-pin)",
        allowed("awk 'BEGIN{system(\"echo hi\")}'") &&
            allowed("awk 'BEGIN{system(\"echo hi\" )}'") &&
            allowed("awk 'BEGIN{system(\"ec\" \"ho hi\")}'"))
    check("W47 benign awk denied pure-literal system argument still refused (re-pin)",
        refused("awk 'BEGIN{system(\"input tap 1 1\")}'") &&
            refused("awk 'BEGIN{system(cmd)}'"))
    check("W47 benign awk print argument compound with pure pipe command allowed",
        allowed("awk '{print \"a\" \$1 | \"sort\"}'") &&
            allowed("awk '{print \"a\" \$1}'"))
    check("W47 benign awk programs without embedded commands allowed (re-pin)",
        allowed("awk '{print}'") &&
            allowed("awk 'BEGIN{print \"a\" \"b\" | \"sort\"}'") &&
            allowed("awk -F: '{print \$1}' /etc/passwd"))

    // ============ Source cross-check: derived set completeness ============
    // The resolved-name set must cover EVERY program name
    // the filter recognises, or the next dispatch addition
    // reopens the round-10 hole silently. This check parses
    // the dispatch tables and branch literals out of
    // HeroDesign.kt and asserts coverage — a future name
    // added to a dispatch branch/table without reaching
    // the derived set (or without a behavioural pin above)
    // fails here.
    val srcFile = File(args.getOrNull(0) ?: ".",
        "app/src/main/java/io/deskguest/app/design/HeroDesign.kt")
    check("W47 cross-check source readable", srcFile.isFile)
    val src = if (srcFile.isFile) srcFile.readText() else ""
    fun balanced(openIdx: Int): String {
        var depth = 0
        var i = openIdx
        while (i < src.length) {
            when (src[i]) {
                '(' -> depth++
                ')' -> { depth--; if (depth == 0) return src.substring(openIdx + 1, i) }
            }
            i++
        }
        return ""
    }
    fun setContents(declName: String): Set<String> {
        val idx = src.indexOf("val $declName")
        if (idx < 0) return emptySet()
        val sIdx = src.indexOf("setOf(", idx)
        if (sIdx < 0) return emptySet()
        return Regex("\"([^\"]+)\"").findAll(balanced(sIdx + 5)).map { it.groupValues[1] }.toSet()
    }
    fun mapKeys(declName: String): Set<String> {
        val idx = src.indexOf("val $declName")
        if (idx < 0) return emptySet()
        val mIdx = src.indexOf("mapOf(", idx)
        if (mIdx < 0) return emptySet()
        return Regex("\"([^\"]+)\"\\s+to\\b").findAll(balanced(mIdx + 5)).map { it.groupValues[1] }.toSet()
    }
    val derived = setContents("shellNames") + setContents("multicallNames") +
        setOf("su", "nohup", "awk", "eval", "find") + mapKeys("wrapperFlagArgWords") +
        setContents("chainPrefixWords") + mapKeys("prefixFlagArgWords") +
        setContents("slotParentNames") + setContents("deniedVerbNames")
    val declIdx = src.indexOf("val dispatchedNames")
    val declText = if (declIdx >= 0) src.substring(declIdx, minOf(declIdx + 800, src.length)) else ""
    check("W47 cross-check dispatchedNames derives from every dispatch table",
        declIdx >= 0 && listOf("shellNames", "multicallNames", "wrapperFlagArgWords",
            "chainPrefixWords", "prefixFlagArgWords", "slotParentNames",
            "deniedVerbNames").all { declText.contains(it) })
    check("W47 cross-check tables parsed non-empty",
        setContents("shellNames").size == 7 && setContents("multicallNames").size == 2 &&
            mapKeys("wrapperFlagArgWords").size == 6 && setContents("chainPrefixWords").size == 5 &&
            mapKeys("prefixFlagArgWords").size == 3 && setContents("slotParentNames").size == 4 &&
            setContents("deniedVerbNames").size == 2 && derived.size == 30)
    // Branch literals and dispatched sets inside the
    // invocation pass must all be covered by the derived set.
    val invStart = src.indexOf("private fun invocationRefused")
    val invEnd = src.indexOf("private fun joinAwkAdjacentLiterals")
    val invBody = if (invStart >= 0 && invEnd > invStart) src.substring(invStart, invEnd) else ""
    val branchLiterals = Regex("""cwBase == "([a-z]+)"""").findAll(invBody)
        .map { it.groupValues[1] }.toSet()
    check("W47 cross-check invocation branch literals covered",
        invBody.isNotEmpty() && branchLiterals.isNotEmpty() && derived.containsAll(branchLiterals))
    val aliasTables = mapOf(
        "shells" to setContents("shellNames"),
        "multicallNames" to setContents("multicallNames"),
        "wrapperFlagArgs" to mapKeys("wrapperFlagArgWords"),
        "chainPrefixes" to setContents("chainPrefixWords")
    )
    val inIdents = Regex("""cwBase in ([a-zA-Z]+)""").findAll(invBody)
        .map { it.groupValues[1] }.toSet()
    check("W47 cross-check invocation dispatched sets covered",
        inIdents.isNotEmpty() && inIdents.all { ident ->
            val table = aliasTables[ident] ?: setContents(ident) + mapKeys(ident)
            table.isNotEmpty() && derived.containsAll(table)
        })
    // The verb-position pass's by-name judgements (slot
    // parents, the input/monkey literal set, the top-level
    // dangerous-verbs set) must be covered too.
    val verbStart = src.indexOf("private fun verbPositionRefused")
    val verbEnd = src.indexOf("private fun payloadInvocationRefused")
    val verbBody = if (verbStart >= 0 && verbEnd > verbStart) src.substring(verbStart, verbEnd) else ""
    val verbLiterals = Regex("""cwBase == "([a-z]+)"""").findAll(verbBody)
        .map { it.groupValues[1] }.toSet()
    val verbInlineSets = Regex("""cwBase in setOf\(([^)]*)\)""").findAll(verbBody)
        .flatMap { m -> Regex("\"([^\"]+)\"").findAll(m.groupValues[1]).map { it.groupValues[1] } }
        .toSet()
    check("W47 cross-check verb-position by-name judgements covered",
        verbBody.isNotEmpty() && derived.containsAll(verbLiterals) &&
            derived.containsAll(verbInlineSets) && derived.containsAll(setContents("dangerousVerbs")))
    check("W47 cross-check locator prefix tables covered",
        derived.containsAll(setContents("chainPrefixWords")) &&
            derived.containsAll(mapKeys("prefixFlagArgWords")) &&
            setContents("grammarPrefixWords").containsAll(setContents("chainPrefixWords")))
    // The behavioural pins above cover exactly the derived
    // set — a name added to a table without a pin here
    // breaks this equality and forces the pin.
    val pinnedNames = setOf(
        "sh", "bash", "dash", "ash", "zsh", "ksh", "mksh",
        "busybox", "toybox", "su", "nohup", "awk", "eval", "find",
        "env", "setsid", "timeout", "stdbuf", "doas", "nice",
        "xargs", "exec", "command", "time", "builtin",
        "cmd", "am", "pm", "monkey", "input"
    )
    check("W47 cross-check behavioural pins cover exactly the derived set",
        pinnedNames == derived)

    // ============ Prior-wave spot re-pins (unchanged) ============
    check("W47 regression prior refusals still refuse",
        refused("input tap 1 1") &&
            refused("awk -f prog") &&
            refused("awk 'BEGIN{system(\"in\" \"put tap 1 1\")}'") &&
            refused("HOME=/system; \$HOME/bin/sh -c '\$(echo in)put tap 1 1'"))
    check("W47 regression benign forms still allowed",
        allowed("sh -c 'echo hi'") &&
            allowed("\$HOME/bin/tool run") &&
            allowed("awk -F: '{print \$1}' /etc/passwd"))

    println("W47ShellFilterTest: $passes PASS / $failures FAIL")
    if (failures > 0) kotlin.system.exitProcess(1)
}
