// Wave 45 Lane A — P1-F1 ROUND-9 pins (Android).
// round-9 (W41 confirmation) returned FIX-INADEQUATE on
// the W40 filter: one new counter-example in the
// carve-out class plus three rejected residuals ((i),
// (ii), (iv); (iii) was accepted). Every DeepSeek claim
// was PROBED against pre-W45 code before fixing (W45
// lane log has the full probe table — all four claims
// reproduced as stated):
//  (1) RESOLVED-NAME RULE: $HOME/bin/sh has a literal
//      final component, so the carve-out accepted it and
//      invocationRefused returned on hadExpansion before
//      the shells branch — the -c payload was never
//      scanned. Closure: a literal final component naming
//      a dispatched program (shells, busybox/toybox, su,
//      wrappers, awk, eval, find) takes the resolved
//      name's rules in full, payload recursion included.
//  (2) PAYLOAD CASE PRESERVATION (residual (i)): payload
//      extraction was case-folded, so depth-1 awk -f was
//      indistinguishable from -F. Closure: extraction and
//      substitution bodies preserve original case
//      (ScanTok.caseRaw), and the awk flag walker is
//      case-sensitive at every depth.
//  (3) UNRESOLVABLE COMMAND WORDS FAIL CLOSED
//      (residual (ii)): a pure-substitution command word
//      whose producer does not resolve to a literal word
//      refuses whatever its tail. This FLIPS the W40 pin
//      $(cat /sdcard/c) -la from allowed to refused —
//      named here and in the W45 lane log as the rule's
//      cost.
//  (4) AWK ADJACENT-LITERAL CONCATENATION (residual
//      (iv)): awk joins whitespace-separated adjacent
//      string literals; the embedded-command scan joins
//      them before judging system()/pipe strings, and
//      checks every system() call. Pure/model layer only.
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

    // ============ Point 1: resolved-name rule ============
    check("W45 round-9 verbatim refused",
        refused("i=in; export i; HOME=/system; export HOME; \$HOME/bin/sh -c '\${i}put tap 1 1'"))
    check("W45 variable-path bash with assembled payload refused",
        refused("\$HOME/bin/bash -c 'i=in; \${i}put tap 1 1'"))
    check("W45 variable-path shell with script-file operand refused",
        refused("\$HOME/bin/sh /sdcard/x"))
    check("W45 variable-path awk -f refused",
        refused("\$HOME/bin/awk -f prog"))
    check("W45 variable-path busybox shell with denied payload refused",
        refused("\$HOME/bin/busybox sh -c 'input tap 1 1'"))
    check("W45 variable-path shell with own-package payload refused",
        refused("\$HOME/bin/sh -c 'am start -n io.deskguest.app/.MainActivity'"))
    check("W45 braced variable-path shell with denied payload refused",
        refused("\${HOME}/bin/sh -c 'input tap 1 1'"))
    check("W45 variable-path denied verb by name still refused",
        refused("\$HOME/bin/input tap 1 1"))
    // Benign controls, named per-case in the brief: a
    // resolved shell with a benign scanned payload stays
    // allowed, and a literal final component naming
    // nothing regulated keeps the carve-out treatment.
    check("W45 benign variable-path shell with benign payload allowed",
        allowed("\$HOME/bin/sh -c 'echo hi'"))
    check("W45 benign variable-path env shell with benign payload allowed",
        allowed("\$HOME/bin/env sh -c 'echo hi'"))
    check("W45 benign variable-path busybox echo allowed",
        allowed("\$HOME/bin/busybox echo hi"))
    check("W45 benign variable-path unregulated tool allowed",
        allowed("\$HOME/bin/tool run") && allowed("\$HOME/bin/tool tap 1 1"))
    // Inside a wrapper chain the W32 posture stands: an
    // expansion in the nested command position refuses.
    check("W45 wrapper-chain variable-path command word still refused",
        refused("env \$HOME/bin/sh -c 'echo hi'"))

    // ============ Point 2: payload case preservation ============
    check("W45 depth-1 awk -f plain name refused",
        refused("sh -c 'awk -f prog'"))
    check("W45 depth-1 awk -f attached refused",
        refused("sh -c 'awk -fprog'"))
    check("W45 depth-2 awk -f plain name refused",
        refused("sh -c 'sh -c \"awk -f prog\"'"))
    check("W45 depth-1 awk -f via busybox payload refused",
        refused("busybox sh -c 'awk -f prog'"))
    check("W45 substitution-body awk -f refused",
        refused("echo \$(sh -c 'awk -f prog')"))
    // Controls: -F keeps its separator at every depth —
    // with case preserved these MUST stay allowed.
    check("W45 depth-1 awk -F attached separator allowed",
        allowed("sh -c 'awk -F: \"{print \\\$1}\" /etc/passwd'"))
    check("W45 depth-1 awk -F with f as its separator allowed",
        allowed("sh -c 'awk -Ff \"{print}\"'"))
    check("W45 depth-1 awk -F separate separator allowed",
        allowed("sh -c 'awk -F \":\" \"{print}\"'"))
    check("W45 depth-2 awk -F separator allowed",
        allowed("sh -c 'sh -c \"awk -Ff {print}\"'"))
    check("W45 substitution-body awk -F separator allowed",
        allowed("echo \$(awk -F: '{print}' /etc/passwd)"))
    check("W45 benign mixed-case payload still allowed",
        allowed("sh -c 'echo HeLLo'"))

    // ============ Point 3: unresolvable command words ============
    check("W45 unresolvable command word with literal tail refused (the named flip)",
        refused("\$(cat /sdcard/c) -la"))
    check("W45 unresolvable command word with no tail refused",
        refused("\$(cat /sdcard/c)"))
    check("W45 unresolvable backtick command word refused",
        refused("`cat /sdcard/c` -la"))
    check("W45 unresolvable producer command word refused",
        refused("\$(basename /system/bin/ls) -la"))
    check("W45 unresolvable command word inside a payload refused",
        refused("sh -c '\$(cat /sdcard/c) -la'"))
    // Resolved forms keep working, payload scanned.
    check("W45 resolved echo command word allowed",
        allowed("\$(echo ls) -la"))
    check("W45 resolved printf command word allowed",
        allowed("\$(printf %s ls) -la"))
    check("W45 resolved path command word allowed",
        allowed("\$(echo /system/bin/ls) -la"))
    check("W45 resolved shell with benign payload allowed",
        allowed("\$(echo sh) -c 'echo hi'"))
    check("W45 resolved shell with denied payload refused",
        refused("\$(echo sh) -c 'input tap 1 1'"))
    // Argument position is untouched by the rule.
    check("W45 benign unresolvable substitution in argument position allowed",
        allowed("echo \$(cat /sdcard/c)"))

    // ============ Point 4: awk adjacent literals ============
    check("W45 round-9 awk concatenation verbatim refused",
        refused("awk 'BEGIN{system(\"in\" \"put tap 1 1\")}'"))
    check("W45 awk three-literal concatenation refused",
        refused("awk 'BEGIN{system(\"in\" \"p\" \"ut tap 1 1\")}'"))
    check("W45 awk concatenated pipe-position command refused",
        refused("awk 'BEGIN{\"in\" \"put tap 1 1\" | getline}'"))
    check("W45 awk concatenated print-pipe command refused",
        refused("awk 'BEGIN{print x | \"in\" \"put tap 1 1\"}'"))
    check("W45 awk second system call with denied command refused",
        refused("awk 'BEGIN{system(\"echo hi\"); system(\"input tap 1 1\")}'"))
    // Benign controls: adjacent literals without an
    // embedded denied command stay allowed.
    check("W45 benign awk adjacent literals without embedded command allowed",
        allowed("awk '{print \"a\" \"b\"}'"))
    check("W45 benign awk concatenated system command allowed",
        allowed("awk 'BEGIN{system(\"ec\" \"ho hi\")}'"))
    check("W45 benign awk concatenated pipe literals allowed",
        allowed("awk 'BEGIN{print \"a\" \"b\" | \"sort\"}'"))

    // ============ Prior-wave spot re-pins (unchanged) ============
    check("W45 regression prior refusals still refuse",
        refused("input tap 1 1") &&
            refused("awk -f prog") &&
            refused("sh /sdcard/x") &&
            refused("PATH=../../../../../../../../system/bin/\$(echo in)\$(echo put); \$HOME/bin/\$PATH tap 1 1"))
    check("W45 regression benign forms still allowed",
        allowed("sh -c 'echo hi'") &&
            allowed("\$HOME/bin/tool run") &&
            allowed("awk -F: '{print \$1}' /etc/passwd"))

    println("W45ShellFilterTest: $passes PASS / $failures FAIL")
    if (failures > 0) kotlin.system.exitProcess(1)
}
