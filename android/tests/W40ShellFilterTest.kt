// Wave 40 Lane A — P1-F1 ROUND-8 pins (Android).
// round-8 (W33 confirmation) returned FIX-INADEQUATE on
// the W32 filter with one new counter-example and two
// inadequate residuals (A and B). Every DeepSeek claim was
// PROBED against pre-W40 code before fixing (W40 lane log
// has the full probe table — all four claims reproduced
// as stated, unlike the round-7 verbatim):
//  (1) CARVE-OUT HOLE: the W17 benignVarPath carve-out
//      required only norm.contains('/') — never a literal
//      final component — so $HOME/bin/$PATH passed as a
//      benign variable-only path and provablyBenign also
//      skipped the tail verb check. Closure: the carve-out
//      covers variable DIRECTORY components only; the
//      final component must be literal text. Composition
//      pinned: a literal denied final component reached
//      via a variable path is still the denied verb by
//      name and refuses.
//  (2) RESIDUAL A: a pure-substitution command word
//      ($(echo sh) -c '…') returned on hadExpansion before
//      the shells branch, so its -c payload was never
//      scanned, and inside the payload ${i}put is a
//      variable-assembled verb. Closure: a pure
//      substitution with a simple literal-producing body
//      (echo/printf of literals) is RESOLVED and the full
//      invocation rules apply to the resolved word; an
//      unresolvable one with a -c-shaped or substitution
//      tail refuses. The pinned benign pure-substitution
//      uses stay allowed (named per-case below).
//  (3) ANSI-C QUOTING: $'...' escapes were invisible to
//      every token view. Closure: $'...' segments decode
//      during tokenisation; an undecodable segment in
//      command position refuses.
//  (4) RESIDUAL B: awk -f <plain name> was allowed
//      because case-folding made -f indistinguishable
//      from -F. Closure: awk flag handling is
//      case-sensitive where case survives (top level) via
//      ScanTok.caseNorm, so -f refuses in all forms while
//      -F stays allowed; inline awk program text is
//      scanned for embedded command strings (system()
//      arguments, pipe-position literals). Pure/model
//      layer only.
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

    // ============ Item 1: carve-out hole ============
    check("W40 round-8 verbatim refused",
        refused("PATH=../../../../../../../../system/bin/\$(echo in)\$(echo put); \$HOME/bin/\$PATH tap 1 1"))
    check("W40 variable program name with denied tail refused",
        refused("\$HOME/bin/\$PATH tap 1 1"))
    check("W40 variable program name refused whatever its tail",
        refused("\$HOME/bin/\$PATH run"))
    check("W40 expansion joined into final component refused",
        refused("\$HOME/bin/\${PATH}put run"))
    check("W40 expansion inside literal final component refused",
        refused("\$HOME/bin/to\${HOME}ol run"))
    // Composition pin: with a literal final component, the
    // name itself is judged — a variable directory does not
    // launder a denied program name.
    check("W40 literal denied final component via variable path refused",
        refused("\$HOME/bin/input tap 1 1"))
    check("W40 literal monkey final component via variable path refused",
        refused("\$HOME/bin/monkey -p com.other"))
    // Benign controls: variable directory + literal final
    // component is exactly the pinned W17 floor.
    check("W40 benign variable path with literal final component allowed",
        allowed("\$HOME/bin/tool run") && allowed("\${HOME}/bin/tool run"))
    check("W40 benign literal tool with tap as its argument allowed",
        allowed("\$HOME/bin/tool tap 1 1"))

    // ============ Item 2: pure-substitution command word ============
    check("W40 residual A verbatim refused",
        refused("\$(echo sh) -c 'i=in; \${i}put tap 1 1'"))
    check("W40 resolved shell with literal denied payload refused",
        refused("\$(echo sh) -c 'input tap 1 1'"))
    check("W40 printf-resolved shell with assembled payload refused",
        refused("\$(printf %s sh) -c 'i=in; \${i}put tap 1 1'"))
    check("W40 backtick-resolved shell with denied payload refused",
        refused("`echo sh` -c 'input tap 1 1'"))
    check("W40 unresolvable command word with -c tail refused",
        refused("\$(cat /sdcard/c) -c 'echo hi'"))
    check("W40 unresolvable command word with substitution tail refused",
        refused("\$(cat /sdcard/c) \$(echo hi)"))
    // The payload-side half of residual A was already closed
    // for directly scanned payloads in W32; re-pin so the
    // composition (resolution + assembled rule) is explicit.
    check("W40 variable-assembled verb inside a scanned payload refused",
        refused("sh -c 'i=in; \${i}put tap 1 1'"))
    // Benign controls, named per-case: resolution makes the
    // command word KNOWN, so a benign resolved shell with a
    // benign scanned payload stays allowed, as do the
    // pinned pure-substitution uses from W28/W32.
    check("W40 benign resolved shell with benign payload allowed",
        allowed("\$(echo sh) -c 'echo hi'") && allowed("\$(printf sh) -c 'echo hi'") &&
            allowed("`echo sh` -c 'echo hi'"))
    check("W40 benign pinned pure-substitution command word allowed",
        allowed("\$(echo ls) -la"))
    // W45 FLIP (round-9 point 3, pre-authorised): an
    // unresolvable pure-substitution command word now
    // REFUSES whatever its tail — the executed word is
    // unknowable file content. This check was "allowed"
    // in W40; the flip is named in the W45 lane log.
    check("W40 unresolvable command word refused (W45 flip of the W40 pin)",
        refused("\$(cat /sdcard/c) -la"))

    // ============ Item 3: ANSI-C quoting ============
    check("W40 ANSI-C verbatim refused", refused("\$'in\\x70ut' tap 1 1"))
    check("W40 ANSI-C hex first character refused", refused("\$'\\x69nput' tap 1 1"))
    check("W40 ANSI-C octal escape refused", refused("\$'in\\160ut' tap 1 1"))
    check("W40 ANSI-C unicode escape refused", refused("\$'in\\u0070ut' tap 1 1"))
    check("W40 ANSI-C undecodable segment in command position refused",
        refused("\$'in\\xzzut' tap 1 1"))
    // Benign controls: decoded-benign words stay allowed.
    check("W40 benign ANSI-C command words allowed",
        allowed("\$'echo' hi") && allowed("\$'ls' -la"))
    check("W40 benign ANSI-C argument allowed", allowed("echo \$'hi\\nthere'"))
    check("W40 benign undecodable ANSI-C segment in argument position allowed",
        allowed("echo \$'a\\xzz'"))

    // ============ Item 4: awk ============
    check("W40 residual B verbatim chain refused",
        refused("cd /data/local/tmp; printf '%s\\n' 'BEGIN{system(\"i=in; \${i}put tap 1 1\")}' > prog; awk -f prog"))
    check("W40 awk -f plain name refused", refused("awk -f prog"))
    check("W40 awk -f attached file refused", refused("awk -fprog"))
    check("W40 awk -f via busybox and env refused",
        refused("busybox awk -f prog") && refused("env awk -f prog"))
    check("W40 awk inline system with assembled verb refused",
        refused("awk 'BEGIN{system(\"i=in; \${i}put tap 1 1\")}'"))
    check("W40 awk inline system with literal denied command refused",
        refused("awk 'BEGIN{system(\"input tap 1 1\")}'"))
    check("W40 awk inline system with unextractable argument refused",
        refused("awk 'BEGIN{system(cmd)}'"))
    check("W40 awk pipe-position denied command literal refused",
        refused("awk 'BEGIN{\"input tap 1 1\" | getline}'"))
    check("W40 awk program via --source with denied system refused",
        refused("awk --source 'BEGIN{system(\"input tap 1 1\")}'"))
    // Benign controls: inline programs and the -F
    // field-separator forms stay allowed.
    check("W40 benign awk inline program allowed", allowed("awk '{print \$1}' file"))
    check("W40 benign awk -F attached separator allowed",
        allowed("awk -F: '{print \$1}' /etc/passwd"))
    check("W40 benign awk -F separate separator allowed",
        allowed("awk -F ':' '{print \$1}' /etc/passwd"))
    check("W40 benign awk -F with f as its separator allowed",
        allowed("awk -Ff '{print \$1}' file"))
    check("W40 benign awk -v assignment allowed", allowed("awk -v x=1 '{print x}'"))
    check("W40 benign awk system with benign command allowed",
        allowed("awk 'BEGIN{system(\"echo hi\")}'"))
    check("W40 benign awk pipe literals allowed",
        allowed("awk 'BEGIN{print \"hi\" | \"sort\"}'") &&
            allowed("awk 'BEGIN{\"echo hi\" | getline}'"))

    // ============ Prior-wave spot re-pins (unchanged) ============
    check("W40 regression prior refusals still refuse",
        refused("input tap 1 1") &&
            refused("a\$(echo m) start -n com.other/.Main") &&
            refused("awk -f /sdcard/prog") &&
            refused("awk --file=/sdcard/prog") &&
            refused("sh /sdcard/x"))
    check("W40 regression benign other-package payload still allowed",
        allowed("sh -c 'am start -n com.other/.Main'"))

    println("W40ShellFilterTest: $passes PASS / $failures FAIL")
    if (failures > 0) kotlin.system.exitProcess(1)
}
