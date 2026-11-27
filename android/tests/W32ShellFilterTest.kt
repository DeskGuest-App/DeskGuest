// Wave 32 Lane A — P1-F1 ROUND-7 pins (Android).
// round-7 (W31 confirmation) returned FIX-INADEQUATE
// on the W28 filter with one new counter-example and three
// rejected residuals. Every claim was PROBED against pre-W32
// code before fixing (W32 lane log has the full probe table):
//  (1) `in$(echo put) tap 1 1` — NOT reproduced as stated: the
//      verbatim string was already REFUSED pre-W32 (its tail
//      names the literal input verb `tap`). The class behind
//      it IS real: an assembled command word with a tail no
//      rule judges escaped (`a$(echo m) start -n com.other/…`,
//      `mon$(echo key) -p com.other 1`, `s$(echo h) -c 'echo
//      hi'` all probed ALLOWED pre-W32). Closure: an ASSEMBLED
//      word in COMMAND position refuses in every context.
//      Pure-substitution command words keep their posture —
//      decision pinned below with its justification.
//  (2) R1 script files — probed ALLOWED pre-W32. Coordinator
//      decision: shell interpreters invoked with a script-file
//      operand REFUSE (inline -c stays, scanned); stdin forms
//      (-s, bare -, input redirection with no -c) refuse too;
//      toybox dispatch added; toybox awk's unambiguous -f file
//      forms refuse. This flips ONE W28 pin (named there).
//  (3) R2 wrapper-position expansion — probed ALLOWED pre-W32
//      (`env $OPTS sh -c '…'` halted unwrapping, payload never
//      recursed). Closure: any expansion in a position a
//      wrapper chain's unwrapping must step over refuses —
//      the final command cannot be determined, and unknown
//      fails closed. Literal chains stay allowed.
//  (4) R3 su trailing command — probed ALLOWED pre-W32.
//      Android su semantics could not be verified against a
//      real Android su binary in this environment (stock
//      Android ships none; the general su contract passes
//      post-user arguments to the shell), so the fail-closed
//      side is implemented: su's trailing command is joined
//      and recursed like a -c payload; ambiguous shapes
//      refuse. Pure/model layer only.
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

    // ============ Point 1: assembled command word ============
    check("W32 DS round-7 verbatim refused (already refused pre-W32 via its verb tail)",
        refused("in\$(echo put) tap 1 1"))
    check("W32 assembled input verb, plain tail, refused",
        refused("in\$(echo put) hello"))
    check("W32 assembled am verb refused", refused("a\$(echo m) start -n com.other/.Main"))
    check("W32 assembled pm verb refused", refused("p\$(echo m) clear com.other"))
    check("W32 assembled cmd verb refused", refused("c\$(echo md) statusbar expand"))
    check("W32 assembled monkey verb refused", refused("mon\$(echo key) -p com.other 1"))
    check("W32 assembled su verb refused", refused("s\$(echo u) -c 'echo hi'"))
    check("W32 assembled sh verb refused", refused("s\$(echo h) -c 'echo hi'"))
    check("W32 assembled verb backtick form refused", refused("in`echo put` tap 1 1"))
    check("W32 assembled verb quoted form refused", refused("\"in\$(echo put)\" tap 1 1"))
    check("W32 assembled verb default-value form refused", refused("in\${X:-put} hello"))
    check("W32 multiple-expansion command word refused", refused("\$(echo l)\$(echo s) -la"))
    check("W32 assembled verb behind assignment refused",
        refused("X=1 a\$(echo m) start -n com.other/.Main"))
    check("W32 assembled verb behind exec refused",
        refused("exec a\$(echo m) start -n com.other/.Main"))
    check("W32 assembled verb in condition refused",
        refused("if a\$(echo m) start -n com.other/.Main; then :; fi"))
    check("W32 assembled verb in case arm refused",
        refused("case x in x) a\$(echo m) start -n com.other/.Main;; esac"))
    // Benign controls: assembled words in ARGUMENT position are
    // governed by the existing rules and must stay allowed.
    check("W32 benign assembled word in argument position allowed",
        allowed("echo in\$(echo put)") && allowed("echo a\$(echo m)"))
    // DECISION PINNED: a PURE command word (exactly one
    // expansion, no literal join) keeps the W17–W28 posture.
    // Its body is re-checked as a command in its own right, and
    // every tail that would make an unknown verb dangerous (an
    // input verb, the own package) is literal and judged — so
    // the unknown is bounded by scanned text on both sides.
    check("W32 decision pinned: pure-substitution command word, benign body, allowed",
        allowed("\$(echo ls) -la"))
    check("W32 benign variable-only path command word allowed",
        allowed("\$HOME/bin/tool run") && allowed("\${HOME}/bin/tool run"))

    // ============ Point 2: interpreter script files ============
    check("W32 R1 verbatim sh script file refused", refused("sh /sdcard/x"))
    check("W32 bash script file refused", refused("bash /sdcard/x"))
    check("W32 path-prefixed interpreter script file refused", refused("/system/bin/sh /sdcard/x"))
    check("W32 flag-before-operand script file refused", refused("sh -x /sdcard/x"))
    check("W32 dashdash script file refused", refused("sh -- /sdcard/x"))
    check("W32 busybox sh script file refused", refused("busybox sh /sdcard/x"))
    check("W32 toybox sh script file refused", refused("toybox sh /sdcard/x"))
    check("W32 env-routed script file refused", refused("env sh /sdcard/x"))
    check("W32 stdin script flag -s refused", refused("sh -s"))
    check("W32 stdin script bare dash refused", refused("sh -"))
    check("W32 input-redirection script refused", refused("sh < /sdcard/x"))
    check("W32 awk -f path program file refused", refused("awk -f /sdcard/prog"))
    check("W32 awk --file program file refused", refused("awk --file=/sdcard/prog"))
    // Benign controls: inline -c payloads remain available.
    check("W32 benign sh -c echo allowed", allowed("sh -c 'echo hi'"))
    check("W32 benign sh -xc echo allowed", allowed("sh -xc 'echo hi'"))
    check("W32 benign sh -o with -c allowed", allowed("sh -o vi -c 'echo hi'"))
    check("W32 benign sh -c with stdin redirect allowed", allowed("sh -c 'echo hi' < /dev/null"))
    check("W32 benign sh -c with dollar-zero operand allowed", allowed("sh -c 'echo hi' /sdcard/x"))
    check("W32 benign interpreter text in argument position allowed", allowed("echo sh /sdcard/x"))
    check("W32 benign awk inline and -F separator allowed",
        allowed("awk '{print \$1}' /sdcard/f") && allowed("awk -F: '{print}'"))
    check("W32 benign toybox/busybox sh -c allowed",
        allowed("toybox sh -c 'echo hi'") && allowed("busybox sh -c 'echo hi'"))

    // ============ Point 3: expansion in wrapper position ============
    check("W32 R2 verbatim substance refused",
        refused("env \$OPTS sh -c 'a\$(printf %s m) start -n \"io.deskguest.ap\$(printf %s p)/.MainActivity\"'"))
    check("W32 wrapper expansion with benign payload still refused",
        refused("env \$OPTS sh -c 'echo hi'"))
    check("W32 wrapper flag-argument expansion refused", refused("env -u \$X sh -c 'echo hi'"))
    check("W32 wrapper assignment-value expansion refused", refused("env FOO=\$X sh -c 'echo hi'"))
    check("W32 timeout duration expansion refused", refused("timeout \$T sh -c 'echo hi'"))
    check("W32 nohup command-position expansion refused", refused("nohup \$X sh -c 'echo hi'"))
    check("W32 xargs expansion refused", refused("xargs \$X sh -c 'echo hi'"))
    check("W32 find -exec expansion command refused", refused("find /sdcard -exec \$X {} \\;"))
    // Benign controls: literal wrapper chains stay allowed.
    check("W32 benign literal env chain allowed", allowed("env FOO=1 sh -c 'echo hi'"))
    check("W32 benign literal timeout chain allowed", allowed("timeout 5 sh -c 'echo hi'"))
    check("W32 benign literal stdbuf/nice/setsid/xargs chains allowed",
        allowed("stdbuf -o0 sh -c 'echo hi'") && allowed("nice -n 5 sh -c 'echo hi'") &&
            allowed("setsid sh -c 'echo hi'") && allowed("xargs sh -c 'echo hi'"))
    check("W32 benign non-wrapper expansion arguments allowed",
        allowed("echo \$OPTS") && allowed("ls \$HOME/docs"))

    // ============ Point 4: su trailing command ============
    check("W32 R3 verbatim refused", refused("su root eval 'in\$(echo put) tap 1 1'"))
    check("W32 su trailing literal denied command refused", refused("su root input tap 1 1"))
    check("W32 su trailing script-file command refused", refused("su root sh /sdcard/x"))
    check("W32 su expansion user operand refused", refused("su \$U id"))
    check("W32 su expansion trailing command refused", refused("su root \$X"))
    check("W32 su stdin-redirection script refused", refused("su < /sdcard/x"))
    // Benign controls, per the implemented fail-closed
    // semantics: no trailing command = no payload.
    check("W32 benign su bare/user/login forms allowed",
        allowed("su") && allowed("su root") && allowed("su -"))
    check("W32 benign su trailing plain commands allowed",
        allowed("su root id") && allowed("su root ls -la"))
    check("W32 benign su -c forms allowed",
        allowed("su -c 'echo hi'") && allowed("su root -c 'echo hi'"))
    check("W32 benign su trailing interpreter -c allowed", allowed("su root sh -c 'echo hi'"))
    check("W32 benign su trailing eval allowed", allowed("su root eval 'echo hi'"))
    check("W32 benign su shell-flag form allowed", allowed("su -s /system/bin/sh root id"))

    // ============ Prior-wave spot re-pins (unchanged) ============
    check("W32 regression prior refusals still refuse",
        refused("input tap 1 1") &&
            refused("sh -c 'a\$(printf %s m) start -n \"io.deskguest.ap\$(printf %s p)/.MainActivity\"'") &&
            refused("am start -n \$(cat /sdcard/c)"))
    check("W32 regression benign other-package payload still allowed",
        allowed("sh -c 'am start -n com.other/.Main'"))

    println("W32ShellFilterTest: $passes PASS / $failures FAIL")
    if (failures > 0) kotlin.system.exitProcess(1)
}
