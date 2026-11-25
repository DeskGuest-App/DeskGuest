// Wave 28 Lane A — P1-F1 ROUND-6 pins (Android).
// round-6 (W27 confirmation) returned FIX-INADEQUATE
// on the W25 filter with two findings:
//  (1) SECOND-SHELL RE-PARSE: `sh -c 'a$(printf %s m) start -n
//      "io.agenticcontrol.ap$(printf %s p)/.MainActivity"'` —
//      the outer filter saw literal `sh` and an opaque quoted
//      payload; the inner shell assembled `am` + the own
//      package and ran it. Closure (W28a): payload invocations
//      at the corrected command position (interpreter -c,
//      eval, su -c, wrappers, find -exec) extract the payload
//      argument verbatim and run the FULL filter over it as
//      its own command line, depth-capped at 3; a payload that
//      cannot be extracted verbatim refuses.
//  (2) RESIDUAL CLOSURE: `am start -n $(cat /sdcard/c)` must
//      fail closed. Closure (W28b): ANY command substitution
//      in a literal slot parent's tail refuses, pure or
//      assembled; parameter expansion is not a substitution.
// Both verbatim strings were probed ALLOWED on pre-W28 code
// (W28 lane log). Pure/model layer only.
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
    val f1 = "sh -c 'a\$(printf %s m) start -n \"io.agenticcontrol.ap\$(printf %s p)/.MainActivity\"'"
    val f1Payload = "a\$(printf %s m) start -n \"io.agenticcontrol.ap\$(printf %s p)/.MainActivity\""

    // ============ Finding 1 verbatim (permanent pin) ============
    check("W28 DS round-6 exact second-shell evasion refused", refused(f1))

    // ============ Finding 1 variants: interpreters and forms ============
    check("W28 bash -c assembled payload refused", refused("bash -c '$f1Payload'"))
    check("W28 dash -c assembled payload refused", refused("dash -c '$f1Payload'"))
    check("W28 zsh -c assembled payload refused", refused("zsh -c '$f1Payload'"))
    check("W28 path-prefixed interpreter refused", refused("/system/bin/sh -c '$f1Payload'"))
    check("W28 busybox sh -c assembled payload refused", refused("busybox sh -c '$f1Payload'"))
    check("W28 double-quoted payload with substitutions refused",
        refused("sh -c \"a\$(printf %s m) start -n \\\"io.agenticcontrol.ap\$(printf %s p)/.MainActivity\\\"\""))
    check("W28 eval single-quoted assembled payload refused", refused("eval '$f1Payload'"))
    check("W28 eval joined-args literal own-package payload refused",
        refused("eval 'am start -n' 'io.agenticcontrol.app/.MainActivity'"))
    check("W28 backtick command word inside payload refused",
        refused("sh -c '`printf %s am` start -n io.agenticcontrol.app/.MainActivity'"))
    check("W28 payload inside a command substitution refused",
        refused("echo \$(sh -c '$f1Payload')"))
    check("W28 payload inside a case arm refused",
        refused("case x in x) sh -c '$f1Payload';; esac"))
    check("W28 combined-flag -xc payload refused", refused("sh -xc '$f1Payload'"))

    // ============ Finding 1 variants: wrappers and nesting routes ============
    check("W28 xargs sh -c refused", refused("echo x | xargs sh -c '$f1Payload'"))
    check("W28 find -exec sh -c refused", refused("find /sdcard -exec sh -c '$f1Payload' {} \\;"))
    check("W28 find -execdir sh -c refused", refused("find /sdcard -execdir sh -c '$f1Payload' {} \\;"))
    check("W28 env sh -c refused", refused("env sh -c '$f1Payload'"))
    check("W28 env assignment + sh -c refused", refused("env FOO=1 sh -c '$f1Payload'"))
    check("W28 su -c direct assembled payload refused", refused("su -c '$f1Payload'"))
    check("W28 su root -c literal payload refused", refused("su root -c 'am start -n io.agenticcontrol.app/.MainActivity'"))
    check("W28 doas sh -c refused", refused("doas sh -c '$f1Payload'"))
    check("W28 setsid sh -c refused", refused("setsid sh -c '$f1Payload'"))
    check("W28 nohup sh -c refused", refused("nohup sh -c '$f1Payload'"))
    check("W28 timeout sh -c refused", refused("timeout 5 sh -c '$f1Payload'"))
    check("W28 exec sh -c refused", refused("exec sh -c '$f1Payload'"))
    check("W28 condition sh -c refused", refused("if sh -c '$f1Payload'; then :; fi"))

    // ============ Finding 1: unscannable payloads refuse ============
    check("W28 sh -c pure-substitution payload unscannable refused",
        refused("sh -c \$(cat /sdcard/c)"))
    check("W28 sh -c unquoted assembled payload unscannable refused",
        refused("sh -c a\$(printf %s m)"))
    check("W28 sh -c variable payload unscannable refused",
        refused("sh -c \$PAYLOADX"))
    check("W28 eval unquoted expansion argument unscannable refused",
        refused("eval \$PAYLOADX"))

    // ============ Finding 1: recursion depth ============
    // Nesting via proper shell double-quote escaping (the
    // '\'' idiom garbles beyond depth 2 in the scanner's
    // tokenisation; the escaped-double-quote form is the
    // verbatim string a shell would actually pass down).
    fun nest(payload: String, times: Int): String {
        var p = payload
        repeat(times) {
            val esc = p.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\$", "\\\$").replace("`", "\\`")
            p = "sh -c \"$esc\""
        }
        return p
    }
    check("W28 nested sh -c depth 2 assembled inner refused",
        refused(nest("am start -n io.agenticcontrol.app/.MainActivity", 2)))
    check("W28 nested sh -c depth 2 benign allowed", allowed(nest("echo hi", 2)))
    check("W28 nested sh -c depth 3 benign allowed", allowed(nest("echo hi", 3)))
    check("W28 depth-cap overflow (depth 4 and 5 benign) refused",
        refused(nest("echo hi", 4)) && refused(nest("echo hi", 5)))

    // ============ Finding 2 verbatim + per-slot-parent variants ============
    check("W28 DS round-6 residual verbatim refused", refused("am start -n \$(cat /sdcard/c)"))
    check("W28 am backtick tail refused", refused("am start -n `cat /sdcard/c`"))
    check("W28 pm pure-substitution tail refused", refused("pm clear \$(cat /sdcard/c)"))
    check("W28 pm backtick tail refused", refused("pm clear `cat /sdcard/c`"))
    check("W28 cmd activity pure-substitution tail refused",
        refused("cmd activity start -n \$(cat /sdcard/c)"))
    check("W28 cmd package backtick tail refused", refused("cmd package clear `cat /sdcard/c`"))
    check("W28 cmd any-subcommand substitution tail refused",
        refused("cmd statusbar expand \$(cat /sdcard/c)"))
    check("W28 monkey substitution tail refused", refused("monkey -p com.other \$(cat /sdcard/c)"))
    check("W28 slot parent in case arm substitution tail refused",
        refused("case x in x) am start -n \$(cat /sdcard/c);; esac"))

    // ============ Benign controls: payloads that must stay allowed ============
    check("W28 benign sh -c echo allowed", allowed("sh -c 'echo hi'"))
    check("W28 benign sh -c ls allowed", allowed("sh -c 'ls -la'"))
    check("W28 benign sh -c other-package am allowed",
        allowed("sh -c 'am start -n com.other/.Main'"))
    check("W28 benign bash -c variable echo allowed", allowed("bash -c 'echo \$HOME'"))
    check("W28 benign eval quoted echo allowed (decision pinned)", allowed("eval 'echo \$HOME'"))
    check("W28 benign eval double-quoted echo allowed", allowed("eval \"echo \$HOME\""))
    check("W28 benign eval plain args allowed", allowed("eval echo hi"))
    check("W28 benign env wrapper payload allowed", allowed("env FOO=1 sh -c 'echo hi'"))
    check("W28 benign nohup payload allowed", allowed("nohup sh -c 'echo hi'"))
    check("W28 benign find -exec echo allowed", allowed("find /sdcard -exec echo {} \\;"))
    check("W28 benign find -exec sh -c echo allowed", allowed("find /sdcard -exec sh -c 'echo hi' {} \\;"))
    check("W28 benign sh -c text in argument position allowed", allowed("echo sh -c 'echo hi'"))
    // W32 FLIP (justified, named in the W32 lane log): the W28
    // stated limit pinned this ALLOWED; the round-7 coordinator
    // decision reverses the posture — an interpreter script
    // file is an unscannable payload and now REFUSES. The full
    // W32 pin set lives in W32ShellFilterTest.
    check("W28/W32 flip: interpreter script file now refused", refused("sh /sdcard/script.sh"))

    // ============ Benign controls: slot parents, parameter expansion only ============
    check("W28 benign slot parents with parameter expansion only allowed",
        allowed("am start -n \$PKG/.Main") &&
            allowed("cmd activity start -n \${PKG}/.Main") &&
            allowed("pm clear \$PKG") &&
            allowed("am start -n com.other/.Main"))
    check("W28 benign ordinary substitution floor unchanged",
        allowed("echo \$(date)") &&
            allowed("echo `date`") &&
            allowed("echo \$((1+2))") &&
            allowed("ls \${HOME}/docs") &&
            allowed("\$HOME/bin/tool run"))

    // ============ Prior-wave spot re-pins (unchanged) ============
    check("W28 regression prior refusals still refuse",
        refused("input tap 1 1") &&
            refused("sh -c 'input tap 1 1'") &&
            refused("case x in x) \"\$(printf %s a)m\" start -n \"io.agenticcontrol.ap\$(printf %s p)/.MainActivity\";; esac") &&
            refused("am start -n \"io.agenticcontrol.ap\$(printf %s p)/.MainActivity\"") &&
            refused("\$(printf %s am) start -n io.agenticcontrol.app/.MainActivity"))
    check("W28 regression command-position substitution, benign tail, stays allowed",
        allowed("\$(echo ls) -la"))

    println("W28ShellFilterTest: $passes PASS / $failures FAIL")
    if (failures > 0) kotlin.system.exitProcess(1)
}
