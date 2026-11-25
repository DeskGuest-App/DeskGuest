// Wave 51 Lane A — P1-F1 ROUND-12 pins (Android).
// round-12 (W50 confirmation) returned FIX-INADEQUATE on
// the W49 filter via an ESCAPE-DECODING hole, not the
// sink rule: `awk 'BEGIN{system("\151nput tap 1 1")}'`
// was ALLOWED pre-W51 — awk decodes the octal escape
// \151 as `i`, so the executed command is `input tap
// 1 1`, but unescapeAwkString's pair-collapse rule
// turned \1 into `1` and the recursed payload was
// `151nput tap 1 1`, an unknown benign verb. Every
// claim was PROBED against pre-W51 code before fixing
// (W51 lane log has the probe table): octal and hex
// escapes hid denied verbs at system(), at print /
// getline / coprocess pipe sinks, inside adjacent-
// literal assembly and mid-verb, and an octal space
// hid the verb/argument split. The principle now
// implemented: any decoding the scanner applies to a
// literal must reproduce the target interpreter's
// decoding EXACTLY; where a form cannot be decoded
// faithfully, the literal is unextractable and
// refuses. unescapeAwkString implements awk's table
// (one-letter set, octal \ooo 1-3 digits, hex \xhh
// 1-2 digits — the gawk/busybox decoding, fail-closed
// over stock BWK awk which lacks \x; see the decoder's
// doc in HeroDesign.kt for the dialect decision) plus
// awk's literal-char rule for other escaped chars,
// and returns null for dialect-divergent forms (\x
// with no digit, \u/\U, \e/\E), which every caller
// refuses as unextractable. SAME-CLASS AUDIT (shell
// side): decodeAnsiC re-checked against mksh/bash
// $'...' — faithful on octal/hex/standard escapes
// (pinned below on decoded denied payloads), one
// divergence fixed (\c? is DEL, not 0x1F); the
// payload extractor's double-quote backslash rule
// is POSIX-faithful (pinned below). Pure/model only.
// W53 SUPERSESSION (round-13): the \x hex decoding
// described above is WITHDRAWN — \x in awk string
// literals is unextractable and refuses (the BWK
// superset argument was rejected, residual R2). One
// pin below flips with it, named in place. The octal
// decoding and everything else in this header stands.
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

    // ============ The round-12 break: octal at system() ============
    check("W51 round-12 verbatim octal system refused",
        refused("awk 'BEGIN{system(\"\\151nput tap 1 1\")}'"))
    check("W51 octal verb with no arguments refused",
        refused("awk 'BEGIN{system(\"\\151nput\")}'"))
    check("W51 octal mid-verb and octal monkey refused",
        refused("awk 'BEGIN{system(\"inp\\165t tap 1 1\")}'") &&
            refused("awk 'BEGIN{system(\"monk\\145y -p com.other\")}')"))
    check("W51 octal separator escapes refused (space split, semicolon injection)",
        refused("awk 'BEGIN{system(\"input\\040tap 1 1\")}'") &&
            refused("awk 'BEGIN{system(\"echo hi\\073 input tap 1 1\")}')"))

    // ============ Octal/hex at every pipe sink ============
    check("W51 octal at print-pipe sink refused",
        refused("awk 'BEGIN{print \"x\" | \"\\151nput tap 1 1\"}'"))
    check("W51 octal at getline-pipe sink refused",
        refused("awk 'BEGIN{\"\\151nput tap 1 1\" | getline}'"))
    check("W51 octal at coprocess sink refused",
        refused("awk 'BEGIN{print \"x\" |& \"\\151nput tap 1 1\"}'"))
    check("W51 hex at system and pipe sinks refused",
        refused("awk 'BEGIN{system(\"\\x69nput tap 1 1\")}'") &&
            refused("awk 'BEGIN{print \"x\" | \"\\x69nput tap 1 1\"}'") &&
            refused("awk 'BEGIN{\"in\\x70ut tap 1 1\" | getline}'"))

    // ============ Mixed literal+escape assembly ============
    check("W51 adjacent literal plus escape assembly refused",
        refused("awk 'BEGIN{system(\"in\" \"\\160ut tap 1 1\")}'") &&
            refused("awk 'BEGIN{system(\"inp\" \"\\165t tap 1 1\")}'") &&
            refused("awk 'BEGIN{print \"x\" | \"in\" \"\\160ut tap 1 1\"}'"))

    // ============ Dialect-divergent forms refuse as unextractable ============
    check("W51 unicode escape in awk literal refused (BWK/gawk diverge)",
        refused("awk 'BEGIN{system(\"\\u0069nput tap 1 1\")}'"))
    check("W51 divergent escape refuses whatever its content",
        refused("awk 'BEGIN{system(\"echo \\u0041\")}'") &&
            refused("awk 'BEGIN{system(\"echo \\e hi\")}')"))
    check("W51 hex escape with no hex digit refused",
        refused("awk 'BEGIN{system(\"\\x nput tap 1 1\")}'"))

    // ============ Benign decoded controls (fidelity, not blanket refusal) ============
    check("W51 benign octal-decoded sink commands allowed",
        allowed("awk 'BEGIN{system(\"\\145cho hi\")}'") &&
            allowed("awk 'BEGIN{print \"x\" | \"s\\157rt\"}'") &&
            allowed("awk 'BEGIN{\"s\\157rt\" | getline}'"))
    // W53 FLIP (named, round-13 ruling): the benign hex
    // case below was ALLOWED by W51's hex decoding; \x in
    // awk literals is now unextractable and refuses (see
    // the W53 suite / lane log). The standard-escape cases
    // keep their W51 verdicts in the same check.
    check("W51 benign hex sink command refused (W53 flip); standard-escape sink commands allowed",
        refused("awk 'BEGIN{system(\"\\x65cho hi\")}'") &&
            allowed("awk 'BEGIN{system(\"echo\\thi\")}'") &&
            allowed("awk 'BEGIN{system(\"echo hi\")}'"))

    // ============ Shell side audit: $'...' fidelity pins ============
    check("W51 ANSI-C octal denied verb in command position refused (re-pin)",
        refused("\$'\\151nput' tap 1 1"))
    check("W51 ANSI-C octal payload carrying denied verb refused on decoded content",
        refused("sh -c \$'\\151nput tap 1 1'"))
    check("W51 ANSI-C hex payload carrying denied verb refused on decoded content",
        refused("sh -c \$'\\x69nput tap 1 1'"))
    check("W51 ANSI-C standard escape payload carrying denied verb refused",
        refused("sh -c \$'input\\ttap 1 1'"))
    check("W51 ANSI-C benign decoded payloads allowed",
        allowed("sh -c \$'\\145cho hi'") && allowed("sh -c \$'echo hi'"))

    // ============ Shell side audit: double-quote payload pins ============
    check("W51 double-quoted payload carrying denied verb refused",
        refused("sh -c \"input tap 1 1\""))
    check("W51 benign double-quoted argument allowed",
        allowed("echo \"a\\nb\""))

    // ============ Prior-wave re-pins (unchanged) ============
    check("W51 regression prior refusals still refuse",
        refused("input tap 1 1") &&
            refused("awk 'BEGIN{c=\"sort\"; print \"x\" | c}'") &&
            refused("awk 'BEGIN{system(\"in\" \"put tap 1 1\")}'") &&
            refused("\$'in\\x70ut' tap 1 1"))
    check("W51 regression benign awk programs still allowed",
        allowed("awk 'BEGIN{print \"x\" | \"sort\"}'") &&
            allowed("awk '{print \$1}' file"))

    println("W51ShellFilterTest: $passes PASS / $failures FAIL")
    if (failures > 0) kotlin.system.exitProcess(1)
}
