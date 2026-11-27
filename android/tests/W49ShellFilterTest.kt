// Wave 49 Lane A — P1-F1 ROUND-11 pins (Android).
// round-11 (W48 confirmation) returned FIX-INADEQUATE on
// the W47 filter: residual R1 (variable pipe commands
// unextracted) was REJECTED via the counter-example
// `awk 'BEGIN{c="in" "put tap 1 1"; c | getline}'` —
// ALLOWED pre-W49. Adjacent literals join into a complete
// command inside a variable; the variable then executes
// through a pipe sink with no system() call and no literal
// in command position, so the W47 purity rule (which
// judged literals) had nothing to judge. Every claim was
// PROBED against pre-W49 code before fixing (W49 lane log
// has the full probe tables): variable, function-call,
// field and parenthesised commands at print/printf pipes,
// getline pipes and coprocess pipes were all ALLOWED when
// their content was benign — the hole was purity, not
// content. The rule now implemented: PURITY AT EVERY AWK
// COMMAND SINK. At system() (W47), at print/printf … |
// expr, at expr | getline and at the gawk coprocess |&
// (both directions), the command operand must be a PURE
// string literal at the sink itself, after the W45
// adjacent-literal joining; anything else — variable,
// field, function call, parenthesised expression, or a
// concatenation involving a non-literal or an unjoined
// literal — REFUSES as unextractable. No data-flow
// tracking: what cannot be read at the point of execution
// is refused, even when the variable's assigned value is
// a benign literal the scanner could in principle see.
// Pure-literal sink commands keep the exact prior
// treatment (joined, then shell-filtered). File
// redirection (print … > expr, print … >> expr,
// getline … < expr) is NOT a command sink — the operand
// is a filename — and is untouched, distinguished from
// pipes by awk's own grammar. Pure/model layer only.
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

    // ============ The round-11 break and its class ============
    check("W49 round-11 verbatim variable getline pipe refused",
        refused("awk 'BEGIN{c=\"in\" \"put tap 1 1\"; c | getline}'"))
    check("W49 variable at system sink refused (benign and denied values alike)",
        refused("awk 'BEGIN{c=\"echo hi\"; system(c)}'") &&
            refused("awk 'BEGIN{c=\"input tap 1 1\"; system(c)}'"))
    check("W49 variable at print-pipe sink refused (purity, not content)",
        refused("awk 'BEGIN{c=\"sort\"; print \"x\" | c}'") &&
            refused("awk 'BEGIN{c=\"input tap 1 1\"; print \"x\" | c}'"))
    check("W49 variable at printf-pipe sink refused",
        refused("awk 'BEGIN{c=\"sort\"; printf \"x\" | c}'"))
    check("W49 variable at getline-pipe sink refused (plain, var form, loop form)",
        refused("awk 'BEGIN{c=\"sort\"; c | getline}'") &&
            refused("awk 'BEGIN{c=\"sort\"; c | getline line}'") &&
            refused("awk 'BEGIN{c=\"cat file\"; while ((c | getline line) > 0) print line}'"))
    check("W49 variable at coprocess sinks refused (print |& and |& getline)",
        refused("awk 'BEGIN{c=\"sort\"; print \"x\" |& c}'") &&
            refused("awk 'BEGIN{c=\"sort\"; c |& getline}'"))

    // ============ Non-literal expressions at sinks ============
    check("W49 function call at pipe sinks refused",
        refused("awk 'BEGIN{print \"x\" | substr(\"sort\",1)}'") &&
            refused("awk 'BEGIN{substr(\"sort\",1) | getline}'"))
    check("W49 field at pipe sinks refused",
        refused("awk 'BEGIN{print \"x\" | \$1}'") &&
            refused("awk 'BEGIN{\$1 | getline}'"))
    check("W49 parenthesised literal at print-pipe sink refused as unextractable",
        refused("awk 'BEGIN{print \"x\" | (\"sort\")}'"))
    check("W49 mixed literal+variable at pipe sinks refused (re-pin under sink rule)",
        refused("awk 'BEGIN{print \"x\" | \"in\" c}'") &&
            refused("awk 'BEGIN{\"in\" c | getline}'") &&
            refused("awk 'BEGIN{print \"x\" | c \"sort\"}'"))
    check("W49 unjoined juxtaposed literals at print-pipe sink refused (not the W45-joined literal)",
        refused("awk 'BEGIN{print \"x\" | \"so\"\"rt\"}'"))

    // ============ Pure-literal controls at every sink ============
    check("W49 pure-literal system sink unchanged (re-pin)",
        allowed("awk 'BEGIN{system(\"echo hi\")}'") &&
            refused("awk 'BEGIN{system(\"input tap 1 1\")}'"))
    check("W49 pure-literal print/printf-pipe sink unchanged",
        allowed("awk 'BEGIN{print \"x\" | \"sort\"}'") &&
            allowed("awk 'BEGIN{printf \"x\" | \"sort\"}'") &&
            refused("awk 'BEGIN{print \"x\" | \"input tap 1 1\"}'"))
    check("W49 pure-literal getline-pipe sink unchanged (plain and var form)",
        allowed("awk 'BEGIN{\"sort\" | getline}'") &&
            allowed("awk 'BEGIN{\"sort\" | getline line}'") &&
            refused("awk 'BEGIN{\"input tap 1 1\" | getline}'"))
    check("W49 pure-literal coprocess sinks unchanged (both directions)",
        allowed("awk 'BEGIN{print \"x\" |& \"sort\"}'") &&
            allowed("awk 'BEGIN{\"sort\" |& getline}'") &&
            refused("awk 'BEGIN{print \"x\" |& \"input tap 1 1\"}'") &&
            refused("awk 'BEGIN{\"input tap 1 1\" |& getline}'"))
    check("W49 joined literals at pipe sinks keep W45 treatment (re-pin)",
        allowed("awk 'BEGIN{print \"a\" \"b\" | \"sort\"}'") &&
            refused("awk 'BEGIN{print \"x\" | \"in\" \"put tap 1 1\"}'") &&
            refused("awk 'BEGIN{\"in\" \"put tap 1 1\" | getline}'"))

    // ============ File redirection is not a command sink ============
    check("W49 file redirection with literal filename allowed (write, append, read)",
        allowed("awk 'BEGIN{print \"x\" > \"file\"}'") &&
            allowed("awk 'BEGIN{print \"x\" >> \"file\"}'") &&
            allowed("awk 'BEGIN{getline < \"file\"}'"))
    check("W49 file redirection with variable filename allowed (not a sink)",
        allowed("awk 'BEGIN{print \"x\" > f}'") &&
            allowed("awk 'BEGIN{print \"x\" >> c}'") &&
            allowed("awk 'BEGIN{getline line < f}'") &&
            allowed("awk 'BEGIN{c=\"file\"; print \"x\" > c}'") &&
            allowed("awk 'BEGIN{c=\"file\"; getline < c}'"))
    check("W49 denied-content filename literal refusal unchanged (pre-existing view, not the sink scan)",
        refused("awk 'BEGIN{print \"x\" > \"input tap 1 1\"}'"))

    // ============ Pipes in data are not sinks ============
    check("W49 pipe inside regex, string and split separator stays allowed",
        allowed("awk '/a|b/ {print}'") &&
            allowed("awk 'BEGIN{if (x ~ /a|b/) print}'") &&
            allowed("awk 'BEGIN{print \"a|b\"}'") &&
            allowed("awk 'BEGIN{split(\"a|b\",arr,\"|\"); print arr[1]}'"))
    check("W49 close() of a pipe name is not an execution sink (unchanged)",
        allowed("awk 'BEGIN{close(c)}'") &&
            allowed("awk 'BEGIN{print \"x\" | \"sort\"; close(\"sort\")}'"))

    // ============ Benign programs and prior-wave re-pins ============
    check("W49 benign awk programs without command sinks allowed (re-pin)",
        allowed("awk '{print}'") &&
            allowed("awk '{print \"a\" \$1 | \"sort\"}'") &&
            allowed("awk -F: '{print \$1}' /etc/passwd"))
    check("W49 regression prior refusals still refuse",
        refused("input tap 1 1") &&
            refused("awk -f prog") &&
            refused("awk 'BEGIN{system(\"in\" \"put tap 1 1\")}'") &&
            refused("awk 'BEGIN{system(\"in\" x)}'") &&
            refused("awk 'BEGIN{\"in\" x | getline}'"))

    println("W49ShellFilterTest: $passes PASS / $failures FAIL")
    if (failures > 0) kotlin.system.exitProcess(1)
}
