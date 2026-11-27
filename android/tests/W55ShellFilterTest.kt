// Wave 55 Lane A — P1-F1 ROUND-14 remainder pins (Android).
// Round 14 (W54 confirmation) returned FIX-INADEQUATE on
// W53 claim (a) on packet-evidence grounds ONLY: DeepSeek
// traced the two BACKTICK recording sites (scanSegments
// and normaliseExpansions record bodies verbatim, without
// deleting a backslash-LF pair) and its packet excerpt of
// shellInputRefused cut off at line 1140 — four lines
// before the inners recursion at 1144-1150:
//
//   // Substitution bodies are commands in their own right.
//   if (depth < 3) { for (inner in inners.distinct()) {
//       if (inner.isNotBlank() &&
//           shellInputRefused(inner, ownPackage, depth + 1))
//           return true } }
//
// SETTLED IN W55 (probe harness against the CURRENT filter,
// pre-pin, plus no-pair controls): the verbatim counter-
// example `` `in\<LF>put tap 1 1` `` is REFUSED — the
// recursion re-parses the recorded body as its own command
// line in the unquoted top-level context, whose views
// delete the pair and judge the joined verb. The code was
// correct; the defect was the packet's missing excerpt
// plus this missing pin set. NO production code changed
// in W55. Shell ground truth (bash, this VM): a backtick
// body with the pair split across a verb executes the
// joined verb (captured output proves the join), in bare
// and double-quoted positions alike.
// Two REFUSED shapes below are named honestly as
// PRE-EXISTING fail-closed posture, not continuation
// behaviour, each pinned WITH its no-pair control so the
// round-15 packet can see the pair is not the cause:
//  (i) a double-quoted pure substitution command word is
//      not a resolvable form (the no-pair twin refuses
//      identically);
//  (ii) a pure substitution whose producer result carries
//      whitespace (a quoted multi-word argument) is
//      unresolved in command position (no-pair twin
//      refuses identically).
// One pair-caused OVER-refusal is also pinned as current
// behaviour (safe direction, no fix taken): extraction of
// a backtick body by the real shell deletes a backslash-LF
// even inside single quotes WITHIN the body (the body's
// own quote parsing happens after extraction), while the
// recursion's re-parse keeps the pair inside those single
// quotes and the resulting literal carries the LF, so a
// benign single-quoted-literal backtick body refuses as
// an unresolved pure substitution. The dangerous mirror
// (a single-quoted PAYLOAD inside the body) still refuses
// via the payload re-parse, pinned below. Blast radius
// probed: backtick bodies with legitimate backslashes
// (\$HOME form, \` escape, \\ and \n forms) keep exactly
// their pre-W55 verdicts — no production change, so no
// verdict in any prior suite moves. Pure/model only.
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
    val LF = "\n"
    val BS = "\\"

    // ============ The round-14 counter-example, verbatim ============
    check("W55 verbatim backtick continuation refused (inners recursion judges joined body)",
        refused("`in${BS}${LF}put tap 1 1`"))
    check("W55 dollar-paren twin continuation refused",
        refused("\$(in${BS}${LF}put tap 1 1)"))
    check("W55 backtick inside double quotes continuation refused",
        refused("\"`in${BS}${LF}put tap 1 1`\"") &&
            refused("echo \"`in${BS}${LF}put tap 1 1`\""))
    check("W55 backtick body in sh payload continuation refused",
        refused("sh -c '`in${BS}${LF}put tap 1 1`'"))

    // ============ Pair inside quotes WITHIN the body ============
    check("W55 pair inside double quotes within backtick body refused",
        refused("`\"in${BS}${LF}put\" tap 1 1`"))
    check("W55 pair inside single-quoted payload within backtick body refused",
        refused("`sh -c 'in${BS}${LF}put tap 1 1'`"))
    check("W55 regulated names split in backtick body refused (monkey, am)",
        refused("`monk${BS}${LF}ey -p com.other`") &&
            refused("`a${BS}${LF}m start -n io.deskguest.app/.MainActivity`"))

    // ============ Benign controls: joined body is benign ============
    check("W55 benign verb split in backtick body allowed",
        allowed("`ec${BS}${LF}ho hi`"))
    check("W55 benign verb split in dollar-paren body allowed",
        allowed("\$(ec${BS}${LF}ho hi)"))
    check("W55 benign split substitution in argument position allowed",
        allowed("echo `ec${BS}${LF}ho hi`") &&
            allowed("echo `echo hi`"))

    // ============ Blast radius: legitimate backslashes in bodies ============
    check("W55 backtick bodies with legitimate backslashes keep verdicts",
        allowed("`echo ${BS}\$HOME`") &&
            allowed("`echo a${BS}`b`") &&
            allowed("`echo a${BS}${BS}b`") &&
            allowed("`echo a${BS}nb`") &&
            allowed("`echo hi`"))

    // ============ Named pre-existing fail-closed shapes (pair-independent) ============
    check("W55 double-quoted pure substitution refuses with and without the pair",
        refused("\"`ec${BS}${LF}ho hi`\"") &&
            refused("\"`echo hi`\""))
    check("W55 quoted multi-word producer result refuses with and without the pair",
        refused("`echo \"ec${BS}${LF}ho hi\"`") &&
            refused("`echo \"echo hi\"`"))
    check("W55 single-quoted literal backtick body over-refuses (named, safe direction)",
        refused("`echo 'a${BS}${LF}b'`") &&
            allowed("`echo 'ab'`") &&
            allowed("echo 'a${BS}${LF}b'"))

    println("W55ShellFilterTest: $passes PASS / $failures FAIL")
    if (failures > 0) kotlin.system.exitProcess(1)
}
