// Wave 53 Lane A — P1-F1 ROUND-13 pins (Android).
// round-13 (W52 confirmation) returned FIX-INADEQUATE on
// the W51 filter via TWO breaks, both probed against
// pre-W53 code first (W53 lane log has the probe tables):
//  (1) BACKSLASH-LF LINE CONTINUATION. POSIX/mksh delete
//  a backslash immediately followed by a newline in
//  unquoted and double-quoted contexts, so
//  `sh -c "in\<LF>put tap 1 1"` executes `input tap 1 1`;
//  pre-W53 every text-assembly path kept the LF, the
//  recursion split at it, and no verb was judged — the
//  counter-example and its whole neighbourhood (top-level
//  unquoted, single-quoted payload, unquoted payload
//  token, depth 2, monkey / cmd-slot / awk-name / sh-name
//  splits, eval, awk string literals) were ALLOWED
//  pre-W53. The fix is per-context fidelity at every
//  assembly/split point (scanSegments unquoted and
//  double-quoted branches, normaliseExpansions and the
//  legacy view outside single quotes, extractPayload-
//  Literal's unquoted and double-quoted branches,
//  unescapeAwkString and the awk program-text pass):
//  the pair is DELETED where the shell deletes it and
//  KEPT where the shell keeps it (single-quoted spans —
//  carried verbatim into the recursion, which judges it
//  in the inner context; ANSI-C $'...' — probed against
//  bash, the pair is literal there). Benign commands
//  split across lines stay allowed; a single-quoted
//  backslash-LF literal is judged as the literal it is.
//  (2) \x IN AWK STRING LITERALS IS UNEXTRACTABLE.
//  The W51 superset argument for hex-decoding \xhh is
//  rejected (round-13 residual R2): under a BWK
//  literal-char reading \x27 is the text `x27`, not a
//  quote, so syntax the hex reading makes inert stays
//  active in the executed command — a dangerous-
//  direction divergence — and which awk binary PATH
//  resolution selects is unknowable (BWK builds
//  themselves disagree on \x). unescapeAwkString now
//  returns null for \x in any form, joining \u/\U and
//  \e/\E; every caller refuses. NAMED FLIP: the W51 pin
//  `system("\x65cho hi")` (benign hex-decoded echo) was
//  ALLOWED pre-W53 and is REFUSED here — the W51 suite's
//  copy of that pin is updated in place (see its file).
//  Octal stays decoded (byte value agreed by BWK, mawk,
//  gawk, busybox — probed for BWK/mawk in the lane log).
//  Pure/model only.
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
    val LF = "\n"
    val BS = "\\"

    // ============ Point 1: the round-13 counter-example and its class ============
    check("W53 round-13 verbatim double-quoted payload split refused",
        refused("sh -c \"in${BS}${LF}put tap 1 1\""))
    check("W53 top-level unquoted verb split refused",
        refused("in${BS}${LF}put tap 1 1"))
    check("W53 single-quoted payload split refused (inner shell deletes)",
        refused("sh -c 'in${BS}${LF}put tap 1 1'"))
    check("W53 unquoted payload token split refused",
        refused("sh -c in${BS}${LF}put tap 1 1"))
    check("W53 depth-2 payload split refused",
        refused("sh -c 'sh -c \"in${BS}${LF}put tap 1 1\"'"))
    check("W53 regulated names split by continuation refused (monkey, cmd slot, am)",
        refused("monk${BS}${LF}ey -p com.other") &&
            refused("cmd in${BS}${LF}put tap 1 1") &&
            refused("a${BS}${LF}m start -n io.agenticcontrol.app/.MainActivity"))
    check("W53 interpreter names split by continuation refused (sh, awk)",
        refused("s${BS}${LF}h -c 'input tap 1 1'") &&
            refused("aw${BS}${LF}k 'BEGIN{system(\"input tap 1 1\")}'"))
    check("W53 eval argument split refused",
        refused("eval in${BS}${LF}put tap 1 1"))
    check("W53 double-quoted command word split refused",
        refused("\"in${BS}${LF}put\" tap 1 1"))

    // ============ Point 1 at the awk path ============
    check("W53 awk string literal continuation split refused (system)",
        refused("awk 'BEGIN{system(\"in${BS}${LF}put tap 1 1\")}'"))
    check("W53 awk string literal continuation split refused (print pipe)",
        refused("awk 'BEGIN{print \"x\" | \"in${BS}${LF}put tap 1 1\"}'"))
    check("W53 awk double-quoted program continuation split refused",
        refused("awk \"BEGIN{system(\\\"in${BS}${LF}put tap 1 1\\\")}\""))
    check("W53 awk program-text continuation before system refused",
        refused("awk 'BEGIN{syst${BS}${LF}em(\"input tap 1 1\")}'"))

    // ============ Point 1: benign continuations stay allowed ============
    check("W53 benign unquoted split command allowed",
        allowed("echo one ${BS}${LF} two"))
    check("W53 benign double-quoted split payload allowed",
        allowed("sh -c \"echo one ${BS}${LF} two\""))
    check("W53 benign single-quoted payload split allowed (judged inside)",
        allowed("sh -c 'echo one ${BS}${LF} two'"))
    check("W53 benign double-quoted joined argument allowed",
        allowed("echo \"a${BS}${LF}b\""))
    check("W53 awk benign string continuation allowed (echo joins, judged benign)",
        allowed("awk 'BEGIN{system(\"ec${BS}${LF}ho hi\")}'"))

    // ============ Point 1: single-quoted literal judged as the literal ============
    check("W53 single-quoted backslash-LF literal allowed as literal text",
        allowed("echo 'a${BS}${LF}b'") &&
            allowed("printf '%s' 'in${BS}${LF}put'"))
    check("W53 ANSI-C backslash-LF kept literal (probed bash) allowed",
        allowed("\$'in${BS}${LF}put' tap 1 1") &&
            allowed("echo \$'a${BS}${LF}b'"))

    // ============ Point 2: \x in awk literals refuses as unextractable ============
    check("W53 hex verb at awk system refused",
        refused("awk 'BEGIN{system(\"\\x69nput tap 1 1\")}'"))
    check("W53 hex at awk pipe sinks refused",
        refused("awk 'BEGIN{print \"x\" | \"\\x69nput tap 1 1\"}'") &&
            refused("awk 'BEGIN{\"\\x69nput tap 1 1\" | getline}'"))
    check("W53 hex quote form refused (round-13 R2 counter-example shape)",
        refused("awk 'BEGIN{system(\"echo \\x27; input tap 1 1; echo \\x27\")}'"))
    check("W53 benign hex sink command now refused (named flip of the W51 pin)",
        refused("awk 'BEGIN{system(\"\\x65cho hi\")}'"))
    check("W53 hex with no digit still refused",
        refused("awk 'BEGIN{system(\"\\x nput tap 1 1\")}'"))

    // ============ Point 2: octal and standard escapes unchanged ============
    check("W53 octal decoding unchanged (verb refused, benign allowed)",
        refused("awk 'BEGIN{system(\"\\151nput tap 1 1\")}'") &&
            allowed("awk 'BEGIN{system(\"\\145cho hi\")}'"))
    check("W53 standard-escape awk sink commands still allowed",
        allowed("awk 'BEGIN{system(\"echo\\thi\")}'") &&
            allowed("awk 'BEGIN{system(\"echo hi\")}'"))

    // ============ Prior-wave re-pins (unchanged) ============
    check("W53 regression prior refusals still refuse",
        refused("input tap 1 1") &&
            refused("sh -c \"input tap 1 1\"") &&
            refused("awk 'BEGIN{system(\"\\u0069nput tap 1 1\")}'") &&
            refused("\$'in\\x70ut' tap 1 1"))
    check("W53 regression benign forms still allowed",
        allowed("echo hi") &&
            allowed("sh -c 'echo hi'") &&
            allowed("awk 'BEGIN{print \"x\" | \"sort\"}'"))

    println("W53ShellFilterTest: $passes PASS / $failures FAIL")
    if (failures > 0) kotlin.system.exitProcess(1)
}
