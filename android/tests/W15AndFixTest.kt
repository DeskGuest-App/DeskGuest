// Wave 15 Lane B — round-2 re-pass inadequacies (Android).
// P1-F2 GENUINELY OVERTURNED: a non-null node can expose a null
// packageName — the node ACTION decision is now fail-closed
// (GateModel.nodeTargetRefused), consulted by every action path in
// ControlAccessibilityService that consults a target package.
// P1-F1 FIX-INADEQUATE: shellInputRefused now covers the
// cmd activity / cmd package / cmd input equivalents of am/pm/input
// and shell indirection (backticks, $(...), $VAR naming a dangerous
// verb, assignments carrying a dangerous value, and an unresolvable
// $VAR command word in an input-verb / self-target context).
// Pure/model layer + source pins over the real call sites.
// Args: [0] = android project dir.
import io.deskguest.app.design.GateModel
import java.io.File

private var failures = 0
private var passes = 0
private fun check(name: String, cond: Boolean) {
    if (cond) { passes++; println("PASS $name") } else { failures++; println("FAIL $name") }
}

fun main(args: Array<String>) {
    val root = args.getOrNull(0) ?: "."
    val own = "io.deskguest.app"

    // ================= P1-F2: node action decision =================
    check("W15 P1-F2 node decision refuses a NULL package (live null-package node)",
        GateModel.nodeTargetRefused(null, own))
    check("W15 P1-F2 node decision refuses an empty package",
        GateModel.nodeTargetRefused("", own))
    check("W15 P1-F2 node decision refuses a blank package",
        GateModel.nodeTargetRefused("   ", own))
    check("W15 P1-F2 node decision refuses DeskGuest's own package",
        GateModel.nodeTargetRefused(own, own))
    check("W15 P1-F2 node decision allows a named other package",
        !GateModel.nodeTargetRefused("com.other.app", own))
    check("W15 P1-F2 classification kept distinct: null is not DeskGuest as a fact, yet the action refuses",
        !GateModel.targetIsDeskGuestWindow(null, own) && GateModel.nodeTargetRefused(null, own))
    check("W15 P1-F2 coordinate decision still fail-closed (null/blank/own refuse, other allows)",
        GateModel.coordinateTargetRefused(null, own) &&
            GateModel.coordinateTargetRefused(" ", own) &&
            GateModel.coordinateTargetRefused(own, own) &&
            !GateModel.coordinateTargetRefused("com.other.app", own))

    // Source pins: the branch is on EVERY action path that consults
    // a target package in the service — tap (node), type (node),
    // launch (requested package) — and the gesture paths keep the
    // fail-closed coordinate decision.
    val a11y = File(root, "app/src/main/java/io/deskguest/app/access/ControlAccessibilityService.kt").readText()
    check("W15 P1-F2 pin: service's targetIsOwnWindow delegates to the fail-closed node decision",
        a11y.contains("GateModel.nodeTargetRefused(targetPackage, packageName)"))
    check("W15 P1-F2 pin: tapByRef consults it on the live node before performAction/tapAt",
        a11y.contains("targetIsOwnWindow(live.packageName") &&
            a11y.indexOf("targetIsOwnWindow(live.packageName") <
                a11y.indexOf("live.performAction"))
    check("W15 P1-F2 pin: typeText consults it on the target node before SET_TEXT",
        a11y.contains("targetIsOwnWindow(node.packageName") &&
            a11y.indexOf("targetIsOwnWindow(node.packageName") <
                a11y.indexOf("ACTION_SET_TEXT"))
    check("W15 P1-F2 pin: launchApp consults it on the requested package",
        a11y.contains("if (targetIsOwnWindow(packageName)) return false"))
    check("W15 P1-F2 pin: tapAt + swipe keep the fail-closed coordinate decision (2 call sites)",
        a11y.split("GateModel.coordinateTargetRefused(currentAppPackage(), packageName)").size - 1 == 2)

    // ================= P1-F1: cmd equivalents =================
    check("W15 P1-F1 cmd activity force-stop own refused",
        GateModel.shellInputRefused("cmd activity force-stop $own", own))
    check("W15 P1-F1 cmd activity kill own refused",
        GateModel.shellInputRefused("cmd activity kill $own", own))
    check("W15 P1-F1 cmd activity start own refused",
        GateModel.shellInputRefused("cmd activity start -n $own/.MainActivity", own))
    check("W15 P1-F1 cmd package clear own refused",
        GateModel.shellInputRefused("cmd package clear $own", own))
    check("W15 P1-F1 cmd package uninstall own refused",
        GateModel.shellInputRefused("cmd package uninstall $own", own))
    check("W15 P1-F1 cmd package path own refused",
        GateModel.shellInputRefused("cmd package path $own", own))
    check("W15 P1-F1 path-prefixed cmd activity own refused",
        GateModel.shellInputRefused("/system/bin/cmd activity force-stop $own", own))
    check("W15 P1-F1 flagged cmd activity own refused (flag before subcommand)",
        GateModel.shellInputRefused("cmd -w activity force-stop $own", own))
    check("W15 P1-F1 cmd input tap refused (cmd form of the input binary)",
        GateModel.shellInputRefused("cmd input tap 1 1", own))
    check("W15 P1-F1 cmd input swipe refused",
        GateModel.shellInputRefused("cmd input swipe 1 2 3 4", own))
    check("W15 P1-F1 quoted cmd activity own refused",
        GateModel.shellInputRefused("sh -c 'cmd activity force-stop $own'", own))
    check("W15 P1-F1 cmd forms naming ANOTHER package stay allowed",
        !GateModel.shellInputRefused("cmd activity start -n com.other/.Main", own) &&
            !GateModel.shellInputRefused("cmd package path com.other", own) &&
            !GateModel.shellInputRefused("cmd package list packages", own))
    check("W15 P1-F1 unrelated cmd subcommand stays allowed (cmd is not blanket-refused)",
        !GateModel.shellInputRefused("cmd activity top", own) &&
            !GateModel.shellInputRefused("cmd statusbar expand", own))

    // ================= P1-F1: indirection =================
    check("W15 P1-F1 backticked am naming own refused",
        GateModel.shellInputRefused("`am` force-stop $own", own))
    check("W15 P1-F1 backticked input refused",
        GateModel.shellInputRefused("echo `input tap 1 1`", own))
    check("W15 P1-F1 assignment carrying input, invoked via var, refused",
        GateModel.shellInputRefused("V=input; \$V tap 1 1", own))
    check("W15 P1-F1 assignment carrying am, invoked via var on own, refused",
        GateModel.shellInputRefused("V=am; \$V force-stop $own", own))
    check("W15 P1-F1 var reference naming input refuses",
        GateModel.shellInputRefused("\$INPUT tap 1 1", own))
    check("W15 P1-F1 braced var reference naming am refuses",
        GateModel.shellInputRefused("\${AM} force-stop $own", own))
    check("W15 P1-F1 var reference naming cmd refuses",
        GateModel.shellInputRefused("\$CMD activity force-stop $own", own))
    check("W15 P1-F1 var reference naming pm refuses",
        GateModel.shellInputRefused("\$PM clear $own", own))
    check("W15 P1-F1 var reference naming monkey refuses",
        GateModel.shellInputRefused("\$MONKEY -p $own 10", own))
    check("W15 P1-F1 unresolvable var command word + tap refuses (fail-closed indirection)",
        GateModel.shellInputRefused("\$X tap 1 1", own))
    check("W15 P1-F1 unresolvable braced var command word + swipe refuses",
        GateModel.shellInputRefused("\${X} swipe 1 2 3 4", own))
    check("W15 P1-F1 unresolvable var command word inside backticks + tap refuses",
        GateModel.shellInputRefused("`\$X tap 1 1`", own))
    check("W15 P1-F1 unresolvable var command word inside substitution + tap refuses",
        GateModel.shellInputRefused("echo \$(\$X tap 1 1)", own))
    check("W15 P1-F1 unresolvable var command word naming own package refuses",
        GateModel.shellInputRefused("\$X force-stop $own", own))
    check("W15 P1-F1 quote-concatenated input refuses (in\"put\")",
        GateModel.shellInputRefused("in\"put\" tap 1 1", own))
    check("W15 P1-F1 backslash-split input refuses (in\\put)",
        GateModel.shellInputRefused("in\\put tap 1 1", own))
    check("W15 P1-F1 quote-split input refuses ('in''put')",
        GateModel.shellInputRefused("'in''put' tap 1 1", own))
    check("W15 P1-F1 ordinary variable expansions stay allowed (no verb named, no input context)",
        !GateModel.shellInputRefused("echo \$HOME", own) &&
            !GateModel.shellInputRefused("ls \${HOME}/docs", own) &&
            !GateModel.shellInputRefused("echo \$PATH", own) &&
            !GateModel.shellInputRefused("\$HOME/bin/tool run", own))
    check("W15 P1-F1 ordinary shell still allowed (regression floor)",
        !GateModel.shellInputRefused("settings get global device_name", own) &&
            !GateModel.shellInputRefused("dumpsys battery", own) &&
            !GateModel.shellInputRefused("pm list packages", own) &&
            !GateModel.shellInputRefused("am start -n com.other/.Main", own) &&
            !GateModel.shellInputRefused("logcat -d", own))

    println("W15AndFixTest: $passes PASS / $failures FAIL")
    if (failures > 0) kotlin.system.exitProcess(1)
}
