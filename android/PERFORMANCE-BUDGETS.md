# DeskGuest — Performance Budgets (Android)

Created 2026-11-23, Wave 11 Lane B, as the artefact behind the
FEATURES §11 "Performance budgets" entry. Rule for this file:
every number below is either (a) a budget enforced in code, named
with its source, or (b) a measurement from a named run on a named
date. Anything not yet measured is listed under NOT MEASURED —
never estimated, never rounded into a claim.

## Budgets enforced in code today

| Budget | Value | Enforced at |
|---|---|---|
| Snapshot element cap | 1,500 elements | `access/SnapshotStore.kt` MAX_NODES — a cut snapshot marks itself TRUNCATED and the tool result says so |
| Snapshot tree-depth cap | 35 levels | `access/SnapshotStore.kt` MAX_DEPTH |
| Shell/tool output cap | per-tool caps (logcat lines, notify chars, file bytes) | `server/ShellToolHost.kt`, `server/OwedToolHost.kt`, `server/FileScope.kt` |
| Replay record bound | 2,000 entries, oldest-drop counted | `server/ReplayLog.kt` MAX_ENTRIES |
| Notification cache bound | 50 entries, 500 chars per field | `notify/NotificationCache.kt` |
| App-card store bound | 100 cards, 2,000 chars per note | `access/AppCards.kt` |

## Measured (this VM, 2026-11-23, Wave 11 Lane B run)

| Measurement | Value | Source |
|---|---|---|
| Full Android JVM suite wall time | 86 s | `builds/w11-suites.sh` run, log `builds/completion-logs/w11-and-suites.log` |
| JVM suite result in that run | 3,516 checks, 0 FAIL, every suite rc=0 | same log |
| Manual APK build | completes; DEX gate 3,195 classes | `builds/completion-logs/w11-build-manual.log` |

These are VM-side build/test numbers. They say nothing about
on-device cold start or frame times — see below.

## NOT MEASURED / NOT BUILT (de-scoped legs, named plainly)

- **Baseline profiles / macrobenchmarks: NOT BUILT.** No
  baseline-profile artefact or macrobenchmark module exists in
  either tree (verified by the Wave 10 trace audit, §1a §11).
  The original FEATURES wording claimed them "in CI"; that claim
  is withdrawn in FEATURES §11 (2026-11-23 amendment).
- **On-device vitals gates (crash % / ANR % as release blockers):
  NOT MEASURED.** This product ships no telemetry (§13 NEVER
  list), so no vitals stream exists to gate on; the Play-vitals
  figures in the original entry (1.09% crash, 0.47% ANR) are
  platform bad-behaviour thresholds, not measurements of this
  app, and are no longer stated as this product's budgets.
- **Cold-start budget: NOT SET.** No on-device cold-start
  measurement has been taken (device-proof class). A number will
  be added here only when a real device run produces one.

What stands instead, honestly: the in-code caps above (which keep
the agent-facing surfaces bounded by construction) and the JVM
suite as the regression gate. If device profiling is ever run,
its numbers land in this file with their run named.
