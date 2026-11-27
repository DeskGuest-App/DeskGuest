#!/usr/bin/env bash
# VM-side test suites for the server core (SPEC §10 S1 gate):
#  1. Every JVM suite under tests/ — compiled together with every
#     non-Android app source and run, one JVM per suite.
#  2. HTTP flow — the real McpHttpServer over real sockets, driven by a
#     Python client (JVM-originated loopback connects are reset in this
#     sandbox; native clients connect cleanly — see BUILD-LOG.md).
#
# W13 repair: the previous version carried a HAND-MAINTAINED source
# list that went stale — it omitted the design/chat/update sources
# its own test list needed and failed to compile even on an
# unchanged tree. Sources and suites are now DISCOVERED: every
# app source that does not import android.* (the JVM-compilable
# tree) and every tests/*Test.kt with a main. Adding a source or a
# suite needs no edit here — that is the point of the repair.
set -uo pipefail
cd "$(dirname "$0")"
export JAVA_HOME=$HOME/workspace/tools/jdk-17
export PATH=$JAVA_HOME/bin:$PATH
KOTLINC=$HOME/workspace/tools/kotlinc/bin/kotlinc
JSON_JAR=$HOME/workspace/tools/downloads/json.jar
STDLIB=$HOME/workspace/tools/kotlinc/lib/kotlin-stdlib.jar
OUT=/tmp/deskguest-tests
WORK=/tmp/deskguest-http
rm -rf "$OUT" "$WORK"; mkdir -p "$OUT" "$WORK"

mapfile -t SRCS < <(grep -rL "^import android" app/src/main/java --include=*.kt | sort)
mapfile -t TESTS < <(ls tests/*Test.kt | sort)
mapfile -t TESTSRCS < <(ls tests/*.kt | sort)
echo "compiling ${#SRCS[@]} app sources + ${#TESTSRCS[@]} test files"
"$KOTLINC" -classpath "$JSON_JAR" -d "$OUT" "${SRCS[@]}" "${TESTSRCS[@]}"
COMPILE_RC=$?
if [ $COMPILE_RC -ne 0 ]; then
  echo "COMPILE FAILED rc=$COMPILE_RC"
  exit $COMPILE_RC
fi

CP="$OUT:$JSON_JAR:$STDLIB"
ROOT=$PWD
XCHECK=/tmp/deskguest-xcheck
rm -rf "$XCHECK"
python3 tests/make_manifest_fixture.py "$XCHECK" >/dev/null

TOTAL_PASS=0; TOTAL_FAIL=0; FAILED_SUITES=""
run_suite() {
  local cls="$1"; shift
  local out rc p fl extra
  out=$(timeout 600 java -classpath "$CP" "$cls" "$@" 2>&1); rc=$?
  p=$(printf '%s' "$out" | grep -c "^PASS" || true)
  fl=$(printf '%s' "$out" | grep -c "^FAIL" || true)
  extra=$(printf '%s' "$out" | grep -oE "[0-9]+ checks PASS|ALL [0-9]+ CHECKS PASS" | grep -oE "[0-9]+" | head -1)
  if [ -n "$extra" ]; then p=$extra; fi
  TOTAL_PASS=$((TOTAL_PASS + p)); TOTAL_FAIL=$((TOTAL_FAIL + fl))
  echo "SUITE $cls rc=$rc pass=$p fail=$fl"
  if [ "$fl" != "0" ] || [ "$rc" != "0" ]; then
    FAILED_SUITES="$FAILED_SUITES $cls"
    printf '%s\n' "$out" | grep -E "^FAIL|Exception|Caused" | head -n 10
  fi
}

for f in "${TESTS[@]}"; do
  n=$(basename "$f" .kt)
  # ManifestVerifierTest takes fixture-dir arguments; it runs in
  # its arg form below, not in this loop.
  if [ "$n" = "ManifestVerifierTest" ]; then continue; fi
  if grep -q "object $n" "$f" && grep -q "@JvmStatic" "$f"; then
    run_suite "$n" "$ROOT"
  else
    run_suite "${n}Kt" "$ROOT"
  fi
done
# ManifestVerifierTest needs its fixture dirs as arguments (it also
# ran in the loop above with the tree root; the arg form is the
# authoritative one — both must pass).
run_suite ManifestVerifierTestKt "$XCHECK" "$HOME/.config/deskguest"

java -classpath "$CP" HttpServerMainKt "$WORK" &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null || true' EXIT
for i in $(seq 1 50); do [ -f "$WORK/ready.txt" ] && break; sleep 0.2; done
python3 tests/http_flow.py "$WORK/code.txt"
HTTP_RC=$?
kill $SERVER_PID 2>/dev/null || true
trap - EXIT
echo "HTTP flow rc=$HTTP_RC"

echo "TOTAL pass=$TOTAL_PASS fail=$TOTAL_FAIL"
if [ "$TOTAL_FAIL" != "0" ] || [ -n "$FAILED_SUITES" ] || [ $HTTP_RC -ne 0 ]; then
  echo "FAILED SUITES:$FAILED_SUITES"
  exit 1
fi
echo "ALL SUITES DONE"
