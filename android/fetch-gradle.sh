#!/usr/bin/env bash
# Fetch the Gradle 8.14.3 distribution to the home disk (/tmp is a 512 MB
# tmpfs — too small for the 131 MB archive plus working files).
set -uo pipefail
LOG=$HOME/workspace/agent-control-app/android/toolchain-setup.log
exec >> "$LOG" 2>&1
echo "== gradle fetch v2 $(date -Is) =="
mkdir -p "$HOME/workspace/tools/downloads"
DEST=$HOME/workspace/tools/downloads/gradle-8.14.3-bin.zip
ok=0
for u in \
  "https://github.com/gradle/gradle-distributions/releases/download/v8.14.3/gradle-8.14.3-bin.zip" \
  "https://services.gradle.org/distributions/gradle-8.14.3-bin.zip" ; do
  echo "trying $u"
  if curl -fL -C - --retry 8 --retry-all-errors --retry-delay 5 --connect-timeout 30 -o "$DEST" "$u"; then
    echo "downloaded from $u"; ok=1; break
  fi
done
[ "$ok" = 1 ] || { echo "FAIL: gradle download all sources"; exit 1; }
unzip -q -o "$DEST" -d "$HOME/workspace/tools" && echo "gradle unzipped"
"$HOME/workspace/tools/gradle-8.14.3/bin/gradle" --version 2>/dev/null | grep -E "^Gradle"
echo "== gradle fetch v2 done =="
