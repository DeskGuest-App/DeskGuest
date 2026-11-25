#!/usr/bin/env bash
# DeskGuest — manual build pipeline.
#
# Why this exists: Gradle's client<->daemon protocol breaks in this VM's
# sandbox (verified across Gradle 8.13/8.14.3 and JDK 17/21 with a
# checksum-genuine distribution; the daemon receives the build, the reply
# stream fails deserialization). Every step below is a plain CLI process
# with no IPC protocol: aapt2 -> kotlinc -> d8 -> zipalign -> apksigner.
# Full account: BUILD-LOG.md.
set -euo pipefail
cd "$(dirname "$0")"
export JAVA_HOME=$HOME/workspace/tools/jdk-17
export PATH=$JAVA_HOME/bin:$PATH
SDK=$HOME/workspace/tools/android-sdk
BT=$SDK/build-tools/36.0.0
PLATFORM=$SDK/platforms/android-36/android.jar
KOTLINC=$HOME/workspace/tools/kotlinc/bin/kotlinc
STDLIB=$HOME/workspace/tools/kotlinc/lib/kotlin-stdlib.jar
OUT=app/build/manual
VERSION=$(grep -o 'android:versionName="[^"]*"' app/src/main/AndroidManifest.xml | cut -d'"' -f2)
APK_NAME="DeskGuest-${VERSION}.apk"
rm -rf "$OUT"; mkdir -p "$OUT/gen" "$OUT/classes" "$OUT/dex"

echo "[1/6] aapt2 compile resources"
"$BT/aapt2" compile --dir app/src/main/res -o "$OUT/res.zip"

echo "[2/6] aapt2 link (APK skeleton + R.java + bundled assets)"
"$BT/aapt2" link -o "$OUT/app-unsigned.apk" -I "$PLATFORM" \
  --manifest app/src/main/AndroidManifest.xml \
  -A app/src/main/assets \
  --java "$OUT/gen" --min-sdk-version 30 --target-sdk-version 36 \
  "$OUT/res.zip"

echo "[3/6] kotlinc (app sources + generated R)"
ANDROIDX_CORE=$HOME/workspace/tools/android-libs/core-1.13.1/classes.jar
find app/src/main/java "$OUT/gen" \( -name '*.kt' -o -name '*.java' \) > "$OUT/sources.txt"
"$KOTLINC" -classpath "$PLATFORM:$ANDROIDX_CORE" -d "$OUT/classes" @"$OUT/sources.txt"

echo "[4/6] d8 (dex, incl. Kotlin stdlib + AndroidX core for FileProvider)"
"$BT/d8" --min-api 30 --output "$OUT/dex" \
  $(find "$OUT/classes" -name '*.class') "$STDLIB" "$ANDROIDX_CORE"

echo "[5/6] package dex + zipalign"
# Every dex d8 emitted (classes.dex, classes2.dex, ...) — zipping only
# classes.dex would silently drop classes if d8 ever splits (the
# hazard banked in BUILD-LOG 2026-11-15, fixed in the 0.4.4 round).
(cd "$OUT/dex" && zip -q ../app-unsigned.apk classes*.dex)
"$BT/zipalign" -f 4 "$OUT/app-unsigned.apk" "$OUT/app-aligned.apk"

echo "[6/6] apksigner (release key by default; ACP_DEBUG_SIGN=1 for the debug key)"
if [ "${ACP_DEBUG_SIGN:-0}" = "1" ]; then
  KEYSTORE=$HOME/workspace/tools/debug.keystore
  if [ ! -f "$KEYSTORE" ]; then
    keytool -genkeypair -keystore "$KEYSTORE" -storepass android -keypass android \
      -alias androiddebugkey -keyalg RSA -keysize 2048 -validity 10000 \
      -dname "CN=Android Debug,O=Android,C=US" >/dev/null 2>&1
  fi
  KS_PASS=android; KEY_ALIAS=androiddebugkey
else
  KEYSTORE=$HOME/.config/agentic-control/release.keystore
  KS_PASS=$(cat "$HOME/.config/agentic-control/keystore-password")
  KEY_ALIAS=agentic-control
fi
"$BT/apksigner" sign --ks "$KEYSTORE" --ks-pass "pass:$KS_PASS" --key-pass "pass:$KS_PASS" \
  --ks-key-alias "$KEY_ALIAS" \
  --out "$OUT/$APK_NAME" "$OUT/app-aligned.apk"
"$BT/apksigner" verify "$OUT/$APK_NAME"

echo "[7/7] dex completeness gate (every manifest component defined in the dex)"
python3 ../scripts/check-dex.py "$OUT/$APK_NAME" app/src/main/AndroidManifest.xml

ls -la "$OUT/$APK_NAME"
echo "MANUAL BUILD OK"
