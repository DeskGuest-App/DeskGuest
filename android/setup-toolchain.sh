#!/usr/bin/env bash
# DeskGuest — toolchain setup v3 (single run, fails whole).
# Why v3: this VM's egress proxy breaks the JDK's built-in HTTP tunnelling
# (sdkmanager dies in HttpURLConnection.doTunneling0 even with proxy -D
# flags). curl handles the proxy fine, so SDK packages are fetched with
# curl from Google's official repository manifest and laid down manually.
# License files below carry Google's published acceptance hashes — the
# same values `sdkmanager --licenses` writes after a yes.
set -uo pipefail
export JAVA_HOME=$HOME/workspace/tools/jdk-21
export PATH=$JAVA_HOME/bin:$PATH
SDK=$HOME/workspace/tools/android-sdk
mkdir -p "$SDK/platforms" "$SDK/build-tools" "$SDK/licenses"
LOG=$HOME/workspace/agent-control-app/android/toolchain-setup.log
exec > >(tee -a "$LOG") 2>&1
echo "== toolchain setup v3 $(date -Is) =="

# --- licenses (published acceptance hashes) ---
printf '8933bad161af4178b1185d1a37fbf41ea5269c55\nd56f5187479451eabf01fb78af6dfcb131a6481e\n24333f8a63b6825ea9c5514f83c2829b004d1fee\n' > "$SDK/licenses/android-sdk-license"
printf '84831b9409646a918e30573bab4c9c91346d8abd\n' > "$SDK/licenses/android-sdk-preview-license"

# --- resolve exact archive URLs from the official manifest ---
curl -sf https://dl.google.com/android/repository/repository2-3.xml -o /tmp/repo.xml || { echo "FAIL: manifest fetch"; exit 1; }
read -r PLATFORM_URL BT_URL <<< "$(python3 - <<'PY'
import xml.etree.ElementTree as ET
ns = {'r': 'http://schemas.android.com/repository/android/common/02',
      'a': 'http://schemas.android.com/sdk/android/repo/addon2/03',
      's': 'http://schemas.android.com/sdk/android/repo/sys-img2/03',
      'repo': 'http://schemas.android.com/sdk/android/repo/repository2/03'}
tree = ET.parse('/tmp/repo.xml')
root = tree.getroot()
def tag(e): return e.tag.split('}')[-1]
want = {'platforms;android-36': None, 'build-tools;36.0.0': None}
for pkg in root.iter():
    if tag(pkg) != 'remotePackage': continue
    path = pkg.get('path')
    if path not in want: continue
    # stable channel only
    chans = [c.get('ref') for c in pkg.iter() if tag(c) == 'channelRef']
    if 'channel-0' not in chans: continue
    for arch in pkg.iter():
        if tag(arch) != 'archive': continue
        os_el = [e for e in arch.iter() if tag(e) == 'host-os']
        if os_el and os_el[0].text != 'linux': continue
        url = [e for e in arch.iter() if tag(e) == 'url'][0].text
        want[path] = 'https://dl.google.com/android/repository/' + url
print(want['platforms;android-36'], want['build-tools;36.0.0'])
PY
)"
echo "platform archive: $PLATFORM_URL"
echo "build-tools archive: $BT_URL"
[ -n "$PLATFORM_URL" ] && [ -n "$BT_URL" ] && [ "$PLATFORM_URL" != "None" ] && [ "$BT_URL" != "None" ] || { echo "FAIL: archive resolution"; exit 1; }

dl() { # url destdir
  local f=/tmp/$(basename "$1")
  curl -fL --retry 2 -o "$f" "$1" || return 1
  unzip -q -o "$f" -d "$2"
}

# --- platform-tools ---
if [ ! -x "$SDK/platform-tools/adb" ]; then
  dl https://dl.google.com/android/repository/platform-tools-latest-linux.zip "$SDK" || { echo "FAIL: platform-tools"; exit 1; }
fi
# --- platform android-36 (zip root folder is android-36) ---
if [ ! -f "$SDK/platforms/android-36/android.jar" ]; then
  dl "$PLATFORM_URL" "$SDK/platforms" || { echo "FAIL: platform"; exit 1; }
fi
# --- build-tools 36.0.0 (zip root folder varies; normalize) ---
if [ ! -x "$SDK/build-tools/36.0.0/aapt2" ]; then
  dl "$BT_URL" /tmp/bt-extract || { echo "FAIL: build-tools download"; exit 1; }
  src=$(find /tmp/bt-extract -name aapt2 -printf '%h' -quit)
  [ -n "$src" ] || { echo "FAIL: build-tools layout"; exit 1; }
  mkdir -p "$SDK/build-tools/36.0.0"
  cp -r "$src"/. "$SDK/build-tools/36.0.0"/
  chmod +x "$SDK/build-tools/36.0.0"/* 2>/dev/null || true
fi

# --- gradle ---
if [ ! -x "$HOME/workspace/tools/gradle-8.14.3/bin/gradle" ]; then
  curl -fL --retry 2 -o /tmp/gradle.zip https://services.gradle.org/distributions/gradle-8.14.3-bin.zip || { echo "FAIL: gradle download"; exit 1; }
  unzip -q -o /tmp/gradle.zip -d "$HOME/workspace/tools"
fi

echo "--- verification ---"
"$SDK/platform-tools/adb" --version | head -1
ls -la "$SDK/platforms/android-36/android.jar"
"$SDK/build-tools/36.0.0/aapt2" version
"$HOME/workspace/tools/gradle-8.14.3/bin/gradle" --version 2>/dev/null | grep -E "Gradle|JVM" | head -3
echo "== toolchain setup v3 complete =="
