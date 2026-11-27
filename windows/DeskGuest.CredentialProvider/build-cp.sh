#!/usr/bin/env bash
# Cross-compile the DeskGuest credential provider with mingw-w64 (GCC 13.2,
# installed on the build VM). Output: DeskGuestCredentialProvider.dll (x64 PE).
set -euo pipefail
cd "$(dirname "$0")"
x86_64-w64-mingw32-g++ -std=c++17 -O2 -shared -static \
  -o DeskGuestCredentialProvider.dll DeskGuestCredentialProvider.cpp DeskGuestCredentialProvider.def \
  -lole32 -lsecur32 -ladvapi32 -luuid
echo "built: $(file DeskGuestCredentialProvider.dll)"
