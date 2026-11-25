#!/usr/bin/env bash
# DeskGuest — build runner.
#
# Why it looks like this (learned 2026-11-10, three failed builds):
# the sandbox breaks Gradle's client<->daemon localhost handshake, so
# builds must run IN-PROCESS: org.gradle.daemon=false (gradle.properties)
# plus a client JVM whose args exactly match org.gradle.jvmargs, which
# is what GRADLE_OPTS below guarantees. Dependency downloads use the
# proxy configured via systemProp in gradle.properties (host/port only;
# the proxy answers Google/Maven without authentication from here).
set -uo pipefail
cd "$(dirname "$0")"
export JAVA_HOME=$HOME/workspace/tools/jdk-21
export ANDROID_HOME=$HOME/workspace/tools/android-sdk
export ANDROID_SDK_ROOT=$ANDROID_HOME
export GRADLE_OPTS="-Xmx1024m -Dfile.encoding=UTF-8"
# Dedicated, project-owned Gradle home: tonight's failed runs left the
# shared /root/.gradle registry corrupted with stale daemon entries.
export GRADLE_USER_HOME="$HOME/workspace/tools/gradle-home"

exec "$HOME/workspace/tools/gradle-8.14.3/bin/gradle" "$@"
