#!/usr/bin/env bash
# VM-side test suites for the server core (SPEC §10 S1 gate):
#  1. McpCoreTest — protocol + pairing logic, in-process.
#  2. HTTP flow — the real McpHttpServer over real sockets, driven by a
#     Python client (JVM-originated loopback connects are reset in this
#     sandbox; native clients connect cleanly — see BUILD-LOG.md).
set -euo pipefail
cd "$(dirname "$0")"
export JAVA_HOME=$HOME/workspace/tools/jdk-17
export PATH=$JAVA_HOME/bin:$PATH
KOTLINC=$HOME/workspace/tools/kotlinc/bin/kotlinc
JSON_JAR=$HOME/workspace/tools/downloads/json.jar
STDLIB=$HOME/workspace/tools/kotlinc/lib/kotlin-stdlib.jar
OUT=/tmp/deskguest-tests
WORK=/tmp/deskguest-http
rm -rf "$OUT" "$WORK"; mkdir -p "$OUT" "$WORK"

"$KOTLINC" -classpath "$JSON_JAR" -d "$OUT" \
  app/src/main/java/io/deskguest/app/server/McpCore.kt \
  app/src/main/java/io/deskguest/app/server/CommandGateWiring.kt \
  app/src/main/java/io/deskguest/app/server/McpHttpServer.kt \
  app/src/main/java/io/deskguest/app/server/PairingStore.kt \
  app/src/main/java/io/deskguest/app/server/SessionManager.kt \
  app/src/main/java/io/deskguest/app/server/SessionBudget.kt \
  app/src/main/java/io/deskguest/app/server/ClipboardPolicy.kt \
  app/src/main/java/io/deskguest/app/server/DataFlow.kt \
  app/src/main/java/io/deskguest/app/server/SessionEvents.kt \
  app/src/main/java/io/deskguest/app/server/BootRestartPolicy.kt \
  app/src/main/java/io/deskguest/app/server/AuditLog.kt \
  app/src/main/java/io/deskguest/app/server/ApprovalGate.kt \
  app/src/main/java/io/deskguest/app/access/WaitCondition.kt \
  app/src/main/java/io/deskguest/app/adb/Ed25519.kt \
  app/src/main/java/io/deskguest/app/adb/Spake25519.kt \
  app/src/main/java/io/deskguest/app/adb/Hkdf.kt \
  app/src/main/java/io/deskguest/app/adb/PairingCipher.kt \
  app/src/main/java/io/deskguest/app/adb/AdbProtocol.kt \
  app/src/main/java/io/deskguest/app/adb/AdbKey.kt \
  app/src/main/java/io/deskguest/app/adb/AdbIdentity.kt \
  app/src/main/java/io/deskguest/app/adb/AdbPairing.kt \
  app/src/main/java/io/deskguest/app/adb/TlsExporter.kt \
  app/src/main/java/io/deskguest/app/crypto/AesGcm.kt \
  app/src/main/java/io/deskguest/app/mesh/MeshProtocol.kt \
  app/src/main/java/io/deskguest/app/access/SnapshotStore.kt \
  app/src/main/java/io/deskguest/app/update/ManifestVerifier.kt \
  app/src/main/java/io/deskguest/app/presence/PresencePalette.kt \
  app/src/main/java/io/deskguest/app/strings/ConsentStrings.kt \
  app/src/main/java/io/deskguest/app/enrollment/DeviceIdentity.kt \
  app/src/main/java/io/deskguest/app/enrollment/Sas.kt \
  app/src/main/java/io/deskguest/app/enrollment/EnrollmentStore.kt \
  app/src/main/java/io/deskguest/app/enrollment/EnrollPayload.kt \
  app/src/main/java/io/deskguest/app/roster/TransportPolicy.kt \
  app/src/main/java/io/deskguest/app/roster/RosterStore.kt \
  app/src/main/java/io/deskguest/app/session/SessionStore.kt \
  app/src/main/java/io/deskguest/app/transport/Transport.kt \
  app/src/main/java/io/deskguest/app/transport/HubMesh.kt \
  app/src/main/java/io/deskguest/app/transport/TailscaleSetup.kt \
  app/src/main/java/io/deskguest/app/wiring/PlatformStores.kt \
  app/src/main/java/io/deskguest/app/wiring/PlatformToolHost.kt \
  app/src/main/java/io/deskguest/app/enterprise/Enterprise.kt \
  app/src/main/java/io/deskguest/app/transport/RemainingRungs.kt \
  app/src/main/java/io/deskguest/app/transport/TorProvisioning.kt \
  app/src/main/java/io/deskguest/app/transport/ConnectionDoctor.kt \
  app/src/main/java/io/deskguest/app/session/Terminal.kt \
  app/src/main/java/io/deskguest/app/crypto/SecondFactor.kt \
  app/src/main/java/io/deskguest/app/wake/Wake.kt \
  app/src/main/java/io/deskguest/app/session/StandaloneTransfers.kt \
  app/src/main/java/io/deskguest/app/session/SessionTunnels.kt \
  app/src/main/java/io/deskguest/app/quickassist/QuickAssist.kt \
  app/src/main/java/io/deskguest/app/aipack/AiPack.kt \
  app/src/main/java/io/deskguest/app/rmm/RmmEndpoint.kt \
  app/src/main/java/io/deskguest/app/cameraview/CameraView.kt \
  app/src/main/java/io/deskguest/app/camerashare/CameraShare.kt \
  app/src/main/java/io/deskguest/app/insession/InSession.kt \
  app/src/main/java/io/deskguest/app/bgtools/BgTools.kt \
  app/src/main/java/io/deskguest/app/probes/Probes.kt \
  app/src/main/java/io/deskguest/app/deploy/Deploy.kt \
  app/src/main/java/io/deskguest/app/vendorpass/VendorPass.kt \
  app/src/main/java/io/deskguest/app/backup/Backup.kt \
  app/src/main/java/io/deskguest/app/recovery/RecoveryBlob.kt \
  app/src/main/java/io/deskguest/app/mobileop/MobileOperator.kt \
  app/src/main/java/io/deskguest/app/rmmspine/SignedCommands.kt \
  app/src/main/java/io/deskguest/app/rmmspine/JobJournal.kt \
  app/src/main/java/io/deskguest/app/rmmspine/Rmm07Policy.kt \
  app/src/main/java/io/deskguest/app/rmmspine/Mdm.kt \
  app/src/main/java/io/deskguest/app/rmmspine/RemediationRunbooks.kt \
  app/src/main/java/io/deskguest/app/safety/InvisibleApps.kt \
  app/src/main/java/io/deskguest/app/safety/DrivingLockout.kt \
  app/src/main/java/io/deskguest/app/notify/NotificationCache.kt \
  app/src/main/java/io/deskguest/app/server/ReplayLog.kt \
  app/src/main/java/io/deskguest/app/server/FileScope.kt \
  tests/DataFlowTest.kt \

java -classpath "$OUT:$JSON_JAR:$STDLIB" DataFlowTestKt
echo "REDUCED DATAFLOW SUITE DONE"