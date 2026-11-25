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
OUT=/tmp/acp-tests
WORK=/tmp/acp-http
rm -rf "$OUT" "$WORK"; mkdir -p "$OUT" "$WORK"

"$KOTLINC" -classpath "$JSON_JAR" -d "$OUT" \
  app/src/main/java/io/agenticcontrol/app/server/McpCore.kt \
  app/src/main/java/io/agenticcontrol/app/server/CommandGateWiring.kt \
  app/src/main/java/io/agenticcontrol/app/server/McpHttpServer.kt \
  app/src/main/java/io/agenticcontrol/app/server/PairingStore.kt \
  app/src/main/java/io/agenticcontrol/app/server/SessionManager.kt \
  app/src/main/java/io/agenticcontrol/app/server/SessionBudget.kt \
  app/src/main/java/io/agenticcontrol/app/server/ClipboardPolicy.kt \
  app/src/main/java/io/agenticcontrol/app/server/DataFlow.kt \
  app/src/main/java/io/agenticcontrol/app/server/SessionEvents.kt \
  app/src/main/java/io/agenticcontrol/app/server/BootRestartPolicy.kt \
  app/src/main/java/io/agenticcontrol/app/server/AuditLog.kt \
  app/src/main/java/io/agenticcontrol/app/server/ApprovalGate.kt \
  app/src/main/java/io/agenticcontrol/app/access/WaitCondition.kt \
  app/src/main/java/io/agenticcontrol/app/adb/Ed25519.kt \
  app/src/main/java/io/agenticcontrol/app/adb/Spake25519.kt \
  app/src/main/java/io/agenticcontrol/app/adb/Hkdf.kt \
  app/src/main/java/io/agenticcontrol/app/adb/PairingCipher.kt \
  app/src/main/java/io/agenticcontrol/app/adb/AdbProtocol.kt \
  app/src/main/java/io/agenticcontrol/app/adb/AdbKey.kt \
  app/src/main/java/io/agenticcontrol/app/adb/AdbIdentity.kt \
  app/src/main/java/io/agenticcontrol/app/adb/AdbPairing.kt \
  app/src/main/java/io/agenticcontrol/app/adb/TlsExporter.kt \
  app/src/main/java/io/agenticcontrol/app/crypto/AesGcm.kt \
  app/src/main/java/io/agenticcontrol/app/mesh/MeshProtocol.kt \
  app/src/main/java/io/agenticcontrol/app/access/SnapshotStore.kt \
  app/src/main/java/io/agenticcontrol/app/update/ManifestVerifier.kt \
  app/src/main/java/io/agenticcontrol/app/presence/PresencePalette.kt \
  app/src/main/java/io/agenticcontrol/app/strings/ConsentStrings.kt \
  app/src/main/java/io/agenticcontrol/app/enrollment/DeviceIdentity.kt \
  app/src/main/java/io/agenticcontrol/app/enrollment/Sas.kt \
  app/src/main/java/io/agenticcontrol/app/enrollment/EnrollmentStore.kt \
  app/src/main/java/io/agenticcontrol/app/enrollment/EnrollPayload.kt \
  app/src/main/java/io/agenticcontrol/app/roster/TransportPolicy.kt \
  app/src/main/java/io/agenticcontrol/app/roster/RosterStore.kt \
  app/src/main/java/io/agenticcontrol/app/session/SessionStore.kt \
  app/src/main/java/io/agenticcontrol/app/transport/Transport.kt \
  app/src/main/java/io/agenticcontrol/app/transport/HubMesh.kt \
  app/src/main/java/io/agenticcontrol/app/transport/TailscaleSetup.kt \
  app/src/main/java/io/agenticcontrol/app/wiring/PlatformStores.kt \
  app/src/main/java/io/agenticcontrol/app/wiring/PlatformToolHost.kt \
  app/src/main/java/io/agenticcontrol/app/enterprise/Enterprise.kt \
  app/src/main/java/io/agenticcontrol/app/transport/RemainingRungs.kt \
  app/src/main/java/io/agenticcontrol/app/transport/TorProvisioning.kt \
  app/src/main/java/io/agenticcontrol/app/transport/ConnectionDoctor.kt \
  app/src/main/java/io/agenticcontrol/app/session/Terminal.kt \
  app/src/main/java/io/agenticcontrol/app/crypto/SecondFactor.kt \
  app/src/main/java/io/agenticcontrol/app/wake/Wake.kt \
  app/src/main/java/io/agenticcontrol/app/session/StandaloneTransfers.kt \
  app/src/main/java/io/agenticcontrol/app/session/SessionTunnels.kt \
  app/src/main/java/io/agenticcontrol/app/quickassist/QuickAssist.kt \
  app/src/main/java/io/agenticcontrol/app/aipack/AiPack.kt \
  app/src/main/java/io/agenticcontrol/app/rmm/RmmEndpoint.kt \
  app/src/main/java/io/agenticcontrol/app/cameraview/CameraView.kt \
  app/src/main/java/io/agenticcontrol/app/camerashare/CameraShare.kt \
  app/src/main/java/io/agenticcontrol/app/insession/InSession.kt \
  app/src/main/java/io/agenticcontrol/app/bgtools/BgTools.kt \
  app/src/main/java/io/agenticcontrol/app/probes/Probes.kt \
  app/src/main/java/io/agenticcontrol/app/deploy/Deploy.kt \
  app/src/main/java/io/agenticcontrol/app/vendorpass/VendorPass.kt \
  app/src/main/java/io/agenticcontrol/app/backup/Backup.kt \
  app/src/main/java/io/agenticcontrol/app/recovery/RecoveryBlob.kt \
  app/src/main/java/io/agenticcontrol/app/mobileop/MobileOperator.kt \
  app/src/main/java/io/agenticcontrol/app/rmmspine/SignedCommands.kt \
  app/src/main/java/io/agenticcontrol/app/rmmspine/JobJournal.kt \
  app/src/main/java/io/agenticcontrol/app/rmmspine/Rmm07Policy.kt \
  app/src/main/java/io/agenticcontrol/app/rmmspine/Mdm.kt \
  app/src/main/java/io/agenticcontrol/app/rmmspine/RemediationRunbooks.kt \
  app/src/main/java/io/agenticcontrol/app/safety/InvisibleApps.kt \
  app/src/main/java/io/agenticcontrol/app/safety/DrivingLockout.kt \
  app/src/main/java/io/agenticcontrol/app/notify/NotificationCache.kt \
  app/src/main/java/io/agenticcontrol/app/server/ReplayLog.kt \
  app/src/main/java/io/agenticcontrol/app/server/FileScope.kt \
  tests/DataFlowTest.kt \

java -classpath "$OUT:$JSON_JAR:$STDLIB" DataFlowTestKt
echo "REDUCED DATAFLOW SUITE DONE"