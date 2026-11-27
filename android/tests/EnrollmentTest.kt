import io.deskguest.app.adb.Ed25519
import io.deskguest.app.crypto.AesGcmLineCipher
import io.deskguest.app.enrollment.DeviceIdentity
import io.deskguest.app.enrollment.EnrollPayload
import io.deskguest.app.enrollment.EnrollmentStore
import java.io.File
import java.nio.file.Files
import java.util.Base64

/**
 * JVM tests for Slice 1 (enrollment + identity foundation):
 * - Ed25519 sign/verify anchored to RFC 8032 §7.1 TEST 1 and TEST 2
 *   (exact vector bytes; key derivation already anchored in
 *   AdbCryptoTest.kt).
 * - Enrollment codes: scope/group binding, single-use, burn after
 *   5 wrong attempts, expiry, case/dash-insensitive redemption.
 * - Roster: revoke blocks signature verification immediately.
 * - Persistence: TSV round-trip preserves roster + receipts,
 *   corrupt lines are skipped, and the identity file on disk holds
 *   no plaintext seed.
 * - QR payload: round-trip plus hostile-input rejection.
 */
private var failures = 0

private fun check(name: String, condition: Boolean) {
    if (condition) println("PASS  $name")
    else {
        println("FAIL  $name")
        failures++
    }
}

private fun hex(bytes: ByteArray): String = Ed25519.bytesToHex(bytes)
private fun unhex(s: String): ByteArray = Ed25519.hexToBytes(s)
private fun b64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)

private fun wrongCodeFor(liveDisplay: String): String {
    val raw = liveDisplay.replace("-", "")
    val first = if (raw[0] == 'A') 'B' else 'A'
    return first + raw.substring(1)
}

fun main() {
    val dir = Files.createTempDirectory("deskguest-enrollment-test").toFile()

    // ---- RFC 8032 §7.1 TEST 1: sign + verify, exact bytes ----
    val seed1 = unhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    val id1 = DeviceIdentity.fromSeed(seed1)
    check(
        "RFC TEST 1 public key",
        hex(id1.publicKey) == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    )
    val sig1 = unhex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )
    check("RFC TEST 1 signature is 64 bytes", sig1.size == 64)
    check("RFC TEST 1 sign(empty) matches the vector", id1.sign(ByteArray(0)).contentEquals(sig1))
    check("RFC TEST 1 verify(empty, vector sig)", DeviceIdentity.verify(id1.publicKey, ByteArray(0), sig1))
    check("RFC TEST 1 verify rejects a different message", !DeviceIdentity.verify(id1.publicKey, byteArrayOf(1), sig1))

    // ---- RFC 8032 §7.1 TEST 2: sign + verify, exact bytes ----
    // Vector bytes cross-checked against RFC 8032 §7.1 as published
    // (see the RFC text): seed 4ccd…a6fb, message single byte 0x72.
    val seed2 = unhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
    val id2 = DeviceIdentity.fromSeed(seed2)
    check(
        "RFC TEST 2 public key",
        hex(id2.publicKey) == "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
    )
    val msg2 = unhex("72")
    val sig2 = unhex(
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da" +
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
    )
    check("RFC TEST 2 signature is 64 bytes", sig2.size == 64)
    check("RFC TEST 2 sign(0x72) matches the vector", id2.sign(msg2).contentEquals(sig2))
    check("RFC TEST 2 verify(0x72, vector sig)", DeviceIdentity.verify(id2.publicKey, msg2, sig2))

    // ---- Fingerprint (DeviceId) stability ----
    val id1Again = DeviceIdentity.fromSeed(seed1.copyOf())
    check("deviceId is stable for the same seed", id1.deviceId == id1Again.deviceId)
    check("deviceId equals SHA-256 fingerprint of the public key",
        id1.deviceId == DeviceIdentity.deviceIdFor(id1.publicKey))
    check("deviceId is 64 lowercase hex chars",
        id1.deviceId.length == 64 && id1.deviceId.all { it in '0'..'9' || it in 'a'..'f' })
    check("different seeds give different deviceIds", id1.deviceId != id2.deviceId)
    check("publicKeyBase64 decodes to the public key",
        Base64.getDecoder().decode(id1.publicKeyBase64).contentEquals(id1.publicKey))

    // ---- Sign/verify roundtrip + tamper + malformed ----
    val generated = DeviceIdentity.generate()
    val message = "hello enrollment".toByteArray(Charsets.UTF_8)
    val signature = generated.sign(message)
    check("sign/verify roundtrip", generated.verify(message, signature))
    check("sign/verify roundtrip (static verify)",
        DeviceIdentity.verify(generated.publicKey, message, signature))
    val tamperedMessage = message.copyOf(); tamperedMessage[0] = (tamperedMessage[0].toInt() xor 1).toByte()
    check("tampered message fails", !generated.verify(tamperedMessage, signature))
    val tamperedSig = signature.copyOf(); tamperedSig[40] = (tamperedSig[40].toInt() xor 1).toByte()
    check("tampered signature fails", !generated.verify(message, tamperedSig))
    check("wrong public key fails", !DeviceIdentity.verify(id1.publicKey, message, signature))
    check("short signature fails closed", !DeviceIdentity.verify(generated.publicKey, message, signature.copyOf(63)))
    check("empty signature fails closed", !DeviceIdentity.verify(generated.publicKey, message, ByteArray(0)))
    check("short public key fails closed", !DeviceIdentity.verify(generated.publicKey.copyOf(31), message, signature))
    check("all-zero signature fails closed", !DeviceIdentity.verify(generated.publicKey, message, ByteArray(64)))
    check("oversized-S signature fails closed", !DeviceIdentity.verify(
        generated.publicKey, message,
        signature.copyOfRange(0, 32) + ByteArray(32) { 0xFF.toByte() }
    ))

    // ---- Identity persistence: wrapped seed, lazy explicit load ----
    val cipher = AesGcmLineCipher(AesGcmLineCipher.generateKey())
    val identityFile = File(dir, "identity.txt")
    generated.save(identityFile, cipher)
    val identityOnDisk = identityFile.readText()
    check("identity file is wrapped (v1: prefix)", identityOnDisk.contains("v1:"))
    check("identity file contains no plaintext seed (hex)",
        !identityOnDisk.contains(hex(generated.seedCopy())))
    check("identity file contains no plaintext seed (base64)",
        !identityOnDisk.contains(b64(generated.seedCopy())))
    check("identity file is a single wrapped v1: value (D38/F12: renamed — this asserts the wrapped form, not a key-absence property)",
        identityOnDisk.trim().startsWith("v1:") && !identityOnDisk.trim().contains("\n"))
    val loadedIdentity = DeviceIdentity.load(identityFile, cipher)
    check("identity save/load roundtrip preserves deviceId",
        loadedIdentity != null && loadedIdentity.deviceId == generated.deviceId)
    check("loaded identity signs verifiably",
        loadedIdentity != null && generated.verify(message, loadedIdentity.sign(message)))
    val wrongCipher = AesGcmLineCipher(AesGcmLineCipher.generateKey())
    check("identity under the wrong key fails closed (null)",
        DeviceIdentity.load(identityFile, wrongCipher) == null)
    check("missing identity file loads as null",
        DeviceIdentity.load(File(dir, "nope.txt"), cipher) == null)
    val corruptIdentityFile = File(dir, "identity-corrupt.txt")
    corruptIdentityFile.writeText("!!!not a wrapped seed!!!")
    check("corrupt identity file loads as null, never throws",
        DeviceIdentity.load(corruptIdentityFile, cipher) == null)

    // ---- Enrollment: code binds scope + group ----
    val rosterFile = File(dir, "roster.tsv")
    val store = EnrollmentStore(rosterFile, cipher)
    val enrolling = DeviceIdentity.generate()
    val enrollingDevice = EnrollmentStore.EnrollingDevice(
        deviceId = enrolling.deviceId,
        publicKeyBase64 = enrolling.publicKeyBase64,
        displayName = "Owner's Phone"
    )
    val code = store.mint("personal", "group-42", "Family Group")
    check("minted code displays as XXXXX-XXXXX",
        code.length == 11 && code[5] == '-' &&
            EnrollmentStore.normalizeCode(code) != null)
    check("code alphabet excludes ambiguous chars",
        EnrollmentStore.normalizeCode(code)!!.all { it in EnrollmentStore.CODE_ALPHABET })
    // Redeem with the code lowercased and without the dash: accepted.
    val rawLower = code.replace("-", "").lowercase()
    val enrolled = store.redeem(rawLower, enrollingDevice)
    check("redeem succeeds case/dash-insensitively", enrolled != null)
    check("redeem binds the mint's scope", enrolled?.scope == "personal")
    check("redeem binds the mint's group id", enrolled?.groupId == "group-42")
    check("redeem binds the mint's group name", enrolled?.groupName == "Family Group")
    check("redeem records the enrolling device",
        enrolled?.deviceId == enrolling.deviceId &&
            enrolled?.publicKeyBase64 == enrolling.publicKeyBase64 &&
            enrolled?.displayName == "Owner's Phone" &&
            enrolled?.revoked == false && (enrolled?.enrolledAtMs ?: 0) > 0)

    // ---- Single-use ----
    check("code is single-use (second redeem fails)",
        store.redeem(code, EnrollmentStore.EnrollingDevice(
            DeviceIdentity.generate().deviceId,
            DeviceIdentity.generate().publicKeyBase64, "Second"
        )) == null)
    check("roster all() holds exactly the one device", store.all().size == 1)
    check("byGroup finds the device", store.byGroup("group-42").map { it.deviceId } == listOf(enrolling.deviceId))
    check("byGroup for another group is empty", store.byGroup("nope").isEmpty())

    // ---- verifyEnrolledSignature + revoke ----
    val enrolledMsg = "roster check".toByteArray(Charsets.UTF_8)
    val enrolledSig = enrolling.sign(enrolledMsg)
    check("verifyEnrolledSignature accepts the enrolled device",
        store.verifyEnrolledSignature(enrolling.deviceId, enrolledMsg, enrolledSig))
    check("verifyEnrolledSignature rejects a tampered message",
        !store.verifyEnrolledSignature(enrolling.deviceId, tamperedMessage, enrolledSig))
    check("verifyEnrolledSignature rejects unknown devices",
        !store.verifyEnrolledSignature("unknown-device", enrolledMsg, enrolledSig))
    check("verifyEnrolledSignature rejects malformed signatures",
        !store.verifyEnrolledSignature(enrolling.deviceId, enrolledMsg, ByteArray(10)))
    check("revoke returns true for an enrolled device", store.revoke(enrolling.deviceId))
    check("revoked flag is visible on the roster",
        store.all().firstOrNull { it.deviceId == enrolling.deviceId }?.revoked == true)
    check("revoke blocks verifyEnrolledSignature immediately",
        !store.verifyEnrolledSignature(enrolling.deviceId, enrolledMsg, enrolledSig))
    check("revoke of an unknown device returns false", !store.revoke("unknown-device"))

    // ---- Receipts + TSV roundtrip (roster separate from identity) ----
    store.recordReceipt(
        EnrollmentStore.EnrollmentReceipt(
            enrollerName = "Home Server",
            enrollerDeviceId = "server-device-id",
            scope = "personal",
            groupName = "Family Group",
            enrolledAtMs = 1700000000123L
        )
    )
    check("receipts() returns the recorded receipt",
        store.receipts().size == 1 && store.receipts()[0].enrollerName == "Home Server")
    check("roster file is separate from the identity file", rosterFile != identityFile && rosterFile.exists())
    val reloadedStore = EnrollmentStore(rosterFile, cipher)
    check("TSV roundtrip preserves the roster",
        reloadedStore.all().size == 1 &&
            reloadedStore.all()[0].deviceId == enrolling.deviceId &&
            reloadedStore.all()[0].scope == "personal" &&
            reloadedStore.all()[0].groupId == "group-42" &&
            reloadedStore.all()[0].groupName == "Family Group" &&
            reloadedStore.all()[0].revoked)
    check("TSV roundtrip preserves receipts",
        reloadedStore.receipts().size == 1 &&
            reloadedStore.receipts()[0].enrollerDeviceId == "server-device-id" &&
            reloadedStore.receipts()[0].enrolledAtMs == 1700000000123L)
    check("revocation persists across reload (verify still blocked)",
        !reloadedStore.verifyEnrolledSignature(enrolling.deviceId, enrolledMsg, enrolledSig))

    // Corrupt lines are skipped, never fatal.
    rosterFile.appendText("\ngarbage line with no tabs\ndevice\ttoo\tfew\nreceipt\tonly\n")
    val afterCorrupt = EnrollmentStore(rosterFile, cipher)
    check("corrupt TSV lines are skipped, roster intact",
        afterCorrupt.all().size == 1 && afterCorrupt.receipts().size == 1)

    // ---- D31: per-device transport mode persists ----
    val transportFile = File(dir, "transport.tsv")
    val transportStore = EnrollmentStore(transportFile, cipher)
    // D38 S1-AND F7: transport is bound at MINT (like scope/group);
    // the redeeming side no longer supplies it.
    val transportCode = transportStore.mint(
        "local", "local-group", "Local",
        transportMode = "manual", allowedTransports = setOf("wifi", "tailscale")
    )
    val transportDeviceId = DeviceIdentity.generate()
    val transportEnrolled = transportStore.redeem(
        transportCode,
        EnrollmentStore.EnrollingDevice(
            transportDeviceId.deviceId, transportDeviceId.publicKeyBase64, "Transport Device"
        )
    )
    check("D31 redeem records the MINT-bound transportMode=manual",
        transportEnrolled?.transportMode == "manual")
    check("D31 redeem records allowedTransports",
        transportEnrolled?.allowedTransports == setOf("wifi", "tailscale"))
    val transportReloaded = EnrollmentStore(transportFile, cipher)
    check("D31 transportMode + allowedTransports survive the TSV round-trip",
        transportReloaded.all().singleOrNull()?.transportMode == "manual" &&
            transportReloaded.all().singleOrNull()?.allowedTransports == setOf("wifi", "tailscale"))
    check("D31 defaults are inherit / empty on a plain enrollment",
        reloadedStore.all()[0].transportMode == "inherit" &&
            reloadedStore.all()[0].allowedTransports.isEmpty())
    // An older 9-field device line (no D31 trailing fields) loads
    // with the defaults, corrupt-safe as before. (D38/F1: the
    // fixture's deviceId is now the key's real fingerprint — a
    // line whose id does not match its key is corrupt and skipped,
    // which the D38 block below proves.)
    val legacyIdentity = DeviceIdentity.generate()
    val legacyTransportFile = File(dir, "transport-legacy.tsv")
    legacyTransportFile.writeText(
        "device\t${legacyIdentity.deviceId}\tLegacy\t${legacyIdentity.publicKeyBase64}\tlocal\tg\tG\t1700000000000\t0"
    )
    val legacyTransport = EnrollmentStore(legacyTransportFile, cipher)
    check("D31 older/shorter TSV line loads with inherit / empty defaults",
        legacyTransport.all().singleOrNull()?.transportMode == "inherit" &&
            legacyTransport.all().singleOrNull()?.allowedTransports?.isEmpty() == true)
    check("D31 setTransport persists a mode change",
        transportReloaded.setTransport(transportDeviceId.deviceId, "manual", setOf("wifi")) &&
            EnrollmentStore(transportFile, cipher).all().singleOrNull()?.allowedTransports == setOf("wifi"))

    // ---- Burn after 5 wrong attempts against a live code ----
    val burnFile = File(dir, "burn.tsv")
    val burnStore = EnrollmentStore(burnFile, cipher)
    val burnCode = burnStore.mint("local", "local-group", "Local")
    // D38/F1: the device must present a MATCHING id/key pair (the
    // old fixture generated the id and the key from two different
    // identities, which the binding check now rightly refuses).
    val burnIdentity = DeviceIdentity.generate()
    val burnDevice = EnrollmentStore.EnrollingDevice(
        burnIdentity.deviceId,
        burnIdentity.publicKeyBase64, "Burn Test"
    )
    var wrongResults = 0
    repeat(5) {
        if (burnStore.redeem(wrongCodeFor(burnCode), burnDevice) == null) wrongResults++
    }
    check("5 wrong attempts are all refused", wrongResults == 5)
    check("code is burned after 5 wrong attempts (correct code now fails)",
        burnStore.redeem(burnCode, burnDevice) == null)
    check("burned code leaves no roster entry", burnStore.all().isEmpty())
    // A fresh mint still works after a burn.
    val burnCode2 = burnStore.mint("local", "local-group", "Local")
    check("a fresh code redeems after a burn", burnStore.redeem(burnCode2, burnDevice) != null)

    // Wrong attempts below the burn limit do not kill the code.
    val tolerantFile = File(dir, "tolerant.tsv")
    val tolerantStore = EnrollmentStore(tolerantFile, cipher)
    val tolerantCode = tolerantStore.mint("company", "work", "Work Group")
    repeat(2) { tolerantStore.redeem(wrongCodeFor(tolerantCode), burnDevice) }
    check("code survives wrong attempts below the burn limit",
        tolerantStore.redeem(tolerantCode, burnDevice)?.groupId == "work")

    // Failures against no live code count for nothing.
    val idleFile = File(dir, "idle.tsv")
    val idleStore = EnrollmentStore(idleFile, cipher)
    repeat(6) { idleStore.redeem("AAAAAAAAAA", burnDevice) }
    val idleCode = idleStore.mint("local", "g", "G")
    check("guesses against no live code do not burn the next code",
        idleStore.redeem(idleCode, burnDevice) != null)

    // ---- Expiry (D38/F12: injected fake clock, no real-time sleep) ----
    var fakeNow = 1_700_000_000_000L
    val expiryFile = File(dir, "expiry.tsv")
    val expiryStore = EnrollmentStore(expiryFile, cipher) { fakeNow }
    val expiryCode = expiryStore.mint("local", "g", "G", ttlMs = 50)
    fakeNow += 100 // advance past the TTL without sleeping
    check("expired code cannot be redeemed", expiryStore.redeem(expiryCode, burnDevice) == null)
    check("default TTL is 10 minutes", EnrollmentStore.CODE_TTL_MS == 10 * 60 * 1000L)

    // ---- QR payload ----
    val qrCode = store.mint("company", "group-42", "Work")
    // mint on `store` opened a new live code; use its raw form.
    val payload = EnrollPayload.build(qrCode, "company", "group-42")
    check("QR payload has the exact deskguest://enroll/1 shape",
        payload.startsWith("deskguest://enroll/1?c=") && payload.contains("&s=company") && payload.contains("&g=group-42"))
    val parsed = EnrollPayload.parse(payload)
    check("QR roundtrip preserves code/scope/group",
        parsed != null &&
            parsed.code == EnrollmentStore.normalizeCode(qrCode) &&
            parsed.scope == "company" && parsed.groupId == "group-42")
    check("QR payload carries the code without the dash",
        parsed != null && !parsed.code.contains("-"))
    check("QR parse rejects wrong scheme",
        EnrollPayload.parse("http://enroll/1?c=${parsed!!.code}&s=company&g=group-42") == null)
    check("QR parse rejects wrong version",
        EnrollPayload.parse("deskguest://enroll/2?c=${parsed.code}&s=company&g=group-42") == null)
    check("QR parse rejects wrong path",
        EnrollPayload.parse("deskguest://pair/1?c=${parsed.code}&s=company&g=group-42") == null)
    check("QR parse rejects missing code",
        EnrollPayload.parse("deskguest://enroll/1?s=company&g=group-42") == null)
    check("QR parse rejects blank code",
        EnrollPayload.parse("deskguest://enroll/1?c=&s=company&g=group-42") == null)
    check("QR parse rejects missing scope",
        EnrollPayload.parse("deskguest://enroll/1?c=${parsed.code}&g=group-42") == null)
    check("QR parse rejects missing group",
        EnrollPayload.parse("deskguest://enroll/1?c=${parsed.code}&s=company") == null)
    check("QR parse rejects unknown scope",
        EnrollPayload.parse("deskguest://enroll/1?c=${parsed.code}&s=galaxy&g=group-42") == null)
    check("QR parse rejects garbage", EnrollPayload.parse("not a payload at all") == null)
    check("QR parse rejects empty string", EnrollPayload.parse("") == null)
    check("QR parse rejects null", EnrollPayload.parse(null) == null)
    check("QR parse rejects bare prefix", EnrollPayload.parse("deskguest://enroll/1") == null)
    check("QR parse rejects malformed code chars",
        EnrollPayload.parse("deskguest://enroll/1?c=0000000000&s=company&g=group-42") == null)

    // ================= D38 reconciliation (S1-AND findings) =================
    run {
        // F1: deviceId must be the presented key's fingerprint.
        val f1File = File(dir, "d38-f1.tsv")
        val f1Store = EnrollmentStore(f1File, cipher)
        val victim = DeviceIdentity.generate()
        val attacker = DeviceIdentity.generate()
        val f1Code = f1Store.mint("company", "g1", "G1")
        check("D38/F1 redeem with a deviceId that does NOT match the key is refused, no roster entry",
            f1Store.redeem(
                f1Code,
                EnrollmentStore.EnrollingDevice(victim.deviceId, attacker.publicKeyBase64, "Attacker")
            ) == null && f1Store.all().isEmpty())
        check("D38/F1 the code stays live after the refused mismatch (legitimate retry succeeds)",
            f1Store.redeem(
                f1Code,
                EnrollmentStore.EnrollingDevice(victim.deviceId, victim.publicKeyBase64, "Victim")
            ) != null)
        check("setup: victim revoked", f1Store.revoke(victim.deviceId))
        val f1Code2 = f1Store.mint("company", "g1", "G1")
        check("D38/F1 a REVOKED device cannot be resurrected by redeeming again",
            f1Store.redeem(
                f1Code2,
                EnrollmentStore.EnrollingDevice(victim.deviceId, victim.publicKeyBase64, "Victim")
            ) == null && f1Store.byId(victim.deviceId)?.revoked == true)

        // F1/F8: load-time validation + duplicate resolution.
        val f8File = File(dir, "d38-f8.tsv")
        val goodId = DeviceIdentity.generate()
        val revokedId = DeviceIdentity.generate()
        f8File.writeText(
            listOf(
                // id/key mismatch -> corrupt, skipped
                "device\t${victim.deviceId}\tMismatch\t${attacker.publicKeyBase64}\tcompany\tg\tG\t1700000000000\t0",
                // unknown scope -> skipped
                "device\t${goodId.deviceId}\tBadScope\t${goodId.publicKeyBase64}\tgalaxy\tg\tG\t1700000000000\t0",
                // duplicate id: active line first, revoked line second -> revoked wins
                "device\t${revokedId.deviceId}\tDup\t${revokedId.publicKeyBase64}\tcompany\tg\tG\t1700000000000\t0",
                "device\t${revokedId.deviceId}\tDup\t${revokedId.publicKeyBase64}\tcompany\tg\tG\t1700000000001\t1"
            ).joinToString("\n")
        )
        val f8Store = EnrollmentStore(f8File, cipher)
        check("D38/F1/F8 load skips id/key-mismatched and unknown-scope lines",
            f8Store.all().none { it.displayName == "Mismatch" || it.displayName == "BadScope" } &&
                f8Store.byId(victim.deviceId) == null && f8Store.byId(goodId.deviceId) == null)
        check("D38/F8 duplicate roster lines resolve in favour of REVOKED",
            f8Store.all().count { it.deviceId == revokedId.deviceId } == 1 &&
                f8Store.byId(revokedId.deviceId)?.revoked == true)

        // F3: a plaintext seed file is refused under a wrapping cipher.
        val plainSeedFile = File(dir, "d38-f3-identity.txt")
        plainSeedFile.writeText(b64(generated.seedCopy()))
        check("D38/F3 a plaintext Base64 seed file loads as null under a wrapping cipher",
            DeviceIdentity.load(plainSeedFile, cipher) == null)

        // F5: small-order / non-point keys.
        val f5File = File(dir, "d38-f5.tsv")
        val f5Store = EnrollmentStore(f5File, cipher)
        val identityPoint = ByteArray(32).also { it[0] = 1 } // encoded identity point
        val f5Code = f5Store.mint("company", "g", "G")
        check("D38/F5 redeem with the identity-point key is refused",
            f5Store.redeem(
                f5Code,
                EnrollmentStore.EnrollingDevice(
                    DeviceIdentity.deviceIdFor(identityPoint), b64(identityPoint), "Identity Point"
                )
            ) == null && f5Store.all().isEmpty())
        val nonPoint = ByteArray(32) { 0xFF.toByte() }
        val f5Code2 = f5Store.mint("company", "g", "G")
        check("D38/F5 redeem with a non-curve-point key is refused",
            f5Store.redeem(
                f5Code2,
                EnrollmentStore.EnrollingDevice(
                    DeviceIdentity.deviceIdFor(nonPoint), b64(nonPoint), "Non Point"
                )
            ) == null)
        // Universal forgery against the identity point: sig = ([s]B, s)
        // verifies under A = identity for ANY message in the old code.
        val forgedS = java.math.BigInteger.valueOf(42)
        val forgedR = Ed25519.encode(Ed25519.scalarmultBase(forgedS))
        val forgedSig = forgedR + Ed25519.intToLittleEndian(forgedS, 32)
        check("D38/F5 verify rejects the identity-point public key (universal forgery impossible)",
            !DeviceIdentity.verify(identityPoint, "anything".toByteArray(), forgedSig))

        // F4: persistence failures roll back and report honestly.
        val failDir = File(dir, "d38-f4-fail.tsv").also { it.mkdir() } // a DIRECTORY as the store path
        val failStore = EnrollmentStore(failDir, cipher)
        val failCode = failStore.mint("local", "g", "G")
        val failDevice = DeviceIdentity.generate()
        check("D38/F4 redeem against an unwritable store returns null and keeps NO roster entry",
            failStore.redeem(
                failCode,
                EnrollmentStore.EnrollingDevice(failDevice.deviceId, failDevice.publicKeyBase64, "F")
            ) == null && failStore.all().isEmpty())
        check("D38/F4 the code is NOT burned by the persistence failure (still redeemable in principle)",
            failStore.currentCode() != null)
        val f4File = File(dir, "d38-f4.tsv")
        val f4Store = EnrollmentStore(f4File, cipher)
        val f4Device = DeviceIdentity.generate()
        val f4Code = f4Store.mint("local", "g", "G")
        check("setup: f4 device enrolled",
            f4Store.redeem(
                f4Code,
                EnrollmentStore.EnrollingDevice(f4Device.deviceId, f4Device.publicKeyBase64, "F4")
            ) != null)
        f4File.delete(); f4File.mkdir() // the store path becomes a directory: saves now fail
        check("D38/F4 revoke reports false when the revocation cannot be persisted, memory rolled back",
            !f4Store.revoke(f4Device.deviceId) && f4Store.byId(f4Device.deviceId)?.revoked == false)

        // F11: identity save refuses to overwrite the root identity.
        val f11File = File(dir, "d38-f11-identity.txt")
        val f11Id = DeviceIdentity.generate()
        f11Id.save(f11File, cipher)
        val overwriteThrew = try {
            DeviceIdentity.generate().save(f11File, cipher)
            false
        } catch (e: IllegalStateException) {
            true
        }
        check("D38/F11 saving over an existing identity file without force is refused",
            overwriteThrew && DeviceIdentity.load(f11File, cipher)?.deviceId == f11Id.deviceId)
        check("D38/F11 an explicit forced overwrite succeeds",
            run {
                val replacement = DeviceIdentity.generate()
                replacement.save(f11File, cipher, overwrite = true)
                DeviceIdentity.load(f11File, cipher)?.deviceId == replacement.deviceId
            })

        // F6: no sleep-based backoff remains (behavioral anchor: a
        // wrong guess returns promptly and other calls are not
        // stalled — the burn still applies, proven above).
        check("D38/F6 the burn limit constant still governs wrong guesses",
            EnrollmentStore.MAX_REDEEM_ATTEMPTS == 5)
        val f6Store = EnrollmentStore(File(dir, "d38-f6.tsv"), cipher)
        f6Store.mint("local", "g", "G")
        val f6Device = DeviceIdentity.generate()
        val f6Start = System.nanoTime()
        repeat(4) {
            f6Store.redeem(
                "ZZZZZ-ZZZZZ",
                EnrollmentStore.EnrollingDevice(f6Device.deviceId, f6Device.publicKeyBase64, "Guesser")
            )
        }
        val f6ElapsedMs = (System.nanoTime() - f6Start) / 1_000_000
        check("D38/F6 wrong guesses return PROMPTLY (no sleep under the monitor; 4 guesses in ${f6ElapsedMs}ms, code not yet burned)",
            f6ElapsedMs < 1500 && f6Store.currentCode() != null)

        // F9: the QR payload's scope/group are display hints only —
        // a tampered payload cannot change what redeem files the
        // device into; the MINT's binding is authoritative.
        val f9Store = EnrollmentStore(File(dir, "d38-f9.tsv"), cipher)
        val f9Code = f9Store.mint("personal", "gpers", "Personal Group")
        val tamperedPayload =
            "deskguest://enroll/1?c=${EnrollmentStore.normalizeCode(f9Code)}&s=company&g=dg-evil"
        val f9Parsed = EnrollPayload.parse(tamperedPayload)
        val f9Device = DeviceIdentity.generate()
        check("D38/F9 a tampered QR (scope/group rewritten) still redeems under the MINT's scope + group",
            f9Parsed != null && f9Parsed.scope == "company" &&
                f9Store.redeem(
                    f9Parsed.code,
                    EnrollmentStore.EnrollingDevice(f9Device.deviceId, f9Device.publicKeyBase64, "Enrollee")
                )?.let { it.scope == "personal" && it.groupId == "gpers" } == true)
    }

    dir.deleteRecursively()
    println(if (failures == 0) "ALL ENROLLMENT TESTS PASSED" else "$failures ENROLLMENT TEST(S) FAILED")
    if (failures > 0) kotlin.system.exitProcess(1)
}
