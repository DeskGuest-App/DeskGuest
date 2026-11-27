import io.deskguest.app.enrollment.DeviceIdentity
import io.deskguest.app.enrollment.PairingSas
import io.deskguest.app.recovery.RecoveryBlob
import io.deskguest.app.recovery.RecoveryBlobException
import io.deskguest.app.recovery.RecoveryContact
import io.deskguest.app.recovery.X25519Recovery
import java.io.File
import java.security.SecureRandom
import java.util.Base64

/**
 * C20 — Recovery blob (Android mirror). Mirrors the C# suite
 * (DeskGuest.Tests/RecoveryBlobTests.cs): round-trip, wrong credential
 * refuses, restore-over-live-identity refuses, contact-sealed copy
 * cannot be opened by a non-named contact or by the contact alone,
 * tampering refuses. Plus the cross-platform fixture exchange with
 * the C# harness (xwrite/xread modes): a blob written by either
 * platform must restore on the other.
 *
 * Fixture identity seed = bytes 0x01..0x20; contact seed = 0xA0..0xBF
 * (identical in harness-c20/Program.cs).
 */
private var failures = 0

private fun check(name: String, condition: Boolean) {
    if (condition) println("PASS  $name")
    else {
        println("FAIL  $name")
        failures++
    }
}

private fun checkRefuses(name: String, block: () -> Unit) {
    try {
        block()
        println("FAIL  $name (no refusal)")
        failures++
    } catch (e: RecoveryBlobException) {
        println("PASS  $name")
    } catch (e: Exception) {
        println("FAIL  $name (wrong exception: ${e.javaClass.simpleName}: ${e.message})")
        failures++
    }
}

private const val PASSPHRASE = "correct horse battery staple"
private const val CREATED = "2026-11-22T12:00:00Z"

private fun fixtureSeed(start: Int): ByteArray = ByteArray(32) { (start + it).toByte() }

private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it.toInt() and 0xFF) }
private fun unhex(text: String): ByteArray = ByteArray(text.length / 2) {
    text.substring(it * 2, it * 2 + 2).toInt(16).toByte()
}

/** In-memory stand-in for the phone's stores: export strings in,
 *  applied payload captured, emptiness flags controllable. */
private class FakeStores {
    var liveIdentity = false
    var empty = true
    var applied: io.deskguest.app.recovery.RecoveryPayloadData? = null
    fun apply(payload: io.deskguest.app.recovery.RecoveryPayloadData) {
        applied = payload
    }
}

private data class RecoveryWorld(
    val seed: ByteArray,
    val deviceId: String,
    val pairingsExport: String,
    val rosterExport: String
)

private fun world(): RecoveryWorld {
    val seed = fixtureSeed(0x21)
    val deviceId = DeviceIdentity.deviceIdFor(DeviceIdentity.derivePublicKey(seed))
    val pairings = """[{"Id":"p1","AgentName":"agent-one","Scopes":["look_only"]}]"""
    val roster = """{"scopes":["personal-1"],"users":["owner","ai-1"]}"""
    return RecoveryWorld(seed, deviceId, pairings, roster)
}

fun main(args: Array<String>) {
    if (args.size >= 2 && args[0] == "xwrite") {
        xwrite(File(args[1]))
        return
    }
    if (args.size >= 2 && args[0] == "xread") {
        xread(File(args[1]))
        if (failures > 0) kotlin.system.exitProcess(1)
        return
    }

    // ---- key sheet -------------------------------------------------
    check("word list matches pinned SAS list", RecoveryBlob.KEY_SHEET_WORDS == PairingSas.WORDS)
    val key = ByteArray(32).also { SecureRandom().nextBytes(it) }
    val sheet = RecoveryBlob.keySheetEncode(key)
    check("key sheet has 34 words", sheet.split(' ').size == 34)
    check("key sheet round-trips", RecoveryBlob.keySheetDecode(sheet).contentEquals(key))
    check("key sheet case/separator tolerant",
        RecoveryBlob.keySheetDecode(sheet.uppercase().replace(' ', '-')).contentEquals(key))
    val wrongWords = sheet.split(' ').toMutableList()
    wrongWords[5] = if (wrongWords[5] == "bab") "bad" else "bab"
    checkRefuses("key sheet one wrong word refuses") { RecoveryBlob.keySheetDecode(wrongWords.joinToString(" ")) }

    // ---- X25519 pins -------------------------------------------------
    check("x25519 rfc7748 vector 1", hex(
        X25519Recovery.raw(
            unhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
            unhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
        )
    ) == "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
    check("x25519 rfc7748 vector 2", hex(
        X25519Recovery.raw(
            unhex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"),
            unhex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493")
        )
    ) == "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957")
    check("pbkdf2 rfc7914 vector", hex(
        RecoveryBlob.pbkdf2Sha256("password".toByteArray(), "salt".toByteArray(), 1, 32)
    ) == "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b")
    run {
        val aliceSeed = fixtureSeed(0x30)
        val bobSeed = fixtureSeed(0x50)
        val alicePub = DeviceIdentity.derivePublicKey(aliceSeed)
        val bobPub = DeviceIdentity.derivePublicKey(bobSeed)
        val aShared = X25519Recovery.raw(X25519Recovery.scalarFromEd25519Seed(aliceSeed), X25519Recovery.publicFromEd25519(bobPub))
        val bShared = X25519Recovery.raw(X25519Recovery.scalarFromEd25519Seed(bobSeed), X25519Recovery.publicFromEd25519(alicePub))
        check("x25519 ed25519 agreement", aShared.contentEquals(bShared) && aShared.any { it != 0.toByte() })
    }

    // ---- round trips ---------------------------------------------------
    val (seed, deviceId, pairingsExport, rosterExport) = world()
    val contactSeed = fixtureSeed(0xA0)
    val contact = RecoveryContact("Contact One", DeviceIdentity.derivePublicKey(contactSeed))
    val export = RecoveryBlob.export(seed, deviceId, pairingsExport, rosterExport, PASSPHRASE, listOf(contact), CREATED)

    check("export device id", export.deviceId == deviceId)
    check("export one contact blob", export.contactBlobs.size == 1)
    check("blob has no plaintext seed",
        !String(export.primaryBlob, Charsets.UTF_8).contains(Base64.getEncoder().encodeToString(seed)))
    check("inspect primary", RecoveryBlob.inspect(export.primaryBlob).let { it.kind == "primary" && it.deviceId == deviceId && it.contactName == null })
    check("inspect contact", RecoveryBlob.inspect(export.contactBlobs[0].second).let { it.kind == "contact" && it.contactName == "Contact One" })

    run {
        val stores = FakeStores()
        val restored = RecoveryBlob.restorePrimary(export.primaryBlob, PASSPHRASE, null,
            { stores.liveIdentity }, { stores.empty }, stores::apply)
        check("round-trip passphrase identity", restored.identitySeed.contentEquals(seed) && restored.deviceId == deviceId)
        check("round-trip passphrase stores applied", stores.applied?.pairingsExport == pairingsExport && stores.applied?.rosterExport == rosterExport)
    }
    run {
        val stores = FakeStores()
        val restored = RecoveryBlob.restorePrimary(export.primaryBlob, null, export.keySheet,
            { stores.liveIdentity }, { stores.empty }, stores::apply)
        check("round-trip key sheet identity", restored.identitySeed.contentEquals(seed))
    }

    // ---- destruction: wrong credentials --------------------------------
    run {
        val stores = FakeStores()
        checkRefuses("wrong passphrase refuses") {
            RecoveryBlob.restorePrimary(export.primaryBlob, "wrong horse battery staple", null,
                { stores.liveIdentity }, { stores.empty }, stores::apply)
        }
        check("wrong passphrase applied nothing", stores.applied == null)
    }
    run {
        val stores = FakeStores()
        val otherSheet = RecoveryBlob.keySheetEncode(ByteArray(32).also { SecureRandom().nextBytes(it) })
        checkRefuses("wrong key sheet refuses") {
            RecoveryBlob.restorePrimary(export.primaryBlob, null, otherSheet,
                { stores.liveIdentity }, { stores.empty }, stores::apply)
        }
        check("wrong sheet applied nothing", stores.applied == null)
    }
    checkRefuses("no credential refuses") { RecoveryBlob.openPrimary(export.primaryBlob, null, null) }
    checkRefuses("short passphrase export refused") {
        RecoveryBlob.export(seed, deviceId, pairingsExport, rosterExport, "short", emptyList(), CREATED)
    }

    // ---- destruction: tampering ------------------------------------------
    fun tamper(blob: ByteArray, field: String, after: String? = null): ByteArray {
        val text = String(blob, Charsets.UTF_8)
        // org.json does not guarantee key order, so a field that
        // occurs in several slots must be located within its parent
        // object (the C# serializer's order is deterministic; this
        // suite cannot rely on that here).
        val from = if (after != null) {
            val a = text.indexOf(after)
            require(a >= 0) { "anchor $after not found" }
            a
        } else 0
        val marker = "\"$field\":\""
        val idx = text.indexOf(marker, from)
        require(idx >= 0) { "field $field not found" }
        val pos = idx + marker.length + 4
        val replacement = if (text[pos] == 'A') 'B' else 'A'
        return (text.substring(0, pos) + replacement + text.substring(pos + 1)).toByteArray(Charsets.UTF_8)
    }
    run {
        val stores = FakeStores()
        checkRefuses("tampered payload ciphertext refuses") {
            RecoveryBlob.restorePrimary(tamper(export.primaryBlob, "payloadCiphertext"), PASSPHRASE, null,
                { stores.liveIdentity }, { stores.empty }, stores::apply)
        }
        check("tamper applied nothing", stores.applied == null)
    }
    checkRefuses("tampered passphrase slot refuses") {
        RecoveryBlob.openPrimary(tamper(export.primaryBlob, "wrappedKey", after = "\"passphrase\""), PASSPHRASE, null)
    }
    checkRefuses("truncated blob refuses") {
        RecoveryBlob.openPrimary(export.primaryBlob.copyOf(40), PASSPHRASE, null)
    }
    checkRefuses("garbage blob refuses") { RecoveryBlob.inspect("not a blob".toByteArray()) }

    // ---- destruction: import over live identity ---------------------------
    run {
        val stores = FakeStores()
        stores.liveIdentity = true
        stores.empty = false
        checkRefuses("restore over live identity refuses") {
            RecoveryBlob.restorePrimary(export.primaryBlob, PASSPHRASE, null,
                { stores.liveIdentity }, { stores.empty }, stores::apply)
        }
        check("live identity import applied nothing", stores.applied == null)
    }
    run {
        val stores = FakeStores()
        stores.empty = false
        checkRefuses("restore into non-empty stores refuses") {
            RecoveryBlob.restorePrimary(export.primaryBlob, PASSPHRASE, null,
                { stores.liveIdentity }, { stores.empty }, stores::apply)
        }
        check("non-empty import applied nothing", stores.applied == null)
    }

    // ---- sealed contact copies ----------------------------------------------
    run {
        val stores = FakeStores()
        val restored = RecoveryBlob.restoreFromContactCopy(export.contactBlobs[0].second, contactSeed, export.keySheet,
            { stores.liveIdentity }, { stores.empty }, stores::apply)
        check("contact copy round-trips", restored.identitySeed.contentEquals(seed))
    }
    run {
        val stores = FakeStores()
        checkRefuses("contact alone without sheet cannot restore") {
            RecoveryBlob.restoreFromContactCopy(export.contactBlobs[0].second, contactSeed, "",
                { stores.liveIdentity }, { stores.empty }, stores::apply)
        }
        val wrongSheet = RecoveryBlob.keySheetEncode(ByteArray(32).also { SecureRandom().nextBytes(it) })
        checkRefuses("contact with wrong sheet cannot restore") {
            RecoveryBlob.restoreFromContactCopy(export.contactBlobs[0].second, contactSeed, wrongSheet,
                { stores.liveIdentity }, { stores.empty }, stores::apply)
        }
        check("contact-alone attempts applied nothing", stores.applied == null)
    }
    run {
        val strangerSeed = fixtureSeed(0x70)
        checkRefuses("non-named contact cannot open") {
            RecoveryBlob.openContactCopy(export.contactBlobs[0].second, strangerSeed, export.keySheet)
        }
    }
    checkRefuses("holder cannot open contact copy with passphrase+sheet") {
        RecoveryBlob.openPrimary(export.contactBlobs[0].second, PASSPHRASE, export.keySheet)
    }
    checkRefuses("primary blob refused on contact path") {
        RecoveryBlob.openContactCopy(export.primaryBlob, contactSeed, export.keySheet)
    }
    run {
        val stores = FakeStores()
        checkRefuses("tampered sealed slot refuses") {
            RecoveryBlob.restoreFromContactCopy(tamper(export.contactBlobs[0].second, "sealedWrappedKey"),
                contactSeed, export.keySheet, { stores.liveIdentity }, { stores.empty }, stores::apply)
        }
        check("sealed tamper applied nothing", stores.applied == null)
    }

    println(if (failures == 0) "ALL RECOVERY BLOB TESTS PASSED" else "$failures FAILURES")
    if (failures > 0) kotlin.system.exitProcess(1)
}

// ---- cross-platform fixture exchange -------------------------------------

private fun xwrite(dir: File) {
    dir.mkdirs()
    val seed = fixtureSeed(0x01)
    val deviceId = DeviceIdentity.deviceIdFor(DeviceIdentity.derivePublicKey(seed))
    // Pairings export in the C# PairingService DTO shape so the C#
    // harness's restore path can apply it (the blob carries store
    // exports opaquely; the fixture chooses the shared shape).
    val tokenHash = "a".repeat(64)
    val pairings = """[{"Id":"xcheck-pairing","AgentName":"xcheck-agent","Scopes":["look_only"],"CreatedUtc":"2026-11-22T12:00:00+00:00","ExpiresUtc":null,"SessionTimeBoxSeconds":null,"Revoked":false,"TokenHash":"$tokenHash","ProtectedAgentName":"xcheck-agent"}]"""
    val roster = """{"fixture":"android","owner":"owner"}"""
    val contactSeed = fixtureSeed(0xA0)
    val contact = RecoveryContact("Xcheck Contact", DeviceIdentity.derivePublicKey(contactSeed))
    val export = RecoveryBlob.export(seed, deviceId, pairings, roster, PASSPHRASE, listOf(contact), CREATED)
    File(dir, "primary.deskguestb").writeBytes(export.primaryBlob)
    File(dir, "contact.deskguestb").writeBytes(export.contactBlobs[0].second)
    File(dir, "sheet.txt").writeText(export.keySheet)
    File(dir, "expected.txt").writeText(deviceId)
    File(dir, "contact-seed.b64").writeText(Base64.getEncoder().encodeToString(contactSeed))
    println("XWRITE OK device=$deviceId")
}

private fun xread(dir: File) {
    val expected = File(dir, "expected.txt").readText().trim()
    val sheet = File(dir, "sheet.txt").readText().trim()
    val contactSeed = Base64.getDecoder().decode(File(dir, "contact-seed.b64").readText().trim())
    run {
        val stores = FakeStores()
        val restored = RecoveryBlob.restorePrimary(File(dir, "primary.deskguestb").readBytes(), PASSPHRASE, null,
            { false }, { true }, stores::apply)
        check("xcheck primary-by-passphrase device", restored.deviceId == expected)
        check("xcheck primary pairings carried", restored.pairingsExport.contains("xcheck-agent"))
        check("xcheck primary roster carried", restored.rosterExport.contains("owner"))
        check("xcheck primary seed reproduces device",
            DeviceIdentity.deviceIdFor(DeviceIdentity.derivePublicKey(restored.identitySeed)) == expected)
    }
    run {
        val restored = RecoveryBlob.openPrimary(File(dir, "primary.deskguestb").readBytes(), null, sheet)
        check("xcheck primary-by-sheet device", restored.deviceId == expected)
    }
    run {
        val restored = RecoveryBlob.openContactCopy(File(dir, "contact.deskguestb").readBytes(), contactSeed, sheet)
        check("xcheck contact-copy device", restored.deviceId == expected)
    }
    println(if (failures == 0) "XREAD OK" else "XREAD $failures FAILURES")
}
