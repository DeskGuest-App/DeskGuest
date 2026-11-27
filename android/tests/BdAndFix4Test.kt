import io.deskguest.app.backup.BackupCrypto
import io.deskguest.app.backup.BackupPolicy
import io.deskguest.app.backup.BackupService
import io.deskguest.app.backup.SafTree
import io.deskguest.app.backup.StoreSource
import io.deskguest.app.cameraview.ChainedAudit
import io.deskguest.app.recovery.RecoveryBlob
import io.deskguest.app.server.EventSubscriptions
import io.deskguest.app.server.EventToolHost
import io.deskguest.app.server.PairingStore
import io.deskguest.app.server.SessionEvents
import java.io.File
import java.nio.file.Files
import java.security.MessageDigest

/**
 * Wave 5 Lane B regression + destruction suite:
 *  TASK 1 — backup payload encryption at rest (bd-and-rest F4
 *  remainder): round-trip byte-equal, ciphertext at rest, wrong key
 *  refused with the target byte-identical, tampered ciphertext
 *  refused, entry-swap refused (AAD binding), passphrase path via
 *  the C20 PBKDF2, key-sheet key path, legacy plaintext refused by
 *  an encryption-configured service (no silent downgrade) and still
 *  restored by an unconfigured one.
 *  TASK 2 — bd-supp-eventsub Android fixes: scoped delivery
 *  fail-closed (F1), tombstone/revoke cleanup (F4/F5/F10), TTL +
 *  listAll (F6), sequence + replay ring (F7), isSubscribed (F8),
 *  descriptor built from the registry incl. clipboard_read (F9),
 *  sanitized unknown-kind echo (F11).
 */
private var failures = 0
private fun check(name: String, condition: Boolean) {
    if (condition) println("PASS  $name") else { println("FAIL  $name"); failures++ }
}
private fun sha(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }
private var clockNow = 1_700_300_000_000L
private fun tick(): Long { clockNow += 1_000L; return clockNow }

private class MemTree : SafTree {
    val files = mutableMapOf<String, ByteArray>()
    override fun granted() = true
    override fun write(n: String, b: ByteArray) = true.also { files[n] = b.copyOf() }
    override fun read(n: String) = files[n]?.copyOf()
    fun snapshot(): Map<String, String> = files.mapValues { sha(it.value) }
}

fun main() {
    val manifestKey = "w5-manifest-key".toByteArray()
    val payloadKey = ByteArray(32) { (it * 7 + 3).toByte() }
    val wrongKey = ByteArray(32) { (it * 13 + 91).toByte() }
    val stores = StoreSource {
        mapOf(
            "roster.tsv" to "roster-secret-rows".toByteArray(),
            "pairings.tsv" to "pairing-token-material".toByteArray()
        )
    }

    // ---------- TASK 1: raw-key encryption ----------
    run {
        BackupPolicy.enabled = true
        val dest = MemTree()
        val svc = BackupService(stores, ChainedAudit(), { tick() }, manifestKey, payloadKey)
        val m = svc.backup(dest).getOrThrow()
        val storedRoster = dest.files["${m.id}/deskguest/roster.tsv"]!!
        check("W5-1 payload at rest is ciphertext (magic present, plaintext absent)",
            BackupCrypto.isEncrypted(storedRoster) &&
                !String(storedRoster, Charsets.UTF_8).contains("roster-secret-rows"))
        check("W5-1 manifest declares the encryption headers",
            String(dest.files["${m.id}/manifest.txt"]!!, Charsets.UTF_8).contains("#enc\taes-256-gcm\tv2"))
        check("W5-1 verify passes on ciphertext integrity (no key needed for hashes)",
            BackupService(stores, ChainedAudit(), { tick() }, manifestKey).verify(dest, m.id).isSuccess)

        val target = MemTree()
        check("W5-1 round-trip restores byte-equal plaintext",
            svc.restore(dest, m.id, target).isSuccess &&
                target.files["deskguest/roster.tsv"]!!.contentEquals("roster-secret-rows".toByteArray()) &&
                target.files["deskguest/pairings.tsv"]!!.contentEquals("pairing-token-material".toByteArray()))

        // DESTRUCTION: wrong key — refused, target byte-identical.
        val victim = MemTree()
        victim.files["keep.txt"] = "untouched".toByteArray()
        val before = victim.snapshot()
        val wrongSvc = BackupService(stores, ChainedAudit(), { tick() }, manifestKey, wrongKey)
        check("W5-1 DESTRUCTION wrong key refuses restore",
            wrongSvc.restore(dest, m.id, victim).isFailure)
        check("W5-1 DESTRUCTION wrong key leaves the target byte-identical",
            victim.snapshot() == before)

        // DESTRUCTION: no key at all.
        val noKeySvc = BackupService(stores, ChainedAudit(), { tick() }, manifestKey)
        check("W5-1 DESTRUCTION keyless service cannot restore an encrypted backup",
            noKeySvc.restore(dest, m.id, MemTree()).isFailure)

        // DESTRUCTION: tampered ciphertext (hash + MAC recomputed so
        // only the GCM tag can catch it).
        val tampered = MemTree()
        dest.files.forEach { (k, v) -> tampered.files[k] = v.copyOf() }
        val entryName = "deskguest/roster.tsv"
        val raw = tampered.files["${m.id}/$entryName"]!!
        raw[raw.size - 1] = (raw[raw.size - 1] + 1).toByte()
        val lines = String(tampered.files["${m.id}/manifest.txt"]!!, Charsets.UTF_8).lines().toMutableList()
        val idx = lines.indexOfFirst { it.startsWith("$entryName\t") }
        lines[idx] = "$entryName\t${sha(raw)}"
        val macIdx = lines.indexOfFirst { it.startsWith("#hmac\t") }
        val macInput = lines.filter { !it.startsWith("#hmac") }.joinToString("\n")
        val mac = javax.crypto.Mac.getInstance("HmacSHA256")
        mac.init(javax.crypto.spec.SecretKeySpec(manifestKey, "HmacSHA256"))
        lines[macIdx] = "#hmac\t" + mac.doFinal(macInput.toByteArray()).joinToString("") { "%02x".format(it) }
        tampered.files["${m.id}/manifest.txt"] = lines.joinToString("\n").toByteArray()
        val tamperTarget = MemTree()
        check("W5-1 DESTRUCTION tampered ciphertext refused by the GCM tag, nothing written",
            svc.restore(tampered, m.id, tamperTarget).isFailure && tamperTarget.files.isEmpty())

        // DESTRUCTION: swap two entries' ciphertexts (hashes updated
        // the same way) — the AAD name binding must refuse.
        val swapped = MemTree()
        dest.files.forEach { (k, v) -> swapped.files[k] = v.copyOf() }
        val a = swapped.files["${m.id}/deskguest/roster.tsv"]!!
        val b = swapped.files["${m.id}/deskguest/pairings.tsv"]!!
        swapped.files["${m.id}/deskguest/roster.tsv"] = b
        swapped.files["${m.id}/deskguest/pairings.tsv"] = a
        val sLines = String(swapped.files["${m.id}/manifest.txt"]!!, Charsets.UTF_8).lines().toMutableList()
        for (n in listOf("deskguest/roster.tsv", "deskguest/pairings.tsv")) {
            val i = sLines.indexOfFirst { it.startsWith("$n\t") }
            sLines[i] = "$n\t${sha(swapped.files["${m.id}/$n"]!!)}"
        }
        val sMacIdx = sLines.indexOfFirst { it.startsWith("#hmac\t") }
        val sMacInput = sLines.filter { !it.startsWith("#hmac") }.joinToString("\n")
        val mac2 = javax.crypto.Mac.getInstance("HmacSHA256")
        mac2.init(javax.crypto.spec.SecretKeySpec(manifestKey, "HmacSHA256"))
        sLines[sMacIdx] = "#hmac\t" + mac2.doFinal(sMacInput.toByteArray()).joinToString("") { "%02x".format(it) }
        swapped.files["${m.id}/manifest.txt"] = sLines.joinToString("\n").toByteArray()
        check("W5-1 DESTRUCTION swapped ciphertexts refused (AAD binds backup id + entry name)",
            svc.restore(swapped, m.id, MemTree()).isFailure)
    }

    // ---------- TASK 1: passphrase path (C20 PBKDF2 discipline) ----------
    run {
        BackupPolicy.enabled = true
        val dest = MemTree()
        val svc = BackupService(stores, ChainedAudit(), { tick() }, manifestKey, null, "correct horse battery")
        val m = svc.backup(dest).getOrThrow()
        check("W5-2 passphrase manifest carries kdf + salt headers",
            String(dest.files["${m.id}/manifest.txt"]!!, Charsets.UTF_8)
                .let { it.contains("#kdf\tpbkdf2-sha256\t600000") && it.contains("#salt\t") })
        val target = MemTree()
        check("W5-2 passphrase round-trip byte-equal",
            svc.restore(dest, m.id, target).isSuccess &&
                target.files["deskguest/roster.tsv"]!!.contentEquals("roster-secret-rows".toByteArray()))
        val wrongPass = BackupService(stores, ChainedAudit(), { tick() }, manifestKey, null, "wrong horse battery")
        val victim = MemTree()
        check("W5-2 DESTRUCTION wrong passphrase refused, nothing written",
            wrongPass.restore(dest, m.id, victim).isFailure && victim.files.isEmpty())
        // The derivation IS the C20 function at the C20 count.
        val salt = ByteArray(16) { it.toByte() }
        check("W5-2 key derivation reuses RecoveryBlob.pbkdf2Sha256 verbatim",
            BackupCrypto.deriveKey("pw", salt).contentEquals(
                RecoveryBlob.pbkdf2Sha256("pw".toByteArray(Charsets.UTF_8), salt, 600_000, 32)))
    }

    // ---------- TASK 1: key-sheet key + legacy policy ----------
    run {
        BackupPolicy.enabled = true
        val sheetKey = ByteArray(32) { (255 - it).toByte() }
        val sheet = RecoveryBlob.keySheetEncode(sheetKey)
        val dest = MemTree()
        val svc = BackupService(stores, ChainedAudit(), { tick() }, manifestKey, RecoveryBlob.keySheetDecode(sheet))
        val m = svc.backup(dest).getOrThrow()
        check("W5-3 C20 key-sheet key opens its own backup",
            svc.restore(dest, m.id, MemTree()).isSuccess)

        // Legacy plaintext backup, made by an unconfigured service.
        val legacyDest = MemTree()
        val legacySvc = BackupService(stores, ChainedAudit(), { tick() }, manifestKey, allowLegacyPlaintext = true) // W12-DS: legacy fixture opts in explicitly
        val lm = legacySvc.backup(legacyDest).getOrThrow()
        check("W5-3 unconfigured service still restores its legacy plaintext backup",
            legacySvc.restore(legacyDest, lm.id, MemTree()).isSuccess)
        val encTarget = MemTree()
        check("W5-3 DESTRUCTION encryption-configured service REFUSES the legacy plaintext backup (no silent downgrade)",
            svc.restore(legacyDest, lm.id, encTarget).isFailure && encTarget.files.isEmpty())
        check("W5-3 legacy backup still verifies for inspection",
            svc.verify(legacyDest, lm.id).isSuccess)
        BackupPolicy.enabled = false
    }

    // ---------- TASK 2: eventsub fixes ----------
    run {
        val keyA = "w5-token-a"; val keyB = "w5-token-b"
        EventSubscriptions.clearPairing(keyA); EventSubscriptions.clearPairing(keyB)
        val sessionEvent = SessionEvents.Event("session_started")

        // F1: scoped delivery is fail-closed.
        check("W5-4 subscribe ok", EventSubscriptions.subscribe(keyA, listOf("session")) == null)
        check("W5-4 F1 scoped delivery passes while Observe is held",
            EventSubscriptions.shouldDeliverScoped(keyA, sessionEvent) { true })
        check("W5-4 F1 scoped delivery DENIED the moment Observe is gone",
            !EventSubscriptions.shouldDeliverScoped(keyA, sessionEvent) { false })

        // F8: isSubscribed agrees with the filter, no copy involved.
        check("W5-4 F8 isSubscribed", EventSubscriptions.isSubscribed(keyA, "session") &&
            !EventSubscriptions.isSubscribed(keyA, "app_crash"))

        // F6: listAll enumerates the live watch.
        check("W5-4 F6 listAll shows the watch",
            EventSubscriptions.listAll()[keyA] == setOf("session"))

        // F11: unknown-kind echo is truncated + sanitized.
        val echoErr = EventSubscriptions.subscribe(keyA, listOf("x".repeat(200) + "\nINJECT")) ?: ""
        check("W5-4 F11 unknown kind refused with a sanitized, truncated echo",
            echoErr.startsWith("unknown_event_kind:") && !echoErr.contains("INJECT") &&
                !echoErr.contains("x".repeat(40)))

        // F5/F4/F10: revoke tombstones; subscribe cannot resurrect.
        EventSubscriptions.revokePairing(keyA)
        check("W5-4 F4 revoke clears the subscription",
            EventSubscriptions.filterFor(keyA).isEmpty() &&
                !EventSubscriptions.shouldDeliver(keyA, sessionEvent))
        check("W5-4 F5 subscribe after revoke is refused (tombstone)",
            EventSubscriptions.subscribe(keyA, listOf("session")) != null &&
                EventSubscriptions.filterFor(keyA).isEmpty())
        check("W5-4 F5 tombstone does not touch other pairings",
            EventSubscriptions.subscribe(keyB, listOf("session")) == null)
        EventSubscriptions.clearPairing(keyB)

        // PairingStore.revoke is the production choke point (F4).
        val dir = Files.createTempDirectory("w5-pairings").toFile()
        val store = PairingStore(File(dir, "pairings.tsv"))
        val pairing = store.redeem(store.beginPairing("W5 Agent")!!, setOf("observe"))!!
        EventSubscriptions.subscribe(pairing.token, listOf("session"))
        check("W5-4 F4 setup: subscription live before revoke",
            EventSubscriptions.isSubscribed(pairing.token, "session"))
        store.revoke(pairing.token)
        check("W5-4 F4 PairingStore.revoke clears + tombstones the subscription",
            !EventSubscriptions.isSubscribed(pairing.token, "session") &&
                EventSubscriptions.isTombstoned(pairing.token) &&
                EventSubscriptions.subscribe(pairing.token, listOf("session")) != null)

        // F6 TTL: expiry drops the watch; re-subscribe renews.
        val keyT = "w5-token-ttl"
        EventSubscriptions.clearPairing(keyT)
        var fakeNow = 5_000_000L
        EventSubscriptions.clockMs = { fakeNow }
        try {
            check("W5-4 F6 ttl subscribe ok", EventSubscriptions.subscribe(keyT, listOf("session")) == null)
            fakeNow += EventSubscriptions.SUBSCRIPTION_TTL_MS + 1
            check("W5-4 F6 expired subscription delivers nothing and lists nothing",
                !EventSubscriptions.shouldDeliver(keyT, sessionEvent) &&
                    !EventSubscriptions.listAll().containsKey(keyT))
        } finally {
            EventSubscriptions.clockMs = { System.currentTimeMillis() }
        }
        EventSubscriptions.clearPairing(keyT)

        // F7: sequence is monotonic and the ring replays in order.
        val before = SessionEvents.eventsSince(0).lastOrNull()?.seq ?: 0
        SessionEvents.emitKind("app_crash", mapOf("where" to "w5"))
        SessionEvents.emitKind("app_crash", mapOf("where" to "w5b"))
        val replay = SessionEvents.eventsSince(before)
        check("W5-4 F7 emitted events carry increasing sequence numbers",
            replay.size == 2 && replay[1].seq == replay[0].seq + 1 && replay[0].seq > before)
        check("W5-4 F7 event JSON carries the sequence",
            SessionEvents.toJson(replay[0]).contains("\"seq\":${replay[0].seq}"))

        // F9: descriptor + schema are built from the registry.
        val host = EventToolHost()
        val subscribeTool = host.tools().first { it.name == "events_subscribe" }
        check("W5-4 F9 descriptor names clipboard_read (registry-built, no drift)",
            subscribeTool.description.contains("clipboard_read"))
        check("W5-4 F9 input schema enum lists every registry kind",
            SessionEvents.ALL_KINDS.all { subscribeTool.inputSchema.toString().contains("\"$it\"") })
    }

    println(if (failures == 0) "BdAndFix4Test: ALL PASS" else "BdAndFix4Test: $failures FAILURES")
    if (failures > 0) kotlin.system.exitProcess(1)
}
