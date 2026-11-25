package io.agenticcontrol.app.backup

import io.agenticcontrol.app.cameraview.ChainedAudit
import io.agenticcontrol.app.recovery.RecoveryBlob
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * RMM-06 (Android, per the 2026-11-21 completion decision) — ACP's
 * OWN backup engine: ACP's own stores + folders the user explicitly
 * grants via the storage-access framework (SAF), to USER-OWNED
 * storage only. The manifest's allowBackup=false platform posture
 * is untouched — this is not Android platform backup and does not
 * reverse it. No vendor cloud destination exists in the shape:
 * a destination is a user-granted tree id or nothing. Backups are
 * content-hashed per file, hash-chained in the audit, and restore
 * verifies every hash before writing anything back.
 */
object BackupPolicy {
    // Local posture stays OFF until the owner turns it on (privacy
    // posture); a bound ManagementPolicyEngine governs through
    // PolicyGate under the registry key rmm.backup.enabled
    // (bd-and-rmm F2).
    @Volatile var enabled: Boolean = false // rmm.backup.enabled, local default OFF (privacy posture)
    fun isEnabled(): Boolean =
        io.agenticcontrol.app.rmmspine.PolicyGate.enabledFor("rmm.backup.enabled", enabled)
}

fun interface StoreSource { fun files(): Map<String, ByteArray> } // ACP's own stores, by logical name
interface SafTree { fun granted(): Boolean; fun write(name: String, bytes: ByteArray): Boolean; fun read(name: String): ByteArray? }

/**
 * W5 — backup payload encryption at rest (bd-and-rest F4 remainder),
 * built on the C20 recovery-blob crypto discipline: AES-256-GCM
 * (12-byte random nonce, 128-bit tag) per payload file, with the
 * passphrase key derived by PBKDF2-HMAC-SHA256 at the C20 iteration
 * count via [RecoveryBlob.pbkdf2Sha256] — the exact function the
 * recovery blob uses, so one passphrase discipline covers both.
 *
 * Stored form: [MAGIC] + nonce + ciphertext||tag. The AAD binds each
 * ciphertext to its backup id AND entry name, so a ciphertext swapped
 * between files or backups fails its tag. The manifest hash remains
 * SHA-256 of the STORED bytes, so integrity verifies before any key
 * is touched; decryption happens only inside restore, after verify.
 *
 * Key control: the key is the USER's — either a raw 32-byte key
 * (e.g. decoded from a C20 recovery key sheet), a passphrase, or, in
 * the production wiring, a key HKDF-derived from the device identity
 * seed, which itself lives Keystore-wrapped and moves only through
 * the user's C20 recovery export/restore.
 */
object BackupCrypto {
    val MAGIC: ByteArray = "ACPENC2".toByteArray(Charsets.UTF_8)
    const val KDF_ITERATIONS: Int = RecoveryBlob.PASSPHRASE_ITERATIONS
    private val random = SecureRandom()

    // W12-DS P8-F18: minimum stored form is magic + 12 nonce +
    // 16 tag; shorter is malformed, never zero-padded into GCM.
    fun isEncrypted(stored: ByteArray): Boolean =
        stored.size >= MAGIC.size + 12 + 16 && MAGIC.indices.all { stored[it] == MAGIC[it] }

    // W12-DS P8-F5: length-prefixed components — the old
    // "v2|id|name" concatenation let (id="a", name="b|c") and
    // (id="a|b", name="c") collide to identical AAD.
    fun aad(backupId: String, entryName: String): ByteArray {
        val id = backupId.toByteArray(Charsets.UTF_8)
        val name = entryName.toByteArray(Charsets.UTF_8)
        val out = ByteArray(4 + id.size + 4 + name.size)
        fun putLen(at: Int, v: Int) { out[at] = (v ushr 24).toByte(); out[at + 1] = (v ushr 16).toByte(); out[at + 2] = (v ushr 8).toByte(); out[at + 3] = v.toByte() }
        putLen(0, id.size); id.copyInto(out, 4)
        putLen(4 + id.size, name.size); name.copyInto(out, 8 + id.size)
        return "acp-backup-payload-v3".toByteArray(Charsets.UTF_8) + out
    }

    fun newSalt(): ByteArray = ByteArray(16).also { random.nextBytes(it) }

    fun deriveKey(passphrase: String, salt: ByteArray): ByteArray =
        RecoveryBlob.pbkdf2Sha256(passphrase.toByteArray(Charsets.UTF_8), salt, KDF_ITERATIONS, 32)

    fun encrypt(key: ByteArray, backupId: String, entryName: String, plain: ByteArray): ByteArray {
        require(key.size == 32) { "a backup payload key is exactly 32 bytes" }
        val nonce = ByteArray(12).also { random.nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(aad(backupId, entryName))
        return MAGIC + nonce + cipher.doFinal(plain)
    }

    /** Throws on any tag/format failure — callers turn that into a
     *  refusal that writes nothing. */
    fun decrypt(key: ByteArray, backupId: String, entryName: String, stored: ByteArray): ByteArray {
        require(key.size == 32) { "a backup payload key is exactly 32 bytes" }
        if (!isEncrypted(stored)) throw IllegalStateException("payload entry is not in encrypted form: $entryName")
        val nonce = stored.copyOfRange(MAGIC.size, MAGIC.size + 12)
        val sealed = stored.copyOfRange(MAGIC.size + 12, stored.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(aad(backupId, entryName))
        return cipher.doFinal(sealed)
    }
}

data class BackupManifest(val id: String, val createdMs: Long, val entries: Map<String, String>, val sourceKinds: Set<String>)

class BackupService(
    private val stores: StoreSource,
    val audit: ChainedAudit = ChainedAudit(),
    private val clockMs: () -> Long = { System.currentTimeMillis() },
    /** bd-and-rest F4 fix: when a manifest key is wired (the
     *  platform layer passes a device-held key), the manifest
     *  carries an HMAC-SHA256 over its entry lines and [verify]
     *  refuses a manifest whose HMAC is missing or wrong — so
     *  rewriting a file AND its hash together no longer passes.
     *  With no key wired the manifest is hash-only, exactly the
     *  pre-fix shape, and this KDoc says so rather than implying
     *  tamper-evidence the build does not have. */
    private val manifestKey: ByteArray? = null,
    /** W5 payload encryption: a raw 32-byte payload key (the wired
     *  path HKDF-derives it from the identity seed; a caller may
     *  instead supply a key decoded from a C20 recovery key sheet). */
    private val payloadKey: ByteArray? = null,
    /** W5 payload encryption, passphrase path: when no raw
     *  [payloadKey] is given, the payload key is PBKDF2-derived from
     *  this passphrase with a per-backup salt recorded in the
     *  manifest. When BOTH are null the service keeps the exact
     *  pre-encryption (W4-B) plaintext behaviour — and, being
     *  unconfigured, it is also the only configuration that will
     *  restore a legacy plaintext backup (see [restore]). */
    private val payloadPassphrase: String? = null,
    /** W12-DS P8-F1/F2: fail-closed by default. An unconfigured
     *  service (no payload key/passphrase, or no manifest key)
     *  REFUSES to back up, verify or restore instead of silently
     *  writing/authenticating-nothing plaintext. Legacy plaintext
     *  behaviour exists ONLY behind this explicit opt-in, used by
     *  the pre-encryption regression fixtures; production wiring
     *  (PlatformStores.backupService) always passes both keys. */
    private val allowLegacyPlaintext: Boolean = false
) {
    init {
        require(payloadKey == null || payloadKey.size == 32) { "a backup payload key is exactly 32 bytes" }
    }

    private val encryptionConfigured: Boolean get() = payloadKey != null || payloadPassphrase != null

    fun sha(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }

    private fun manifestMac(entryLines: String): String? {
        val key = manifestKey ?: return null
        val mac = javax.crypto.Mac.getInstance("HmacSHA256")
        mac.init(javax.crypto.spec.SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(entryLines.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }

    /** The payload key for a backup whose manifest carries [salt]
     *  (passphrase-derived at backup time), or the configured key.
     *  Null when this service cannot open encrypted payloads. */
    private fun payloadKeyFor(salt: ByteArray?): ByteArray? = when {
        payloadKey != null -> payloadKey
        payloadPassphrase != null && salt != null ->
            BackupCrypto.deriveKey(payloadPassphrase, salt)
        else -> null
    }

    /**
     * [safFolders] are caller-supplied ONLY from SAF grants; this
     * engine has no path to any folder the user did not grant.
     */
    @Synchronized
    fun backup(destination: SafTree, safFolders: Map<String, Map<String, ByteArray>> = emptyMap()): Result<BackupManifest> {
        fun refuse(r: String): Result<BackupManifest> { audit.append("backup_refused", "reason=$r"); return Result.failure(IllegalStateException(r)) }
        if (!BackupPolicy.isEnabled()) return refuse("policy rmm.backup.enabled is OFF")
        // W12-DS P8-F1/F2 fail-closed: no silent plaintext, no
        // unauthenticated manifest.
        if (!allowLegacyPlaintext && !encryptionConfigured)
            return refuse("no payload key or passphrase is configured — backups are encrypted or refused, never plaintext")
        if (!allowLegacyPlaintext && manifestKey == null)
            return refuse("no manifest key is configured — an unauthenticated manifest cannot prove tamper, so backup refuses")
        if (!destination.granted()) return refuse("destination is not a user-granted storage tree (user-owned storage only)")
        val all = mutableMapOf<String, ByteArray>()
        stores.files().forEach { (k, v) -> all["acp/$k"] = v }
        safFolders.forEach { (folder, files) -> files.forEach { (k, v) -> all["saf/$folder/$k"] = v } }
        if (all.isEmpty()) return refuse("nothing in scope to back up")
        // W12-DS P8-F6/F14: refuse unwritable/unparseable names at
        // backup time rather than emitting an unrestorable tree.
        for (name in all.keys) if (!entryNameValid(name)) return refuse("entry name outside the allow-list: $name")
        // bd-and-rest F4 fix: time/UUID-based ids — the old
        // in-memory counter restarted at 1 every process, so the
        // first backup after each restart overwrote "backup-1".
        val id = "backup-" + java.util.UUID.randomUUID().toString().replace("-", "").take(20)
        // W5: with a payload key configured, EVERY payload file is
        // encrypted before it leaves for user storage — there is no
        // plaintext mode in an encryption-configured service. The
        // manifest hash is over the stored (ciphertext) bytes.
        val salt = if (payloadKey == null && payloadPassphrase != null) BackupCrypto.newSalt() else null
        val key = payloadKeyFor(salt)
        val stored = if (key != null) all.mapValues { (name, bytes) -> BackupCrypto.encrypt(key, id, name, bytes) } else all
        val entries = stored.mapValues { sha(it.value) }
        for ((name, bytes) in stored) if (!destination.write("$id/$name", bytes)) return refuse("destination write failed: $name")
        val headerLines = mutableListOf<String>()
        if (key != null) {
            headerLines.add("#enc\taes-256-gcm\tv2")
            if (salt != null) {
                headerLines.add("#kdf\tpbkdf2-sha256\t${BackupCrypto.KDF_ITERATIONS}")
                headerLines.add("#salt\t${Base64.getEncoder().encodeToString(salt)}")
            } else {
                headerLines.add("#kdf\traw-key")
            }
        }
        val entryLines = entries.entries.joinToString("\n") { "${it.key}\t${it.value}" }
        val macInput = (headerLines + entryLines).joinToString("\n")
        val body = if (headerLines.isEmpty()) entryLines else (headerLines + entryLines).joinToString("\n")
        val manifestText = manifestMac(macInput)?.let { "$body\n#hmac\t$it" } ?: body
        if (!destination.write("$id/manifest.txt", manifestText.toByteArray())) return refuse("manifest write failed")
        val m = BackupManifest(id, clockMs(), entries, setOf("acp_stores") + if (safFolders.isEmpty()) emptySet() else setOf("saf_granted"))
        audit.append("backup_created", "id=$id files=${entries.size} kinds=${m.sourceKinds.joinToString(",")}")
        return Result.success(m)
    }

    /** A parsed manifest: entry hashes (over STORED bytes) plus the
     *  W5 encryption headers, when present. */
    private data class ParsedManifest(
        val entries: Map<String, String>,
        val encrypted: Boolean,
        val salt: ByteArray?,
        // W12-DS P8-F7: the exact bytes whose hashes verified —
        // restore writes/decrypts THESE, never a second read.
        val verifiedBytes: Map<String, ByteArray> = emptyMap()
    )

    // W12-DS P8-F6/F14: entry names are validated BEFORE any I/O —
    // no "..", no absolute names, no TAB/newline (the manifest's
    // own separators), only acp/ or saf/ roots.
    private fun entryNameValid(name: String): Boolean =
        name.isNotBlank() && !name.startsWith("/") &&
            name.none { it == '\t' || it == '\n' || it == '\r' } &&
            name.split('/').none { it == ".." || it.isEmpty() } &&
            (name.startsWith("acp/") || name.startsWith("saf/"))

    private fun parseManifest(source: SafTree, backupId: String): Result<ParsedManifest> {
        val text = source.read("$backupId/manifest.txt") ?: return Result.failure(IllegalStateException("no manifest at destination"))
        val entries = mutableMapOf<String, String>()
        var macLine: String? = null
        var encrypted = false
        var salt: ByteArray? = null
        val entryLines = mutableListOf<String>()
        val headerLines = mutableListOf<String>()
        for (line in String(text, Charsets.UTF_8).lines()) {
            if (line.isBlank()) continue
            if (line.startsWith("#hmac\t")) { macLine = line.removePrefix("#hmac\t").trim(); continue }
            if (line.startsWith("#")) {
                headerLines.add(line)
                val parts = line.split("\t")
                when (parts[0]) {
                    "#enc" -> {
                        if (parts.size != 3 || parts[1] != "aes-256-gcm" || parts[2] != "v2")
                            return Result.failure(IllegalStateException("unsupported backup encryption header — restore refused"))
                        encrypted = true
                    }
                    "#salt" -> salt = try {
                        Base64.getDecoder().decode(parts.getOrNull(1) ?: "")
                    } catch (e: Exception) {
                        return Result.failure(IllegalStateException("corrupt manifest: bad salt"))
                    }
                    "#kdf" -> Unit // informational; the salt + service config decide derivation
                    else -> return Result.failure(IllegalStateException("corrupt manifest: unknown header ${parts[0]}"))
                }
                continue
            }
            val parts = line.split("\t"); if (parts.size != 2) return Result.failure(IllegalStateException("corrupt manifest"))
            entries[parts[0]] = parts[1]
            entryLines.add(line)
        }
        if (manifestKey != null) {
            val expected = manifestMac((headerLines + entryLines).joinToString("\n"))
            if (macLine == null || expected == null ||
                !MessageDigest.isEqual(macLine.toByteArray(), expected.toByteArray())) {
                audit.append("backup_verify_failed", "id=$backupId file=manifest-mac")
                return Result.failure(IllegalStateException("manifest HMAC missing or invalid — restore refused"))
            }
        }
        // W12-DS P8-F6: validate every name before the first read.
        for (name in entries.keys) {
            if (!entryNameValid(name)) return Result.failure(IllegalStateException("entry name outside the allow-list: $name"))
        }
        val verified = mutableMapOf<String, ByteArray>()
        for ((name, hash) in entries) {
            val bytes = source.read("$backupId/$name") ?: return Result.failure(IllegalStateException("missing file in backup: $name"))
            if (sha(bytes) != hash) { audit.append("backup_verify_failed", "id=$backupId file=$name"); return Result.failure(IllegalStateException("hash mismatch: $name — restore refused")) }
            verified[name] = bytes
        }
        return Result.success(ParsedManifest(entries, encrypted, salt, verified))
    }

    /** Verify: every hash must match, and (with a manifest key
     *  wired) the manifest HMAC must be present and valid. Any
     *  mismatch refuses the WHOLE backup. Verification is over the
     *  stored bytes, so it needs no payload key. */
    @Synchronized
    fun verify(source: SafTree, backupId: String): Result<BackupManifest> {
        // W12-DS P8-F20: the source grant is checked like every
        // other tree; P8-F2: no manifest key = no verification.
        if (!source.granted()) return Result.failure(IllegalStateException("backup source is not a user-granted storage tree"))
        if (!allowLegacyPlaintext && manifestKey == null)
            return Result.failure(IllegalStateException("no manifest key is configured — manifest cannot be authenticated, verify refused"))
        val parsed = parseManifest(source, backupId)
        if (parsed.isFailure) return Result.failure(parsed.exceptionOrNull()!!)
        val p = parsed.getOrThrow()
        audit.append("backup_verified", "id=$backupId files=${p.entries.size}")
        return Result.success(BackupManifest(backupId, 0, p.entries, emptySet()))
    }

    /**
     * bd-and-rest F4 fix — the restore the header always promised:
     * runs [verify] FIRST (every hash + the manifest HMAC) and only
     * then writes anything back. Names are allow-listed by shape:
     * only `acp/…` and `saf/…` entries restore, and any name with a
     * `..` segment refuses the whole restore before a single write.
     * The target receives each entry under its backed-up name.
     */
    @Synchronized
    fun restore(source: SafTree, backupId: String, target: SafTree): Result<BackupManifest> {
        fun refuse(r: String): Result<BackupManifest> { audit.append("backup_restore_refused", "id=$backupId reason=$r"); return Result.failure(IllegalStateException(r)) }
        if (!BackupPolicy.isEnabled()) return refuse("policy rmm.backup.enabled is OFF")
        if (!target.granted()) return refuse("restore target is not a user-granted storage tree")
        // W12-DS P8-F20/F2: source grant + manifest authentication.
        if (!source.granted()) return refuse("backup source is not a user-granted storage tree")
        if (!allowLegacyPlaintext && manifestKey == null)
            return refuse("no manifest key is configured — manifest cannot be authenticated, restore refused")
        val parsed = parseManifest(source, backupId)
        if (parsed.isFailure) return refuse("verification failed: ${parsed.exceptionOrNull()?.message}")
        val p = parsed.getOrThrow()
        val manifest = BackupManifest(backupId, 0, p.entries, emptySet())
        for (name in manifest.entries.keys) {
            if (name.split('/').any { it == ".." } ||
                !(name.startsWith("acp/") || name.startsWith("saf/"))) {
                return refuse("entry name outside the allow-list: $name")
            }
        }
        // W5 restore law (the C20 discipline): EVERY entry is
        // decrypted into memory BEFORE the first write, so a wrong
        // key or a tampered ciphertext refuses with the target
        // byte-identical. An encryption-configured service refuses
        // a legacy PLAINtext backup outright — accepting one would
        // be a silent downgrade of the at-rest guarantee.
        val plain = mutableMapOf<String, ByteArray>()
        if (p.encrypted) {
            val key = payloadKeyFor(p.salt)
                ?: return refuse("backup is encrypted but this service holds no payload key for it — restore refused, nothing written")
            for (name in manifest.entries.keys) {
                // W12-DS P8-F7: decrypt the VERIFIED bytes.
                val storedBytes = p.verifiedBytes[name] ?: return refuse("missing file in backup: $name")
                plain[name] = try {
                    BackupCrypto.decrypt(key, backupId, name, storedBytes)
                } catch (e: Exception) {
                    return refuse("payload decryption failed for $name (wrong key or tampered ciphertext) — restore refused, nothing written")
                }
            }
        } else {
            if (encryptionConfigured) {
                return refuse("backup payload is NOT encrypted but this service is encryption-configured — legacy plaintext backups are refused, never silently downgraded")
            }
            // W12-DS P8-F1: plaintext restore only behind the
            // explicit legacy opt-in.
            if (!allowLegacyPlaintext) {
                return refuse("backup payload is NOT encrypted and this service does not allow legacy plaintext — restore refused, nothing written")
            }
            for (name in manifest.entries.keys) {
                plain[name] = p.verifiedBytes[name] ?: return refuse("missing file in backup: $name")
            }
        }
        for ((name, bytes) in plain) {
            if (!target.write(name, bytes)) return refuse("restore write failed: $name")
        }
        audit.append("backup_restored", "id=$backupId files=${manifest.entries.size}")
        return Result.success(manifest)
    }
}
