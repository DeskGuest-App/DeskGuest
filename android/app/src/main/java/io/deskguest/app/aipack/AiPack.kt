package io.deskguest.app.aipack

import io.deskguest.app.transport.sha256Hex
import java.io.File

/**
 * Local AI pack machinery (Block F, D25 — Android mirror of the
 * Windows AiPackService): a wizard-offered OPTIONAL download of
 * UI-TARS-1.5-7B (Apache-2.0) from the author's OFFICIAL source
 * only, hash-verified against pins shipped in the product, licence
 * shown and accepted before any download, and NO override on hash
 * mismatch (the partial is deleted and the download refuses).
 *
 * Pin state (A3, 2026-11-22), same as Windows: pins CAPTURED
 * from the author's own Hugging Face listing at repo commit
 * 683d002dd99d8f95104d31e70391a39348857f4e via
 * scripts/aipack_pin_capture.py — non-LFS files byte-downloaded
 * at capture time and checked against the author's listing oid,
 * LFS pins from the author's LFS metadata (full byte-verification
 * of the large shards is the recorded remainder in the capture
 * record). The manifest carries an integrity digest over its pin
 * list: a manifest edited to match a tampered artefact fails
 * [AiPackManifest.validateIntegrity] and the download refuses
 * before any fetch. The pack's runtime is an adopted
 * component class whose audit status is UNAUDITED (T7/S11),
 * recorded as such; the pack AI is a leashed participant under its
 * own identity ([AiPackManifest.PACK_USER_ID]), never admin.
 */
data class PackFile(val relativePath: String, val sha256: String, val sizeBytes: Long)

data class AiPackManifest(
    val packId: String,
    val displayName: String,
    val licenseId: String,
    val licenseSummary: String,
    val officialBaseUrl: String,
    val files: List<PackFile>,
    val pinsCaptured: Boolean,
    val auditStatus: String,
    val manifestDigest: String
) {
    /** The manifest's own integrity protection (mirror of the
     *  Windows ValidateIntegrity): an edited pin list without a
     *  matching digest fails, as do an inconsistent pinsCaptured
     *  flag, malformed pins, duplicates and escaping paths. */
    fun validateIntegrity(): Pair<Boolean, String> {
        if (pinsCaptured != files.isNotEmpty())
            return false to "manifest integrity failure: PinsCaptured is $pinsCaptured but the manifest carries ${files.size} file(s) — refusing"
        val seen = HashSet<String>()
        for (f in files) {
            if (f.relativePath.contains("..") || f.relativePath.startsWith("/"))
                return false to "manifest integrity failure: pack file path '${f.relativePath}' escapes the pack folder — refusing"
            if (!seen.add(f.relativePath))
                return false to "manifest integrity failure: duplicate pack file path '${f.relativePath}' — refusing"
            if (f.sha256.length != 64 || !f.sha256.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' })
                return false to "manifest integrity failure: pin for '${f.relativePath}' is not a SHA-256 hex digest — refusing"
            if (f.sizeBytes <= 0)
                return false to "manifest integrity failure: pin for '${f.relativePath}' carries a non-positive size — refusing"
        }
        if (pinsCaptured) {
            if (manifestDigest.isBlank())
                return false to "manifest integrity failure: pins are captured but no manifest digest is recorded — refusing"
            val actual = computeManifestDigest(packId, officialBaseUrl, files)
            if (!actual.equals(manifestDigest, ignoreCase = true))
                return false to "manifest integrity failure: the manifest digest does not match the pinned file list — the manifest has been altered since its pins were captured; refusing"
        }
        return true to "manifest integrity verified"
    }

    companion object {
        const val PACK_USER_ID = "local-ai-pack"

        /** Canonical digest, byte-identical to the Windows form:
         *  SHA-256 (lowercase hex) of PackId + "\n" + baseUrl +
         *  "\n" + "path|sha256-lowercase|size\n" per file, UTF-8. */
        fun computeManifestDigest(packId: String, officialBaseUrl: String, files: List<PackFile>): String {
            val sb = StringBuilder()
            sb.append(packId).append('\n').append(officialBaseUrl).append('\n')
            for (f in files)
                sb.append(f.relativePath).append('|').append(f.sha256.lowercase()).append('|').append(f.sizeBytes).append('\n')
            val digest = java.security.MessageDigest.getInstance("SHA-256")
                .digest(sb.toString().toByteArray(Charsets.UTF_8))
            return digest.joinToString("") { "%02x".format(it) }
        }

        val UI_TARS_1_5_7B = AiPackManifest(
            packId = "ui-tars-1.5-7b",
            displayName = "UI-TARS-1.5-7B (local AI pack)",
            licenseId = "Apache-2.0",
            licenseSummary = "Apache License 2.0 — you may use, modify and redistribute this model under the " +
                "Apache-2.0 terms, including the NOTICE and patent-grant terms. The full licence " +
                "text ships with the download (LICENSE file in the author's repository). " +
                "Pack rule (D25): Apache-2.0/MIT checkpoints only.",
            officialBaseUrl = "https://huggingface.co/ByteDance-Seed/UI-TARS-1.5-7B/resolve/main",
            files = listOf(
                PackFile(".gitattributes", "34448b82c17d60fec9b65b1f093c115ddbaadc04beb1b0140b6bfed2e012a930", 1570L),
                PackFile("README.md", "fd6ebdc23c119b356e12876c964597d2920e3a2878424a6b5a5b8706e6bc23c4", 8370L),
                PackFile("added_tokens.json", "58b54bbe36fc752f79a24a271ef66a0a0830054b4dfad94bde757d851968060b", 605L),
                PackFile("chat_template.json", "ad60d90252ed0b0705ba14e2d0ad0fec0beac1ea955642b54059b36052d8bc96", 1050L),
                PackFile("config.json", "77d9ec7321cc572e3579e2c84799c9cadaded63c49ce93b101733349fc330c43", 1374L),
                PackFile("merges.txt", "8831e4f1a044471340f7c0a83d7bd71306a5b867e95fd870f74d0c5308a904d5", 1671853L),
                PackFile("model-00001-of-00007.safetensors", "791690d15fbd7cb35c5024562a333b6962b4f399e8e00c1d039d516744fd8a9c", 4952311608L),
                PackFile("model-00002-of-00007.safetensors", "63fdb5528959e72f74516d7e4a5e66337e129428ad49ed82acef03ef648991ca", 4984124272L),
                PackFile("model-00003-of-00007.safetensors", "8cd4f439df9219991790e0bd557176445165bfcdcae6b98acd4b2a4e70b4adfb", 4932743936L),
                PackFile("model-00004-of-00007.safetensors", "8cd5267eecb26fd6c77a88cf76a52805b887f2c571c424eb244b97464d3071f2", 4998852296L),
                PackFile("model-00005-of-00007.safetensors", "68774baed4c0324a411f21b30d3a9e69959f0ac0713eef456dbaaa798d0076d0", 4984124336L),
                PackFile("model-00006-of-00007.safetensors", "4fce8e78b8af34aa378ab2e6b627711a2527a4de66256d81d444b5e95b956c05", 4932743992L),
                PackFile("model-00007-of-00007.safetensors", "7b9c3b8638e8cab6cacf3315f2326816ceef2afc0706647d71be37494b462d9c", 3383846800L),
                PackFile("model.safetensors.index.json", "6030a4a846a2252af2c3cad013ceb7eac26b263bdfa774ce68c151643ca0270e", 57619L),
                PackFile("preprocessor_config.json", "f2058c716eef96ccaed1cc1e2d0c08306b62586d535b28d9d08e691b2fab7ca0", 350L),
                PackFile("special_tokens_map.json", "76862e765266b85aa9459767e33cbaf13970f327a0e88d1c65846c2ddd3a1ecd", 613L),
                PackFile("tokenizer.json", "9c5ae00e602b8860cbd784ba82a8aa14e8feecec692e7076590d014d7b7fdafa", 11421896L),
                PackFile("tokenizer_config.json", "d8fae64aa6999ec858de2e7e1823f46133514627129f664cc761376c5f520a5e", 7253L),
                PackFile("vocab.json", "ca10d7e9fb3ed18575dd1e277a2579c16d108e32f27439684afa0e10b1440910", 2776833L)
            ),
            pinsCaptured = true,
            auditStatus = "unaudited",
            manifestDigest = "8398a0f9d6cf75e02f48e51226c904425c3d52372cdc56555c5ce9f909fb3157"
        )

        fun forFixture(baseUrl: String, files: List<PackFile>): AiPackManifest =
            AiPackManifest("fixture-pack", "Fixture pack (test only)", "Apache-2.0",
                "Fixture licence text (test only)", baseUrl, files, pinsCaptured = true, auditStatus = "unaudited-fixture",
                manifestDigest = computeManifestDigest("fixture-pack", baseUrl, files))
    }
}

class AiPackService(val manifest: AiPackManifest) {
    var licenceAccepted: Boolean = false
        private set

    /** bd-and-remote F7 fix: WHO accepted the licence and WHEN,
     *  recorded at acceptance and persisted through [licenceSink]
     *  when the platform wires one (a record line the wiring
     *  stores). Before this fix acceptLicence ignored its userId
     *  and kept only a Boolean in memory. */
    var licenceAcceptedBy: String? = null
        private set
    var licenceAcceptedAtMs: Long = 0L
        private set
    var licenceSink: ((String) -> Unit)? = null

    fun licenceToShow(): String =
        "${manifest.displayName}\nLicence: ${manifest.licenseId}\n${manifest.licenseSummary}\n" +
            "Source (official, the only source): ${manifest.officialBaseUrl}\n" +
            "Every downloaded file is verified against a hash pinned in the product; a mismatch refuses the download — there is no override."

    fun acceptLicence(userId: String, nowMs: Long = System.currentTimeMillis()) {
        licenceAccepted = true
        licenceAcceptedBy = userId
        licenceAcceptedAtMs = nowMs
        try {
            licenceSink?.invoke("licence_accepted pack=${manifest.packId} by=$userId atMs=$nowMs")
        } catch (_: Exception) { /* a failing sink never un-accepts */ }
    }

    /** Restore an acceptance record (the wiring reads its stored
     *  line back at startup). Only the exact record shape this
     *  class emits is honoured. */
    fun restoreLicenceRecord(line: String?): Boolean {
        if (line.isNullOrBlank()) return false
        val parts = line.trim().split(' ')
        if (parts.size != 4 || parts[0] != "licence_accepted") return false
        if (parts[1] != "pack=${manifest.packId}") return false
        if (!parts[2].startsWith("by=")) return false
        val at = parts[3].removePrefix("atMs=").toLongOrNull() ?: return false
        licenceAccepted = true
        licenceAcceptedBy = parts[2].removePrefix("by=")
        licenceAcceptedAtMs = at
        return true
    }

    /** Download every pinned file. [fetcher] writes the file at
     *  (url, destPath); tests supply a fixture fetcher. */
    fun download(
        targetDir: File,
        fetcher: (url: String, dest: File) -> Unit,
        sourceBaseOverride: String? = null,
        fixtureMode: Boolean = false
    ): Pair<Boolean, String> {
        if (!licenceAccepted)
            return false to "licence not accepted — the wizard shows the licence before any download (D25)"
        val source = sourceBaseOverride ?: manifest.officialBaseUrl
        if (!fixtureMode && source != manifest.officialBaseUrl)
            return false to "wrong source — the pack downloads only from the author's official source (${manifest.officialBaseUrl}); '$source' refused, no override"
        if (fixtureMode && source == AiPackManifest.UI_TARS_1_5_7B.officialBaseUrl)
            return false to "fixture mode against the production source is refused — fixtures stay local and named"
        val integrity = manifest.validateIntegrity()
        if (!integrity.first) return integrity
        if (!manifest.pinsCaptured || manifest.files.isEmpty())
            return false to "no pinned hashes are captured for this pack yet — download refused (a download without a pin to verify against is not offered)"
        if (!fixtureMode && manifest.officialBaseUrl != AiPackManifest.UI_TARS_1_5_7B.officialBaseUrl)
            return false to "refused: source '${manifest.officialBaseUrl}' is not the author's official source — the pack downloads from the official source only, and there is no source override"
        targetDir.mkdirs()
        for (file in manifest.files) {
            if (file.relativePath.contains("..") || file.relativePath.startsWith("/"))
                return false to "pack file path '${file.relativePath}' escapes the pack folder — refused"
            // F7: free-storage check before each shard lands.
            val usable = targetDir.usableSpace
            if (usable in 1 until file.sizeBytes)
                return false to "not enough free storage for ${file.relativePath} (${file.sizeBytes} bytes needed, $usable usable) — refused before download"
            val dest = File(targetDir, file.relativePath)
            dest.parentFile?.mkdirs()
            val partial = File(targetDir, file.relativePath + ".partial")
            try {
                fetcher(source.trimEnd('/') + "/" + file.relativePath, partial)
            } catch (e: Exception) {
                partial.delete()
                return false to "download of ${file.relativePath} failed: ${e.javaClass.simpleName}"
            }
            // F7 fix: size + hash are computed STREAMING (fixed
            // buffer). The old readBytes() loaded a whole shard —
            // several GB for UI-TARS — into memory and would OOM
            // any Android device.
            if (partial.length() != file.sizeBytes) {
                partial.delete()
                return false to "size mismatch for ${file.relativePath} — refused, partial deleted"
            }
            if (sha256FileHex(partial) != file.sha256.lowercase()) {
                partial.delete()
                return false to "hash mismatch for ${file.relativePath} — refused and reported; the partial was deleted and there is no override"
            }
            if (!partial.renameTo(dest)) {
                partial.copyTo(dest, overwrite = true); partial.delete()
            }
        }
        return true to "pack downloaded and verified against its pinned hashes"
    }

    fun verifyInstalled(targetDir: File): Pair<Boolean, String> {
        val integrity = manifest.validateIntegrity()
        if (!integrity.first) return integrity
        if (!manifest.pinsCaptured) return false to "no pins captured — nothing can be verified"
        for (file in manifest.files) {
            val f = File(targetDir, file.relativePath)
            if (!f.exists()) return false to "missing ${file.relativePath}"
            if (sha256FileHex(f) != file.sha256.lowercase())
                return false to "hash mismatch for ${file.relativePath} — the installed pack does not match its pins"
        }
        return true to "installed pack verified against its pinned hashes"
    }

    companion object {
        /** Streaming SHA-256 of a file (1 MiB buffer) — the only
         *  hash path for pack files; whole-file reads are gone. */
        fun sha256FileHex(file: File): String {
            val digest = java.security.MessageDigest.getInstance("SHA-256")
            file.inputStream().use { input ->
                val buffer = ByteArray(1 shl 20)
                while (true) {
                    val n = input.read(buffer)
                    if (n < 0) break
                    digest.update(buffer, 0, n)
                }
            }
            return digest.digest().joinToString("") { "%02x".format(it) }
        }
    }
}
