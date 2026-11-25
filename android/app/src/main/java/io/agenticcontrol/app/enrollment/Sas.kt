package io.agenticcontrol.app.enrollment

import java.security.MessageDigest
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * U9 — Short Authentication String (SAS) for pairing/enrollment
 * (CENSUS-UNION U9). PINNED RENDERING (both trees): 6 decimal
 * digits + 4 words from the fixed 256-word list below. Display
 * form: "961 003 \u00b7 tat vav gat hab".
 *
 * PINNED ALGORITHM (must match the C# mirror byte-for-byte; shared
 * test vectors live in both suites):
 *   key    = SHA-256(initiatorPub || responderPub)  (32-byte keys)
 *   digest = HMAC-SHA-256(key, UTF8("ACP-SAS-v1") || 0x00 || UTF8(transcriptId))
 *   digits = BE-uint32(digest[0..4]) mod 1,000,000, zero-padded to 6
 *   words  = WORDS[digest[4]], WORDS[digest[5]], WORDS[digest[6]], WORDS[digest[7]]
 * Roles are ORDERED: initiator = the device presenting/redeeming,
 * responder = the device that minted the code.
 *
 * Confirmation semantics (coordinator ruling for U9, RULING
 * 2026-11-19 endpoint-local pattern): pairing completes
 * cryptographically as before — SAS never blocks the consent
 * floor. The record carries the SAS and an honest confirmed flag:
 * UNCONFIRMED ("not yet verified") until the human at the endpoint
 * locally confirms the compared strings match.
 */
data class SasString(val digits: String, val words: List<String>) {
    val display: String
        get() = if (digits.length == 6)
            digits.substring(0, 3) + " " + digits.substring(3) + " \u00b7 " + words.joinToString(" ")
        else digits + " \u00b7 " + words.joinToString(" ")
    override fun toString(): String = display
}

object PairingSas {
    const val STATE_CONFIRMED = "sas_confirmed"
    const val STATE_UNCONFIRMED = "sas_unconfirmed"
    /** W13 P4-F5: ABSENT is a distinct state — no SAS was ever
     *  computed for this record (legacy enroller sent no key), as
     *  opposed to UNCONFIRMED, where a SAS exists and awaits the
     *  owner's comparison. The two previously shared one state,
     *  so the UI could not tell "compare these digits" from
     *  "there are no digits to compare". */
    const val STATE_ABSENT = "sas_absent"

    /** U9 follow-up audit action: enrollee received an enrollment
     *  response from a LEGACY enroller carrying no public key, so
     *  no SAS could be computed enrollee-side. Named and audited —
     *  never silently faked. */
    const val AUDIT_ABSENT_NO_ENROLLER_KEY = "sas_absent_no_enroller_key"

    /** U9 follow-up audit action: an enrollment response carried a
     *  public key whose fingerprint does NOT match the enroller
     *  DeviceId the enrollee already held (the commitment from the
     *  code/QR transcript). Refused and audited — the MITM leg. */
    const val AUDIT_ENROLLER_KEY_MISMATCH = "sas_enroller_key_mismatch"

    /** U9 follow-up audit action: an enrollment response carried a
     *  malformed enroller public key. Refused and audited. */
    const val AUDIT_ENROLLER_KEY_MALFORMED = "sas_enroller_key_malformed"

    /** The fixed 256-word list (index = one digest byte). Pinned
     *  verbatim in the C# mirror — edits MUST land in both trees. */
    val WORDS: List<String> = listOf(
        "bab", "bad", "bag", "bak", "bal", "bam", "ban", "bap",
        "bar", "bas", "bat", "bav", "beb", "bed", "beg", "bek",
        "dab", "dad", "dag", "dak", "dal", "dam", "dan", "dap",
        "dar", "das", "dat", "dav", "deb", "ded", "deg", "dek",
        "fab", "fad", "fag", "fak", "fal", "fam", "fan", "fap",
        "far", "fas", "fat", "fav", "feb", "fed", "feg", "fek",
        "gab", "gad", "gag", "gak", "gal", "gam", "gan", "gap",
        "gar", "gas", "gat", "gav", "geb", "ged", "geg", "gek",
        "hab", "had", "hag", "hak", "hal", "ham", "han", "hap",
        "har", "has", "hat", "hav", "heb", "hed", "heg", "hek",
        "jab", "jad", "jag", "jak", "jal", "jam", "jan", "jap",
        "jar", "jas", "jat", "jav", "jeb", "jed", "jeg", "jek",
        "kab", "kad", "kag", "kak", "kal", "kam", "kan", "kap",
        "kar", "kas", "kat", "kav", "keb", "ked", "keg", "kek",
        "lab", "lad", "lag", "lak", "lal", "lam", "lan", "lap",
        "lar", "las", "lat", "lav", "leb", "led", "leg", "lek",
        "mab", "mad", "mag", "mak", "mal", "mam", "man", "map",
        "mar", "mas", "mat", "mav", "meb", "med", "meg", "mek",
        "nab", "nad", "nag", "nak", "nal", "nam", "nan", "nap",
        "nar", "nas", "nat", "nav", "neb", "ned", "neg", "nek",
        "pab", "pad", "pag", "pak", "pal", "pam", "pan", "pap",
        "par", "pas", "pat", "pav", "peb", "ped", "peg", "pek",
        "rab", "rad", "rag", "rak", "ral", "ram", "ran", "rap",
        "rar", "ras", "rat", "rav", "reb", "red", "reg", "rek",
        "sab", "sad", "sag", "sak", "sal", "sam", "san", "sap",
        "sar", "sas", "sat", "sav", "seb", "sed", "seg", "sek",
        "tab", "tad", "tag", "tak", "tal", "tam", "tan", "tap",
        "tar", "tas", "tat", "tav", "teb", "ted", "teg", "tek",
        "vab", "vad", "vag", "vak", "val", "vam", "van", "vap",
        "var", "vas", "vat", "vav", "veb", "ved", "veg", "vek",
        "zab", "zad", "zag", "zak", "zal", "zam", "zan", "zap",
        "zar", "zas", "zat", "zav", "zeb", "zed", "zeg", "zek",
    )

    /** Compute the SAS. Null (fail-closed, never throws) for keys
     *  that are not exactly 32 bytes or an empty transcript. */
    fun compute(initiatorPublicKey: ByteArray?, responderPublicKey: ByteArray?, transcriptId: String?): SasString? {
        if (initiatorPublicKey == null || initiatorPublicKey.size != 32) return null
        if (responderPublicKey == null || responderPublicKey.size != 32) return null
        if (transcriptId.isNullOrBlank()) return null
        val key = MessageDigest.getInstance("SHA-256")
            .digest(initiatorPublicKey + responderPublicKey)
        val domain = "ACP-SAS-v1".toByteArray(Charsets.UTF_8)
        // W12-DS P3-F23: the pinned algorithm is UTF8(transcriptId)
        // verbatim — no trim (the blank check above already ran).
        val transcript = transcriptId.toByteArray(Charsets.UTF_8)
        val message = ByteArray(domain.size + 1 + transcript.size)
        domain.copyInto(message, 0)
        transcript.copyInto(message, domain.size + 1)
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        val digest = mac.doFinal(message)
        // W12-DS P3-F7: unsigned interpretation — the old signed Int
        // made digest[0] >= 0x80 (half of outputs) render negative
        // digits ("-00001") and diverge from the C# uint mirror.
        val n = ((digest[0].toInt() and 0xFF) shl 24) or ((digest[1].toInt() and 0xFF) shl 16) or
            ((digest[2].toInt() and 0xFF) shl 8) or (digest[3].toInt() and 0xFF)
        val digits = "%06d".format(java.util.Locale.ROOT, (n.toLong() and 0xFFFFFFFFL) % 1000000L)
        val words = listOf(
            WORDS[digest[4].toInt() and 0xFF], WORDS[digest[5].toInt() and 0xFF],
            WORDS[digest[6].toInt() and 0xFF], WORDS[digest[7].toInt() and 0xFF]
        )
        return SasString(digits, words)
    }

    /** Base64-key overload (the form enrollment presents). */
    fun computeBase64(initiatorPublicKeyBase64: String?, responderPublicKeyBase64: String?, transcriptId: String?): SasString? {
        val init = try { Base64.getDecoder().decode(initiatorPublicKeyBase64 ?: "") } catch (_: Exception) { return null }
        val resp = try { Base64.getDecoder().decode(responderPublicKeyBase64 ?: "") } catch (_: Exception) { return null }
        return compute(init, resp, transcriptId)
    }

    /** Whitespace/case-tolerant display comparison for confirm. */
    fun displaysMatch(a: String?, b: String?): Boolean {
        if (a.isNullOrBlank() || b.isNullOrBlank()) return false
        // Compact form: separators and digit grouping are display
        // formatting, not content.
        fun norm(s: String): String = s.filter { !it.isWhitespace() && it != '\u00b7' }.lowercase()
        return norm(a) == norm(b)
    }
}
