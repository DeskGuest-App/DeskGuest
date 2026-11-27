using System.Security.Cryptography;
using System.Text;

namespace DeskGuest.Shared.Enrollment;

/// <summary>
/// U9 — Short Authentication String (SAS) for pairing/enrollment
/// (CENSUS-UNION U9). PINNED RENDERING (spec commit, both trees):
/// 6 decimal digits + 4 words from the fixed 256-word list below —
/// never emoji, never digits-only. Display form:
/// "961 003 \u00b7 tat vav gat hab".
///
/// PINNED ALGORITHM (must match the Kotlin mirror byte-for-byte;
/// shared test vectors live in both suites):
///   key    = SHA-256(initiatorPub \u2016 responderPub)   (32-byte keys)
///   digest = HMAC-SHA-256(key, UTF8("DeskGuest-SAS-v1") \u2016 0x00 \u2016 UTF8(transcriptId))
///   digits = BE-uint32(digest[0..4]) mod 1,000,000, zero-padded to 6
///   words  = WordList[digest[4]], WordList[digest[5]],
///            WordList[digest[6]], WordList[digest[7]]
/// Roles are ORDERED: initiator = the device presenting/redeeming,
/// responder = the device that minted the code. Both sides compute
/// with the same role order, so both derive the identical string;
/// substituting EITHER key (a MITM swapping its own key for either
/// peer's) changes the string on the honest side.
///
/// Confirmation semantics (coordinator ruling for U9, following the
/// RULING 2026-11-19 endpoint-local pattern): pairing completes
/// cryptographically exactly as before — SAS never blocks the
/// consent floor. The pairing/enrollment record carries the SAS and
/// an honest confirmed flag: it starts UNCONFIRMED ("not yet
/// verified") and flips only when the human at the endpoint
/// locally confirms the compared strings match. Nothing may set
/// the flag on the human's behalf.
/// </summary>
public sealed record SasString(string Digits, IReadOnlyList<string> Words)
{
    /// <summary>Human display form: "961 003 \u00b7 tat vav gat hab".</summary>
    public string Display =>
        Digits.Length == 6
            ? Digits.Substring(0, 3) + " " + Digits.Substring(3) + " \u00b7 " + string.Join(" ", Words)
            : Digits + " \u00b7 " + string.Join(" ", Words);

    public override string ToString() => Display;
}

public static class PairingSas
{
    public const string StateConfirmed = "sas_confirmed";
    public const string StateUnconfirmed = "sas_unconfirmed";

    /// <summary>U9 follow-up audit action: an enrollee received an
    /// enrollment response from a LEGACY enroller carrying no public
    /// key, so no SAS could be computed enrollee-side. The absence is
    /// named and audited — never silently faked as a SAS.</summary>
    public const string AuditAbsentNoEnrollerKey = "sas_absent_no_enroller_key";

    /// <summary>U9 follow-up audit action: an enrollment response
    /// carried a public key whose fingerprint does NOT match the
    /// enroller DeviceId the enrollee already held (the commitment
    /// from the code/QR transcript). The key — and any SAS derived
    /// from it — is refused. This is the MITM reveal leg.</summary>
    public const string AuditEnrollerKeyMismatch = "sas_enroller_key_mismatch";

    /// <summary>U9 follow-up audit action: an enrollment response
    /// carried a malformed enroller public key (bad base64, wrong
    /// length, or a small-order point). Refused and audited.</summary>
    public const string AuditEnrollerKeyMalformed = "sas_enroller_key_malformed";

    /// <summary>The fixed 256-word list (index = one digest byte).
    /// Generated as 16 onsets \u00d7 16 rimes; pinned verbatim in the
    /// Kotlin mirror — any edit here MUST land in both trees in the
    /// same commit or cross-platform SAS comparison silently breaks.</summary>
    public static readonly IReadOnlyList<string> WordList = new[]
    {
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
    };

    /// <summary>Compute the SAS. Null (fail-closed, never throws) for
    /// keys that are not exactly 32 bytes or an empty transcript.</summary>
    public static SasString? Compute(byte[]? initiatorPublicKey, byte[]? responderPublicKey, string? transcriptId)
    {
        if (initiatorPublicKey is null || initiatorPublicKey.Length != 32) return null;
        if (responderPublicKey is null || responderPublicKey.Length != 32) return null;
        if (string.IsNullOrWhiteSpace(transcriptId)) return null;
        var keyMaterial = new byte[64];
        Buffer.BlockCopy(initiatorPublicKey, 0, keyMaterial, 0, 32);
        Buffer.BlockCopy(responderPublicKey, 0, keyMaterial, 32, 32);
        var key = SHA256.HashData(keyMaterial);
        var domain = Encoding.UTF8.GetBytes("DeskGuest-SAS-v1");
        var transcript = Encoding.UTF8.GetBytes(transcriptId.Trim());
        var message = new byte[domain.Length + 1 + transcript.Length];
        Buffer.BlockCopy(domain, 0, message, 0, domain.Length);
        Buffer.BlockCopy(transcript, 0, message, domain.Length + 1, transcript.Length);
        byte[] digest;
        using (var hmac = new HMACSHA256(key))
            digest = hmac.ComputeHash(message);
        var n = (uint)((digest[0] << 24) | (digest[1] << 16) | (digest[2] << 8) | digest[3]);
        var digits = (n % 1000000).ToString("D6");
        var words = new[] { WordList[digest[4]], WordList[digest[5]], WordList[digest[6]], WordList[digest[7]] };
        return new SasString(digits, words);
    }

    /// <summary>Base64-key overload (the form enrollment presents).</summary>
    public static SasString? ComputeBase64(string? initiatorPublicKeyBase64, string? responderPublicKeyBase64, string? transcriptId)
    {
        byte[] init, resp;
        try
        {
            init = Convert.FromBase64String(initiatorPublicKeyBase64 ?? "");
            resp = Convert.FromBase64String(responderPublicKeyBase64 ?? "");
        }
        catch (FormatException) { return null; }
        return Compute(init, resp, transcriptId);
    }

    /// <summary>Constant-shape comparison of two display strings
    /// (case-insensitive, whitespace-tolerant) for the confirm path.</summary>
    public static bool DisplaysMatch(string? a, string? b)
    {
        if (string.IsNullOrWhiteSpace(a) || string.IsNullOrWhiteSpace(b)) return false;
        // Compact form: separators and digit grouping are display
        // formatting, not content — "108 306 · fad tal" and
        // "108306 fad tal" are the same SAS spoken/typed two ways.
        static string Norm(string s) => string.Concat(
            s.Where(c => !char.IsWhiteSpace(c) && c != '\u00b7')
             .Select(char.ToLowerInvariant));
        return string.Equals(Norm(a), Norm(b), StringComparison.Ordinal);
    }
}
