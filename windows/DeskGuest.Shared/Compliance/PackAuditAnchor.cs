using System.Text;

namespace DeskGuest.Shared.Compliance;

/// <summary>
/// W37 — KEYED anchoring for stored compliance packs, closing the
/// append-replay sibling hole W36-B §3 named: before W37 a stored
/// pack's integrity rested on an UNKEYED SHA-256 recorded in the
/// (unkeyed) enterprise audit chain, so a data-dir-only attacker
/// could alter a stored pack, recompute its hash, append a
/// matching "compliance_pack_compiled" record, and — after a Core
/// restart re-imported the chain from the data-dir file —
/// ComplianceService.VerifyStoredPack passed for the forged pack.
///
/// The fix reuses the W30/W36 pointer machinery verbatim in
/// discipline, not a parallel invention:
///   * the anchor key is the SAME runtime pointer-signing key
///     (PointerSigningCustody): private half custodied in the
///     install root, public half pinned in the install root,
///     (re)pinned only at install / production-signed update
///     events. It is the right anchor from the code: it is the
///     only runtime key whose custody domain is exactly the
///     install root a data-dir-only attacker cannot read, and
///     ComplianceService is composed in the same Core that
///     already composes that custody for UpdateManager.
///   * APPEND-THEN-SIGN (the W36 ordering): Compile appends the
///     compliance_pack_compiled record FIRST — its detail carries
///     the pre-append scheme marker pack_sig_scheme=v1, which can
///     live under the record's own hash — learns the appended
///     entry's (Seq, Hash), then signs the POSITION payload
///     (BuildPackPayload: domain separator + pack id + the pack's
///     content hash + that record's Seq + that record's Hash).
///   * The signature cannot live in the record it commits to (a
///     record's hash is computed over its detail), so it travels
///     in a FOLLOW-UP record, kind compliance_pack_signature,
///     whose detail names the compiled record's Seq and the
///     signing key's fingerprint. Both records are ordinary chain
///     records, so the anchor survives chain export/import — i.e.
///     a Core restart — with no new file format.
///   * VerifyStoredPack, in addition to every pre-W37 leg (chain
///     verifies, anchored record exists, recomputed hash matches
///     the anchored hash), requires for a scheme-marked record:
///     a signature record naming THAT record's Seq, whose
///     signature verifies over the position payload under the
///     install-root pin. The attacker's appended record sits at a
///     new Seq with a new Hash, so a replayed genuine signature
///     does not verify over it, and a forged signature cannot be
///     produced without the custodied seed: refusal lands at the
///     POSITION-BOUND signature leg, by name.
///
/// Migration (W17 fail-closed named pattern, W36 discipline):
/// packs compiled before keying carry no scheme marker and no
/// signature record — the named LEGACY-UNKEYED-PACK posture. Such
/// a pack is accepted on the unkeyed hash anchor ONLY while no
/// pack-keying witness survives: no scheme-marked compiled record
/// anywhere in the chain, no signature record anywhere in the
/// chain, and no composed custody that has begun keying. Once
/// pack keying has begun, an unsigned or position-less pack
/// record REFUSES BY NAME — never a silent acceptance.
///
/// Rotation: the pointer key rotates at each production-signed
/// update apply. Rotation archives the outgoing pin in the
/// install root (pointer-signing-pub-archive/&lt;fingerprint&gt;.pub,
/// written by PointerSigningCustody's rotation path) BEFORE the
/// new pin replaces it, and a pack signature record names its
/// signing key's fingerprint, so verification judges a pack under
/// the pin it was actually signed with — current or archived.
/// Packs therefore do NOT become unverifiable on rotation; new
/// packs sign under the rotated key.
///
/// Boundary, exact: a data-dir-only attacker can neither forge a
/// pack signature nor replay a genuine pack's signature onto an
/// appended record (position leg). What remains open is the same
/// named class as pointers: a WRITABLE INSTALL ROOT (restore pack
/// + chain + pin/archive together — every restored byte genuine),
/// and execution as the Core/SYSTEM, which can sign.
///
/// W45 / DS round-9 Item 4 parenthetical — FRESHNESS. Round 9
/// confirmed the boundary above within its terms and flagged the
/// parallel it did not cover: whole-chain rollback to an OLDER
/// GENUINE pack (truncate the chain to the older pack's position,
/// restore that pack — every byte genuine, every W37 leg passing
/// on the truncated chain) is the pointer leg's staged-rollback
/// shape. The pack leg's freshness rested on nothing before W45:
/// VerifyStoredPack judged the chain alone, and the chain is a
/// data-dir file. It closes with the same discipline as pointers
/// because the pack anchor already writes through the same
/// machinery: the SAME install-root anchor marker
/// (PointerAuditAnchor) over the SAME chain. A keyed Compile now
/// advances that marker to the position its two records landed
/// at (append first, marker second; a failed advance refuses the
/// compile by name and stores no pack), and VerifyStoredPack
/// judges the chain against the marker with the pointer leg's
/// freshness rule — shorter than the marker, or a rewritten
/// prefix at the marker's count, refuses by name; growth past
/// the marker still verifies. NEW BOUNDARY, exact: a data-dir-only
/// attacker can neither forge, replay (W37), nor whole-chain
/// roll back (W45) a compliance pack; rollback requires a
/// writable install root or Core/SYSTEM execution, as above.
///
/// W47 / DS round-10 Item 2 — the W45 pack advance was NOT
/// atomic with its appends: it ran outside the chain gate with
/// no chain save at all, naming a pre-gate snapshot, so a
/// concurrent pointer advance could be REGRESSED by it and the
/// staged rollback reopened. The compile's appends, verified
/// persist and advance are now ONE gated operation under the
/// chain owner's gate (see ComplianceService / PointerAuditAnchor
/// W47 note): the advance is computed from live entries inside
/// the gate, only after the persist verifies durable, and the
/// advance itself refuses any regression by name. The boundary
/// above is unchanged; it is now kept by construction.
/// </summary>
public static class PackAuditAnchor
{
    public const string CompiledKind = "compliance_pack_compiled";
    public const string SignatureKind = "compliance_pack_signature";
    public const string SchemeMarker = "pack_sig_scheme=v1";

    /// <summary>The position payload a pack signature commits to:
    /// domain separator, pack id, the pack's content hash, and the
    /// Seq + own Hash of the ONE compliance_pack_compiled record
    /// publishing that hash. The record hash commits to the
    /// record's full content, its predecessor and its position in
    /// the chain's hash linkage, so an appended forgery — which
    /// necessarily sits at a different Seq with a different Hash —
    /// cannot be re-targeted by a replayed signature.</summary>
    public static byte[] BuildPackPayload(string packId, string contentHash, long recordSeq, string recordHash) =>
        Encoding.UTF8.GetBytes(
            $"deskguest-pack-position-v1|pack={packId}|content_hash={contentHash.ToLowerInvariant()}|seq={recordSeq}|record_hash={recordHash.ToLowerInvariant()}|");
}
