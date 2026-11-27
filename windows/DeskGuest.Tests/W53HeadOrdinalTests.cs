using DeskGuest.Shared.Enterprise;
using DeskGuest.Shared.Update;

namespace DeskGuest.Tests;

/// <summary>Wave 53 Lane B — round-13 Item 2 fixes in the guarded
/// marker Write primitive (DeepSeek round-13 verdict,
/// log-laneW52-dsconfirm12.md Item 2: FIX-INADEQUATE on two
/// points against the W51 fix).
///
/// POINT 1 — ORDINAL HEAD COMPARISON: the W51 same-count guard
/// compared heads with OrdinalIgnoreCase, so a case-only change
/// ('f'x64 -> 'F'x64 at count 5) was judged "same" and LANDED,
/// rewriting the marker bytes under a byte-identical-only claim.
/// The head is not constrained to lowercase hex (ReadOne accepts
/// any non-empty value) and the marker is covered by no hash or
/// signature of its own, so case is content, not encoding. The
/// guard now compares ORDINALLY. Sibling audit (all
/// OrdinalIgnoreCase sites in DeskGuest.Shared/Update): the two other
/// comparisons against the uncovered marker — FreshnessRefusal's
/// prefix binding and AdvanceInstallRootMarker's landing check —
/// are ordinal now too (FreshnessRefusal pinned here; the landing
/// check has no injection point between write and re-read, so it
/// is covered by the advance suites). The remaining sites are
/// judged SAFE with reasons and two are pinned as deliberately
/// case-insensitive below: Check's pointer-hash comparison (the
/// recorded side is integrity-covered by the audit chain's own
/// hash verification before it is reached, and the comparison is
/// digest equality over a canonical lowercase computed hash),
/// SlotIntegrity's content-hash comparisons (digest equality;
/// the expected value is named by the pointer the caller already
/// trusts, so case grants an attacker nothing), PointerSigning's
/// archived-pin fingerprint (a LOOKUP key: the returned key bytes
/// are re-verified by recomputing the fingerprint from them),
/// and the path comparisons / path dedup set (Windows paths,
/// lookup/selection only, never a sameness guarantee over stored
/// bytes).
///
/// POINT 2 — WITNESS PRESERVATION: the W49/W51 preservation
/// branch required a non-null standing ChainEntries, so a
/// HEAD-ONLY marker lost its head to a witness-only write.
/// Preservation now preserves EACH field independently from the
/// standing marker: a witness write leaves count AND head exactly
/// as they stand, for all four standing combinations (count-only,
/// head-only, both, neither), byte-compared here.</summary>
public class W53HeadOrdinalTests
{
    private static PointerAnchorMarker.Marker Marker(string dir) =>
        Assert.Single(PointerAnchorMarker.ReadAll(dir));

    private static string Head(int seed) => new string((char)('a' + seed % 26), 64);

    // ---------- Point 1: DeepSeek's exact round-13 sequence ----------

    [Fact]
    public void DeepSeekSequence_CaseOnlyHeadChange_Refused_MarkerByteUnchanged()
    {
        var dir = TestUtil.TempDir();
        // (1) 'f'x64 at count 5 lands.
        PointerAnchorMarker.Write(dir, null, 5, new string('f', 64));
        var bytesBefore = File.ReadAllBytes(PointerAnchorMarker.MarkerPath(dir));

        // (2) 'F'x64 at the same count differs ONLY in case.
        // Pre-W53 the OrdinalIgnoreCase guard judged it "same"
        // and the write rewrote chain_head. Now: refused by name.
        var ex = Assert.Throws<PointerAnchorMarker.MarkerWriteRefusedException>(
            () => PointerAnchorMarker.Write(dir, null, 5, new string('F', 64)));
        Assert.Contains("monotonicity guard", ex.Message);
        Assert.Contains("same-count rewrite", ex.Message);
        Assert.Equal(bytesBefore, File.ReadAllBytes(PointerAnchorMarker.MarkerPath(dir)));
        Assert.Equal(new string('f', 64), Marker(dir).ChainHead);
        Assert.Equal(5, Marker(dir).ChainEntries);

        // The truly byte-identical rewrite still proceeds.
        PointerAnchorMarker.Write(dir, null, 5, new string('f', 64));
        Assert.Equal(bytesBefore, File.ReadAllBytes(PointerAnchorMarker.MarkerPath(dir)));
    }

    [Fact]
    public void CaseOnlyHeadChange_UpperToLower_Refused_MarkerByteUnchanged()
    {
        // The reverse direction: case is content either way.
        var dir = TestUtil.TempDir();
        PointerAnchorMarker.Write(dir, null, 5, new string('F', 64));
        var bytesBefore = File.ReadAllBytes(PointerAnchorMarker.MarkerPath(dir));

        Assert.Throws<PointerAnchorMarker.MarkerWriteRefusedException>(
            () => PointerAnchorMarker.Write(dir, null, 5, new string('f', 64)));
        Assert.Equal(bytesBefore, File.ReadAllBytes(PointerAnchorMarker.MarkerPath(dir)));
        Assert.Equal(new string('F', 64), Marker(dir).ChainHead);
    }

    [Fact]
    public void SingleCharacterCaseFlip_Refused_MarkerByteUnchanged()
    {
        // One character's case differs; the rest is identical.
        var dir = TestUtil.TempDir();
        var head = "a" + new string('b', 63);
        PointerAnchorMarker.Write(dir, null, 5, head);
        var bytesBefore = File.ReadAllBytes(PointerAnchorMarker.MarkerPath(dir));

        Assert.Throws<PointerAnchorMarker.MarkerWriteRefusedException>(
            () => PointerAnchorMarker.Write(dir, null, 5, "A" + new string('b', 63)));
        Assert.Equal(bytesBefore, File.ReadAllBytes(PointerAnchorMarker.MarkerPath(dir)));
        Assert.Equal(head, Marker(dir).ChainHead);
    }

    // ---------- Point 2: witness preservation, all four combinations ----------

    private void WitnessPreserves(long? standingCount, string? standingHead)
    {
        var dir = TestUtil.TempDir();
        var sha = new string('f', 64);
        PointerAnchorMarker.Write(dir, sha, standingCount, standingHead);
        var standing = Marker(dir);
        Assert.Equal(standingCount, standing.ChainEntries);
        Assert.Equal(standingHead, standing.ChainHead);

        // The witness-only write (the UpdateManager / updates-root
        // shape): proposes no position, updates only the hash.
        var sha2 = new string('e', 64);
        PointerAnchorMarker.Write(dir, sha2, null, null);

        var marker = Marker(dir);
        Assert.Equal(sha2, marker.PointerSha256);
        Assert.Equal(standingCount, marker.ChainEntries);
        Assert.Equal(standingHead, marker.ChainHead);

        // BYTE-COMPARED: the post-witness marker is byte-identical
        // to a marker written directly in the final state.
        var reference = TestUtil.TempDir();
        PointerAnchorMarker.Write(reference, sha2, standingCount, standingHead);
        Assert.Equal(
            File.ReadAllBytes(PointerAnchorMarker.MarkerPath(reference)),
            File.ReadAllBytes(PointerAnchorMarker.MarkerPath(dir)));
    }

    [Fact]
    public void WitnessWrite_StandingBoth_PreservesCountAndHead_ByteCompared() =>
        WitnessPreserves(5, Head(5));

    [Fact]
    public void WitnessWrite_StandingCountOnly_PreservesCount_HeadStaysNull_ByteCompared() =>
        WitnessPreserves(5, null);

    [Fact]
    public void WitnessWrite_StandingHeadOnly_PreservesHead_ByteCompared()
    {
        // DeepSeek round-13's additional gap, exactly: a head-only
        // marker (no chain_entries) lost its head to a witness
        // write pre-W53, because preservation required a count.
        var dir = TestUtil.TempDir();
        PointerAnchorMarker.Write(dir, null, null, Head(5));
        var raw = File.ReadAllText(PointerAnchorMarker.MarkerPath(dir));
        Assert.Contains("chain_head", raw);
        Assert.DoesNotContain("chain_entries", raw);

        WitnessPreserves(null, Head(5));
    }

    [Fact]
    public void WitnessWrite_StandingNeither_PreservesNeither_ByteCompared() =>
        WitnessPreserves(null, null);

    // ---------- Point 1 sibling fix: FreshnessRefusal is ordinal ----------

    [Fact]
    public void FreshnessRefusal_CaseOnlyHeadTamper_Refuses_ExactHeadBinds()
    {
        // A real chain (hashes are canonical lowercase hex) and a
        // marker whose recorded head is the UPPERCASE form of the
        // entry hash at its count. Pre-W53 the OrdinalIgnoreCase
        // prefix binding judged it the same head and bound; the
        // marker is covered by nothing, so the case tamper must
        // refuse. The exact head still binds (no over-refusal).
        var log = new ChainedAuditLog();
        for (var i = 0; i < 3; i++)
            log.Append("session_open", "SYSTEM", $"entry {i}", DateTimeOffset.UtcNow);
        var entries = log.Entries;
        var head = entries[^1].Hash;
        Assert.True(head.Any(c => c is >= 'a' and <= 'f'),
            "test requires a chain head containing a hex letter");

        var dir = TestUtil.TempDir();
        PointerAnchorMarker.Write(dir, null, entries.Count, head.ToUpperInvariant());
        var markers = PointerAnchorMarker.ReadAll(dir);
        var refusal = PointerAuditAnchor.FreshnessRefusal(markers, entries);
        Assert.NotNull(refusal);
        Assert.Contains("NOT the marker's recorded head", refusal);

        var dir2 = TestUtil.TempDir();
        PointerAnchorMarker.Write(dir2, null, entries.Count, head);
        Assert.Null(PointerAuditAnchor.FreshnessRefusal(
            PointerAnchorMarker.ReadAll(dir2), entries));
    }

    // ---------- Point 1 sibling audit: deliberately safe, pinned ----------

    [Fact]
    public void SiblingSafe_SlotIntegrity_UppercaseExpectedHash_StillVerifies_DigestEquality()
    {
        // JUDGED SAFE, pinned as intended behaviour: SlotIntegrity
        // compares a computed canonical lowercase content hash
        // against an expected hash NAMED BY the pointer the caller
        // already trusts. It is digest equality (hex case is the
        // digest's encoding, not slot bytes), and case grants an
        // attacker nothing: anyone who can set the expected value
        // could set its lowercase form. No stored bytes are
        // rewritten on the strength of this comparison.
        var root = TestUtil.TempDir();
        var slot = Path.Combine(root, "slot");
        Directory.CreateDirectory(slot);
        File.WriteAllText(Path.Combine(slot, "app.exe"), "payload");
        var hash = SlotIntegrity.ContentHash(slot);
        Assert.True(SlotIntegrity.Verify(slot, hash.ToUpperInvariant()));
        Assert.False(SlotIntegrity.Verify(slot, new string('0', 64)));
    }

    [Fact]
    public void SiblingSafe_ArchivedPin_UppercaseFingerprint_StillResolves_LookupOnly()
    {
        // JUDGED SAFE, pinned as intended behaviour: the archived
        // pin fingerprint is a LOOKUP key (the archive path itself
        // is built from its lowercase form); the returned bytes are
        // accepted only after their fingerprint is RECOMPUTED from
        // them, so a case-variant key cannot substitute a key.
        var root = TestUtil.TempDir();
        var install = Path.Combine(root, "install"); Directory.CreateDirectory(install);
        var data = Path.Combine(root, "data"); Directory.CreateDirectory(data);
        var custody = new PointerSigningCustody(install, data);
        custody.EnsureKeyForInstall();
        var pin = PointerSigningCustody.ReadPin(install);
        Assert.NotNull(pin);
        PointerSigningCustody.ArchiveCurrentPin(install);
        var fingerprint = PointerSigningCustody.FingerprintOf(pin!);

        var resolved = PointerSigningCustody.ReadArchivedPin(install, fingerprint.ToUpperInvariant());
        Assert.NotNull(resolved);
        Assert.Equal(pin!, resolved!);
        Assert.Null(PointerSigningCustody.ReadArchivedPin(install, new string('0', 64)));
    }
}
