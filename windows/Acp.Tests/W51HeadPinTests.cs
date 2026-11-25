using Acp.Shared.Update;

namespace Acp.Tests;

/// <summary>Wave 51 Lane B — same-count HEAD IMMUTABILITY in the
/// guarded marker Write primitive: the DeepSeek round-12 Item 2
/// fix. Round 12's counter-example against the W49 guard: after
/// Write(dir, null, 5, Head(5)) lands, Write(dir, null, 5, null)
/// SUCCEEDED and erased chain_head; Write(dir, null, 5, Head(9))
/// then also succeeded, because the W49 same-count refusal was
/// gated on BOTH heads being non-null — the erasure disarmed it.
/// The vouched position at a given count could thus be silently
/// rewritten through the primitive (no production caller writes
/// a counted marker with a null head today; the hole was at the
/// primitive's guarantee, which is what round 12 judged).
///
/// THE W51 RULE: at the SAME count as the current marker, the
/// head is immutable in every direction — a proposed write whose
/// head differs from the current head refuses by name, where
/// "differs" includes value→null (erasure), null→value
/// (un-vouching a headless position into a headed one) and
/// value→different-value. The only same-count writes that
/// proceed are (a) byte-identical (count, head) rewrites
/// (idempotent) and (b) witness-only writes, which carry NO
/// position fields at all (chainEntries is null): the W49
/// primitive already PRESERVES the standing count/head for
/// those rather than dropping them, so a witness-only write is
/// not a same-count head change and stays allowed. At a GREATER
/// count writes proceed as before (a new position — including,
/// pinned deliberately, a greater-count write with a null head:
/// no head was ever vouched at that count, so nothing is
/// rewritten; the rule is NOT widened to refuse it). Backward
/// counts keep refusing as before (W49 pins).</summary>
public class W51HeadPinTests
{
    private static PointerAnchorMarker.Marker Marker(string dir) =>
        Assert.Single(PointerAnchorMarker.ReadAll(dir));

    private static string Head(int seed) => new string((char)('a' + seed % 26), 64);

    // ---------- DeepSeek's exact round-12 sequence ----------

    [Fact]
    public void DeepSeekSequence_SameCountNullHead_Refused_MarkerByteUnchanged_ThenDifferentHeadStillRefused()
    {
        var dir = TestUtil.TempDir();
        // Step 1 of the sequence: (5, Head(5)) lands.
        PointerAnchorMarker.Write(dir, null, 5, Head(5));
        var bytesBefore = File.ReadAllBytes(PointerAnchorMarker.MarkerPath(dir));

        // Step 2: the same-count NULL-head write — pre-W51 this
        // succeeded and DROPPED chain_head from the marker.
        var ex = Assert.Throws<PointerAnchorMarker.MarkerWriteRefusedException>(
            () => PointerAnchorMarker.Write(dir, null, 5, null));
        Assert.Contains("monotonicity guard", ex.Message);
        Assert.Contains("same-count rewrite", ex.Message);
        // Refused means byte-unchanged: the head was NOT erased.
        Assert.Equal(bytesBefore, File.ReadAllBytes(PointerAnchorMarker.MarkerPath(dir)));
        Assert.Equal(Head(5), Marker(dir).ChainHead);
        Assert.Equal(5, Marker(dir).ChainEntries);

        // Step 3: because the erasure never landed, the later
        // same-count different-head write still refuses (pre-W51
        // it succeeded once the standing head was null).
        var ex2 = Assert.Throws<PointerAnchorMarker.MarkerWriteRefusedException>(
            () => PointerAnchorMarker.Write(dir, null, 5, Head(9)));
        Assert.Contains("same-count rewrite", ex2.Message);
        Assert.Equal(bytesBefore, File.ReadAllBytes(PointerAnchorMarker.MarkerPath(dir)));
        Assert.Equal(Head(5), Marker(dir).ChainHead);
    }

    [Fact]
    public void SameCountDifferentHead_Refused_MarkerByteUnchanged()
    {
        // The value→different-value direction, pinned on its own
        // (also covered inside the W49 suite; restated here so
        // the W51 mutation battery names it in this file).
        var dir = TestUtil.TempDir();
        PointerAnchorMarker.Write(dir, null, 5, Head(5));
        var bytesBefore = File.ReadAllBytes(PointerAnchorMarker.MarkerPath(dir));

        var ex = Assert.Throws<PointerAnchorMarker.MarkerWriteRefusedException>(
            () => PointerAnchorMarker.Write(dir, null, 5, Head(9)));
        Assert.Contains("monotonicity guard", ex.Message);
        Assert.Contains("same-count rewrite", ex.Message);
        Assert.Equal(bytesBefore, File.ReadAllBytes(PointerAnchorMarker.MarkerPath(dir)));
    }

    [Fact]
    public void HeadlessMarkerAtCount_NullToValueAtSameCount_Refused_MarkerByteUnchanged()
    {
        var dir = TestUtil.TempDir();
        // Construct the headless-at-a-count state FAITHFULLY: the
        // FIRST write to an empty directory proposes count 5 with
        // no head. No marker stands yet, so there is no standing
        // position to rewrite and the write lands — the marker
        // file genuinely carries chain_entries=5 and NO
        // chain_head line (asserted from the raw bytes, not just
        // the parsed view).
        PointerAnchorMarker.Write(dir, null, 5, null);
        var raw = File.ReadAllText(PointerAnchorMarker.MarkerPath(dir));
        Assert.Contains("chain_entries=5", raw);
        Assert.DoesNotContain("chain_head", raw);
        Assert.Null(Marker(dir).ChainHead);
        var bytesBefore = File.ReadAllBytes(PointerAnchorMarker.MarkerPath(dir));

        // Now a headed write at the SAME count would un-vouch
        // the headless position into a headed one — a same-count
        // head change (null→value) and refused by name, W51.
        var ex = Assert.Throws<PointerAnchorMarker.MarkerWriteRefusedException>(
            () => PointerAnchorMarker.Write(dir, null, 5, Head(5)));
        Assert.Contains("monotonicity guard", ex.Message);
        Assert.Contains("same-count rewrite", ex.Message);
        Assert.Equal(bytesBefore, File.ReadAllBytes(PointerAnchorMarker.MarkerPath(dir)));
        Assert.Null(Marker(dir).ChainHead);
    }

    // ---------- the allowed same-count shapes ----------

    [Fact]
    public void SameCountIdenticalHead_IdempotentRewrite_Allowed()
    {
        var dir = TestUtil.TempDir();
        var sha = new string('f', 64);
        PointerAnchorMarker.Write(dir, sha, 5, Head(5));

        // Byte-identical (count, head): an idempotent re-write.
        PointerAnchorMarker.Write(dir, sha, 5, Head(5));
        var marker = Marker(dir);
        Assert.Equal(5, marker.ChainEntries);
        Assert.Equal(Head(5), marker.ChainHead);

        // Identical (count, head) with a refreshed pointer hash
        // is still the same position: allowed, hash updates.
        var sha2 = new string('e', 64);
        PointerAnchorMarker.Write(dir, sha2, 5, Head(5));
        marker = Marker(dir);
        Assert.Equal(sha2, marker.PointerSha256);
        Assert.Equal(Head(5), marker.ChainHead);
    }

    [Fact]
    public void HeadlessMarkerAtCount_IdenticalNullHeadRewrite_Allowed()
    {
        // (5, null) rewritten as (5, null) is byte-identical in
        // its position fields: idempotent, allowed — the rule
        // refuses a DIFFERENT head, and null vs null is not
        // different.
        var dir = TestUtil.TempDir();
        PointerAnchorMarker.Write(dir, null, 5, null);
        PointerAnchorMarker.Write(dir, null, 5, null);
        var marker = Marker(dir);
        Assert.Equal(5, marker.ChainEntries);
        Assert.Null(marker.ChainHead);
    }

    [Fact]
    public void WitnessOnlyWrite_PreservesCountAndHead_StillAllowed()
    {
        // The witness-only write (no count proposed — the
        // UpdateManager / updates-root shape) carries no position
        // fields at all. W49 made it PRESERVE the standing
        // count/head rather than drop them, so it is not a
        // same-count head change: it stays allowed under W51 and
        // the vouched position survives it exactly.
        var dir = TestUtil.TempDir();
        var sha = new string('f', 64);
        PointerAnchorMarker.Write(dir, sha, 5, Head(5));

        var sha2 = new string('e', 64);
        PointerAnchorMarker.Write(dir, sha2, null, null);
        var marker = Marker(dir);
        Assert.Equal(sha2, marker.PointerSha256);
        Assert.Equal(5, marker.ChainEntries);
        Assert.Equal(Head(5), marker.ChainHead);
    }

    // ---------- the greater-count path, unchanged ----------

    [Fact]
    public void GreaterCount_HeadedWrite_Proceeds_AsBefore()
    {
        var dir = TestUtil.TempDir();
        PointerAnchorMarker.Write(dir, null, 5, Head(5));
        PointerAnchorMarker.Write(dir, null, 6, Head(6));
        var marker = Marker(dir);
        Assert.Equal(6, marker.ChainEntries);
        Assert.Equal(Head(6), marker.ChainHead);
    }

    [Fact]
    public void GreaterCount_NullHeadWrite_Proceeds_PinnedUnchanged_ThenImmutableAtItsCount()
    {
        // PINNED, NOT WIDENED: a greater-count write with a null
        // head proceeds exactly as it did pre-W51. Judgement,
        // stated: it creates a NEW position at a count where no
        // head was ever vouched, so it rewrites nothing the
        // guarantee protects; production writers always supply
        // the head at a greater count, so refusing here would
        // change behaviour no round has faulted. What W51 does
        // guarantee is that the headless position so created is
        // then immutable at ITS count (see the null→value pin).
        var dir = TestUtil.TempDir();
        PointerAnchorMarker.Write(dir, null, 5, Head(5));
        PointerAnchorMarker.Write(dir, null, 6, null);
        var marker = Marker(dir);
        Assert.Equal(6, marker.ChainEntries);
        Assert.Null(marker.ChainHead);

        // And at count 6 the head is now pinned as headless:
        // a headed write at 6 refuses.
        Assert.Throws<PointerAnchorMarker.MarkerWriteRefusedException>(
            () => PointerAnchorMarker.Write(dir, null, 6, Head(6)));
        Assert.Null(Marker(dir).ChainHead);
    }
}
