using Acp.Shared.Input;

namespace Acp.Tests;

/// <summary>
/// FR-140 — type_text intermittently lost a character on the
/// way into real targets while reporting success (Tested-AI
/// battery run 6, 2026-11-25: the audit-verified line "DeskGuest
/// battery — ChatGPT drive test — TANGO-4417" saved as "DeskGuest
/// battery — ChatGPT rive test — TANGO-4417"; a path submitted
/// as "C:\Users\…" arrived in the Save As field as "C:\Uses\…";
/// every event SendInput-accepted, success reported both times —
/// ≈1 character per 50 under the battery's conditions).
///
/// FR-139's honest count ends at the OS input queue; delivery
/// into the target is a further step the count cannot see. The
/// fix, in three parts: each character is sent as key-down, a
/// short hold, key-up (an instant down/up batch can be
/// coalesced by the target's text stack); the sender runs
/// closed-loop against the target's document length, never
/// more than a chunk ahead of the target's own processing; and
/// where the target exposes its text (UIA TextPattern), the
/// delivery is verified against the prediction — with one
/// repair pass over exactly the span the call owns when the
/// read-back falls short.
///
/// The prediction (TypingVerification, Acp.Shared) is pure and
/// pinned directly here. The UIA capture and the sends are
/// Windows-bound, so the engine's shape is pinned by source, in
/// the W73 pattern. The byte-exact landing at battery scale is
/// proven live on the laptop (BUILD-LOG, FR-140 entry) — no
/// Linux pin can stand in for it.
/// </summary>
public class Fr140FixTests
{
    private static string SrcFile(params string[] parts)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            foreach (var root in new[] { "src", Path.Combine("windows-agent", "src") })
            {
                var c = Path.Combine(new[] { dir.FullName, root }.Concat(parts).ToArray());
                if (File.Exists(c)) return File.ReadAllText(c);
            }
            dir = dir.Parent;
        }
        throw new DirectoryNotFoundException(string.Join("/", parts) + " not found above " + AppContext.BaseDirectory);
    }

    private static string Engine() => SrcFile("Acp.SessionAgent", "DesktopEngine.cs");

    private static string MethodBody(string src, string signatureStart, string nextSignatureStart)
    {
        var start = src.IndexOf(signatureStart, StringComparison.Ordinal);
        Assert.True(start >= 0, signatureStart + " not found");
        var rest = src.Substring(start);
        var end = rest.IndexOf(nextSignatureStart, StringComparison.Ordinal);
        return end > 0 ? rest.Substring(0, end) : rest;
    }

    // ---- the prediction ----

    [Fact]
    public void ExpectedAfter_AppendAtCaret()
    {
        Assert.Equal("Hello world",
            TypingVerification.ExpectedAfter("Hello ", 6, 0, "world"));
    }

    [Fact]
    public void ExpectedAfter_ReplaceSelection_TheSaveAsCase()
    {
        // The Save As filename field: the existing name is fully
        // selected and the typed path replaces it wholesale.
        Assert.Equal(@"C:\Users\DeskGuest\dg-battery-chatgpt.txt",
            TypingVerification.ExpectedAfter("Untitled.txt", 0, 12, @"C:\Users\DeskGuest\dg-battery-chatgpt.txt"));
    }

    [Fact]
    public void ExpectedAfter_MidDocumentInsert()
    {
        Assert.Equal("abXcd", TypingVerification.ExpectedAfter("abcd", 2, 0, "X"));
    }

    [Fact]
    public void ExpectedAfter_TypedNewlineBecomesTheDocumentsOwnBreak()
    {
        // A CRLF document: the typed LF is an Enter key and
        // lands as CRLF, so the prediction carries CRLF too.
        Assert.Equal("AB\r\nCX\r\nYD",
            TypingVerification.ExpectedAfter("AB\r\nCD", 5, 0, "X\nY"));
        // An LF document keeps LF.
        Assert.Equal("AB\nCX\nYD",
            TypingVerification.ExpectedAfter("AB\nCD", 4, 0, "X\nY"));
    }

    [Fact]
    public void DocumentBreak_Inference()
    {
        Assert.Equal("\r\n", TypingVerification.DocumentBreak("a\r\nb"));
        Assert.Equal("\r", TypingVerification.DocumentBreak("a\rb"));
        Assert.Equal("\n", TypingVerification.DocumentBreak("a\nb"));
        Assert.Equal("\r\n", TypingVerification.DocumentBreak("")); // Windows default
    }

    [Fact]
    public void ConvertedLength_CountsBreaksOncePerLanding()
    {
        // "A\nB" in a CRLF document: A=1, break=2, B=1.
        Assert.Equal(4, TypingVerification.ConvertedLength("A\nB", 3, "\r\n"));
        Assert.Equal(3, TypingVerification.ConvertedLength("A\nB", 2, "\r\n"));
        // A source CRLF pair is two source characters landing
        // as ONE break.
        Assert.Equal(3, TypingVerification.ConvertedLength("A\r\nB", 3, "\r\n"));
        Assert.Equal(4, TypingVerification.ConvertedLength("A\r\nB", 4, "\r\n"));
        // In an LF document a break stays one character.
        Assert.Equal(3, TypingVerification.ConvertedLength("A\nB", 3, "\n"));
    }

    [Fact]
    public void ExpectedLengthAt_TracksTheClosedLoopTarget()
    {
        // Measured in the read-back's normalised coordinates
        // (breaks count once there): before "Hello " (6),
        // nothing selected, "A\nB": after 2 confirmed source
        // characters the document must hold 6 + 2.
        Assert.Equal(8, TypingVerification.ExpectedLengthAt("Hello ", 0, "A\nB", 2));
        // A replaced selection shrinks the base first.
        Assert.Equal(2, TypingVerification.ExpectedLengthAt("Untitled", 8, "ab", 2));
    }

    [Fact]
    public void MatchesExpected_IsExactOnContent()
    {
        Assert.True(TypingVerification.MatchesExpected("abc", "abc"));
        Assert.False(TypingVerification.MatchesExpected("abc", "abd"));
        Assert.False(TypingVerification.MatchesExpected("abc", "ab"));
    }

    [Fact]
    public void MatchesExpected_BreaksCompareByPresenceNotRepresentation()
    {
        // The proof-round measurement: Notepad's text pattern
        // reads breaks back as one character each, whatever
        // form the prediction used. Every representation of
        // the same content matches; any content difference
        // still fails.
        Assert.True(TypingVerification.MatchesExpected("A\r\nB", "A\nB"));
        Assert.True(TypingVerification.MatchesExpected("A\rB", "A\nB"));
        Assert.True(TypingVerification.MatchesExpected("A\nB", "A\r\nB"));
        Assert.False(TypingVerification.MatchesExpected("A\r\nB", "A\nC"));
        Assert.False(TypingVerification.MatchesExpected("A\r\nB", "AB"));
        // Normalised converted lengths, for the closed loop.
        Assert.Equal(3, TypingVerification.ConvertedLengthNormalized("A\nB", 3));
        Assert.Equal(3, TypingVerification.ConvertedLengthNormalized("A\r\nB", 4));
        Assert.Equal(2, TypingVerification.ConvertedLengthNormalized("A\r\nB", 3));
    }

    // ---- the repair question ----

    [Fact]
    public void OwnedRegion_WholeDocumentWhenNothingElseWasThere()
    {
        // The battery's leg-6 shape: an empty document, the
        // typed line landed with a hole — the whole read-back is
        // the call's own span and may be rewritten.
        Assert.True(TypingVerification.TryOwnedRegion("", 0, 0,
            "DeskGuest battery — ChatGPT rive test — TANGO-4417",
            out var start, out var length));
        Assert.Equal(0, start);
        Assert.Equal(50, length);
    }

    [Fact]
    public void OwnedRegion_SpanBetweenIntactPrefixAndSuffix()
    {
        Assert.True(TypingVerification.TryOwnedRegion("Hello ", 6, 0, "Hello wold",
            out var start, out var length));
        Assert.Equal(6, start);
        Assert.Equal(4, length); // "wold" — the owned span, hole and all
    }

    [Fact]
    public void OwnedRegion_RefusesWhenUntouchedTextMoved()
    {
        // Prefix damaged: something outside the call's span
        // changed — the call must not rewrite anything.
        Assert.False(TypingVerification.TryOwnedRegion("Hello ", 6, 0, "Xello world", out _, out _));
        // Suffix damaged, same rule.
        Assert.False(TypingVerification.TryOwnedRegion("abEND", 2, 0, "abXEN", out _, out _));
    }

    // ---- the engine's shape (source pins) ----

    [Fact]
    public void Engine_VerifiesDelivery_AndRepairsOnlyItsOwnSpan()
    {
        var body = MethodBody(Engine(), "private async Task<(bool, string)> TypeTextAsync", "/// <summary>FR-139: one planned typing event");
        Assert.Contains("TryCaptureTargetText()", body);
        Assert.Contains("TypingVerification.ExpectedAfter(", body);
        Assert.Contains("TypingVerification.MatchesExpected(", body);
        Assert.Contains("TypingVerification.TryOwnedRegion(", body);
        Assert.Contains("delivery confirmed in the target", body);
        // Decisions are made on SETTLED reads only (two
        // consecutive agreeing read-backs) — the initial verify
        // and the post-repair verify alike; and the repair
        // re-validates its region against its own fresh read
        // before deleting anything.
        var settledReads = body.Split(new[] { "ReadSettledTargetTextAsync(snapshot.Element, ct)" }, StringSplitOptions.None).Length - 1;
        Assert.True(settledReads >= 2, $"expected the settled read at the verify and the post-repair verify, found {settledReads}");
        // The repair is bounded-retry: the intermittent loss
        // can strike a retype too, so the loop re-validates
        // and retries while the difference stays owned.
        Assert.Contains("attempt <= 3", body);
        var repair = MethodBody(Engine(), "private async Task<bool> TryRepairOwnedRegionAsync", "private const ushort VkDelete");
        Assert.Contains("freshStart != regionStart", repair);
        // A mismatch is a failure with the read-back counts —
        // never a success claim.
        Assert.Contains("typing did not land intact in the target", body);
    }

    [Fact]
    public void Engine_SplitsKeyDownAndUp_AndRunsClosedLoop()
    {
        var loop = MethodBody(Engine(), "private async Task<int> SendTypingPlanAsync", "/// <summary>FR-140: the closed loop's wait");
        // Down and up are separate sends, the key held to the
        // end of its deadline-paced slot.
        Assert.Contains("Stopwatch.StartNew()", loop);
        Assert.Contains("(u + 1) * paceMs", loop);
        // The closed loop waits on the target's own length.
        Assert.Contains("WaitForTargetLengthAsync(snapshot, text, confirmedChars, ct)", loop);
        Assert.Contains("TypingChunkChars", loop);
        // After a break unit, a settle beat precedes the next
        // line's first character (the gauntlet's line-start
        // losses).
        Assert.Contains("TextTypingPlan.VkReturn", loop);
        Assert.Contains("Task.Delay(BreakSettleMs, ct)", loop);
    }
}
