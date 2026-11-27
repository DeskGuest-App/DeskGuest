using DeskGuest.Shared.Input;

namespace DeskGuest.Tests;

/// <summary>
/// FR-139 — type_text corrupted mixed strings into Win32 edit
/// controls while reporting the submitted count as typed
/// (Tested-AI battery run 5, 2026-11-25: the line "DeskGuest
/// battery — ChatGPT drive test — TANGO-4417" landed in Notepad
/// as "DeskGuest " + 41 copies of "7"; a 691-character text
/// landed as 492 characters with every newline dropped, reported
/// as "typed 691 characters"; "ALPHA\nBRAVO" landed as
/// "ALPHABRAVO", reported as 11 typed).
///
/// The plan and the result wording are pure (DeskGuest.Shared) and are
/// pinned directly here. The raw send is Windows-bound, so the
/// engine's use of the plan is pinned by source, in the W73
/// pattern: the plan is built up front, sends go out one
/// character at a time with the pace between them through the
/// one noted funnel, and the funnel's accepted count is checked
/// before any success is reported.
/// The byte-exact landing itself is proven live on the laptop
/// (BUILD-LOG, FR-139 entry) — no Linux pin can stand in for it.
/// </summary>
public class Fr139FixTests
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

    private static string Engine() => SrcFile("DeskGuest.SessionAgent", "DesktopEngine.cs");

    private static string MethodBody(string src, string signatureStart, string nextSignatureStart)
    {
        var start = src.IndexOf(signatureStart, StringComparison.Ordinal);
        Assert.True(start >= 0, signatureStart + " not found");
        var rest = src.Substring(start);
        var end = rest.IndexOf(nextSignatureStart, StringComparison.Ordinal);
        return end > 0 ? rest.Substring(0, end) : rest;
    }

    private const string Leg6Line = "DeskGuest battery — ChatGPT drive test — TANGO-4417";

    [Fact]
    public void Plan_ForTheBatteryLine_IsOneUnicodePairPerCharacter()
    {
        var plan = TextTypingPlan.Build(Leg6Line);
        Assert.Equal(51, plan.TotalChars);
        Assert.Equal(102, plan.Events.Count);
        Assert.All(plan.Events, e => Assert.False(e.IsVirtualKey));
        // Down/up strictly alternate, same character on both halves.
        for (var i = 0; i < plan.Events.Count; i += 2)
        {
            Assert.False(plan.Events[i].KeyUp);
            Assert.True(plan.Events[i + 1].KeyUp);
            Assert.Equal(plan.Events[i].Char, plan.Events[i + 1].Char);
            Assert.Equal(Leg6Line[i / 2], plan.Events[i].Char);
        }
        // The em dashes ride as their own code points — the plan
        // never substitutes, drops, or re-encodes a character.
        Assert.Equal(2, plan.Events.Count(e => !e.KeyUp && e.Char == '—'));
        Assert.Equal(51, plan.ConfirmedChars(102));
    }

    [Fact]
    public void Plan_NewlineIsTheEnterKey_NeverARawLineFeed()
    {
        var plan = TextTypingPlan.Build("ALPHA\nBRAVO");
        Assert.Equal(11, plan.TotalChars);
        Assert.Equal(22, plan.Events.Count);
        // No event in ANY plan carries a raw '\n' or '\r' as a
        // Unicode character — that was the dropped-newline defect.
        Assert.DoesNotContain(plan.Events, e => !e.IsVirtualKey && (e.Char == '\n' || e.Char == '\r'));
        // The newline is a VK_RETURN down/up pair at the seam.
        var seam = plan.Events[10];
        Assert.True(seam.IsVirtualKey);
        Assert.Equal(TextTypingPlan.VkReturn, seam.VirtualKey);
        Assert.False(seam.KeyUp);
        Assert.True(plan.Events[11].IsVirtualKey && plan.Events[11].KeyUp);
        Assert.Equal(11, plan.ConfirmedChars(22));
    }

    [Fact]
    public void Plan_CrLfIsOneEnter_ThatCompletesBothCharacters()
    {
        var plan = TextTypingPlan.Build("A\r\nB");
        Assert.Equal(4, plan.TotalChars);
        Assert.Equal(6, plan.Events.Count); // A pair + ONE Return pair + B pair
        Assert.Equal(1, plan.Events.Count(e => e.IsVirtualKey && !e.KeyUp));
        Assert.Equal(4, plan.ConfirmedChars(6));
        // A lone CR is one Enter completing itself.
        var lone = TextTypingPlan.Build("A\rB");
        Assert.Equal(6, lone.Events.Count);
        Assert.Equal(3, lone.ConfirmedChars(6));
    }

    [Fact]
    public void Plan_TabIsTheTabKey()
    {
        var plan = TextTypingPlan.Build("A\tB");
        Assert.Contains(plan.Events, e => e.IsVirtualKey && e.VirtualKey == TextTypingPlan.VkTab && !e.KeyUp);
        Assert.DoesNotContain(plan.Events, e => !e.IsVirtualKey && e.Char == '\t');
    }

    [Fact]
    public void Plan_ConfirmedChars_TracksPartialAcceptanceExactly()
    {
        var plan = TextTypingPlan.Build(Leg6Line);
        Assert.Equal(0, plan.ConfirmedChars(0));
        // The battery's faithful segment: the first 10 characters
        // ("DeskGuest ") are 20 events.
        Assert.Equal(10, plan.ConfirmedChars(20));
        // A mid-pair stop confirms only the completed characters.
        Assert.Equal(10, plan.ConfirmedChars(21));
        Assert.Equal(51, plan.ConfirmedChars(10_000)); // clamped, never over-claims
    }

    [Fact]
    public void Plan_Units_OnePerCharacter_EachAWholePair()
    {
        // The flood lesson (live-proven 2026-11-25): the engine
        // sends ONE unit per SendInput call with a pace between
        // units, so the plan must group strictly per character.
        var units = TextTypingPlan.Build(Leg6Line).Units();
        Assert.Equal(51, units.Count);
        Assert.All(units, u =>
        {
            Assert.Equal(2, u.Events.Count);       // one down/up pair
            Assert.False(u.Events[0].KeyUp);
            Assert.True(u.Events[1].KeyUp);
            Assert.Equal(1, u.CharsCompleted);
        });
        // The CRLF Enter is ONE unit that completes two characters.
        var crlf = TextTypingPlan.Build("A\r\nB").Units();
        Assert.Equal(3, crlf.Count);
        Assert.Equal(2, crlf[1].CharsCompleted);
        Assert.All(crlf[1].Events, e => Assert.True(e.IsVirtualKey));
        // A long string still groups per character, pairs whole.
        var big = TextTypingPlan.Build(new string('x', 1200) + "\n" + new string('y', 300)).Units();
        Assert.Equal(1501, big.Count);
        Assert.Equal(1501, big.Sum(u => u.CharsCompleted));
    }

    [Fact]
    public void Outcome_FullAcceptance_IsTheOnlySuccess()
    {
        var (ok, text) = TextTypingPlan.Outcome(51, 51);
        Assert.True(ok);
        Assert.Equal("typed 51 characters", text);
        var (ok0, text0) = TextTypingPlan.Outcome(0, 0);
        Assert.True(ok0);
        Assert.Equal("typed 0 characters", text0);
    }

    [Fact]
    public void Outcome_Shortfall_IsAFailure_WithTheTrueCounts()
    {
        var (ok, text) = TextTypingPlan.Outcome(691, 492);
        Assert.False(ok);
        Assert.Contains("492", text);
        Assert.Contains("691", text);
        // The failure never wears the success wording.
        Assert.DoesNotContain("typed 691 characters", text);
    }

    [Fact]
    public void Engine_BuildsThePlan_PacesPerCharacter_AndChecksEveryAcceptedCount()
    {
        var engine = Engine();
        var body = MethodBody(engine, "private async Task<(bool, string)> TypeTextAsync", "/// <summary>FR-139: one planned typing event");
        Assert.Contains("TextTypingPlan.Build(text)", body);
        Assert.Contains("TextTypingPlan.Outcome(", body);
        // FR-140: the send loop moved into SendTypingPlanAsync
        // (the verify/repair paths share it); the FR-139 shape
        // is pinned there now — the plan's units, the pace
        // between characters (a flood is the proven corruption,
        // so the delay's presence is pinned, not left to a
        // comment's good intentions), and the funnel's accepted
        // count checked per send.
        var loop = MethodBody(engine, "private async Task<int> SendTypingPlanAsync", "/// <summary>FR-140: the closed loop's wait");
        Assert.Contains("plan.Units()", loop);
        // FR-140 (proof-round amendment): the pace is a
        // deadline schedule, not a per-character delay — two
        // Task.Delays per character each round up to the
        // Windows timer tick and tripled the rate (measured:
        // 2,156 characters in 61 s). The pin follows: a
        // stopwatch and the slot deadline are what pace the
        // sends now.
        Assert.Contains("Stopwatch.StartNew()", loop);
        Assert.Contains("(u + 1) * paceMs", loop);
        Assert.Contains("var inserted = SendInputNoted(inputs);", loop);
        // The pre-fix shape is gone: no per-character loop, and
        // no unconditional success claim built from the raw count.
        Assert.DoesNotContain("foreach (var ch in text)", body);
        Assert.DoesNotContain("typed {text.Length} characters", body);
    }

    [Fact]
    public void Engine_SendWrapper_HandsBackTheAcceptedCount()
    {
        var engine = Engine();
        Assert.Contains("private static uint SendInputNoted", engine);
        var wrapper = MethodBody(engine, "private static uint SendInputNoted", "private static string CapturePngBase64");
        Assert.Contains("var inserted = NativeMethods.SendInput(", wrapper);
        Assert.Contains("return inserted;", wrapper);
    }
}
