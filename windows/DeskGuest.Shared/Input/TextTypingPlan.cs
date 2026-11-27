namespace DeskGuest.Shared.Input;

/// <summary>
/// FR-139 — one planned key event behind type_text. A character
/// event carries a Unicode code point (sent with
/// KEYEVENTF_UNICODE); a virtual-key event carries a VK code
/// (sent as a plain key press). The engine translates the plan
/// into raw input events verbatim — all decisions about WHAT a
/// string means as keystrokes live here, in pure, testable code.
/// </summary>
public readonly record struct TypingEvent(bool IsVirtualKey, char Char, ushort VirtualKey, bool KeyUp)
{
    public static TypingEvent UnicodeDown(char c) => new(false, c, 0, false);
    public static TypingEvent UnicodeUp(char c) => new(false, c, 0, true);
    public static TypingEvent VkDown(ushort vk) => new(true, '\0', vk, false);
    public static TypingEvent VkUp(ushort vk) => new(true, '\0', vk, true);
}

/// <summary>
/// FR-139 — a built typing plan: the event sequence for a string,
/// plus, for every event, how many source characters that event
/// COMPLETES (a character completes at its key-up; the line feed
/// of a CRLF pair completes at the pair's single Enter key-up).
/// That bookkeeping is what lets the engine turn the OS's
/// inserted-event count into a confirmed character count — the
/// only count its result may claim.
/// </summary>
public sealed class TypingPlan
{
    internal TypingPlan(IReadOnlyList<TypingEvent> events, IReadOnlyList<int> completions, int totalChars)
    {
        Events = events;
        Completions = completions;
        TotalChars = totalChars;
    }

    public IReadOnlyList<TypingEvent> Events { get; }
    public IReadOnlyList<int> Completions { get; }
    public int TotalChars { get; }

    /// <summary>The events grouped per source character: one unit
    /// per character, each a whole down/up pair (the CRLF pair's
    /// single Enter is one unit completing two characters). The
    /// engine sends ONE unit per SendInput call with a short pace
    /// between units — see TextTypingPlan's note on why a flood
    /// corrupts.</summary>
    public IReadOnlyList<TypingUnit> Units()
    {
        var units = new List<TypingUnit>();
        var current = new List<TypingEvent>();
        for (var i = 0; i < Events.Count; i++)
        {
            current.Add(Events[i]);
            if (Completions[i] > 0)
            {
                units.Add(new TypingUnit(current, Completions[i]));
                current = new List<TypingEvent>();
            }
        }
        if (current.Count > 0)
            units.Add(new TypingUnit(current, 0));
        return units;
    }

    /// <summary>How many source characters are confirmed typed
    /// when the OS accepted the first <paramref name="insertedEvents"/>
    /// events of this plan.</summary>
    public int ConfirmedChars(int insertedEvents)
    {
        var n = Math.Clamp(insertedEvents, 0, Events.Count);
        var sum = 0;
        for (var i = 0; i < n; i++) sum += Completions[i];
        return sum;
    }
}

/// <summary>FR-139 — one source character's worth of a typing
/// plan: a whole down/up pair (or the CRLF pair's single Enter
/// pair) plus how many source characters its completion covers.</summary>
public sealed record TypingUnit(IReadOnlyList<TypingEvent> Events, int CharsCompleted);

/// <summary>
/// FR-139 — the typing plan behind the desktop engine's
/// type_text, and the tool's result wording.
///
/// The pre-fix engine typed one unchecked SendInput call per
/// character and reported the SUBMITTED count as typed. Proven
/// against Notepad in the Tested-AI battery (run 5, 2026-11-25):
/// a 51-character line landed as a faithful start plus a run of
/// one repeated glyph; a 691-character text landed as 492
/// characters with every newline dropped — while the tool
/// reported "typed 691 characters". Four defects, one path:
/// (1) a newline sent as a raw line-feed CHARACTER is ignored by
/// edit controls — a newline is the Enter KEY; (2) SendInput's
/// return (how many events the OS input queue actually accepted)
/// was never read, so unaccepted events vanished silently;
/// (3) the report claimed the submitted count with no evidence;
/// (4) the whole string went out as one instant flood — and a
/// flood CORRUPTS inside TSF/RichEdit targets (Windows 11
/// Notepad proven live, fix lane 2026-11-25): the first word and
/// the first space land, then every remaining character is
/// stamped as the string's final character ("DeskGuest battery
/// — ChatGPT drive test — TANGO-4417" arrived as "DeskGuest " +
/// 41 copies of "7", with SendInput accepting every event). The
/// same string typed one character at a time landed byte-exact.
///
/// The fixed shape: build the whole plan here — characters as
/// Unicode pairs, '\n' and '\r' as VK_RETURN presses (a CRLF pair
/// is ONE Enter), '\t' as VK_TAB — then send it ONE CHARACTER AT
/// A TIME with a short pace between characters, verify every
/// character's accepted count, and report through
/// <see cref="Outcome"/>: success names only the characters the
/// OS confirmed; a shortfall is a failure with the true counts.
/// </summary>
public static class TextTypingPlan
{
    public const ushort VkReturn = 0x0D;
    public const ushort VkTab = 0x09;

    public static TypingPlan Build(string text)
    {
        var events = new List<TypingEvent>(text.Length * 2);
        var completions = new List<int>(text.Length * 2);

        void Pair(TypingEvent down, TypingEvent up, int completesAtUp)
        {
            events.Add(down); completions.Add(0);
            events.Add(up); completions.Add(completesAtUp);
        }

        for (var i = 0; i < text.Length; i++)
        {
            var ch = text[i];
            switch (ch)
            {
                case '\r':
                    // CRLF is one Enter, not two: the pair's
                    // key-up completes BOTH source characters.
                    var crlf = i + 1 < text.Length && text[i + 1] == '\n';
                    Pair(TypingEvent.VkDown(VkReturn), TypingEvent.VkUp(VkReturn), crlf ? 2 : 1);
                    if (crlf) i++;
                    break;
                case '\n':
                    Pair(TypingEvent.VkDown(VkReturn), TypingEvent.VkUp(VkReturn), 1);
                    break;
                case '\t':
                    Pair(TypingEvent.VkDown(VkTab), TypingEvent.VkUp(VkTab), 1);
                    break;
                default:
                    Pair(TypingEvent.UnicodeDown(ch), TypingEvent.UnicodeUp(ch), 1);
                    break;
            }
        }
        return new TypingPlan(events, completions, text.Length);
    }

    /// <summary>The type_text result for a finished (or stopped)
    /// send. Success is claimed ONLY when every planned character
    /// is confirmed by the OS's accepted-event count; anything
    /// less is a failure that states the true counts — the tool
    /// never reports submitted characters as typed.</summary>
    public static (bool Ok, string Text) Outcome(int totalChars, int confirmedChars)
    {
        if (confirmedChars >= totalChars)
            return (true, $"typed {totalChars} characters");
        return (false, $"typing fell short: the OS input queue accepted {confirmedChars} of {totalChars} characters; the remaining {totalChars - confirmedChars} did not land");
    }
}
