namespace Acp.Shared.Input;

/// <summary>
/// FR-140 — the pure half of type_text's delivery verification.
///
/// The battery (run 6, 2026-11-25) proved the gap FR-139 could
/// not see: SendInput's accepted-event count ends at the OS
/// input queue, but a target app can still drop a character on
/// its own side of the queue — the scripted line arrived in
/// Notepad missing the "d" of "drive", a file path arrived in
/// the Save As field missing the "r" of "Users", and the tool
/// reported success both times (≈1 character per 50 under the
/// battery's real conditions).
///
/// Where the target exposes its text (UI Automation TextPattern
/// — Notepad, standard edit controls, most real text fields),
/// the engine reads the text before and after typing and
/// verifies the delivery against the prediction computed here:
/// the before-text with the typed text inserted at the captured
/// selection. These functions are the whole prediction: pure,
/// pinned, and shared by the engine's verify and repair paths.
///
/// Coordinates: everything here works in the DOCUMENT's own
/// text space — the same space UI Automation reports offsets
/// in. The one conversion is line breaks: the plan sends a
/// typed LF as the Enter key, which lands as the document's own
/// line break (CRLF in a Windows document). Predictions
/// therefore convert the typed text's line breaks to the
/// document's break, inferred from the before-text, before
/// inserting, and region offsets stay in the document's
/// coordinates. The final comparison is made in
/// break-NORMALISED form (see NormalizeBreaks): a target may
/// read its breaks back in a different representation than
/// the prediction's, and that difference is not a delivery
/// failure — a missing or altered content character is.
/// </summary>
public static class TypingVerification
{
    /// <summary>The document's line break, inferred from its
    /// existing text: CRLF if the text uses it, else a lone CR
    /// if it uses that, else LF (also the empty-document
    /// default is CRLF — the Windows convention).</summary>
    public static string DocumentBreak(string before)
    {
        if (before.Contains("\r\n")) return "\r\n";
        if (before.Contains('\r')) return "\r";
        if (before.Contains('\n')) return "\n";
        return "\r\n";
    }

    /// <summary>The typed text as it will appear in the
    /// document: its line breaks (CRLF, CR, or LF in the source)
    /// become the document's break.</summary>
    public static string ConvertTyped(string typed, string docBreak)
    {
        var lf = typed.Replace("\r\n", "\n").Replace("\r", "\n");
        return docBreak == "\n" ? lf : lf.Replace("\n", docBreak);
    }

    /// <summary>How many document characters the first
    /// <paramref name="sourceChars"/> characters of the typed
    /// text occupy once converted (a source line break counts
    /// once in the source and docBreak.Length in the document;
    /// a source CRLF pair is two source characters landing as
    /// one break).</summary>
    public static int ConvertedLength(string typed, int sourceChars, string docBreak)
    {
        var n = Math.Clamp(sourceChars, 0, typed.Length);
        var len = 0;
        for (var i = 0; i < n; i++)
        {
            var ch = typed[i];
            if (ch == '\r')
            {
                // One break; a following LF inside the counted
                // span is the same break (the CRLF pair completes
                // atomically in the plan, so a counted span never
                // ends between the pair's two characters).
                len += docBreak.Length;
                if (i + 1 < n && typed[i + 1] == '\n') i++;
            }
            else if (ch == '\n')
            {
                len += docBreak.Length;
            }
            else len += 1;
        }
        return len;
    }

    /// <summary>The document text predicted after typing
    /// <paramref name="typed"/> into <paramref name="before"/>
    /// at the selection (selStart, selLen): the selection is
    /// replaced by the (break-converted) typed text. Offsets are
    /// clamped into range.</summary>
    public static string ExpectedAfter(string before, int selStart, int selLen, string typed)
    {
        selStart = Math.Clamp(selStart, 0, before.Length);
        selLen = Math.Clamp(selLen, 0, before.Length - selStart);
        return before[..selStart] + ConvertTyped(typed, DocumentBreak(before)) + before[(selStart + selLen)..];
    }

    /// <summary>Break-normalised form: every break — CRLF, CR,
    /// LF — folds to a single LF. The document's CONTENT is
    /// what delivery promises; the break's representation in
    /// the read-back is the target's own business, and targets
    /// differ from the prediction's convention: the Windows 11
    /// Notepad text pattern reads its breaks back as ONE
    /// character each, whatever was typed (measured live in
    /// the FR-140 proof round: a 10-line type read back
    /// exactly 9 characters short of the CRLF prediction —
    /// the 9 breaks — with every content character intact).
    /// A raw comparison fails that delivery forever; the
    /// normalised comparison still fails on any lost, added
    /// or altered CONTENT character.</summary>
    public static string NormalizeBreaks(string text)
        => text.Replace("\r\n", "\n").Replace('\r', '\n');

    /// <summary>True when the read-back document holds exactly
    /// the predicted content — character for character, with
    /// breaks compared by presence, not representation.</summary>
    public static bool MatchesExpected(string actual, string expected) =>
        string.Equals(NormalizeBreaks(actual), NormalizeBreaks(expected), StringComparison.Ordinal);

    /// <summary>How many NORMALISED document characters the
    /// first <paramref name="sourceChars"/> characters of the
    /// typed text occupy (every break counts once, a source
    /// CRLF pair is one break) — the closed loop's progress
    /// measure, in the coordinates the read-back reports.</summary>
    public static int ConvertedLengthNormalized(string typed, int sourceChars)
    {
        var n = Math.Clamp(sourceChars, 0, typed.Length);
        var len = 0;
        for (var i = 0; i < n; i++)
        {
            var ch = typed[i];
            if (ch == '\r')
            {
                len += 1;
                if (i + 1 < n && typed[i + 1] == '\n') i++;
            }
            else len += 1;
        }
        return len;
    }

    /// <summary>
    /// The repair question: the read-back document differs from
    /// the prediction — is the difference confined to the region
    /// this type_text call owns (the span its typed text was
    /// predicted to occupy), so the call may safely rewrite just
    /// that span? True when the read-back still begins with the
    /// predicted prefix (the before-text ahead of the selection)
    /// and still ends with the predicted suffix (the before-text
    /// behind it): everything the call did NOT touch is intact,
    /// and the span between prefix and suffix — whatever of the
    /// typed text actually landed — is the owned region. On
    /// true, <paramref name="regionStart"/> and
    /// <paramref name="regionLength"/> locate that span in the
    /// READ-BACK document's own coordinates.
    /// </summary>
    public static bool TryOwnedRegion(string before, int selStart, int selLen, string actual,
                                      out int regionStart, out int regionLength)
    {
        regionStart = 0;
        regionLength = 0;
        selStart = Math.Clamp(selStart, 0, before.Length);
        selLen = Math.Clamp(selLen, 0, before.Length - selStart);
        var prefix = before[..selStart];
        var suffix = before[(selStart + selLen)..];
        if (actual.Length < prefix.Length + suffix.Length) return false;
        if (!actual.StartsWith(prefix, StringComparison.Ordinal)) return false;
        if (!actual.EndsWith(suffix, StringComparison.Ordinal)) return false;
        regionStart = prefix.Length;
        regionLength = actual.Length - prefix.Length - suffix.Length;
        return true;
    }

    /// <summary>The document length once the target has
    /// processed the first <paramref name="confirmedChars"/>
    /// source characters of the typed text: the before-length,
    /// minus the replaced selection, plus the converted length
    /// of those characters. The engine's closed loop waits for
    /// the target to reach this length before sending the next
    /// chunk, so the sender never runs more than one chunk ahead
    /// of the target's own processing — the backlog the FR-140
    /// losses fell out of never builds up.</summary>
    public static int ExpectedLengthAt(string before, int selLen, string typed, int confirmedChars)
    {
        selLen = Math.Clamp(selLen, 0, before.Length);
        // Measured against the read-back's normalised length:
        // breaks count once there, whatever the document's
        // stored form. (selLen arrives in raw read-back
        // coordinates; a selection spanning breaks is the one
        // approximation, and the wait it feeds has a timeout —
        // a miscount degrades the loop to timed pacing, never
        // to a wrong claim.)
        return NormalizeBreaks(before).Length - selLen + ConvertedLengthNormalized(typed, confirmedChars);
    }
}
