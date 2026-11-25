namespace Acp.Shared.Presence;

/// <summary>
/// FR-111 / FR-114 (W60-A) — the ONE presence compositor model,
/// as amended by the W72 pill build (2026-11-23, micro-decision
/// under delegation, W71 BUILD-SPEC §1). the owner's live photos
/// (2026-11-23 19:25 / 19:30 CT) showed THREE presence renderings
/// from different build layers colliding on one desktop: the
/// session Box, a gate panel carrying its own generic presence
/// header, and a takeover-hint bar floating as its own window.
/// The law this model pins:
///
///  * A session composes EXACTLY three presence elements — Box,
///    Glow, Ghost (PresenceLaw.Elements). Nothing else floats.
///    The Box's live form is the Screen 11 PILL: face circle, the
///    one-sentence line (PillSentence), and STOP (ESC).
///  * The takeover hint does NOT print on the pill (W72
///    micro-decision superseding the W60-A printed bottom line):
///    STOP (ESC) is the visible control path. Touch-to-yield
///    still FUNCTIONS; it is taught in setup/help, not printed.
///    The hint text and chord constants are retained below for
///    those surfaces. The hint is never an element, never a
///    window, never a bar of its own.
///  * Roster and elapsed no longer print on the Box (W72): the
///    pill carries exactly face + sentence + STOP. Roster data
///    lives on the session/roster surfaces and in audit; elapsed
///    lives in History.
///  * The approval gate is a CARD within this system, not a
///    presence surface: it carries no presence header of its own
///    (the Box above it — held by the compositor while a gate is
///    up — is the header: named agent, STOP), and the generic
///    header sentence exists NOWHERE in the session presence
///    path: every presence header names the specific paired
///    agent. The pill sentence names the agent and says "your
///    computer" — it is not the banned unnamed generic.
///  * Detail levels (FR-105): Full and CompactMinimum now return
///    the same three line kinds — the pill form itself satisfies
///    the compact floor (name + state + STOP) at every level.
///    Pinned by W60PresenceCompositionTests.
/// </summary>
public enum PresenceElementKind { Box, Glow, Ghost }

/// <summary>Box detail levels (FR-105 customization surface:
/// detail is a property of the Box as one unit).</summary>
public enum BoxDetailLevel { Full, CompactMinimum }

/// <summary>One content line of the Box, in render order.</summary>
public enum BoxLineKind { DriverName, StateSentence, Roster, Stop, TakeoverHint }

public static class PresenceComposition
{
    /// <summary>The takeover chord — the product's actual chord
    /// text. Retained for setup/help surfaces (W72: the pill does
    /// not print it); one home so every surface agrees.</summary>
    public const string TakeoverChordText = "Ctrl + Alt + Shift + Backspace";

    /// <summary>The hint line's exact affordance text (FR-111:
    /// composition changed, copy did not). W72: no longer Box
    /// content — it is the setup/help teaching of the touch-to-
    /// yield chord, which still functions. The SessionAgent reads
    /// the same sentence through its U8 Strings door
    /// (PresenceTakeoverHint) and the shared DesignStrings table
    /// (presence_takeover_hint); the W60 tests pin all three equal.</summary>
    public const string TakeoverHintText = "Press Ctrl + Alt + Shift + Backspace to take over";

    /// <summary>The BANNED generic header. Named here only so the
    /// composition tests can pin its absence from every session
    /// presence surface: a presence header names the specific
    /// paired agent or it does not render.</summary>
    public const string GenericHeaderText = "AI is controlling this computer";

    /// <summary>The gate card's kind tag — content hosted by the
    /// compositor, deliberately NOT a PresenceElementKind.</summary>
    public const string GateCardKind = "GATE_CARD";

    /// <summary>The elements a live session composes: exactly the
    /// Box and the Glow, plus the Ghost while it is drawn (it
    /// withdraws while a gate is up or the owner is driving —
    /// PresenceLaw.GhostDrawn decides that, this model only
    /// enumerates).</summary>
    public static IReadOnlyList<PresenceElementKind> SessionElements(bool ghostDrawn) =>
        ghostDrawn
            ? new[] { PresenceElementKind.Box, PresenceElementKind.Glow, PresenceElementKind.Ghost }
            : new[] { PresenceElementKind.Box, PresenceElementKind.Glow };

    /// <summary>The elements composed while a gate is up: the Box
    /// (amber, held above the card — the card's header) and the
    /// Glow. The Ghost is withdrawn (PresenceLaw.GhostDrawn), and
    /// the gate card is content, not an element.</summary>
    public static IReadOnlyList<PresenceElementKind> GateElements() =>
        new[] { PresenceElementKind.Box, PresenceElementKind.Glow };

    /// <summary>The Box's content lines, in order, for a detail
    /// level. The pill form (W72): exactly driver name, state
    /// sentence, STOP — at BOTH detail levels, so Full ==
    /// CompactMinimum and the FR-105 floor is satisfied by the
    /// pill itself. hasRoster stays a parameter (signature
    /// stability for Android-mirrored callers) but no longer adds
    /// a printed line: roster/elapsed are not pill content.</summary>
    public static IReadOnlyList<BoxLineKind> BoxLines(BoxDetailLevel detail, bool hasRoster) =>
        new[] { BoxLineKind.DriverName, BoxLineKind.StateSentence, BoxLineKind.Stop };

    /// <summary>The pill's controlling-state sentence — ONE home
    /// (W72, Board 4 Screen 11 verbatim): the bold segment names
    /// the LIVE paired agent, the regular segment is the board's
    /// exact remainder. Renderer, tests and any future surface
    /// read it here so they can never drift apart.</summary>
    public static (string BoldSegment, string RegularSegment) PillSentence(string agentName) =>
        ($"{agentName} (AI Agent)", " is controlling your computer — You see everything");

    /// <summary>FR-105 (W85): the COMPACT PILL detail form's line —
    /// the detail-level option the owner's photo evidence added (the
    /// ChatGPT/Codex compact pill, beaten: ours still names the
    /// driver, states the state as a WORD, and carries STOP beside
    /// it in the renderer). Exactly three parts — name, state word,
    /// and the STOP label the renderer draws — never fewer: the
    /// compact form is smaller, never emptier.</summary>
    public static (string Name, string StateWord, string StopLabel) CompactPillLine(
        string agentName, string stateWord) =>
        (agentName, stateWord, "STOP (ESC)");

    /// <summary>W117 / F2 — the presence branches whose sentence
    /// the pill carries. EVERY branch names the driver: W115
    /// proved the owner-driving branch read only "Paused — you're
    /// driving" with no agent name on any surface, against the
    /// names-the-driver law (FR-121's rule, extended to all
    /// branches here). BranchSentence is the ONE home for these
    /// sentences; the renderer and the preview both read it, and
    /// the W117 pins check every branch for the pairing's name.</summary>
    public enum PresenceBranch { Driving, OwnerDriving, Waiting, Gate, Blocked }

    /// <summary>The sentence a branch renders, ALWAYS naming the
    /// specific paired agent. Driving is the board sentence
    /// (PillSentence) verbatim. OwnerDriving keeps the existing
    /// copy register ("Paused — you're driving") and prepends
    /// the name the law requires — the agent is still present
    /// and observing while the owner drives. Gate is the live
    /// sentence W115 captured above the gate card. Blocked equals
    /// the SessionAgent's PresenceBlockedFormat string (pinned
    /// equal in the W117 tests so the two homes cannot drift).</summary>
    public static string BranchSentence(PresenceBranch branch, string agentName) => branch switch
    {
        PresenceBranch.Driving => PillSentence(agentName).BoldSegment + PillSentence(agentName).RegularSegment,
        PresenceBranch.OwnerDriving => $"{agentName} is paused — you're driving",
        PresenceBranch.Waiting => $"{agentName} is here — waiting",
        PresenceBranch.Gate => $"{agentName} is working on your laptop",
        PresenceBranch.Blocked => $"{agentName} is blocked — STOP is in force",
        _ => $"{agentName} is here",
    };

    /// <summary>The gate card's exit colours — ONE home, consumed
    /// by the GateSheet renderer, so the exits' contrast is a
    /// property of the system, not of a window that happens to
    /// host them. Approve is achromatic (light fill, dark text);
    /// Deny and Deny-and-end sit on the card's dark fill with
    /// light text. FR-114's live evidence (Deny labels rendering
    /// white-on-light, near-invisible) is what happens when a
    /// platform template overrides these bindings; the renderer
    /// therefore pins them through an explicit template, and the
    /// W60 tests pin the ratios below at WCAG AA or better.</summary>
    public static class GateCardColors
    {
        public const int ApproveBackground = unchecked((int)0xFFF0F0F3);
        public const int ApproveForeground = unchecked((int)0xFF101016);
        public const int DenyBackground = unchecked((int)0xFF1B1B24);
        public const int DenyForeground = unchecked((int)0xFFF0F0F3);
        // W119 (S12 revision, W64 token sheet): red #DC2626 is
        // strict-use — it appears ONLY on «Deny and end session»,
        // the one exit that ends the session. White on #DC2626 is
        // 4.83:1 (WCAG AA for the exits' 14.5pt semibold text).
        public const int DenyAndEndBackground = unchecked((int)0xFFDC2626);
        public const int DenyAndEndForeground = unchecked((int)0xFFFFFFFF);
        public const int CardBackground = unchecked((int)0xFF14141C);
    }

    /// <summary>WCAG relative-luminance contrast ratio between two
    /// ARGB colours (alpha ignored — both colours are opaque).
    /// 1.0 is no contrast; 21.0 is black on white.</summary>
    public static double ContrastRatio(int argbA, int argbB)
    {
        double Luminance(int argb)
        {
            double Channel(int shift)
            {
                var c = ((argb >> shift) & 0xFF) / 255.0;
                return c <= 0.03928 ? c / 12.92 : Math.Pow((c + 0.055) / 1.055, 2.4);
            }
            return 0.2126 * Channel(16) + 0.7152 * Channel(8) + 0.0722 * Channel(0);
        }
        var (hi, lo) = (Luminance(argbA), Luminance(argbB));
        if (hi < lo) (hi, lo) = (lo, hi);
        return (hi + 0.05) / (lo + 0.05);
    }
}
