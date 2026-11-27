namespace DeskGuest.Shared.Design;

/// <summary>
/// W9 Task 4 — the OI-05 STOP-hotkey extended fixture, run. The
/// design rounds agreed the mechanism and left the chord undecided:
/// the shipped default is the FIRST candidate that passes the
/// extended fixture — the five conflict lists the merged record
/// names (Windows OS assignments, RDP client mappings, GPU hotkeys
/// across Intel/NVIDIA/AMD, OEM utilities, common clipboard/screen
/// tools). The Box STOP is the floor and always works; the hotkey
/// is a non-disableable convenience on top of it.
///
/// A candidate FAILS on an exact claim in any list, and also on a
/// SLIP-ADJACENT claim: a claimed chord with the same key differing
/// by exactly one modifier — a panicked near-miss must not land on
/// somebody else's function (the Intel Ctrl+Alt+F12 display chord
/// is the standing example). Every claim below carries its source;
/// lists consulted with no claim on any candidate are recorded in
/// ConsultedLists so the coverage is auditable, not implied.
/// </summary>
public static class StopHotkeyFixture
{
    public sealed record Candidate(string Chord, IReadOnlySet<string> Modifiers, string Key);

    public sealed record Claim(string ListName, string Chord, IReadOnlySet<string> Modifiers, string Key, string ClaimedBy, string Source);

    public sealed record Verdict(Candidate Candidate, bool Survives, string Reason);

    public const string ListWindowsOs = "windows_os";
    public const string ListRdpClient = "rdp_client";
    public const string ListGpuHotkeys = "gpu_hotkeys";
    public const string ListOemUtilities = "oem_utilities";
    public const string ListClipboardScreenTools = "clipboard_screen_tools";

    /// <summary>All five lists the merged record requires, whether
    /// or not they produced a claim on a candidate.</summary>
    public static readonly IReadOnlyList<string> ConsultedLists = new[]
    {
        ListWindowsOs, ListRdpClient, ListGpuHotkeys, ListOemUtilities, ListClipboardScreenTools,
    };

    private static Candidate C(string chord)
    {
        var parts = chord.Split('+');
        return new Candidate(chord, parts.Take(parts.Length - 1).ToHashSet(StringComparer.OrdinalIgnoreCase), parts[^1]);
    }

    private static Claim K(string list, string chord, string by, string source)
    {
        var c = C(chord);
        return new Claim(list, chord, c.Modifiers, c.Key, by, source);
    }

    /// <summary>Claims, each with the source it was read from
    /// (checked 2026-11-23).</summary>
    public static readonly IReadOnlyList<Claim> Claims = new[]
    {
        // Windows OS assignments.
        K(ListWindowsOs, "Ctrl+Shift+Esc", "Windows Task Manager",
            "Windows OS assignment; also named in the design record's rejected set"),
        K(ListWindowsOs, "Win+Ctrl+Shift+B", "Windows graphics-driver restart (WDDM/DWM reset)",
            "Microsoft-published black-screen troubleshooting chord; corroborated by How-To Geek and Puget Systems"),
        // RDP client mappings — Microsoft Learn, "Remote Desktop
        // Services Shortcut Keys" (learn.microsoft.com/en-us/windows/win32/termserv/terminal-services-shortcut-keys).
        K(ListRdpClient, "Ctrl+Alt+End", "RDP: Windows Security dialog (the RDP Ctrl+Alt+Del)",
            "Microsoft Learn, Remote Desktop Services Shortcut Keys"),
        K(ListRdpClient, "Ctrl+Alt+Home", "RDP: activate the connection bar",
            "Microsoft Learn, Remote Desktop Services Shortcut Keys"),
        K(ListRdpClient, "Ctrl+Alt+Break", "RDP: switch client between full-screen and window mode",
            "Microsoft Learn, Remote Desktop Services Shortcut Keys"),
        K(ListRdpClient, "Ctrl+Alt+Pause", "RDP: full-screen/window switch (Break alternate)",
            "Microsoft Learn, Remote Desktop Services Shortcut Keys"),
        K(ListRdpClient, "Ctrl+Alt+Minus", "RDP: snapshot of the active window to the clipboard",
            "Microsoft Learn, Remote Desktop Services Shortcut Keys"),
        K(ListRdpClient, "Ctrl+Alt+Plus", "RDP: snapshot of the entire client area to the clipboard",
            "Microsoft Learn, Remote Desktop Services Shortcut Keys"),
        // GPU hotkeys.
        K(ListGpuHotkeys, "Ctrl+Alt+F12", "Intel graphics (legacy): display/rotation hotkey family",
            "Intel support article 000005596, as carried in the design x-exam [R1] fold"),
        K(ListGpuHotkeys, "Alt+F9", "NVIDIA GeForce Experience / NVIDIA App: start/stop manual recording",
            "NVIDIA GeForce Experience default shortcut lists (multiple corroborating listings)"),
        K(ListGpuHotkeys, "Alt+F10", "NVIDIA: save the last minutes (Instant Replay)",
            "NVIDIA GeForce Experience default shortcut lists"),
        K(ListGpuHotkeys, "Alt+Shift+F10", "NVIDIA: toggle Instant Replay on/off",
            "NVIDIA GeForce Experience default shortcut lists"),
        K(ListGpuHotkeys, "Alt+F12", "NVIDIA: toggle FPS counter",
            "NVIDIA GeForce Experience default shortcut lists"),
        K(ListGpuHotkeys, "Ctrl+Shift+O", "AMD Software Adrenalin: toggle performance overlay",
            "AMD support article DH3-038 (amd.com)"),
        K(ListGpuHotkeys, "Ctrl+Shift+L", "AMD Software Adrenalin: toggle performance logging",
            "AMD support article DH3-038 (amd.com)"),
        K(ListGpuHotkeys, "Ctrl+Shift+E", "AMD Software Adrenalin: toggle video recording",
            "AMD Adrenalin hotkey listings (MakeUseOf / defkey corroborated)"),
        // OEM utilities and clipboard/screen tools were consulted
        // (ConsultedLists): their published defaults bind Fn-row /
        // vendor keys and PrintScreen-family chords (ShareX:
        // Ctrl+PrintScreen region capture; Ditto: Ctrl+grave) — none
        // claims any candidate chord below, exactly or slip-adjacent.
    };

    /// <summary>The candidate pool in preference order: the three
    /// chords the design rounds already rejected with evidence, the
    /// RDP/OS/GPU claims found by this fixture run, and the
    /// four-modifier F-row chords that remain.</summary>
    public static readonly IReadOnlyList<Candidate> Candidates = new[]
    {
        C("Ctrl+Alt+Shift+F9"),
        C("Ctrl+Alt+Shift+F11"),
        C("Ctrl+Alt+Shift+F12"),
        C("Ctrl+Alt+Shift+F10"),
        C("Ctrl+Shift+Esc"),
        C("Ctrl+Alt+End"),
        C("Ctrl+Alt+F12"),
        C("Ctrl+Alt+Break"),
        C("Ctrl+Alt+Home"),
        C("Ctrl+Alt+Minus"),
        C("Win+Ctrl+Shift+B"),
        C("Alt+Shift+F10"),
        C("Ctrl+Shift+O"),
    };

    public static IReadOnlyList<Verdict> Evaluate()
    {
        var verdicts = new List<Verdict>();
        foreach (var candidate in Candidates)
        {
            var exact = Claims.FirstOrDefault(k => k.Chord.Equals(candidate.Chord, StringComparison.OrdinalIgnoreCase));
            if (exact is not null)
            {
                verdicts.Add(new Verdict(candidate, false,
                    $"claimed in {exact.ListName}: {exact.ClaimedBy} [{exact.Source}]"));
                continue;
            }
            var adjacent = Claims.FirstOrDefault(k =>
                k.Key.Equals(candidate.Key, StringComparison.OrdinalIgnoreCase) &&
                SymmetricDifference(k.Modifiers, candidate.Modifiers) == 1);
            if (adjacent is not null)
            {
                verdicts.Add(new Verdict(candidate, false,
                    $"slip-adjacent to {adjacent.Chord} claimed in {adjacent.ListName}: {adjacent.ClaimedBy} [{adjacent.Source}]"));
                continue;
            }
            verdicts.Add(new Verdict(candidate, true,
                "no exact or slip-adjacent claim in any of the five fixture lists"));
        }
        return verdicts;
    }

    private static int SymmetricDifference(IReadOnlySet<string> a, IReadOnlySet<string> b)
        => a.Count(m => !b.Contains(m)) + b.Count(m => !a.Contains(m));

    /// <summary>The shipped default: the first surviving candidate
    /// in preference order, or null if the fixture kills them all
    /// (an honest outcome the record allows — the Box is the
    /// floor). Run 2026-11-23: Ctrl+Alt+Shift+F9.</summary>
    public static Candidate? DefaultChord => Evaluate().FirstOrDefault(v => v.Survives)?.Candidate;
}
