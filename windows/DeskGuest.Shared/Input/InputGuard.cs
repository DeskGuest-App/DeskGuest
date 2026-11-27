namespace DeskGuest.Shared.Input;

/// <summary>
/// BD-WIN-AGENT F7: the ONE keyboard-injection guard (X1 credential
/// fields, X19 SAS/lock combos). Before this, the refusals were
/// per-tool substring checks: key_press matched only the literal
/// spellings "ctrl+alt+del" / "win+l", input_primitives key_down had
/// no check at all, and a password field could be filled by
/// clipboard_set + ctrl+v. Every keyboard injection path in the
/// Session Agent now routes through this guard:
///
///   * Chords are parsed into a canonical virtual-key set, so word
///     order and spelling ("alt+ctrl+del", "control+alt+delete",
///     "l+win", "windows+l") cannot slip past.
///   * The forbidden-combo test runs against the PROSPECTIVE held
///     set (keys already held via key_down plus the key about to go
///     down), so a combo assembled one key_down at a time is refused
///     at the key that completes it.
///   * <see cref="NeedsCredentialFieldCheck"/> names exactly the
///     injections that must first prove the focused element is not
///     a password field (printable keys, Enter, and the paste chord)
///     — the caller performs that UIA probe and FAILS CLOSED when
///     the probe cannot run.
/// </summary>
public static class InputGuard
{
    public const ushort VkShift = 0x10;
    public const ushort VkControl = 0x11;
    public const ushort VkAlt = 0x12;
    public const ushort VkLWin = 0x5B;
    public const ushort VkRWin = 0x5C;
    public const ushort VkDelete = 0x2E;
    public const ushort VkReturn = 0x0D;

    /// <summary>Canonical virtual-key for one key name, or 0 when the
    /// name is unknown. Accepts every spelling the engine's Vk map
    /// accepts, plus the long forms ("control", "delete", "windows",
    /// "meta", "cmd") an agent might emit.</summary>
    public static ushort VirtualKeyFor(string? key) => key?.Trim().ToLowerInvariant() switch
    {
        "ctrl" or "control" or "ctl" => VkControl,
        "alt" or "menu" => VkAlt,
        "shift" => VkShift,
        "win" or "windows" or "meta" or "cmd" or "command" or "super" => VkLWin,
        "lwin" => VkLWin,
        "rwin" => VkRWin,
        "enter" or "return" => VkReturn,
        "esc" or "escape" => 0x1B,
        "tab" => 0x09,
        "backspace" or "back" => 0x08,
        "delete" or "del" => VkDelete,
        "insert" or "ins" => 0x2D,
        "space" or "spacebar" => 0x20,
        "up" => 0x26, "down" => 0x28, "left" => 0x25, "right" => 0x27,
        "home" => 0x24, "end" => 0x23, "pageup" or "page_up" or "pgup" => 0x21,
        "pagedown" or "page_down" or "pgdn" => 0x22,
        "capslock" or "caps_lock" => 0x14,
        "f1" => 0x70, "f2" => 0x71, "f3" => 0x72, "f4" => 0x73, "f5" => 0x74, "f6" => 0x75,
        "f7" => 0x76, "f8" => 0x77, "f9" => 0x78, "f10" => 0x79, "f11" => 0x7A, "f12" => 0x7B,
        { Length: 1 } single => (ushort)char.ToUpperInvariant(single[0]),
        _ => 0,
    };

    /// <summary>Parse a "+"-joined chord ("ctrl+shift+a") into its
    /// virtual keys, in the order written (modifiers first, as an
    /// agent writes them — the caller presses in this order and
    /// releases in reverse). Returns null when any part is unknown —
    /// the caller refuses rather than guessing.</summary>
    public static List<ushort>? ParseChord(string? keys)
    {
        if (string.IsNullOrWhiteSpace(keys)) return null;
        var list = new List<ushort>();
        foreach (var part in keys.Split('+', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            var vk = VirtualKeyFor(part);
            if (vk == 0) return null;
            if (!list.Contains(vk)) list.Add(vk);
        }
        return list.Count > 0 ? list : null;
    }

    /// <summary>True when a key set contains a combo that can never
    /// be injected (X19): Ctrl+Alt+Del (the secure attention
    /// sequence) or Win+L (workstation lock), in any order/spelling.</summary>
    public static bool IsForbiddenCombo(IEnumerable<ushort> keys)
    {
        var set = keys as IReadOnlySet<ushort> ?? new HashSet<ushort>(keys);
        return (set.Contains(VkControl) && set.Contains(VkAlt) && set.Contains(VkDelete))
            || ((set.Contains(VkLWin) || set.Contains(VkRWin)) && set.Contains((ushort)'L'));
    }

    /// <summary>True when pressing <paramref name="next"/> while
    /// <paramref name="alreadyHeld"/> are down would complete a
    /// forbidden combo — the split key_down/key_up bypass.</summary>
    public static bool WouldCompleteForbiddenCombo(IEnumerable<ushort> alreadyHeld, ushort next)
    {
        var prospective = new HashSet<ushort>(alreadyHeld) { next };
        return IsForbiddenCombo(prospective);
    }

    /// <summary>True for the paste chord Ctrl+V (any Win key absent):
    /// pasting is typing for guard purposes.</summary>
    public static bool IsPasteChord(IEnumerable<ushort> keys)
    {
        var set = keys as IReadOnlySet<ushort> ?? new HashSet<ushort>(keys);
        return set.Contains(VkControl) && set.Contains((ushort)'V') && !set.Contains(VkLWin) && !set.Contains(VkRWin);
    }

    /// <summary>True when a single key press can put text (or a
    /// line commit) into the focused field: letters, digits, space,
    /// Enter, and common punctuation virtual keys.</summary>
    public static bool IsTextProducingKey(ushort vk) =>
        (vk >= (ushort)'A' && vk <= (ushort)'Z')
        || (vk >= (ushort)'0' && vk <= (ushort)'9')
        || vk == 0x20 /* space */ || vk == VkReturn || vk == 0x09 /* tab */
        || (vk >= 0xBA && vk <= 0xE4); // OEM punctuation range

    /// <summary>The credential-field (X1) decision for one injection:
    /// true when the caller must verify the focused element is not a
    /// password field (failing closed) before sending. Covers whole
    /// chords (paste, any text-producing member) and single keys.</summary>
    public static bool NeedsCredentialFieldCheck(IEnumerable<ushort> keys) =>
        IsPasteChord(keys) || keys.Any(IsTextProducingKey);
}
