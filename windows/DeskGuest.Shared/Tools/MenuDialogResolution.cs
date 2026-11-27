namespace DeskGuest.Shared.Tools;

/// <summary>
/// FR-142 (issue #34) — how ui_menu_dialog resolves a name to an
/// action. The battery's leg 6 (run 7, 2026-11-25) proved the old
/// rule destructive: the engine took the FIRST depth-first element
/// whose name contained the item text. For the item "Save As" with
/// the Save As dialog already open, that first match is the dialog
/// WINDOW itself — it carries no Invoke/ExpandCollapse pattern, so
/// the fallback centre-clicked the window: the click landed in the
/// file list, stole keyboard focus from the file-name edit,
/// collapsed its selection and flipped the dialog's action button
/// from Save to Open. Every later step of the save flow then acted
/// on the wrong control with no error anywhere, and the file was
/// never written.
///
/// The resolution here is the whole fix, and it is pure so it can
/// be pinned without a desktop: given every name match in walk
/// order, described structurally, decide what the tool may do.
///
///   * EXACT name matches decide before substring matches. A
///     caption is a name, not a search term: the item "Save As"
///     names the dialog titled "Save As" exactly, while the
///     "Save as type:" combo merely CONTAINS it — and a combo is
///     expandable, so a substring-first rule lets the longer name
///     hijack the call (the first FR-142 build expanded that
///     combo on the battery's exact call; proven live, fixed by
///     this partition). Exactness ignores case, surrounding
///     whitespace, and a trailing ellipsis (menu captions carry
///     "Save As..." for the item "Save As").
///   * Within the deciding partition, ACTIONABLE matches win, in
///     walk order. Actionable means a menu item / button class of
///     control, or any non-window element exposing Invoke or
///     ExpandCollapse. The winner's own patterns choose Invoke
///     over Expand over a plain click.
///   * A WINDOW is never actionable — not even if it somehow
///     reports an invoke pattern. A name that matches only the
///     window of an already-open dialog resolves to AlreadyOpen:
///     the tool reports the dialog is already open and clicks
///     NOTHING. Clicking a window's own surface is a state-changing
///     act disguised as a handle, and it is never what the caller
///     asked for.
///   * A name matching only non-actionable, non-window elements
///     (a label, a pane, an edit) is refused plainly, naming what
///     it matched — never a blind centre-click on a bystander.
///   * No matches at all is NotFound, as before.
/// </summary>
public enum MenuDialogOutcome
{
    Invoke,
    Expand,
    Click,
    AlreadyOpen,
    RefuseNonActionable,
    NotFound,
}

/// <summary>One name match, described structurally: the element's
/// name and control type (UIA programmatic name without the
/// "ControlType." prefix), and which action patterns it exposes.</summary>
public sealed record MenuDialogCandidate(
    string Name, string ControlType, bool HasInvoke, bool HasExpandCollapse);

public static class MenuDialogResolution
{
    /// <summary>Control types that are legitimate click/invoke
    /// targets for a by-name menu/dialog action.</summary>
    private static readonly IReadOnlySet<string> ActionableControlTypes =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "MenuItem", "Button", "SplitButton", "ListItem", "TreeItem",
            "TabItem", "CheckBox", "RadioButton", "Hyperlink",
        };

    public static bool IsWindow(MenuDialogCandidate candidate) =>
        string.Equals(candidate.ControlType, "Window", StringComparison.OrdinalIgnoreCase);

    /// <summary>Actionable = a real menu item / button, or any
    /// non-window element that can be invoked or expanded. A window
    /// is excluded FIRST, unconditionally: its surface is never a
    /// click target for name resolution.</summary>
    public static bool IsActionable(MenuDialogCandidate candidate) =>
        !IsWindow(candidate)
        && (candidate.HasInvoke
            || candidate.HasExpandCollapse
            || ActionableControlTypes.Contains(candidate.ControlType));

    /// <summary>An element's name IS the requested item's name:
    /// equal ignoring case and surrounding whitespace, with a
    /// trailing ellipsis (the menu-caption convention) forgiven
    /// on either side.</summary>
    public static bool IsExactName(string? elementName, string itemName) =>
        string.Equals(NormalizeCaption(elementName), NormalizeCaption(itemName), StringComparison.OrdinalIgnoreCase);

    private static string NormalizeCaption(string? name)
    {
        var s = (name ?? "").Trim();
        if (s.EndsWith("...", StringComparison.Ordinal)) s = s[..^3].TrimEnd();
        else if (s.EndsWith("…", StringComparison.Ordinal)) s = s[..^1].TrimEnd();
        return s;
    }

    /// <summary>Decide the action over all name matches in walk
    /// order. Exact-name matches form the deciding pool when any
    /// exist; otherwise every (substring) match does. Returns the
    /// outcome and the index of the match it refers to, in the
    /// ORIGINAL list (-1 for NotFound).</summary>
    public static (MenuDialogOutcome Outcome, int Index) Decide(IReadOnlyList<MenuDialogCandidate> matches, string itemName)
    {
        var pool = new List<int>();
        for (var i = 0; i < matches.Count; i++)
            if (IsExactName(matches[i].Name, itemName)) pool.Add(i);
        if (pool.Count == 0)
            for (var i = 0; i < matches.Count; i++) pool.Add(i);

        foreach (var i in pool)
        {
            var candidate = matches[i];
            if (!IsActionable(candidate)) continue;
            if (candidate.HasInvoke) return (MenuDialogOutcome.Invoke, i);
            if (candidate.HasExpandCollapse) return (MenuDialogOutcome.Expand, i);
            return (MenuDialogOutcome.Click, i);
        }
        foreach (var i in pool)
            if (IsWindow(matches[i]))
                return (MenuDialogOutcome.AlreadyOpen, i);
        if (pool.Count > 0)
            return (MenuDialogOutcome.RefuseNonActionable, pool[0]);
        return (MenuDialogOutcome.NotFound, -1);
    }
}
