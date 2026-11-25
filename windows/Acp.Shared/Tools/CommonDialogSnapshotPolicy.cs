namespace Acp.Shared.Tools;

/// <summary>
/// FR-142 (issue #34) — the snapshot walk's guarantee for common
/// file dialogs (Save As / Open). The battery's leg 6 probe
/// (2026-11-25) verified that DeskGuest's own snapshot of a Save
/// As dialog did not contain the file-name label, the file-name
/// combo/edit, or the Save-as-type combo at all — while an
/// independent UIA walk saw them plainly. From the agent's seat
/// the controls that matter most in that dialog class simply did
/// not exist, so a save flow could not be verified from the
/// snapshot the agent is given.
///
/// The walk's two shared limits are what starve a dialog subtree:
/// one node budget for the whole desktop, spent depth-first, and
/// one depth cap. A dialog's own tree spends both against the
/// agent — a fat sibling subtree (the shell folder view, with a
/// list item per file) can consume the budget before the walk
/// ever reaches the bottom-band controls, and the file-name edit
/// sits one level below its combo, near the depth cap.
///
/// The policy here is the pure half of the guarantee the walk
/// (UiaSnapshot, Windows-bound) implements:
///
///   * A common dialog window — the standard dialog class
///     #32770 — gets its OWN node budget (DialogNodeBudget) and a
///     depth allowance (DialogDepthAllowance) beyond the caller's
///     cap, so other windows and the dialog's own size cannot
///     starve it.
///   * Inside a dialog subtree the budget is spent BREADTH-FAIR:
///     while siblings remain unwalked, no single child subtree
///     may consume more than half the remaining budget (with a
///     floor so a late, small subtree — a combo and its edit —
///     always fits). ChildSubtreeAllowance is that rule.
///   * The file-name and file-type controls are identifiable from
///     their snapshot descriptors (IsFileNameControl /
///     IsFileTypeControl), which is what the pin checks and what
///     an agent (or a verifier) looks for in the snapshot.
/// </summary>
public static class CommonDialogSnapshotPolicy
{
    /// <summary>Node budget reserved for one common dialog's
    /// subtree, independent of the desktop-wide budget.</summary>
    public const int DialogNodeBudget = 500;

    /// <summary>Extra depth a common dialog's subtree may use
    /// beyond the caller's cap.</summary>
    public const int DialogDepthAllowance = 10;

    /// <summary>Floor for a child subtree's allowance while
    /// siblings remain: a small late subtree always fits whole.</summary>
    public const int MinChildSubtreeNodes = 32;

    /// <summary>The standard Windows dialog class: every common
    /// file dialog (Save As / Open) is a #32770 window.</summary>
    public static bool IsCommonDialogWindow(string? className, string? controlType) =>
        string.Equals(controlType, "Window", StringComparison.OrdinalIgnoreCase)
        && string.Equals(className, "#32770", StringComparison.Ordinal);

    /// <summary>How many nodes one child subtree may consume.
    /// The last remaining child takes whatever is left; any
    /// earlier child is capped at half the remaining budget,
    /// floored at MinChildSubtreeNodes, never more than remains.</summary>
    public static int ChildSubtreeAllowance(int remainingBudget, int childrenRemaining)
    {
        if (remainingBudget <= 0) return 0;
        if (childrenRemaining <= 1) return remainingBudget;
        return Math.Min(remainingBudget, Math.Max(MinChildSubtreeNodes, remainingBudget / 2));
    }

    /// <summary>The file-name edit/combo of a common dialog,
    /// identified from snapshot descriptors: by its host
    /// automation id, or as a text-entry control carrying the
    /// "File name" label.</summary>
    public static bool IsFileNameControl(string? name, string? controlType, string? automationId)
    {
        if (string.Equals(automationId, "FileNameControlHost", StringComparison.OrdinalIgnoreCase))
            return true;
        return IsTextEntry(controlType)
            && name is not null
            && name.StartsWith("File name", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>The Save-as-type / Files-of-type combo of a common
    /// dialog, identified the same way.</summary>
    public static bool IsFileTypeControl(string? name, string? controlType, string? automationId)
    {
        if (string.Equals(automationId, "FileTypeControlHost", StringComparison.OrdinalIgnoreCase))
            return true;
        return IsTextEntry(controlType)
            && name is not null
            && (name.StartsWith("Save as type", StringComparison.OrdinalIgnoreCase)
                || name.StartsWith("Files of type", StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsTextEntry(string? controlType) =>
        string.Equals(controlType, "Edit", StringComparison.OrdinalIgnoreCase)
        || string.Equals(controlType, "ComboBox", StringComparison.OrdinalIgnoreCase);
}
