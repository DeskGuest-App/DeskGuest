using DeskGuest.Shared.Tools;

namespace DeskGuest.Tests;

/// <summary>
/// FR-142 — issue #34: ui_menu_dialog centre-clicked the Save As
/// dialog itself, and the snapshot could not see the dialog's
/// file-name controls (Tested-AI battery leg 6 run 7, 2026-11-25,
/// reproduced end-to-end by the operator discrimination probe).
///
/// Defect 1: the engine resolved a name by FIRST depth-first
/// match. For the item "Save As" with that dialog already open,
/// the first match is the dialog window — no action patterns, so
/// the fallback clicked its centre: the click landed in the file
/// list, stole the file-name focus, collapsed the selection and
/// flipped the action button from Save to Open. The fix is the
/// pure MenuDialogResolution: actionable matches win in walk
/// order, a window is NEVER actionable, a window-only match is
/// AlreadyOpen (report, click nothing), a non-actionable-only
/// match is refused plainly.
///
/// Defect 2: the snapshot walk's shared desktop budget/depth
/// starved the dialog subtree — the file-name label, combo/edit
/// and Save-as-type combo were absent from DeskGuest's own
/// snapshot while an independent UIA walk saw them. The walk now
/// gives a common dialog (#32770) its own budget and depth and
/// spends that budget breadth-fair, under the pure
/// CommonDialogSnapshotPolicy pinned here; nodes also carry their
/// ValuePattern value, so the file-name edit appears WITH its
/// current contents.
///
/// The resolution and the policy are pure (DeskGuest.Shared) and pinned
/// directly. The engine and the walk are Windows-bound; their
/// shape is pinned by source, in the W73 pattern. The live
/// behaviour — already-open reported with focus unmoved, the
/// save landing byte-exact, the snapshot naming the file-name
/// edit and its value — is proven on the laptop (BUILD-LOG,
/// FR-142 entry).
/// </summary>
public class Fr142FixTests
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
    private static string Snapshot() => SrcFile("DeskGuest.SessionAgent", "UiaSnapshot.cs");

    private static string MethodBody(string src, string signatureStart, string nextSignatureStart)
    {
        var start = src.IndexOf(signatureStart, StringComparison.Ordinal);
        Assert.True(start >= 0, signatureStart + " not found");
        var rest = src.Substring(start);
        var end = rest.IndexOf(nextSignatureStart, StringComparison.Ordinal);
        return end > 0 ? rest.Substring(0, end) : rest;
    }

    private static MenuDialogCandidate C(string name, string type, bool invoke = false, bool expand = false) =>
        new(name, type, invoke, expand);

    // ---- defect 1: the resolution ----

    [Fact]
    public void WindowOnlyMatch_IsAlreadyOpen_NeverActionable()
    {
        // The battery's exact trap: the only "Save As" match is
        // the already-open dialog window itself.
        var (outcome, index) = MenuDialogResolution.Decide(new[] { C("Save As", "Window") }, "Save As");
        Assert.Equal(MenuDialogOutcome.AlreadyOpen, outcome);
        Assert.Equal(0, index);
        Assert.False(MenuDialogResolution.IsActionable(C("Save As", "Window")));
    }

    [Fact]
    public void WindowWithPatterns_IsStillNeverActionable()
    {
        // The window exclusion comes first, unconditionally —
        // even a synthetic window claiming patterns resolves to
        // AlreadyOpen, never to a click on its surface.
        var window = C("Save As", "Window", invoke: true, expand: true);
        Assert.False(MenuDialogResolution.IsActionable(window));
        var (outcome, _) = MenuDialogResolution.Decide(new[] { window }, "Save As");
        Assert.Equal(MenuDialogOutcome.AlreadyOpen, outcome);
    }

    [Fact]
    public void SubstringHijack_ExactWindowBeatsPartialActionable()
    {
        // The first FR-142 build's live failure: the item
        // "Save As" exactly names the open dialog, but the
        // "Save as type:" combo merely CONTAINS it — and a combo
        // is expandable, so a substring-first rule expanded the
        // combo instead of reporting the dialog already open.
        var matches = new[]
        {
            C("Save As", "Window"),
            C("Save as type:", "ComboBox", expand: true),
        };
        var (outcome, index) = MenuDialogResolution.Decide(matches, "Save As");
        Assert.Equal(MenuDialogOutcome.AlreadyOpen, outcome);
        Assert.Equal(0, index);
    }

    [Fact]
    public void ExactName_IgnoresEllipsisAndCase_PartialStillWorksAsFallback()
    {
        // Menu captions carry the ellipsis: "Save As..." is the
        // exact item "save as".
        Assert.True(MenuDialogResolution.IsExactName("Save As...", "save as"));
        Assert.True(MenuDialogResolution.IsExactName("Save As", "Save As"));
        Assert.False(MenuDialogResolution.IsExactName("Save as type:", "Save As"));
        // With no exact match anywhere, substring matches still
        // decide (the pre-FR-142 behaviour, kept as the fallback).
        var (outcome, _) = MenuDialogResolution.Decide(new[]
        {
            C("Save As...", "MenuItem", invoke: true),
        }, "Save A");
        Assert.Equal(MenuDialogOutcome.Invoke, outcome);
    }

    [Fact]
    public void ActionableMatch_BeatsAnEarlierWindowMatch()
    {
        // Walk order puts the dialog window first (it is the
        // ancestor); the Save BUTTON inside it must still win —
        // "Save" the item is the button's act, not the window's.
        var matches = new[]
        {
            C("Save As", "Window"),
            C("Save", "Button", invoke: true),
        };
        var (outcome, index) = MenuDialogResolution.Decide(matches, "Save");
        Assert.Equal(MenuDialogOutcome.Invoke, outcome);
        Assert.Equal(1, index);
    }

    [Fact]
    public void RealMenuItem_InvokesByName()
    {
        // A non-actionable bystander earlier in walk order is
        // skipped; the real menu item is what gets invoked.
        var (outcome, index) = MenuDialogResolution.Decide(new[]
        {
            C("File", "Text"),
            C("Save As...", "MenuItem", invoke: true),
        }, "Save As");
        Assert.Equal(MenuDialogOutcome.Invoke, outcome);
        Assert.Equal(1, index);
    }

    [Fact]
    public void ExpandableMatch_Expands_PatternlessButton_Clicks()
    {
        var (expandOutcome, _) = MenuDialogResolution.Decide(new[] { C("Recent", "MenuItem", expand: true) }, "Recent");
        Assert.Equal(MenuDialogOutcome.Expand, expandOutcome);
        // A button-class control with no patterns is still a
        // legitimate click target (the F8 glide-click fallback).
        var (clickOutcome, _) = MenuDialogResolution.Decide(new[] { C("OK", "Button") }, "OK");
        Assert.Equal(MenuDialogOutcome.Click, clickOutcome);
    }

    [Fact]
    public void NonActionableOnlyMatch_IsRefusedPlainly()
    {
        // A label or an edit field is not a menu item; the tool
        // must say so instead of centre-clicking a bystander.
        var (outcome, index) = MenuDialogResolution.Decide(new[] { C("Save As", "Text") }, "Save As");
        Assert.Equal(MenuDialogOutcome.RefuseNonActionable, outcome);
        Assert.Equal(0, index);
        var (editOutcome, _) = MenuDialogResolution.Decide(new[] { C("Save As", "Edit") }, "Save As");
        Assert.Equal(MenuDialogOutcome.RefuseNonActionable, editOutcome);
    }

    [Fact]
    public void NoMatches_IsNotFound()
    {
        var (outcome, index) = MenuDialogResolution.Decide(Array.Empty<MenuDialogCandidate>(), "Save As");
        Assert.Equal(MenuDialogOutcome.NotFound, outcome);
        Assert.Equal(-1, index);
    }

    // ---- defect 2: the dialog snapshot policy ----

    [Fact]
    public void CommonDialog_IsTheStandardDialogClassWindow()
    {
        Assert.True(CommonDialogSnapshotPolicy.IsCommonDialogWindow("#32770", "Window"));
        Assert.False(CommonDialogSnapshotPolicy.IsCommonDialogWindow("#32770", "Pane"));
        Assert.False(CommonDialogSnapshotPolicy.IsCommonDialogWindow("Notepad", "Window"));
        Assert.False(CommonDialogSnapshotPolicy.IsCommonDialogWindow(null, null));
    }

    [Fact]
    public void ChildAllowance_IsBreadthFair()
    {
        // Last child takes whatever remains.
        Assert.Equal(500, CommonDialogSnapshotPolicy.ChildSubtreeAllowance(500, 1));
        // An earlier child is capped at half the remainder…
        Assert.Equal(250, CommonDialogSnapshotPolicy.ChildSubtreeAllowance(500, 4));
        // …floored so a small late subtree always fits whole…
        Assert.Equal(CommonDialogSnapshotPolicy.MinChildSubtreeNodes,
            CommonDialogSnapshotPolicy.ChildSubtreeAllowance(40, 3));
        // …never more than remains, and nothing from nothing.
        Assert.Equal(20, CommonDialogSnapshotPolicy.ChildSubtreeAllowance(20, 3));
        Assert.Equal(0, CommonDialogSnapshotPolicy.ChildSubtreeAllowance(0, 3));
    }

    [Fact]
    public void FileNameControl_IsIdentifiedFromDescriptors()
    {
        // By host automation id (the combo host in the dialog)…
        Assert.True(CommonDialogSnapshotPolicy.IsFileNameControl("", "Pane", "FileNameControlHost"));
        // …and as the text-entry control carrying the label.
        Assert.True(CommonDialogSnapshotPolicy.IsFileNameControl("File name:", "Edit", ""));
        Assert.True(CommonDialogSnapshotPolicy.IsFileNameControl("File name:", "ComboBox", ""));
        // Not the type combo, not an unrelated edit.
        Assert.False(CommonDialogSnapshotPolicy.IsFileNameControl("Save as type:", "ComboBox", ""));
        Assert.False(CommonDialogSnapshotPolicy.IsFileNameControl("Search", "Edit", ""));
    }

    [Fact]
    public void FileTypeControl_IsIdentifiedFromDescriptors()
    {
        Assert.True(CommonDialogSnapshotPolicy.IsFileTypeControl("", "Pane", "FileTypeControlHost"));
        Assert.True(CommonDialogSnapshotPolicy.IsFileTypeControl("Save as type:", "ComboBox", ""));
        Assert.True(CommonDialogSnapshotPolicy.IsFileTypeControl("Files of type:", "ComboBox", ""));
        Assert.False(CommonDialogSnapshotPolicy.IsFileTypeControl("File name:", "Edit", ""));
    }

    // ---- the engine + walk shape (source pins) ----

    [Fact]
    public void Engine_ResolvesOverAllCandidates_AndAlreadyOpenClicksNothing()
    {
        var body = MethodBody(Engine(),
            "private async Task<(bool, string)> MenuDialogAsync",
            "private (bool, string) AppLaunch");
        Assert.Contains("FindMenuCandidates", body);
        Assert.Contains("MenuDialogResolution.Decide", body);
        // The first-match lookup that caused the defect is gone
        // from this method.
        Assert.DoesNotContain("FindByText(itemName)", body);
        // The already-open report is returned BEFORE any click
        // can be issued in the method — zero clicks on that path.
        var alreadyOpenAt = body.IndexOf("is already open; nothing was clicked", StringComparison.Ordinal);
        var clickAt = body.IndexOf("InjectClickAtAsync", StringComparison.Ordinal);
        Assert.True(alreadyOpenAt >= 0, "already-open wording not found in MenuDialogAsync");
        Assert.True(clickAt > alreadyOpenAt, "a click call precedes the already-open return in MenuDialogAsync");
    }

    [Fact]
    public void SnapshotWalk_CarriesValues_AndGuaranteesDialogSubtrees()
    {
        var src = Snapshot();
        // Nodes carry their ValuePattern value.
        Assert.Contains("string Value", src);
        Assert.Contains("ValuePattern.Pattern", src);
        // Candidate collection for the resolution exists.
        Assert.Contains("FindMenuCandidates", src);
        // The dialog guarantee is wired into the walk: detection,
        // the reserved budget, the depth allowance, the fair cap.
        Assert.Contains("CommonDialogSnapshotPolicy.IsCommonDialogWindow", src);
        Assert.Contains("CommonDialogSnapshotPolicy.DialogNodeBudget", src);
        Assert.Contains("CommonDialogSnapshotPolicy.DialogDepthAllowance", src);
        Assert.Contains("CommonDialogSnapshotPolicy.ChildSubtreeAllowance", src);
    }
}
