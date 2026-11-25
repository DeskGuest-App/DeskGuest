using System.Text.Json;
using System.Windows.Automation;
using Acp.Shared.Tools;

namespace Acp.SessionAgent;

/// <summary>
/// UI Automation perception (census row 6): a depth- and count-capped
/// tree walk producing snapshot-scoped element refs. Refs live only
/// until the next snapshot; an action against a stale ref fails with a
/// re-snapshot hint, never a guessed click (SPEC §6, agent-desktop
/// lesson). UNPROVEN-ON-WINDOWS until the laptop gate.
/// </summary>
public sealed class UiaSnapshotService
{
    private readonly Dictionary<string, AutomationElement> _refs = new();
    private int _snapshotSeq;

    public string CurrentSnapshotId { get; private set; } = "";

    /// <summary>FR-112 (W65): the first exception swallowed during
    /// the most recent Capture, as "Type: message" — null when the
    /// walk was clean. Before this lane, Walk() caught ONLY
    /// ElementNotAvailableException: any other exception from a
    /// property getter mid-walk (e.g. InvalidOperationException,
    /// the W58 live failure) aborted the WHOLE snapshot and surfaced
    /// upstream as a generic desktop-engine error with the real
    /// exception lost. Now every element-level failure is contained
    /// to that element, recorded here, and ridden out in the
    /// snapshot JSON as uia_diagnostics so the real exception is
    /// captured in the product's own output.</summary>
    public string? LastCaptureError { get; private set; }

    public sealed record Node(
        string Ref, string Name, string ControlType, string AutomationId,
        bool IsEnabled, bool IsPassword, bool IsOffscreen,
        double X, double Y, double W, double H,
        // FR-142 (issue #34): the element's current value
        // (ValuePattern) — an agent verifying a save flow needs the
        // file-name edit's CONTENT in the snapshot, not just its
        // existence. "" when the element exposes no value.
        string Value,
        List<Node> Children);

    public (string SnapshotId, Node Root) Capture(int maxDepth = 6, int maxNodes = 400)
    {
        _refs.Clear();
        LastCaptureError = null;
        var id = $"s{++_snapshotSeq}";
        CurrentSnapshotId = id;
        var budget = new int[] { maxNodes };
        var rootEl = AutomationElement.RootElement;
        var root = Walk(rootEl, id, 0, maxDepth, budget, _refs);
        return (id, root);
    }

    private void NoteError(Exception ex)
    {
        // First failure only — it is the diagnostic of record; later
        // ones are usually the same element class repeating.
        LastCaptureError ??= $"{ex.GetType().Name}: {ex.Message}";
    }

    /// <summary>BD-WIN-AGENT F11: an internal lookup walk over a
    /// SCRATCH ref table. FindByText / InteractiveElements used to
    /// run a full Capture(), which cleared _refs and bumped the
    /// snapshot id — so wait_for, app_switch, ui_menu_dialog and
    /// screenshot_annotated silently invalidated every element ref
    /// the agent already held. Scratch walks never touch the agent's
    /// snapshot state.</summary>
    private Node ScratchWalk(AutomationElement rootEl, Dictionary<string, AutomationElement> scratch, int maxDepth = 6, int maxNodes = 400)
    {
        var budget = new int[] { maxNodes };
        return Walk(rootEl, "scratch", 0, maxDepth, budget, scratch);
    }

    private Node Walk(AutomationElement el, string snapshotId, int depth, int maxDepth, int[] budget, Dictionary<string, AutomationElement> refs, bool inDialog = false)
    {
        var refId = $"{snapshotId}:{refs.Count}";
        refs[refId] = el;
        budget[0]--;

        string name = "", controlType = "", automationId = "", className = "";
        bool enabled = false, isPassword = false, offscreen = true;
        var rect = System.Windows.Rect.Empty;
        try
        {
            var c = el.Current;
            name = c.Name ?? "";
            controlType = c.ControlType?.ProgrammaticName?.Replace("ControlType.", "") ?? "";
            automationId = c.AutomationId ?? "";
            className = c.ClassName ?? "";
            enabled = c.IsEnabled;
            offscreen = c.IsOffscreen;
            rect = c.BoundingRectangle;
            isPassword = el.GetCurrentPropertyValue(AutomationElement.IsPasswordProperty) is true;
        }
        catch (ElementNotAvailableException) { /* element vanished mid-walk; node stands with what we got */ }
        catch (Exception ex) { NoteError(ex); /* FR-112: one element's bad property must not abort the whole snapshot */ }

        // FR-142 (issue #34): the element's value rides the node —
        // best-effort, the node stands without it when unreadable.
        string value = "";
        try
        {
            if (el.TryGetCurrentPattern(ValuePattern.Pattern, out var vp))
                value = ((ValuePattern)vp).Current.Value ?? "";
        }
        catch { /* value is metadata; a bad read must not cost the node */ }

        var node = new Node(refId, name, controlType, automationId, enabled, isPassword, offscreen,
            rect.IsEmpty ? 0 : rect.X, rect.IsEmpty ? 0 : rect.Y, rect.IsEmpty ? 0 : rect.Width, rect.IsEmpty ? 0 : rect.Height,
            value,
            new List<Node>());

        // FR-142 (issue #34): a common file dialog's subtree is
        // guaranteed its own budget and depth (see
        // CommonDialogSnapshotPolicy) — the desktop-wide budget,
        // spent depth-first, starved exactly the file-name
        // controls this policy names. Inside a dialog subtree the
        // budget is spent breadth-fair: while siblings remain, no
        // child subtree (the shell folder view above all) may eat
        // more than its allowance.
        var isDialogRoot = !inDialog && CommonDialogSnapshotPolicy.IsCommonDialogWindow(className, controlType);
        var effInDialog = inDialog || isDialogRoot;
        var effMaxDepth = isDialogRoot ? Math.Max(maxDepth, depth + CommonDialogSnapshotPolicy.DialogDepthAllowance) : maxDepth;
        var childBudget = isDialogRoot ? new int[] { CommonDialogSnapshotPolicy.DialogNodeBudget } : budget;

        if (depth < effMaxDepth && childBudget[0] > 0)
        {
            var children = new List<AutomationElement>();
            try
            {
                var walker = TreeWalker.RawViewWalker;
                var child = walker.GetFirstChild(el);
                while (child is not null)
                {
                    children.Add(child);
                    AutomationElement? next = null;
                    try { next = walker.GetNextSibling(child); }
                    catch (ElementNotAvailableException) { }
                    catch (Exception ex) { NoteError(ex); }
                    child = next;
                }
            }
            catch (ElementNotAvailableException) { }
            catch (Exception ex) { NoteError(ex); }

            for (var i = 0; i < children.Count; i++)
            {
                if (childBudget[0] <= 0) break;
                var current = children[i];
                try
                {
                    if (effInDialog && i < children.Count - 1)
                    {
                        var allowance = CommonDialogSnapshotPolicy.ChildSubtreeAllowance(childBudget[0], children.Count - i);
                        if (allowance <= 0) break;
                        var sub = new int[] { allowance };
                        node.Children.Add(Walk(current, snapshotId, depth + 1, effMaxDepth, sub, refs, effInDialog));
                        childBudget[0] -= allowance - sub[0];
                    }
                    else
                    {
                        node.Children.Add(Walk(current, snapshotId, depth + 1, effMaxDepth, childBudget, refs, effInDialog));
                    }
                }
                catch (ElementNotAvailableException) { }
                catch (Exception ex) { NoteError(ex); /* FR-112: a child subtree failure is contained to that subtree */ }
            }
        }
        return node;
    }

    public AutomationElement? Resolve(string elementRef) =>
        elementRef.StartsWith(CurrentSnapshotId + ":", StringComparison.Ordinal) && _refs.TryGetValue(elementRef, out var el)
            ? el
            : null;

    public string SerializeSnapshot()
    {
        var (id, root) = Capture();
        return JsonSerializer.Serialize(new { snapshot_id = id, root, uia_diagnostics = LastCaptureError }, new JsonSerializerOptions { WriteIndented = true });
    }

    /// <summary>Find the first element (depth-first) whose name
    /// contains text. BD-WIN-AGENT F11: searches the FOREGROUND
    /// window's subtree first (the overwhelmingly common target,
    /// and a far smaller walk), then the full desktop — always in a
    /// scratch table, so the agent's snapshot refs survive.</summary>
    public AutomationElement? FindByText(string text)
    {
        var scratch = new Dictionary<string, AutomationElement>();
        AutomationElement? Search(AutomationElement rootEl)
        {
            scratch.Clear();
            var root = ScratchWalk(rootEl, scratch);
            AutomationElement? found = null;
            void Visit(Node n)
            {
                if (found is not null) return;
                if (n.Name.Contains(text, StringComparison.OrdinalIgnoreCase) && scratch.TryGetValue(n.Ref, out var el))
                {
                    found = el;
                    return;
                }
                foreach (var c in n.Children) Visit(c);
            }
            Visit(root);
            return found;
        }

        try
        {
            var hwnd = NativeMethods.GetForegroundWindow();
            if (hwnd != IntPtr.Zero)
            {
                var fg = AutomationElement.FromHandle(hwnd);
                if (fg is not null && Search(fg) is { } hit) return hit;
            }
        }
        catch { /* foreground unreadable: fall through to the desktop walk */ }
        return Search(AutomationElement.RootElement);
    }

    /// <summary>FR-142 (issue #34): EVERY element whose name
    /// contains text, in FindByText's search order (the foreground
    /// window's subtree first, then the full desktop), each paired
    /// with the pure MenuDialogCandidate describing it.
    /// ui_menu_dialog resolves over all of them: the first-match
    /// rule it replaces returned the Save As dialog WINDOW itself
    /// for the item "Save As", and the engine centre-clicked it.
    /// Scratch walks, like FindByText — the agent's snapshot refs
    /// survive.</summary>
    public IReadOnlyList<(AutomationElement Element, MenuDialogCandidate Candidate)> FindMenuCandidates(string text)
    {
        var result = new List<(AutomationElement Element, MenuDialogCandidate Candidate)>();
        void Collect(AutomationElement rootEl)
        {
            var scratch = new Dictionary<string, AutomationElement>();
            var root = ScratchWalk(rootEl, scratch);
            void Visit(Node n)
            {
                if (n.Name.Contains(text, StringComparison.OrdinalIgnoreCase) && scratch.TryGetValue(n.Ref, out var el))
                    result.Add((el, DescribeCandidate(el, n)));
                foreach (var c in n.Children) Visit(c);
            }
            Visit(root);
        }

        try
        {
            var hwnd = NativeMethods.GetForegroundWindow();
            if (hwnd != IntPtr.Zero)
            {
                var fg = AutomationElement.FromHandle(hwnd);
                if (fg is not null) Collect(fg);
            }
        }
        catch { /* foreground unreadable: fall through to the desktop walk */ }
        if (result.Count == 0)
        {
            try { Collect(AutomationElement.RootElement); }
            catch { /* desktop unreadable: no candidates, the caller reports not-found */ }
        }
        return result;
    }

    private static MenuDialogCandidate DescribeCandidate(AutomationElement el, Node n)
    {
        var invoke = false;
        var expand = false;
        try { invoke = el.TryGetCurrentPattern(InvokePattern.Pattern, out _); } catch { }
        try { expand = el.TryGetCurrentPattern(ExpandCollapsePattern.Pattern, out _); } catch { }
        return new MenuDialogCandidate(n.Name, n.ControlType, invoke, expand);
    }

    /// <summary>Interactive elements with bounds, for annotated screenshots.</summary>
    public IReadOnlyList<(string Label, System.Windows.Rect Rect)> InteractiveElements()
    {
        // BD-WIN-AGENT F11: scratch walk — an annotated screenshot
        // must not invalidate the agent's snapshot refs either.
        var scratch = new Dictionary<string, AutomationElement>();
        var root = ScratchWalk(AutomationElement.RootElement, scratch);
        var list = new List<(string, System.Windows.Rect)>();
        void Visit(Node n)
        {
            var interactive = n.ControlType is "Button" or "Edit" or "CheckBox" or "RadioButton" or "ListItem" or "MenuItem" or "Hyperlink" or "TabItem" or "ComboBox";
            if (interactive && !n.IsOffscreen && n.W > 0 && n.H > 0)
                list.Add(((list.Count + 1).ToString(), new System.Windows.Rect(n.X, n.Y, n.W, n.H)));
            foreach (var c in n.Children) Visit(c);
        }
        Visit(root);
        return list;
    }
}
