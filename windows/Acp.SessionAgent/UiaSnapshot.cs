using System.Text.Json;
using System.Windows.Automation;

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

    private Node Walk(AutomationElement el, string snapshotId, int depth, int maxDepth, int[] budget, Dictionary<string, AutomationElement> refs)
    {
        var refId = $"{snapshotId}:{refs.Count}";
        refs[refId] = el;
        budget[0]--;

        string name = "", controlType = "", automationId = "";
        bool enabled = false, isPassword = false, offscreen = true;
        var rect = System.Windows.Rect.Empty;
        try
        {
            var c = el.Current;
            name = c.Name ?? "";
            controlType = c.ControlType?.ProgrammaticName?.Replace("ControlType.", "") ?? "";
            automationId = c.AutomationId ?? "";
            enabled = c.IsEnabled;
            offscreen = c.IsOffscreen;
            rect = c.BoundingRectangle;
            isPassword = el.GetCurrentPropertyValue(AutomationElement.IsPasswordProperty) is true;
        }
        catch (ElementNotAvailableException) { /* element vanished mid-walk; node stands with what we got */ }
        catch (Exception ex) { NoteError(ex); /* FR-112: one element's bad property must not abort the whole snapshot */ }

        var node = new Node(refId, name, controlType, automationId, enabled, isPassword, offscreen,
            rect.IsEmpty ? 0 : rect.X, rect.IsEmpty ? 0 : rect.Y, rect.IsEmpty ? 0 : rect.Width, rect.IsEmpty ? 0 : rect.Height,
            new List<Node>());

        if (depth < maxDepth && budget[0] > 0)
        {
            try
            {
                var walker = TreeWalker.RawViewWalker;
                var child = walker.GetFirstChild(el);
                while (child is not null && budget[0] > 0)
                {
                    AutomationElement current = child;
                    AutomationElement? next = null;
                    try { next = walker.GetNextSibling(current); }
                    catch (ElementNotAvailableException) { }
                    catch (Exception ex) { NoteError(ex); }
                    try { node.Children.Add(Walk(current, snapshotId, depth + 1, maxDepth, budget, refs)); }
                    catch (ElementNotAvailableException) { }
                    catch (Exception ex) { NoteError(ex); /* FR-112: a child subtree failure is contained to that subtree */ }
                    child = next;
                }
            }
            catch (ElementNotAvailableException) { }
            catch (Exception ex) { NoteError(ex); }
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
