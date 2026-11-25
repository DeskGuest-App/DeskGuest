namespace Acp.Tests;

/// <summary>
/// FR-136 — coordinate clicks landed at the REAL cursor instead of
/// the requested point. The click path glided only the ghost
/// (the presence overlay) and then sent the button event, which
/// the OS delivers at the real cursor's position; the real cursor
/// was never positioned. Observed worst case (2026-11-25): a click
/// aimed at a sidebar item fired on the presence pill's STOP
/// button, where a previous click had left the cursor, and
/// engaged the kill switch.
///
/// The engine is Windows-bound (SendInput/SetCursorPos), so these
/// are source pins in the W73 pattern: the click/move/drag/
/// multi-select paths must position the real cursor at the target
/// BEFORE the button event, the positioning must be bracketed in
/// the self-input window, and every raw SendInput in the engine
/// must funnel through the one noted wrapper.
/// </summary>
public class Fr136FixTests
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

    private static string Engine() => SrcFile("Acp.SessionAgent", "DesktopEngine.cs");

    private static string MethodBody(string src, string signatureStart, string nextSignatureStart)
    {
        var start = src.IndexOf(signatureStart, StringComparison.Ordinal);
        Assert.True(start >= 0, signatureStart + " not found");
        var rest = src.Substring(start);
        var end = rest.IndexOf(nextSignatureStart, StringComparison.Ordinal);
        return end > 0 ? rest.Substring(0, end) : rest;
    }

    [Fact]
    public void ClickPath_PositionsTheRealCursorBeforeTheButton()
    {
        var body = MethodBody(Engine(), "private async Task InjectClickAtAsync", "// ---------- Perception");
        var positionAt = body.IndexOf("PositionCursor(x, y)", StringComparison.Ordinal);
        var buttonAt = body.IndexOf("MouseButton(button, down: true)", StringComparison.Ordinal);
        Assert.True(positionAt >= 0, "InjectClickAtAsync never positions the real cursor");
        Assert.True(buttonAt > positionAt, "the button fires before the cursor is positioned");
    }

    [Fact]
    public void MouseMove_PositionsTheRealCursor()
    {
        var body = MethodBody(Engine(), "private async Task<(bool, string)> MouseMoveAsync", "private async Task<(bool, string)> DragAsync");
        Assert.Contains("PositionCursor(x, y)", body);
    }

    [Fact]
    public void Drag_PositionsAtTheStart_AndTravelsWithTheDrag()
    {
        var body = MethodBody(Engine(), "private async Task<(bool, string)> DragAsync", "private async Task<(bool, string)> MultiSelectAsync");
        Assert.Contains("PositionCursor(x1, y1)", body);
        // The stepped travel toward the drop point while held.
        Assert.Contains("(x2 - x1) * i / steps", body);
        var downAt = body.IndexOf("MouseButton(\"left\", true)", StringComparison.Ordinal);
        var startAt = body.IndexOf("PositionCursor(x1, y1)", StringComparison.Ordinal);
        Assert.True(startAt >= 0 && downAt > startAt, "the drag presses down before the cursor is at the start point");
    }

    [Fact]
    public void MultiSelect_PositionsAtEachPoint()
    {
        var body = MethodBody(Engine(), "private async Task<(bool, string)> MultiSelectAsync", "private async Task<(bool, string)> MultiEditAsync");
        Assert.Contains("PositionCursor(px, py)", body);
    }

    [Fact]
    public void PositionCursor_IsBracketedInTheSelfInputWindow()
    {
        var body = MethodBody(Engine(), "private static void PositionCursor", "/// <summary>FR-130: every raw SendInput");
        Assert.Contains("SelfInputWindow.Shared.Note", body);
        Assert.Contains("NativeMethods.SetCursorPos(x, y)", body);
    }

    [Fact]
    public void EveryRawSendInput_FunnelsThroughTheNotedWrapper()
    {
        var engine = Engine();
        // Exactly one direct SendInput call site may exist in the
        // engine: inside SendInputNoted itself. Any other direct
        // call is an injection the watcher cannot tell from
        // outside input (FR-130 defect 3).
        var count = 0;
        var idx = 0;
        while ((idx = engine.IndexOf("NativeMethods.SendInput(", idx, StringComparison.Ordinal)) >= 0)
        {
            count++;
            idx += 10;
        }
        Assert.Equal(1, count);
        var wrapper = MethodBody(engine, "private static void SendInputNoted", "private static string CapturePngBase64");
        Assert.Contains("NativeMethods.SendInput(", wrapper);
        Assert.Contains("SelfInputWindow.Shared.Note", wrapper);
    }
}
