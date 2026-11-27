using DeskGuest.Shared.Threading;

namespace DeskGuest.Tests;

/// <summary>
/// FR-138 — an owner-approved clipboard_set died at execution
/// with ThreadStateException: the desktop engine called the WPF
/// (OLE) clipboard from the IPC channel's thread-pool (MTA)
/// threads, and the clipboard demands an STA thread (Tested-AI
/// battery run 5, 2026-11-25: gate_allowed at 09:27:09Z, then
/// the error; the clipboard never changed). The deny branch had
/// always worked, and every earlier write attempt died upstream
/// of execution, so the path looked healthy until the first
/// approved write.
///
/// The dispatcher's behaviour (work runs, results and exceptions
/// travel back, one dedicated thread) is pinned directly here.
/// The apartment state itself is Windows-only, and the engine is
/// Windows-bound, so the engine's routing is pinned by source in
/// the W73 pattern: BOTH clipboard directions run their OLE
/// touch inside the dispatcher, and no other engine code touches
/// the WPF clipboard at all. Execution on a real STA thread is
/// proven live on the laptop (BUILD-LOG, FR-138 entry).
/// </summary>
public class Fr138FixTests
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

    private static string MethodBody(string src, string signatureStart, string nextSignatureStart)
    {
        var start = src.IndexOf(signatureStart, StringComparison.Ordinal);
        Assert.True(start >= 0, signatureStart + " not found");
        var rest = src.Substring(start);
        var end = rest.IndexOf(nextSignatureStart, StringComparison.Ordinal);
        return end > 0 ? rest.Substring(0, end) : rest;
    }

    [Fact]
    public void Dispatcher_RunsTheWork_AndReturnsItsResult()
    {
        Assert.Equal(42, StaDispatcher.Invoke(() => 42));
        Assert.Equal("clip", StaDispatcher.Invoke(() => "clip"));
    }

    [Fact]
    public void Dispatcher_RunsEverything_OnOneDedicatedThread()
    {
        var caller = Environment.CurrentManagedThreadId;
        var first = StaDispatcher.Invoke(() => Environment.CurrentManagedThreadId);
        var second = StaDispatcher.Invoke(() => Environment.CurrentManagedThreadId);
        Assert.Equal(first, second);          // one dedicated thread, reused
        Assert.NotEqual(caller, first);       // never the caller's thread
        Assert.Equal(first, StaDispatcher.DispatcherThreadId);
    }

    [Fact]
    public void Dispatcher_PropagatesExceptions_WithTheirTypeIntact()
    {
        var ex = Assert.Throws<InvalidOperationException>(
            () => StaDispatcher.Invoke<int>(() => throw new InvalidOperationException("ole says no")));
        Assert.Equal("ole says no", ex.Message);
        // A throwing item never kills the thread: the next call runs.
        Assert.Equal(7, StaDispatcher.Invoke(() => 7));
    }

    [Fact]
    public void Dispatcher_SetsSta_OnlyWhereApartmentStateExists()
    {
        var src = SrcFile("DeskGuest.Shared", "Threading", "StaDispatcher.cs");
        Assert.Contains("SetApartmentState(ApartmentState.STA)", src);
        Assert.Contains("OperatingSystem.IsWindows()", src);
    }

    [Fact]
    public void ClipboardGet_RunsItsOleTouch_OnTheStaThread()
    {
        var body = MethodBody(Engine(), "private (bool, string) ClipboardGet()", "private (bool, string) ClipboardSet");
        Assert.Contains("StaDispatcher.Invoke", body);
        Assert.Contains("System.Windows.Clipboard.GetText()", body);
        // The policy gate still runs BEFORE any clipboard touch.
        var gateAt = body.IndexOf("DenyReasonFor", StringComparison.Ordinal);
        var touchAt = body.IndexOf("StaDispatcher.Invoke", StringComparison.Ordinal);
        Assert.True(gateAt >= 0 && touchAt > gateAt, "the clipboard is touched before the policy gate");
    }

    [Fact]
    public void ClipboardSet_RunsItsOleTouch_OnTheStaThread()
    {
        var body = MethodBody(Engine(), "private (bool, string) ClipboardSet", "private async Task<(bool, string)> ShellExecAsync");
        Assert.Contains("StaDispatcher.Invoke", body);
        Assert.Contains("System.Windows.Clipboard.SetText(text)", body);
        // The write gate and the credential-focus refusal still
        // run before the touch.
        var touchAt = body.IndexOf("StaDispatcher.Invoke", StringComparison.Ordinal);
        Assert.True(body.IndexOf("ClipboardGate.CheckWrite", StringComparison.Ordinal) < touchAt);
        Assert.True(body.IndexOf("FocusBlocksTyping", StringComparison.Ordinal) < touchAt);
    }

    [Fact]
    public void NoOtherEngineCode_TouchesTheWpfClipboard()
    {
        // The class audit, pinned: the WPF clipboard may appear
        // ONLY inside the two dispatched clipboard methods
        // (ContainsText + GetText in the read, SetText in the
        // write). Any new direct call site anywhere else in the
        // engine reopens the defect class.
        var engine = Engine();
        var count = 0;
        var idx = 0;
        while ((idx = engine.IndexOf("System.Windows.Clipboard", idx, StringComparison.Ordinal)) >= 0)
        {
            count++;
            idx += 10;
        }
        Assert.Equal(3, count);
    }
}
