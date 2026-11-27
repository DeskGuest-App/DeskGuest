using DeskGuest.Shared.Input;
using DeskGuest.Shared.Presence;

namespace DeskGuest.Tests;

/// <summary>
/// FR-141 — the takeover watcher yielded driving to the agent's
/// OWN sustained typing (Tested-AI battery run 6, 2026-11-25:
/// four audit instances of "local keyboard input yielded
/// driving to the owner" while the only keyboard input in
/// flight was the session agent's paced type_text; reproduced
/// by this lane at will — flips 5.5 s, 18.4 s, 19.7 s and
/// 22.4 s into continuous types, and again with a single agent
/// process, so duplicate agents were ruled out by experiment).
///
/// The FR-130 distinction rested on a 350 ms note tail: any
/// stall in the send path longer than the tail opened a gap the
/// agent's own key evidence waited on the other side of. The
/// fix has two halves that must hold together:
///   * OPERATION scope — the engine brackets each whole
///     injection operation in the SelfInputWindow; while one is
///     open, coverage does not depend on note timing at all.
///   * PHYSICAL evidence — the watcher's low-level hooks now
///     observe the injected flag directly, so genuine owner
///     input (a real keystroke, a real mouse act) is never
///     suppressed, even mid-operation: fixing the false flips
///     must not weaken real take-over. Input injected by OTHER
///     processes (the bridge) sets neither half and classifies
///     exactly as before.
///
/// The window semantics and the gate's truth table are pure
/// (DeskGuest.Shared) and pinned directly. The hook and the engine
/// brackets are Windows-bound; their shape is pinned by source,
/// in the W73 pattern. The live behaviour — a sustained type
/// with zero false flips, and owner-class input still yielding
/// — is proven on the laptop (BUILD-LOG, FR-141 entry).
///
/// FR-145 AMENDMENT (owner ruling, 2026-11-25 23:31–23:33 CT):
/// ordinary input never yields at all now, so the false-flip
/// defect class this file fixed is abolished at the root. The
/// window + gate machinery survives for ONE decision: the
/// takeover chord must not be triggerable by the agent's own
/// injected input. The truth-table pins below stand unchanged
/// (the gate's semantics did not move); the watcher source pin
/// is rewritten to the narrowed call-site set, annotated in
/// place. The physical-evidence pins also stand: physical
/// evidence is what lets a physically pressed chord yield
/// even mid-operation.
/// </summary>
public class Fr141FixTests
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
    private static string Watcher() => SrcFile("DeskGuest.SessionAgent", "LocalInputWatcher.cs");

    private static string MethodBody(string src, string signatureStart, string nextSignatureStart)
    {
        var start = src.IndexOf(signatureStart, StringComparison.Ordinal);
        Assert.True(start >= 0, signatureStart + " not found");
        var rest = src.Substring(start);
        var end = rest.IndexOf(nextSignatureStart, StringComparison.Ordinal);
        return end > 0 ? rest.Substring(0, end) : rest;
    }

    // ---- the operation scope ----

    [Fact]
    public void Operation_CoversRegardlessOfNoteTiming()
    {
        var w = new SelfInputWindow(TimeSpan.FromMilliseconds(350));
        var t0 = DateTime.UtcNow;
        Assert.False(w.Covers(t0)); // no note, no operation
        using (w.BeginOperation())
        {
            Assert.True(w.OperationActive);
            // An hour from any note, the bracket still covers:
            // coverage inside an operation is not a timing fact.
            Assert.True(w.Covers(t0.AddHours(1)));
        }
        Assert.False(w.OperationActive);
        Assert.False(w.Covers(t0.AddHours(1)));
    }

    [Fact]
    public void Operations_Nest_AndCloseWithTheOutermost()
    {
        var w = new SelfInputWindow(TimeSpan.FromMilliseconds(350));
        var outer = w.BeginOperation();
        var inner = w.BeginOperation();
        inner.Dispose();
        Assert.True(w.OperationActive); // the outer bracket still holds
        Assert.True(w.Covers(DateTime.UtcNow.AddMinutes(5)));
        outer.Dispose();
        Assert.False(w.OperationActive);
    }

    [Fact]
    public void OperationScope_DoubleDisposeDoesNotOverDecrement()
    {
        var w = new SelfInputWindow(TimeSpan.FromMilliseconds(350));
        var first = w.BeginOperation();
        first.Dispose();
        first.Dispose(); // idempotent: must not eat a later operation
        Assert.False(w.OperationActive);
        using (w.BeginOperation())
            Assert.True(w.OperationActive);
        Assert.False(w.OperationActive);
    }

    [Fact]
    public void AfterAnOperation_TheTailRulesAgain()
    {
        var w = new SelfInputWindow(TimeSpan.FromMilliseconds(350));
        var t0 = DateTime.UtcNow;
        w.Note(t0);
        using (w.BeginOperation()) { }
        Assert.True(w.Covers(t0.AddMilliseconds(100)));  // inside the note's tail
        Assert.False(w.Covers(t0.AddMilliseconds(400))); // past it, operation closed
    }

    // ---- the gate's truth table ----

    [Fact]
    public void Gate_PhysicalInputIsNeverSuppressed()
    {
        // A genuine owner keystroke/mouse act yields on its own
        // evidence — covered or not, signal latch or not.
        // (FR-145: the yield this evidence feeds is now only the
        // chord decision; the gate's truth table is unchanged.)
        Assert.True(LocalSignalGate.ShouldYield(physicalPending: true, signalObserved: false, selfCovered: true));
        Assert.True(LocalSignalGate.ShouldYield(physicalPending: true, signalObserved: true, selfCovered: true));
        Assert.True(LocalSignalGate.ShouldYield(physicalPending: true, signalObserved: false, selfCovered: false));
    }

    [Fact]
    public void Gate_ClassifiedEvidenceYieldsUnlessSelfCovered()
    {
        Assert.True(LocalSignalGate.ShouldYield(physicalPending: false, signalObserved: true, selfCovered: false));
        Assert.False(LocalSignalGate.ShouldYield(physicalPending: false, signalObserved: true, selfCovered: true));
        Assert.False(LocalSignalGate.ShouldYield(physicalPending: false, signalObserved: false, selfCovered: false));
        Assert.False(LocalSignalGate.ShouldYield(physicalPending: false, signalObserved: false, selfCovered: true));
    }

    // ---- the engine + watcher shape (source pins) ----

    [Fact]
    public void Engine_BracketsItsInjectionOperations()
    {
        var engine = Engine();
        // type_text above all (the defect's own path), plus the
        // other sustained/holding operations.
        var typeBody = MethodBody(engine, "private async Task<(bool, string)> TypeTextAsync", "/// <summary>FR-139: one planned typing event");
        Assert.Contains("SelfInputWindow.Shared.BeginOperation()", typeBody);
        Assert.Contains("SelfInputWindow.Shared.BeginOperation()",
            MethodBody(engine, "private async Task InjectClickAtAsync", "/// <summary>FR-136: place the REAL cursor"));
        Assert.Contains("SelfInputWindow.Shared.BeginOperation()",
            MethodBody(engine, "private (bool, string) KeyPress", "private (bool, string) Scroll"));
        // At least the six bracketed operations exist.
        var count = engine.Split(new[] { "SelfInputWindow.Shared.BeginOperation()" }, StringSplitOptions.None).Length - 1;
        Assert.True(count >= 6, $"expected at least 6 BeginOperation brackets in the engine, found {count}");
    }

    [Fact]
    public void Watcher_ObservesPhysicalInputThroughTheHooks()
    {
        var watcher = Watcher();
        Assert.Contains("NativeMethods.WH_KEYBOARD_LL", watcher);
        Assert.Contains("NativeMethods.LLKHF_INJECTED", watcher);
        Assert.Contains("NativeMethods.LLMHF_INJECTED", watcher);
        Assert.Contains("_physKeyPending", watcher);
        Assert.Contains("_physMousePending", watcher);
    }

    [Fact]
    public void Watcher_DecidesThroughTheGate_WithDecisionTimeCoverage()
    {
        var watcher = Watcher();
        // Coverage is sampled into selfCovered at decision time
        // (after the state sample), and the decision goes through
        // the one gate.
        Assert.Contains("var selfCovered = SelfInputWindow.Shared.Covers(DateTime.UtcNow);", watcher);
        // FR-145 rewrite: the FR-141-era pin expected the gate at
        // THREE decisions (chord, keyboard, mouse). Under the new
        // law ordinary keyboard/mouse signals are never raised,
        // so exactly ONE gate decision remains — the chord — and
        // the ordinary-input yield calls are gone from the
        // watcher entirely.
        var decisions = watcher.Split(new[] { "LocalSignalGate.ShouldYield(" }, StringSplitOptions.None).Length - 1;
        Assert.Equal(1, decisions);
        Assert.DoesNotContain("SetOwnerDriving(true)", watcher);
        Assert.DoesNotContain("SetOwnerDrivingFromKeyboard(true)", watcher);
        Assert.Contains("_presence.TakeoverHotkeyPressed();", watcher);
    }
}
