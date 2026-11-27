using DeskGuest.Shared.Input;
using DeskGuest.Shared.Presence;

namespace DeskGuest.Tests;

/// <summary>
/// FR-145 — input is never a floor event (owner ruling,
/// 2026-11-25 23:31–23:33 CT, restating the settled 2026-11-25
/// 13:47–14:09 floor design). The defect: ordinary local input
/// — mouse move/click/wheel, keyboard, from any process —
/// yielded driving to the owner for AI agent sessions under
/// TakeOver mode (FR-141 even had physical input yield
/// mid-typing). The owner's ruling: "moving the mouse or
/// remoting in doesn't stop ones control, for AI agents only
/// take control or give control does, that way I can pop in
/// and move my mouse around whenever however and the agent
/// carries on like normal."
///
/// The law these pins hold:
///   * TakeoverStateMachine.LocalInput NEVER yields — every
///     class × every mode returns ObservedCoexist and
///     OwnerDriving stays false, including after chord-yield +
///     hand-back cycles.
///   * TakeoverModes.LocalInputYields is false for every mode.
///   * The chord (Take control) still yields in every mode;
///     hand-back (Give control / gate approval) still returns
///     driving to the agent; STOP is untouched (pinned in W73).
///   * The chord decision keeps its SelfInputWindow coverage:
///     a chord the agent synthesises itself does NOT yield;
///     a physically pressed chord does (LocalSignalGate).
///   * The watcher raises NO ordinary-input yield call; the
///     presence layer's ordinary-input entry points cannot set
///     owner-driving; the settings copy no longer promises
///     touch-to-yield.
///
/// The destruction pass for this fix lives in these pins: the
/// agent's own sustained typing, bridge-injected clicks, wheel
/// pulses, physical-flag hook evidence, a synthesised chord, a
/// physical chord, and the hand-back click's own input are all
/// driven at the machine/gate/classifier level below.
/// </summary>
public class Fr145FixTests
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

    private static string AgentFile(string file) => SrcFile("DeskGuest.SessionAgent", file);

    private static string MethodBody(string src, string signatureStart, string nextSignatureStart)
    {
        var start = src.IndexOf(signatureStart, StringComparison.Ordinal);
        Assert.True(start >= 0, signatureStart + " not found");
        var rest = src.Substring(start);
        var end = rest.IndexOf(nextSignatureStart, StringComparison.Ordinal);
        return end > 0 ? rest.Substring(0, end) : rest;
    }

    private static readonly TakeoverMode[] AllModes =
        { TakeoverMode.TakeOver, TakeoverMode.Share, TakeoverMode.HotkeyOnly };

    // ---------------- the law: LocalInput never yields ----------------

    [Theory]
    [InlineData(TakeoverInputClass.Mouse, TakeoverMode.TakeOver, TakeoverMode.TakeOver)]
    [InlineData(TakeoverInputClass.Mouse, TakeoverMode.TakeOver, TakeoverMode.Share)]
    [InlineData(TakeoverInputClass.Mouse, TakeoverMode.Share, TakeoverMode.HotkeyOnly)]
    [InlineData(TakeoverInputClass.Mouse, TakeoverMode.HotkeyOnly, TakeoverMode.TakeOver)]
    [InlineData(TakeoverInputClass.Keyboard, TakeoverMode.TakeOver, TakeoverMode.TakeOver)]
    [InlineData(TakeoverInputClass.Keyboard, TakeoverMode.HotkeyOnly, TakeoverMode.TakeOver)]
    [InlineData(TakeoverInputClass.Keyboard, TakeoverMode.Share, TakeoverMode.Share)]
    [InlineData(TakeoverInputClass.Keyboard, TakeoverMode.TakeOver, TakeoverMode.HotkeyOnly)]
    public void LocalInput_NeverYields_EveryClassEveryMode(
        TakeoverInputClass cls, TakeoverMode mouseMode, TakeoverMode keyboardMode)
    {
        var m = new TakeoverStateMachine();
        Assert.Equal(TakeoverInputOutcome.ObservedCoexist, m.LocalInput(cls, mouseMode, keyboardMode));
        Assert.False(m.OwnerDriving);
    }

    [Fact]
    public void LocalInputYields_IsFalse_ForEveryMode()
    {
        foreach (var mode in AllModes)
            Assert.False(TakeoverModes.LocalInputYields(mode));
    }

    [Fact]
    public void Destruction_SustainedBarrage_OfBothClasses_NeverYields()
    {
        // The owner's pop-in, worst case: a thousand mixed
        // signals — moves, clicks, wheel, sustained typing —
        // across rotating modes. Not one yields.
        var m = new TakeoverStateMachine();
        for (var i = 0; i < 1000; i++)
        {
            var cls = i % 2 == 0 ? TakeoverInputClass.Mouse : TakeoverInputClass.Keyboard;
            var outcome = m.LocalInput(cls, AllModes[i % 3], AllModes[(i + 1) % 3]);
            Assert.Equal(TakeoverInputOutcome.ObservedCoexist, outcome);
            Assert.False(m.OwnerDriving);
        }
    }

    [Fact]
    public void Destruction_ClassifiedSignals_Exist_ButNeverYield()
    {
        // The classifiers still SEE the input (W107/W111
        // classification is untouched): a stationary click, a
        // wheel pulse and a sub-poll key tap all classify as
        // signals. Fed to the machine, every one coexists.
        var mouseLatch = new LocalInputClassification.MouseButtonLatch();
        Assert.True(LocalInputClassification.IsMouseSignal(
            new LocalInputClassification.MousePoll(
                CursorMoved: false, AnyButtonDown: true,
                AnyButtonPressedSinceLastPoll: false, WheelActivity: false),
            mouseLatch));
        Assert.True(LocalInputClassification.IsMouseSignal(
            new LocalInputClassification.MousePoll(
                CursorMoved: false, AnyButtonDown: false,
                AnyButtonPressedSinceLastPoll: false, WheelActivity: true),
            mouseLatch));
        var keyLatch = new LocalInputClassification.KeyboardLatch();
        Assert.True(LocalInputClassification.IsKeyboardSignal(
            new LocalInputClassification.KeyboardPoll(
                AnyKeyDown: false, AnyKeyPressedSinceLastPoll: true),
            keyLatch));

        var m = new TakeoverStateMachine();
        Assert.Equal(TakeoverInputOutcome.ObservedCoexist,
            m.LocalInput(TakeoverInputClass.Mouse, TakeoverMode.TakeOver, TakeoverMode.TakeOver));
        Assert.Equal(TakeoverInputOutcome.ObservedCoexist,
            m.LocalInput(TakeoverInputClass.Keyboard, TakeoverMode.TakeOver, TakeoverMode.TakeOver));
        Assert.False(m.OwnerDriving);
    }

    // ---------------- explicit Take / Give still works ----------------

    [Fact]
    public void Chord_StillYields_InEveryModeContext()
    {
        foreach (var mode in AllModes)
        {
            var m = new TakeoverStateMachine();
            // Ordinary input in this mode first: coexists.
            Assert.Equal(TakeoverInputOutcome.ObservedCoexist,
                m.LocalInput(TakeoverInputClass.Mouse, mode, mode));
            // The deliberate chord: yields.
            Assert.True(m.TakeoverHotkey());
            Assert.True(m.OwnerDriving);
            // While the owner drives, ordinary input reports
            // AlreadyOwnerDriving and changes nothing.
            Assert.Equal(TakeoverInputOutcome.AlreadyOwnerDriving,
                m.LocalInput(TakeoverInputClass.Keyboard, mode, mode));
            Assert.True(m.OwnerDriving);
        }
    }

    [Fact]
    public void HandBack_StillReturnsDriving_ToTheAgent()
    {
        var m = new TakeoverStateMachine();
        Assert.True(m.TakeoverHotkey());
        Assert.True(m.HandBack());
        Assert.False(m.OwnerDriving);
        Assert.False(m.HandBack()); // idempotent-safe, as before
    }

    [Fact]
    public void Destruction_ChordHandBackCycles_InputNeverReYields()
    {
        // Chord-yield → hand-back → input barrage, repeatedly:
        // after every hand-back the agent drives, and no amount
        // of ordinary input re-yields — including the hand-back
        // click's OWN input landing inside the FR-120 grace
        // window (with ordinary input dead, no path re-yields).
        var m = new TakeoverStateMachine();
        for (var cycle = 0; cycle < 5; cycle++)
        {
            Assert.True(m.TakeoverHotkey());
            Assert.True(m.OwnerDriving);
            Assert.True(m.HandBack());
            Assert.False(m.OwnerDriving);
            for (var i = 0; i < 50; i++)
            {
                var cls = i % 2 == 0 ? TakeoverInputClass.Mouse : TakeoverInputClass.Keyboard;
                Assert.Equal(TakeoverInputOutcome.ObservedCoexist,
                    m.LocalInput(cls, TakeoverMode.TakeOver, TakeoverMode.TakeOver));
                Assert.False(m.OwnerDriving);
            }
        }
    }

    [Fact]
    public void Destruction_SessionBoundary_StillClearsAChordYield_StaleFlag()
    {
        // FR-130 interplay: a chord yield in session A must not
        // latch session B — reconciliation still clears it.
        var m = new TakeoverStateMachine();
        Assert.True(m.TakeoverHotkey());
        Assert.True(m.OwnerDriving);
        Assert.True(m.ReconcileAtSessionBoundary());
        Assert.False(m.OwnerDriving);
        Assert.False(m.ReconcileAtSessionBoundary()); // clean machine: no clear
    }

    // ---------------- the chord gate: self-synthesised vs physical ----------------

    [Fact]
    public void Destruction_AgentSynthesisedChord_DoesNotYield()
    {
        // The agent's own injection window covers the evidence:
        // a chord the agent synthesised (e.g. while driving a
        // type_text that happens to include the chord keys) must
        // NOT take control from itself.
        var w = new SelfInputWindow(TimeSpan.FromMilliseconds(350));
        var t0 = DateTime.UtcNow;
        using (w.BeginOperation())
        {
            Assert.True(w.Covers(t0.AddHours(1))); // operation scope, not timing
            Assert.False(LocalSignalGate.ShouldYield(
                physicalPending: false, signalObserved: true, selfCovered: w.Covers(t0)));
        }
        // The note tail covers the same way.
        w.Note(t0);
        Assert.False(LocalSignalGate.ShouldYield(
            physicalPending: false, signalObserved: true, selfCovered: w.Covers(t0)));
    }

    [Fact]
    public void Destruction_PhysicalChord_Yields_EvenMidOperation()
    {
        // The complementary half: physical (non-injected) chord
        // evidence is never suppressed — a real hand on the
        // chord takes control even while the agent is mid-
        // operation inside its own injection window.
        Assert.True(LocalSignalGate.ShouldYield(
            physicalPending: true, signalObserved: true, selfCovered: true));
        Assert.True(LocalSignalGate.ShouldYield(
            physicalPending: true, signalObserved: false, selfCovered: true));
    }

    [Fact]
    public void BridgeInjectedChord_Yields_AsBefore()
    {
        // Named behaviour, unchanged from FR-141: a chord
        // injected by ANOTHER process (the bridge) sets neither
        // the physical flag nor the self-coverage flag, so the
        // gate passes it — only the AGENT's OWN synthesised
        // chord is refused (the pin above).
        Assert.True(LocalSignalGate.ShouldYield(
            physicalPending: false, signalObserved: true, selfCovered: false));
    }

    // ---------------- source pins: no ordinary-input yield path ships ----------------

    [Fact]
    public void Watcher_ContainsNoOrdinaryInputYieldCall()
    {
        var watcher = AgentFile("LocalInputWatcher.cs");
        // The ordinary-input yield calls are GONE from PollOnce.
        Assert.DoesNotContain("SetOwnerDriving(true)", watcher);
        Assert.DoesNotContain("SetOwnerDrivingFromKeyboard(true)", watcher);
        // The one signal the watcher still raises is the chord.
        Assert.Contains("_presence.TakeoverHotkeyPressed();", watcher);
        // …decided through the gate exactly once (the chord).
        var decisions = watcher.Split(new[] { "LocalSignalGate.ShouldYield(" }, StringSplitOptions.None).Length - 1;
        Assert.Equal(1, decisions);
        // The classifiers still run (evidence is consumed and
        // baselined, never replayed).
        Assert.Contains("LocalInputClassification.IsMouseSignal", watcher);
        Assert.Contains("LocalInputClassification.IsKeyboardSignal", watcher);
    }

    [Fact]
    public void Presence_OrdinaryInputEntryPoints_CannotSetOwnerDriving()
    {
        var presence = AgentFile("Presence.cs");
        var mouse = MethodBody(presence,
            "public void SetOwnerDriving(bool driving)", "public void SetOwnerDrivingFromKeyboard");
        Assert.DoesNotContain("_ownerDriving = true", mouse);
        Assert.DoesNotContain("TakeoverYielded", mouse);
        Assert.DoesNotContain("TakeoverDetected", mouse);
        // The hand-back direction still routes through.
        Assert.Contains("HandBackToAgent(TakeoverActors.OwnerHandBackControl)", mouse);

        var keyboard = MethodBody(presence,
            "public void SetOwnerDrivingFromKeyboard(bool driving)", "public void TakeoverHotkeyPressed");
        Assert.DoesNotContain("_ownerDriving = true", keyboard);
        Assert.DoesNotContain("TakeoverYielded", keyboard);
        Assert.Contains("HandBackToAgent(TakeoverActors.OwnerHandBackControl)", keyboard);

        // The chord path is the one input-path yield left: it
        // sets owner-driving and raises the yield events.
        var chord = MethodBody(presence,
            "public void TakeoverHotkeyPressed()", "public void HandBackToAgent");
        Assert.Contains("_ownerDriving = true", chord);
        Assert.Contains("TakeoverHotkeyYielded", chord);
        // …and it is NOT behind the hand-back grace window (a
        // deliberate chord inside the window is a fresh take).
        Assert.DoesNotContain("YieldSuppressed", chord);
    }

    [Fact]
    public void StateMachineSource_LocalInputHasNoYieldBranch()
    {
        var control = SrcFile("DeskGuest.Shared", "Presence", "TakeoverControl.cs");
        var local = MethodBody(control,
            "public TakeoverInputOutcome LocalInput(", "public bool TakeoverHotkey()");
        Assert.DoesNotContain("OwnerDriving = true", local);
        Assert.Contains("ObservedCoexist", local);
        var chord = MethodBody(control,
            "public bool TakeoverHotkey()", "public bool HandBack()");
        Assert.Contains("OwnerDriving = true", chord);
    }

    [Fact]
    public void SettingsCopy_NoLongerPromisesTouchToYield()
    {
        var strings = AgentFile("Strings.cs");
        var resx = AgentFile("Strings.resx");
        foreach (var surface in new[] { strings, resx })
        {
            Assert.DoesNotContain("Touch it and you are driving", surface);
            // Every mode sentence now names the chord as the
            // take path (the HotkeyOnly sentence already did).
            Assert.Contains("Ctrl + Alt + Shift + Backspace", surface);
        }
        // The TakeOver sentence says the new law in plain words.
        Assert.Contains("never interrupts your AI", strings);
        Assert.Contains("never interrupts your AI", resx);
        // The group intro no longer frames touching as taking.
        Assert.Contains("never takes over", strings);
        Assert.Contains("never takes over", resx);
        // The policy page row: no more "takes over instantly".
        var pages = AgentFile("MainWindow.Pages.cs");
        Assert.DoesNotContain("takes over instantly", pages);
        Assert.DoesNotContain("touch-to-yield", pages);
        Assert.Contains("never interrupts the agent", pages);
    }

    [Fact]
    public void Presence_HandBack_GraceWindow_StillRecorded_AndChordExempt()
    {
        // FR-120's grace window survives as belt-and-braces on
        // the (now non-yielding) ordinary-input paths; the
        // destruction property is pinned at the machine level
        // by Destruction_ChordHandBackCycles_InputNeverReYields:
        // nothing the hand-back click itself does can re-yield.
        var presence = AgentFile("Presence.cs");
        var handBack = MethodBody(presence,
            "public void HandBackToAgent(string actor)", "public void ApplyFleetDefaults");
        Assert.Contains("_yieldSuppressedUntilUtc = DateTime.UtcNow.AddMilliseconds(1500)", handBack);
        Assert.Contains("TakeoverHandedBack", handBack);
    }
}
