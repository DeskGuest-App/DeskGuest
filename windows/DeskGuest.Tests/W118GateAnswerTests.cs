using DeskGuest.Shared.Design;
using DeskGuest.Shared.Ipc;
using DeskGuest.Shared.Presence;

namespace DeskGuest.Tests;

/// <summary>
/// W118 — gate-answer vs yield, from W115's live evidence: one
/// click dead-centre on Approve during a live session produced
/// the FR-120 touch-to-yield but NO gate answer; the gate failed
/// closed on timeout. Mechanism (traced in GateSheet.cs /
/// LocalInputWatcher.cs / DesignLaw.cs): the click was the FIRST
/// input ever delivered to that GateSheet window, so at press
/// time _humanActivated was false and every exit was DISABLED
/// (OI-13). The press's tunnel phase latched the activation —
/// and that is all it could do: a press on a disabled WPF button
/// captures nothing, so its release raises no Click, and the
/// 50 ms arm timer enabled the exits into a press that no longer
/// existed. The yield fired in parallel through the watcher's
/// independent path. The gate was unanswerable by a single
/// click — in EVERY takeover mode (the yield was a bystander;
/// SHARE and HOTKEY ONLY lose the same click to the same latch).
///
/// The fix has TWO layers, both live-proven necessary on the
/// W118 lane itself:
///  (1) GateSheetModel.ArmsOnActivation + GateSheet.Activate:
///      the activation event completes arming SYNCHRONOUSLY in
///      its tunnel phase when the 600 ms delay already elapsed.
///  (2) GateSheetModel.WindowPressAnswers + the sheet's
///      pending-press record: layer (1) alone FAILED live
///      (W118 gate 1: single Approve click at T+25 s on the
///      armed-by-its-own-press card still produced
///      gate_no_answer) — a press on a still-DISABLED exit is
///      routed by WPF to the element beneath it, so the exit
///      never captures its own press even once enabled
///      mid-event. The window therefore completes the press
///      itself: press on an exit this press just armed +
///      release on the SAME exit = that exit's click, through
///      the same Decide path as the button's own Click.
///      (W118 gate 2 confirmed the routing model live: a body
///      click armed the card, and the following Deny click —
///      on an exit enabled at press start — answered
///      gate_denied through WPF's own path.)
/// One act, both effects. OI-13 is untouched: a press inside
/// the 600 ms delay still cannot answer.
///
/// FR-145 AMENDMENT (owner ruling, 2026-11-25 23:31–23:33 CT):
/// the yield half of the W115 sequence no longer exists —
/// ordinary local input (including a gate-answer click) never
/// yields, in any mode. The pins below that asserted the
/// click's yield are rewritten to the new law (the click
/// answers; the machine coexists), annotated in place. The
/// gate-answer half — this file's actual subject — is
/// unchanged: one click must still answer the gate.
///
/// The sequence simulations below run the REAL models
/// (GateSheetModel, GatePromptLifecycle, TakeoverStateMachine)
/// under the WPF press contract as live-established: an exit's
/// own capture happens only when it was enabled at PRESS
/// START; the window-press path covers exactly the
/// disabled-at-start + armed-by-this-press case.
/// </summary>
public class W118GateAnswerTests
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
        throw new FileNotFoundException(string.Join("/", parts));
    }

    // ---------- the sequence model (W115 replayed) ----------

    private sealed class GateSim
    {
        public bool HumanActivated;
        public bool ExitsEnabled;
        public bool Decided;
        public string? Answer;
        private readonly long _shownAtMs;
        private readonly DateTimeOffset _expiresUtc;

        public GateSim(long shownAtMs, DateTimeOffset expiresUtc)
        {
            _shownAtMs = shownAtMs;
            _expiresUtc = expiresUtc;
        }

        private bool Live(long nowMs) =>
            !GatePromptLifecycle.ShouldDismiss(GatePromptLifecycle.Evaluate(
                DateTimeOffset.UnixEpoch.AddMilliseconds(nowMs), _expiresUtc,
                sessionLive: true, Decided));

        private void TryArm(long nowMs)
        {
            if (Live(nowMs) && GateSheetModel.ControlsArmed(_shownAtMs, nowMs, HumanActivated))
                ExitsEnabled = true;
        }

        /// <summary>One press+release on Approve at pressAtMs.
        /// layer: 0 = pre-W118 (activation only latches; the
        /// 50 ms timer arms after the press is gone);
        /// 1 = synchronous arm only (W118 first build — FAILED
        /// live at gate 1: the press on the disabled-at-start
        /// exit is routed beneath it and never captures);
        /// 2 = the shipped fix (sync arm + the window completes
        /// the press on a same-exit release).</summary>
        public void ClickApprove(long pressAtMs, int layer) =>
            Press(pressAtMs, layer, pressOnExit: true, releaseOnSameExit: true);

        /// <summary>A press at pressAtMs with explicit geometry:
        /// whether it starts on the Approve exit and whether the
        /// release lands on that same exit.</summary>
        public void Press(long pressAtMs, int layer, bool pressOnExit, bool releaseOnSameExit)
        {
            var enabledAtPressStart = ExitsEnabled;
            // Tunnel phase: Window.PreviewMouseDown.
            HumanActivated = true;
            if (layer >= 1 && GateSheetModel.ArmsOnActivation(_shownAtMs, pressAtMs))
                TryArm(pressAtMs);
            var armedByThisPress = !enabledAtPressStart && ExitsEnabled;
            // The exit's OWN capture: only when it was enabled
            // at press start (the live-established contract).
            var captured = enabledAtPressStart && pressOnExit;
            // The arm timer's next tick (+50 ms) — arms for the
            // NEXT press; it never retrofits this one.
            TryArm(pressAtMs + 50);
            // Release: the button's Click (captured path) or the
            // window's completion (layer 2), both through the
            // same Decide evaluation.
            var windowAnswers = layer >= 2 && GateSheetModel.WindowPressAnswers(
                enabledAtPressStart, armedByThisPress, pressOnExit, releaseOnSameExit);
            if ((captured && releaseOnSameExit || windowAnswers)
                && Live(pressAtMs)
                && GateSheetModel.ControlsArmed(_shownAtMs, pressAtMs, HumanActivated))
            {
                Decided = true;
                Answer = "Approved";
            }
        }
    }

    private static readonly DateTimeOffset Expiry30s = DateTimeOffset.UnixEpoch.AddSeconds(30);

    // ---------- the W115 sequence, TAKE OVER ----------

    [Fact]
    public void W115Sequence_PreFix_FirstClickAnswersNothing_AndUnderFr145NeverYielded()
    {
        var sim = new GateSim(shownAtMs: 0, Expiry30s);
        var machine = new TakeoverStateMachine();
        sim.ClickApprove(pressAtMs: 20_000, layer: 0);
        var outcome = machine.LocalInput(TakeoverInputClass.Mouse,
            TakeoverMode.TakeOver, TakeoverMode.TakeOver);
        // FR-145 rewrite: the FR-120-era pin asserted this click
        // YIELDED (W115's owner-driving capture). Under the new
        // law the same click coexists — input is never a floor
        // event — so the only half of the W115 defect that can
        // still occur is the lost answer…
        Assert.Equal(TakeoverInputOutcome.ObservedCoexist, outcome);
        Assert.False(machine.OwnerDriving);
        // …and pre-fix, no answer was recorded (gate_no_answer).
        Assert.Null(sim.Answer);
        Assert.False(sim.Decided);
    }

    [Fact]
    public void W115Sequence_Fixed_OneClickAnswers_AndCoexistsUnderFr145()
    {
        var sim = new GateSim(shownAtMs: 0, Expiry30s);
        var machine = new TakeoverStateMachine();
        sim.ClickApprove(pressAtMs: 20_000, layer: 2);
        var outcome = machine.LocalInput(TakeoverInputClass.Mouse,
            TakeoverMode.TakeOver, TakeoverMode.TakeOver);
        Assert.Equal("Approved", sim.Answer);
        Assert.True(sim.Decided);
        // FR-145: the answering click does not take the floor —
        // the agent keeps driving (the FR-120-era pin asserted
        // Yielded + OwnerDriving here).
        Assert.Equal(TakeoverInputOutcome.ObservedCoexist, outcome);
        Assert.False(machine.OwnerDriving);
    }

    // ---------- the other modes: the answer simply lands ----------

    [Theory]
    [InlineData(TakeoverMode.Share)]
    [InlineData(TakeoverMode.HotkeyOnly)]
    public void Fixed_ShareAndHotkeyOnly_AnswerLands_NoYield(TakeoverMode mode)
    {
        var sim = new GateSim(shownAtMs: 0, Expiry30s);
        var machine = new TakeoverStateMachine();
        sim.ClickApprove(pressAtMs: 20_000, layer: 2);
        var outcome = machine.LocalInput(TakeoverInputClass.Mouse, mode, mode);
        Assert.Equal("Approved", sim.Answer);
        // FR-145: every mode coexists (was: per-mode outcomes).
        Assert.Equal(TakeoverInputOutcome.ObservedCoexist, outcome);
        Assert.False(machine.OwnerDriving);
    }

    [Theory]
    [InlineData(TakeoverMode.Share)]
    [InlineData(TakeoverMode.HotkeyOnly)]
    public void PreFix_ShareAndHotkeyOnly_FirstClickAlsoLost(TakeoverMode mode)
    {
        // The defect was never takeover-specific: with no yield
        // in play at all, the arming latch still ate the click.
        var sim = new GateSim(shownAtMs: 0, Expiry30s);
        sim.ClickApprove(pressAtMs: 20_000, layer: 0);
        Assert.Null(sim.Answer);
    }

    [Fact]
    public void Layer1_SyncArmAlone_StillLosesThePress_TheGate1LiveResult()
    {
        // The first W118 build armed synchronously and STILL
        // produced gate_no_answer on a single Approve click at
        // T+25 s (audit: gate_raised 16:09:33.497, yield
        // 16:09:58.758, gate_no_answer 16:10:03.517). The press
        // on the disabled-at-start exit is routed beneath it;
        // arming mid-event does not retrofit capture. This pin
        // keeps that lesson in the suite.
        var sim = new GateSim(shownAtMs: 0, Expiry30s);
        sim.ClickApprove(pressAtMs: 20_000, layer: 1);
        Assert.Null(sim.Answer);
        // But the press DID arm the card: the next press takes
        // WPF's own path and answers (the gate-2 live shape).
        sim.ClickApprove(pressAtMs: 21_000, layer: 1);
        Assert.Equal("Approved", sim.Answer);
    }

    [Fact]
    public void WindowPressAnswers_TruthTable()
    {
        // The one answering shape: disabled at start, armed by
        // this press, press and release on the same exit.
        Assert.True(GateSheetModel.WindowPressAnswers(false, true, true, true));
        Assert.False(GateSheetModel.WindowPressAnswers(true, true, true, true));   // already enabled: WPF's path
        Assert.False(GateSheetModel.WindowPressAnswers(false, false, true, true)); // never armed (inside the delay)
        Assert.False(GateSheetModel.WindowPressAnswers(false, true, false, true)); // press started off the exit
        Assert.False(GateSheetModel.WindowPressAnswers(false, true, true, false)); // released off the exit
    }

    [Fact]
    public void Fixed_PressOnExitReleasedOffIt_AnswersNothing()
    {
        var sim = new GateSim(shownAtMs: 0, Expiry30s);
        sim.Press(pressAtMs: 20_000, layer: 2, pressOnExit: true, releaseOnSameExit: false);
        Assert.Null(sim.Answer);
    }

    [Fact]
    public void Fixed_BodyPressThenReleaseOnExit_AnswersNothing()
    {
        // A press that starts on the card body arms the card
        // (activation), but its release over an exit is not a
        // click on that exit — the press never started there.
        var sim = new GateSim(shownAtMs: 0, Expiry30s);
        sim.Press(pressAtMs: 20_000, layer: 2, pressOnExit: false, releaseOnSameExit: true);
        Assert.Null(sim.Answer);
        // The NEXT press, on the now-armed exit, answers.
        sim.ClickApprove(pressAtMs: 21_000, layer: 2);
        Assert.Equal("Approved", sim.Answer);
    }

    // ---------- OI-13 survives the fix ----------

    [Fact]
    public void ArmsOnActivation_BoundaryIsExactlyTheArmDelay()
    {
        Assert.False(GateSheetModel.ArmsOnActivation(0, 599));
        Assert.True(GateSheetModel.ArmsOnActivation(0, 600));
        Assert.True(GateSheetModel.ArmsOnActivation(0, 20_000));
        Assert.False(GateSheetModel.ArmsOnActivation(5_000, 5_599));
        Assert.True(GateSheetModel.ArmsOnActivation(5_000, 5_600));
        // And it is exactly ControlsArmed with the activation in hand.
        Assert.Equal(
            GateSheetModel.ControlsArmed(0, 600, humanActivated: true),
            GateSheetModel.ArmsOnActivation(0, 600));
    }

    [Fact]
    public void Fixed_PressInsideThe600msDelay_StillCannotAnswer()
    {
        var sim = new GateSim(shownAtMs: 0, Expiry30s);
        sim.ClickApprove(pressAtMs: 100, layer: 2);
        Assert.Null(sim.Answer);
        // The activation latched and the timer completed the arm
        // at the delay's end — the NEXT press answers.
        sim.ClickApprove(pressAtMs: 700, layer: 2);
        Assert.Equal("Approved", sim.Answer);
    }

    [Fact]
    public void Fixed_PressAfterTheGateExpired_AnswersNothing()
    {
        // The answer is recorded against the gate that was up
        // when the click landed — a click landing after that
        // gate died answers nothing (the prompt retires instead).
        var sim = new GateSim(shownAtMs: 0, Expiry30s);
        sim.ClickApprove(pressAtMs: 31_000, layer: 2);
        Assert.Null(sim.Answer);
        Assert.False(sim.Decided);
    }

    [Fact]
    public void Fixed_SecondClickAfterAnswer_ChangesNothing()
    {
        var sim = new GateSim(shownAtMs: 0, Expiry30s);
        sim.ClickApprove(pressAtMs: 20_000, layer: 2);
        Assert.Equal("Approved", sim.Answer);
        // A decided gate's state wins over every later transition.
        var state = GatePromptLifecycle.Evaluate(
            DateTimeOffset.UnixEpoch.AddSeconds(31), Expiry30s,
            sessionLive: true, decided: sim.Decided);
        Assert.Equal(GatePromptState.Decided, state);
        Assert.False(GatePromptLifecycle.ShouldDismiss(state));
    }

    // ---------- source pins: the shipped wiring ----------

    [Fact]
    public void GateSheet_ActivationArmsSynchronouslyInTheTunnelPhase()
    {
        var gate = SrcFile("DeskGuest.SessionAgent", "GateSheet.cs");
        // Activate latches, then arms synchronously per the model.
        Assert.Contains("private void Activate()", gate);
        Assert.Contains("_humanActivated = true;", gate);
        Assert.Contains("GateSheetModel.ArmsOnActivation(_shownAtMs, Environment.TickCount64)", gate);
        Assert.Contains("TryArmNow();", gate);
        // The arm timer is the same single arming path (backstop).
        Assert.Contains("_armTimer.Tick += (_, _) => TryArmNow();", gate);
        // Narrator/UIA activation takes the same path.
        Assert.Contains("public void HumanActivate()", gate);
    }

    [Fact]
    public void GateSheet_WindowCompletesThePressItsOwnActivationArmed()
    {
        var gate = SrcFile("DeskGuest.SessionAgent", "GateSheet.cs");
        // Press recording + completion are wired on both the
        // mouse and touch preview paths.
        Assert.Contains("RecordPress(e.GetPosition(this), wasEnabled);", gate);
        Assert.Contains("CompletePress(e.GetPosition(this));", gate);
        Assert.Contains("RecordPress(e.GetTouchPoint(this).Position, wasEnabled);", gate);
        Assert.Contains("CompletePress(e.GetTouchPoint(this).Position);", gate);
        Assert.Contains("private void RecordPress(", gate);
        Assert.Contains("private void CompletePress(", gate);
        Assert.Contains("GateSheetModel.WindowPressAnswers(", gate);
        // Completion flows through the ONE decision path, the
        // same one the exits' own Click handlers call.
        Assert.Contains("b.Click += (_, _) => Decide(outcome);", gate);
        Assert.Contains("private async void Decide(Outcome outcome)", gate);
        Assert.Contains("Decide(outcome.Value);", gate);
        // The press geometry comes from the exits' own rendered
        // rectangles, never the routed event target.
        Assert.Contains("b.TranslatePoint(new System.Windows.Point(0, 0), this)", gate);
    }

    [Fact]
    public void GateSheet_Oi13NotWeakened_ExitsStillStartDisabled()
    {
        var gate = SrcFile("DeskGuest.SessionAgent", "GateSheet.cs");
        Assert.Contains("IsEnabled = false, // armed only per OI-13", gate);
        // No path enables an exit except TryArmNow's lifecycle +
        // arming evaluation.
        Assert.Contains("GatePromptLifecycle.ExitsLive(state,", gate);
        Assert.Contains("GateSheetModel.ControlsArmed(_shownAtMs, Environment.TickCount64, _humanActivated)", gate);
    }
}
