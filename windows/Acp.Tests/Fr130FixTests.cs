using Acp.Core;
using Acp.Shared.Input;
using Acp.Shared.Presence;

namespace Acp.Tests;

/// <summary>
/// FR-130 — the presence-pill latch. The pill rendered "paused —
/// you're driving" from a takeover flag set in an earlier session
/// while the Core reported takeover_active: false, and every
/// agent input was gated behind a hand-back nobody local was
/// present to give. Three defects: (1) the takeover reset lived
/// only in HideSession, which the live directive lifecycle never
/// calls; (2) the agent's SessionState report hardcoded
/// TakeoverActive: false, so the Core could never see the pill's
/// state; (3) the local-input watcher had no way to tell the
/// agent's own injections from outside input.
///
/// Pins: the boundary reconciliation on the shared state machine
/// (a stale flag clears at a session boundary and the clear is
/// reported; a clean machine is untouched; enter/exit still work
/// in both directions afterwards); the self-input window's
/// coverage semantics; the Core-side report path carrying the
/// real value; and source pins for the wiring (the directive
/// path reconciles, the report senders carry OwnerDrivingNow,
/// the watcher consults the window, the Core's audit coercion
/// accepts the reconciliation kind/actor).
/// </summary>
public class Fr130FixTests
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

    private static string AgentFile(string file) => SrcFile("Acp.SessionAgent", file);
    private static string CoreFile(string file) => SrcFile("Acp.Core", file);

    // ---------------- the boundary reconciliation ----------------

    [Fact]
    public void Boundary_ClearsAStaleOwnerDrivingFlag_AndReportsTheClear()
    {
        var m = new TakeoverStateMachine();
        Assert.Equal(TakeoverInputOutcome.Yielded,
            m.LocalInput(TakeoverInputClass.Mouse, TakeoverMode.TakeOver, TakeoverMode.TakeOver));
        Assert.True(m.OwnerDriving);

        // A new session starts: the stale flag must not survive it.
        Assert.True(m.ReconcileAtSessionBoundary());
        Assert.False(m.OwnerDriving);
    }

    [Fact]
    public void Boundary_OnACleanMachine_ChangesNothing_AndReportsNoClear()
    {
        var m = new TakeoverStateMachine();
        Assert.False(m.ReconcileAtSessionBoundary());
        Assert.False(m.OwnerDriving);
    }

    [Fact]
    public void Boundary_AfterReconcile_TakeoverStillWorksInBothDirections()
    {
        var m = new TakeoverStateMachine();
        m.LocalInput(TakeoverInputClass.Keyboard, TakeoverMode.TakeOver, TakeoverMode.TakeOver);
        Assert.True(m.OwnerDriving);
        Assert.True(m.ReconcileAtSessionBoundary());

        // Enter again by input, exit by explicit hand-back.
        Assert.Equal(TakeoverInputOutcome.Yielded,
            m.LocalInput(TakeoverInputClass.Mouse, TakeoverMode.TakeOver, TakeoverMode.TakeOver));
        Assert.True(m.OwnerDriving);
        Assert.True(m.HandBack());
        Assert.False(m.OwnerDriving);

        // Enter by the chord, exit by reset.
        Assert.True(m.TakeoverHotkey());
        Assert.True(m.OwnerDriving);
        m.Reset();
        Assert.False(m.OwnerDriving);
    }

    [Fact]
    public void Boundary_SessionRestartWithStaleFlag_StartsAgentDriving()
    {
        // The run-3 shape: session A yields; session A ends without
        // the reset path running; session B's start directive is
        // the only reconciliation point there is.
        var m = new TakeoverStateMachine();
        m.LocalInput(TakeoverInputClass.Mouse, TakeoverMode.TakeOver, TakeoverMode.TakeOver);
        Assert.True(m.OwnerDriving); // session A: owner driving

        Assert.True(m.ReconcileAtSessionBoundary()); // session B starts
        Assert.False(m.OwnerDriving); // session B: agent driving, pill agrees with the Core
    }

    // ---------------- the self-input window ----------------

    [Fact]
    public void SelfInputWindow_NoNote_NeverCovers()
    {
        var w = new SelfInputWindow(TimeSpan.FromMilliseconds(350));
        Assert.False(w.Covers(DateTime.UtcNow));
    }

    [Fact]
    public void SelfInputWindow_NoteCoversInsideTheTail_AndNotAfter()
    {
        var w = new SelfInputWindow(TimeSpan.FromMilliseconds(350));
        var t0 = new DateTime(2026, 11, 25, 7, 0, 0, DateTimeKind.Utc);
        w.Note(t0);
        Assert.True(w.Covers(t0));
        Assert.True(w.Covers(t0.AddMilliseconds(349)));
        Assert.False(w.Covers(t0.AddMilliseconds(351)));
        Assert.False(w.Covers(t0.AddSeconds(-1))); // a note never covers the past
    }

    [Fact]
    public void SelfInputWindow_ALaterNoteReArmsTheWindow()
    {
        var w = new SelfInputWindow(TimeSpan.FromMilliseconds(350));
        var t0 = new DateTime(2026, 11, 25, 7, 0, 0, DateTimeKind.Utc);
        w.Note(t0);
        Assert.False(w.Covers(t0.AddSeconds(2)));
        w.Note(t0.AddSeconds(2));
        Assert.True(w.Covers(t0.AddSeconds(2).AddMilliseconds(100)));
    }

    // ---------------- the Core-side report path ----------------

    [Fact]
    public void CoreFacts_FollowTheAgentsReportedTakeoverValue_BothWays()
    {
        // The invariant the latch violated: the pill face and the
        // Core's takeover_status are one fact. The Core side of
        // the invariant is this report application — it must carry
        // the reported value in BOTH directions, never pin false.
        var state = new CoreState();
        state.ApplyAgentSessionReport(true, true, null, null);
        Assert.True(state.Session.TakeoverActive);
        state.ApplyAgentSessionReport(true, false, null, null);
        Assert.False(state.Session.TakeoverActive);
    }

    // ---------------- source pins: the wiring ----------------

    [Fact]
    public void DirectivePath_ReconcilesTakeoverAtSessionBoundaries()
    {
        var presence = AgentFile("Presence.cs");
        Assert.Contains("ReconcileAtSessionBoundary", presence);
        Assert.Contains("TakeoverReconciled", presence);
        // The reconciliation hangs off the session-active edge in
        // ApplyDirective, not off a path the lifecycle never calls.
        var apply = presence.Substring(presence.IndexOf("public void ApplyDirective(bool sessionActive", StringComparison.Ordinal));
        apply = apply.Substring(0, apply.IndexOf("public void ApplyStopEngaged", StringComparison.Ordinal));
        Assert.Contains("sessionActive != wasSessionActive", apply);
        Assert.Contains("ReconcileAtSessionBoundary()", apply);
    }

    [Fact]
    public void SessionStateReports_CarryTheRealTakeoverValue()
    {
        var ipc = AgentFile("IpcClient.cs");
        // The hardcoded-false sender is gone, in both the heartbeat
        // and the handshake Auth report.
        Assert.DoesNotContain("nowUnlocked, false", ipc);
        Assert.DoesNotContain("DesktopUnlocked, false, null, fgTitle", ipc);
        // The heartbeat tracks the takeover state as a change
        // trigger and sends the live value.
        Assert.Contains("nowTakeover", ipc);
        Assert.Contains("nowUnlocked, nowTakeover, null, fgTitle, fgProcess", ipc);
        // Transitions report immediately, not only on heartbeat.
        Assert.Contains("SendSessionStateQuietAsync", ipc);
        Assert.Contains("DesktopUnlocked, _presence.OwnerDrivingNow, null, fgTitle, fgProcess", ipc);
    }

    [Fact]
    public void Watcher_SuppressesOnlyInsideTheSelfInputWindow()
    {
        var watcher = AgentFile("LocalInputWatcher.cs");
        Assert.Contains("SelfInputWindow.Shared.Covers", watcher);
        Assert.Contains("!selfInput", watcher);
    }

    [Fact]
    public void Core_AuditCoercionAcceptsTheReconciliationRecord()
    {
        var runtime = CoreFile("CoreRuntime.cs");
        Assert.Contains("TakeoverRecordKinds.Reconciled", runtime);
        Assert.Contains("TakeoverActors.PresenceReconciliation", runtime);
        // The vocabulary itself is defined once, in the shared home.
        Assert.Equal("takeover_reconciled", TakeoverRecordKinds.Reconciled);
        Assert.Equal("presence-reconciliation", TakeoverActors.PresenceReconciliation);
        Assert.Contains("cleared at session start", TakeoverRecordDetail.Reconciled());
    }
}
