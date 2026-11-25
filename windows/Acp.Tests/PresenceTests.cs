using System.IO.Pipes;
using System.Text.Json;
using Acp.Core;
using Acp.Core.Ipc;
using Acp.Shared.Ipc;
using Acp.Shared.Presence;
using Acp.Shared.State;

namespace Acp.Tests;

/// <summary>Regression tests for the M1 presence rework (2026-11-17),
/// written against the field failure the owner hit the same day: the
/// banner said "An agent is controlling this PC" (the name never
/// arrived), and after STOP the banner showed "You pressed STOP"
/// with a second STOP button that did nothing and no way to clear
/// the block — SetUserStop(false) had no caller in the product.
/// These tests pin: the name flows, every state has a working exit,
/// dismiss is notice-only, and the Core's clear path works over the
/// real IPC channel.</summary>
public class PresenceTests
{
    // ---- The directive decision (Core side) -------------------------

    [Theory]
    [InlineData(false, false, PresenceMode.Off)]
    [InlineData(true, false, PresenceMode.Active)]
    [InlineData(true, true, PresenceMode.Blocked)]
    [InlineData(false, true, PresenceMode.Blocked)]
    public void Directive_MapsTruthToMode(bool sessionActive, bool stopInForce, PresenceMode expected)
    {
        Assert.Equal(expected, PresenceDirective.Decide(sessionActive, stopInForce));
    }

    // ---- The state machine (Agent side) -----------------------------

    [Fact]
    public void Machine_SessionStart_NamesTheAgent()
    {
        var m = new PresenceStateMachine();
        m.SessionStarted("Muse");
        Assert.Equal(PresenceMode.Active, m.Mode);
        Assert.Equal("Muse", m.DisplayName);
        Assert.True(m.SessionActive);
    }

    [Fact]
    public void Machine_StopDuringSession_Blocked_ThenClearReturnsToActive()
    {
        var m = new PresenceStateMachine();
        m.SessionStarted("Muse");
        m.StopEngaged();
        Assert.Equal(PresenceMode.Blocked, m.Mode);
        Assert.True(m.StopInForce);
        m.StopCleared();
        Assert.Equal(PresenceMode.Active, m.Mode);
        Assert.False(m.StopInForce);
    }

    [Fact]
    public void Machine_SessionEndWhileBlocked_StaysBlocked_ThenClearGoesOff()
    {
        // The Core ends the session when STOP engages; the block —
        // and its banner with the working CLEAR control — must
        // survive the session's end, and clearing it must land Off.
        var m = new PresenceStateMachine();
        m.SessionStarted("Muse");
        m.StopEngaged();
        m.SessionEnded();
        Assert.Equal(PresenceMode.Blocked, m.Mode);
        Assert.Equal("Muse", m.DisplayName); // the blocked banner still names who is blocked
        m.StopCleared();
        Assert.Equal(PresenceMode.Off, m.Mode);
    }

    [Fact]
    public void Machine_SessionEnd_NoStop_GoesOff()
    {
        var m = new PresenceStateMachine();
        m.SessionStarted("Muse");
        m.SessionEnded();
        Assert.Equal(PresenceMode.Off, m.Mode);
    }

    [Fact]
    public void Machine_Dismiss_OnlyInBlocked_AndNoticeOnly()
    {
        // REPAIRED (Wave 2 Lane B, 2026-11-22) with disclosure: this
        // test predates bd-shared-session F8, under which dismiss is
        // REFUSED while a session is active — DISMISS may hide the
        // blocked notice only, never the last on-screen indicator of
        // a live session (MinimalIndicatorVisible). The dismissal
        // assertions now run after the session ends, which is the
        // state F8 built them for; the in-session refusal is asserted
        // by name instead of assumed away.
        var m = new PresenceStateMachine();
        Assert.False(m.Dismiss()); // Off: dismiss does not exist here
        m.SessionStarted("Muse");
        Assert.False(m.Dismiss()); // Active: STOP is the control, not dismiss
        Assert.Equal(PresenceMode.Active, m.Mode);
        m.StopEngaged();
        Assert.False(m.Dismiss()); // F8: session still live — dismiss refused
        Assert.Equal(PresenceMode.Blocked, m.Mode);
        m.SessionEnded();
        Assert.True(m.Dismiss());
        Assert.Equal(PresenceMode.BlockedDismissed, m.Mode);
        Assert.True(m.StopInForce); // dismiss hides the notice, never the block
    }

    [Fact]
    public void Machine_Directive_SameBlockKeepsDismissal_ReengagedBlockResurfaces()
    {
        // REPAIRED (Wave 2 Lane B, 2026-11-22) with disclosure: same
        // F8 staleness as Machine_Dismiss_OnlyInBlocked_AndNoticeOnly
        // — the dismissal is taken on the session-inactive directive
        // below (the state the rest of this test already reconciles
        // against), not while the session is live.
        var m = new PresenceStateMachine();
        m.ApplyDirective(sessionActive: true, agentName: "Muse", stopInForce: true);
        Assert.Equal(PresenceMode.Blocked, m.Mode);
        Assert.False(m.Dismiss()); // F8: session live — refused
        m.ApplyDirective(sessionActive: false, agentName: "Muse", stopInForce: true);
        Assert.True(m.Dismiss());
        // Reconciliation pushes for the SAME block must not resurrect
        // the notice the owner dismissed…
        m.ApplyDirective(sessionActive: false, agentName: "Muse", stopInForce: true);
        Assert.Equal(PresenceMode.BlockedDismissed, m.Mode);
        // …but a block that was cleared and re-engaged is new and shows.
        m.ApplyDirective(sessionActive: false, agentName: "Muse", stopInForce: false);
        Assert.Equal(PresenceMode.Off, m.Mode);
        m.ApplyDirective(sessionActive: false, agentName: "Muse", stopInForce: true);
        Assert.Equal(PresenceMode.Blocked, m.Mode);
    }

    [Fact]
    public void Machine_Directive_CarriesNameAndSessionTruth()
    {
        var m = new PresenceStateMachine();
        m.ApplyDirective(sessionActive: true, agentName: "Agent A", stopInForce: false);
        Assert.Equal(PresenceMode.Active, m.Mode);
        Assert.Equal("Agent A", m.DisplayName);
        m.ApplyDirective(sessionActive: false, agentName: null, stopInForce: false);
        Assert.Equal(PresenceMode.Off, m.Mode);
    }

    // ---- The wire: the name has its own field ------------------------

    [Fact]
    public void IpcMessage_AgentName_RoundTripsSeparatelyFromVersion()
    {
        var msg = new IpcMessage(IpcKinds.Presence, null, null, "{}", null, "on", "0.1.0", null, null, "intent",
            AgentName: "Muse");
        var json = JsonSerializer.Serialize(msg);
        var back = JsonSerializer.Deserialize<IpcMessage>(json)!;
        Assert.Equal("Muse", back.AgentName);
        Assert.Equal("0.1.0", back.AgentVersion); // the version slot is not the name (the original bug)
    }

    // ---- The Core's clear path ----------------------------------------

    [Fact]
    public void CoreState_UserStop_SetAndClear_StopFileStillForces()
    {
        var state = new CoreState();
        state.SetUserStop(true);
        Assert.True(state.StopInForce);
        Assert.Equal(EndpointState.StoppedByUser, state.ComputeState());
        state.SetUserStop(false);
        Assert.False(state.StopInForce);
        // The STOP file is an independent switch: clearing the UI
        // stop must not lift a file stop.
        state.SetStopFilePresent(true);
        state.SetUserStop(true);
        state.SetUserStop(false);
        Assert.True(state.StopInForce);
        state.SetStopFilePresent(false);
        Assert.False(state.StopInForce);
    }

    [Fact]
    public async Task Ipc_UserStop_ThenUserStopClear_OverRealPipe()
    {
        var pipeName = "acp-test-" + Guid.NewGuid().ToString("N")[..8];
        var state = new CoreState();
        var server = new AgentIpcServer(state, "s3cret-token", pipeName);
        using var cts = new CancellationTokenSource();
        var run = server.RunAsync(cts.Token);
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            using var client = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            await client.ConnectAsync(5000, timeout.Token);
            var nonce = IpcAuth.NewNonce();
            var hello = new IpcMessage(IpcKinds.Hello, null, null, JsonSerializer.Serialize(new { nonce }), null, null, "test-agent", true, false, null);
            await IpcFraming.WriteAsync(client, JsonSerializer.Serialize(hello), timeout.Token);
            var ackJson = await IpcFraming.ReadAsync(client, timeout.Token);
            Assert.NotNull(ackJson);
            var auth = new IpcMessage(IpcKinds.Auth, null, null, null, null, "s3cret-token", "test-agent", true, false, null);
            await IpcFraming.WriteAsync(client, JsonSerializer.Serialize(auth), timeout.Token);
            for (var i = 0; i < 100 && !server.AgentAuthenticated; i++)
                await Task.Delay(25, timeout.Token);
            Assert.True(server.AgentAuthenticated);

            var stop = new IpcMessage(IpcKinds.UserStop, null, null, null, null, null, null, null, null, null);
            await IpcFraming.WriteAsync(client, JsonSerializer.Serialize(stop), timeout.Token);
            for (var i = 0; i < 100 && !state.StopInForce; i++)
                await Task.Delay(25, timeout.Token);
            Assert.True(state.StopInForce);

            // W10 / V2-C4: the clear now carries the physical-human
            // provenance stamp the Core requires in EVERY session
            // state (pre-fix a bare message was honored — the F2
            // hole). The bare-message refusal is pinned in
            // W10WinV2FixTests; this test keeps proving the M1 exit
            // exists through the legitimate path.
            var clear = new IpcMessage(IpcKinds.UserStopClear, null, null, null, null, null, null, null, null, null,
                InputProvenance: IpcProvenance.PhysicalHuman);
            await IpcFraming.WriteAsync(client, JsonSerializer.Serialize(clear), timeout.Token);
            for (var i = 0; i < 100 && state.StopInForce; i++)
                await Task.Delay(25, timeout.Token);
            Assert.False(state.StopInForce); // the blocked state has an exit (M1)
        }
        finally
        {
            cts.Cancel();
            server.Dispose();
            try { await run; } catch { }
        }
    }
}
