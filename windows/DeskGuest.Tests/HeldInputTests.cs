using System.IO.Pipes;
using System.Text.Json;
using DeskGuest.Core;
using DeskGuest.Core.Ipc;
using DeskGuest.Core.Modules;
using DeskGuest.Shared.Input;
using DeskGuest.Shared.Ipc;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.Tools;

namespace DeskGuest.Tests;

/// <summary>U7 link-loss fail-safe regression tests (2026-11-22).
/// The hazard: the desktop engine injects key/button DOWN and UP as
/// separate acts; if the link dies, the session ends, STOP engages,
/// or the pairing is revoked between a down and its up, the physical
/// input stays down on the controlled machine. These tests pin the
/// release mechanism (HeldInputTracker) and every Core-side trigger
/// wired in this lane: IPC channel drop ends the session at once,
/// revocation mid-session ends the session, and session_stop sends
/// the explicit release order. The agent-side triggers (pipe
/// disconnect / STOP / inactive presence in AgentIpcClient) ride on
/// the same tracker; DeskGuest.Tests cannot reference the WPF session
/// agent, so those one-line wirings are compile-proven with the
/// Release build, as with the presence machine before them.</summary>
public class HeldInputTests
{
    internal static int FreePort()
    {
        var l = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
        l.Start();
        var port = ((System.Net.IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }

    private sealed class RecordingSink : IInputReleaseSink
    {
        public List<string> Released { get; } = new();
        public bool ThrowOnKey { get; set; }
        public void ReleaseKey(ushort virtualKey)
        {
            if (ThrowOnKey) throw new InvalidOperationException("sink fault");
            Released.Add($"key:0x{virtualKey:X2}");
        }
        public void ReleaseMouseButton(string button) => Released.Add($"button:{button}");
    }

    // ---- The mechanism ----------------------------------------------

    [Fact]
    public void Down_ThenReleaseAll_SendsMatchingUps_AndClears()
    {
        var tracker = new HeldInputTracker();
        var sink = new RecordingSink();
        tracker.NoteKeyDown(0x11); // CTRL
        tracker.NoteMouseDown("left");
        Assert.True(tracker.HasHeldInput);

        var result = tracker.ReleaseAll(sink);

        // Buttons first, then keys — and the tracker is empty after.
        Assert.Equal(new[] { "button:left", "key:0x11" }, result.Released);
        Assert.Empty(result.Failed);
        Assert.Equal(result.Released, sink.Released);
        Assert.False(tracker.HasHeldInput);
        Assert.Empty(tracker.HeldSnapshot());
    }

    [Fact]
    public void NormalDownUp_LeavesHeldSetEmpty_ReleaseAllSendsNothing()
    {
        var tracker = new HeldInputTracker();
        var sink = new RecordingSink();
        tracker.NoteKeyDown(0x41);
        tracker.NoteKeyUp(0x41);
        tracker.NoteMouseDown("right");
        tracker.NoteMouseUp("right");

        var result = tracker.ReleaseAll(sink);

        Assert.Empty(result.Released);
        Assert.Empty(result.Failed);
        Assert.Empty(sink.Released);
    }

    [Fact]
    public void ReleaseAll_KeysComeUpInReverseAcquisitionOrder()
    {
        // A chord pressed CTRL then SHIFT must release SHIFT then
        // CTRL — the mirror of how it went down.
        var tracker = new HeldInputTracker();
        var sink = new RecordingSink();
        tracker.NoteKeyDown(0x11);
        tracker.NoteKeyDown(0x10);
        tracker.NoteKeyDown(0x43);

        var result = tracker.ReleaseAll(sink);

        Assert.Equal(new[] { "key:0x43", "key:0x10", "key:0x11" }, result.Released);
    }

    [Fact]
    public void DuplicateDown_IsOneHold_OneRelease()
    {
        var tracker = new HeldInputTracker();
        var sink = new RecordingSink();
        tracker.NoteKeyDown(0x11);
        tracker.NoteKeyDown(0x11);
        tracker.NoteMouseDown("left");
        tracker.NoteMouseDown("left");

        var result = tracker.ReleaseAll(sink);

        Assert.Equal(new[] { "button:left", "key:0x11" }, result.Released);
    }

    [Fact]
    public void UnknownButton_NormalisesToLeft_ZeroVk_Ignored()
    {
        // The engine's send path maps unknown button names to
        // LEFTDOWN; the tracker must record the hold as "left" or
        // the release would aim at a button that is not the one down.
        var tracker = new HeldInputTracker();
        tracker.NoteKeyDown(0);
        tracker.NoteMouseDown("sideways");
        Assert.Equal(new[] { "button:left" }, tracker.HeldSnapshot());
        tracker.NoteMouseUp("LEFT");
        Assert.False(tracker.HasHeldInput);
    }

    [Fact]
    public void SinkThrowsOnOneItem_RestStillReleased_FailuresNamedAndKeptForRetry()
    {
        // BD-SUPP-HELDINPUT F3: the pre-fix test asserted the DEFECT
        // as correct — failed key-ups were reported as released and
        // forgotten. Now: failures are named in Failed, NOT in
        // Released, and stay tracked so the next trigger retries.
        var tracker = new HeldInputTracker();
        var sink = new RecordingSink { ThrowOnKey = true };
        tracker.NoteMouseDown("left");
        tracker.NoteKeyDown(0x11);
        tracker.NoteKeyDown(0x10);

        var result = tracker.ReleaseAll(sink);

        Assert.Equal(new[] { "button:left" }, result.Released);
        Assert.Equal(new[] { "key:0x10", "key:0x11" }, result.Failed);
        Assert.Equal(new[] { "button:left" }, sink.Released); // keys threw, button still went out
        Assert.True(tracker.HasHeldInput);                   // failed keys are STILL held — truthfully
        Assert.Equal(new[] { "key:0x10", "key:0x11" }, tracker.HeldSnapshot().OrderBy(x => x).ToArray());
        // Retry with a healthy sink: the stranded keys now release.
        sink.ThrowOnKey = false;
        var retry = tracker.ReleaseAll(sink);
        // DS-P6-F20 (Wave 12): failed holds are re-queued in their
        // ORIGINAL acquisition order [0x11, 0x10] (the pre-fix code
        // re-queued in failure order and this assertion encoded
        // that), so reverse-order release sends 0x10 up first.
        Assert.Equal(new[] { "key:0x10", "key:0x11" }, retry.Released);
        Assert.Empty(retry.Failed);
        Assert.False(tracker.HasHeldInput);
    }

    [Fact]
    public void ReleaseAll_IsIdempotent()
    {
        var tracker = new HeldInputTracker();
        var sink = new RecordingSink();
        tracker.NoteKeyDown(0x5B);
        Assert.Single(tracker.ReleaseAll(sink).Released);
        Assert.Empty(tracker.ReleaseAll(sink).Released);
        Assert.Single(sink.Released);
    }

    // ---- Trigger: IPC channel drop -----------------------------------

    [Fact]
    public async Task AgentChannel_ClientDisconnect_RaisesConnectionDropped()
    {
        var pipeName = "deskguest-test-" + Guid.NewGuid().ToString("N")[..8];
        var server = new AgentIpcServer(new CoreState(), "tok", pipeName);
        var dropped = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        server.AgentConnectionDropped += () => dropped.TrySetResult();
        using var cts = new CancellationTokenSource();
        var run = server.RunAsync(cts.Token);
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            using var client = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            await client.ConnectAsync(5000, timeout.Token);
            client.Dispose(); // the link dies
            await dropped.Task.WaitAsync(timeout.Token);
        }
        finally
        {
            cts.Cancel();
            server.Dispose();
            try { await run; } catch { }
        }
    }

    [Fact]
    public async Task CoreRuntime_LinkLoss_EndsLiveSessionImmediately_AndAudits()
    {
        var dir = TestUtil.TempDir();
        var rt = new CoreRuntime(new CoreOptions
        {
            DataDir = dir, Port = FreePort(), Protector = new DevOnlyPassThroughProtector(),
            Probe = new FakeProbe(), FactChecks = new FakeFactChecks(), Runner = new FakeRunner(),
            SupervisorPeriod = TimeSpan.FromMilliseconds(100)
        });
        await rt.StartAsync(default);
        try
        {
            // Use the runtime's own pairing store so the session
            // binds a pairing it knows.
            var code = rt.Pairings.CreatePairingCode("link-loss-agent", TimeSpan.FromMinutes(5), Scopes.Preset("look_only"));
            var exchange = rt.Pairings.ExchangeCode(code, "link-loss-agent");
            Assert.NotNull(exchange);
            var live = rt.Pairings.List().Single(p => p.Id == exchange!.PairingId);
            rt.Sessions.Start(live);
            Assert.NotNull(rt.Sessions.Current);

            // A client connects to the agent pipe, then the link dies.
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            using (var client = new NamedPipeClientStream(".", AgentIpcServer.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous))
            {
                await client.ConnectAsync(5000, timeout.Token);
            } // dispose = link loss

            for (var i = 0; i < 100 && rt.Sessions.Current is not null; i++)
                await Task.Delay(25, timeout.Token);
            Assert.Null(rt.Sessions.Current);
            Assert.Contains(rt.Audit.ReadTail(50), e => e.Outcome == "link_loss_session_ended");
        }
        finally
        {
            await rt.StopAsync(default);
            await rt.DisposeAsync();
        }
    }

    // ---- Trigger: pairing revocation mid-session ---------------------

    [Fact]
    public void CoreRuntime_RevokePairingFromLaptop_EndsItsLiveSession()
    {
        var rt = new CoreRuntime(new CoreOptions { DataDir = TestUtil.TempDir(), FactChecks = new FakeFactChecks(), Runner = new FakeRunner() });
        var code = rt.Pairings.CreatePairingCode("revoke-agent", TimeSpan.FromMinutes(5), Scopes.Preset("look_only"));
        var exchange = rt.Pairings.ExchangeCode(code, "revoke-agent");
        Assert.NotNull(exchange);
        var live = rt.Pairings.List().Single(p => p.Id == exchange!.PairingId);
        rt.Sessions.Start(live);

        var ok = rt.TryRevokePairingFromLaptop(JsonSerializer.Serialize(new { id = live.Id }));

        Assert.True(ok);
        Assert.Null(rt.Sessions.Current);
        Assert.Contains(rt.Audit.ReadTail(50), e => e.Outcome == "session_ended:pairing_revoked");
    }

    [Fact]
    public void CoreRuntime_RevokeOtherPairing_LeavesSessionAlone()
    {
        var rt = new CoreRuntime(new CoreOptions { DataDir = TestUtil.TempDir(), FactChecks = new FakeFactChecks(), Runner = new FakeRunner() });
        var code = rt.Pairings.CreatePairingCode("stays-agent", TimeSpan.FromMinutes(5), Scopes.Preset("look_only"));
        var exchange = rt.Pairings.ExchangeCode(code, "stays-agent");
        Assert.NotNull(exchange);
        var live = rt.Pairings.List().Single(p => p.Id == exchange!.PairingId);
        rt.Sessions.Start(live);

        var ok = rt.TryRevokePairingFromLaptop(JsonSerializer.Serialize(new { id = "no-such-pairing" }));

        Assert.False(ok);
        Assert.NotNull(rt.Sessions.Current);
    }

    [Fact]
    public async Task PairingAdmin_Revoke_EndsLiveSession_AndReportsIt()
    {
        var (svc, pairing, _) = TestUtil.MakePairing(new HashSet<string> { Scopes.Admin });
        var sessions = new SessionManager();
        sessions.Start(pairing);
        SessionRecord? ended = null;
        var module = new PairingAdminModule(svc, sessions, r => ended = r);
        var ctx = new ToolExecutionContext(pairing, TestUtil.Session(), TestUtil.State(), new HashSet<string>(), "unused");

        var result = await module.ExecuteAsync(
            JsonDocument.Parse(JsonSerializer.Serialize(new { action = "revoke", pairing_id = pairing.Id })).RootElement,
            ctx, default);

        Assert.True(result.Ok);
        Assert.Contains("session was ended", result.Text);
        Assert.Null(sessions.Current);
        Assert.Equal(pairing.Id, ended?.PairingId);
    }

    // ---- Trigger: session end (session_stop) sends the release order --

    [Fact]
    public async Task SessionStop_SendsReleaseInputsOrder_ToAgent()
    {
        var pipeName = "deskguest-test-" + Guid.NewGuid().ToString("N")[..8];
        var state = new CoreState();
        var server = new AgentIpcServer(state, "tok", pipeName);
        using var cts = new CancellationTokenSource();
        var run = server.RunAsync(cts.Token);
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            using var client = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            await client.ConnectAsync(5000, timeout.Token);
            // Authenticate like the real agent (mutual-auth handshake).
            var nonce = IpcAuth.NewNonce();
            await IpcFraming.WriteAsync(client, JsonSerializer.Serialize(
                new IpcMessage(IpcKinds.Hello, null, null, JsonSerializer.Serialize(new { nonce }), null, null, "test-agent", true, false, null)), timeout.Token);
            var ackJson = await IpcFraming.ReadAsync(client, timeout.Token);
            Assert.NotNull(ackJson);
            await IpcFraming.WriteAsync(client, JsonSerializer.Serialize(
                new IpcMessage(IpcKinds.Auth, null, null, null, null, "tok", "test-agent", true, false, null)), timeout.Token);
            for (var i = 0; i < 100 && !server.AgentAuthenticated; i++)
                await Task.Delay(25, timeout.Token);
            Assert.True(server.AgentAuthenticated);

            var sessions = new SessionManager();
            var pairing = TestUtil.BarePairing(new HashSet<string> { Scopes.Observe });
            sessions.Start(pairing);
            var module = new SessionStopModule(sessions, state, server);
            var ctx = new ToolExecutionContext(pairing, TestUtil.Session(), TestUtil.State(), new HashSet<string>(), "unused");
            var result = await module.ExecuteAsync(default, ctx, timeout.Token);
            Assert.True(result.Ok);
            Assert.Null(sessions.Current);

            // The agent's next frame on the pipe must be the release order.
            var frame = await IpcFraming.ReadAsync(client, timeout.Token);
            Assert.NotNull(frame);
            var msg = JsonSerializer.Deserialize<IpcMessage>(frame!);
            Assert.Equal(IpcKinds.ReleaseInputs, msg!.Kind);
        }
        finally
        {
            cts.Cancel();
            server.Dispose();
            try { await run; } catch { }
        }
    }
}
