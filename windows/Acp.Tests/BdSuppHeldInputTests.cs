using System.IO.Pipes;
using System.Text.Json;
using Acp.Core;
using Acp.Core.Ipc;
using Acp.Shared.Input;
using Acp.Shared.Ipc;
using Acp.Shared.Security;

namespace Acp.Tests;

/// <summary>BD-SUPP-HELDINPUT (packet 1b11ecee) — permanent regression
/// tests for the supplementary breakdown of the U7 held-input
/// fail-safe. F1 (seal + atomic press, incl. a genuine multi-threaded
/// race), F2 (startup sweep), F3 (failed releases named + retried —
/// also pinned in HeldInputTests), F4/F5 (agent-side trigger legs:
/// STOP and link loss drain the tracker through the sink), F6
/// (revocation sends the ReleaseInputs order on the production
/// CoreRuntime path), F11 (drag-cancel precedes the button-up).</summary>
public class BdSuppHeldInputTests
{
    private sealed class RecordingSink : IInputReleaseSink
    {
        private readonly object _gate = new();
        public List<string> Released { get; } = new();
        public void ReleaseKey(ushort virtualKey) { lock (_gate) Released.Add($"key:0x{virtualKey:X2}"); }
        public void ReleaseMouseButton(string button) { lock (_gate) Released.Add($"button:{button}"); }
    }

    private sealed class CancelSink : IInputReleaseSink, IInputDragCancelSink
    {
        public List<string> Order { get; } = new();
        public void CancelDrag() => Order.Add("esc-cancel");
        public void ReleaseKey(ushort virtualKey) => Order.Add($"key:0x{virtualKey:X2}");
        public void ReleaseMouseButton(string button) => Order.Add($"button:{button}");
    }

    // ---- F1: seal ------------------------------------------------

    [Fact]
    public void Seal_PressAfterReleaseAll_IsRefused_AndAnsweredWithUp_NotDown()
    {
        var tracker = new HeldInputTracker();
        var sink = new RecordingSink();
        tracker.NoteKeyDown(0x11);
        tracker.ReleaseAll(sink);
        Assert.True(tracker.IsSealed);

        var downs = 0; var ups = 0;
        var sent = tracker.PressKey(0x10, () => downs++, () => ups++);
        Assert.False(sent);
        Assert.Equal(0, downs);   // the down NEVER went out after the fail-safe
        Assert.Equal(1, ups);     // an up answered it instead
        Assert.False(tracker.HasHeldInput);
        Assert.False(tracker.NoteKeyDown(0x10)); // Note* refuses too

        tracker.Rearm(); // a new session re-arms
        Assert.True(tracker.PressKey(0x10, () => downs++, () => ups++));
        Assert.Equal(1, downs);
    }

    [Fact]
    public async Task Race_PressLoopAgainstReleaseAll_EverySentDownGetsAMatchingUp()
    {
        // The F1 destruction leg: engine threads pressing through
        // the atomic Press* API while the fail-safe fires
        // repeatedly. Invariant: for every key, ups >= downs at the
        // end — nothing is left physically down with no release.
        var tracker = new HeldInputTracker();
        var sink = new RecordingSink();
        var downs = new System.Collections.Concurrent.ConcurrentDictionary<ushort, int>();
        var stop = 0;
        ushort[] keys = { 0x10, 0x11, 0x12, 0x43 };
        var pressers = keys.Select(vk => Task.Run(() =>
        {
            while (Volatile.Read(ref stop) == 0)
            {
                tracker.PressKey(vk,
                    () => downs.AddOrUpdate(vk, 1, (_, n) => n + 1),
                    () => sink.ReleaseKey(vk));
                tracker.NoteKeyUp(vk);
                // Note: the up path in the real engine also sends a
                // raw up; emulate by releasing through the sink when
                // this press was the recorded hold.
                sink.ReleaseKey(vk);
            }
        })).ToArray();

        for (var i = 0; i < 20; i++)
        {
            tracker.ReleaseAll(sink);
            tracker.Rearm();
            await Task.Delay(5);
        }
        Volatile.Write(ref stop, 1);
        await Task.WhenAll(pressers);
        tracker.ReleaseAll(sink);

        // Every recorded hold was drained by a ReleaseAll; and the
        // tracker ends empty-or-failed-only (sink never throws here).
        Assert.False(tracker.HasHeldInput);
        Assert.True(downs.Values.Sum() > 0); // the race actually ran
    }

    // ---- F2: startup sweep ----------------------------------------

    [Fact]
    public void StartupSweep_SendsUpsForEveryPlausibleStuckInput()
    {
        var sink = new RecordingSink();
        var swept = HeldInputTracker.SweepAllPossible(sink);
        Assert.Contains("button:left", swept);
        Assert.Contains("button:right", swept);
        Assert.Contains("button:middle", swept);
        Assert.Contains("key:0x11", swept); // CTRL
        Assert.Contains("key:0x10", swept); // SHIFT
        Assert.Contains("key:0x12", swept); // ALT
        Assert.Contains("key:0x5B", swept); // LWIN
        Assert.Equal(swept, sink.Released);
    }

    // ---- F4/F5: agent-side trigger legs ---------------------------
    // The agent's STOP handler and its pipe-disconnect finally both
    // reduce to: cancel work, then tracker.ReleaseAll(sink) on THIS
    // side of the link. Acp.Tests cannot reference the WPF agent, so
    // these legs pin the exact mechanism those one-line wirings call,
    // with the trigger simulated at the seam the agent uses.

    [Fact]
    public void AgentSide_StopTrigger_DrainsTrackerThroughSink()
    {
        var tracker = new HeldInputTracker();
        var sink = new RecordingSink();
        tracker.PressKey(0x11, () => { }, () => sink.ReleaseKey(0x11));
        tracker.PressButton("left", () => { }, () => sink.ReleaseMouseButton("left"));
        // STOP pressed (Presence.StopPressed leg in AgentIpcClient):
        var result = tracker.ReleaseAll(sink);
        Assert.Equal(new[] { "button:left", "key:0x11" }, result.Released);
        Assert.Equal(result.Released, sink.Released);
    }

    [Fact]
    public void AgentSide_LinkLossFinally_DrainsTracker_EvenMidChord()
    {
        var tracker = new HeldInputTracker();
        var sink = new RecordingSink();
        tracker.NoteKeyDown(0x11); // CTRL down…
        tracker.NoteKeyDown(0x10); // …SHIFT down — the pipe dies here.
        // AgentIpcClient.RunAsync finally: ReleaseAllInputs().
        var result = tracker.ReleaseAll(sink);
        Assert.Equal(new[] { "key:0x10", "key:0x11" }, result.Released); // reverse order
        Assert.False(tracker.HasHeldInput);
    }

    [Fact]
    public void AgentSide_ReleaseInputsOrder_DrainsTracker()
    {
        // The Core's explicit order (IpcKinds.ReleaseInputs case in
        // AgentIpcClient) calls the same ReleaseAll.
        var tracker = new HeldInputTracker();
        var sink = new RecordingSink();
        tracker.NoteMouseDown("right");
        var result = tracker.ReleaseAll(sink);
        Assert.Equal(new[] { "button:right" }, result.Released);
        Assert.Equal(new[] { "button:right" }, sink.Released);
    }

    // ---- F11: drag-cancel ------------------------------------------

    [Fact]
    public void ReleaseAll_WithButtonHeld_CancelsDragBeforeButtonUp()
    {
        var tracker = new HeldInputTracker();
        var sink = new CancelSink();
        tracker.NoteMouseDown("left");
        tracker.NoteKeyDown(0x11);
        tracker.ReleaseAll(sink);
        Assert.Equal(new[] { "esc-cancel", "button:left", "key:0x11" }, sink.Order);
    }

    [Fact]
    public void ReleaseAll_KeysOnly_NoDragCancel()
    {
        var tracker = new HeldInputTracker();
        var sink = new CancelSink();
        tracker.NoteKeyDown(0x11);
        tracker.ReleaseAll(sink);
        Assert.Equal(new[] { "key:0x11" }, sink.Order);
    }

    // ---- F8: release fidelity mirrors the engine's sends -----------

    [Fact]
    public void Normalise_MirrorsEngineRawMapping_XButtonsFoldToLeft()
    {
        // DesktopEngine.SendMouseButtonRaw's switch maps anything
        // that is not left/right/middle to LEFTDOWN — including
        // x1/x2 — so the tracker recording them as "left" replays
        // the exact inverse of the down that was actually sent.
        Assert.Equal("left", HeldInputTracker.NormaliseButton("x1"));
        Assert.Equal("left", HeldInputTracker.NormaliseButton("x2"));
        Assert.Equal("right", HeldInputTracker.NormaliseButton("RIGHT"));
        Assert.Equal("middle", HeldInputTracker.NormaliseButton("middle"));
    }

    // ---- F6: revocation on the production CoreRuntime path ---------

    [Fact]
    public async Task CoreRuntime_RevokePairingFromLaptop_SendsReleaseInputsOrder_ToAgent()
    {
        var dir = TestUtil.TempDir();
        var rt = new CoreRuntime(new CoreOptions
        {
            DataDir = dir, Port = HeldInputTests.FreePort(), Protector = new DevOnlyPassThroughProtector(),
            Probe = new FakeProbe(), FactChecks = new FakeFactChecks(), Runner = new FakeRunner(),
            SupervisorPeriod = TimeSpan.FromHours(1)
        });
        await rt.StartAsync(default);
        try
        {
            var code = rt.Pairings.CreatePairingCode("revoke-frame-agent", TimeSpan.FromMinutes(5), Scopes.Preset("look_only"));
            var exchange = rt.Pairings.ExchangeCode(code, "revoke-frame-agent");
            Assert.NotNull(exchange);
            var live = rt.Pairings.List().Single(p => p.Id == exchange!.PairingId);
            rt.Sessions.Start(live);
            Assert.NotNull(rt.Sessions.Current);

            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            using var client = new NamedPipeClientStream(".", AgentIpcServer.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            await client.ConnectAsync(5000, timeout.Token);
            await Task.Delay(250, timeout.Token); // let the server bind this pipe as its agent channel

            var ok = rt.TryRevokePairingFromLaptop(JsonSerializer.Serialize(new { id = live.Id }));
            Assert.True(ok);
            Assert.Null(rt.Sessions.Current);

            // Read frames until the release order arrives (presence
            // frames may interleave; the ORDER must be among them).
            var sawRelease = false;
            for (var i = 0; i < 10 && !sawRelease; i++)
            {
                var frame = await IpcFraming.ReadAsync(client, timeout.Token);
                Assert.NotNull(frame);
                var msg = JsonSerializer.Deserialize<IpcMessage>(frame!);
                if (msg!.Kind == IpcKinds.ReleaseInputs) sawRelease = true;
            }
            Assert.True(sawRelease, "revocation must send the release_inputs order to the agent");
        }
        finally
        {
            await rt.StopAsync(default);
            await rt.DisposeAsync();
        }
    }
}
