using System.IO;
using System.Windows;
using System.Windows.Threading;

namespace DeskGuest.SessionAgent;

/// <summary>
/// Session Agent composition (DESIGN §3.2): presence layer, desktop
/// engine, IPC client. Starts at logon (installer task), lives in the
/// tray, and never exits because the Core is down — the IPC client
/// retries forever. If the Core relaunches us elevated (census row 89),
/// the banner says so; elevation is a visible session state.
/// </summary>
public partial class App : System.Windows.Application
{
    private AgentIpcClient? _ipc;
    private DesktopEngine? _engine;
    private CancellationTokenSource? _cts;
    private System.Windows.Forms.NotifyIcon? _tray;
    private StopHotkeyHost? _stopHotkey;
    // The tray popup's mesh line (Block H): derived from the latest
    // host-state snapshot the Core pushed — the agent's one mesh
    // source, shared with the host window. Starts "unavailable"
    // (truthfully: no snapshot yet) and updates on every snapshot,
    // including into an already-open popup.
    private string _lastMeshLine = DeskGuest.Shared.Presence.MeshLineText.Unavailable;
    private TrayPopup? _openPopup;

    /// <summary>Portable helper startup: presence + engine + IPC,
    /// exactly like the installed agent (the helped person's PC is
    /// protected by the same layer), but the ONLY window is the
    /// helper. Presence is shown from the first second, before any
    /// session exists.</summary>
    private void StartPortableHelper()
    {
        ShutdownMode = ShutdownMode.OnMainWindowClose;
        var presence = new PresenceLayer(Dispatcher.CurrentDispatcher);
        var engine = new DesktopEngine(
            glideTo: (x, y) => presence.GlideGhostToAsync(x, y),
            narrate: text => presence.SetNarration(text));
        _engine = engine;
        // BD-SUPP-HELDINPUT F2: startup sweep — if a predecessor
        // agent was killed mid-hold, its injected downs are still
        // physically down; send the ups before serving anything.
        try { engine.SweepStuckInputsOnStartup(); } catch { }
        _ipc = new AgentIpcClient(engine, presence,
            agentVersion: (typeof(App).Assembly.GetName().Version?.ToString() ?? "unknown") + "-portable");
        WireOrphanExit();
        // W9 Task 4: the fixture-chosen STOP hotkey protects the
        // helped person's PC too — same chord, same user-stop path.
        _stopHotkey = new StopHotkeyHost(async () => { try { await _ipc.RequestUserStopAsync(); } catch { } });
        var helper = new PortableHelperWindow(
            sendAction: async (kind, payload) =>
            {
                try { await _ipc.SendHostActionAsync(kind, System.Text.Json.JsonSerializer.Serialize(payload)); return true; }
                catch { return false; }
            },
            sendStop: async () =>
            {
                try { await _ipc.RequestUserStopAsync(); return true; }
                catch { return false; }
            });
        _ipc.QuickAssistCodeReceived += json => helper.SetCode(json);
        _ipc.HostStateReceived += json => helper.SetHostState(json);
        MainWindow = helper;
        helper.Show();
        // Presence from the first second: the box names the mode
        // and the STOP affordance before anyone connects.
        presence.ShowSession("DeskGuest Quick Fix", "This PC is running the portable help helper. Nothing is installed; closing the helper ends everything.");
        _ = Task.Run(async () =>
        {
            for (var i = 0; i < 15; i++)
            {
                try { await _ipc.RequestHostStateAsync(); return; }
                catch { await Task.Delay(2000); }
            }
        });
    }

    protected override void OnStartup(StartupEventArgs e)
    {
        // Quick Fix law — nothing persists: in portable mode the
        // crash/startup log file below is NOT written (it would leave
        // a file under LocalAppData on the helped person's PC after
        // the helper is gone). Portable runs keep diagnostics in
        // memory only (the handlers below no-op without a log path).
        var portable = e.Args.Any(a => string.Equals(a, "--portable", StringComparison.OrdinalIgnoreCase) ||
                                       string.Equals(a, "--quick-assist", StringComparison.OrdinalIgnoreCase));
        // Crash + startup diagnostics: a host-visible log, because a
        // tray app that dies silently is indistinguishable from a Core
        // outage (learned live at the first install, 2026-11-14: the
        // agent crashed in WPF native-library load and only the Windows
        // event log knew). Best-effort; never let logging kill startup.
        try
        {
            if (portable) throw new InvalidOperationException("portable: no persistent log");
            var logDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DeskGuest");
            Directory.CreateDirectory(logDir);
            var logPath = Path.Combine(logDir, "agent-crash.log");
            File.AppendAllText(logPath, $"{DateTimeOffset.Now:O} agent starting (pid {Environment.ProcessId}){Environment.NewLine}");
            AppDomain.CurrentDomain.UnhandledException += (_, args) =>
            {
                try { File.AppendAllText(logPath, $"{DateTimeOffset.Now:O} UNHANDLED: {args.ExceptionObject}{Environment.NewLine}"); } catch { }
            };
            DispatcherUnhandledException += (_, args) =>
            {
                try { File.AppendAllText(logPath, $"{DateTimeOffset.Now:O} DISPATCHER: {args.Exception}{Environment.NewLine}"); } catch { }
            };
            // W20: IPC connection diagnostics land in the same log.
            AgentIpcClient.ConnectionDiagnostic = line =>
            {
                try { File.AppendAllText(logPath, $"{DateTimeOffset.Now:O} {line}{Environment.NewLine}"); } catch { }
            };
        }
        catch { }

        base.OnStartup(e);

        // Portable quick-assist mode (Block F, D24b): the same
        // binary, run with --portable by a person being helped.
        // No host window, no tray, nothing installed; the helper
        // window is the whole surface and closing it ends the run.
        if (e.Args.Any(a => string.Equals(a, "--portable", StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(a, "--quick-assist", StringComparison.OrdinalIgnoreCase)))
        {
            StartPortableHelper();
            return;
        }

        var mainWindow = new MainWindow();
        MainWindow = mainWindow;

        var presence = new PresenceLayer(Dispatcher.CurrentDispatcher);
        var engine = new DesktopEngine(
            glideTo: (x, y) => presence.GlideGhostToAsync(x, y),
            narrate: text => presence.SetNarration(text));
        _engine = engine;
        // BD-SUPP-HELDINPUT F2: startup sweep (see portable path).
        try { engine.SweepStuckInputsOnStartup(); } catch { }
        _ipc = new AgentIpcClient(engine, presence,
            agentVersion: typeof(App).Assembly.GetName().Version?.ToString() ?? "unknown");
        WireOrphanExit();
        // W9 Task 4: the fixture-chosen STOP hotkey (StopHotkeyFixture
        // .DefaultChord), non-disableable, registered for the agent's
        // lifetime; a press sends the same user stop as the tray.
        _stopHotkey = new StopHotkeyHost(async () => { try { await _ipc.RequestUserStopAsync(); } catch { } });

        mainWindow.Attach(presence, () => _ipc.DesktopUnlocked, async (gate, approved) =>
        {
            // Gate approvals from this window travel ONLY over the
            // authenticated IPC channel (C3). If the pipe is down the
            // send throws and the window says the approval was not
            // sent — never a silent pretend-success.
            try { await _ipc.SendGateApprovalAsync(gate, approved); return true; }
            catch { return false; }
        }, async password =>
        {
            // The vault seed travels the same channel under the same
            // rule: a failed send is reported as not-stored, never
            // pretended. The Core's state report comes back on
            // VaultStateReceived and lands on the window's status line.
            try { await _ipc.SendVaultSetAsync(password); return true; }
            catch { return false; }
        }, async () =>
        {
            try { await _ipc.SendVaultWipeAsync(); return true; }
            catch { return false; }
        }, async () =>
        {
            // STOP from this window: same authenticated channel, same
            // honesty rule — a failed send is reported as not sent.
            try { await _ipc.RequestUserStopAsync(); return true; }
            catch { return false; }
        }, async () =>
        {
            try { await _ipc.RequestUserStopClearAsync(); return true; }
            catch { return false; }
        }, async () =>
        {
            // Host-state snapshots for the companion window (M4):
            // requested on open and on a slow poll; the Core answers
            // with facts only.
            try { await _ipc.RequestHostStateAsync(); return true; }
            catch { return false; }
        }, async id =>
        {
            try { await _ipc.RevokePairingAsync(id); return true; }
            catch { return false; }
        }, async (agentName, preset, connectionJson) =>
        {
            try { await _ipc.CreatePairingCodeAsync(agentName, preset, connectionJson); return true; }
            catch { return false; }
        }, async (kind, payload) =>
        {
            // Slice 2/3 host-window actions (Block A): roster, session,
            // and enrollment acts travel ONLY over this authenticated
            // channel, under the same honesty rule as every sender
            // above — a failed send is reported as not sent.
            try { await _ipc.SendHostActionAsync(kind, payload); return true; }
            catch { return false; }
        }, async (pairingId, body) =>
        {
            // W9 Agent chat (Addendum A): the owner's send from the
            // host window, same channel discipline as every sender
            // above — a failed send is reported as not sent and the
            // draft stays in the box.
            try { await _ipc.SendChatMessageAsync(pairingId, body); return true; }
            catch { return false; }
        }, async pairingId =>
        {
            try { await _ipc.RequestChatThreadAsync(pairingId); return true; }
            catch { return false; }
        }, async (pairingId, orderId, answer) =>
        {
            // W120 / S13: the owner's answer on an order card, same
            // channel discipline — a failed send is reported as not
            // sent and the card stays pending.
            try { await _ipc.SendChatOrderAnswerAsync(pairingId, orderId, answer); return true; }
            catch { return false; }
        });
        _ipc.VaultStateReceived += text => mainWindow.SetVaultStatus(text);
        _ipc.HostStateReceived += json =>
        {
            mainWindow.SetHostState(json);
            _lastMeshLine = DeskGuest.Shared.Presence.MeshLineText.FromSnapshotJson(json);
            _openPopup?.SetMeshLine(_lastMeshLine);
        };
        _ipc.PairingCodeReceived += json => mainWindow.SetPairingCode(json);
        _ipc.RecoveryKeySheetReceived += json => mainWindow.SetRecoveryKeySheet(json);
        _ipc.EnrollmentCodeReceived += json => mainWindow.SetEnrollmentCode(json);
        _ipc.OffboardBlastReceived += json => mainWindow.SetOffboardBlast(json);
        _ipc.ActionResultReceived += json => mainWindow.SetActionResult(json);
        _ipc.DiscoveryResultReceived += json => mainWindow.SetDiscoveryResults(json);
        _ipc.QuickAssistCodeReceived += json => mainWindow.SetQuickAssistCode(json);
        // W9: the per-action gate's live caller. A gate request from
        // the Core becomes the §3 GateSheet on the UI thread; the
        // sheet's exit is the answer. Deny-and-end's teardown is the
        // CORE's (audit-first, then session end) — the sheet's local
        // callback stays null here so the ordering lives in exactly
        // one place. A sheet closed with no exit, or any failure to
        // present it, answers DENY: no approval is ever the default.
        _ipc.GateRequestReceived += payloadJson =>
        {
            var request = DeskGuest.Shared.Ipc.GateRequestPayload.Parse(payloadJson);
            if (request is null) return;
            Dispatcher.InvokeAsync(async () =>
            {
                string answer;
                try
                {
                    // FR-120 (W73): the agent asking for control
                    // back is a gate request like any other (tool =
                    // takeover_handback). The owner's approval on
                    // the card IS the hand-back — routed to the
                    // presence layer only on Approved, only while
                    // the owner is actually driving. A denial (or a
                    // dead gate) changes nothing: the owner keeps
                    // driving. The agent has no other path back.
                    var isHandBackAsk = request.Tool == DeskGuest.Shared.Presence.TakeoverGate.HandBackTool;
                    var outcome = GateSheet.Present(
                        DeskGuest.Shared.Ipc.GatePayloadRenderer.Render(
                            presence.ViewState.DisplayName, request.GateClass, request.Tool,
                            request.PayloadBytes()),
                        request.PayloadBytes(), request.FromChat,
                        onDenyAndEnd: null, presence,
                        // FR-114: the prompt's lifecycle is bound to
                        // its gate — the wire request's own expiry,
                        // and the presence layer's session truth as
                        // the session-end probe. Either dying
                        // retires the prompt (no live Approve for a
                        // dead gate).
                        expiresUtc: request.ExpiresUtc,
                        sessionLive: () => presence.ViewState.SessionActive);
                    answer = outcome switch
                    {
                        GateSheet.Outcome.Approved => DeskGuest.Shared.Ipc.GateAnswers.Allow,
                        GateSheet.Outcome.DeniedAndEnded => DeskGuest.Shared.Ipc.GateAnswers.DenyAndEnd,
                        _ => DeskGuest.Shared.Ipc.GateAnswers.Deny,
                    };
                    if (isHandBackAsk && outcome == GateSheet.Outcome.Approved)
                        presence.HandBackToAgent(DeskGuest.Shared.Presence.TakeoverActors.OwnerGateApproval);
                }
                catch { answer = DeskGuest.Shared.Ipc.GateAnswers.Deny; }
                try { await _ipc.SendGateAnswerAsync(request.Id, answer); } catch { /* unsent = NO; the Core's timeout resolves it as a deny */ }
            });
        };
        _ipc.ChatThreadReceived += json => mainWindow.SetChatThread(json);

        _tray = new System.Windows.Forms.NotifyIcon
        {
            Icon = System.Drawing.Icon.ExtractAssociatedIcon(Environment.ProcessPath ?? "")
                ?? System.Drawing.SystemIcons.Shield,
            Text = "DeskGuest",
            Visible = true
        };
        _tray.DoubleClick += (_, _) => { mainWindow.Show(); mainWindow.Activate(); };
        _tray.MouseClick += (_, args) =>
        {
            if (args.Button != System.Windows.Forms.MouseButtons.Left) return;
            var (_, stopInForce, sessionActive, displayName) = (
                presence.ViewState.Mode, presence.ViewState.StopInForce,
                presence.ViewState.SessionActive, presence.ViewState.DisplayName);
            // Ask the Core for a fresh snapshot as the popup opens;
            // the answer lands in the popup live (HostStateReceived
            // above) — the line shown at open is the latest fact the
            // agent holds, never a fetch the popup makes itself.
            _ = Task.Run(async () => { try { await _ipc.RequestHostStateAsync(); } catch { } });
            var popup = new TrayPopup(
                headerLine: _ipc.DesktopUnlocked ? "Running · desktop unlocked" : "Running · desktop locked",
                sessionLine: stopInForce ? $"{displayName} is blocked — STOP is in force"
                    : sessionActive ? $"{displayName} · Active Session"
                    : "No active session",
                sessionSub: stopInForce ? "Clear STOP from the dashboard or the presence box."
                    : sessionActive ? $"{displayName} is controlling your PC"
                    : "Your AI can only control this PC during a visible session.",
                stopInForce: stopInForce,
                meshLine: _lastMeshLine,
                onStop: async () => { try { await _ipc.RequestUserStopAsync(); } catch { } },
                onOpenDashboard: () => { mainWindow.Show(); mainWindow.Activate(); });
            _openPopup = popup;
            popup.Closed += (_, _) => { if (ReferenceEquals(_openPopup, popup)) _openPopup = null; };
            popup.Show();
            popup.PlaceAtTray();
            popup.Activate();
        };

        _cts = new CancellationTokenSource();
        _ = Task.Run(() => _ipc.RunAsync(_cts.Token));

        mainWindow.Show();
    }

    /// <summary>FR-119 (W76): an orphaned agent whose tokens are
    /// all refused exits the process cleanly — OnExit releases held
    /// input and drops the tray icon, and the Core's watchdog
    /// relaunches a fresh agent with a current token.</summary>
    private void WireOrphanExit()
    {
        if (_ipc is null) return;
        _ipc.ExitRequested += () => Dispatcher.BeginInvoke(new Action(() => Shutdown()));
    }

    protected override void OnExit(ExitEventArgs e)
    {
        // U7: the agent process going away is a link loss like any
        // other — never exit with an injected key/button still down.
        try { _engine?.ReleaseAllInputs(); } catch { }
        _stopHotkey?.Dispose();
        _cts?.Cancel();
        if (_tray is not null) { _tray.Visible = false; _tray.Dispose(); }
        base.OnExit(e);
    }
}
