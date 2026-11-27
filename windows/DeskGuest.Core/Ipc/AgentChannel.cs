using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using DeskGuest.Shared.Ipc;
using DeskGuest.Shared.Tools;

namespace DeskGuest.Core.Ipc;

/// <summary>The Core's side of the desktop plane: send a policy-approved
/// tool request to the connected Session Agent and await its result.
/// When no agent is connected the call is honestly unavailable.</summary>
public interface IAgentChannel
{
    bool AgentConnected { get; }
    Task<ToolResult> CallDesktopToolAsync(string tool, string argumentsJson, CancellationToken ct);
}

/// <summary>
/// Named-pipe server for the Session Agent (DESIGN §3.1). One agent
/// connection at a time (per console session in Phase 0); heartbeats
/// feed the watchdog and the state store. On Windows the installer
/// ACLs the pipe to SYSTEM + the owner; the pipe name is product-fixed.
/// </summary>
public sealed class AgentIpcServer : IAgentChannel, Services.IAgentLiveness, IDisposable
{
    public const string PipeName = "deskguest-windows-agent";

    private readonly CoreState _state;
    private readonly string? _expectedToken;
    private readonly string _pipeName;
    private readonly string? _expectedAgentImagePath;
    private readonly Func<NamedPipeServerStream, bool>? _clientVerifier;
    private readonly Shared.Ipc.CoreIdentityKey? _coreIdentity;
    private bool _authenticated;
    private readonly ConcurrentDictionary<string, TaskCompletionSource<IpcMessage>> _pending = new();
    private NamedPipeServerStream? _pipe;
    private StreamWriter? _writer;
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private DateTimeOffset _lastAgentHeartbeatUtc = DateTimeOffset.MinValue;
    private string? _agentVersion;

    /// <param name="expectedToken">Per-boot IPC secret the agent must
    /// present in its Auth message (Text field), after the Core has
    /// proven itself via the Hello/HMAC handshake. Delivery (W20,
    /// revising the BD-WIN-CORE-1 F1 env-only shape on the W19
    /// diagnosis): the Core generates the token per boot and delivers
    /// the SAME secret two ways — the launch environment for agents
    /// it launches itself, and an ACL'd token file (SYSTEM + console
    /// user only, rotated every boot, deleted on clean shutdown —
    /// IpcTokenFile / IpcTokenFileChannel) for task-launched agents,
    /// which can never receive a Core env block. OS identity
    /// (VerifyConnectedClient) is the primary gate and runs whether
    /// or not a token is configured; the token is the mutual-auth
    /// second factor, from either delivery. Null disables the token
    /// leg (unit tests / dev only) — never the OS-identity leg on
    /// Windows.</param>
    public AgentIpcServer(CoreState state, string? expectedToken = null, string? pipeName = null,
        string? expectedAgentImagePath = null, Func<NamedPipeServerStream, bool>? clientVerifier = null,
        Shared.Ipc.CoreIdentityKey? coreIdentity = null)
    {
        _state = state;
        _expectedToken = expectedToken;
        _pipeName = pipeName ?? PipeName;
        _expectedAgentImagePath = expectedAgentImagePath;
        _clientVerifier = clientVerifier;
        _coreIdentity = coreIdentity;
    }

    /// <summary>W25: build the HelloAck for one Hello — the HMAC
    /// proof (Text) PLUS, when this Core holds an identity key,
    /// the Ed25519 signature over the nonce in the payload
    /// (CoreIdentity.BuildHelloAckProof). Factored out so the
    /// harness pins the ack's exact shape off-pipe. A Core with
    /// no identity key sends a payload-less ack, and a W25 Agent
    /// refuses it: the signature is the identity proof, the HMAC
    /// alone no longer suffices.</summary>
    internal static IpcMessage BuildHelloAck(string expectedToken, string nonce, Shared.Ipc.CoreIdentityKey? coreIdentity) =>
        new(IpcKinds.HelloAck, null, null,
            coreIdentity is null ? null : Shared.Ipc.CoreIdentity.BuildHelloAckProof(coreIdentity, nonce),
            null, IpcAuth.ComputeHelloAck(expectedToken, nonce), null, null, null, null);

    /// <summary>BD-WIN-CORE-1 F1: the IPC token alone no longer
    /// authenticates the session agent. On Windows (and whenever a
    /// verifier is injected, e.g. tests), the connected client's OS
    /// identity is verified BEFORE any message is read: the client
    /// process must run in the active console session, as the console
    /// user (never SYSTEM), from the expected agent image. A process
    /// that merely read the token — e.g. an agent tool running as
    /// SYSTEM via shell_exec_system — fails every one of these facts,
    /// which it cannot assert or forge through the payload.</summary>
    private bool VerifyConnectedClient(NamedPipeServerStream pipe)
    {
        if (_clientVerifier is not null) return _clientVerifier(pipe);
        // W10 / V2-X2: the pre-fix shape skipped OS verification
        // entirely when no token was configured — a host wiring that
        // ever passed a null token silently accepted ANY client as
        // the owner's agent. On Windows the OS identity check now
        // runs WHATEVER the token configuration; the token remains
        // the mutual-auth second factor, not the switch that turns
        // identity checking on. (Off-Windows there is no Windows
        // identity to check — the sandbox/dev posture, named.)
        if (!OperatingSystem.IsWindows()) return true;
        try { return IpcClientIdentity.VerifyWindows(pipe, _expectedAgentImagePath); }
        catch { return false; } // fail closed: an unverifiable client is not the owner's UI
    }

    /// <summary>Whether the currently connected agent has authenticated.
    /// Desktop calls are refused until it has.</summary>
    public bool AgentAuthenticated => _expectedToken is null || _authenticated;

    public bool AgentConnected => _pipe is { IsConnected: true };
    public DateTimeOffset LastAgentHeartbeatUtc => _lastAgentHeartbeatUtc;
    public string? AgentVersion => _agentVersion;

    /// <summary>U2: event bus + live-session pairing provider,
    /// wired by CoreRuntime. Foreground reports become
    /// foreground_app / screen_change events, origin-scoped to the
    /// live session's pairing when one is live (desktop facts seen
    /// during a pairing's session belong to that pairing).</summary>
    public Shared.Sessions.AgentEventBus? Events { get; set; }
    public Func<string?>? LivePairingIdProvider { get; set; }
    private string? _lastFgTitle;
    private string? _lastFgProcess;

    private void PublishForegroundIfChanged(string? title, string? process)
    {
        if (Events is null) return;
        if (title == _lastFgTitle && process == _lastFgProcess) return;
        var hadPrevious = _lastFgTitle is not null || _lastFgProcess is not null;
        _lastFgTitle = title; _lastFgProcess = process;
        var origin = LivePairingIdProvider?.Invoke();
        Events.Publish(Shared.Sessions.AgentEventKinds.ForegroundApp,
            $"foreground_app: {process ?? "?"} — {title ?? ""}", origin);
        if (hadPrevious)
            Events.Publish(Shared.Sessions.AgentEventKinds.ScreenChange,
                $"screen_change: foreground is now {process ?? "?"} — {title ?? ""}", origin);
    }

    /// <summary>Raised when the agent reports a session-state change.</summary>
    public event Action<IpcMessage>? AgentMessageReceived;

    /// <summary>Raised when an agent connection that had connected
    /// is lost (agent died, Core-side drop/restart, pipe teardown) —
    /// the U7 link-loss signal. CoreRuntime ends any live agent
    /// session on it immediately rather than waiting for the idle
    /// timeout: while the desktop plane is unreachable, nothing may
    /// keep acting in the session's name, and the agent releases any
    /// held input on its own side of the same drop.</summary>
    public event Action? AgentConnectionDropped;

    public async Task RunAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try { _pipe = CreatePipe(); }
            catch (Exception)
            {
                // W10 / V2-C5: pipe construction FAILED CLOSED (e.g.
                // the ACL could not be built). There is no fallback
                // pipe — the server simply does not listen until
                // construction succeeds. Retry slowly; the watchdog
                // surfaces a Core whose agent channel never comes up.
                try { await Task.Delay(TimeSpan.FromSeconds(1), ct); } catch (OperationCanceledException) { break; }
                continue;
            }
            var connected = false;
            try
            {
                await _pipe.WaitForConnectionAsync(ct);
                connected = true;
                if (!VerifyConnectedClient(_pipe))
                {
                    // Not the owner's session agent by OS facts —
                    // drop without reading a single message: no
                    // state changes, no responses, no token oracle.
                    try { _pipe.Disconnect(); } catch { }
                    continue;
                }
                _lastAgentHeartbeatUtc = DateTimeOffset.UtcNow;
                await ReadLoopAsync(_pipe, ct);
            }
            catch (OperationCanceledException) { break; }
            catch (IOException) { /* agent died; loop and accept the next one */ }
            finally
            {
                _authenticated = false;
                _state.UpdateSession(s => s with { AgentConnected = false });
                try { _pipe?.Dispose(); } catch { }
                _pipe = null;
                if (connected)
                {
                    try { AgentConnectionDropped?.Invoke(); } catch { /* a handler fault never kills the accept loop */ }
                }
            }
        }
    }

    private async Task ReadLoopAsync(NamedPipeServerStream pipe, CancellationToken ct)
    {
        while (pipe.IsConnected && !ct.IsCancellationRequested)
        {
            // BD-SHARED-SESSION F12: before Auth, frames are capped
            // at the pre-auth limit — no 64 MB allocation on an
            // unauthenticated peer's say-so.
            var json = await IpcFraming.ReadAsync(pipe, ct,
                _authenticated ? IpcFraming.MaxFrameBytes : IpcFraming.PreAuthMaxFrameBytes);
            if (json is null) break;
            IpcMessage? msg;
            try { msg = JsonSerializer.Deserialize<IpcMessage>(json); } catch (JsonException) { continue; }
            if (msg is null) continue;

            if (_expectedToken is not null && !_authenticated && msg.Kind != IpcKinds.Hello && msg.Kind != IpcKinds.Auth)
                continue; // unauthenticated noise: no state changes, no responses (C2)
            // BD-SHARED-SESSION F1 + W10 / V2-C4: consent-class kinds
            // (gate approval, pairing-code mint, session acts, vault
            // set, CLEAR STOP) are honored ONLY with a physical-human
            // provenance assertion — in EVERY session state, not only
            // while a session is live (the pre-fix shape applied the
            // bare message whenever no session was live). An injected
            // click the controlling agent made itself is not the
            // person at the keyboard, and neither is an unasserted
            // message on an authenticated channel alone.
            if (IpcConsent.IsConsentKind(msg.Kind) &&
                !IpcConsent.CanHonor(msg, _state.Session.SessionExists && _state.Session.AgentConnected))
                continue;
            switch (msg.Kind)
            {
                case IpcKinds.Hello:
                    // Mutual-auth step 1 (2026-11-15 blocker fix): the
                    // Hello carries NO secret any more — only a fresh
                    // nonce. We prove ourselves with an HMAC over the
                    // nonce keyed by the token; the agent presents the
                    // token (Auth) only after verifying that proof, so
                    // a squatter pipe learns nothing and is never
                    // trusted with vault material.
                    _agentVersion = msg.AgentVersion;
                    if (_expectedToken is null)
                    {
                        _authenticated = true; // dev/test posture: no token configured
                        _state.UpdateSession(s => s with { AgentConnected = true });
                        _state.ApplyAgentSessionReport(msg.DesktopUnlocked, msg.TakeoverActive, msg.ForegroundTitle, msg.ForegroundProcess);
                        break;
                    }
                    string? nonce = null;
                    try
                    {
                        if (msg.ArgumentsJson is not null && JsonDocument.Parse(msg.ArgumentsJson).RootElement.TryGetProperty("nonce", out var n))
                            nonce = n.GetString();
                    }
                    catch (JsonException) { }
                    if (string.IsNullOrWhiteSpace(nonce))
                        return; // no nonce, no proof possible: drop
                    await NotifyAgentAsync(BuildHelloAck(_expectedToken, nonce, _coreIdentity), ct);
                    break;
                case IpcKinds.Auth:
                    if (_expectedToken is not null && msg.Text != _expectedToken)
                        return; // wrong handshake secret: drop the connection entirely
                    _authenticated = true;
                    _agentVersion = msg.AgentVersion ?? _agentVersion;
                    _state.AgentVersion = _agentVersion ?? _state.AgentVersion;
                    _state.UpdateSession(s => s with { AgentConnected = true });
                    _state.ApplyAgentSessionReport(msg.DesktopUnlocked, msg.TakeoverActive, msg.ForegroundTitle, msg.ForegroundProcess);
                    break;
                case IpcKinds.Heartbeat:
                    _lastAgentHeartbeatUtc = DateTimeOffset.UtcNow;
                    _state.UpdateSession(s => s with { AgentConnected = true });
                    break;
                case IpcKinds.SessionState:
                    _state.ApplyAgentSessionReport(msg.DesktopUnlocked, msg.TakeoverActive, msg.ForegroundTitle, msg.ForegroundProcess);
                    PublishForegroundIfChanged(msg.ForegroundTitle, msg.ForegroundProcess);
                    break;
                case IpcKinds.UserStop:
                    _state.SetUserStop(true);
                    break;
                case IpcKinds.UserStopClear:
                    // The exit from the blocked state (M1, 2026-11-17):
                    // arrives only over this authenticated channel from
                    // the laptop UI, like UserStop itself — and, as a
                    // consent-class kind, only with the physical-human
                    // provenance assertion the consent guard above has
                    // already required (W10 / V2-C4). CoreRuntime
                    // audits it via AgentMessageReceived.
                    _state.SetUserStop(false);
                    break;
                case IpcKinds.ToolResponse:
                    if (msg.RequestId is not null && _pending.TryRemove(msg.RequestId, out var tcs))
                    {
                        tcs.TrySetResult(msg);
                    }
                    break;
                case IpcKinds.GateAnswer:
                    // W9 per-action gate: an answer completes ONLY
                    // the pending request whose id BOTH the frame and
                    // the payload name (GateRequestPayload.ParseAnswer
                    // refuses a disagreement — an answer cannot be
                    // re-pointed at another pending request). The
                    // consent-class guard above has already refused
                    // agent-injected answers during a live session;
                    // the broker (CoreRuntime's raiser) binds the
                    // answer to the exact request, pairing and
                    // session, consumes it once, and refuses replays.
                    if (msg.RequestId is not null &&
                        GateRequestPayload.ParseAnswer(msg.ArgumentsJson, msg.RequestId) is not null &&
                        _pending.TryRemove(msg.RequestId, out var gateTcs))
                    {
                        gateTcs.TrySetResult(msg);
                    }
                    break;
            }
            AgentMessageReceived?.Invoke(msg);
        }
    }

    /// <summary>Build the agent pipe's ACL: SYSTEM + Administrators
    /// + the owner account (DESKGUEST_LOGON_USER) only. Extracted so the
    /// failure mode is directly testable: a bad owner account makes
    /// NTAccount.Translate throw, and that exception is the signal
    /// CreatePipe fails closed on (W10 / V2-C5).</summary>
    internal static PipeSecurity BuildPipeSecurity(string? ownerAccount)
    {
        var security = new PipeSecurity();
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        if (!string.IsNullOrWhiteSpace(ownerAccount))
        {
            var sid = new NTAccount(ownerAccount).Translate(typeof(SecurityIdentifier));
            security.AddAccessRule(new PipeAccessRule(sid, PipeAccessRights.ReadWrite, AccessControlType.Allow));
        }
        return security;
    }

    /// <summary>W69 (FR-116): who the pipe's owner grant names. The
    /// DESKGUEST_LOGON_USER env var wins when set (the installer / standing
    /// launch script sets it). When it is UNSET, the pre-fix code
    /// granted SYSTEM + Administrators only — and in the Path B
    /// console-host shape (Core running as the console user, launched
    /// directly without the env var) the Session Agent, running as
    /// that same user at medium integrity, could not connect AT ALL:
    /// every connect was "Access to the path is denied", the agent
    /// retried forever, and AgentConnected stayed false with no
    /// Core-side error anywhere (proven live 2026-11-23, W65 deploy:
    /// launch env omitted DESKGUEST_LOGON_USER; W57's launch script set it
    /// and the same build authenticated). The fallback derives the
    /// SAME fact — the console session's logon account — from the OS
    /// (WTS session information, no privilege required), so a launch
    /// that forgets the env var degrades to the correct grant instead
    /// of a silent deadlock. Derivation failure keeps the fail-closed
    /// SYSTEM + Administrators ACL.</summary>
    internal static string? ResolvePipeOwnerAccount(string? envValue, string? derivedValue) =>
        !string.IsNullOrWhiteSpace(envValue) ? envValue
        : !string.IsNullOrWhiteSpace(derivedValue) ? derivedValue
        : null;

    private NamedPipeServerStream CreatePipe()
    {
        // W10 / V2-C5: the WINDOWS branch creates the pipe with
        // PipeOptions.FirstPipeInstance — if another process already
        // owns the pipe name, creation throws instead of queueing
        // behind a squatter (the CP pipe already had this discipline;
        // the agent pipe did not). The off-Windows branch is the
        // dev/test posture (no ACL API exists there); it keeps the
        // multi-instance shape the in-process test runtimes rely on.
        if (!OperatingSystem.IsWindows())
            return new NamedPipeServerStream(_pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        // Windows: ACL the pipe itself — SYSTEM + Administrators + the
        // owner account only. (The code comment that used to claim "the
        // installer ACLs the pipe" was wrong: a pipe's security must be
        // set at creation, by the creating process. C2.)
        // W10 / V2-C5: ACL construction failure is FAIL CLOSED. The
        // pre-fix catch fell back to a pipe with the DEFAULT ACL —
        // a bad DESKGUEST_LOGON_USER silently produced an under-ACL'd pipe
        // "because the token handshake still gates everything". Now
        // the exception propagates and RunAsync retries without ever
        // listening on an under-ACL'd pipe.
        var security = BuildPipeSecurity(ResolvePipeOwnerAccount(
            Environment.GetEnvironmentVariable("DESKGUEST_LOGON_USER"),
            IpcClientIdentity.ConsoleUserAccountName()));
        return NamedPipeServerStreamAcl.Create(_pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous | PipeOptions.FirstPipeInstance, 0, 0, security);
    }

    public async Task<ToolResult> CallDesktopToolAsync(string tool, string argumentsJson, CancellationToken ct)
    {
        if (!AgentAuthenticated)
            return ToolResult.Unavailable("the session agent has not authenticated to the Core (IPC handshake incomplete)");
        var pipe = _pipe;
        if (pipe is null || !pipe.IsConnected)
            return ToolResult.Unavailable("session agent not connected (no interactive session, or the agent is down)");

        var requestId = Guid.NewGuid().ToString("N");
        var tcs = new TaskCompletionSource<IpcMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        _pending[requestId] = tcs;
        var request = new IpcMessage(IpcKinds.ToolRequest, requestId, tool, argumentsJson, null, null, null, null, null, null);
        await _writeLock.WaitAsync(ct);
        try { await IpcFraming.WriteAsync(pipe, JsonSerializer.Serialize(request), ct); }
        finally { _writeLock.Release(); }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(60));
        try
        {
            var response = await tcs.Task.WaitAsync(timeout.Token);
            return response.Ok == true
                ? ToolResult.Success(response.Text ?? "")
                : ToolResult.Unavailable(response.Text ?? "desktop tool failed in the session agent");
        }
        catch (OperationCanceledException)
        {
            _pending.TryRemove(requestId, out _);
            return ToolResult.Error("agent_timeout", "the session agent did not answer within 60s");
        }
    }

    /// <summary>W9: raise one per-action gate request to the Session
    /// Agent and await its GateSheet answer. Returns the answer
    /// message, or null when no authenticated agent is connected or
    /// no answer arrives within <paramref name="timeout"/> — the
    /// caller treats null as NO (a gate nobody answers is a deny,
    /// never a stall and never a yes). The pending entry is keyed by
    /// the request's own id, so concurrent gates cannot cross.</summary>
    public async Task<IpcMessage?> RequestGateAnswerAsync(GateRequest request, TimeSpan timeout, CancellationToken ct)
    {
        if (!AgentAuthenticated) return null;
        var pipe = _pipe;
        if (pipe is null || !pipe.IsConnected) return null;

        var tcs = new TaskCompletionSource<IpcMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!_pending.TryAdd(request.Id, tcs)) return null;
        var message = new IpcMessage(IpcKinds.GateRequest, request.Id, request.Tool,
            GateRequestPayload.Build(request), null, null, null, null, null, null);
        await _writeLock.WaitAsync(ct);
        try { await IpcFraming.WriteAsync(pipe, JsonSerializer.Serialize(message), ct); }
        catch { _pending.TryRemove(request.Id, out _); return null; }
        finally { _writeLock.Release(); }

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(timeout);
        try
        {
            return await tcs.Task.WaitAsync(deadline.Token);
        }
        catch (OperationCanceledException)
        {
            _pending.TryRemove(request.Id, out _);
            return null;
        }
    }

    /// <summary>Drop the current agent connection (supervisor restart
    /// path, census row 86): the read loop exits, state flips to
    /// not-connected, and the watchdog relaunches the agent.</summary>
    public void DropConnection()
    {
        try { _pipe?.Dispose(); } catch { }
    }

    /// <summary>Tell the agent presence state (session start/stop, STOP).</summary>
    public async Task NotifyAgentAsync(IpcMessage message, CancellationToken ct)
    {
        var pipe = _pipe;
        if (pipe is null || !pipe.IsConnected) return;
        await _writeLock.WaitAsync(ct);
        try { await IpcFraming.WriteAsync(pipe, JsonSerializer.Serialize(message), ct); }
        finally { _writeLock.Release(); }
    }

    public void Dispose()
    {
        try { _pipe?.Dispose(); } catch { }
        _writeLock.Dispose();
    }
}

/// <summary>OS-derived facts about a connected IPC client process,
/// plus the pure policy over them (BD-WIN-CORE-1 F1). The facts come
/// from the kernel (pipe client PID → session, token SID, image
/// path); none of them can be supplied or influenced by the client's
/// payload.</summary>
public sealed record IpcClientFacts(
    uint ClientSessionId, uint ConsoleSessionId,
    string? ClientUserSid, string? ConsoleUserSid, bool ClientIsSystem,
    string? ClientImagePath, string? ExpectedImagePath);

public static class IpcClientIdentity
{
    public static bool Evaluate(IpcClientFacts f)
    {
        if (f.ClientIsSystem) return false;                       // SYSTEM-spawned clients refuse (shell_exec_system is SYSTEM)
        if (f.ConsoleSessionId == 0xFFFFFFFF) return false;        // no console session: nobody at the laptop
        if (f.ClientSessionId != f.ConsoleSessionId) return false; // must be the interactive session
        if (string.IsNullOrEmpty(f.ClientUserSid) || string.IsNullOrEmpty(f.ConsoleUserSid)) return false;
        if (!string.Equals(f.ClientUserSid, f.ConsoleUserSid, StringComparison.OrdinalIgnoreCase)) return false;
        if (!string.IsNullOrEmpty(f.ExpectedImagePath))
        {
            if (string.IsNullOrEmpty(f.ClientImagePath)) return false;
            var expected = f.ExpectedImagePath!;
            var actual = f.ClientImagePath!;
            // W10 / V2-X1: the pre-fix policy accepted a BARE file
            // name as the expected image and compared names only —
            // any same-named binary in any directory passed (a
            // SYSTEM process can plant one in the console session).
            // The expected image must now be a fully qualified path
            // (production Program.cs passes exactly that); a bare
            // name FAILS CLOSED instead of weakening the check.
            // Compared under WindowsPath semantics: these are
            // Windows paths wherever the decision runs.
            if (!WindowsPath.IsFullyQualified(expected)) return false;
            if (!WindowsPath.EqualsFull(actual, expected)) return false;
        }
        return true;
    }

    /// <summary>Collect the facts for the connected pipe client from
    /// Windows itself. Any failure throws; the caller fails closed.</summary>
    public static bool VerifyWindows(NamedPipeServerStream pipe, string? expectedImagePath)
    {
        if (!Native.GetNamedPipeClientProcessId(pipe.SafePipeHandle.DangerousGetHandle(), out var pid) || pid == 0)
            return false;
        if (!Native.ProcessIdToSessionId(pid, out var clientSession)) return false;
        var consoleSession = Native.WTSGetActiveConsoleSessionId();
        var process = Native.OpenProcess(0x1000 /* PROCESS_QUERY_LIMITED_INFORMATION */, false, pid);
        if (process == IntPtr.Zero) return false;
        try
        {
            var image = QueryImagePath(process);
            if (!Native.OpenProcessToken(process, 0x0008 /* TOKEN_QUERY */, out var token)) return false;
            string? clientSid;
            try { clientSid = SidOf(token); } finally { Native.CloseHandle(token); }
            string? consoleSid = null;
            if (consoleSession != 0xFFFFFFFF && Native.WTSQueryUserToken(consoleSession, out var userToken))
            {
                using (userToken) consoleSid = new WindowsIdentity(userToken.DangerousGetHandle()).User?.Value;
            }
            // W20 (console-host shape): WTSQueryUserToken requires
            // SE_TCB — a SYSTEM-only privilege. A Core running as
            // the console user (the Path B console host) can never
            // hold it, so the token route fails with
            // ERROR_PRIVILEGE_NOT_HELD and the pre-fix code derived
            // a null console SID, which Evaluate refuses — the
            // console-host Core dropped EVERY agent, however genuine
            // (proven live in the W20 deploy: agent facts all
            // correct, connection dropped pre-Hello). The fallback
            // derives the SAME fact — the console session's logon
            // user's SID — from WTS session information (user +
            // domain names, no privilege required) resolved through
            // NTAccount. It is an OS fact about the SESSION, never
            // about the connected client, so the policy in Evaluate
            // is untouched: client SID must still equal it.
            if (consoleSid is null && consoleSession != 0xFFFFFFFF)
                consoleSid = ConsoleUserSidFromSessionInfo(consoleSession);
            var isSystem = clientSid is not null &&
                new SecurityIdentifier(clientSid).IsWellKnown(WellKnownSidType.LocalSystemSid);
            return Evaluate(new IpcClientFacts(clientSession, consoleSession, clientSid, consoleSid, isSystem, image, expectedImagePath));
        }
        finally { Native.CloseHandle(process); }
    }

    /// <summary>W20: the console session's logon user SID from
    /// WTSQuerySessionInformation (WTSUserName + WTSDomainName) —
    /// the unprivileged route to the same fact WTSQueryUserToken
    /// gives a SYSTEM caller. Null on any failure (fail closed:
    /// Evaluate refuses a null console SID).</summary>
    private static string? QuerySessionString(uint sessionId, int infoClass)
    {
        if (!Native.WTSQuerySessionInformation(IntPtr.Zero, sessionId, infoClass, out var buffer, out _))
            return null;
        try { return Marshal.PtrToStringUni(buffer); }
        finally { Native.WTSFreeMemory(buffer); }
    }

    /// <summary>W69 (FR-116): the ACTIVE CONSOLE session's logon
    /// account as an NTAccount name ("DOMAIN\user", or bare "user"
    /// when the session reports no domain) — the account the agent
    /// pipe's owner grant must name when DESKGUEST_LOGON_USER is unset
    /// (see AgentIpcServer.ResolvePipeOwnerAccount). Same
    /// unprivileged WTS session-information route as the console SID
    /// below; null when there is no console session or the session
    /// reports no user (fail closed: no owner grant is added).</summary>
    public static string? ConsoleUserAccountName()
    {
        var sessionId = Native.WTSGetActiveConsoleSessionId();
        if (sessionId == 0xFFFFFFFF) return null;
        var user = QuerySessionString(sessionId, 5 /* WTSUserName */);
        if (string.IsNullOrWhiteSpace(user)) return null;
        var domain = QuerySessionString(sessionId, 7 /* WTSDomainName */);
        return string.IsNullOrWhiteSpace(domain) ? user : $@"{domain}\{user}";
    }

    private static string? ConsoleUserSidFromSessionInfo(uint sessionId)
    {
        string? Query(int infoClass) => QuerySessionString(sessionId, infoClass);
        var user = Query(5 /* WTSUserName */);
        var domain = Query(7 /* WTSDomainName */);
        if (string.IsNullOrWhiteSpace(user)) return null;
        try
        {
            var account = string.IsNullOrWhiteSpace(domain) ? new NTAccount(user) : new NTAccount(domain, user);
            return (account.Translate(typeof(SecurityIdentifier)) as SecurityIdentifier)?.Value;
        }
        catch { return null; }
    }

    private static string? SidOf(IntPtr token)
    {
        if (!Native.GetTokenInformation(token, 1 /* TokenUser */, IntPtr.Zero, 0, out var len) && len == 0) return null;
        var buf = Marshal.AllocHGlobal(len);
        try
        {
            if (!Native.GetTokenInformation(token, 1, buf, len, out _)) return null;
            var sidPtr = Marshal.PtrToStructure<Native.TokenUser>(buf).Sid;
            return new SecurityIdentifier(sidPtr).Value;
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    private static string? QueryImagePath(IntPtr process)
    {
        var sb = new StringBuilder(1024);
        var size = (uint)sb.Capacity;
        return Native.QueryFullProcessImageName(process, 0, sb, ref size) ? sb.ToString() : null;
    }

    private static class Native
    {
        [StructLayout(LayoutKind.Sequential)] public struct TokenUser { public IntPtr Sid; }
        [DllImport("kernel32.dll", SetLastError = true)] public static extern bool GetNamedPipeClientProcessId(IntPtr pipe, out uint clientProcessId);
        [DllImport("kernel32.dll", SetLastError = true)] public static extern bool ProcessIdToSessionId(uint pid, out uint sessionId);
        [DllImport("kernel32.dll")] public static extern uint WTSGetActiveConsoleSessionId();
        [DllImport("kernel32.dll", SetLastError = true)] public static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] public static extern bool QueryFullProcessImageName(IntPtr process, uint flags, StringBuilder name, ref uint size);
        [DllImport("advapi32.dll", SetLastError = true)] public static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
        [DllImport("advapi32.dll", SetLastError = true)] public static extern bool GetTokenInformation(IntPtr token, int cls, IntPtr info, int len, out int retLen);
        [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
        [DllImport("wtsapi32.dll", SetLastError = true)] public static extern bool WTSQueryUserToken(uint sessionId, out Microsoft.Win32.SafeHandles.SafeAccessTokenHandle token);
        [DllImport("wtsapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] public static extern bool WTSQuerySessionInformation(IntPtr server, uint sessionId, int infoClass, out IntPtr buffer, out uint bytesReturned);
        [DllImport("wtsapi32.dll")] public static extern void WTSFreeMemory(IntPtr memory);
    }
}

/// <summary>Test double for the desktop plane.</summary>
public sealed class FakeAgentChannel : IAgentChannel
{
    public bool AgentConnected { get; set; } = true;
    public Func<string, string, ToolResult>? Handler { get; set; }
    public List<(string Tool, string Args)> Calls { get; } = new();

    public Task<ToolResult> CallDesktopToolAsync(string tool, string argumentsJson, CancellationToken ct)
    {
        Calls.Add((tool, argumentsJson));
        if (!AgentConnected) return Task.FromResult(ToolResult.Unavailable("session agent not connected"));
        return Task.FromResult(Handler?.Invoke(tool, argumentsJson) ?? ToolResult.Success("fake desktop result"));
    }
}
