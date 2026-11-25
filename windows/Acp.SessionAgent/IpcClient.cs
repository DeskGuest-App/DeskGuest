using System.IO;
using System.IO.Pipes;
using System.Text.Json;
using Acp.Shared.Ipc;
using Acp.Shared.Policy;
using Acp.Shared.Presence;

namespace Acp.SessionAgent;

/// <summary>
/// The Agent's side of the Core IPC (DESIGN §3.1/§3.2). The client
/// retries the connection forever with backoff — the Agent must not die
/// because the Core is restarting, the mirror of the Core's lane rule.
/// The Agent holds no credentials and no policy authority: it executes
/// what arrives (already policy-approved) and reports honestly.
/// </summary>
public sealed class AgentIpcClient
{
    private readonly DesktopEngine _engine;
    private readonly PresenceLayer _presence;
    private readonly string _agentVersion;
    private NamedPipeClientStream? _pipe;
    private readonly SemaphoreSlim _writeLock = new(1, 1);

    // BD-WIN-AGENT F5: tool requests run OFF the read loop under this
    // coordinator's token, so StopAll / ReleaseInputs / presence-off
    // are handled the moment they arrive — never queued behind a
    // running tool — and STOP cancels the in-flight tool.
    private readonly StopCoordinator _stop = new();

    /// <summary>Raised when local session facts change (lock state poll).</summary>
    public bool DesktopUnlocked => NativeMethods.InputDesktopIsDefault();

    /// <summary>W20 live-diagnosis hook: the App wires this to the
    /// agent-crash.log. A tray agent whose handshake fails silently
    /// is indistinguishable from a Core outage (the App's own
    /// startup-log rationale); the retry loop therefore reports each
    /// DISTINCT connection failure once — type + message, never any
    /// token material — and reports recovery when a connection
    /// finally authenticates.</summary>
    public static Action<string>? ConnectionDiagnostic;
    private string? _lastDiagnostic;

    // FR-119 (W76): bounded orphan handling. The token retry
    // policy (pure, in Acp.Shared) counts AUTH failures per token
    // source: a stale ENV token (this process was launched by a
    // Core that has since restarted and rotated the secret) is
    // rejected after the bounded count and resolution falls back
    // to the token FILE (the current boot's published secret);
    // when no sanctioned token this process can present works,
    // the policy latches ShouldExit and RunAsync ends so the host
    // can exit cleanly — the Core's watchdog then relaunches a
    // fresh agent with a current token (the W69-proven recovery).
    private readonly IpcTokenFile.TokenRetryPolicy _tokenPolicy = new();
    private IpcTokenSource _presentedSource = IpcTokenSource.None;
    private bool _exitForOrphan;

    /// <summary>FR-119: raised once when RunAsync ends because this
    /// agent is an orphan whose tokens are all refused — the host
    /// (App) shuts the process down cleanly on this signal.</summary>
    public event Action? ExitRequested;

    public AgentIpcClient(DesktopEngine engine, PresenceLayer presence, string agentVersion)
    {
        _engine = engine;
        _presence = presence;
        _agentVersion = agentVersion;
    }

    /// <summary>The Core's per-boot IPC secret (C2). The Core (SYSTEM)
    /// writes it into the data dir, ACL'd to SYSTEM + the owner; this
    /// agent runs AS the owner, so it can read it — a random local
    /// process running as someone else cannot. Presented in Hello;
    /// the Core drops connections that get it wrong.</summary>
    private (string? Token, IpcTokenSource Source) ReadIpcToken()
    {
        // W20 token channel (the BD-WIN-CORE-1 F1 env-only delivery
        // deadlocked task-launched agents — W19 diagnosis Defect B):
        // the SAME per-boot secret arrives by (a) the launch
        // environment (ACP_IPC_TOKEN, set by the Core's
        // CreateProcessAsUser environment block) when the Core
        // launched us, or (b) the Core-published token file in the
        // Core data dir, ACL'd to SYSTEM + the console user — this
        // agent runs AS the console user, so it can read it; a
        // process running as a different user cannot, and an
        // unreadable file resolves exactly like an absent one
        // (RefuseNoToken stands). The source is labelled in the
        // Hello payload; the Core audits it. Env wins when both
        // exist (IpcTokenFile.Resolve).
        // FR-119 (W76): the raw channels are re-read on EVERY
        // attempt and the retry policy picks which one is presented
        // — normally env (unchanged), but after the bounded count
        // of auth failures on a stale env token, the file (which
        // the CURRENT Core boot published) wins, so an orphaned
        // agent recovers instead of spinning forever.
        var fromEnv = Environment.GetEnvironmentVariable(IpcTokenFile.TokenEnvironmentVariable);
        string? fromFile = null;
        try
        {
            var path = Environment.GetEnvironmentVariable(IpcTokenFile.FileEnvironmentVariable)
                ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "ACP", "data", IpcTokenFile.FileName);
            fromFile = IpcTokenFile.Read(path);
        }
        catch { fromFile = null; }
        return _tokenPolicy.Current(fromEnv, fromFile);
    }

    /// <summary>True only after the Core has PROVEN itself (HelloAck
    /// HMAC verified) and we have presented the token. Vault and gate
    /// traffic is refused until this is set (2026-11-15 blocker fix:
    /// the agent previously trusted whatever hosted the pipe name —
    /// a squatter would have received the token and vault passwords).</summary>
    private bool _coreAuthenticated;
    /// <summary>W8: the previous directive's live-session truth —
    /// the presence self-test runs on the inactive→active edge.</summary>
    private bool _sessionWasActive;

    /// <summary>FR-120 (W73): the local-input watcher — runs only
    /// while a session is live.</summary>
    private LocalInputWatcher? _watcher;

    public async Task RunAsync(CancellationToken ct)
    {
        // U7: a local STOP press releases held input FIRST, locally —
        // the release must not wait for (or depend on) the Core
        // round-trip; if the link is already dead, the press still
        // has to let go of the machine.
        // BD-WIN-AGENT F5: the press also CANCELS the running tool —
        // releasing held keys alone left a long type_text typing and
        // a shell_exec running after STOP.
        _presence.StopPressed += () => { _stop.CancelCurrentWork(); _engine.ReleaseAllInputs(); _ = SendUserStopQuietAsync(); };
        _presence.StopClearPressed += () => _ = SendUserStopClearQuietAsync();
        // FR-120 (W73): the takeover session-record feed. Every
        // yield / hand-back / hotkey / mode change the presence
        // layer raises is reported to the Core on the takeover_
        // event kind; the Core appends it to the audit chain (the
        // agent session's record). Reports only — this feed can
        // set nothing. The local-input watcher is created here and
        // runs only while a session is live (presence case below).
        _watcher ??= new LocalInputWatcher(_presence);
        _presence.TakeoverYielded += inputClass =>
        {
            _ = SendTakeoverEventQuietAsync(TakeoverRecordKinds.Yield, TakeoverActors.LocalInput,
                TakeoverRecordDetail.Yield(inputClass));
            _ = SendSessionStateQuietAsync();
        };
        _presence.TakeoverHotkeyYielded += () =>
        {
            _ = SendTakeoverEventQuietAsync(TakeoverRecordKinds.Hotkey, TakeoverActors.OwnerHotkey,
                "takeover hotkey yielded driving to the owner");
            _ = SendSessionStateQuietAsync();
        };
        _presence.TakeoverHandedBack += actor =>
        {
            _ = SendTakeoverEventQuietAsync(TakeoverRecordKinds.HandBack, actor,
                TakeoverRecordDetail.HandBack(actor));
            _ = SendSessionStateQuietAsync();
        };
        // FR-130: the boundary reconciliation is an audit fact —
        // a latched pill corrected itself, and the chain says so.
        _presence.TakeoverReconciled += () =>
            _ = SendTakeoverEventQuietAsync(TakeoverRecordKinds.Reconciled,
                TakeoverActors.PresenceReconciliation, TakeoverRecordDetail.Reconciled());
        _presence.TakeoverModesChanged += (oldMouse, oldKeyboard, newMouse, newKeyboard) =>
        {
            // The actor distinction (FR-120 ownership rule): a
            // change while a session is live arrived IN SESSION;
            // otherwise it is the owner at the machine, local.
            var actor = _sessionWasActive ? TakeoverActors.InSession : TakeoverActors.OwnerLocal;
            if (newMouse != oldMouse)
                _ = SendTakeoverEventQuietAsync(TakeoverRecordKinds.ModeChanged, actor,
                    TakeoverRecordDetail.ModeChange(TakeoverInputClass.Mouse, oldMouse, newMouse));
            if (newKeyboard != oldKeyboard)
                _ = SendTakeoverEventQuietAsync(TakeoverRecordKinds.ModeChanged, actor,
                    TakeoverRecordDetail.ModeChange(TakeoverInputClass.Keyboard, oldKeyboard, newKeyboard));
        };
        while (!ct.IsCancellationRequested)
        {
            // FR-119: a failure BEFORE the pipe connects is "Core
            // down or restarting" and never counts against any
            // token; a failure AFTER connect is a handshake/auth
            // failure and is recorded against the presented source.
            var connected = false;
            try
            {
                _pipe = new NamedPipeClientStream(".", CorePipe.Name, PipeDirection.InOut, PipeOptions.Asynchronous);
                await _pipe.ConnectAsync(2000, ct);
                connected = true;
                await HandshakeAsync(ct);
                var heartbeat = HeartbeatLoopAsync(ct);
                await ReadLoopAsync(ct);
                try { await heartbeat; } catch { }
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                // Core down or restarting (or it failed mutual auth):
                // wait and retry. Never exit — EXCEPT the FR-119
                // orphan bound below. W20: surface each
                // distinct failure through the diagnostic hook — a
                // deterministic handshake refusal (bad token source,
                // identity mismatch, squatter check) otherwise looks
                // exactly like "Core down" forever.
                var line = $"ipc connect failed: {ex.GetType().Name}: {ex.Message}";
                if (line != _lastDiagnostic)
                {
                    _lastDiagnostic = line;
                    try { ConnectionDiagnostic?.Invoke(line); } catch { }
                }
                if (connected)
                {
                    _tokenPolicy.RecordAuthFailure(_presentedSource);
                    if (_tokenPolicy.ShouldExit)
                    {
                        _exitForOrphan = true;
                        try { ConnectionDiagnostic?.Invoke("ipc orphan exit: every token this agent can present was refused after the bounded retry — exiting cleanly so the Core watchdog relaunches a fresh agent (FR-119)"); } catch { }
                        break;
                    }
                    if (_tokenPolicy.EnvRejected && _presentedSource == IpcTokenSource.Environment)
                    {
                        try { ConnectionDiagnostic?.Invoke("ipc token fallback: the launch-environment token was refused repeatedly (stale after a Core restart) — falling back to the token file (FR-119)"); } catch { }
                    }
                }
                try { await Task.Delay(3000, ct); } catch (OperationCanceledException) { break; }
            }
            finally
            {
                _coreAuthenticated = false;
                // BD-WIN-AGENT F5: a dead link cancels in-flight tool
                // work too — a tool must not keep acting on a machine
                // whose control channel just vanished.
                _stop.CancelCurrentWork();
                // U7 link-loss fail-safe: the pipe is down (Core
                // died, restarted, dropped us, or this agent is
                // shutting down) — any key/button an agent action
                // left held is released NOW, on this side of the
                // dead link, before any reconnect attempt. The Core
                // cannot send this order over a dead pipe; the
                // release has to be local and unconditional.
                try { _engine.ReleaseAllInputs(); } catch { }
                try { _pipe?.Dispose(); } catch { }
                _pipe = null;
            }
        }
        // FR-119: the loop ended on the orphan bound (not on
        // cancellation) — tell the host to exit the process
        // cleanly. The finally above has already released any held
        // input, so shutdown cannot strand a pressed key.
        if (_exitForOrphan)
        {
            try { ExitRequested?.Invoke(); } catch { }
        }
    }

    /// <summary>Mutual authentication (2026-11-15 blocker fix):
    /// 1) Hello carries only a fresh nonce — no secret crosses yet.
    /// 2) The Core answers HelloAck = HMAC(token, nonce); we verify it
    ///    against our own copy of the token (handed to this process
    ///    through the launch environment, or — for task-launched
    ///    agents — the Core's ACL'd token file: the SAME per-boot
    ///    secret by either delivery, W20).
    ///    A squatter pipe cannot forge this and learns nothing.
    /// 3) Only then do we present the token (Auth). Any failure throws,
    ///    which drops the pipe and retries — vault/gate sends stay
    ///    gated on _coreAuthenticated throughout.</summary>
    /// <summary>BD-WIN-AGENT F4: verify the pipe SERVER is the real
    /// Core process via GetNamedPipeServerProcessId. The HMAC
    /// handshake proves the peer holds the token; this proves the
    /// token-holder is the Core binary, not another token-holding
    /// process squatting the pipe name. Any failure throws — the
    /// caller drops the pipe and _coreAuthenticated stays false
    /// (fail closed).
    /// W22 (round-4): the image check is no longer
    /// name-only. W28 (round 6): the observed image must equal
    /// the REGISTERED Core path from the protected install trust
    /// record (InstallTrust.IsCoreServerImage against the
    /// record), canonicalised — ACP_CORE_EXE may only select
    /// that one path, never widen beyond the record. An Agent
    /// that cannot name its Core's registered home does not get
    /// to trust a pipe host on a file name.</summary>
    /// <summary>W35: the AcpCore service state IN FORCE, read
    /// from the OS. The service key's existence only proves the
    /// service is INSTALLED; the shape in force is its RUNNING
    /// state, queried through the SCM (an unprivileged status
    /// read). Key present but the query fails ⇒ Unknown, which
    /// the decision treats as in force (fail closed). Key absent
    /// ⇒ NotInstalled, whatever the query would say.</summary>
    private static InstallTrustServiceState ReadAcpCoreServiceState()
    {
        bool installed;
        try
        {
            using var serviceKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\AcpCore");
            installed = serviceKey is not null;
        }
        catch { return InstallTrustServiceState.Unknown; }
        if (!installed) return InstallTrustServiceState.NotInstalled;
        var manager = NativeMethods.OpenSCManager(null, null, NativeMethods.SC_MANAGER_CONNECT);
        if (manager == IntPtr.Zero) return InstallTrustServiceState.Unknown;
        try
        {
            var service = NativeMethods.OpenService(manager, "AcpCore", NativeMethods.SERVICE_QUERY_STATUS);
            if (service == IntPtr.Zero) return InstallTrustServiceState.Unknown;
            try
            {
                return NativeMethods.QueryServiceStatusEx(service, NativeMethods.SC_STATUS_PROCESS_INFO,
                    out var status, System.Runtime.InteropServices.Marshal.SizeOf<NativeMethods.SERVICE_STATUS_PROCESS>(), out _)
                    ? status.dwCurrentState == NativeMethods.SERVICE_RUNNING
                        ? InstallTrustServiceState.Running
                        : InstallTrustServiceState.Stopped
                    : InstallTrustServiceState.Unknown;
            }
            finally { NativeMethods.CloseServiceHandle(service); }
        }
        catch { return InstallTrustServiceState.Unknown; }
        finally { NativeMethods.CloseServiceHandle(manager); }
    }

    /// <summary>W28: load + evaluate the install trust record —
    /// the Agent's ONLY trust anchor. The record is read from its
    /// FIXED machine location (InstallTrust.FixedRecordPath),
    /// never from beside this Agent's image, its working
    /// directory, or any launcher-controlled variable; the store
    /// facts (owner + ACL) and the deployment shape in force
    /// (W35: the AcpCore service's RUNNING state, or a provably
    /// protected store — never mere service-key existence) come
    /// from the OS. The
    /// pure decision is InstallTrust.Evaluate; its State names
    /// every refusal for the diagnostic/audit log.</summary>
    private static InstallTrustDecision LoadInstallTrust()
    {
        var path = InstallTrust.FixedRecordPath();
        var content = InstallTrust.TryReadRecordContent(path);
        string? ownerSid = null;
        IReadOnlyList<IpcTokenFileAclEntry>? entries = null;
        string? currentSid = null;
        var serviceState = InstallTrustServiceState.NotInstalled;
        if (OperatingSystem.IsWindows())
        {
            serviceState = ReadAcpCoreServiceState();
            try { currentSid = System.Security.Principal.WindowsIdentity.GetCurrent().User?.Value; } catch { }
            try
            {
                if (content is not null)
                {
                    var security = new System.IO.FileInfo(path).GetAccessControl();
                    ownerSid = (security.GetOwner(typeof(System.Security.Principal.SecurityIdentifier))
                        as System.Security.Principal.SecurityIdentifier)?.Value;
                    var mapped = new List<IpcTokenFileAclEntry>();
                    foreach (System.Security.AccessControl.FileSystemAccessRule rule in
                        security.GetAccessRules(true, false, typeof(System.Security.Principal.SecurityIdentifier)))
                    {
                        if (rule.AccessControlType != System.Security.AccessControl.AccessControlType.Allow) continue;
                        var sid = (rule.IdentityReference as System.Security.Principal.SecurityIdentifier)?.Value;
                        if (sid is null) continue;
                        var rights = rule.FileSystemRights;
                        var vocabulary =
                            rights.HasFlag(System.Security.AccessControl.FileSystemRights.FullControl) ? "FullControl"
                            : (rights & (System.Security.AccessControl.FileSystemRights.Write
                                | System.Security.AccessControl.FileSystemRights.Delete
                                | System.Security.AccessControl.FileSystemRights.Modify
                                | System.Security.AccessControl.FileSystemRights.ChangePermissions
                                | System.Security.AccessControl.FileSystemRights.TakeOwnership)) != 0 ? "Write"
                            : "Read";
                        mapped.Add(new IpcTokenFileAclEntry(sid, vocabulary, IsSystem: false));
                    }
                    entries = mapped;
                }
            }
            catch { /* store facts unreadable: entries stay null, ClassifyStore treats an unprovable store as unprotected */ }
        }
        return InstallTrust.Evaluate(content, ownerSid, entries, currentSid, serviceState,
            Environment.ProcessPath, Environment.GetEnvironmentVariable(IpcTrust.CoreExeEnvironmentVariable));
    }

    private void VerifyCoreServerProcess(InstallTrustRecord trustRecord)
    {
        var coreOverride = Environment.GetEnvironmentVariable(IpcTrust.CoreExeEnvironmentVariable);
        if (InstallTrust.ExpectedCoreImagePaths(trustRecord, coreOverride).Count == 0)
            throw new InvalidOperationException("ACP_CORE_EXE names a Core outside the install trust record — refusing to trust any pipe host (fail closed, W28)");
        var handle = _pipe?.SafePipeHandle.DangerousGetHandle() ?? IntPtr.Zero;
        if (handle == IntPtr.Zero || !NativeMethods.GetNamedPipeServerProcessId(handle, out var pid) || pid == 0)
            throw new InvalidOperationException("could not identify the pipe server process — refusing to trust it (possible pipe squatter)");
        var proc = NativeMethods.OpenProcess(NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (proc == IntPtr.Zero)
            throw new InvalidOperationException("could not open the pipe server process for identity verification — refusing to trust it");
        try
        {
            var sb = new System.Text.StringBuilder(1024);
            var size = (uint)sb.Capacity;
            var image = NativeMethods.QueryFullProcessImageName(proc, 0, sb, ref size) ? sb.ToString() : null;
            if (!InstallTrust.IsCoreServerImage(image, trustRecord, coreOverride))
                throw new InvalidOperationException($"the pipe is hosted by '{image ?? "unknown"}', not the ACP Core at its registered path in the install trust record — refusing to trust it (possible pipe squatter)");
        }
        finally { NativeMethods.CloseHandle(proc); }
    }

    private async Task HandshakeAsync(CancellationToken ct)
    {
        var (token, tokenSource) = ReadIpcToken();
        // FR-119: the source this attempt presents — RunAsync
        // records an auth failure against exactly this source.
        _presentedSource = tokenSource;
        var (fgTitle, fgProcess) = ForegroundWindow.Current();
        // BD-WIN-AGENT F4: FAIL CLOSED on a missing token. The pre-fix
        // code marked the Core authenticated with no HMAC proof at
        // all ("dev/test posture"), so every launch path that never
        // received the env-only token — the installer logon task, a
        // manual start, --portable — trusted any pipe squatter with
        // vault, gate and STOP traffic. Now: no token + no explicit
        // per-process dev opt-in (ACP_DEV_ALLOW_NO_TOKEN=1) = no
        // trust, no tool execution, no sends. The retry loop keeps
        // the agent alive; if the Core later launches us WITH the
        // token, the next attempt authenticates properly.
        // ReadIpcToken already resolved env-vs-file; either source
        // is the same secret and the same Authenticated posture.
        var posture = token is not null
            ? IpcTrustPosture.Authenticated
            : IpcTrust.Decide(null, Environment.GetEnvironmentVariable(IpcTrust.DevOptInVariable));
        if (posture == IpcTrustPosture.RefuseNoToken)
            throw new InvalidOperationException("no IPC token was provided by the launcher and no dev opt-in is set — refusing to trust an unverified Core (fail closed, BD-WIN-AGENT F4)");
        if (posture == IpcTrustPosture.DevUnauthenticated)
        {
            // Explicit dev posture ONLY (ACP_DEV_ALLOW_NO_TOKEN=1):
            // unauthenticated interop, labelled in the version slot
            // so the Core's log shows this agent ran unauthenticated.
            await SendAsync(new IpcMessage(IpcKinds.Hello, null, null, null, null, null, _agentVersion + " (DEV-UNAUTHENTICATED)", DesktopUnlocked, _presence.OwnerDrivingNow, null, fgTitle, fgProcess), ct);
            _coreAuthenticated = true;
            return;
        }
        // W28 (round-6): BEFORE any pipe trust, this
        // Agent must find ITSELF in the protected install trust
        // record — the pin and the registered Core path come from
        // the record ONLY, never from beside this Agent's image.
        // A copied Agent (its canonical path is not the
        // registered Agent path), an absent/malformed record, or
        // an unprotected record store in the service shape all
        // refuse here, fail closed, with the state named — the
        // retry loop's diagnostic hook carries it to the log.
        var trust = LoadInstallTrust();
        if (!trust.Accepted || trust.Record is null)
            throw new InvalidOperationException($"install trust record check failed [{trust.State}] — refusing to trust any pipe host (fail closed, W28)");
        VerifyCoreServerProcess(trust.Record);
        var nonce = IpcAuth.NewNonce();
        // W20: tokenSource labels WHICH delivery carried our copy
        // (env|file) — metadata for the Core's audit log, never the
        // token itself.
        var helloArgs = JsonSerializer.Serialize(new { nonce, tokenSource = IpcTokenFile.SourceLabel(tokenSource) });
        await SendAsync(new IpcMessage(IpcKinds.Hello, null, null, helloArgs, null, null, _agentVersion, DesktopUnlocked, _presence.OwnerDrivingNow, null, fgTitle, fgProcess), ct);
        using var ackTimeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        ackTimeout.CancelAfter(TimeSpan.FromSeconds(10));
        var json = await IpcFraming.ReadAsync(_pipe!, ackTimeout.Token);
        if (json is null) throw new InvalidOperationException("Core closed the pipe during the handshake");
        var ack = JsonSerializer.Deserialize<IpcMessage>(json);
        if (ack is null || ack.Kind != IpcKinds.HelloAck || !IpcAuth.VerifyHelloAck(token, nonce, ack.Text))
            throw new InvalidOperationException("the pipe host failed mutual authentication — refusing to trust it (possible pipe squatter)");
        // W25 (round-5): the HMAC proves the host holds
        // the per-boot token — a secret the console user can
        // legitimately READ from the token file, so it cannot
        // distinguish the Core from a fake Core running as that
        // user. The identity proof is asymmetric: the host must
        // SIGN this connection's nonce with the Core identity
        // key, and the signature must verify against the pinned
        // public key. W28 (round 6): that pin comes ONLY from
        // the protected install trust record evaluated above —
        // the W25 beside-image pin followed the Agent's image
        // and was itself attacker-plantable on a copied Agent.
        // No record, no signature, or a bad signature all
        // refuse, exactly like a bad HMAC. The public key the
        // host sends about itself is never consulted
        // (CoreIdentity.VerifyHelloAckProof).
        var pinnedCoreKey = trust.PinnedCorePublicKey;
        if (pinnedCoreKey is null)
            throw new InvalidOperationException("the install trust record carried no usable Core identity key — refusing to trust any pipe host (fail closed, W28)");
        if (!CoreIdentity.VerifyHelloAckProof(pinnedCoreKey, nonce, ack.ArgumentsJson))
            throw new InvalidOperationException("the pipe host failed the Core identity signature check — refusing to trust it (possible fake Core, W25)");
        await SendAsync(new IpcMessage(IpcKinds.Auth, null, null, null, null, token, _agentVersion, DesktopUnlocked, _presence.OwnerDrivingNow, null, fgTitle, fgProcess), ct);
        _coreAuthenticated = true;
        // FR-119: a successful authentication (env or the file
        // fallback) clears the retry policy's accounting.
        _tokenPolicy.RecordSuccess();
        if (_lastDiagnostic is not null)
        {
            _lastDiagnostic = null;
            try { ConnectionDiagnostic?.Invoke($"ipc connected: authenticated via token source {IpcTokenFile.SourceLabel(tokenSource)}"); } catch { }
        }
    }

    private async Task HeartbeatLoopAsync(CancellationToken ct)
    {
        var lastUnlocked = DesktopUnlocked;
        var lastTakeover = _presence.OwnerDrivingNow;
        var (lastFgTitle, lastFgProcess) = ForegroundWindow.Current();
        while (!ct.IsCancellationRequested && _pipe is { IsConnected: true })
        {
            await SendAsync(new IpcMessage(IpcKinds.Heartbeat, null, null, null, null, null, null, null, null, null), ct);
            var nowUnlocked = DesktopUnlocked;
            var nowTakeover = _presence.OwnerDrivingNow;
            var (fgTitle, fgProcess) = ForegroundWindow.Current();
            // Session-state is reported on ANY change the policy layer
            // consumes: lock transitions AND the protected-targets
            // foreground feed (M5) — a protected window coming to the
            // front must reach the Core before the next agent call.
            // FR-130: the takeover state is reported too, with its
            // REAL value — this sender hardcoded false, so the
            // Core's takeover_status could never reflect the pill
            // and the two faces of one fact diverged silently.
            if (nowUnlocked != lastUnlocked || fgTitle != lastFgTitle || fgProcess != lastFgProcess
                || nowTakeover != lastTakeover)
            {
                lastUnlocked = nowUnlocked;
                lastTakeover = nowTakeover;
                lastFgTitle = fgTitle;
                lastFgProcess = fgProcess;
                await SendAsync(new IpcMessage(IpcKinds.SessionState, null, null, null, null, null, null, nowUnlocked, nowTakeover, null, fgTitle, fgProcess), ct);
            }
            await Task.Delay(5000, ct);
        }
    }

    /// <summary>FR-130: an immediate session-state report on a
    /// takeover transition, carrying the REAL takeover value, so
    /// the Core's takeover_status converges on the transition
    /// itself instead of the next heartbeat change. Best-effort
    /// like the takeover-event feed: a failed send leaves the
    /// heartbeat carrying the same truth within seconds.</summary>
    private async Task SendSessionStateQuietAsync()
    {
        try
        {
            if (_pipe is null || !_coreAuthenticated) return;
            var (fgTitle, fgProcess) = ForegroundWindow.Current();
            await SendAsync(new IpcMessage(IpcKinds.SessionState, null, null, null, null, null, null,
                DesktopUnlocked, _presence.OwnerDrivingNow, null, fgTitle, fgProcess), CancellationToken.None);
        }
        catch { }
    }

    /// <summary>Send a gate approval (or its revocation) from the
    /// laptop UI to the Core (inspector C3's sanctioned path): the ONLY
    /// runtime route into the Core's approved-gates set is this
    /// message, over the token-authenticated IPC channel. Throws when
    /// not connected — the UI must say so rather than pretend the
    /// approval landed.
    /// W10 / V2-C4: this and every other consent-class sender in this
    /// class (VaultSet, VaultWipe, PairingCreateCode, UserStopClear,
    /// SendHostActionAsync's SessionAction, GateAnswer) stamp the
    /// physical-human provenance assertion. Each of these methods is
    /// invoked ONLY from a laptop-UI event handler — the call exists
    /// because a person acted in the window — which is exactly the
    /// fact the assertion records, on the same basis as the W9 gate
    /// answer stamp. The Core now requires the assertion in every
    /// session state; an unstamped consent message is refused.</summary>
    public async Task SendGateApprovalAsync(string gate, bool approved, CancellationToken ct = default)
    {
        if (!_coreAuthenticated) throw new InvalidOperationException("not connected to a verified Core");
        var payload = JsonSerializer.Serialize(new { gate, approved });
        await SendAsync(new IpcMessage(IpcKinds.GateApproval, null, null, payload, null, null, null, null, null, null,
            InputProvenance: IpcProvenance.PhysicalHuman, AgentSessionLive: _sessionWasActive), ct);
    }

    /// <summary>W9: raised when the Core raises a per-action gate
    /// request (payload JSON = GateRequestPayload). The subscriber
    /// (App) shows the §3 GateSheet on the UI thread and answers via
    /// SendGateAnswerAsync. Raised OFF the read loop by the handler
    /// below, so a slow human decision never stalls STOP/presence
    /// traffic.</summary>
    public event Action<string>? GateRequestReceived;

    /// <summary>W9: send the GateSheet's answer for one gate request.
    /// This sender is called ONLY from the GateSheet exit path in
    /// App — an outcome exists at all only because the sheet's exits
    /// armed (600 ms + a human activation on the sheet window), so
    /// the physical-human provenance asserted here is the sheet's
    /// own arming fact, not a claim any other caller may borrow.
    /// The Core's consent guard refuses gate answers during a live
    /// session without exactly this assertion. Throws when not
    /// connected — an unsent answer is a NO, and the Core's 30 s
    /// gate timeout resolves the request as a deny.</summary>
    public async Task SendGateAnswerAsync(string requestId, string answer, CancellationToken ct = default)
    {
        if (!_coreAuthenticated) throw new InvalidOperationException("not connected to a verified Core — the gate answer was NOT sent");
        var payload = GateRequestPayload.BuildAnswer(requestId, answer);
        await SendAsync(new IpcMessage(IpcKinds.GateAnswer, requestId, null, payload, null, null, null, null, null, null,
            InputProvenance: IpcProvenance.PhysicalHuman, AgentSessionLive: _sessionWasActive), ct);
    }

    /// <summary>W9: raised when the Core answers a chat-thread
    /// request with the pairing's thread JSON (owner channel only).</summary>
    public event Action<string>? ChatThreadReceived;

    /// <summary>W9: the owner sends a chat message from the host
    /// window (Addendum A host surface). Laptop-UI channel only;
    /// the Core appends it to the pairing's thread and counts it
    /// Sent in the data-flow ledger. Throws when not connected —
    /// the window says the message was not sent.</summary>
    public async Task SendChatMessageAsync(string pairingId, string body, CancellationToken ct = default)
    {
        if (!_coreAuthenticated) throw new InvalidOperationException("not connected to a verified Core — the chat message was NOT sent");
        var payload = JsonSerializer.Serialize(new { pairingId, body });
        await SendAsync(new IpcMessage(IpcKinds.ChatSend, null, null, payload, null, null, null, null, null, null), ct);
    }

    /// <summary>W9: ask the Core for one pairing's chat thread (the
    /// answer arrives on ChatThreadReceived). W122 / N22: the
    /// request carries opened=true — this call IS the owner
    /// opening the thread, so the Core advances the owner's seen
    /// cursor (the inbox's unread for this thread clears). The
    /// Core's internal re-pushes never carry the flag.</summary>
    public async Task RequestChatThreadAsync(string pairingId, CancellationToken ct = default)
    {
        if (!_coreAuthenticated) throw new InvalidOperationException("not connected to a verified Core");
        var payload = JsonSerializer.Serialize(new { pairingId, opened = true });
        await SendAsync(new IpcMessage(IpcKinds.ChatThreadRequest, null, null, payload, null, null, null, null, null, null), ct);
    }

    /// <summary>W120 / S13: the owner's answer on one order card in
    /// the thread (Approve / Deny / Deny and end session — the
    /// GateAnswers vocabulary). The card is the gate for the
    /// order's exact bytes; the Core executes only on allow.
    /// Throws when not connected — the window says the answer was
    /// not sent and the card stays pending.</summary>
    public async Task SendChatOrderAnswerAsync(string pairingId, string orderId, string answer, CancellationToken ct = default)
    {
        if (!_coreAuthenticated) throw new InvalidOperationException("not connected to a verified Core — the card answer was NOT sent");
        var payload = JsonSerializer.Serialize(new { pairingId, orderId, answer });
        await SendAsync(new IpcMessage(IpcKinds.ChatOrderAnswer, null, null, payload, null, null, null, null, null, null), ct);
    }

    /// <summary>Raised when the Core reports the vault's state back
    /// (after a seed/wipe from this window): the status line shows the
    /// Core's own record, never the window's guess.</summary>
    public event Action<string>? VaultStateReceived;

    /// <summary>Send the logon password the owner just typed in THIS
    /// window to the Core's vault, over the same token-authenticated
    /// channel as gate approvals. The password exists only in the
    /// PasswordBox, this payload, and the Core's vault — it is never
    /// logged, never shown again, and no tool can read it back.
    /// Throws when not connected — the UI must say so rather than
    /// pretend the vault landed.</summary>
    public async Task SendVaultSetAsync(string password, CancellationToken ct = default)
    {
        if (!_coreAuthenticated) throw new InvalidOperationException("not connected to a verified Core — the password was NOT sent");
        var payload = JsonSerializer.Serialize(new { password });
        await SendAsync(new IpcMessage(IpcKinds.VaultSet, null, null, payload, null, null, null, null, null, null,
            InputProvenance: IpcProvenance.PhysicalHuman, AgentSessionLive: _sessionWasActive), ct);
    }

    /// <summary>Wipe the vault from this window (same channel
    /// discipline as seeding).</summary>
    public async Task SendVaultWipeAsync(CancellationToken ct = default)
    {
        // BD-WIN-AGENT F4: this sender was the one route missing the
        // _coreAuthenticated guard every sibling sender has — a wipe
        // could be sent to an unverified pipe host.
        if (!_coreAuthenticated) throw new InvalidOperationException("not connected to a verified Core — the wipe was NOT sent");
        await SendAsync(new IpcMessage(IpcKinds.VaultWipe, null, null, null, null, null, null, null, null, null,
            InputProvenance: IpcProvenance.PhysicalHuman, AgentSessionLive: _sessionWasActive), ct);
    }

    /// <summary>Raised when the Core answers a host-state request
    /// (M4): the companion window renders the snapshot JSON verbatim —
    /// facts from the Core, never the window's guesses.</summary>
    public event Action<string>? HostStateReceived;

    /// <summary>Raised when the Core mints a pairing code for the
    /// companion window to display (payload JSON: code, expiresUtc,
    /// agentName, preset).</summary>
    public event Action<string>? PairingCodeReceived;

    /// <summary>C20 wiring: raised ONCE per recovery export with the
    /// key sheet for the window to show the owner (payload JSON:
    /// keySheet, deviceId, primaryPath, contactPaths). The sheet is
    /// shown once and never stored by the window or the Core.</summary>
    public event Action<string>? RecoveryKeySheetReceived;

    /// <summary>Ask the Core for a fresh host-state snapshot. Throws
    /// when not connected — the window keeps showing its last snapshot
    /// labelled with its age rather than pretending freshness.</summary>
    public async Task RequestHostStateAsync(CancellationToken ct = default)
    {
        if (!_coreAuthenticated) throw new InvalidOperationException("not connected to a verified Core");
        await SendAsync(new IpcMessage(IpcKinds.HostStateRequest, null, null, null, null, null, null, null, null, null), ct);
    }

    /// <summary>Revoke a pairing from the companion window (laptop-UI
    /// only route, like gate approvals). Throws when not connected.</summary>
    public async Task RevokePairingAsync(string pairingId, CancellationToken ct = default)
    {
        if (!_coreAuthenticated) throw new InvalidOperationException("not connected to a verified Core");
        var payload = JsonSerializer.Serialize(new { id = pairingId });
        await SendAsync(new IpcMessage(IpcKinds.PairingRevoke, null, null, payload, null, null, null, null, null, null), ct);
    }

    /// <summary>Mint a pairing code from the companion window. The
    /// Core binds the preset's scopes at mint time (C1); the code
    /// comes back on PairingCodeReceived. Throws when not connected.</summary>
    public async Task CreatePairingCodeAsync(string agentName, string preset, string? connectionJson = null, CancellationToken ct = default)
    {
        if (!_coreAuthenticated) throw new InvalidOperationException("not connected to a verified Core");
        // W97: the optional connection-mode choice rides as a
        // nested object (the Core parses + validates it and binds
        // it to the code; an invalid one refuses the mint).
        string payload;
        if (string.IsNullOrWhiteSpace(connectionJson))
        {
            payload = JsonSerializer.Serialize(new { agentName, preset });
        }
        else
        {
            var obj = new System.Text.Json.Nodes.JsonObject
            {
                ["agentName"] = agentName,
                ["preset"] = preset,
                ["connection"] = System.Text.Json.Nodes.JsonNode.Parse(connectionJson),
            };
            payload = obj.ToJsonString();
        }
        await SendAsync(new IpcMessage(IpcKinds.PairingCreateCode, null, null, payload, null, null, null, null, null, null,
            InputProvenance: IpcProvenance.PhysicalHuman, AgentSessionLive: _sessionWasActive), ct);
    }

    // ---- Slice 2/3 host-window actions (Block A wiring) ------------
    // Same channel discipline as gate approvals and the vault: these
    // sends exist ONLY on this token-authenticated laptop-UI channel.
    // Session "accept" sent from here is the endpoint-local UI act of
    // the 2026-11-19 ruling — the window is physically at the
    // endpoint; there is no other sender of these kinds anywhere.

    /// <summary>Raised when the Core answers an enrollment mint
    /// (payload JSON: code, qr, expiresUtc, scope, groupId, groupName).</summary>
    public event Action<string>? EnrollmentCodeReceived;

    /// <summary>Raised when the Core answers an offboarding preview
    /// with the D14 blast-list JSON.</summary>
    public event Action<string>? OffboardBlastReceived;

    /// <summary>Raised when the Core reports a roster/session/
    /// enrollment action's outcome (payload JSON: action, ok, detail).</summary>
    public event Action<string>? ActionResultReceived;

    /// <summary>Raised when the Core answers a discovery browse with
    /// the classified results (Block C part 1; payload JSON: devices).</summary>
    public event Action<string>? DiscoveryResultReceived;
    public event Action<string>? QuickAssistCodeReceived;

    /// <summary>Send one host-window action payload of the given IPC
    /// kind to the Core. Throws when not connected — the window says
    /// the act was NOT sent rather than pretending it landed.</summary>
    public async Task SendHostActionAsync(string kind, string payloadJson, CancellationToken ct = default)
    {
        if (!_coreAuthenticated) throw new InvalidOperationException("not connected to a verified Core");
        await SendAsync(new IpcMessage(kind, null, null, payloadJson, null, null, null, null, null, null,
            InputProvenance: IpcProvenance.PhysicalHuman, AgentSessionLive: _sessionWasActive), ct);
    }

    private async Task ReadLoopAsync(CancellationToken ct)
    {
        while (_pipe is { IsConnected: true } && !ct.IsCancellationRequested)
        {
            var json = await IpcFraming.ReadAsync(_pipe, ct);
            if (json is null) break;
            IpcMessage? msg;
            try { msg = JsonSerializer.Deserialize<IpcMessage>(json); } catch (JsonException) { continue; }
            if (msg is null) continue;

            // Defence in depth: never execute for a peer that has not
            // completed mutual authentication (the handshake normally
            // guarantees this before the read loop starts).
            if (!_coreAuthenticated) break;
            switch (msg.Kind)
            {
                case IpcKinds.ToolRequest when msg.Tool is not null:
                {
                    // BD-WIN-AGENT F5: dispatch OFF the read loop.
                    // The pre-fix loop awaited the tool inline, so
                    // StopAll / ReleaseInputs / presence-off queued
                    // behind it — STOP did not outrank a running
                    // tool. The tool runs under the StopCoordinator's
                    // current token; any STOP trigger cancels it.
                    var tool = msg.Tool;
                    var requestId = msg.RequestId;
                    var args = msg.ArgumentsJson is null ? default : JsonDocument.Parse(msg.ArgumentsJson).RootElement.Clone();
                    var workToken = _stop.CurrentToken;
                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            var (ok, text) = await _engine.ExecuteAsync(tool, args, workToken);
                            await SendAsync(new IpcMessage(IpcKinds.ToolResponse, requestId, tool, null, ok, text, null, null, null, null), ct);
                        }
                        catch { /* pipe dropped mid-tool: the response dies with the link; the finally in RunAsync already released held input */ }
                    });
                    break;
                }
                case IpcKinds.Presence:
                {
                    // M1 directive protocol: the Core pushes complete
                    // truth — {active, agent, stopInForce} in the
                    // payload, the agent's name in its own field, the
                    // intent line as narration. The layer reconciles
                    // its state machine from that; it never infers
                    // state from which fields happen to be set (the
                    // pre-M1 handler read the version slot for a name
                    // and could not leave the blocked state at all).
                    var (active, agent, stopInForce, seconds, actions) = ParsePresenceDirective(msg);
                    var (floorHolder, terminalOpen, participants) = ParsePresenceRoster(msg);
                    // U7: a directive that says STOP is in force or
                    // that NO session is active (session ended for
                    // any reason — stop, expiry, revocation, agent's
                    // own session_stop) releases held input before
                    // anything else renders. A live-session directive
                    // never releases: holds inside a session are the
                    // agent's deliberate acts.
                    // BD-WIN-AGENT F5: it also cancels the running
                    // tool — releasing keys alone left the tool
                    // itself acting.
                    if (stopInForce || !active) { _stop.CancelCurrentWork(); _engine.ReleaseAllInputs(); }
                    // BD-SUPP-HELDINPUT F1: a directive that opens a
                    // LIVE session re-arms the tracker a ReleaseAll
                    // sealed — new holds belong to the new session.
                    if (active && !stopInForce) _engine.RearmHeldInputs();
                    // FR-121 (W76): fail closed on an UNNAMED
                    // session start. The presence law requires the
                    // Box to name the SPECIFIC driver; a directive
                    // that would start a session with no name (and
                    // no name already held) is a wiring bug, and the
                    // session is refused here exactly like a failed
                    // self-test — work cancelled, inputs released,
                    // user-stop sent, and the defect surfaced as a
                    // named defect state on the blocked box. The
                    // generic name is never rendered.
                    if (active && !stopInForce && !_sessionWasActive && _presence.SessionWouldBeUnnamed(agent))
                    {
                        _stop.CancelCurrentWork();
                        _engine.ReleaseAllInputs();
                        _ = SendUserStopQuietAsync();
                        _presence.FlagDriverNameMissing(Strings.Get("PresenceDriverNameMissing"));
                        _sessionWasActive = false;
                        break;
                    }
                    // W8 (§2): the presence self-test is drawn and
                    // verified BEFORE a session is accepted — on
                    // the inactive→active transition, all three
                    // elements + STOP must draw, or the session is
                    // refused here: STOP is engaged and the failure
                    // is narrated on the box line, never hidden.
                    if (active && !stopInForce && !_sessionWasActive)
                    {
                        var test = _presence.RunSelfTest();
                        if (!test.Passed)
                        {
                            _stop.CancelCurrentWork();
                            _engine.ReleaseAllInputs();
                            _ = SendUserStopQuietAsync();
                            _presence.ApplyDirective(false, agent, true,
                                Strings.Format("PresenceSelfTestFailedFormat", string.Join("; ", test.Failures)));
                            _sessionWasActive = false;
                            break;
                        }
                    }
                    var wasActive = _sessionWasActive;
                    _sessionWasActive = active && !stopInForce;
                    _presence.ApplyDirective(active, agent, stopInForce, msg.Narration, seconds, actions,
                        floorHolder, terminalOpen, participants);
                    // FR-120 (W73): the watcher runs exactly while
                    // a session is live; on the start edge the
                    // active modes enter the session record.
                    if (_sessionWasActive && !wasActive)
                    {
                        _watcher?.Start();
                        var (m, k) = _presence.ActiveTakeoverModes;
                        _ = SendTakeoverEventQuietAsync(TakeoverRecordKinds.ModesAtStart,
                            TakeoverActors.OwnerLocal, TakeoverRecordDetail.Modes(m, k));
                    }
                    else if (!_sessionWasActive && wasActive)
                    {
                        _watcher?.Stop();
                    }
                    break;
                }
                case IpcKinds.TakeoverDefaults:
                    // FR-120 (W73): the Core's resolved fleet
                    // defaults — applied in memory only, and only
                    // where the device has not chosen (the palette
                    // decides). Policy never writes presence.json.
                    PresencePalette.FleetDefaults = TakeoverFleetDefaults.FromIpcJson(msg.ArgumentsJson);
                    _presence.ApplyFleetDefaults();
                    break;
                case IpcKinds.ClipboardPolicy:
                    // U1: the Core's resolved clipboard policy — the
                    // engine's standing instruction at the clipboard
                    // path. Malformed payloads are ignored inside
                    // ApplyClipboardPolicy; the standing instruction
                    // stands.
                    _engine.ApplyClipboardPolicy(msg.ArgumentsJson);
                    break;
                case IpcKinds.ReleaseInputs:
                    // U7 explicit order (session end / revocation):
                    // unconditional, no payload, no policy check.
                    // BD-WIN-AGENT F5: cancel the running tool too.
                    _stop.CancelCurrentWork();
                    _engine.ReleaseAllInputs();
                    break;
                case IpcKinds.StopAll:
                    // BD-WIN-AGENT F5: STOP outranks the running
                    // tool — cancel it FIRST, then release its holds.
                    _stop.CancelCurrentWork();
                    _engine.ReleaseAllInputs();
                    _presence.ApplyStopEngaged();
                    break;
                case IpcKinds.Notify:
                    _presence.ShowNotice(msg.Text ?? "");
                    break;
                case IpcKinds.VaultState:
                    VaultStateReceived?.Invoke(msg.Text ?? "");
                    break;
                case IpcKinds.HostState:
                    HostStateReceived?.Invoke(msg.ArgumentsJson ?? "{}");
                    break;
                case IpcKinds.PairingCode:
                    PairingCodeReceived?.Invoke(msg.ArgumentsJson ?? "{}");
                    break;
                case IpcKinds.RecoveryKeySheet:
                    RecoveryKeySheetReceived?.Invoke(msg.ArgumentsJson ?? "{}");
                    break;
                case IpcKinds.EnrollmentCodeMsg:
                    EnrollmentCodeReceived?.Invoke(msg.ArgumentsJson ?? "{}");
                    break;
                case IpcKinds.RosterOffboardBlast:
                    OffboardBlastReceived?.Invoke(msg.ArgumentsJson ?? "{}");
                    break;
                case IpcKinds.ActionResult:
                    ActionResultReceived?.Invoke(msg.ArgumentsJson ?? "{}");
                    break;
                case IpcKinds.DiscoveryResult:
                    DiscoveryResultReceived?.Invoke(msg.ArgumentsJson ?? "{}");
                    break;
                case IpcKinds.QuickAssistCode:
                    QuickAssistCodeReceived?.Invoke(msg.ArgumentsJson ?? "{}");
                    break;
                case IpcKinds.GateRequest:
                    // W9: dispatch OFF the read loop (the F5 rule) —
                    // the GateSheet waits on a human for up to the
                    // gate's 30 s window, and STOP / presence traffic
                    // must never queue behind a human decision.
                    var gatePayload = msg.ArgumentsJson ?? "{}";
                    _ = Task.Run(() => { try { GateRequestReceived?.Invoke(gatePayload); } catch { /* a failed sheet is a NO — the Core's timeout resolves it as a deny */ } });
                    break;
                case IpcKinds.ChatThread:
                    ChatThreadReceived?.Invoke(msg.ArgumentsJson ?? "{}");
                    break;
            }
        }
    }

    /// <summary>Parse a Presence directive. The payload JSON is
    /// authoritative; the Text/AgentName fields are the fallback for
    /// a peer that predates the payload (mixed-version window during
    /// a rolling deploy).</summary>
    private static (bool Active, string? Agent, bool StopInForce, long Seconds, int Actions) ParsePresenceDirective(IpcMessage msg)
    {
        var active = msg.Text != "off";
        var stopInForce = false;
        string? agent = msg.AgentName;
        long seconds = 0;
        var actions = 0;
        if (msg.ArgumentsJson is not null)
        {
            try
            {
                using var doc = JsonDocument.Parse(msg.ArgumentsJson);
                var root = doc.RootElement;
                if (root.TryGetProperty("active", out var a) && a.ValueKind is JsonValueKind.True or JsonValueKind.False)
                    active = a.GetBoolean();
                if (root.TryGetProperty("stopInForce", out var s) && s.ValueKind is JsonValueKind.True or JsonValueKind.False)
                    stopInForce = s.GetBoolean();
                if (agent is null && root.TryGetProperty("agent", out var n) && n.ValueKind == JsonValueKind.String)
                    agent = n.GetString();
                if (root.TryGetProperty("seconds", out var sec) && sec.ValueKind == JsonValueKind.Number)
                    seconds = sec.GetInt64();
                if (root.TryGetProperty("actions", out var act) && act.ValueKind == JsonValueKind.Number)
                    actions = act.GetInt32();
            }
            catch (JsonException) { /* fall back to the field-level reading above */ }
        }
        return (active, agent, stopInForce, seconds, actions);
    }

    /// <summary>The D35 roster fold-in of a presence directive
    /// (Block F): floor holder, terminal fact, and the participant
    /// list the Core rides inside the presence box. Absent fields
    /// mean no roster — the box renders as it always has.</summary>
    private static (string? FloorHolder, bool TerminalOpen, List<(string Name, string Role, string Floor, string Transport)> Participants)
        ParsePresenceRoster(IpcMessage msg)
    {
        string? floorHolder = null;
        var terminalOpen = false;
        var participants = new List<(string, string, string, string)>();
        if (msg.ArgumentsJson is null) return (null, false, participants);
        try
        {
            using var doc = JsonDocument.Parse(msg.ArgumentsJson);
            var root = doc.RootElement;
            if (root.TryGetProperty("floorHolder", out var fh) && fh.ValueKind == JsonValueKind.String)
                floorHolder = fh.GetString();
            if (root.TryGetProperty("terminalOpen", out var to) && to.ValueKind == JsonValueKind.True)
                terminalOpen = true;
            if (root.TryGetProperty("participants", out var parts) && parts.ValueKind == JsonValueKind.Array)
                foreach (var p in parts.EnumerateArray())
                {
                    string S(string n) => p.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";
                    participants.Add((S("name"), S("role"), S("floor"), S("transport")));
                }
        }
        catch (JsonException) { /* no roster rides this directive */ }
        return (floorHolder, terminalOpen, participants);
    }

    private async Task SendUserStopQuietAsync()
    {
        try { await RequestUserStopAsync(); } catch { }
    }

    /// <summary>FR-120 (W73): report one takeover session-record
    /// fact to the Core. Best-effort like every quiet sender: a
    /// dropped report is a lost record line, never a behaviour
    /// change — the takeover itself already happened locally,
    /// which is the owner's machine working as designed.</summary>
    private async Task SendTakeoverEventQuietAsync(string kind, string actor, string detail)
    {
        try
        {
            if (_pipe is null || !_coreAuthenticated) return;
            var payload = JsonSerializer.Serialize(new { kind, actor, detail });
            await SendAsync(new IpcMessage(IpcKinds.TakeoverEvent, null, null, payload, null, null, null, null, null, null), CancellationToken.None);
        }
        catch { }
    }

    private async Task SendUserStopClearQuietAsync()
    {
        try { await RequestUserStopClearAsync(); }
        catch
        {
            // The clear did not reach a verified Core: say so on the
            // banner instead of letting the owner believe the block lifted.
            _presence.SetNarration("Not connected to the Core — STOP is still in force.");
        }
    }

    /// <summary>Engage STOP from the laptop UI (banner or host
    /// window). Throws when not connected to a verified Core — the
    /// UI must say the stop did not land rather than pretend.</summary>
    public async Task RequestUserStopAsync(CancellationToken ct = default)
    {
        if (!_coreAuthenticated) throw new InvalidOperationException("not connected to a verified Core");
        await SendAsync(new IpcMessage(IpcKinds.UserStop, null, null, null, null, null, null, null, null, null), ct);
    }

    /// <summary>Clear STOP from the laptop UI (banner CLEAR STOP or
    /// the host window's clear control) — the blocked state's exit
    /// (M1). Same channel discipline as the engagement.</summary>
    public async Task RequestUserStopClearAsync(CancellationToken ct = default)
    {
        if (!_coreAuthenticated) throw new InvalidOperationException("not connected to a verified Core");
        await SendAsync(new IpcMessage(IpcKinds.UserStopClear, null, null, null, null, null, null, null, null, null,
            InputProvenance: IpcProvenance.PhysicalHuman, AgentSessionLive: _sessionWasActive), ct);
    }

    private async Task SendAsync(IpcMessage message, CancellationToken ct)
    {
        var pipe = _pipe ?? throw new InvalidOperationException("not connected");
        await _writeLock.WaitAsync(ct);
        try { await IpcFraming.WriteAsync(pipe, JsonSerializer.Serialize(message), ct); }
        finally { _writeLock.Release(); }
    }
}

/// <summary>Pipe name shared with the Core (kept in one place).</summary>
public static class CorePipe
{
    public const string Name = "acp-windows-agent";
}
