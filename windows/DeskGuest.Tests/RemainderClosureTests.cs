using System.IO.Pipes;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using DeskGuest.Core;
using DeskGuest.Core.Ipc;
using DeskGuest.Core.Mcp;
using DeskGuest.Core.Modules;
using DeskGuest.Core.Services;
using DeskGuest.Launcher;
using DeskGuest.Shared.Audit;
using DeskGuest.Shared.Ipc;
using DeskGuest.Shared.Policy;
using DeskGuest.Shared.Security;
using DeskGuest.Shared.Tools;

namespace DeskGuest.Tests;

/// <summary>Remainder-closure run: launcher shim, gate-approval path,
/// protected-targets foreground feed, LAN-lane TLS. Everything here is
/// VM-proven logic; the Windows-runtime surfaces stay UNPROVEN-ON-WINDOWS.</summary>
public class LauncherShimTests
{
    private static byte[] MakeZip(string content)
    {
        using var ms = new MemoryStream();
        using (var zip = new System.IO.Compression.ZipArchive(ms, System.IO.Compression.ZipArchiveMode.Create, leaveOpen: true))
        {
            var entry = zip.CreateEntry("app.txt");
            using var w = new StreamWriter(entry.Open());
            w.Write(content);
        }
        return ms.ToArray();
    }

    private static string SeedInstall(string root, params string[] slots)
    {
        var install = Path.Combine(root, "install");
        var updates = Path.Combine(root, "data", "updates");
        Directory.CreateDirectory(install);
        File.WriteAllText(Path.Combine(install, LauncherCore.CoreExeName), "base-core");
        File.WriteAllText(Path.Combine(install, LauncherCore.AgentExeName), "base-agent");
        foreach (var slot in slots)
        {
            var dir = Path.Combine(updates, "slots", slot);
            Directory.CreateDirectory(dir);
            File.WriteAllText(Path.Combine(dir, LauncherCore.CoreExeName), $"core-{slot}");
            File.WriteAllText(Path.Combine(dir, LauncherCore.AgentExeName), $"agent-{slot}");
        }
        // BD-WIN-AGENT F6: a seeded slot is only launcher-eligible
        // with an integrity anchor in the pointer, exactly as a real
        // staged update records one. Anchor slot A (the default
        // active slot) when it was seeded.
        if (slots.Contains("A"))
        {
            var hash = DeskGuest.Shared.Update.SlotIntegrity.ContentHash(Path.Combine(updates, "slots", "A"));
            File.WriteAllText(Path.Combine(updates, "active-slot.json"),
                JsonSerializer.Serialize(new { Active = 0, Version = "0.1.0", StagedVersion = (string?)null, LastOutcome = "seed", StagedSlotHash = (string?)null, ActiveSlotHash = hash }));
        }
        return updates;
    }

    [Fact]
    public void Resolve_DefaultPointer_UsesSlotA()
    {
        var root = TestUtil.TempDir();
        var updates = SeedInstall(root, "A", "B");
        var target = LauncherCore.ResolveTarget(Path.Combine(root, "install"), updates);
        Assert.False(target.FellBack);
        Assert.EndsWith(Path.Combine("slots", "A", LauncherCore.CoreExeName), target.CoreExe);
    }

    [Fact]
    public async Task Resolve_AfterUpdateFlip_UsesNewSlot()
    {
        var root = TestUtil.TempDir();
        var updatesRoot = SeedInstall(root, "A", "B");
        using var verifier = new RsaUpdateSignatureVerifier();
        var updates = new UpdateManager(updatesRoot, verifier, _ => Task.FromResult(true));
        // A real update package carries the binaries the launcher execs.
        using var ms = new MemoryStream();
        using (var zip = new System.IO.Compression.ZipArchive(ms, System.IO.Compression.ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var name in new[] { LauncherCore.CoreExeName, LauncherCore.AgentExeName })
            {
                var entry = zip.CreateEntry(name);
                using var w = new StreamWriter(entry.Open());
                w.Write("v2-binary");
            }
        }
        var package = ms.ToArray();
        Assert.True(updates.StagePackage(package, verifier.Sign(package), "2.0.0").Ok);
        var (ok, _) = await updates.ApplyStagedAsync(default);
        Assert.True(ok);
        // The pointer now names slot B; the launcher must exec slot B's
        // Core AND slot B's Agent — the flip is the swap (closure of
        // the Stage 4 named remainder).
        var target = LauncherCore.ResolveTarget(Path.Combine(root, "install"), updatesRoot);
        Assert.False(target.FellBack);
        Assert.EndsWith(Path.Combine("slots", "B", LauncherCore.CoreExeName), target.CoreExe);
        Assert.EndsWith(Path.Combine("slots", "B", LauncherCore.AgentExeName), target.AgentExe);
    }

    [Fact]
    public void Resolve_MissingSlotCore_FallsBackToBase()
    {
        var root = TestUtil.TempDir();
        var updates = SeedInstall(root); // no slots at all
        var target = LauncherCore.ResolveTarget(Path.Combine(root, "install"), updates);
        Assert.True(target.FellBack);
        Assert.EndsWith(LauncherCore.CoreExeName, target.CoreExe);
        Assert.Contains("install", target.CoreExe);
    }

    [Fact]
    public void Resolve_CorruptPointer_FallsBackToBase_Unanchored()
    {
        // BD-WIN-AGENT F6 supersedes the pre-fix expectation: a torn
        // pointer carries no integrity anchor, so the slot it would
        // name is UNVERIFIED and the launcher runs the base binaries
        // rather than whatever sits in the slot directory.
        var root = TestUtil.TempDir();
        var updates = SeedInstall(root, "A");
        File.WriteAllText(Path.Combine(updates, "active-slot.json"), "{torn");
        var target = LauncherCore.ResolveTarget(Path.Combine(root, "install"), updates);
        Assert.True(target.FellBack);
        Assert.Equal(Path.Combine(root, "install", LauncherCore.CoreExeName), target.CoreExe);
    }

    [Fact]
    public async Task Run_ExecutesResolvedCore_WithSlotAgentEnv_AndPassesExitCode()
    {
        var root = TestUtil.TempDir();
        var updates = SeedInstall(root, "A");
        LaunchRequest? seen = null;
        var log = new StringWriter();
        var exit = await LauncherCore.RunAsync(Path.Combine(root, "install"), updates, "",
            req => { seen = req; return Task.FromResult(3); }, log);
        Assert.Equal(3, exit);
        Assert.NotNull(seen);
        Assert.EndsWith(Path.Combine("slots", "A", LauncherCore.CoreExeName), seen!.ExePath);
        Assert.EndsWith(Path.Combine("slots", "A", LauncherCore.AgentExeName),
            seen.EnvironmentOverrides["DESKGUEST_AGENT_EXE"]);
    }

    [Fact]
    public async Task Run_SlotChildStartFailure_RetriesBaseOnce()
    {
        var root = TestUtil.TempDir();
        var updates = SeedInstall(root, "A");
        var attempts = new List<string>();
        var exit = await LauncherCore.RunAsync(Path.Combine(root, "install"), updates, "",
            req =>
            {
                attempts.Add(req.ExePath);
                if (attempts.Count == 1) throw new InvalidOperationException("cannot start");
                return Task.FromResult(0);
            }, new StringWriter());
        Assert.Equal(0, exit);
        Assert.Equal(2, attempts.Count);
        Assert.EndsWith(Path.Combine("slots", "A", LauncherCore.CoreExeName), attempts[0]);
        Assert.Equal(Path.Combine(root, "install", LauncherCore.CoreExeName), attempts[1]);
    }
}

public class GateApprovalPathTests
{
    private static CoreRuntime Runtime(string dataDir) => new(new CoreOptions
    {
        DataDir = dataDir,
        Port = 18799,
        Protector = new DevOnlyPassThroughProtector(),
        Probe = new FakeProbe(),
        FactChecks = new FakeFactChecks()
    });

    [Fact]
    public void Approval_AppliesAndRevokes()
    {
        var runtime = Runtime(TestUtil.TempDir());
        Assert.True(runtime.TryApplyGateApproval("""{"gate":"power","approved":true}"""));
        Assert.Contains("power", runtime.ApprovedGateClasses);
        Assert.True(runtime.TryApplyGateApproval("""{"gate":"power","approved":false}"""));
        Assert.DoesNotContain("power", runtime.ApprovedGateClasses);
    }

    [Fact]
    public void Approval_Malformed_ChangesNothing()
    {
        var runtime = Runtime(TestUtil.TempDir());
        Assert.False(runtime.TryApplyGateApproval("not json"));
        Assert.False(runtime.TryApplyGateApproval("""{"approved":true}"""));
        Assert.False(runtime.TryApplyGateApproval(null));
        Assert.Empty(runtime.ApprovedGateClasses);
    }

    [Fact]
    public void Approval_RuntimeFileEdit_ChangesNothing_C3Regression()
    {
        // C3: approved-gates.json is read ONCE at Core start. A mid-run
        // edit (e.g. by a SYSTEM shell tool) must NOT approve anything —
        // the laptop UI over authenticated IPC is the only runtime path.
        var dataDir = TestUtil.TempDir();
        var runtime = Runtime(dataDir);
        File.WriteAllText(Path.Combine(dataDir, "approved-gates.json"), """["power","vault_ops"]""");
        Assert.Empty(runtime.ApprovedGateClasses);
    }

    [Fact]
    public async Task Ipc_UnauthenticatedGateApproval_NeverReachesTheCore()
    {
        // The IPC server drops everything from an unauthenticated
        // connection (C2/C3): a gate_approval sent before a completed
        // mutual-auth handshake must not even raise the message event
        // the Core acts on. Handshake (2026-11-15 blocker fix): Hello
        // carries a nonce, the Core answers an HMAC proof, and only
        // then does the agent present the token in Auth.
        var state = new CoreState();
        var pipeName = "deskguest-test-" + Guid.NewGuid().ToString("N");
        var server = new AgentIpcServer(state, "s3cret", pipeName);
        var gateEvents = 0;
        server.AgentMessageReceived += msg => { if (msg.Kind == IpcKinds.GateApproval) gateEvents++; };
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var run = server.RunAsync(cts.Token);

        async Task HandshakeAsync(NamedPipeClientStream client, string token)
        {
            var nonce = IpcAuth.NewNonce();
            await IpcFraming.WriteAsync(client,
                JsonSerializer.Serialize(new IpcMessage(IpcKinds.Hello, null, null, JsonSerializer.Serialize(new { nonce }), null, null, "0", true, false, null)), cts.Token);
            var ackJson = await IpcFraming.ReadAsync(client, cts.Token);
            Assert.NotNull(ackJson);
            await IpcFraming.WriteAsync(client,
                JsonSerializer.Serialize(new IpcMessage(IpcKinds.Auth, null, null, null, null, token, "0", true, false, null)), cts.Token);
        }

        try
        {
            // 1) Pre-auth gate approval: ignored entirely.
            // 2) Wrong-token Auth after a well-formed Hello: dropped.
            using (var client = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous))
            {
                await client.ConnectAsync(5000, cts.Token);
                await IpcFraming.WriteAsync(client,
                    JsonSerializer.Serialize(new IpcMessage(IpcKinds.GateApproval, null, null, """{"gate":"power","approved":true}""", null, null, null, null, null, null)), cts.Token);
                await HandshakeAsync(client, "wrong");
                await Task.Delay(500, cts.Token);
            }
            Assert.Equal(0, gateEvents);
            Assert.False(state.Session.AgentConnected);

            // 3) Full handshake with the right token, THEN the
            // approvals. W10 / V2-C4 superseded this test's original
            // phase 3 (a bare GateApproval lands): provenance is now
            // required ALWAYS, so an authenticated-but-unstamped
            // approval — and an agent-injected one — must STILL be
            // refused by the consent guard; only the physical-human
            // stamped approval (the shape the real Session Agent's
            // SendGateApprovalAsync sends) lands.
            using (var client = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous))
            {
                await client.ConnectAsync(5000, cts.Token);
                await HandshakeAsync(client, "s3cret");
                await IpcFraming.WriteAsync(client,
                    JsonSerializer.Serialize(new IpcMessage(IpcKinds.GateApproval, null, null, """{"gate":"power","approved":true}""", null, null, null, null, null, null)), cts.Token);
                await IpcFraming.WriteAsync(client,
                    JsonSerializer.Serialize(new IpcMessage(IpcKinds.GateApproval, null, null, """{"gate":"power","approved":true}""", null, null, null, null, null, null,
                        InputProvenance: IpcProvenance.AgentInjected)), cts.Token);
                await Task.Delay(500, cts.Token);
                Assert.Equal(0, gateEvents);
                await IpcFraming.WriteAsync(client,
                    JsonSerializer.Serialize(new IpcMessage(IpcKinds.GateApproval, null, null, """{"gate":"power","approved":true}""", null, null, null, null, null, null,
                        InputProvenance: IpcProvenance.PhysicalHuman)), cts.Token);
                for (var i = 0; i < 50 && gateEvents == 0; i++) await Task.Delay(100, cts.Token);
            }
            Assert.Equal(1, gateEvents);
        }
        finally
        {
            cts.Cancel();
            try { await run; } catch { }
            server.Dispose();
        }
    }
}

public class ProtectedTargetsFeedTests
{
    private static ToolDescriptor DesktopTool(string name = "screenshot") =>
        new(name, "test", Scopes.Observe, SessionRequirement.Agent, RiskTier.Medium, null, "Agent");

    private static JsonElement Args(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.Clone();
    }

    [Fact]
    public void Policy_ProtectedProcessInForeground_DeniesDesktopTools()
    {
        var engine = new PolicyEngine();
        engine.ProtectedTargets.Add("KeePass");
        var pairing = TestUtil.BarePairing(Scopes.All);
        var d = engine.Evaluate(pairing, DesktopTool(), Args("{}"), TestUtil.Session(), TestUtil.State(),
            new HashSet<string>(), foregroundWindowName: "vault.kdbx — KeePass", foregroundProcessName: "KeePass");
        Assert.False(d.Allowed);
        Assert.Contains("blocked_by_user_rule", d.DenyReason);
    }

    [Fact]
    public void Policy_ProtectedTitleInForeground_DeniesDesktopTools()
    {
        var engine = new PolicyEngine();
        engine.ProtectedTargets.Add("Bank — Sign In");
        var pairing = TestUtil.BarePairing(Scopes.All);
        var d = engine.Evaluate(pairing, DesktopTool(), Args("{}"), TestUtil.Session(), TestUtil.State(),
            new HashSet<string>(), foregroundWindowName: "Bank — Sign In", foregroundProcessName: "chrome");
        Assert.False(d.Allowed);
        Assert.Contains("blocked_by_user_rule", d.DenyReason);
    }

    [Fact]
    public void Policy_UnprotectedForeground_Allows_AndCoreToolsUnaffected()
    {
        var engine = new PolicyEngine();
        engine.ProtectedTargets.Add("KeePass");
        var pairing = TestUtil.BarePairing(Scopes.All);
        var allowed = engine.Evaluate(pairing, DesktopTool(), Args("{}"), TestUtil.Session(), TestUtil.State(),
            new HashSet<string>(), foregroundWindowName: "notes.txt — Notepad", foregroundProcessName: "notepad");
        Assert.True(allowed.Allowed);
        // A Core-plane tool is not a capture/input tool: the foreground
        // rule never applies to it even with a protected window up front.
        var coreTool = new ToolDescriptor("endpoint_state", "test", Scopes.Observe, SessionRequirement.Core, RiskTier.Low, null, "SYSTEM");
        var coreAllowed = engine.Evaluate(pairing, coreTool, Args("{}"), TestUtil.Session(), TestUtil.State(),
            new HashSet<string>(), foregroundWindowName: "KeePass", foregroundProcessName: "KeePass");
        Assert.True(coreAllowed.Allowed);
    }

    [Fact]
    public void CoreState_AppliesAgentForegroundReport()
    {
        var state = new CoreState();
        state.ApplyAgentSessionReport(true, false, "vault.kdbx — KeePass", "KeePass");
        Assert.Equal("KeePass", state.Session.ForegroundProcess);
        Assert.Equal("vault.kdbx — KeePass", state.Session.ForegroundTitle);
        Assert.True(state.Session.DesktopUnlocked);
        // A later report with unknown foreground keeps the last fact.
        state.ApplyAgentSessionReport(null, null, null, null);
        Assert.Equal("KeePass", state.Session.ForegroundProcess);
    }

    private sealed class StubDesktopModule : IToolModule
    {
        public ToolDescriptor Descriptor { get; } = new("screenshot", "stub", Scopes.Observe, SessionRequirement.Agent, RiskTier.Medium, null, "Agent");
        public Task<ToolResult> ExecuteAsync(JsonElement arguments, ToolExecutionContext ctx, CancellationToken ct) =>
            Task.FromResult(ToolResult.Success("fake screenshot bytes"));
    }

    [Fact]
    public async Task McpHandler_ProtectedForeground_BlocksCall_UntilForegroundChanges()
    {
        var (pairings, _, token) = TestUtil.MakePairing(Scopes.All);
        var policy = new PolicyEngine();
        policy.ProtectedTargets.Add("KeePass");
        var registry = new ToolRegistry();
        registry.Register(new StubDesktopModule());
        var state = new CoreState();
        state.UpdateSession(s => s with { SessionExists = true, AgentConnected = true, DesktopUnlocked = true });
        state.ApplyAgentSessionReport(null, null, "vault.kdbx — KeePass", "KeePass");
        var handler = new McpHandler(pairings, policy, registry, TestUtil.AuditLog(TestUtil.TempDir()), state, new SessionManager());

        const string body = """{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"screenshot","arguments":{}}}""";
        var blocked = await handler.HandleAsync(body, $"Bearer {token}", new HashSet<string>(), default);
        Assert.Contains("blocked_by_user_rule", blocked.Json);

        state.ApplyAgentSessionReport(null, null, "notes.txt — Notepad", "notepad");
        var allowed = await handler.HandleAsync(body, $"Bearer {token}", new HashSet<string>(), default);
        Assert.Contains("fake screenshot bytes", allowed.Json);
    }
}

public class LanTlsTests
{
    private static int FreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    [Fact]
    public void CertificateStore_GeneratesOnce_AndPinIsStableAcrossRestarts()
    {
        var dataDir = TestUtil.TempDir();
        var first = new LanCertificateStore(dataDir);
        var cert1 = first.EnsureCertificate();
        Assert.True(cert1.HasPrivateKey);
        var pin1 = first.Fingerprint;
        Assert.Equal(64, pin1.Length); // SHA-256 hex
        var second = new LanCertificateStore(dataDir);
        Assert.Equal(pin1, second.Fingerprint);
        Assert.Equal(cert1.Thumbprint, second.EnsureCertificate().Thumbprint);
    }

    [Fact]
    public void Pinning_RightPinAccepted_WrongPinAndNoPinRejected()
    {
        var storeA = new LanCertificateStore(TestUtil.TempDir());
        var storeB = new LanCertificateStore(TestUtil.TempDir());
        var certA = storeA.EnsureCertificate();
        Assert.True(CertificatePinning.MatchesPin(certA, storeA.Fingerprint));
        Assert.True(CertificatePinning.MatchesPin(certA, storeA.Fingerprint.ToLowerInvariant()));
        Assert.False(CertificatePinning.MatchesPin(certA, storeB.Fingerprint));
        Assert.False(CertificatePinning.MatchesPin(certA, null));
        Assert.False(CertificatePinning.MatchesPin(null, storeA.Fingerprint));
    }

    [Fact]
    public async Task LanLane_WithoutCertificate_RefusesToStart()
    {
        var (pairings, audit) = MinimalHandlers();
        var lanes = new LaneHostManager(new McpHandler(pairings, new PolicyEngine(), new ToolRegistry(), audit, new CoreState(), new SessionManager()),
            new PairingHandler(pairings, audit), () => new HashSet<string>(), FreePort(), lanCertificate: null);
        Assert.False(await lanes.StartLaneAsync("Lan", "127.0.0.1", default));
        Assert.Empty(lanes.RunningLanes);
        await lanes.DisposeAsync();
    }

    [Fact]
    public async Task LanLane_Tls_PinnedClientConnects_WrongPinAndPlainHttpFail()
    {
        var store = new LanCertificateStore(TestUtil.TempDir());
        var cert = store.EnsureCertificate();
        var pin = store.Fingerprint;
        var port = FreePort();
        var (pairings, audit) = MinimalHandlers();
        var lanes = new LaneHostManager(new McpHandler(pairings, new PolicyEngine(), new ToolRegistry(), audit, new CoreState(), new SessionManager()),
            new PairingHandler(pairings, audit), () => new HashSet<string>(), port, cert);
        try
        {
            Assert.True(await lanes.StartLaneAsync("Lan", "127.0.0.1", default));

            // CONV-F3 test transport (RawSocketTestLeg / log-conv-f3.md):
            // HttpClient loopback connects are steered into this
            // sandbox's egress proxy and never reach the lane (probe
            // D1), so the three legs below speak over a raw Socket —
            // the TLS legs run a real SslStream client handshake with
            // the SAME CertificatePinning.MatchesPin validation the
            // HttpClient callbacks applied, and the HTTP request /
            // response are exercised verbatim on the wire. Only the
            // client transport differs.

            // Correct pin: the handshake completes and the lane serves.
            using (var socket = await RawSocketTestLeg.ConnectSocketLoopbackAsync(port))
            using (var tls = new System.Net.Security.SslStream(
                new NetworkStream(socket, ownsSocket: false), leaveInnerStreamOpen: false,
                (_, presented, _, _) => CertificatePinning.MatchesPin(presented as System.Security.Cryptography.X509Certificates.X509Certificate2, pin)))
            {
                await tls.AuthenticateAsClientAsync(new System.Net.Security.SslClientAuthenticationOptions
                {
                    TargetHost = "127.0.0.1",
                    EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13,
                });
                var request = System.Text.Encoding.ASCII.GetBytes(
                    $"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
                await tls.WriteAsync(request, 0, request.Length);
                using var ms = new MemoryStream();
                await tls.CopyToAsync(ms);
                var raw = System.Text.Encoding.UTF8.GetString(ms.ToArray());
                var statusLine = raw[..raw.IndexOf("\r\n", StringComparison.Ordinal)];
                Assert.Equal((int)HttpStatusCode.OK, int.Parse(statusLine.Split(' ')[1]));
            }

            // Wrong pin: hard rejection at the handshake — no response.
            var wrongPin = new LanCertificateStore(TestUtil.TempDir()).Fingerprint;
            using (var socket = await RawSocketTestLeg.ConnectSocketLoopbackAsync(port))
            using (var tls = new System.Net.Security.SslStream(
                new NetworkStream(socket, ownsSocket: false), leaveInnerStreamOpen: false,
                (_, presented, _, _) => CertificatePinning.MatchesPin(presented as System.Security.Cryptography.X509Certificates.X509Certificate2, wrongPin)))
            {
                await Assert.ThrowsAnyAsync<System.Security.Authentication.AuthenticationException>(
                    () => tls.AuthenticateAsClientAsync(new System.Net.Security.SslClientAuthenticationOptions
                    {
                        TargetHost = "127.0.0.1",
                        EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13,
                    }));
            }

            // Plain HTTP against the TLS port: no service.
            using (var socket = await RawSocketTestLeg.ConnectSocketLoopbackAsync(port))
            using (var plainStream = new NetworkStream(socket, ownsSocket: false))
            {
                var request = System.Text.Encoding.ASCII.GetBytes(
                    $"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
                await plainStream.WriteAsync(request, 0, request.Length);
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                var buffer = new byte[4096];
                var read = 0;
                Exception? readError = null;
                try { read = await plainStream.ReadAsync(buffer, 0, buffer.Length, cts.Token); }
                catch (Exception ex) { readError = ex; }
                // No service = the read died, returned nothing, or the
                // wait timed out — never an HTTP response.
                Assert.True(readError is not null || read == 0,
                    "plain HTTP must not be served on the TLS lane");
            }
        }
        finally { await lanes.DisposeAsync(); }
    }

    [Fact]
    public void PairingExchange_DisclosesLanPin_OnlyOnSuccess()
    {
        var pairings = new PairingService(new DevOnlyPassThroughProtector());
        var audit = TestUtil.AuditLog(TestUtil.TempDir());
        var handler = new PairingHandler(pairings, audit, () => "PIN0123");
        var code = pairings.CreatePairingCode("agent", TimeSpan.FromMinutes(5), Scopes.Preset("full_control"));
        var (status, json) = handler.Handle(JsonSerializer.Serialize(new { code, agent_name = "agent" }));
        Assert.Equal(200, status);
        Assert.Equal("PIN0123", JsonDocument.Parse(json).RootElement.GetProperty("lan_tls_pin").GetString());
        // A failed exchange discloses nothing.
        var (failStatus, failJson) = handler.Handle(JsonSerializer.Serialize(new { code = "bogus", agent_name = "agent" }));
        Assert.Equal(403, failStatus);
        Assert.DoesNotContain("lan_tls_pin", failJson);
    }

    private static (PairingService, FileAuditLog) MinimalHandlers() =>
        (new PairingService(new DevOnlyPassThroughProtector()), TestUtil.AuditLog(TestUtil.TempDir()));
}
