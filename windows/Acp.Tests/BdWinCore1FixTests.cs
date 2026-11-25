using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Acp.Core;
using Acp.Core.Ipc;
using Acp.Core.Mcp;
using Acp.Core.Modules;
using Acp.Core.Platform;
using Acp.Shared.Policy;
using Acp.Shared.Security;
using Acp.Shared.Tools;

namespace Acp.Tests;

/// <summary>BD-WIN-CORE-1 fix lane regression tests (packet
/// 16692022). Every test pins a verified finding's fix; the class
/// names carry the finding id so a failure points at its claim.</summary>
public class BdWinCore1FixTests
{
    private static ToolExecutionContext Ctx(IReadOnlySet<string>? scopes = null, IReadOnlySet<string>? gates = null, string pairingId = "p1") =>
        new(TestUtil.BarePairing(scopes ?? Scopes.All, pairingId), TestUtil.Session(), TestUtil.State(),
            gates ?? new HashSet<string>(), TestUtil.TempDir());

    private static JsonElement Args(string json) => JsonDocument.Parse(json).RootElement.Clone();

    // ---------- F1: IPC client identity is OS-derived ----------
    private static IpcClientFacts Facts(bool system = false, uint clientSession = 1, uint consoleSession = 1,
        string? clientSid = "S-1-5-21-100", string? consoleSid = "S-1-5-21-100",
        string? image = @"C:\Program Files\ACP\AcpSessionAgent.exe", string? expected = @"C:\Program Files\ACP\AcpSessionAgent.exe") =>
        new(clientSession, consoleSession, clientSid, consoleSid, system, image, expected);

    [Fact] public void F1_GenuineAgentFacts_Pass() => Assert.True(IpcClientIdentity.Evaluate(Facts()));
    [Fact] public void F1_SystemClient_Refused() => Assert.False(IpcClientIdentity.Evaluate(Facts(system: true)));
    [Fact] public void F1_WrongSession_Refused() => Assert.False(IpcClientIdentity.Evaluate(Facts(clientSession: 0)));
    [Fact] public void F1_WrongUser_Refused() => Assert.False(IpcClientIdentity.Evaluate(Facts(clientSid: "S-1-5-21-999")));
    [Fact] public void F1_WrongImage_Refused() => Assert.False(IpcClientIdentity.Evaluate(Facts(image: @"C:\evil\AcpSessionAgent.exe".Replace("AcpSessionAgent", "NotAgent"))));
    [Fact] public void F1_NoConsoleSession_Refused() => Assert.False(IpcClientIdentity.Evaluate(Facts(consoleSession: 0xFFFFFFFF)));

    [Fact]
    public void F1_CoreRuntime_PublishesIpcTokenFile_W20Channel()
    {
        // W20 REVISES this pin (W19 diagnosis Defect B): env-only
        // delivery deadlocked task-launched agents, so the Core now
        // publishes the SAME per-boot token to an ACL'd file in the
        // data dir (SYSTEM + console user only on Windows; the ACL
        // plan is pinned in W20TokenChannelTests). What F1 still
        // guarantees: the token reaches ONLY the sanctioned channels
        // — the launcher env block and this one file — and the Core's
        // OS-identity verification is untouched.
        var dir = TestUtil.TempDir();
        var rt = new CoreRuntime(new CoreOptions { DataDir = dir, FactChecks = new FakeFactChecks(), Runner = new FakeRunner() });
        var path = Path.Combine(dir, "ipc-token.txt");
        Assert.True(File.Exists(path), "the W20 token channel must publish the per-boot token file at startup");
        Assert.True(Acp.Shared.Ipc.IpcTokenFile.IsWellFormed(File.ReadAllText(path).Trim()));
        Assert.StartsWith("ipc_file_published", rt.IpcTokenFileStatus);
    }

    [Fact]
    public void F2_AddGrant_InAdministeredScope_WithoutActor_Refused_WithAdminActor_Works()
    {
        var rt = new CoreRuntime(new CoreOptions { DataDir = TestUtil.TempDir(), FactChecks = new FakeFactChecks(), Runner = new FakeRunner() });
        rt.Roster.CreateScope("acme", "company", "Acme");
        rt.Roster.CreateUser("admin", "acme", "Admin", "human");
        rt.Roster.CreateUser("mallory", "acme", "Mallory", "human");
        rt.Roster.CreateUserGroup("ug", "acme", "Users", new[] { "admin" }, Array.Empty<string>());
        rt.Roster.CreateDeviceGroup("dg", "acme", "Devices");
        // Bootstrap: seat the first admin (actor-less seating is the
        // bootstrap case), which makes the scope administered.
        Assert.True(rt.ApplyRosterAction("""{"action":"add_company_admin","scopeId":"acme","userId":"admin"}""").Ok);
        // Actor-less grant in an administered scope: refused.
        var (ok, detail) = rt.ApplyRosterAction("""{"action":"add_grant","scopeId":"acme","userGroupId":"ug","deviceGroupId":"dg","rights":["use"]}""");
        Assert.False(ok, detail);
        // A named non-admin actor: refused by the gated overload.
        var (okForged, detailForged) = rt.ApplyRosterAction("""{"action":"add_grant","scopeId":"acme","userGroupId":"ug","deviceGroupId":"dg","rights":["use"],"actorUserId":"mallory"}""");
        Assert.False(okForged, detailForged);
        // A named company-admin actor: works.
        var (okAdmin, detailAdmin) = rt.ApplyRosterAction("""{"action":"add_grant","scopeId":"acme","userGroupId":"ug","deviceGroupId":"dg","rights":["use"],"actorUserId":"admin"}""");
        Assert.True(okAdmin, detailAdmin);
    }

    [Fact]
    public void F2_AddGrant_BeforeAnyAdmin_BootstrapConstruction_Works()
    {
        // The first-run flow (and the host window's current grant
        // form, which names no actor): a scope with no admins yet
        // can be constructed from the console channel.
        var rt = new CoreRuntime(new CoreOptions { DataDir = TestUtil.TempDir(), FactChecks = new FakeFactChecks(), Runner = new FakeRunner() });
        rt.Roster.CreateScope("beta", "company", "Beta");
        rt.Roster.CreateUser("bea", "beta", "Bea", "human");
        rt.Roster.CreateUserGroup("ops", "beta", "Ops", new[] { "bea" }, Array.Empty<string>());
        rt.Roster.CreateDeviceGroup("fleet", "beta", "Fleet");
        var (ok, detail) = rt.ApplyRosterAction("""{"action":"add_grant","scopeId":"beta","userGroupId":"ops","deviceGroupId":"fleet","rights":["use"]}""");
        Assert.True(ok, detail);
    }

    [Fact]
    public void F2_AddCompanyAdmin_RequiresAdminActor_AfterBootstrap()
    {
        var rt = new CoreRuntime(new CoreOptions { DataDir = TestUtil.TempDir(), FactChecks = new FakeFactChecks(), Runner = new FakeRunner() });
        rt.Roster.CreateScope("acme", "company", "Acme");
        rt.Roster.CreateUser("boss", "acme", "Boss", "human");
        rt.Roster.CreateUser("mallory", "acme", "Mallory", "human");
        rt.Roster.CreateUser("second", "acme", "Second", "human");
        // Bootstrap: no admins yet — the owner at the laptop seats the first.
        var boot = rt.ApplyRosterAction("""{"action":"add_company_admin","scopeId":"acme","userId":"boss"}""");
        Assert.True(boot.Ok, boot.Detail);
        // After bootstrap, a non-admin actor cannot seat another admin.
        var forged = rt.ApplyRosterAction("""{"action":"add_company_admin","scopeId":"acme","userId":"second","actorUserId":"mallory"}""");
        Assert.False(forged.Ok, forged.Detail);
        Assert.False(rt.Roster.IsCompanyAdmin("acme", "second"));
        // A live admin actor can.
        var legit = rt.ApplyRosterAction("""{"action":"add_company_admin","scopeId":"acme","userId":"second","actorUserId":"boss"}""");
        Assert.True(legit.Ok, legit.Detail);
    }

    // ---------- F3: bridge ----------
    private sealed class RecordingRunner : IProcessRunner
    {
        public string? StdinSeen; public int Calls;
        public ProcessResult Result = new(0, "ok", "", false);
        public Task<ProcessResult> RunAsync(string f, string a, TimeSpan t, CancellationToken ct) { Calls++; return Task.FromResult(Result); }
        public Task<ProcessResult> RunWithStdinAsync(string f, string a, string stdin, TimeSpan t, CancellationToken ct)
        { Calls++; StdinSeen = stdin; return Task.FromResult(Result); }
    }

    [Fact]
    public void F3_ValidatePacket_MalformedHex_RefusesCleanly()
    {
        var bridge = new BridgeHost(TestUtil.TempDir(), new RecordingRunner(), () => false);
        Assert.False(bridge.ValidatePacket("{}", "abc"));        // odd length
        Assert.False(bridge.ValidatePacket("{}", "zzzz"));       // non-hex (and wrong length)
        Assert.False(bridge.ValidatePacket("{}", new string('z', 64))); // non-hex, right length
        Assert.False(bridge.ValidatePacket("{}", ""));           // empty
        Assert.True(bridge.ValidatePacket("{}", bridge.ComputeHmac("{}")));
    }

    [Fact]
    public void F3_QueuePacket_TraversalId_Refused()
    {
        var bridge = new BridgeHost(TestUtil.TempDir(), new RecordingRunner(), () => false);
        Assert.Throws<ArgumentException>(() =>
            bridge.QueuePacket(new BridgeHost.BridgePacket("../escape", "k", "p", DateTimeOffset.UtcNow)));
        Assert.False(File.Exists(Path.Combine(bridge.QueueDir, "..", "escape.json")));
    }

    [Fact]
    public async Task F3_RunPacket_PassesPayloadOnStdin_AndMarksDoneOnlyOnSuccess()
    {
        // FindClaudeCli searches PATH: give it a fake install so the
        // run reaches the recording runner.
        var binDir = TestUtil.TempDir();
        await File.WriteAllTextAsync(Path.Combine(binDir, "claude"), "#!/bin/sh" + Environment.NewLine);
        var oldPath = Environment.GetEnvironmentVariable("PATH");
        Environment.SetEnvironmentVariable("PATH", binDir + Path.PathSeparator + oldPath);
        try
        {
        var dir = TestUtil.TempDir();
        var runner = new RecordingRunner { Result = new ProcessResult(1, "", "boom", false) };
        var bridge = new BridgeHost(dir, runner, () => false);
        var packet = new BridgeHost.BridgePacket("pkt-1", "task", "THE PAYLOAD", DateTimeOffset.UtcNow);
        bridge.QueuePacket(packet);
        var failed = await bridge.RunPacketAsync(packet, default);
        Assert.False(failed.Ok);
        Assert.Equal("THE PAYLOAD", runner.StdinSeen); // the packet actually reaches the CLI
        Assert.True(File.Exists(Path.Combine(bridge.QueueDir, "pkt-1.json")), "a failed run must NOT be marked done");
        runner.Result = new ProcessResult(0, "done-output", "", false);
        var ok = await bridge.RunPacketAsync(packet, default);
        Assert.True(ok.Ok);
        Assert.True(File.Exists(Path.Combine(bridge.QueueDir, "done", "pkt-1.json")));
        }
        finally { Environment.SetEnvironmentVariable("PATH", oldPath); }
    }

    // ---------- F5/F7: file transfer + gates ----------
    [Fact]
    public async Task F5_Transfer_Commit_WorksAndOverwritesOnlyWithGate()
    {
        var root = TestUtil.TempDir();
        var scope = new FileScope(new[] { root });
        var mod = new FileTransferModule(scope, TestUtil.TempDir());
        var data = Encoding.UTF8.GetBytes("hello transfer");
        var hash = Convert.ToHexString(SHA256.HashData(data));
        var target = Path.Combine(root, "out.bin");

        async Task<string> Begin()
        {
            var r = await mod.ExecuteAsync(Args(JsonSerializer.Serialize(new { action = "begin", destination = target, sha256 = hash })), Ctx(), default);
            Assert.True(r.Ok, r.Text ?? r.UnavailableReason);
            using var doc = JsonDocument.Parse(r.Text!);
            return doc.RootElement.GetProperty("transfer_id").GetString()!;
        }
        async Task<ToolResult> Chunk(string id) =>
            await mod.ExecuteAsync(Args(JsonSerializer.Serialize(new { action = "chunk", transfer_id = id, data_base64 = Convert.ToBase64String(data) })), Ctx(), default);
        async Task<ToolResult> Commit(string id, IReadOnlySet<string> gates) =>
            await mod.ExecuteAsync(Args(JsonSerializer.Serialize(new { action = "commit", transfer_id = id })), Ctx(gates: gates), default);

        var id1 = await Begin(); Assert.True((await Chunk(id1)).Ok);
        var commit1 = await Commit(id1, new HashSet<string>());
        Assert.True(commit1.Ok, commit1.Text ?? commit1.UnavailableReason ?? commit1.ErrorClass);
        Assert.Equal("hello transfer", await File.ReadAllTextAsync(target));

        // Overwriting the now-existing target requires the deletions gate.
        var id2 = await Begin(); Assert.True((await Chunk(id2)).Ok);
        var commit2 = await Commit(id2, new HashSet<string>());
        Assert.False(commit2.Ok);
        Assert.Contains("deletions", commit2.ErrorClass + commit2.Text);
        var id3 = await Begin(); Assert.True((await Chunk(id3)).Ok);
        var commit3 = await Commit(id3, new HashSet<string> { "deletions" });
        Assert.True(commit3.Ok, commit3.Text ?? commit3.ErrorClass);
    }

    [Fact]
    public async Task F7_StagingPrune_RequiresDeletionsGate_AndPositiveRetention()
    {
        var root = TestUtil.TempDir();
        await File.WriteAllTextAsync(Path.Combine(root, "old.txt"), "x");
        File.SetLastWriteTimeUtc(Path.Combine(root, "old.txt"), DateTime.UtcNow.AddDays(-90));
        var mod = new StagingStoreModule(new FileScope(new[] { root }));
        var ungated = await mod.ExecuteAsync(Args("""{"action":"prune","retention_days":30}"""), Ctx(), default);
        Assert.False(ungated.Ok);
        Assert.True(File.Exists(Path.Combine(root, "old.txt")));
        var zero = await mod.ExecuteAsync(Args("""{"action":"prune","retention_days":0}"""), Ctx(gates: new HashSet<string> { "deletions" }), default);
        Assert.False(zero.Ok);
        var gated = await mod.ExecuteAsync(Args("""{"action":"prune","retention_days":30}"""), Ctx(gates: new HashSet<string> { "deletions" }), default);
        Assert.True(gated.Ok, gated.Text);
        Assert.False(File.Exists(Path.Combine(root, "old.txt")));
    }

    [Fact]
    public void F7_Registry_ProtectedKeys_Refuse()
    {
        Assert.True(AcpProtectedRegistryKeys.IsProtected(@"HKLM\SYSTEM\CurrentControlSet\Services\AcpCore"));
        Assert.True(AcpProtectedRegistryKeys.IsProtected(@"HKLM\SOFTWARE\ACP\Policy"));
        Assert.False(AcpProtectedRegistryKeys.IsProtected(@"HKLM\SOFTWARE\SomeVendor\App"));
    }

    [Fact]
    public void F7_FileScope_SymlinkEscape_Refused()
    {
        if (OperatingSystem.IsWindows()) return; // symlink creation needs privilege on Windows; Linux CI proves the logic
        var root = TestUtil.TempDir();
        var outside = TestUtil.TempDir();
        File.WriteAllText(Path.Combine(outside, "secret.txt"), "s");
        File.CreateSymbolicLink(Path.Combine(root, "link.txt"), Path.Combine(outside, "secret.txt"));
        var scope = new FileScope(new[] { root });
        Assert.Null(scope.ResolveInScope(Path.Combine(root, "link.txt")));
        File.WriteAllText(Path.Combine(root, "real.txt"), "r");
        Assert.NotNull(scope.ResolveInScope(Path.Combine(root, "real.txt")));
    }

    // ---------- F6/F9: MCP choke point ----------
    private sealed class ShellProbeModule : IToolModule
    {
        public int Executions;
        public ToolDescriptor Descriptor { get; } = new("shell_probe", "probe", Scopes.Shell, SessionRequirement.Core, RiskTier.Low, ExecutionContext: "SYSTEM");
        public Task<ToolResult> ExecuteAsync(JsonElement a, ToolExecutionContext c, CancellationToken ct)
        { Executions++; return Task.FromResult(ToolResult.Success("shell ran")); }
    }

    private (McpHandler Handler, string Token, SessionManager Sessions, Pairing Pairing) McpSetup()
    {
        var (pairings, pairing, token) = TestUtil.MakePairing(Scopes.All);
        var sessions = new SessionManager();
        var registry2 = new ToolRegistry();
        var probe = new ShellProbeModule();
        registry2.Register(probe);
        registry2.Register(new SessionStartModule(sessions, new CoreState()));
        _probe = probe;
        var handler = new McpHandler(pairings, new PolicyEngine(), registry2, TestUtil.AuditLog(TestUtil.TempDir()),
            new CoreState(), sessions, TestUtil.TempDir());
        return (handler, token, sessions, pairing);
    }
    private ShellProbeModule _probe = null!;

    private static string CallBody(string name) =>
        JsonSerializer.Serialize(new { jsonrpc = "2.0", id = 1, method = "tools/call", @params = new { name, arguments = new { } } })
            .Replace("\"@params\"", "\"params\"");

    [Fact]
    public async Task F6_ShellTool_WithoutSession_Refused_ThenAllowedInOwnSession()
    {
        var (handler, token, sessions, pairing) = McpSetup();
        var refused = await handler.HandleAsync(CallBody("shell_probe"), $"Bearer {token}", new HashSet<string>(), default);
        Assert.Contains("no_session", refused.Json);
        Assert.Equal(0, _probe.Executions);
        sessions.Start(pairing);
        var allowed = await handler.HandleAsync(CallBody("shell_probe"), $"Bearer {token}", new HashSet<string>(), default);
        Assert.Contains("shell ran", allowed.Json);
        Assert.Equal(1, _probe.Executions);
    }

    [Fact]
    public async Task F6_OtherPairingsSession_CannotBeRidden()
    {
        var (handler, token, sessions, _) = McpSetup();
        sessions.Start(TestUtil.BarePairing(Scopes.All, "someone-else"));
        var refused = await handler.HandleAsync(CallBody("shell_probe"), $"Bearer {token}", new HashSet<string>(), default);
        Assert.Contains("session_owned_by_other_pairing", refused.Json);
        Assert.Equal(0, _probe.Executions);
    }

    [Fact]
    public async Task F9_ToolsList_FilteredByPairingScopes()
    {
        var (pairings, _, token) = TestUtil.MakePairing(new HashSet<string> { Scopes.Observe });
        var registry = new ToolRegistry();
        registry.Register(new ShellProbeModule());
        var handler = new McpHandler(pairings, new PolicyEngine(), registry, TestUtil.AuditLog(TestUtil.TempDir()),
            new CoreState(), new SessionManager(), TestUtil.TempDir());
        var list = await handler.HandleAsync("""{"jsonrpc":"2.0","id":1,"method":"tools/list"}""", $"Bearer {token}", new HashSet<string>(), default);
        Assert.DoesNotContain("shell_probe", list.Json);
    }

    [Fact]
    public async Task F9_NonStringMethod_InvalidRequestNotException()
    {
        var (handler, token, _, _) = McpSetup();
        var r = await handler.HandleAsync("""{"jsonrpc":"2.0","id":1,"method":42}""", $"Bearer {token}", new HashSet<string>(), default);
        Assert.Contains("-32600", r.Json);
    }

    [Fact]
    public void F9_PairingThrottle_IsPerSource()
    {
        var pairings = new PairingService(new DevOnlyPassThroughProtector());
        var handler = new PairingHandler(pairings, TestUtil.AuditLog(TestUtil.TempDir()));
        for (var i = 0; i < 5; i++)
            Assert.Equal(403, handler.Handle("""{"code":"bad","agent_name":"x"}""", "10.0.0.9").Status);
        Assert.Equal(429, handler.Handle("""{"code":"bad","agent_name":"x"}""", "10.0.0.9").Status);
        // A different source is NOT locked out by the attacker's failures.
        Assert.Equal(403, handler.Handle("""{"code":"bad","agent_name":"x"}""", "10.0.0.10").Status);
    }

    // ---------- F8: scrape SSRF classification ----------
    [Theory]
    [InlineData("::ffff:10.0.0.1")]   // IPv4-mapped private
    [InlineData("fc00::1")]           // unique-local
    [InlineData("fd12::1")]           // unique-local
    [InlineData("ff02::1")]           // multicast v6
    [InlineData("224.0.0.1")]         // multicast v4
    [InlineData("255.255.255.255")]   // broadcast
    [InlineData("169.254.169.254")]   // metadata
    public void F8_PrivateOrSpecial_Classified(string ip) =>
        Assert.True(ScrapeModule.IsPrivateOrSpecial(System.Net.IPAddress.Parse(ip)), ip);

    [Fact]
    public void F8_Public_NotClassified() =>
        Assert.False(ScrapeModule.IsPrivateOrSpecial(System.Net.IPAddress.Parse("93.184.216.34")));

    // ---------- F10: presence / notify ----------
    [Fact]
    public async Task F10_PresenceNarration_RequiresOwnSession()
    {
        var state = new CoreState();
        var ipc = new AgentIpcServer(state);
        var sessions = new SessionManager();
        var mod = new PresenceControlModule(ipc, state, sessions);
        var noSession = await mod.ExecuteAsync(Args("""{"narration":"Windows Update in progress"}"""), Ctx(), default);
        Assert.False(noSession.Ok);
        sessions.Start(TestUtil.BarePairing(Scopes.All, "p1"));
        var own = await mod.ExecuteAsync(Args("""{"narration":"working"}"""), Ctx(), default);
        Assert.True(own.Ok, own.Text ?? own.ErrorClass);
    }

    [Fact]
    public async Task F10_Notify_RateLimitedPerPairing()
    {
        var dir = TestUtil.TempDir();
        var ipc = new AgentIpcServer(new CoreState());
        var mod = new NotifyUserModule(ipc, dir);
        for (var i = 0; i < NotifyUserModule.MaxNotificationsPerMinute; i++)
            Assert.True((await mod.ExecuteAsync(Args("""{"message":"hi"}"""), Ctx(), default)).Ok);
        var sixth = await mod.ExecuteAsync(Args("""{"message":"hi"}"""), Ctx(), default);
        Assert.False(sixth.Ok);
        Assert.Contains("rate_limited", sixth.ErrorClass);
    }

    // ---------- F12: store writes ----------
    [Fact]
    public void F12_WriteStoreAtomic_UniqueTemp_NoCollisionResidue()
    {
        var dir = TestUtil.TempDir();
        var rt = new CoreRuntime(new CoreOptions { DataDir = dir, FactChecks = new FakeFactChecks(), Runner = new FakeRunner() });
        // Exercise a store write-through several times; no .tmp-* residue may remain.
        for (var i = 0; i < 5; i++)
        {
            var code = rt.Pairings.CreatePairingCode("a" + i, TimeSpan.FromMinutes(1), Scopes.Preset("look_only"));
            rt.Pairings.ExchangeCode(code, "a" + i);
        }
        Assert.Empty(Directory.EnumerateFiles(dir, "*.tmp-*"));
        Assert.True(File.Exists(Path.Combine(dir, "pairings.json")));
    }
}
