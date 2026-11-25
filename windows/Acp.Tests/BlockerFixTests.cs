using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using Acp.Core;
using Acp.Core.Ipc;
using Acp.Core.Phase2;
using Acp.Core.Services;
using Acp.Shared.Ipc;
using Acp.Shared.Security;
using Acp.Shared.Tools;

namespace Acp.Tests;

/// <summary>Regression tests for the four ACP Windows blockers from
/// The 2026-11-15 review: (1) macro/mission store path traversal,
/// (2) signed-only policy failing open + plugin loads never
/// re-verified, (3) the session agent never authenticating the Core
/// (IPC reverse auth), (4) PowerShell injection through admin-module
/// argument interpolation.</summary>
public class BlockerFixTests
{
    private static ToolExecutionContext Ctx() =>
        new(TestUtil.BarePairing(Scopes.All), TestUtil.Session(),
            TestUtil.State(), new HashSet<string>(), TestUtil.TempDir());

    private static JsonElement Args(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.Clone();
    }

    // ---- Blocker 1: store-name traversal ------------------------------

    [Fact]
    public async Task Macro_SaveTraversal_RefusedAndWritesNothingOutside()
    {
        var dataDir = TestUtil.TempDir();
        var module = new MacroModule(dataDir, new FakeAgentChannel());
        var r = await module.ExecuteAsync(Args("""{"action":"save","name":"../pairings","steps":[]}"""), Ctx(), default);
        Assert.False(r.Ok);
        Assert.Equal("bad_arguments", r.ErrorClass);
        Assert.False(File.Exists(Path.Combine(dataDir, "pairings.json")));
        Assert.Empty(Directory.EnumerateFiles(Path.Combine(dataDir, "macros")));
    }

    [Fact]
    public async Task Macro_ValidName_SaveAndReplay()
    {
        var dataDir = TestUtil.TempDir();
        var module = new MacroModule(dataDir, new FakeAgentChannel());
        var save = await module.ExecuteAsync(Args("""{"action":"save","name":"ok_macro-1","steps":[]}"""), Ctx(), default);
        Assert.True(save.Ok);
        Assert.True(File.Exists(Path.Combine(dataDir, "macros", "ok_macro-1.json")));
        var replay = await module.ExecuteAsync(Args("""{"action":"replay","name":"ok_macro-1"}"""), Ctx(), default);
        Assert.True(replay.Ok);
        var bad = await module.ExecuteAsync(Args("""{"action":"replay","name":"..\\pairings"}"""), Ctx(), default);
        Assert.False(bad.Ok);
        Assert.Equal("bad_arguments", bad.ErrorClass);
    }

    [Fact]
    public void Mission_LoadTraversal_ReturnsNull()
    {
        var engine = new MissionEngine(TestUtil.TempDir());
        Assert.Null(engine.Load("../pairings"));
        Assert.Null(engine.Load("..\\pairings"));
        var m = engine.Create("pairing1", "t", new List<MissionEngine.MissionStep>());
        Assert.NotNull(engine.Load(m.Id));
    }

    // ---- Blocker 2: signature policy fails closed, loads re-verify ----

    [Fact]
    public void Policy_DefaultsToSignedOnly_AndFailsClosedOnCorruptFile()
    {
        var dir = TestUtil.TempDir();
        var policy = new ScriptSignaturePolicy(dir);
        Assert.True(policy.SignedOnly); // no file: ON (was: open)
        policy.SignedOnly = false;
        Assert.False(policy.SignedOnly); // explicit recorded opt-out works
        File.WriteAllText(Path.Combine(dir, "script-policy.json"), "not json");
        Assert.True(new ScriptSignaturePolicy(dir).SignedOnly); // corrupt: closed
    }

    [Fact]
    public void LoadInstalled_UnsignedRefused_WhenSignedOnly()
    {
        var dir = TestUtil.TempDir();
        var plugins = Path.Combine(dir, "plugins");
        Directory.CreateDirectory(plugins);
        File.WriteAllBytes(Path.Combine(plugins, "plugin.dll"), Encoding.UTF8.GetBytes("not an assembly"));
        using var verifier = new RsaUpdateSignatureVerifier();
        var (modules, errors) = ToolModuleInstallModule.LoadInstalled(plugins, verifier, signedOnly: true);
        Assert.Empty(modules);
        Assert.Contains(errors, e => e.Contains("signature"));
    }

    [Fact]
    public void LoadInstalled_SignedDll_PassesTheSignatureGate()
    {
        var dir = TestUtil.TempDir();
        var plugins = Path.Combine(dir, "plugins");
        Directory.CreateDirectory(plugins);
        var dll = Path.Combine(plugins, "plugin.dll");
        var bytes = Encoding.UTF8.GetBytes("not an assembly");
        File.WriteAllBytes(dll, bytes);
        using var signer = new RsaUpdateSignatureVerifier();
        File.WriteAllText(dll + ".sig", Convert.ToBase64String(signer.Sign(bytes)));
        var (modules, errors) = ToolModuleInstallModule.LoadInstalled(plugins, signer, signedOnly: true);
        Assert.Empty(modules); // still not a real assembly…
        Assert.DoesNotContain(errors, e => e.Contains("signature")); // …but the gate passed it
        Assert.NotEmpty(errors); // the load failure itself is named
    }

    [Fact]
    public void LoadInstalled_PolicyOff_KeepsOldBehaviour()
    {
        var dir = TestUtil.TempDir();
        var plugins = Path.Combine(dir, "plugins");
        Directory.CreateDirectory(plugins);
        File.WriteAllBytes(Path.Combine(plugins, "plugin.dll"), Encoding.UTF8.GetBytes("not an assembly"));
        var (_, errors) = ToolModuleInstallModule.LoadInstalled(plugins, null, signedOnly: false);
        Assert.DoesNotContain(errors, e => e.Contains("signature"));
    }

    // ---- Blocker 4: PowerShell literal quoting + argument shapes ------

    [Fact]
    public void PsLiteral_NeutralisesQuotes()
    {
        Assert.Equal("'plain'", RunnerModule.PsLiteral("plain"));
        Assert.Equal("'o''brien'", RunnerModule.PsLiteral("o'brien"));
        Assert.Equal("'a''; evil; '''", RunnerModule.PsLiteral("a'; evil; '"));
        Assert.Equal("''", RunnerModule.PsLiteral(null));
        Assert.Equal("''", RunnerModule.PsLiteral(""));
    }

    [Fact]
    public async Task PackageManage_SmuggledSwitches_Refused()
    {
        var module = new PackageManageModule(new FakeRunner());
        var r = await module.ExecuteAsync(Args("""{"action":"install","package_id":"x --source evil"}"""), Ctx(), default);
        Assert.False(r.Ok);
        Assert.Equal("bad_arguments", r.ErrorClass);
        var clean = await module.ExecuteAsync(Args("""{"action":"install","package_id":"Microsoft.PowerToys"}"""), Ctx(), default);
        Assert.NotEqual("bad_arguments", clean.ErrorClass); // passes validation (OS gate answers on this host)
    }

    // ---- Blocker 3: IPC mutual authentication --------------------------

    [Fact]
    public void IpcAuth_AckBindsTokenAndNonce()
    {
        var nonce = IpcAuth.NewNonce();
        var ack = IpcAuth.ComputeHelloAck("token-abc", nonce);
        Assert.True(IpcAuth.VerifyHelloAck("token-abc", nonce, ack));
        Assert.False(IpcAuth.VerifyHelloAck("token-xyz", nonce, ack));
        Assert.False(IpcAuth.VerifyHelloAck("token-abc", IpcAuth.NewNonce(), ack));
        Assert.False(IpcAuth.VerifyHelloAck("token-abc", nonce, null));
        Assert.False(IpcAuth.VerifyHelloAck("token-abc", nonce, "deadbeef"));
    }

    private static async Task<(AgentIpcServer Server, CancellationTokenSource Cts, Task Run)> StartServerAsync(string token, string pipeName)
    {
        var server = new AgentIpcServer(new CoreState(), token, pipeName);
        var cts = new CancellationTokenSource();
        var run = server.RunAsync(cts.Token);
        return (server, cts, run);
    }

    private static async Task<NamedPipeClientStream> ConnectAndHelloAsync(string pipeName, string nonce, CancellationToken ct)
    {
        var client = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        await client.ConnectAsync(5000, ct);
        var hello = new IpcMessage(IpcKinds.Hello, null, null, JsonSerializer.Serialize(new { nonce }), null, null, "test-agent", true, false, null);
        await IpcFraming.WriteAsync(client, JsonSerializer.Serialize(hello), ct);
        return client;
    }

    [Fact]
    public async Task Ipc_CorrectMutualHandshake_Authenticates()
    {
        var pipeName = "acp-test-" + Guid.NewGuid().ToString("N")[..8];
        var (server, cts, _) = await StartServerAsync("s3cret-token", pipeName);
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            var nonce = IpcAuth.NewNonce();
            using var client = await ConnectAndHelloAsync(pipeName, nonce, timeout.Token);
            var ackJson = await IpcFraming.ReadAsync(client, timeout.Token);
            Assert.NotNull(ackJson);
            var ack = JsonSerializer.Deserialize<IpcMessage>(ackJson!);
            Assert.Equal(IpcKinds.HelloAck, ack!.Kind);
            Assert.True(IpcAuth.VerifyHelloAck("s3cret-token", nonce, ack.Text));
            Assert.False(server.AgentAuthenticated); // not yet: Auth has not been presented
            var auth = new IpcMessage(IpcKinds.Auth, null, null, null, null, "s3cret-token", "test-agent", true, false, null);
            await IpcFraming.WriteAsync(client, JsonSerializer.Serialize(auth), timeout.Token);
            for (var i = 0; i < 100 && !server.AgentAuthenticated; i++)
                await Task.Delay(25, timeout.Token);
            Assert.True(server.AgentAuthenticated);
        }
        finally { cts.Cancel(); server.Dispose(); }
    }

    [Fact]
    public async Task Ipc_WrongTokenAuth_ConnectionDropped()
    {
        var pipeName = "acp-test-" + Guid.NewGuid().ToString("N")[..8];
        var (server, cts, _) = await StartServerAsync("s3cret-token", pipeName);
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            var nonce = IpcAuth.NewNonce();
            using var client = await ConnectAndHelloAsync(pipeName, nonce, timeout.Token);
            var ackJson = await IpcFraming.ReadAsync(client, timeout.Token);
            Assert.NotNull(ackJson); // the proof is offered to anyone; it is worthless without the token
            var auth = new IpcMessage(IpcKinds.Auth, null, null, null, null, "wrong-token", "test-agent", true, false, null);
            await IpcFraming.WriteAsync(client, JsonSerializer.Serialize(auth), timeout.Token);
            var after = await IpcFraming.ReadAsync(client, timeout.Token);
            Assert.Null(after); // server dropped the connection
            Assert.False(server.AgentAuthenticated);
        }
        finally { cts.Cancel(); server.Dispose(); }
    }
}
