using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Acp.Core;
using Acp.Shared.Security;

namespace Acp.Tests;

/// <summary>End-to-end over the loopback lane (dev/test flag): the real
/// CoreRuntime, the real HTTP hosts, the real policy choke point.</summary>
public class McpIntegrationTests : IAsyncLifetime
{
    private const int Port = 18741;
    private readonly string _dataDir = TestUtil.TempDir();
    private CoreRuntime _runtime = null!;
    private readonly HttpClient _http = new() { BaseAddress = new Uri($"http://127.0.0.1:{Port}") };

    public async Task InitializeAsync()
    {
        _runtime = new CoreRuntime(new CoreOptions
        {
            DataDir = _dataDir,
            Port = Port,
            IncludeLoopbackLane = true,
            SupervisorPeriod = TimeSpan.FromMilliseconds(100)
        });
        await _runtime.StartAsync(default);
        // Wait for the loopback lane to serve.
        for (var i = 0; i < 50; i++)
        {
            try
            {
                var health = await _http.GetAsync("/healthz");
                if (health.IsSuccessStatusCode) return;
            }
            catch { /* lane not up yet */ }
            await Task.Delay(100);
        }
        throw new InvalidOperationException("loopback lane never came up");
    }

    public async Task DisposeAsync()
    {
        await _runtime.StopAsync(default);
        await _runtime.DisposeAsync();
        _http.Dispose();
    }

    private async Task<string> PairAsync(string preset)
    {
        // Scopes are bound at mint (C1); the /pair body carries no
        // privilege input anymore — the preset argument here only
        // chooses what the HOST binds to the code.
        var code = _runtime.Pairings.CreatePairingCode("integration-agent", TimeSpan.FromMinutes(5), Scopes.Preset(preset));
        var body = JsonSerializer.Serialize(new { code, agent_name = "integration-agent" });
        var response = await _http.PostAsync("/pair", new StringContent(body, Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
        return json.GetProperty("bearer_token").GetString()!;
    }

    private async Task<JsonElement> McpAsync(string token, string method, object? parameters = null)
    {
        var payload = new Dictionary<string, object?> { ["jsonrpc"] = "2.0", ["id"] = 1, ["method"] = method };
        if (parameters is not null) payload["params"] = parameters;
        var request = new HttpRequestMessage(HttpMethod.Post, "/mcp")
        {
            Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json")
        };
        if (token is not null) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        var response = await _http.SendAsync(request);
        var text = await response.Content.ReadAsStringAsync();
        return JsonDocument.Parse(text).RootElement.Clone();
    }

    [Fact]
    public async Task Unauthenticated_McpCall_Is401()
    {
        var payload = JsonSerializer.Serialize(new { jsonrpc = "2.0", id = 1, method = "tools/list" });
        var response = await _http.PostAsync("/mcp", new StringContent(payload, Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Paired_ToolsList_CoversTheCensusSurface()
    {
        var token = await PairAsync("full_control");
        var result = await McpAsync(token, "tools/list");
        var names = result.GetProperty("result").GetProperty("tools").EnumerateArray()
            .Select(t => t.GetProperty("name").GetString()).ToHashSet();
        foreach (var expected in new[]
        {
            "endpoint_state", "shell_exec_system", "file_read", "screenshot",
            "session_unlock", "child_session", "fleet_board", "mission_engine",
            "agent_update", "bridge_queue", "wake_on_lan_send", "tcp_tunnel",
            "power_reboot_safe_mode", "owner_takeover", "live_view", "power_reboot"
        })
            Assert.Contains(expected, names);
        Assert.True(names.Count >= 100, $"expected the full surface, got {names.Count} tools");
    }

    [Fact]
    public async Task Paired_Call_EndpointState_Succeeds()
    {
        var token = await PairAsync("full_control");
        var result = await McpAsync(token, "tools/call", new { name = "endpoint_state", arguments = new { } });
        var text = result.GetProperty("result").GetProperty("content")[0].GetProperty("text").GetString();
        Assert.False(string.IsNullOrWhiteSpace(text));
        Assert.False(result.GetProperty("result").GetProperty("isError").GetBoolean());
    }

    [Fact]
    public async Task LookOnlyPairing_CannotShell()
    {
        var token = await PairAsync("look_only");
        var result = await McpAsync(token, "tools/call", new { name = "shell_exec_system", arguments = new { command = "whoami" } });
        Assert.True(result.GetProperty("result").GetProperty("isError").GetBoolean());
        var text = result.GetProperty("result").GetProperty("content")[0].GetProperty("text").GetString() ?? "";
        Assert.Contains("scope", text);
    }

    [Fact]
    public async Task RevokedPairing_LosesAccessOnNextCall()
    {
        var token = await PairAsync("full_control");
        var pairing = _runtime.Pairings.Authenticate(token);
        Assert.NotNull(pairing);
        Assert.True(_runtime.Pairings.Revoke(pairing!.Id));
        var payload = JsonSerializer.Serialize(new { jsonrpc = "2.0", id = 1, method = "tools/list" });
        var request = new HttpRequestMessage(HttpMethod.Post, "/mcp")
        {
            Content = new StringContent(payload, Encoding.UTF8, "application/json")
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        var response = await _http.SendAsync(request);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }
}
