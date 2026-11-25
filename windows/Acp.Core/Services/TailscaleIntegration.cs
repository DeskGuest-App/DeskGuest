using System.Diagnostics;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Acp.Shared.Tailscale;
using Microsoft.Win32;

namespace Acp.Core.Services;

/// <summary>Production daemon probe (Block C part 3): reads the
/// local Tailscale client's own reports — `tailscale version`,
/// `tailscale debug prefs` (RunSSH), `tailscale serve status
/// --json` (Serve/Funnel) — and the Windows service environment
/// for the logtail kill switch ACP asserts. Anything it cannot
/// determine makes the probe UNRELIABLE, and setup refuses on an
/// unreliable probe rather than guessing (T2 §7.2: the rung
/// refuses to come up if the kill switch cannot be verified).
/// This probe was exercised against the laptop's installed client
/// during the part-3 proof; the vendor-account legs behind it
/// remain UNPROVEN (no account may be created under programme
/// law).</summary>
public sealed class TailscaleCliProbe : ITailscaleDaemonProbe
{
    public TailscaleDaemonFacts Probe()
    {
        var version = RunCli("version")?.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(l => l.Trim()).FirstOrDefault();
        var reliable = version is not null;

        var prefs = RunCli("debug", "prefs");
        bool? runSsh = null;
        if (prefs is not null)
        {
            try
            {
                using var doc = JsonDocument.Parse(prefs);
                if (doc.RootElement.TryGetProperty("RunSSH", out var rs) && rs.ValueKind is JsonValueKind.True or JsonValueKind.False)
                    runSsh = rs.GetBoolean();
            }
            catch { /* unparsable prefs = unreliable below */ }
        }
        if (runSsh is null) reliable = false;

        var serve = RunCli("serve", "status", "--json");
        bool? serveOn = null, funnelOn = null;
        if (serve is not null)
        {
            try
            {
                using var doc = JsonDocument.Parse(serve);
                serveOn = doc.RootElement.EnumerateObject().Any();
                // BD-WIN-CORE-4/F3: Funnel is read from the PARSED
                // document, never from a raw-text substring — the
                // old exact-whitespace match ('"AllowFunnel": {')
                // reported FunnelEnabled=false for compact JSON
                // while ProbeReliable stayed true, so setup would
                // accept a publicly Funnel-exposed node.
                funnelOn = ParseAllowFunnel(doc.RootElement);
            }
            catch { /* unparsable = unreliable */ }
        }
        if (serveOn is null || funnelOn is null) reliable = false;

        return new TailscaleDaemonFacts(
            InstalledVersion: version,
            LogtailState: ServiceEnvAssertsKillSwitch() ? "disabled-no-logs" : "not-asserted",
            SshEnabled: runSsh ?? true,
            ServeEnabled: serveOn ?? true,
            FunnelEnabled: funnelOn ?? true,
            Conn25Used: false,
            ProbeReliable: reliable);
    }

    /// <summary>BD-WIN-CORE-4/F3: interpret the AllowFunnel entry of
    /// a parsed `tailscale serve status --json` document. Shapes:
    /// absent → false (no funnel configured); boolean → itself;
    /// object (host:port → bool map, the client's real shape) →
    /// true when ANY entry is true. Any other shape is unexpected
    /// → null, which makes the probe UNRELIABLE (refuse rather
    /// than guess).</summary>
    internal static bool? ParseAllowFunnel(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object) return null;
        if (!root.TryGetProperty("AllowFunnel", out var af)) return false;
        return af.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            JsonValueKind.Object => af.EnumerateObject().Any(p =>
                p.Value.ValueKind == JsonValueKind.True ||
                (p.Value.ValueKind == JsonValueKind.Object &&
                 p.Value.EnumerateObject().Any(q => q.Value.ValueKind == JsonValueKind.True))),
            _ => null,
        };
    }

    /// <summary>The kill switch on Windows lives in the Tailscale
    /// service's environment (HKLM\…\Services\Tailscale\Environment).
    /// ACP asserts it there at setup time (an elevated, recorded
    /// act); this reads it back for verification.</summary>
    public static bool ServiceEnvAssertsKillSwitch()
    {
        if (!OperatingSystem.IsWindows()) return false;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\Tailscale");
            if (key?.GetValue("Environment") is string[] env)
                return env.Any(e => e.StartsWith(TailscalePins.KillSwitchEnvVar + "=true", StringComparison.OrdinalIgnoreCase));
            return false;
        }
        catch { return false; }
    }

    private static string? RunCli(params string[] args)
    {
        try
        {
            var exe = File.Exists(@"C:\Program Files\Tailscale\tailscale.exe")
                ? @"C:\Program Files\Tailscale\tailscale.exe" : "tailscale";
            var psi = new ProcessStartInfo(exe)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            foreach (var a in args) psi.ArgumentList.Add(a);
            using var p = Process.Start(psi);
            if (p is null) return null;
            var outTask = p.StandardOutput.ReadToEndAsync();
            if (!p.WaitForExit(10_000)) { try { p.Kill(); } catch { } return null; }
            return p.ExitCode == 0 ? outTask.GetAwaiter().GetResult() : null;
        }
        catch { return null; }
    }
}

/// <summary>The real Tailscale admin API surface (api.tailscale.com
/// /api/v2), implemented against the vendor's published endpoints:
/// OAuth client-credentials exchange, policy get/validate/apply,
/// auth-key creation. Secrets travel only in the token-exchange
/// body and the Authorization header — never in URLs, never
/// logged. LIVE-ACCOUNT STATUS: UNPROVEN — no real account exists
/// in this programme; the flow is proven against a local mock of
/// this same surface (see Acp.Tests).</summary>
public sealed class TailscaleHttpApi : ITailscaleApi
{
    private static readonly HttpClient Http = new() { BaseAddress = new Uri("https://api.tailscale.com/api/v2/") };

    public async Task<ApiResult> ExchangeOAuthAsync(string clientId, string clientSecret, IReadOnlyList<string> scopes, CancellationToken ct = default)
    {
        try
        {
            var form = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["client_id"] = clientId,
                ["client_secret"] = clientSecret,
                ["grant_type"] = "client_credentials",
            });
            using var resp = await Http.PostAsync("oauth/token", form, ct);
            var body = await resp.Content.ReadAsStringAsync(ct);
            if (!resp.IsSuccessStatusCode) return new ApiResult(false, $"token exchange HTTP {(int)resp.StatusCode}");
            using var doc = JsonDocument.Parse(body);
            var token = doc.RootElement.GetProperty("access_token").GetString();
            int? expiresIn = doc.RootElement.TryGetProperty("expires_in", out var ei) && ei.TryGetInt32(out var secs) ? secs : null;
            return token is null ? new ApiResult(false, "token exchange returned no access_token") : new ApiResult(true, "token exchanged", Token: token, ExpiresInSeconds: expiresIn);
        }
        catch (Exception ex) { return new ApiResult(false, $"token exchange failed ({ex.GetType().Name})"); }
    }

    public Task<ApiResult> ExchangeFederatedAsync(IReadOnlyList<string> scopes, CancellationToken ct = default) =>
        Task.FromResult(new ApiResult(false,
            "federated identity exchange is not configured in this build — present a scoped OAuth trust credential instead"));

    private static HttpRequestMessage Authed(HttpMethod method, string path, string token, string? jsonBody = null)
    {
        var req = new HttpRequestMessage(method, path);
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        if (jsonBody is not null) req.Content = new StringContent(jsonBody, Encoding.UTF8, "application/json");
        return req;
    }

    public async Task<ApiResult> GetPolicyAsync(string token, CancellationToken ct = default)
    {
        try
        {
            using var resp = await Http.SendAsync(Authed(HttpMethod.Get, "tailnet/-/acl", token), ct);
            var body = await resp.Content.ReadAsStringAsync(ct);
            return resp.IsSuccessStatusCode
                ? new ApiResult(true, "policy read", Policy: body)
                : new ApiResult(false, $"policy read HTTP {(int)resp.StatusCode}");
        }
        catch (Exception ex) { return new ApiResult(false, $"policy read failed ({ex.GetType().Name})"); }
    }

    public async Task<ApiResult> ValidatePolicyAsync(string token, string policy, CancellationToken ct = default)
    {
        try
        {
            using var resp = await Http.SendAsync(Authed(HttpMethod.Post, "tailnet/-/acl/validate", token, policy), ct);
            return resp.IsSuccessStatusCode
                ? new ApiResult(true, "policy valid")
                : new ApiResult(false, $"policy validation HTTP {(int)resp.StatusCode}: " + await resp.Content.ReadAsStringAsync(ct));
        }
        catch (Exception ex) { return new ApiResult(false, $"policy validation failed ({ex.GetType().Name})"); }
    }

    public async Task<ApiResult> ApplyPolicyAsync(string token, string policy, CancellationToken ct = default)
    {
        try
        {
            using var resp = await Http.SendAsync(Authed(HttpMethod.Post, "tailnet/-/acl", token, policy), ct);
            return resp.IsSuccessStatusCode
                ? new ApiResult(true, "policy applied")
                : new ApiResult(false, $"policy apply HTTP {(int)resp.StatusCode}");
        }
        catch (Exception ex) { return new ApiResult(false, $"policy apply failed ({ex.GetType().Name})"); }
    }

    public async Task<ApiResult> CreateAuthKeyAsync(string token, IReadOnlyList<string> tags, bool singleUse, TimeSpan expiry, CancellationToken ct = default)
    {
        try
        {
            var body = JsonSerializer.Serialize(new
            {
                capabilities = new
                {
                    devices = new
                    {
                        create = new { reusable = !singleUse, ephemeral = false, preauthorized = true, tags },
                    },
                },
                expirySeconds = (long)expiry.TotalSeconds,
            });
            using var resp = await Http.SendAsync(Authed(HttpMethod.Post, "tailnet/-/keys", token, body), ct);
            var text = await resp.Content.ReadAsStringAsync(ct);
            if (!resp.IsSuccessStatusCode) return new ApiResult(false, $"auth key mint HTTP {(int)resp.StatusCode}");
            using var doc = JsonDocument.Parse(text);
            var key = doc.RootElement.TryGetProperty("key", out var k) ? k.GetString() : null;
            return key is null ? new ApiResult(false, "auth key mint returned no key") : new ApiResult(true, "auth key minted", AuthKey: key);
        }
        catch (Exception ex) { return new ApiResult(false, $"auth key mint failed ({ex.GetType().Name})"); }
    }
}
