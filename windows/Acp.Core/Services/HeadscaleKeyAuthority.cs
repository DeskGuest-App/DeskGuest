using System.Diagnostics;
using Acp.Shared.Hub;

namespace Acp.Core.Services;

/// <summary>Production IHeadscaleKeyAuthority (BD-SHARED-TRANSPORT
/// F2): drives the bundled, hash-pinned headscale binary
/// (preauthkeys create / apikeys create / nodes list) and returns
/// the keys HEADSCALE issued. ACP never invents hub credentials
/// locally any more — the vault and join service only store and
/// consume what this returns. A missing binary, a failed command
/// or unparseable output all return null, and the mint paths
/// refuse by name (fail closed).</summary>
public sealed class HeadscaleCliKeyAuthority : IHeadscaleKeyAuthority
{
    private readonly string _binaryPath;
    private readonly string _configPath;
    private readonly Func<string, string[], string?> _run;

    public HeadscaleCliKeyAuthority(string binaryPath, string configPath,
        Func<string, string[], string?>? runOverride = null)
    {
        _binaryPath = binaryPath;
        _configPath = configPath;
        _run = runOverride ?? RunHeadscale;
    }

    public string? CreatePreAuthKey(string hubUser, TimeSpan lifetime)
    {
        var json = _run(_binaryPath, WithConfig(HeadscaleCli.PreAuthKeyCreateArgs(hubUser, lifetime)));
        return HeadscaleCli.ParseCreatedKey(json, "key");
    }

    public string? CreateApiKey(TimeSpan lifetime)
    {
        var json = _run(_binaryPath, WithConfig(HeadscaleCli.ApiKeyCreateArgs(lifetime)));
        return HeadscaleCli.ParseCreatedKey(json, "apiKey");
    }

    /// <summary>Numeric node ids for the given ACP device ids,
    /// from `headscale nodes list` — feeds
    /// HubNodeRegistry.RecordHeadscaleNodeId so Decommission can
    /// name a real node.</summary>
    public IReadOnlyDictionary<string, string> ListNodeIds(IReadOnlySet<string> deviceIds)
    {
        var json = _run(_binaryPath, WithConfig(HeadscaleCli.NodesListArgs()));
        return HeadscaleCli.ParseNodeIds(json, deviceIds);
    }

    private string[] WithConfig(string[] args)
    {
        var all = new string[args.Length + 2];
        all[0] = "--config"; all[1] = _configPath;
        Array.Copy(args, 0, all, 2, args.Length);
        return all;
    }

    private static string? RunHeadscale(string exe, string[] args)
    {
        try
        {
            if (!File.Exists(exe)) return null;
            var psi = new ProcessStartInfo(exe)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            foreach (var a in args) psi.ArgumentList.Add(a);
            using var proc = Process.Start(psi);
            if (proc is null) return null;
            var output = proc.StandardOutput.ReadToEnd();
            if (!proc.WaitForExit(15000)) { try { proc.Kill(); } catch { } return null; }
            return proc.ExitCode == 0 ? output : null;
        }
        catch { return null; }
    }
}
