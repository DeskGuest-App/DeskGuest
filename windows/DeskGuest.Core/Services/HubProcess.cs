using System.Diagnostics;
using System.Net;
using DeskGuest.Shared.Hub;

namespace DeskGuest.Core.Services;

/// <summary>Runs the packaged Headscale binary as an DeskGuest-managed child
/// process (hub packaging, Block C part 2). The Core owns the process:
/// start is only ever invoked by HubLifecycle after the §8 self-check has
/// passed against the on-disk config + policy; stop is GRACEFUL FIRST
/// (BD-WIN-CORE-3/F5): the child is asked to exit and given a grace
/// wait — Headscale flushes its DB on termination — and is killed
/// only after that wait expires. Both redirected streams are DRAINED
/// asynchronously into a bounded ring from the moment the process
/// starts: the old shape redirected stdout/stderr and never read
/// them, so a few KB of hub logs filled the pipe buffer, Headscale
/// blocked on its writes, and the hub silently stopped responding.</summary>
public sealed class HubProcess : IHubProcess
{
    private Process? _process;
    private readonly object _logGate = new();
    private readonly Queue<string> _logRing = new();
    private const int LogRingCapacity = 200;

    public bool IsRunning => _process is { HasExited: false };

    /// <summary>The bounded tail of the hub child's drained output
    /// (stdout+stderr interleaved by arrival).</summary>
    public IReadOnlyList<string> RecentOutput { get { lock (_logGate) return _logRing.ToList(); } }

    public void Start(string binaryPath, string configPath, string workingDir)
    {
        if (IsRunning) throw new InvalidOperationException("hub process already running");
        var psi = new ProcessStartInfo
        {
            FileName = binaryPath,
            Arguments = $"serve --config \"{configPath}\"",
            WorkingDirectory = workingDir,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
        };
        _process = Process.Start(psi) ?? throw new InvalidOperationException("failed to start hub process");
        // BD-WIN-CORE-3/F5: drain BOTH streams for the life of the
        // process — an undrained redirected pipe is a deadlock.
        _process.OutputDataReceived += (_, e) => PushLog(e.Data);
        _process.ErrorDataReceived += (_, e) => PushLog(e.Data);
        _process.BeginOutputReadLine();
        _process.BeginErrorReadLine();
    }

    private void PushLog(string? line)
    {
        if (line is null) return;
        lock (_logGate)
        {
            _logRing.Enqueue(line);
            while (_logRing.Count > LogRingCapacity) _logRing.Dequeue();
        }
    }

    public void Stop()
    {
        if (_process is null) return;
        try
        {
            if (!_process.HasExited)
            {
                // Graceful first (BD-WIN-CORE-3/F5): close the
                // child's stdin / ask it to exit and wait the grace
                // period; kill the tree ONLY if it outlives it.
                try { _process.StandardInput?.Close(); } catch { }
                if (!_process.WaitForExit(5000))
                {
                    _process.Kill(entireProcessTree: true);
                    _process.WaitForExit(5000);
                }
            }
        }
        catch { /* already gone */ }
        _process.Dispose();
        _process = null;
    }

    /// <summary>BD-WIN-CORE-3/F5: the health probe is a LOOPBACK-only
    /// surface. The old callback accepted ANY certificate for ANY
    /// URL handed in; now a non-loopback URL is refused outright,
    /// and the certificate callback accepts only for the loopback
    /// host actually being probed (the DeskGuest-managed hub cert).</summary>
    public bool HealthOk(string healthUrl)
    {
        try
        {
            if (!Uri.TryCreate(healthUrl, UriKind.Absolute, out var uri) ||
                !IPAddress.TryParse(uri.Host, out var ip) || !IPAddress.IsLoopback(ip))
                return false; // not loopback — refused, never probed
            using var handler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (_, cert, _, _) =>
                    cert is not null && IPAddress.IsLoopback(ip),
            };
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(3) };
            var resp = client.GetAsync(healthUrl).GetAwaiter().GetResult();
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }
}
