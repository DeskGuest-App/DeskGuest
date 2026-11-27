using System.Diagnostics;
using DeskGuest.Shared.Tor;

namespace DeskGuest.Core.Services;

/// <summary>Runs the provisioned Tor client as an DeskGuest-managed child
/// process (A2). The Core owns the process: start is only ever
/// invoked by TorSetupService AFTER the binary has been re-verified
/// against its pin (the setup act owns that gate; this runner never
/// starts a path it was not handed by the act). On non-Windows
/// platforms the binary's bundled shared libraries ride beside it
/// in the component home, so the library path points there.</summary>
public sealed class TorProcess : ITorProcessRunner
{
    private Process? _process;

    public bool IsRunning => _process is { HasExited: false };

    public void Start(string binaryPath, string torrcPath, string workingDir)
    {
        if (IsRunning) throw new InvalidOperationException("tor process already running");
        var psi = new ProcessStartInfo
        {
            FileName = binaryPath,
            Arguments = $"-f \"{torrcPath}\"",
            WorkingDirectory = workingDir,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        if (!OperatingSystem.IsWindows())
        {
            var libDir = Path.GetDirectoryName(binaryPath)!;
            var existing = Environment.GetEnvironmentVariable("LD_LIBRARY_PATH");
            psi.Environment["LD_LIBRARY_PATH"] = string.IsNullOrEmpty(existing) ? libDir : libDir + ":" + existing;
        }
        _process = Process.Start(psi) ?? throw new InvalidOperationException("failed to start tor process");
    }

    public void Stop()
    {
        if (_process is null) return;
        try
        {
            if (!_process.HasExited)
            {
                _process.Kill(entireProcessTree: true);
                _process.WaitForExit(5000);
            }
        }
        catch { /* already gone */ }
        _process.Dispose();
        _process = null;
    }
}
