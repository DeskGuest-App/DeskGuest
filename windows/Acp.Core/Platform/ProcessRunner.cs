using System.Diagnostics;

namespace Acp.Core.Platform;

public sealed record ProcessResult(int ExitCode, string StdOut, string StdErr, bool TimedOut);

/// <summary>Runs a process with capped output and a hard timeout.
/// The SYSTEM-context shell tool and the fact checks ride on this.</summary>
public interface IProcessRunner
{
    Task<ProcessResult> RunAsync(string fileName, string arguments, TimeSpan timeout, CancellationToken ct);

    /// <summary>Run with the given text on stdin and a scrubbed
    /// environment (ANTHROPIC_API_KEY removed — BD-WIN-CORE-1 F3:
    /// the bridge's billing-route guard must be enforced HERE, in
    /// the spawned process's environment, not merely claimed in a
    /// comment). The default implementation ignores stdin and is
    /// only for test doubles that record calls; the production
    /// runner overrides it.</summary>
    Task<ProcessResult> RunWithStdinAsync(string fileName, string arguments, string stdin, TimeSpan timeout, CancellationToken ct) =>
        RunAsync(fileName, arguments, timeout, ct);
}

public sealed class SystemProcessRunner : IProcessRunner
{
    private const int MaxOutputChars = 64 * 1024;

    public Task<ProcessResult> RunAsync(string fileName, string arguments, TimeSpan timeout, CancellationToken ct) =>
        RunCoreAsync(fileName, arguments, null, scrubEnvironment: false, timeout, ct);

    public Task<ProcessResult> RunWithStdinAsync(string fileName, string arguments, string stdin, TimeSpan timeout, CancellationToken ct) =>
        RunCoreAsync(fileName, arguments, stdin, scrubEnvironment: true, timeout, ct);

    private async Task<ProcessResult> RunCoreAsync(string fileName, string arguments, string? stdin, bool scrubEnvironment, TimeSpan timeout, CancellationToken ct)
    {
        var psi = new ProcessStartInfo(fileName, arguments)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = stdin is not null,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        if (scrubEnvironment)
        {
            // The bridge billing-route guard, enforced in the child
            // environment itself (BD-WIN-CORE-1 F3).
            psi.Environment.Remove("ANTHROPIC_API_KEY");
        }
        using var process = new Process { StartInfo = psi };
        process.Start();
        if (stdin is not null)
        {
            await process.StandardInput.WriteAsync(stdin.AsMemory(), ct);
            process.StandardInput.Close();
        }
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(timeout);
        try
        {
            var stdout = await process.StandardOutput.ReadToEndAsync(timeoutCts.Token);
            var stderr = await process.StandardError.ReadToEndAsync(timeoutCts.Token);
            await process.WaitForExitAsync(timeoutCts.Token);
            return new ProcessResult(process.ExitCode, Cap(stdout), Cap(stderr), false);
        }
        catch (OperationCanceledException)
        {
            try { process.Kill(entireProcessTree: true); } catch { /* already gone */ }
            return new ProcessResult(-1, "", "timed out", true);
        }
    }

    private static string Cap(string s) => s.Length <= MaxOutputChars ? s : s[..MaxOutputChars] + "\n[output capped]";
}
