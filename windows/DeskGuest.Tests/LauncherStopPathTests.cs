using System.Diagnostics;
using DeskGuest.Launcher;

namespace DeskGuest.Tests;

/// <summary>R1 Defect 1 pins (2026-11-26): the launcher's stop
/// path. The pre-fix StartChildProcessAsync awaited the child's
/// exit with no cancellation, so an SCM stop had no way to bring
/// the Core down with the service. The wait now takes the host's
/// stopping token: cancellation surfaces promptly as
/// OperationCanceledException and the starter kills the child
/// (the kill-on-close Job Object is the backstop). The SCM
/// handshake half of the fix (Generic Host + AddWindowsService in
/// the launcher's Program.cs, mirroring the Core) is structural —
/// it is proven by the live service start in the R1 battery, not
/// by a unit test, and is not claimed here.</summary>
public class LauncherStopPathTests
{
    [Fact]
    public async Task CancelledStop_SurfacesPromptly_InsteadOfWaitingOutTheChild()
    {
        // A 30-second sleeper as the child; a stop that waited for
        // natural exit would take ~30s. Cancellation must surface
        // in a small fraction of that.
        var (exe, args) = OperatingSystem.IsWindows()
            ? ("powershell.exe", "-NoProfile -Command \"Start-Sleep -Seconds 30\"")
            : ("/bin/sleep", "30");
        using var cts = new CancellationTokenSource();
        var sw = Stopwatch.StartNew();
        var run = LauncherCore.StartChildProcessAsync(
            new LaunchRequest(exe, args, new Dictionary<string, string>()),
            cts.Token);
        cts.CancelAfter(TimeSpan.FromMilliseconds(750));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await run);
        sw.Stop();
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(15),
            $"cancellation took {sw.Elapsed} — the stop did not surface promptly");
    }

    [Fact]
    public async Task UncancelledChild_RunsToExit_OwnsItsExitCode()
    {
        // The pre-fix contract is unchanged when nobody stops the
        // service: the child runs to completion and its exit code
        // is the launcher's result.
        var (exe, args) = OperatingSystem.IsWindows()
            ? ("powershell.exe", "-NoProfile -Command \"exit 7\"")
            : ("/bin/sh", "-c \"exit 7\"");
        var code = await LauncherCore.StartChildProcessAsync(
            new LaunchRequest(exe, args, new Dictionary<string, string>()),
            CancellationToken.None);
        Assert.Equal(7, code);
    }
}
