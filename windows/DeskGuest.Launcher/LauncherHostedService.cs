using DeskGuest.Shared.Migration;
using Microsoft.Extensions.Hosting;

namespace DeskGuest.Launcher;

/// <summary>The launcher's hosted service: everything the pre-fix
/// console Program.cs did at startup, moved off the SCM handshake
/// path (R1 fix, 2026-11-26). ExecuteAsync runs AFTER the Windows
/// Service lifetime has reported SERVICE_RUNNING, so the legacy
/// state carry-over and the Core child's whole lifetime can take
/// as long as they take without the SCM timing the start out.
///
/// Lifetime contract, identical to the pre-fix console shape:
/// a child that starts and exits owns its exit code — the code is
/// placed in Environment.ExitCode and the application stops, so
/// the SCM recovery policy decides restarts exactly as it did for
/// the bare Core. An SCM stop cancels the stopping token;
/// LauncherCore.StartChildProcessAsync kills the child (the
/// kill-on-close Job Object is the backstop) and the stop
/// completes as exit code 0 — a requested stop is not a
/// failure.</summary>
public sealed class LauncherHostedService : BackgroundService
{
    private readonly string _installRoot;
    private readonly string _dataDir;
    private readonly string _updatesRoot;
    private readonly string _childArguments;
    private readonly IHostApplicationLifetime _lifetime;
    private readonly TextWriter _log;

    public LauncherHostedService(
        string installRoot, string dataDir, string updatesRoot, string childArguments,
        IHostApplicationLifetime lifetime, TextWriter log)
    {
        _installRoot = installRoot;
        _dataDir = dataDir;
        _updatesRoot = updatesRoot;
        _childArguments = childArguments;
        _lifetime = lifetime;
        _log = log;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            // Item (20) rename carry-over, same discipline as the
            // Core: the launcher is the service entry point, so it
            // runs the one-time legacy-data migration (copy into a
            // fresh tree, merge into a populated one — see
            // LegacyStateMigration) before resolving update slots
            // from the new root.
            try
            {
                LegacyStateMigration.EnsureMigrated(
                    _dataDir,
                    LegacyStateMigration.DefaultLegacyDataDir(_installRoot));
            }
            catch (Exception ex)
            {
                _log.WriteLine($"[deskguest-launcher] legacy state carry-over failed: {ex.GetType().Name}: {ex.Message}");
            }

            var exitCode = await LauncherCore.RunAsync(
                _installRoot, _updatesRoot, _childArguments,
                request => LauncherCore.StartChildProcessAsync(request, stoppingToken),
                _log);
            Environment.ExitCode = exitCode;
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // SCM stop: the child has been killed by the starter;
            // a requested stop completes cleanly.
            Environment.ExitCode = 0;
        }
        catch (Exception ex)
        {
            _log.WriteLine($"[deskguest-launcher] FATAL: {ex.GetType().Name}: {ex.Message}");
            try
            {
                await File.AppendAllTextAsync(Path.Combine(_installRoot, "launcher.log"),
                    $"{DateTimeOffset.UtcNow:O} FATAL {ex.GetType().Name}: {ex.Message}{Environment.NewLine}");
            }
            catch { /* the log is best-effort; SCM recovery is the backstop */ }
            Environment.ExitCode = 127;
        }
        finally
        {
            // The child exited (or the start failed): the service's
            // work is done. Stop the application so the process
            // exits with the child's code and SCM policy applies.
            _lifetime.StopApplication();
        }
    }
}
