using Acp.Launcher;

// ACP-Windows launcher shim (DESIGN §4.6). This is the binary the SCM
// service registration points at. It is deliberately tiny and stable:
// it never updates itself. At every service start it reads the A/B
// update pointer and execs the Core from the active slot, so a
// health-gated pointer flip becomes a real binary swap at the next
// restart — and a bad slot can never wedge the service, because the
// install-root base binaries are always there to fall back to.

var installRoot = AppContext.BaseDirectory;
// BD-WIN-AGENT F6: ACP_DATA_DIR can redirect the data root (and with
// it the updates root the slot binaries come from). A service
// process is non-interactive; in that context the environment is
// not a trust input, so the redirect is IGNORED and the canonical
// ProgramData root is used. The variable keeps working for
// interactive dev runs only.
var dataDir = (!Environment.UserInteractive ? null : Environment.GetEnvironmentVariable("ACP_DATA_DIR"))
    ?? (OperatingSystem.IsWindows()
        ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "ACP", "data")
        : Path.Combine(installRoot, "acp-data"));
var updatesRoot = Path.Combine(dataDir, "updates");

try
{
    var exitCode = await LauncherCore.RunAsync(
        installRoot, updatesRoot,
        string.Join(" ", args.Select(a => a.Contains(' ') ? $"\"{a}\"" : a)),
        LauncherCore.StartChildProcessAsync,
        Console.Error);
    return exitCode;
}
catch (Exception ex)
{
    Console.Error.WriteLine($"[acp-launcher] FATAL: {ex.GetType().Name}: {ex.Message}");
    try
    {
        await File.AppendAllTextAsync(Path.Combine(installRoot, "launcher.log"),
            $"{DateTimeOffset.UtcNow:O} FATAL {ex.GetType().Name}: {ex.Message}{Environment.NewLine}");
    }
    catch { /* the log is best-effort; SCM recovery is the backstop */ }
    return 127;
}
