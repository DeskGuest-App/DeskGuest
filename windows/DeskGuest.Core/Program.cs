using DeskGuest.Core;
using DeskGuest.Shared.Heartbeat;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

// DeskGuest-Windows Core entry point (DESIGN §3.1). On Windows this runs as
// the boot-start LocalSystem service "DeskGuestCore" (SCM recovery configured
// by the installer); elsewhere it runs as a console host, which is how
// the Linux build VM exercises it. The service name and lifetime come
// from AddWindowsService; all behaviour lives in CoreRuntime.

// Self-restart watchdog mode (Block H): a detached copy of this
// binary, armed by service_restart, owns one DeskGuest service's
// stop/start/verify cycle from OUTSIDE the service — the fix for
// the inline restart that stranded the Core in the 2026-11-20
// drill. Dispatched before any host exists; exits with the cycle.
if (args.Contains("--restart-watchdog"))
{
    Environment.ExitCode = await DeskGuest.Core.Services.RestartWatchdogMode.RunAsync(args);
    return;
}

var dataDir = Environment.GetEnvironmentVariable("DESKGUEST_DATA_DIR")
    ?? (OperatingSystem.IsWindows()
        ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "DeskGuest", "data")
        : Path.Combine(AppContext.BaseDirectory, "deskguest-data"));
// Item (20) rename carry-over: on first start under the DeskGuest
// identity, copy any legacy data tree into the new root (no-op when
// the new tree exists or no legacy tree is present). See
// DeskGuest.Shared.Migration.LegacyStateMigration.
try
{
    var migration = DeskGuest.Shared.Migration.LegacyStateMigration.EnsureMigrated(
        dataDir,
        DeskGuest.Shared.Migration.LegacyStateMigration.DefaultLegacyDataDir(AppContext.BaseDirectory));
    if (migration.Outcome is DeskGuest.Shared.Migration.LegacyStateMigration.Outcome.Migrated
        or DeskGuest.Shared.Migration.LegacyStateMigration.Outcome.Merged)
        Console.WriteLine($"DeskGuest Core: carried over {migration.FilesCopied} state file(s) from the legacy data folder into {dataDir} ({migration.FilesAlreadyPresent} already present, {migration.FilesExcluded} excluded by rule).");
}
catch (Exception ex)
{
    Console.Error.WriteLine($"DeskGuest Core: legacy state carry-over failed ({ex.GetType().Name}: {ex.Message}); starting with the new data folder as-is.");
}
var port = int.TryParse(Environment.GetEnvironmentVariable("DESKGUEST_PORT"), out var p) ? p : 8741;
// FR-135 (#15): existence-based sibling resolution — the shipped
// agent is DeskGuest.SessionAgent.exe; the old literal fallback named a
// file that does not exist and stranded every bare launch.
var agentExe = AgentExePathResolver.Resolve(AppContext.BaseDirectory,
    Environment.GetEnvironmentVariable("DESKGUEST_AGENT_EXE"));
var fileRootsEnv = Environment.GetEnvironmentVariable("DESKGUEST_FILE_ROOTS");
var fileRoots = string.IsNullOrWhiteSpace(fileRootsEnv)
    ? Array.Empty<string>()
    : fileRootsEnv.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries);

// FR-124 / W95 (D-W93-1): single-instance guard. The CoreRuntime
// constructor acquires the per-data-dir CoreInstanceLock as its
// first act, before any publishing/binding/state writes; when a
// live Core already holds it, the constructor throws and THIS
// instance exits immediately and cleanly: the clear line on the
// console, its OWN attempted-start record (a new uniquely-named
// file — the shared audit chain is NOT appended to BY THIS
// PROCESS, because W93 proved concurrent chain writes under
// contention are unsafe; W107: the record is tamper-evident and
// the RUNNING Core ingests it into the chain of record from its
// own single-writer side — see CoreRuntime.ConsumeDuplicateStartRecords),
// and the distinct exit code. It writes nothing to heartbeat.json,
// the run marker, the IPC token file, or the trust record, and
// the running Core is completely unaffected.
CoreRuntime runtime;
try
{
    runtime = new CoreRuntime(new CoreOptions
    {
        DataDir = dataDir,
        Port = port,
        AgentExePath = agentExe,
        FileRoots = fileRoots,
        // W30 / D-DEC-7: the install root custodies the runtime
        // pointer-signing key. The launcher passes DESKGUEST_INSTALL_ROOT
        // explicitly because a Core exec'd from an update slot has
        // its base directory inside the data dir (custody there
        // would refuse by name); a Core running from the base
        // binaries IS in the install root.
        InstallRoot = Environment.GetEnvironmentVariable("DESKGUEST_INSTALL_ROOT")
            ?? AppContext.BaseDirectory
    });
}
catch (CoreInstanceLock.AlreadyRunningException ex)
{
    var line = $"DeskGuest Core: {CoreInstanceLock.DuplicateMessage} (data folder: {dataDir}). " +
        "This instance is exiting now; the running Core was not touched. " +
        $"Exit code {CoreInstanceLock.DuplicateExitCode}. Detail: {ex.Message}";
    Console.Error.WriteLine(line);
    Console.WriteLine(line);
    CoreInstanceLock.WriteDuplicateStartRecord(dataDir, line);
    Environment.ExitCode = CoreInstanceLock.DuplicateExitCode;
    return;
}

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(o => o.ServiceName = "DeskGuestCore");
builder.Services.AddSingleton<IHostedService>(runtime);
var host = builder.Build();
await host.RunAsync();
