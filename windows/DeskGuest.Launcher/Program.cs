using DeskGuest.Launcher;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

// DeskGuest-Windows launcher shim (DESIGN §4.6). This is the binary the SCM
// service registration points at. It is deliberately tiny and stable:
// it never updates itself. At every service start it reads the A/B
// update pointer and execs the Core from the active slot, so a
// health-gated pointer flip becomes a real binary swap at the next
// restart — and a bad slot can never wedge the service, because the
// install-root base binaries are always there to fall back to.
//
// R1 FIX (2026-11-26): the pre-fix launcher was a plain console
// program — it never engaged the Windows Service lifetime, so the
// SCM never received its SERVICE_RUNNING handshake and killed the
// first start at the 30s limit (SCM 7009/7000) even though the Core
// itself came up healthy. The launcher now hosts through the same
// Generic Host + AddWindowsService lifetime the Core uses: the
// lifetime reports RUNNING as soon as the host starts, and the
// migration + child supervision run inside the hosted service's
// ExecuteAsync, off the handshake path. Run interactively, the
// console lifetime applies and behaviour is unchanged.

var installRoot = AppContext.BaseDirectory;
// BD-WIN-AGENT F6: DESKGUEST_DATA_DIR can redirect the data root (and with
// it the updates root the slot binaries come from). A service
// process is non-interactive; in that context the environment is
// not a trust input, so the redirect is IGNORED and the canonical
// ProgramData root is used. The variable keeps working for
// interactive dev runs only.
var dataDir = (!Environment.UserInteractive ? null : Environment.GetEnvironmentVariable("DESKGUEST_DATA_DIR"))
    ?? (OperatingSystem.IsWindows()
        ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "DeskGuest", "data")
        : Path.Combine(installRoot, "deskguest-data"));
var updatesRoot = Path.Combine(dataDir, "updates");
var childArguments = string.Join(" ", args.Select(a => a.Contains(' ') ? $"\"{a}\"" : a));

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(o => o.ServiceName = "DeskGuestCore");
builder.Services.AddHostedService(sp => new LauncherHostedService(
    installRoot, dataDir, updatesRoot, childArguments,
    sp.GetRequiredService<IHostApplicationLifetime>(), Console.Error));
var host = builder.Build();
await host.RunAsync();
return Environment.ExitCode;
