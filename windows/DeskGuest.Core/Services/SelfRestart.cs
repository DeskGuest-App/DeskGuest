using System.Diagnostics;
using System.Text.Json;
using DeskGuest.Core.Modules;
using IServiceProvider = DeskGuest.Core.Modules.IServiceProvider;

namespace DeskGuest.Core.Services;

// =====================================================================
// Self-restart that can never strand the Core (Block H fix for the
// defect proven live in the 2026-11-20 break-glass drill).
//
// THE DEFECT: ServiceControlModule's "restart" was Stop()+Start()
// inline. When the target is the Core's OWN service, the Stop kills
// the very process that would issue the Start — the Start line never
// runs, SCM recovery does not fire on a clean stop, and the Core is
// left STOPPED until a human restores it. The drill hit exactly
// this: service_restart stopped the Core and stranded it.
//
// THE SHAPE: a restart of an DeskGuest service is never performed by the
// process being restarted. The tool (1) writes the intent to the
// chained audit BEFORE anything stops, (2) arms an external
// watchdog — a detached copy of this same binary running
// --restart-watchdog — and (3) returns. The watchdog owns the whole
// cycle from outside: stop, wait, start, verify. If the start fails
// it retries; if it still fails and a rollback binary
// (DeskGuestCore.exe.prev*) sits beside the installed exe, it swaps the
// previous binary back in and starts THAT — the floor is "the old
// version runs", never "nothing runs". Every outcome is written to
// <dataDir>/service-restart-outcome.json and raised loudly (Event
// Log); the next Core start consumes the outcome file into the
// chained audit, so the restart's full story lands in the permanent
// record even though the Core was down for part of it.
// =====================================================================

/// <summary>Arms the external restart watchdog. Kept behind an
/// interface so the tool's discipline (never stop yourself, refuse
/// when unarmable) is suite-provable without spawning processes.</summary>
public interface ISelfRestartArmer
{
    void Arm(string serviceName, string dataDir, string exePath);
}

/// <summary>Production armer: spawn a detached copy of the Core
/// binary in --restart-watchdog mode. The child is NOT a service
/// child SCM tracks — SCM stops the service process only, so the
/// watchdog survives the stop it issues and can issue the start.
/// It runs with the service's own account (LocalSystem), which is
/// what starting the service requires.</summary>
public sealed class ProcessSelfRestartArmer : ISelfRestartArmer
{
    /// <summary>How long an arm marker blocks a second arm for
    /// the same service. A watchdog cycle (grace + stop + three
    /// start attempts + a rollback attempt, at the watchdog's own
    /// timeouts) is bounded well under this; a marker older than
    /// this is a dead watchdog's leavings and no longer blocks.</summary>
    public static readonly TimeSpan ArmMarkerFreshness = TimeSpan.FromMinutes(15);

    /// <summary>The arm marker for a service (Block H D38 fix
    /// F11): arming writes it, the watchdog's outcome write
    /// clears it. Two concurrent arms for one service would start
    /// competing watchdogs racing the same stop/start cycle — the
    /// marker makes the second arm refuse instead.</summary>
    public static string ArmMarkerPath(string dataDir, string serviceName) =>
        Path.Combine(dataDir, "restart-watchdog-arms", serviceName + ".arm");

    public void Arm(string serviceName, string dataDir, string exePath)
    {
        if (string.IsNullOrWhiteSpace(exePath) || !File.Exists(exePath))
            throw new InvalidOperationException("cannot arm the restart watchdog: the Core executable path is unknown");
        if (string.IsNullOrWhiteSpace(dataDir))
            throw new InvalidOperationException(
                "cannot arm the restart watchdog: no data directory — the outcome file would land in the watchdog's working directory and never reach the chained audit (F11)");
        var marker = ArmMarkerPath(dataDir, serviceName);
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(marker)!);
            if (File.Exists(marker) &&
                DateTimeOffset.UtcNow - File.GetLastWriteTimeUtc(marker) < ArmMarkerFreshness)
                throw new InvalidOperationException(
                    $"cannot arm the restart watchdog: a watchdog for {serviceName} was already armed moments ago and has not reported an outcome — refusing to start a competing watchdog");
            File.WriteAllText(marker, DateTimeOffset.UtcNow.ToString("O"));
        }
        catch (InvalidOperationException) { throw; }
        catch { /* marker bookkeeping is best-effort; the spawn below is the act */ }
        var psi = new ProcessStartInfo
        {
            FileName = exePath,
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
        };
        psi.ArgumentList.Add("--restart-watchdog");
        psi.ArgumentList.Add(serviceName);
        psi.ArgumentList.Add("--data-dir");
        psi.ArgumentList.Add(dataDir);
        psi.ArgumentList.Add("--exe");
        psi.ArgumentList.Add(exePath);
        try
        {
            using var p = Process.Start(psi)
                ?? throw new InvalidOperationException("cannot arm the restart watchdog: process start returned null");
        }
        catch
        {
            try { File.Delete(marker); } catch { }
            throw;
        }
    }
}

/// <summary>The watchdog's outcome record — the file the next Core
/// start consumes into the chained audit.</summary>
public sealed record RestartOutcome(
    string ServiceName,
    string State,           // restarted | rolled_back | failed | failed_to_stop
    int StartAttempts,
    bool RollbackUsed,
    string Detail,
    DateTimeOffset FinishedUtc);

/// <summary>Where the watchdog leaves its outcome + loud signal.</summary>
public interface IRestartOutcomeSink
{
    void WriteOutcome(RestartOutcome outcome);
    void Loud(string detail);
}

/// <summary>Production sink: the outcome JSON in the data dir (the
/// next Core start reads exactly this path) + a Windows Event Log
/// entry — loud on a machine where the Core itself is down and
/// cannot raise its own alert.</summary>
public sealed class FileRestartOutcomeSink : IRestartOutcomeSink
{
    private readonly string _dataDir;
    public FileRestartOutcomeSink(string dataDir)
    {
        // An empty data dir silently turns every path below
        // cwd-relative — the F11 defect returning at a new
        // construction site. Refuse the construction instead.
        if (string.IsNullOrWhiteSpace(dataDir))
            throw new ArgumentException("a data directory is required — restart outcomes must land where the next Core start consumes them", nameof(dataDir));
        _dataDir = dataDir;
    }

    public static string OutcomePath(string dataDir) =>
        Path.Combine(dataDir, "service-restart-outcome.json");

    /// <summary>The per-outcome directory (Block H D38 fix F11):
    /// EVERY outcome gets its own file here. The old single fixed
    /// file was overwritten by each new outcome and consumed only
    /// at the next Core start — restarting a non-Core service left
    /// the Core running, so that outcome sat unconsumed until a
    /// later outcome overwrote and erased it. The consumer drains
    /// this whole directory (plus the legacy single file).</summary>
    public static string OutcomesDir(string dataDir) =>
        Path.Combine(dataDir, "service-restart-outcomes");

    public static string OutcomeFilePath(string dataDir, RestartOutcome outcome) =>
        Path.Combine(OutcomesDir(dataDir),
            $"{outcome.ServiceName}-{outcome.FinishedUtc:yyyyMMddHHmmssfff}-{Guid.NewGuid():N}.json");

    public void WriteOutcome(RestartOutcome outcome)
    {
        try
        {
            Directory.CreateDirectory(_dataDir);
            Directory.CreateDirectory(OutcomesDir(_dataDir));
            var json = JsonSerializer.Serialize(outcome);
            var file = OutcomeFilePath(_dataDir, outcome);
            File.WriteAllText(file + ".tmp", json);
            File.Move(file + ".tmp", file);
            // Legacy single-file mirror: kept for anything still
            // reading the old path; the directory above is the
            // durable channel.
            var tmp = OutcomePath(_dataDir) + ".tmp";
            File.WriteAllText(tmp, json);
            File.Move(tmp, OutcomePath(_dataDir), overwrite: true);
            // The cycle this arm started is over: clear its arm
            // marker so a later restart can arm again (F11).
            try { File.Delete(ProcessSelfRestartArmer.ArmMarkerPath(_dataDir, outcome.ServiceName)); } catch { }
        }
        catch { /* the Event Log line below is the second channel */ }
        Loud($"DeskGuest service restart watchdog: {outcome.ServiceName} -> {outcome.State} " +
             $"(start attempts {outcome.StartAttempts}, rollback {(outcome.RollbackUsed ? "USED" : "not used")}): {outcome.Detail}");
    }

    public void Loud(string detail)
    {
        try
        {
            if (OperatingSystem.IsWindows())
            {
                const string source = "DeskGuest Core";
                if (!System.Diagnostics.EventLog.SourceExists(source))
                    System.Diagnostics.EventLog.CreateEventSource(source, "Application");
                System.Diagnostics.EventLog.WriteEntry(source, detail,
                    System.Diagnostics.EventLogEntryType.Warning);
            }
        }
        catch { /* loud is best-effort; the outcome file is the record */ }
    }
}

/// <summary>The watchdog state machine. Pure over IServiceProvider
/// + the outcome sink + real files beside the exe (rollback swap),
/// with injectable delay/poll/retry so the whole cycle — including
/// the start-failure rollback — is suite-provable in milliseconds.</summary>
public sealed class RestartWatchdog
{
    private readonly IServiceProvider _svc;
    private readonly IRestartOutcomeSink _sink;
    private readonly Func<TimeSpan, CancellationToken, Task> _delay;
    private readonly Func<DateTimeOffset> _now;
    private readonly Func<string, bool>? _rollbackVerifier;

    public TimeSpan GracePeriod { get; init; } = TimeSpan.FromSeconds(5);
    public TimeSpan PollInterval { get; init; } = TimeSpan.FromMilliseconds(500);
    public TimeSpan StopTimeout { get; init; } = TimeSpan.FromSeconds(60);
    public TimeSpan StartTimeout { get; init; } = TimeSpan.FromSeconds(60);
    public int MaxStartAttempts { get; init; } = 3;

    public RestartWatchdog(IServiceProvider svc, IRestartOutcomeSink sink,
        Func<TimeSpan, CancellationToken, Task>? delay = null,
        Func<DateTimeOffset>? now = null,
        Func<string, bool>? rollbackVerifier = null)
    {
        _svc = svc ?? throw new ArgumentNullException(nameof(svc));
        _sink = sink ?? throw new ArgumentNullException(nameof(sink));
        _delay = delay ?? ((t, ct) => Task.Delay(t, ct));
        _now = now ?? (() => DateTimeOffset.UtcNow);
        _rollbackVerifier = rollbackVerifier;
    }

    /// <summary>BD-WIN-CORE-4/F12: a rollback binary is trusted
    /// ONLY against the hash the installer recorded beside it
    /// (&lt;prev&gt;.sha256, hex SHA-256 of the binary's bytes).
    /// No sidecar, or a mismatching sidecar, means UNTRUSTED: the
    /// watchdog never swaps an unverified binary into the
    /// installed path to run as LocalSystem — anything that can
    /// drop a file into the install directory must not gain a
    /// SYSTEM start by naming it *.prev*.</summary>
    public static bool VerifyRollbackBinary(string prevPath)
    {
        try
        {
            var sidecar = prevPath + ".sha256";
            if (!File.Exists(sidecar)) return false;
            var expected = File.ReadAllText(sidecar).Trim().ToLowerInvariant();
            var actual = Convert.ToHexString(
                System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(prevPath))).ToLowerInvariant();
            return expected.Length == actual.Length &&
                   System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
                       System.Text.Encoding.ASCII.GetBytes(expected),
                       System.Text.Encoding.ASCII.GetBytes(actual));
        }
        catch { return false; }
    }

    private string StatusOf(string name) => _svc.Status(name)?.Status ?? "Unknown";

    private async Task<string> WaitForStatusAsync(string name, string wanted, TimeSpan timeout, CancellationToken ct)
    {
        var deadline = _now() + timeout;
        var status = StatusOf(name);
        while (!string.Equals(status, wanted, StringComparison.OrdinalIgnoreCase) && _now() < deadline)
        {
            await _delay(PollInterval, ct);
            status = StatusOf(name);
        }
        return status;
    }

    /// <summary>Run the whole cycle. Never throws for service-state
    /// reasons: every failure lands in the outcome record instead —
    /// a watchdog that dies silently is the defect this class
    /// exists to replace.</summary>
    public async Task<RestartOutcome> RunAsync(string serviceName, string exePath, CancellationToken ct = default)
    {
        var attempts = 0;
        var rollbackUsed = false;
        RestartOutcome Finish(string state, string detail) => new(
            serviceName, state, attempts, rollbackUsed, detail, _now());

        try
        {
            // Grace: the arming caller finishes its audit + reply
            // (and, when the caller IS the service, its MCP caller
            // gets the answer) before anything stops.
            if (GracePeriod > TimeSpan.Zero) await _delay(GracePeriod, ct);

            var status = StatusOf(serviceName);
            if (string.Equals(status, "Running", StringComparison.OrdinalIgnoreCase) ||
                status.EndsWith("Pending", StringComparison.OrdinalIgnoreCase))
            {
                try { _svc.Stop(serviceName); } catch { /* state re-read below decides */ }
                status = await WaitForStatusAsync(serviceName, "Stopped", StopTimeout, ct);
                if (!string.Equals(status, "Stopped", StringComparison.OrdinalIgnoreCase))
                {
                    var o = Finish("failed_to_stop",
                        $"service did not reach Stopped within {StopTimeout.TotalSeconds:0}s (now {status}); " +
                        "the start was NOT attempted — the service was left in its prior state, not stranded by this watchdog");
                    _sink.WriteOutcome(o);
                    return o;
                }
            }

            // Start, with retries: a start failure is usually
            // transient (a dependency still coming up); the
            // rollback below is the floor, not the first resort.
            string lastError = "";
            for (var i = 0; i < MaxStartAttempts; i++)
            {
                attempts++;
                try { _svc.Start(serviceName); } catch (Exception ex) { lastError = ex.Message; }
                status = await WaitForStatusAsync(serviceName, "Running", StartTimeout, ct);
                if (string.Equals(status, "Running", StringComparison.OrdinalIgnoreCase))
                {
                    var o = Finish("restarted",
                        attempts == 1 && !rollbackUsed
                            ? "service stopped and restarted by the external watchdog"
                            : $"service restarted by the external watchdog after {attempts} start attempt(s)");
                    _sink.WriteOutcome(o);
                    return o;
                }
            }

            // ROLLBACK: the new binary will not start. Put the
            // previous binary back and start that — a running old
            // Core is the floor this design guarantees.
            //
            // The swap is failure-honest (Block H D38 fix F5): the
            // two moves are not atomic, so if the second move
            // fails the ORIGINAL binary is moved back before
            // anything else — the installed path is never left
            // empty by a half-finished swap while a restorable
            // binary exists. And the outcome names what actually
            // happened: before this fix a mid-swap failure was
            // swallowed with rollbackUsed still false, so the
            // record claimed "no rollback binary was available" —
            // false, and pointing the operator the wrong way.
            var prev = FindRollbackBinary(exePath);
            // BD-WIN-CORE-4/F12: verify BEFORE any swap is attempted.
            var prevTrusted = prev is not null &&
                (_rollbackVerifier?.Invoke(prev) ?? VerifyRollbackBinary(prev));
            var swapAttempted = false;
            var swapCompleted = false;
            var swapStranded = false;
            string? failedKeptAt = null;
            if (prev is not null && prevTrusted)
            {
                try
                {
                    swapAttempted = true;
                    var failed = exePath + ".failed-" + _now().ToString("yyyyMMddHHmmss");
                    File.Move(exePath, failed);
                    failedKeptAt = failed;
                    try
                    {
                        File.Move(prev, exePath);
                        swapCompleted = true;
                    }
                    catch
                    {
                        // Second move failed (lock, AV, ACL): put
                        // the original binary BACK at the installed
                        // path before reporting anything.
                        try { File.Move(failed, exePath); failedKeptAt = null; }
                        catch { swapStranded = true; }
                        throw;
                    }
                    rollbackUsed = true;
                    attempts++;
                    try { _svc.Start(serviceName); } catch (Exception ex) { lastError = ex.Message; }
                    status = await WaitForStatusAsync(serviceName, "Running", StartTimeout, ct);
                    if (string.Equals(status, "Running", StringComparison.OrdinalIgnoreCase))
                    {
                        var o = Finish("rolled_back",
                            $"the installed binary would not start after {MaxStartAttempts} attempt(s) ({lastError}); " +
                            $"the previous binary ({Path.GetFileName(prev)}) was restored and is now RUNNING; " +
                            $"the failed binary is kept at {Path.GetFileName(failedKeptAt)}");
                        _sink.WriteOutcome(o);
                        return o;
                    }
                }
                catch (Exception ex) { lastError = ex.Message; }
            }

            var rollbackStory =
                prev is not null && !prevTrusted
                    ? $"a rollback binary was present ({Path.GetFileName(prev)}) but FAILED verification (no installer-recorded .sha256 sidecar, or its hash does not match) — it was NOT swapped in and NOT run as LocalSystem"
                    : swapStranded
                    ? $"CRITICAL: the rollback swap failed midway AND the original binary could not be restored — NO binary is at the installed path; the original is kept at {Path.GetFileName(failedKeptAt!)} and must be moved back by hand"
                    : swapAttempted && !swapCompleted
                        ? $"a rollback binary WAS available ({Path.GetFileName(prev!)}) but the swap failed ({lastError}) — the original binary was restored to the installed path; the rollback did not happen"
                        : rollbackUsed
                            ? "rollback was applied (the previous binary is at the installed path) but it also failed to start"
                            : "no rollback binary was available beside the installed exe";
            var fail = Finish("failed",
                $"service did not reach Running (last state {StatusOf(serviceName)}; {lastError}); " +
                rollbackStory +
                " — this outcome + an Event Log entry are the loud record; restore with DeskGuest-ON.ps1");
            _sink.WriteOutcome(fail);
            return fail;
        }
        catch (Exception ex)
        {
            var o = Finish("failed", $"watchdog itself faulted: {ex.GetType().Name}: {ex.Message}");
            try { _sink.WriteOutcome(o); } catch { }
            return o;
        }
    }

    /// <summary>The newest rollback binary beside the installed
    /// exe: &lt;exe&gt;.prev, &lt;exe&gt;.prev12, &lt;exe&gt;.prev-folder17 —
    /// the installer's own naming. Null when none exists.
    /// Only real binary candidates count: the F12 verification
    /// sidecars (&lt;prev&gt;.sha256) also match the ".prev*"
    /// pattern and are normally written AFTER their binary, so
    /// an unfiltered newest-first enumeration picks the sidecar
    /// — a text hash file — as the "binary"; verification then
    /// refuses it (its own sidecar, &lt;prev&gt;.sha256.sha256,
    /// does not exist) and rollback never happens even though a
    /// verified previous binary sits beside it. Sidecars are
    /// evidence ABOUT a binary, never the binary itself, so
    /// they are excluded here; F12 verification of the chosen
    /// binary is unchanged.</summary>
    public static string? FindRollbackBinary(string exePath)
    {
        if (string.IsNullOrWhiteSpace(exePath)) return null;
        var dir = Path.GetDirectoryName(exePath);
        if (dir is null || !Directory.Exists(dir)) return null;
        var file = Path.GetFileName(exePath);
        return Directory.EnumerateFiles(dir, file + ".prev*")
            .Where(f => !f.EndsWith(".sha256", StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(f => File.GetLastWriteTimeUtc(f))
            .FirstOrDefault();
    }
}

/// <summary>The --restart-watchdog process mode (Program.cs
/// dispatches here before any host is built). Exit code 0 only
/// when the service ends Running (restarted or rolled back).</summary>
public static class RestartWatchdogMode
{
    public static async Task<int> RunAsync(string[] args)
    {
        string? serviceName = null, dataDir = null, exe = null;
        for (var i = 0; i < args.Length; i++)
        {
            if (args[i] == "--restart-watchdog" && i + 1 < args.Length) serviceName = args[++i];
            else if (args[i] == "--data-dir" && i + 1 < args.Length) dataDir = args[++i];
            else if (args[i] == "--exe" && i + 1 < args.Length) exe = args[++i];
        }
        if (serviceName is null || string.IsNullOrWhiteSpace(dataDir) || exe is null) return 2;
        var watchdog = new RestartWatchdog(new WindowsServiceProvider(), new FileRestartOutcomeSink(dataDir));
        var outcome = await watchdog.RunAsync(serviceName, exe);
        return outcome.State is "restarted" or "rolled_back" ? 0 : 1;
    }
}
