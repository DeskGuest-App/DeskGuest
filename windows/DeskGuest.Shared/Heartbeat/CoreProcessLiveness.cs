using System.Diagnostics;

namespace DeskGuest.Shared.Heartbeat;

/// <summary>
/// W113 (W112-C4b) — the death proof independent of activity
/// timestamps. W107/W111 decided a pre-W95 marker's owner
/// (OwnerPid=0) dead when marker AND heartbeat were both stale —
/// but both files are written by the old Core itself, so a
/// suspended or stalled LIVE old Core freezes both signs together
/// and the new Core booted over it. Timestamps are activity, not
/// liveness. This class asks the OS instead: is another DeskGuest
/// Core PROCESS alive right now?
///
/// THE IDENTITY RULE (exactly what matches): a process counts as
/// another DeskGuest Core when its image name — the file name of
/// its executable image, with any ".exe" suffix stripped,
/// compared case-insensitively — is exactly "DeskGuestCore". That is
/// the Core executable's fixed product name (the shipped apphost
/// is DeskGuestCore.exe on Windows, DeskGuestCore on other hosts), so the
/// match is robust to install path: the v21-live copy, the
/// v21-design-live copy, a staging copy, and any future install
/// root all carry the same image name. When the image path is
/// readable it must agree (its file name is the same name by
/// construction). The starting process itself (same pid) never
/// counts.
///
/// WHAT DOES NOT MATCH (named limits): the SessionAgent
/// (DeskGuestSessionAgent.exe), the Launcher, a dotnet host running
/// DeskGuestCore.dll (the dev/test shape — the shipped form is the
/// apphost), and — the hard limit — a Core whose executable file
/// was RENAMED: a renamed-executable Core is out of enumeration's
/// reach, and for it the W107/W111 lock + marker + heartbeat
/// checks remain the only (activity-based) evidence.
///
/// INDETERMINATE: if the process list cannot be obtained at all,
/// or a process exits-or-errors in a way that leaves its identity
/// genuinely unreadable, the verdict is Indeterminate — NOT
/// "no other Core". The Core fails closed on it (refuses) unless
/// the operator performs the named override (see
/// <see cref="OverrideFileName"/>).
/// </summary>
public static class CoreProcessLiveness
{
    /// <summary>The Core executable's product image name, without
    /// extension — the identity every install copy shares.</summary>
    public const string CoreImageName = "DeskGuestCore";

    /// <summary>The one-time operator override for an
    /// INDETERMINATE enumeration: a file with exactly this name,
    /// created by the operator (a human at the console) inside
    /// the data folder. Its mere existence is the deliberate act;
    /// the starting Core consumes (deletes) it when it proceeds
    /// on it, and the use is written into the audit chain at
    /// StartAsync. It never overrides a POSITIVE enumeration
    /// (another Core actually seen running) — positive evidence
    /// is not overridable. It is deliberately a file in the data
    /// folder, not a command-line flag: creating it requires
    /// write access to the protected data folder and a conscious
    /// act aimed at one data folder, and it cannot be passed
    /// casually by a launcher script or an agent's command line.</summary>
    public const string OverrideFileName = "operator-force-start-without-liveness-proof";

    public enum Verdict
    {
        /// <summary>Enumeration succeeded and found no other Core.</summary>
        NoOtherCore,
        /// <summary>Enumeration succeeded and found at least one other Core process alive.</summary>
        OtherCoreRunning,
        /// <summary>Enumeration could not be completed; liveness is unproven either way.</summary>
        Indeterminate,
    }

    /// <summary>One enumerated process: pid, image name (file
    /// name of the executable image, e.g. "DeskGuestCore.exe"), and the
    /// full image path when the OS let us read it.</summary>
    public sealed record ProcessInfo(int Pid, string ImageName, string? ImagePath);

    /// <summary>The enumeration outcome: the verdict, every other
    /// Core process found (empty unless OtherCoreRunning), and a
    /// human detail line for the refusal / audit record.</summary>
    public sealed record Result(Verdict Verdict, IReadOnlyList<ProcessInfo> OtherCores, string Detail);

    /// <summary>Normalize an image name or path to the bare image
    /// name: file name only, ".exe" stripped, lower-cased.</summary>
    public static string NormalizeImageName(string imageNameOrPath)
    {
        // File name only, split on BOTH directory separators:
        // the paths this rule judges are Windows paths, and the
        // rule must give the same answer on any host OS.
        var trimmed = imageNameOrPath.Trim();
        var cut = trimmed.LastIndexOfAny(new[] { '/', '\\' });
        var name = cut >= 0 ? trimmed[(cut + 1)..] : trimmed;
        if (name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            name = name[..^4];
        return name.ToLowerInvariant();
    }

    /// <summary>Is this process another DeskGuest Core? By the
    /// identity rule above: image name exactly DeskGuestCore (any
    /// install path), never the starting process itself. When a
    /// full image path is present, its file name must also be
    /// DeskGuestCore — a bare name claim contradicted by the path is
    /// not a match.</summary>
    public static bool IsCoreProcess(ProcessInfo process, int selfPid)
    {
        if (process.Pid == selfPid) return false;
        if (!string.Equals(NormalizeImageName(process.ImageName), "deskguestcore", StringComparison.Ordinal))
            return false;
        if (process.ImagePath is not null &&
            !string.Equals(NormalizeImageName(process.ImagePath), "deskguestcore", StringComparison.Ordinal))
            return false;
        return true;
    }

    /// <summary>The pure verdict over an enumerated process list
    /// (the pin surface). A null list is an enumeration that never
    /// happened: Indeterminate.</summary>
    public static Result Evaluate(IReadOnlyList<ProcessInfo>? processes, int selfPid)
    {
        if (processes is null)
            return new Result(Verdict.Indeterminate, Array.Empty<ProcessInfo>(),
                "process enumeration did not run");
        var others = processes.Where(p => IsCoreProcess(p, selfPid)).ToList();
        if (others.Count > 0)
            return new Result(Verdict.OtherCoreRunning, others,
                "another DeskGuest Core process is running: " +
                string.Join(", ", others.Select(p =>
                    $"pid {p.Pid} ({(p.ImagePath ?? p.ImageName)})")));
        return new Result(Verdict.NoOtherCore, Array.Empty<ProcessInfo>(),
            $"process enumeration found no other {CoreImageName} process " +
            $"({processes.Count} processes examined, self pid {selfPid} excluded)");
    }

    /// <summary>The production probe: enumerate the OS process
    /// list and evaluate it. Any failure to enumerate — or any
    /// process whose identity cannot be read for a reason other
    /// than having just exited — makes the verdict Indeterminate
    /// (fail closed), never a guessed NoOtherCore.</summary>
    public static Result Probe() => Probe(Environment.ProcessId);

    public static Result Probe(int selfPid)
    {
        Process[] processes;
        try { processes = Process.GetProcesses(); }
        catch (Exception ex)
        {
            return new Result(Verdict.Indeterminate, Array.Empty<ProcessInfo>(),
                $"process enumeration failed ({ex.GetType().Name}: {ex.Message})");
        }
        var infos = new List<ProcessInfo>();
        string? unreadable = null;
        foreach (var p in processes)
        {
            try
            {
                string name;
                try { name = p.ProcessName; }
                catch (InvalidOperationException) { continue; } // exited mid-enumeration: not a live Core
                string? path = null;
                try { path = p.MainModule?.FileName; } catch { /* name alone still decides */ }
                infos.Add(new ProcessInfo(p.Id,
                    path is not null ? Path.GetFileName(path) : name, path));
            }
            catch (Exception ex)
            {
                unreadable = $"pid {p.Id}: {ex.GetType().Name}";
            }
            finally { p.Dispose(); }
        }
        if (unreadable is not null)
        {
            // A process we cannot identify could be the old Core;
            // but a positively identified Core outranks the doubt.
            var partial = Evaluate(infos, selfPid);
            if (partial.Verdict == Verdict.OtherCoreRunning) return partial;
            return new Result(Verdict.Indeterminate, Array.Empty<ProcessInfo>(),
                $"process enumeration could not identify every process ({unreadable})");
        }
        return Evaluate(infos, selfPid);
    }

    /// <summary>Is the operator override present in this data
    /// dir? Presence IS the operator's deliberate act.</summary>
    public static bool OverridePresent(string dataDir) =>
        File.Exists(Path.Combine(Path.GetFullPath(dataDir), OverrideFileName));

    /// <summary>Consume the one-time override (delete it) so it
    /// can never silently authorise a second start. Returns true
    /// when an override was present and consumed.</summary>
    public static bool ConsumeOverride(string dataDir)
    {
        try
        {
            var path = Path.Combine(Path.GetFullPath(dataDir), OverrideFileName);
            if (!File.Exists(path)) return false;
            File.Delete(path);
            return true;
        }
        catch { return false; }
    }
}
