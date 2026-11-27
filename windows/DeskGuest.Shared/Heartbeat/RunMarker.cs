using System.Text.Json;
using DeskGuest.Shared.State;

namespace DeskGuest.Shared.Heartbeat;

/// <summary>
/// Last-word + post-mortem (DESIGN §4.4). The Core continuously records
/// its state to a marker file (the "last word"). On graceful shutdown it
/// marks the run ended-cleanly. On the next start, the marker tells the
/// new run how the previous one ended — clean shutdown, or unclean
/// (power loss / forced off / crash) — so an outage the agent could not
/// watch is still an outage the agent can describe.
/// </summary>
public sealed class RunMarker
{
    private sealed record Marker(
        string RunId,
        EndpointState LastState,
        DateTimeOffset LastSeenUtc,
        bool EndedCleanly,
        string? LastWord,
        // W95 / FR-124: the writing process's pid. Defaulted so a
        // pre-W95 marker (no OwnerPid in the JSON) still parses —
        // pid 0 = unknown owner, no liveness claim is made for it.
        int OwnerPid = 0);

    private readonly string _path;
    private readonly string _runId = Guid.NewGuid().ToString("N");
    private readonly object _gate = new();

    public RunMarker(string path) => _path = path;

    /// <summary>W95 / FR-124 test seam: the owner-liveness check
    /// ReadPreviousRun applies before it may call a run ended.
    /// Arguments: the marker's owner pid and the marker's last-seen
    /// time. Production composition never sets it; the default is
    /// the OS check (DefaultOwnerAlive).</summary>
    public Func<int, DateTimeOffset, bool>? OwnerAliveChecker { get; set; }

    /// <summary>The default liveness check: the pid exists as a
    /// process AND that process did not start after the marker's
    /// last-seen (+ a small slack) — a process younger than the
    /// marker is a REUSED pid, not the marker's owner. This process
    /// itself never counts as the previous run's live owner.</summary>
    public static bool DefaultOwnerAlive(int pid, DateTimeOffset lastSeenUtc)
    {
        if (pid <= 0 || pid == Environment.ProcessId) return false;
        try
        {
            using var p = System.Diagnostics.Process.GetProcessById(pid);
            return p.StartTime.ToUniversalTime() <= lastSeenUtc.UtcDateTime + TimeSpan.FromSeconds(5);
        }
        catch { return false; }
    }

    /// <summary>W107: the marker's raw facts (no characterization):
    /// the single-instance upgrade-coexistence check reads these
    /// BEFORE any overwrite. Null when no marker exists or it
    /// cannot be parsed.</summary>
    public sealed record MarkerSnapshot(
        bool EndedCleanly, int OwnerPid, DateTimeOffset LastSeenUtc, EndpointState? LastState);

    public MarkerSnapshot? Inspect()
    {
        lock (_gate)
        {
            if (!File.Exists(_path)) return null;
            try
            {
                var marker = JsonSerializer.Deserialize<Marker>(File.ReadAllText(_path));
                return marker is null ? null
                    : new MarkerSnapshot(marker.EndedCleanly, marker.OwnerPid, marker.LastSeenUtc, marker.LastState);
            }
            catch { return null; }
        }
    }

    /// <summary>W107: how fresh a not-cleanly-ended marker must be
    /// for its owner to count as possibly still running: three
    /// beats of the Core's ~30 s marker cadence. Older than this,
    /// the owner is demonstrably not beating its marker.</summary>
    public static readonly TimeSpan LiveOwnerFreshnessWindow = TimeSpan.FromSeconds(90);

    /// <summary>W107: may a new Core conclude this marker's owner
    /// is PROVABLY dead (so a start must NOT be blocked)? True
    /// only on positive evidence: the pid is this process itself
    /// (it cannot be a distinct live owner of a previous run), the
    /// pid no longer exists, or the pid exists but started AFTER
    /// the marker's last-seen (+ slack) — a recycled pid, not the
    /// owner. Any other outcome (the pid is alive and old enough,
    /// or the check itself cannot be performed) is NOT proof of
    /// death and returns false.</summary>
    public static bool OwnerProvablyDead(int pid, DateTimeOffset lastSeenUtc)
    {
        if (pid <= 0) return false; // no pid recorded: nothing is provable either way
        if (pid == Environment.ProcessId) return true;
        try
        {
            using var p = System.Diagnostics.Process.GetProcessById(pid);
            // Alive and started no later than the marker's last
            // beat (+ slack) = consistent with being the owner.
            return p.StartTime.ToUniversalTime() > lastSeenUtc.UtcDateTime + TimeSpan.FromSeconds(5);
        }
        catch (ArgumentException) { return true; }  // no such process: provably gone
        catch (InvalidOperationException) { return true; } // exited between lookup and read
        catch { return false; } // indeterminate: NOT proof of death
    }

    /// <summary>W111: read the data dir's heartbeat.json
    /// timestamp — the OTHER life sign a Core of any vintage
    /// emits (the supervisor writes heartbeat.json on the same
    /// ~30 s cadence as the marker beat). Returns the heartbeat's
    /// AtUtc, or null when the file is absent or unparseable
    /// (absent sign — not evidence either way).</summary>
    public static DateTimeOffset? ReadHeartbeatAtUtc(string dataDir)
    {
        try
        {
            var path = Path.Combine(dataDir, "heartbeat.json");
            if (!File.Exists(path)) return null;
            using var doc = JsonDocument.Parse(File.ReadAllText(path));
            if (doc.RootElement.TryGetProperty("AtUtc", out var at) &&
                at.TryGetDateTimeOffset(out var value))
                return value;
            return null;
        }
        catch { return null; }
    }

    /// <summary>Does this heartbeat timestamp count as FRESH —
    /// written within the same freshness window as the marker
    /// (three beats of the ~30 s cadence)? A future timestamp
    /// (clock stepped back) also counts as fresh: fail-closed.</summary>
    public static bool HeartbeatIsFresh(DateTimeOffset? heartbeatAtUtc, DateTimeOffset nowUtc) =>
        heartbeatAtUtc is { } at && nowUtc - at <= LiveOwnerFreshnessWindow;

    /// <summary>W107, extended W111 (W110-C4b): does this marker
    /// indicate a live owner the new Core cannot verify as dead?
    /// The upgrade-coexistence rule: a pre-W95 Core holds NO
    /// instance lock, so the lock being free proves nothing about
    /// it. W107 rested liveness on marker freshness ALONE for a
    /// stale check — a live-but-stalled owner (suspended machine,
    /// long stall) whose marker aged past 90 s was treated as
    /// dead and booted over. W111: liveness rests on EVERY life
    /// sign the data dir offers, and a start proceeds only when
    /// the owner is provably dead on every available sign:
    ///   * cleanly-ended marker → never blocks;
    ///   * a recorded pid that is NOT provably dead (alive with a
    ///     start time consistent with the marker, or the check
    ///     indeterminate) → blocks REGARDLESS of marker age;
    ///   * no pid recorded (pre-W95): a FRESH marker or a FRESH
    ///     heartbeat.json blocks; both stale/absent → the owner
    ///     is not beating anything → start proceeds;
    ///   * a provably-dead pid (gone, or recycled to a younger
    ///     process) → the legitimate restart, whatever the
    ///     heartbeat says: heartbeat.json is fresh at EVERY fast
    ///     restart (the old Core beat it seconds before it died),
    ///     so the heartbeat sign is probative ONLY when no pid
    ///     proof exists (OwnerPid=0). (W111 live lesson: the
    ///     first W111 build let a fresh heartbeat override a
    ///     provably-dead pid and refused this lane's own
    ///     legitimate relaunch on the laptop — reverted to this
    ///     rule before the lane closed.)
    /// The two-argument overload is the no-heartbeat-evidence
    /// form (heartbeat sign absent).</summary>
    public static bool IndicatesLiveOwner(MarkerSnapshot marker, DateTimeOffset nowUtc) =>
        IndicatesLiveOwner(marker, nowUtc, null);

    public static bool IndicatesLiveOwner(
        MarkerSnapshot marker, DateTimeOffset nowUtc, DateTimeOffset? heartbeatAtUtc)
    {
        if (marker.EndedCleanly) return false;
        var heartbeatFresh = HeartbeatIsFresh(heartbeatAtUtc, nowUtc);
        if (marker.OwnerPid > 0)
            return !OwnerProvablyDead(marker.OwnerPid, marker.LastSeenUtc);
        var markerFresh = nowUtc - marker.LastSeenUtc <= LiveOwnerFreshnessWindow;
        return markerFresh || heartbeatFresh;
    }

    /// <summary>FR-135 (#16): does this marker BLOCK a new start?
    /// The pure decision the Core constructor applies. A marker
    /// blocks when it indicates a live owner — with ONE exception:
    /// a pid-less marker (a pre-single-instance build recorded no
    /// owner pid) when process enumeration has already PROVEN no
    /// Core process exists. The W113 doctrine cuts both ways: a
    /// live process outranks every file, and proven absence
    /// outranks a file that cannot name a process — the W135
    /// incident was a just-died old Core's fresh pid-less marker
    /// stranding its successor forever (exit 41) while enumeration
    /// had already proven the machine Core-free. A marker naming
    /// a RECORDED pid is never overridden by enumeration
    /// (defence in depth, W111): its own pid-liveness rule
    /// decides. With enumeration indeterminate or unrun, a
    /// pid-less marker keeps its full freshness discipline.</summary>
    public static bool MarkerBlocksStart(MarkerSnapshot? marker, DateTimeOffset nowUtc,
        DateTimeOffset? heartbeatAtUtc, bool enumerationProvedNoOtherCore)
    {
        if (marker is null) return false;
        if (!IndicatesLiveOwner(marker, nowUtc, heartbeatAtUtc)) return false;
        if (marker.OwnerPid <= 0 && enumerationProvedNoOtherCore) return false;
        return true;
    }

    /// <summary>Read the previous run's marker BEFORE overwriting it.</summary>
    public PreviousRunInfo? ReadPreviousRun()
    {
        lock (_gate)
        {
            if (!File.Exists(_path)) return null;
            try
            {
                var marker = JsonSerializer.Deserialize<Marker>(File.ReadAllText(_path));
                if (marker is null) return null;
                // W95 / FR-124 (the mis-record guard): a run whose
                // owner process is STILL ALIVE has not ended at
                // all, so no end verdict — clean or unclean — may
                // be recorded for it. (The duplicate Core in
                // D-W93-1 read the live Core's mid-run marker and
                // published "did NOT end cleanly" for a run that
                // was still running.) The primary protection is
                // ordering — CoreRuntime only reaches this read
                // while holding the CoreInstanceLock, which a live
                // Core never releases — and this check is the
                // defense in depth at the primitive itself.
                var ownerAlive = !marker.EndedCleanly && marker.OwnerPid > 0 &&
                    (OwnerAliveChecker ?? DefaultOwnerAlive)(marker.OwnerPid, marker.LastSeenUtc);
                var characterization = marker.EndedCleanly
                    ? $"previous run ended cleanly (last state {marker.LastState}, last seen {marker.LastSeenUtc:u})"
                    : ownerAlive
                        ? $"previous run is STILL RUNNING (pid {marker.OwnerPid}, last state {marker.LastState}, last seen {marker.LastSeenUtc:u}) — it has NOT ended, so no end verdict is recorded for it"
                        : $"previous run did NOT end cleanly — power loss, forced off, or crash (last state {marker.LastState}, last seen {marker.LastSeenUtc:u})";
                return new PreviousRunInfo(marker.EndedCleanly, marker.LastState, marker.LastSeenUtc, characterization);
            }
            catch (Exception ex) when (ex is JsonException or IOException)
            {
                return new PreviousRunInfo(false, null, null, "previous run marker unreadable; treating the gap as uncharacterized-unclean");
            }
        }
    }

    /// <summary>Record the current state as this run's last word.</summary>
    public void Beat(EndpointState state, string? lastWord = null)
    {
        lock (_gate)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(_path))!);
            var marker = new Marker(_runId, state, DateTimeOffset.UtcNow, false, lastWord, Environment.ProcessId);
            WriteAtomic(JsonSerializer.Serialize(marker));
        }
    }

    /// <summary>Announce intent before a graceful transition (sleep,
    /// shutdown, update reboot, user stop) — the last-word protocol.</summary>
    public void AnnounceDeparture(EndpointState state, string lastWord) => Beat(state, lastWord);

    public void MarkCleanShutdown(EndpointState finalState)
    {
        lock (_gate)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(_path))!);
            var marker = new Marker(_runId, finalState, DateTimeOffset.UtcNow, true, "clean shutdown", Environment.ProcessId);
            WriteAtomic(JsonSerializer.Serialize(marker));
        }
    }

    /// <summary>BD-SHARED-TRANSPORT F8: the marker is written to a
    /// temp file in the same directory and swapped in with
    /// File.Replace — a power cut mid-write (the exact case this
    /// file exists to describe) can no longer leave a torn,
    /// unreadable marker that loses the previous run's last word;
    /// the reader sees either the old marker whole or the new one
    /// whole.</summary>
    private void WriteAtomic(string json)
    {
        var full = Path.GetFullPath(_path);
        var tmp = full + "." + _runId + ".tmp";
        File.WriteAllText(tmp, json);
        if (File.Exists(full)) File.Replace(tmp, full, null);
        else File.Move(tmp, full);
    }
}

/// <summary>The heartbeat payload (DESIGN §4.4): state, component health,
/// session state, Tailscale state, pending-reboot flag, crash counts, version.</summary>
public sealed record HeartbeatReport(
    DateTimeOffset AtUtc,
    EndpointState State,
    string CoreVersion,
    string AgentVersion,
    bool TailscaleBound,
    bool LanBound,
    bool AgentConnected,
    bool PendingReboot,
    int CoreCrashCount,
    int AgentCrashCount,
    PreviousRunInfo? PreviousRun);
