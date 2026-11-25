using Acp.Core;
using Acp.Shared.Heartbeat;

namespace Acp.Tests;

/// <summary>W95 / FR-124 (defect D-W93-1): the AcpCore single-instance
/// guard. Pins: (1) the lock primitive — acquisition, conflict,
/// per-data-dir keying, release, and stale-lock recovery after a
/// holder process dies without releasing; (2) the CoreRuntime
/// wiring — a second CoreRuntime on a live Core's data dir throws
/// BEFORE any publishing (its data dir's heartbeat / run marker /
/// IPC token / trust record bytes are untouched), a stopped Core
/// frees the dir, and different data dirs coexist; (3) the
/// mis-record guard — a run marker whose owner is still alive is
/// never characterized "did NOT end cleanly"; (4) source pins —
/// the guard precedes all publishing in CoreRuntime and Program.cs
/// carries the clean-exit path (message, own record, exit 41).</summary>
public class W95SingleInstanceTests
{
    private static CoreOptions Options(string dir) => new()
    {
        DataDir = dir,
        FactChecks = new FakeFactChecks(),
        Runner = new FakeRunner(),
        Probe = new FakeProbe(),
    };

    // Source lookup in the W85 pattern: walk up from the test bin
    // dir until the source tree is found.
    private static string SrcFile(params string[] parts)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            foreach (var root in new[] { "src", Path.Combine("windows-agent", "src") })
            {
                var c = Path.Combine(new[] { dir.FullName, root }.Concat(parts).ToArray());
                if (File.Exists(c)) return File.ReadAllText(c);
            }
            dir = dir.Parent;
        }
        throw new FileNotFoundException(string.Join("/", parts));
    }

    // ---------- the lock primitive ----------

    [Fact]
    public void Lock_FirstAcquire_Succeeds_AndWritesHolderRecord()
    {
        var dir = TestUtil.TempDir();
        var held = CoreInstanceLock.Acquire(dir);
        Assert.Equal(CoreInstanceLock.LockPathFor(dir), held.LockPath);
        Assert.True(File.Exists(held.LockPath));
        held.Dispose();
        // The holder record persists in the (never-deleted) lock
        // file after release — while held, FileShare.None rightly
        // refuses even a diagnostic read from a second handle.
        var record = CoreInstanceLock.ReadHolderRecord(held.LockPath);
        Assert.NotNull(record);
        Assert.Contains($"pid={Environment.ProcessId}", record);
    }

    [Fact]
    public void Lock_SecondAcquire_SameDir_RefusedByName_WithDuplicateMessage()
    {
        var dir = TestUtil.TempDir();
        using var first = CoreInstanceLock.Acquire(dir);
        var ex = Assert.Throws<CoreInstanceLock.AlreadyRunningException>(
            () => CoreInstanceLock.Acquire(dir));
        Assert.Contains(CoreInstanceLock.DuplicateMessage, ex.Message);
        Assert.False(CoreInstanceLock.TryAcquire(dir, out var second, out _));
        Assert.Null(second);
    }

    [Fact]
    public void Lock_KeyedToDataDir_DifferentDirs_DoNotCollide()
    {
        var dirA = TestUtil.TempDir();
        var dirB = TestUtil.TempDir();
        using var a = CoreInstanceLock.Acquire(dirA);
        using var b = CoreInstanceLock.Acquire(dirB); // must NOT throw
        Assert.NotEqual(a.LockPath, b.LockPath);
    }

    [Fact]
    public void Lock_Release_AllowsNextAcquire_AndLockFileIsNeverDeleted()
    {
        var dir = TestUtil.TempDir();
        var first = CoreInstanceLock.Acquire(dir);
        var path = first.LockPath;
        first.Dispose();
        first.Dispose(); // idempotent
        Assert.True(File.Exists(path)); // W49 rule: never unlinked
        using var second = CoreInstanceLock.Acquire(dir);
        Assert.Equal(path, second.LockPath);
    }

    [Fact]
    public void Lock_StaleLockFileOnDisk_DoesNotBrickNextStart()
    {
        // The crash / kill / power-loss shape leaves the lock FILE
        // behind (it is never deleted). What bricks a naive
        // lockfile design is refusing on the file's mere existence;
        // this guard refuses only on a live held handle, so a stale
        // file with a dead pid's record acquires cleanly and the
        // record is rewritten for the new holder. (The kernel's
        // release-on-process-death itself is proven by the live
        // two-Core tests — local two-process + laptop — in the
        // lane log; a unit test cannot kill its own host process.)
        var dir = TestUtil.TempDir();
        var stalePath = CoreInstanceLock.LockPathFor(dir);
        Directory.CreateDirectory(dir);
        File.WriteAllText(stalePath, "pid=999999; stale record from a dead run\n");
        var held = CoreInstanceLock.Acquire(dir);
        Assert.NotNull(held);
        held.Dispose();
        var record = CoreInstanceLock.ReadHolderRecord(stalePath);
        Assert.Contains($"pid={Environment.ProcessId}", record);
    }

    [Fact]
    public void Lock_DuplicateStartRecord_IsItsOwnNewFile_TouchingNoSharedState()
    {
        // W107 AMENDMENT (reason recorded): W95 pinned this record
        // as the END of the refusal's story — "no audit" was the
        // intended design. W106 verified that as C4a: the refusal
        // never reached the audit chain of record. The WRITE side
        // is unchanged and still pinned here (the refused process
        // touches no shared state — W93's contention rule); what
        // W107 adds is the other half: the record is tamper-evident
        // (recordSha256 over its own fields) and the RUNNING Core
        // ingests it into the chain (pinned below).
        var dir = TestUtil.TempDir();
        var path = CoreInstanceLock.WriteDuplicateStartRecord(dir, "attempt line");
        Assert.NotNull(path);
        Assert.True(File.Exists(path));
        Assert.Contains("duplicate-core-start-", Path.GetFileName(path));
        var text = File.ReadAllText(path!);
        Assert.Contains("attempt line", text);
        Assert.Contains($"exitCode={CoreInstanceLock.DuplicateExitCode}", text);
        Assert.Contains("recordSha256=", text);
        // Nothing else was created by the refused process: no
        // heartbeat, marker, token, audit.
        var files = Directory.GetFiles(dir).Select(Path.GetFileName).ToArray();
        Assert.Single(files);
        // The record parses back with its hash verified.
        var record = CoreInstanceLock.ReadDuplicateStartRecord(path);
        Assert.NotNull(record);
        Assert.Equal("verified", record!.HashState);
        Assert.Equal("attempt line", record.Line);
    }

    [Fact]
    public void DuplicateStartRecord_TamperedCopy_ReadsAsMismatch_LegacyReadsAsLegacy()
    {
        var dir = TestUtil.TempDir();
        var path = CoreInstanceLock.WriteDuplicateStartRecord(dir, "attempt line")!;
        var lines = File.ReadAllLines(path);
        // Tamper: rewrite the refusal line, keep the hash.
        File.WriteAllText(Path.Combine(dir, "duplicate-core-start-tampered.log"),
            "forged line" + Environment.NewLine + lines[1] + Environment.NewLine + lines[2] + Environment.NewLine);
        var tampered = CoreInstanceLock.ReadDuplicateStartRecord(
            Path.Combine(dir, "duplicate-core-start-tampered.log"));
        Assert.Equal("mismatch", tampered!.HashState);
        // Legacy: a pre-W107 record (no hash line) still parses,
        // honestly labelled unverifiable.
        File.WriteAllText(Path.Combine(dir, "duplicate-core-start-legacy.log"),
            lines[0] + Environment.NewLine + lines[1] + Environment.NewLine);
        var legacy = CoreInstanceLock.ReadDuplicateStartRecord(
            Path.Combine(dir, "duplicate-core-start-legacy.log"));
        Assert.Equal("legacy", legacy!.HashState);
    }

    [Fact]
    public async Task Runtime_IngestsDuplicateStartRecords_IntoTheAuditChain_ExactlyOnce()
    {
        var dir = TestUtil.TempDir();
        // A refusal that happened BEFORE this Core started.
        var recordPath = CoreInstanceLock.WriteDuplicateStartRecord(dir,
            "DeskGuest Core: another DeskGuest Core is already running for this data folder")!;
        var runtime = new CoreRuntime(Options(dir));
        await runtime.StartAsync(default);
        // The refusal is IN the chain of record, verbatim fields,
        // hash state named, and the file is consumed.
        Assert.False(File.Exists(recordPath));
        var tail = runtime.Audit.ReadTail(100);
        var entry = Assert.Single(tail, e => e.Outcome.Contains("duplicate_core_start_refused"));
        Assert.Contains("pid=", entry.Outcome);
        Assert.Contains("record sha256 verified", entry.Outcome);
        Assert.Contains("ingested by the running Core", entry.Outcome);
        // A refusal that lands WHILE the Core runs is ingested by
        // the same duty the supervisor beat calls — exactly once.
        var second = CoreInstanceLock.WriteDuplicateStartRecord(dir, "second refusal")!;
        Assert.Equal(1, runtime.ConsumeDuplicateStartRecords());
        Assert.False(File.Exists(second));
        Assert.Equal(0, runtime.ConsumeDuplicateStartRecords());
        Assert.Equal(2, runtime.Audit.ReadTail(100).Count(e => e.Outcome.Contains("duplicate_core_start_refused")));
        await runtime.StopAsync(default);
        await runtime.DisposeAsync();
    }

    // ---------- CoreRuntime wiring ----------

    [Fact]
    public async Task Runtime_SecondInstance_Throws_AndPublishesNothing()
    {
        var dir = TestUtil.TempDir();
        var first = new CoreRuntime(Options(dir));
        // Snapshot everything the duplicate must NOT touch.
        var tokenPath = Path.Combine(dir, "ipc-token.txt");
        var markerPath = Path.Combine(dir, "run-marker.json");
        Assert.True(File.Exists(tokenPath)); // first Core published in its ctor
        var tokenBefore = File.ReadAllBytes(tokenPath);
        var trustBefore = Directory.GetFiles(dir, "*", SearchOption.AllDirectories)
            .ToDictionary(f => f, f => File.GetLastWriteTimeUtc(f));

        var ex = Assert.Throws<CoreInstanceLock.AlreadyRunningException>(
            () => new CoreRuntime(Options(dir)));
        Assert.Contains(CoreInstanceLock.DuplicateMessage, ex.Message);

        // The duplicate wrote NOTHING: token bytes identical, no
        // heartbeat appeared, no file in the data dir was rewritten.
        Assert.Equal(tokenBefore, File.ReadAllBytes(tokenPath));
        Assert.False(File.Exists(Path.Combine(dir, "heartbeat.json")));
        foreach (var (file, mtime) in trustBefore)
            Assert.Equal(mtime, File.GetLastWriteTimeUtc(file));
        Assert.False(File.Exists(markerPath)); // neither Core started; no marker written

        await first.StopAsync(default);
        await first.DisposeAsync();
    }

    [Fact]
    public async Task Runtime_AfterStop_NextInstanceAcquires()
    {
        var dir = TestUtil.TempDir();
        var first = new CoreRuntime(Options(dir));
        await first.StopAsync(default);
        // True restart semantics: the stopped Core released the dir.
        var second = new CoreRuntime(Options(dir));
        Assert.NotNull(second.InstanceLock);
        await second.StopAsync(default);
        await second.DisposeAsync();
        await first.DisposeAsync();
    }

    [Fact]
    public async Task Runtime_DifferentDataDirs_Coexist()
    {
        var a = new CoreRuntime(Options(TestUtil.TempDir()));
        var b = new CoreRuntime(Options(TestUtil.TempDir()));
        Assert.NotEqual(a.InstanceLock.LockPath, b.InstanceLock.LockPath);
        await a.StopAsync(default);
        await b.StopAsync(default);
        await a.DisposeAsync();
        await b.DisposeAsync();
    }

    // ---------- the mis-record guard (RunMarker) ----------

    [Fact]
    public void Marker_LiveOwner_IsNeverCalledUnclean()
    {
        var dir = TestUtil.TempDir();
        var path = Path.Combine(dir, "run-marker.json");
        var writer = new RunMarker(path);
        writer.Beat(TestUtil.State(), "alive and beating");
        var reader = new RunMarker(path)
        {
            OwnerAliveChecker = (pid, _) => pid == Environment.ProcessId,
        };
        var previous = reader.ReadPreviousRun();
        Assert.NotNull(previous);
        Assert.Contains("STILL RUNNING", previous!.Characterization);
        Assert.DoesNotContain("did NOT end cleanly", previous.Characterization);
    }

    [Fact]
    public void Marker_DeadOwner_StillCharacterizedUnclean()
    {
        var dir = TestUtil.TempDir();
        var path = Path.Combine(dir, "run-marker.json");
        var writer = new RunMarker(path);
        writer.Beat(TestUtil.State());
        var reader = new RunMarker(path)
        {
            OwnerAliveChecker = (_, _) => false,
        };
        var previous = reader.ReadPreviousRun();
        Assert.NotNull(previous);
        Assert.Contains("did NOT end cleanly", previous!.Characterization);
    }

    [Fact]
    public void Marker_PreW95Shape_WithoutOwnerPid_StillParses()
    {
        var dir = TestUtil.TempDir();
        var path = Path.Combine(dir, "run-marker.json");
        // A marker exactly as a pre-W95 Core wrote it (no OwnerPid).
        File.WriteAllText(path,
            "{\"RunId\":\"abc\",\"LastState\":0,\"LastSeenUtc\":\"2026-11-24T09:35:23Z\",\"EndedCleanly\":false,\"LastWord\":null}");
        var previous = new RunMarker(path).ReadPreviousRun();
        Assert.NotNull(previous);
        Assert.Contains("did NOT end cleanly", previous!.Characterization);
    }

    // ---------- W107 (C4b): upgrade coexistence — live marker refuses ----------

    private static void WriteMarker(string dir, int? ownerPid, DateTimeOffset lastSeenUtc, bool endedCleanly = false)
    {
        var pidField = ownerPid is { } pid ? $",\"OwnerPid\":{pid}" : "";
        File.WriteAllText(Path.Combine(dir, "run-marker.json"),
            "{\"RunId\":\"abc\",\"LastState\":0,\"LastSeenUtc\":\"" +
            lastSeenUtc.ToString("o") + $"\",\"EndedCleanly\":{endedCleanly.ToString().ToLowerInvariant()},\"LastWord\":null{pidField}}}");
    }

    [Fact]
    public void Marker_LiveOwnerLogic_FreshnessAndProvableDeath()
    {
        var now = DateTimeOffset.UtcNow;
        // fresh + no pid (pre-W95): cannot verify dead → live-owner
        Assert.True(RunMarker.IndicatesLiveOwner(
            new RunMarker.MarkerSnapshot(false, 0, now, null), now));
        // stale + no pid: the owner is not beating → not live
        Assert.False(RunMarker.IndicatesLiveOwner(
            new RunMarker.MarkerSnapshot(false, 0, now.AddMinutes(-10), null), now));
        // cleanly ended never blocks, however fresh
        Assert.False(RunMarker.IndicatesLiveOwner(
            new RunMarker.MarkerSnapshot(true, 0, now, null), now));
        // fresh + pid provably gone (no such process) → not live
        Assert.False(RunMarker.IndicatesLiveOwner(
            new RunMarker.MarkerSnapshot(false, 999999, now, null), now));
        // fresh + own pid: this process cannot be a distinct live
        // previous owner → not live (the in-process test shape)
        Assert.False(RunMarker.IndicatesLiveOwner(
            new RunMarker.MarkerSnapshot(false, Environment.ProcessId, now, null), now));
    }

    // ---------- W111 (W110-C4b): stalled-owner liveness ----------

    private static void WriteHeartbeat(string dir, DateTimeOffset atUtc) =>
        File.WriteAllText(Path.Combine(dir, "heartbeat.json"),
            "{\"AtUtc\":\"" + atUtc.ToString("o") + "\"}");

    [Fact]
    public void Marker_StalledOwnerLogic_PidAndHeartbeatSigns()
    {
        var now = DateTimeOffset.UtcNow;
        var stale = now.AddMinutes(-10);
        // OwnerPid=0 + FRESH heartbeat + stale marker → refuse:
        // a Core of some vintage is beating heartbeat.json even
        // though its marker aged out (the stalled/suspended case).
        Assert.True(RunMarker.IndicatesLiveOwner(
            new RunMarker.MarkerSnapshot(false, 0, stale, null), now, now));
        // OwnerPid=0 + STALE heartbeat + stale marker → start:
        // provably dead on every available sign.
        Assert.False(RunMarker.IndicatesLiveOwner(
            new RunMarker.MarkerSnapshot(false, 0, stale, null), now, stale));
        // OwnerPid=0 + NO heartbeat + stale marker → start.
        Assert.False(RunMarker.IndicatesLiveOwner(
            new RunMarker.MarkerSnapshot(false, 0, stale, null), now, null));
        // Provably-dead pid + stale marker + FRESH heartbeat →
        // START. W111 AMENDMENT (reason recorded): this pin first
        // asserted refusal (heartbeat overrides dead pid) — the
        // first W111 build's own legitimate laptop relaunch was
        // refused by exactly that rule, because heartbeat.json
        // is fresh at every fast restart (the old Core beat it
        // 49 s before the relaunch). The heartbeat sign is
        // probative only when no pid proof exists (OwnerPid=0).
        Assert.False(RunMarker.IndicatesLiveOwner(
            new RunMarker.MarkerSnapshot(false, 999999, stale, null), now, now));
        // Provably-dead pid + FRESH marker + stale heartbeat →
        // start (the W107 legitimate-restart matrix, intact).
        Assert.False(RunMarker.IndicatesLiveOwner(
            new RunMarker.MarkerSnapshot(false, 999999, now, null), now, stale));
        // Cleanly-ended never blocks, even with a fresh heartbeat.
        Assert.False(RunMarker.IndicatesLiveOwner(
            new RunMarker.MarkerSnapshot(true, 0, stale, null), now, now));
    }

    [Fact]
    public async Task Runtime_LivePid_StaleMarker_RefusesToBoot()
    {
        // W110-C4b core case at runtime level: the owner process
        // is ALIVE (started before the marker) but its marker is
        // >90 s stale (suspended / stalled). W107 booted over it;
        // W111 refuses on the pid sign alone.
        var dir = TestUtil.TempDir();
        // A genuinely old live process: started long before the
        // marker's last beat, so its start time is consistent
        // with being the marker's owner (a fresh sleeper would
        // read as a RECYCLED pid against a stale marker — the
        // provably-dead arm, not this one).
        System.Diagnostics.Process? owner = null;
        foreach (var p in System.Diagnostics.Process.GetProcesses())
        {
            try
            {
                if (p.Id != Environment.ProcessId &&
                    p.StartTime.ToUniversalTime() < DateTime.UtcNow.AddMinutes(-2))
                { owner = p; break; }
            }
            catch { /* unreadable start time: not a usable owner */ }
        }
        Assert.NotNull(owner);
        WriteMarker(dir, owner!.Id, DateTimeOffset.UtcNow.AddMinutes(-10));
        var ex = Assert.Throws<CoreInstanceLock.AlreadyRunningException>(
            () => new CoreRuntime(Options(dir)));
        Assert.Contains("live run marker", ex.Message);
        Assert.True(CoreInstanceLock.TryAcquire(dir, out var held, out _));
        held!.Dispose();
        await Task.CompletedTask;
    }

    [Fact]
    public async Task Runtime_NoPid_FreshHeartbeat_StaleMarker_Refuses_StaleHeartbeat_Starts()
    {
        // OwnerPid=0 (pre-W95) + fresh heartbeat + stale marker → refuse.
        var dir = TestUtil.TempDir();
        WriteMarker(dir, null, DateTimeOffset.UtcNow.AddMinutes(-10));
        WriteHeartbeat(dir, DateTimeOffset.UtcNow);
        var ex = Assert.Throws<CoreInstanceLock.AlreadyRunningException>(
            () => new CoreRuntime(Options(dir)));
        Assert.Contains("pre-single-instance build", ex.Message);

        // OwnerPid=0 + stale heartbeat + stale marker → start.
        var dir2 = TestUtil.TempDir();
        WriteMarker(dir2, null, DateTimeOffset.UtcNow.AddMinutes(-10));
        WriteHeartbeat(dir2, DateTimeOffset.UtcNow.AddMinutes(-10));
        var runtime = new CoreRuntime(Options(dir2));
        Assert.NotNull(runtime.InstanceLock);
        await runtime.StopAsync(default);
        await runtime.DisposeAsync();
    }

    [Fact]
    public void HeartbeatRead_AbsentOrUnparseable_IsAbsentSign()
    {
        var dir = TestUtil.TempDir();
        Assert.Null(RunMarker.ReadHeartbeatAtUtc(dir));
        File.WriteAllText(Path.Combine(dir, "heartbeat.json"), "{not json");
        Assert.Null(RunMarker.ReadHeartbeatAtUtc(dir));
        var at = DateTimeOffset.UtcNow;
        WriteHeartbeat(dir, at);
        var read = RunMarker.ReadHeartbeatAtUtc(dir);
        Assert.NotNull(read);
        Assert.True(Math.Abs((read!.Value - at).TotalSeconds) < 2);
        Assert.True(RunMarker.HeartbeatIsFresh(read, DateTimeOffset.UtcNow));
        Assert.False(RunMarker.HeartbeatIsFresh(at.AddMinutes(-10), DateTimeOffset.UtcNow));
    }

    [Fact]
    public async Task Runtime_LiveMarker_FromALiveProcess_RefusesToBoot()
    {
        // A live owner the new Core CAN name: another process,
        // started before the marker's last beat, marker fresh.
        var dir = TestUtil.TempDir();
        using var sleeper = System.Diagnostics.Process.Start(
            new System.Diagnostics.ProcessStartInfo("sleep", "120") { CreateNoWindow = true })!;
        WriteMarker(dir, sleeper.Id, DateTimeOffset.UtcNow);
        var ex = Assert.Throws<CoreInstanceLock.AlreadyRunningException>(
            () => new CoreRuntime(Options(dir)));
        Assert.Contains(CoreInstanceLock.DuplicateMessage, ex.Message);
        Assert.Contains("live run marker", ex.Message);
        // The refusal released the lock it had acquired: a later
        // start (once the marker's owner is gone) is not bricked
        // by THIS refusal.
        Assert.True(CoreInstanceLock.TryAcquire(dir, out var held, out _));
        held!.Dispose();
        sleeper.Kill();
        await Task.CompletedTask;
    }

    [Fact]
    public async Task Runtime_PreW95Marker_FreshNoPid_Refuses_StaleNoPid_Starts()
    {
        // The in-place-upgrade case (C4b): a pre-W95 Core holds no
        // lock and its marker has OwnerPid=0 — freshness is the
        // only liveness evidence, and a fresh marker refuses.
        var dir = TestUtil.TempDir();
        WriteMarker(dir, null, DateTimeOffset.UtcNow);
        var ex = Assert.Throws<CoreInstanceLock.AlreadyRunningException>(
            () => new CoreRuntime(Options(dir)));
        Assert.Contains("pre-single-instance build", ex.Message);

        // The same marker gone stale: its owner is not beating —
        // the start proceeds (the legitimate post-crash restart).
        var dir2 = TestUtil.TempDir();
        WriteMarker(dir2, null, DateTimeOffset.UtcNow.AddMinutes(-10));
        var runtime = new CoreRuntime(Options(dir2));
        Assert.NotNull(runtime.InstanceLock);
        await runtime.StopAsync(default);
        await runtime.DisposeAsync();
    }

    [Fact]
    public async Task Runtime_DeadOwnerMarker_FreshButPidGone_DoesNotBlock()
    {
        // Legitimate restart: the previous owner crashed seconds
        // ago — marker still fresh, but the pid is provably gone.
        var dir = TestUtil.TempDir();
        WriteMarker(dir, 999999, DateTimeOffset.UtcNow);
        var runtime = new CoreRuntime(Options(dir));
        Assert.NotNull(runtime.InstanceLock);
        await runtime.StopAsync(default);
        await runtime.DisposeAsync();
    }

    [Fact]
    public async Task Runtime_RecycledPidMarker_DoesNotBlock()
    {
        // The pid in the marker now belongs to a YOUNGER process
        // (started after the marker's last beat): recycled, not
        // the owner — provably not the live previous Core.
        var dir = TestUtil.TempDir();
        using var sleeper = System.Diagnostics.Process.Start(
            new System.Diagnostics.ProcessStartInfo("sleep", "120") { CreateNoWindow = true })!;
        await Task.Delay(50);
        // Marker beaten 60 s ago by a process that has since died;
        // its pid was recycled to the sleeper (born just now).
        WriteMarker(dir, sleeper.Id, DateTimeOffset.UtcNow.AddSeconds(-60));
        var runtime = new CoreRuntime(Options(dir));
        Assert.NotNull(runtime.InstanceLock);
        await runtime.StopAsync(default);
        await runtime.DisposeAsync();
        sleeper.Kill();
    }

    // ---------- W113 (W112-C4b): death proof by process enumeration ----------

    private static CoreProcessLiveness.Result Liveness(
        CoreProcessLiveness.Verdict verdict, params CoreProcessLiveness.ProcessInfo[] others) =>
        new(verdict, others, verdict switch
        {
            CoreProcessLiveness.Verdict.OtherCoreRunning =>
                "another DeskGuest Core process is running: " +
                string.Join(", ", others.Select(p => $"pid {p.Pid} ({p.ImagePath ?? p.ImageName})")),
            CoreProcessLiveness.Verdict.Indeterminate => "process enumeration failed (staged)",
            _ => "process enumeration found no other AcpCore process (staged)",
        });

    private static CoreOptions OptionsWithProbe(string dir, Func<CoreProcessLiveness.Result> probe) => new()
    {
        DataDir = dir,
        FactChecks = new FakeFactChecks(),
        Runner = new FakeRunner(),
        Probe = new FakeProbe(),
        CoreLivenessProbe = probe,
    };

    [Fact]
    public void Enumeration_IdentityRule_MatchesByImageName_AnyInstallPath()
    {
        var self = Environment.ProcessId;
        CoreProcessLiveness.ProcessInfo Proc(int pid, string name, string? path = null) => new(pid, name, path);
        // The Core apphost under BOTH laptop install roots, and a
        // staging root: the image name is the identity, the path
        // is not — every copy matches.
        Assert.True(CoreProcessLiveness.IsCoreProcess(
            Proc(4100, "AcpCore.exe", @"C:\ACP-Install\v21-live\AcpCore.exe"), self));
        Assert.True(CoreProcessLiveness.IsCoreProcess(
            Proc(4200, "AcpCore.exe", @"C:\ACP-Install\v21-design-live\AcpCore.exe"), self));
        Assert.True(CoreProcessLiveness.IsCoreProcess(
            Proc(4300, "acpcore", "/opt/acp-stage/AcpCore"), self));
        // Self never counts, however it is named.
        Assert.False(CoreProcessLiveness.IsCoreProcess(
            Proc(self, "AcpCore.exe", @"C:\ACP-Install\v21-design-live\AcpCore.exe"), self));
        // What does NOT match: the SessionAgent, the Launcher, a
        // dotnet host carrying the Core dll (dev shape), and —
        // the named limit — a RENAMED Core executable.
        Assert.False(CoreProcessLiveness.IsCoreProcess(
            Proc(4400, "AcpSessionAgent.exe", @"C:\ACP-Install\v21-live\AcpSessionAgent.exe"), self));
        Assert.False(CoreProcessLiveness.IsCoreProcess(Proc(4500, "dotnet.exe", @"C:\dotnet\dotnet.exe"), self));
        Assert.False(CoreProcessLiveness.IsCoreProcess(
            Proc(4600, "AcpCoreCopy.exe", @"C:\ACP-Install\v21-live\AcpCoreCopy.exe"), self));
        Assert.False(CoreProcessLiveness.IsCoreProcess(Proc(4700, "explorer.exe"), self));
        // A bare name claim contradicted by its own path is not a match.
        Assert.False(CoreProcessLiveness.IsCoreProcess(
            Proc(4800, "AcpCore.exe", @"C:\elsewhere\NotTheCore.exe"), self));
        // The verdict over a mixed list, and the null-list
        // (enumeration never ran) = Indeterminate, never a guess.
        var mixed = CoreProcessLiveness.Evaluate(new[]
        {
            Proc(self, "AcpCore.exe"), Proc(4400, "AcpSessionAgent.exe"),
            Proc(4200, "AcpCore.exe", @"D:\stage\AcpCore.exe"),
        }, self);
        Assert.Equal(CoreProcessLiveness.Verdict.OtherCoreRunning, mixed.Verdict);
        Assert.Single(mixed.OtherCores);
        Assert.Equal(CoreProcessLiveness.Verdict.NoOtherCore,
            CoreProcessLiveness.Evaluate(new[] { Proc(4400, "AcpSessionAgent.exe") }, self).Verdict);
        Assert.Equal(CoreProcessLiveness.Verdict.Indeterminate,
            CoreProcessLiveness.Evaluate(null, self).Verdict);
    }

    [Fact]
    public async Task Runtime_EnumerationFindsOtherCore_Refuses_ForPidlessAndPiddedMarkers()
    {
        var others = new[]
        {
            new CoreProcessLiveness.ProcessInfo(4242, "AcpCore.exe", @"C:\ACP-Install\v21-live\AcpCore.exe"),
        };
        // (a) The exact W112 counter-example state: pre-W95
        // OwnerPid=0 marker, marker AND heartbeat both 2 h stale
        // (a suspended live old Core froze both). W111 proceeded;
        // enumeration refuses — the process is the proof.
        var dir = TestUtil.TempDir();
        WriteMarker(dir, null, DateTimeOffset.UtcNow.AddHours(-2));
        WriteHeartbeat(dir, DateTimeOffset.UtcNow.AddHours(-2));
        var ex = Assert.Throws<CoreInstanceLock.AlreadyRunningException>(
            () => new CoreRuntime(OptionsWithProbe(dir,
                () => Liveness(CoreProcessLiveness.Verdict.OtherCoreRunning, others))));
        Assert.Contains("process enumeration", ex.Message);
        Assert.Contains("4242", ex.Message);
        Assert.True(CoreInstanceLock.TryAcquire(dir, out var held, out _)); // refusal released the lock
        held!.Dispose();

        // (b) A pid'd marker whose pid is provably dead (recycled
        // restart shape) STILL refuses when enumeration sees a
        // Core: enumeration is independent of the marker class.
        var dir2 = TestUtil.TempDir();
        WriteMarker(dir2, 999999, DateTimeOffset.UtcNow);
        var ex2 = Assert.Throws<CoreInstanceLock.AlreadyRunningException>(
            () => new CoreRuntime(OptionsWithProbe(dir2,
                () => Liveness(CoreProcessLiveness.Verdict.OtherCoreRunning, others))));
        Assert.Contains("process enumeration", ex2.Message);
        await Task.CompletedTask;
    }

    [Fact]
    public async Task Runtime_EnumerationFindsNone_Proceeds_FastRestartWithFreshSigns()
    {
        // The fast-restart case must not be bricked in a new form:
        // the old Core exited seconds ago — marker fresh, pid
        // recorded but provably gone, heartbeat fresh from its
        // last beat — and enumeration finds NO other Core process
        // (the old process is GONE). The start proceeds.
        var dir = TestUtil.TempDir();
        WriteMarker(dir, 999999, DateTimeOffset.UtcNow);
        WriteHeartbeat(dir, DateTimeOffset.UtcNow);
        var runtime = new CoreRuntime(OptionsWithProbe(dir,
            () => Liveness(CoreProcessLiveness.Verdict.NoOtherCore)));
        Assert.NotNull(runtime.InstanceLock);
        await runtime.StopAsync(default);
        await runtime.DisposeAsync();
    }

    [Fact]
    public async Task Runtime_EnumerationIndeterminate_Refuses_NamesTheOverride()
    {
        var dir = TestUtil.TempDir();
        var ex = Assert.Throws<CoreInstanceLock.AlreadyRunningException>(
            () => new CoreRuntime(OptionsWithProbe(dir,
                () => Liveness(CoreProcessLiveness.Verdict.Indeterminate))));
        // Fail closed, and the refusal names the operator's way
        // through — the one-time override file, by name.
        Assert.Contains("failing closed", ex.Message);
        Assert.Contains(CoreProcessLiveness.OverrideFileName, ex.Message);
        Assert.True(CoreInstanceLock.TryAcquire(dir, out var held, out _));
        held!.Dispose();
        await Task.CompletedTask;
    }

    [Fact]
    public async Task Runtime_Override_Proceeds_ConsumedAndAudited_ButNeverOverridesPositiveEvidence()
    {
        // The override lets an INDETERMINATE start proceed; it is
        // one-time (consumed) and its use lands in the audit chain
        // at StartAsync.
        var dir = TestUtil.TempDir();
        File.WriteAllText(Path.Combine(dir, CoreProcessLiveness.OverrideFileName),
            "operator: verified no other Core is running\n");
        var runtime = new CoreRuntime(OptionsWithProbe(dir,
            () => Liveness(CoreProcessLiveness.Verdict.Indeterminate)));
        Assert.False(File.Exists(Path.Combine(dir, CoreProcessLiveness.OverrideFileName)));
        await runtime.StartAsync(default);
        var entry = Assert.Single(runtime.Audit.ReadTail(100),
            e => e.Outcome.Contains("core_started_on_operator_liveness_override"));
        Assert.Contains(CoreProcessLiveness.OverrideFileName, entry.Outcome);
        await runtime.StopAsync(default);
        await runtime.DisposeAsync();

        // Positive evidence is NOT overridable: another Core seen
        // running refuses even with the override file present,
        // and the file is left unconsumed.
        var dir2 = TestUtil.TempDir();
        File.WriteAllText(Path.Combine(dir2, CoreProcessLiveness.OverrideFileName), "operator\n");
        var others = new[]
        {
            new CoreProcessLiveness.ProcessInfo(4242, "AcpCore.exe", @"C:\ACP-Install\v21-live\AcpCore.exe"),
        };
        Assert.Throws<CoreInstanceLock.AlreadyRunningException>(
            () => new CoreRuntime(OptionsWithProbe(dir2,
                () => Liveness(CoreProcessLiveness.Verdict.OtherCoreRunning, others))));
        Assert.True(File.Exists(Path.Combine(dir2, CoreProcessLiveness.OverrideFileName)));
    }

    [Fact]
    public void Source_EnumerationGate_SitsBetweenLockAndMarkerChecks()
    {
        var core = SrcFile("Acp.Core", "CoreRuntime.cs");
        var guard = core.IndexOf("InstanceLock = CoreInstanceLock.Acquire(options.DataDir)", StringComparison.Ordinal);
        var enumeration = core.IndexOf("CoreProcessLiveness.Probe", guard, StringComparison.Ordinal);
        var marker = core.IndexOf("RunMarker.IndicatesLiveOwner", StringComparison.Ordinal);
        Assert.True(guard > 0 && enumeration > guard, "enumeration must run after the lock is held");
        Assert.True(marker > enumeration, "the marker check stays, as defense in depth, after enumeration");
        Assert.Contains("core_started_on_operator_liveness_override", core);
        // The production probe is the OS enumeration, and the
        // identity rule lives in the shared primitive.
        var liveness = SrcFile("Acp.Shared", "Heartbeat", "CoreProcessLiveness.cs");
        Assert.Contains("Process.GetProcesses()", liveness);
        Assert.Contains("operator-force-start-without-liveness-proof", liveness);
    }

    // ---------- source pins: the guard precedes all publishing ----------

    [Fact]
    public void Source_GuardIsConstructorsFirstAct_BeforeEveryPublish()
    {
        var core = SrcFile("Acp.Core", "CoreRuntime.cs");
        var guard = core.IndexOf("InstanceLock = CoreInstanceLock.Acquire(options.DataDir)", StringComparison.Ordinal);
        Assert.True(guard > 0, "guard acquisition not found in CoreRuntime constructor");
        foreach (var publish in new[]
        {
            "IpcTokenFileChannel.Publish(options.DataDir",
            "CoreIdentityChannel.LoadOrCreate(",
            "InstallTrustRecordChannel.Provision(",
            "new RunMarker(",
            "new FileAuditLog(",
        })
        {
            var at = core.IndexOf(publish, StringComparison.Ordinal);
            Assert.True(at > guard, $"{publish} must come AFTER the single-instance guard");
        }
        // StartAsync (marker read, heartbeat, lane binds) is only
        // reachable on a constructed — i.e. lock-holding — runtime.
        Assert.Contains("var previous = Marker.ReadPreviousRun();", core);
    }

    [Fact]
    public void Source_ProgramExitsCleanly_WithMessageRecordAndDistinctCode()
    {
        var program = SrcFile("Acp.Core", "Program.cs");
        Assert.Contains("catch (CoreInstanceLock.AlreadyRunningException", program);
        Assert.Contains("CoreInstanceLock.DuplicateMessage", program);
        Assert.Contains("CoreInstanceLock.WriteDuplicateStartRecord(dataDir, line)", program);
        Assert.Contains("Environment.ExitCode = CoreInstanceLock.DuplicateExitCode;", program);
        Assert.Equal(41, CoreInstanceLock.DuplicateExitCode);
        // The host is built only after the guarded construction.
        var caught = program.IndexOf("catch (CoreInstanceLock.AlreadyRunningException", StringComparison.Ordinal);
        var host = program.IndexOf("var host = builder.Build();", StringComparison.Ordinal);
        Assert.True(host > caught);
    }
}
