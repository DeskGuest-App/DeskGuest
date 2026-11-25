using System.Diagnostics;

namespace Acp.Shared.Heartbeat;

/// <summary>
/// FR-124 / W95 (defect D-W93-1): the per-data-dir single-instance
/// guard for AcpCore. A second Core started against the same data
/// dir previously booted fully — republished the IPC token and the
/// install trust record, appended a second boot sequence to the
/// shared audit chain, retried lane binds forever, spawned Agents
/// that failed IPC, and wrote heartbeat.json / run-marker.json
/// concurrently with the live Core (which also made it mis-record
/// the live run as "did NOT end cleanly").
///
/// Mechanism — the codebase's own cross-process pattern (the W49
/// pointer-anchor marker lock): a lock file INSIDE the data dir,
/// opened FileShare.None and held for the holder's whole lifetime.
///   * Keyed to the data dir by construction: the file lives in
///     the dir it guards, so two installs with different data dirs
///     hold different files and never collide.
///   * Liveness is the KERNEL's, not bookkeeping's: the exclusion
///     exists only while the holder's handle is open, and a
///     process's handles close when it dies — crash, kill, or
///     power loss — so a lock file left on disk by a dead Core is
///     just an unlocked file and never bricks the next start.
///     (A named Mutex was rejected: .NET named mutexes are
///     Windows-only, and this Core also runs as a Linux console
///     host in the test suite; the file handle is identical on
///     both.)
///   * The lock file is NEVER deleted (W49 rule): unlinking a
///     lock file another process holds would let a third process
///     lock a fresh inode and split the exclusion. On release the
///     file simply stays, unlocked, carrying the last holder's
///     record as diagnostics.
/// The holder record (pid, process start, acquire time) is written
/// UNDER the lock, so it always names the live holder; a refused
/// second instance reads it best-effort for its own log line (on
/// Windows the held share lock may make even the read fail — the
/// record is diagnostics, never authority).
/// </summary>
public sealed class CoreInstanceLock : IDisposable
{
    /// <summary>The lock file's name inside the data dir.</summary>
    public const string LockFileName = "core-instance.lock";

    /// <summary>The one clear line a refused second instance
    /// prints (pinned verbatim by the W95 tests and Program.cs).</summary>
    public const string DuplicateMessage =
        "another DeskGuest Core is already running for this data folder";

    /// <summary>The distinct process exit code a refused second
    /// instance exits with (Program.cs). Not 0 (not a success),
    /// not 1 (not a generic crash): a named, greppable refusal.</summary>
    public const int DuplicateExitCode = 41;

    /// <summary>The named refusal of a second Core instance. The
    /// CoreRuntime constructor throws this BEFORE any store,
    /// publish, bind, or state write, so a duplicate constructs
    /// nothing and touches no shared state.</summary>
    public sealed class AlreadyRunningException(string message) : InvalidOperationException(message);

    private FileStream? _stream;

    public string LockPath { get; }
    public string DataDir { get; }
    public int OwnerPid { get; }
    public DateTimeOffset AcquiredUtc { get; }

    private CoreInstanceLock(string dataDir, string lockPath, FileStream stream)
    {
        DataDir = dataDir;
        LockPath = lockPath;
        _stream = stream;
        OwnerPid = Environment.ProcessId;
        AcquiredUtc = DateTimeOffset.UtcNow;
        // The holder record, written under the lock: pid + process
        // start + acquire time, one line, for the refused second
        // instance's diagnostics and for a human reading the file.
        try
        {
            var start = "";
            try { start = Process.GetCurrentProcess().StartTime.ToUniversalTime().ToString("o"); } catch { }
            var record = $"pid={OwnerPid}; processStartedUtc={start}; lockAcquiredUtc={AcquiredUtc:o}; machine={Environment.MachineName}\n";
            var bytes = System.Text.Encoding.UTF8.GetBytes(record);
            stream.SetLength(0);
            stream.Position = 0;
            stream.Write(bytes, 0, bytes.Length);
            stream.Flush();
        }
        catch { /* the lock is the exclusion; the record is diagnostics */ }
    }

    /// <summary>The lock path for a data dir (the keying: one lock
    /// per data dir, living in it).</summary>
    public static string LockPathFor(string dataDir) =>
        Path.Combine(Path.GetFullPath(dataDir), LockFileName);

    /// <summary>Acquire the single-instance lock for
    /// <paramref name="dataDir"/>, or throw
    /// <see cref="AlreadyRunningException"/> naming the holder when
    /// a live Core already holds it. NO bounded wait: a second
    /// instance exits IMMEDIATELY (FR-124), it never queues behind
    /// the running Core.</summary>
    public static CoreInstanceLock Acquire(string dataDir)
    {
        if (TryAcquire(dataDir, out var held, out var holderRecord)) return held!;
        throw new AlreadyRunningException(
            $"{DuplicateMessage} (data folder: {Path.GetFullPath(dataDir)}" +
            (holderRecord is not null ? $"; holder: {holderRecord}" : "") + ")");
    }

    /// <summary>Try to acquire; on refusal returns false and the
    /// current holder's record (best-effort — null when the held
    /// share lock also blocks the read).</summary>
    public static bool TryAcquire(string dataDir, out CoreInstanceLock? held, out string? holderRecord)
    {
        held = null;
        holderRecord = null;
        Directory.CreateDirectory(dataDir);
        var lockPath = LockPathFor(dataDir);
        FileStream stream;
        try
        {
            stream = new FileStream(lockPath, FileMode.OpenOrCreate,
                FileAccess.ReadWrite, FileShare.None);
        }
        catch (IOException)
        {
            holderRecord = ReadHolderRecord(lockPath);
            return false;
        }
        held = new CoreInstanceLock(Path.GetFullPath(dataDir), lockPath, stream);
        return true;
    }

    /// <summary>Best-effort read of the holder record in a lock
    /// file. Never throws: under a live holder the read itself may
    /// be refused (Windows share lock), which is also an answer —
    /// the file is held.</summary>
    public static string? ReadHolderRecord(string lockPath)
    {
        try
        {
            if (!File.Exists(lockPath)) return null;
            using var fs = new FileStream(lockPath, FileMode.Open,
                FileAccess.Read, FileShare.ReadWrite);
            using var reader = new StreamReader(fs);
            var line = reader.ReadLine();
            return string.IsNullOrWhiteSpace(line) ? null : line.Trim();
        }
        catch { return null; }
    }

    /// <summary>Write a refused second instance's OWN attempted-start
    /// record: a brand-new, uniquely named file in the data dir
    /// (create-new semantics via the unique name — pid + UTC stamp).
    /// It opens NO existing shared file: not the audit chain (W93
    /// proved concurrent chain appends under contention are the
    /// unsafe case), not heartbeat.json, not the run marker, not
    /// the IPC token, not the trust record. Returns the path
    /// written, or null when even this write was impossible (the
    /// console line + exit code remain the record then).
    ///
    /// W107 (W106-verified C4a): the record is TAMPER-EVIDENT and
    /// is NOT the end of the story. A third line carries
    /// recordSha256 — SHA-256 over the two content lines above it —
    /// so the RUNNING Core's ingestion (CoreRuntime consumes these
    /// files into the audit chain of record, the
    /// ConsumeRestartOutcome shape) can verify the refused
    /// process's own fields arrived unaltered, and can say so in
    /// the chain. The refused process still never touches the
    /// chain itself (the W93 contention rule stands); ingestion is
    /// the live Core's job, done from its own single-writer side.</summary>
    public static string? WriteDuplicateStartRecord(string dataDir, string line)
    {
        try
        {
            Directory.CreateDirectory(dataDir);
            var stamp = DateTimeOffset.UtcNow.ToString("yyyyMMddHHmmssfff");
            var path = Path.Combine(Path.GetFullPath(dataDir),
                $"duplicate-core-start-{stamp}-{Environment.ProcessId}.log");
            var fieldsLine =
                $"attemptedUtc={DateTimeOffset.UtcNow:o}; pid={Environment.ProcessId}; exitCode={DuplicateExitCode}";
            var hash = DuplicateRecordHash(line, fieldsLine);
            File.WriteAllText(path,
                line + Environment.NewLine +
                fieldsLine + Environment.NewLine +
                $"recordSha256={hash}" + Environment.NewLine);
            return path;
        }
        catch { return null; }
    }

    /// <summary>The record hash: SHA-256 (hex) over the refusal
    /// line and the fields line, newline-joined — exactly what
    /// <see cref="ReadDuplicateStartRecord"/> recomputes.</summary>
    public static string DuplicateRecordHash(string line, string fieldsLine) =>
        Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(line + "\n" + fieldsLine + "\n"))).ToLowerInvariant();

    /// <summary>One parsed duplicate-start record (W107). Line and
    /// FieldsLine are the refused process's OWN words, verbatim;
    /// HashState is "verified" (the carried hash matches the
    /// contents), "mismatch" (a hash is present but does not match
    /// — the contents may have been altered after the refusal), or
    /// "legacy" (a pre-W107 record with no hash line: ingestible,
    /// but its integrity is unverifiable and the chain entry must
    /// say so).</summary>
    public sealed record DuplicateStartRecord(
        string Path, string Line, string FieldsLine, string? RecordSha256, string HashState);

    /// <summary>Parse one duplicate-start record file. Returns
    /// null when the file is unreadable or has no content lines —
    /// the ingestion leaves such a file in place rather than
    /// guessing at it.</summary>
    public static DuplicateStartRecord? ReadDuplicateStartRecord(string path)
    {
        try
        {
            var lines = File.ReadAllLines(path);
            if (lines.Length < 2) return null;
            string? hash = null;
            if (lines.Length >= 3 && lines[2].StartsWith("recordSha256=", StringComparison.Ordinal))
                hash = lines[2]["recordSha256=".Length..].Trim();
            var state = hash is null ? "legacy"
                : string.Equals(hash, DuplicateRecordHash(lines[0], lines[1]), StringComparison.OrdinalIgnoreCase)
                    ? "verified" : "mismatch";
            return new DuplicateStartRecord(path, lines[0], lines[1], hash, state);
        }
        catch { return null; }
    }

    /// <summary>Every pending duplicate-start record in a data
    /// dir, oldest first (the filename carries the UTC stamp).</summary>
    public static IReadOnlyList<string> FindDuplicateStartRecords(string dataDir)
    {
        try
        {
            if (!Directory.Exists(dataDir)) return Array.Empty<string>();
            return Directory.EnumerateFiles(dataDir, "duplicate-core-start-*.log")
                .OrderBy(f => f, StringComparer.Ordinal).ToList();
        }
        catch { return Array.Empty<string>(); }
    }

    /// <summary>Release the lock (the file stays, unlocked — see
    /// the class summary). Idempotent; process exit releases too.</summary>
    public void Dispose()
    {
        var stream = Interlocked.Exchange(ref _stream, null);
        try { stream?.Dispose(); } catch { }
    }
}
